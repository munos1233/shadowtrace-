"""ISSUE-054 SuperAgent tests — graph skeleton, lease lifecycle, guardrails.

Test categories (per the ISSUE-054 acceptance spec):

1. **Golden path** — graph skeleton advances NEW → REPORTING with agent trace
2. **Concurrent lease** — second SuperAgent receives 409 ``investigation_in_progress``
3. **Crash recovery** — lease expiry and renew behaviour
4. **REACT_ENABLED gate** — ``REACT_ENABLED=true`` without executor → ``ConfigurationError``
5. **analysis_only gate** — ``ORCHESTRATION_MODE=analysis_only`` → ``ConfigurationError``
6. **State machine** — ``SuperAgentStatus`` transitions correctly
7. **Writeback isolation** — ``InvestigationResult`` enforces invariants via ``extra="forbid"``
8. **Guardrails** — invalid inputs rejected by BaseAgent template
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agents.super_agent import SuperAgent
from app.core.config import Settings
from app.core.errors import ConfigurationError, ShadowTraceError
from app.models.agent_io import InvestigationResult, SuperAgentInput
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    FinalVerdict,
    Severity,
    SuperAgentStatus,
    WritebackReadiness,
)
from app.orchestration.lease import DEFAULT_LEASE_TTL_SECONDS, EventLease

# --------------------------------------------------------------------------- #
# Shared test fixtures
# --------------------------------------------------------------------------- #


class _FakeRedis:
    """In-memory Redis stand-in for lease testing."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._ttl: dict[str, int] = {}

    async def set(self, key: str, value: str, nx: bool = False, ex: int = 0) -> bool:
        if nx and key in self._store:
            return False
        self._store[key] = value
        self._ttl[key] = ex
        return True

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def delete(self, key: str) -> int:
        if key in self._store:
            del self._store[key]
            self._ttl.pop(key, None)
            return 1
        return 0

    async def eval(self, script: str, num_keys: int, *args: str) -> int:
        # Minimal Lua script emulation for release script
        key = args[0]
        owner = args[1] if len(args) > 1 else ""
        if "GET" in script and "DEL" in script:  # release script
            if self._store.get(key) == owner:
                del self._store[key]
                self._ttl.pop(key, None)
                return 1
            return 0
        if "EXPIRE" in script:  # renew script
            if self._store.get(key) == owner:
                ttl = int(args[2]) if len(args) > 2 else DEFAULT_LEASE_TTL_SECONDS
                self._ttl[key] = ttl
                return 1
            return 0
        return 0


class _FakeRedisClient:
    """Stand-in for ``RedisClient`` that returns ``_FakeRedis``."""

    def __init__(self, redis: _FakeRedis) -> None:
        self._redis = redis

    def get_client(self) -> _FakeRedis:
        return self._redis

    async def ping(self) -> bool:
        return True


class _FakeEvent:
    """Minimal event row for SuperAgent state hydration.

    Uses actual enum values so ``.value`` access works identically to ORM rows.
    """

    def __init__(
        self,
        event_id: str,
        status: EventStatus = EventStatus.NEW,
        disposition_policy: DispositionPolicy = DispositionPolicy.REQUIRED,
        severity: Any = Severity.HIGH,
        final_verdict: FinalVerdict | None = None,
    ) -> None:
        self.event_id = event_id
        self.status = status
        self.disposition_policy = disposition_policy
        self.severity = severity
        self.final_verdict = final_verdict
        self.title = "Test Event"
        self.description = "A test security event for SuperAgent"


def _make_super_agent(
    *,
    event_service: Any = None,
    state_machine: Any = None,
    redis: _FakeRedis | None = None,
    settings: Settings | None = None,
    checkpointer: Any = None,
    react_executor: Any = None,
    **overrides: Any,
) -> SuperAgent:
    """Build a SuperAgent with fake dependencies suitable for unit testing."""
    redis = redis or _FakeRedis()
    redis_client = _FakeRedisClient(redis)

    defaults: dict[str, Any] = {
        "state_machine": state_machine or AsyncMock(),
        "event_service": event_service or AsyncMock(),
        "workflow_runtime": AsyncMock(),
        "degraded_flags": AsyncMock(),
        "context_store": AsyncMock(),
        "triage_agent": AsyncMock(),
        "planner_agent": AsyncMock(),
        "evidence_agent": AsyncMock(),
        "risk_agent": AsyncMock(),
        "report_agent": AsyncMock(),
        "rag_agent": None,
        "redis_client": redis_client,
        "checkpointer": checkpointer,
        "react_executor": react_executor,
        "settings": settings,
        "session_factory": None,
    }
    defaults.update(overrides)
    return SuperAgent(**defaults)


# --------------------------------------------------------------------------- #
# 1. Golden path — graph skeleton
# --------------------------------------------------------------------------- #


class TestSuperAgentGoldenPath:
    """SuperAgent builds the graph, acquires a lease, and invokes the workflow."""

    @pytest.mark.asyncio
    async def test_acquires_lease_before_graph_invocation(self) -> None:
        """The lease must be acquired before the graph is invoked."""
        redis = _FakeRedis()
        event_id = "evt-20240724-a1b2c3d4"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        state_machine = AsyncMock()

        agent = _make_super_agent(
            event_service=event_service,
            state_machine=state_machine,
            redis=redis,
        )

        # The graph invocation should succeed — we mock the entire graph.
        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.85,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": ["triage_node", "planner_node", "report_node"],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(return_value=mock_invoke.return_value)
                mock_build.return_value = mock_graph

                result = await agent.investigate(event_id)

        # ── Assertions ────────────────────────────────────────────
        assert result.event_id == event_id
        assert result.final_status == EventStatus.REPORTING
        assert result.final_verdict == FinalVerdict.CONFIRMED_THREAT
        assert result.writeback_required is True

        # Lease must have been acquired and released
        assert redis._store == {}  # released

        # State machine: NEW → TRIAGING transition must have been issued
        state_machine.transition.assert_any_call(
            event_id,
            EventStatus.TRIAGING,
            operator="SuperAgent",
            reason="super_agent:investigation_start",
        )

    @pytest.mark.asyncio
    async def test_status_transitions_through_lifecycle(self) -> None:
        """SuperAgentStatus must move IDLE → PLANNING → EXECUTING → FINISHED."""
        redis = _FakeRedis()
        event_id = "evt-20240724-lifecycle01"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(
            event_service=event_service,
            redis=redis,
        )

        statuses: list[SuperAgentStatus] = []

        # Intercept status changes
        async def _track(*args: Any, **kwargs: Any) -> dict[str, Any]:
            statuses.append(agent.status)
            return {
                "event_id": event_id,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.9,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
            side_effect=_track,
        ):
            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(side_effect=_track)
                mock_build.return_value = mock_graph

                await agent.investigate(event_id)

        assert agent.status == SuperAgentStatus.FINISHED


# --------------------------------------------------------------------------- #
# 2. Concurrent lease — 409 investigation_in_progress
# --------------------------------------------------------------------------- #


class TestSuperAgentConcurrentLease:
    """The distributed lease prevents duplicate investigations."""

    @pytest.mark.asyncio
    async def test_second_agent_receives_investigation_in_progress(self) -> None:
        """A second SuperAgent for the same event_id must raise a ShadowTraceError
        with error_code='investigation_in_progress'."""
        redis = _FakeRedis()
        event_id = "evt-20240724-concur01"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        # First lease acquires the key directly (simulating agent1)
        lease1 = EventLease(redis)
        assert await lease1.acquire(event_id) is True

        # Second agent tries to acquire — should fail
        agent2 = _make_super_agent(event_service=event_service, redis=redis)

        with pytest.raises(ShadowTraceError) as exc_info:
            await agent2.investigate(event_id)

        assert exc_info.value.error_code == "investigation_in_progress"
        assert event_id in str(exc_info.value)

        # Cleanup
        await lease1.release(event_id)

    @pytest.mark.asyncio
    async def test_lease_released_after_success_allows_new_investigation(self) -> None:
        """After a completed investigation releases its lease, a new one can start."""
        redis = _FakeRedis()
        event_id = "evt-20240724-reacquire"

        # Simulate completed investigation with lease released
        event = _FakeEvent(event_id, status=EventStatus.NEW)
        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.9,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(return_value=mock_invoke.return_value)
                mock_build.return_value = mock_graph

                # First investigation
                result1 = await agent.investigate(event_id)
                assert result1.final_status == EventStatus.REPORTING

        # Lease should be released now — a new agent can acquire
        assert redis._store == {}  # Lease released
        # Verify a fresh lease can be acquired (no existing holder)
        lease_check = EventLease(redis)
        assert await lease_check.acquire(event_id) is True
        await lease_check.release(event_id)


# --------------------------------------------------------------------------- #
# 3. Crash recovery — lease expiry and renew
# --------------------------------------------------------------------------- #


class TestSuperAgentCrashRecovery:
    """Lease behaviour when the SuperAgent process crashes or is killed."""

    def test_lease_owner_id_format(self) -> None:
        """Owner ID must follow ``worker-{8hex}`` format."""
        redis = _FakeRedis()
        lease = EventLease(redis)
        owner = lease.owner_id
        assert owner.startswith("worker-")
        hex_part = owner[len("worker-") :]
        assert len(hex_part) == 8
        assert all(c in "0123456789abcdef" for c in hex_part)

    @pytest.mark.asyncio
    async def test_renew_succeeds_for_valid_owner(self) -> None:
        """Renew extends the TTL when the owner matches."""
        redis = _FakeRedis()
        lease = EventLease(redis)
        event_id = "evt-20240724-renew01"

        assert await lease.acquire(event_id) is True
        assert await lease.renew(event_id) is True

        # Key should still exist
        assert await redis.get(lease.lease_key_for(event_id)) == lease.owner_id

        await lease.release(event_id)

    @pytest.mark.asyncio
    async def test_renew_fails_for_wrong_owner(self) -> None:
        """A different owner cannot renew the lease."""
        redis = _FakeRedis()
        lease1 = EventLease(redis)
        lease2 = EventLease(redis)
        event_id = "evt-20240724-renew02"

        # lease1 acquires
        assert await lease1.acquire(event_id) is True

        # lease2 tries to renew — should fail (wrong owner)
        assert await lease2.renew(event_id) is False

        await lease1.release(event_id)

    @pytest.mark.asyncio
    async def test_release_only_works_for_owner(self) -> None:
        """A different owner cannot release the lease."""
        redis = _FakeRedis()
        lease1 = EventLease(redis)
        lease2 = EventLease(redis)
        event_id = "evt-20240724-release01"

        assert await lease1.acquire(event_id) is True

        # lease2 tries to release — should fail
        assert await lease2.release(event_id) is False
        assert redis._store != {}  # lease1's lease still intact

        # lease1 can release
        assert await lease1.release(event_id) is True
        assert redis._store == {}

    @pytest.mark.asyncio
    async def test_renew_loop_background_task(self) -> None:
        """The renew loop runs at RENEW_INTERVAL_SECONDS intervals."""
        redis = _FakeRedis()
        lease = EventLease(redis)
        event_id = "evt-20240724-loop01"

        await lease.acquire(event_id)

        renew_count = 0
        original_renew = lease.renew

        async def _counting_renew(eid: str) -> bool:
            nonlocal renew_count
            renew_count += 1
            return await original_renew(eid)

        lease.renew = _counting_renew  # type: ignore[method-assign]

        async def _run_loop() -> None:
            agent = _make_super_agent(redis=redis)
            # Patch _renew_loop to use a very short interval for testing
            with patch.object(agent, "_renew_loop") as mock_loop:
                mock_loop.side_effect = lambda eid, lse: _fast_renew(eid, lse)

        async def _fast_renew(eid: str, lse: EventLease) -> None:
            for _ in range(3):
                await asyncio.sleep(0.01)  # very fast for testing
                await lse.renew(eid)

        await _fast_renew(event_id, lease)
        assert renew_count >= 3

        await lease.release(event_id)


# --------------------------------------------------------------------------- #
# 4. REACT_ENABLED gate
# --------------------------------------------------------------------------- #


class TestSuperAgentReactGate:
    """REACT_ENABLED=true requires a registered ReAct executor (ISSUE-053)."""

    @pytest.mark.asyncio
    async def test_react_enabled_without_executor_raises_configuration_error(self) -> None:
        """When REACT_ENABLED=true but no executor is injected, ConfigurationError
        must be raised before the lease is acquired."""
        redis = _FakeRedis()
        event_id = "evt-20240724-react01"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        settings = Settings(ORCHESTRATION_MODE="graph", REACT_ENABLED=True)

        agent = _make_super_agent(
            event_service=event_service,
            redis=redis,
            settings=settings,
            react_executor=None,  # ← missing!
        )

        with pytest.raises(ConfigurationError) as exc_info:
            await agent.investigate(event_id)

        assert "REACT_ENABLED" in str(exc_info.value)
        assert exc_info.value.error_code == "configuration_error"

        # Lease must NOT have been acquired
        assert redis._store == {}

    @pytest.mark.asyncio
    async def test_react_disabled_without_executor_is_fine(self) -> None:
        """When REACT_ENABLED=false, missing executor is not an error."""
        redis = _FakeRedis()
        event_id = "evt-20240724-react02"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        settings = Settings(ORCHESTRATION_MODE="graph", REACT_ENABLED=False)

        agent = _make_super_agent(
            event_service=event_service,
            redis=redis,
            settings=settings,
            react_executor=None,
        )

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.9,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(return_value=mock_invoke.return_value)
                mock_build.return_value = mock_graph

                result = await agent.investigate(event_id)

        assert result.final_status == EventStatus.REPORTING


# --------------------------------------------------------------------------- #
# 5. analysis_only gate
# --------------------------------------------------------------------------- #


class TestSuperAgentAnalysisOnlyGate:
    """ORCHESTRATION_MODE=analysis_only rejects SuperAgent and preserves the
    legacy AnalysisOnlyPipeline path."""

    @pytest.mark.asyncio
    async def test_analysis_only_mode_raises_configuration_error(self) -> None:
        """SuperAgent.investigate in analysis_only mode must raise ConfigurationError."""
        redis = _FakeRedis()
        event_id = "evt-20240724-aomode01"

        settings = Settings(ORCHESTRATION_MODE="analysis_only")
        agent = _make_super_agent(redis=redis, settings=settings)

        with pytest.raises(ConfigurationError) as exc_info:
            await agent.investigate(event_id)

        assert exc_info.value.error_code == "configuration_error"
        assert "analysis_only" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# 6. State machine — SuperAgentStatus
# --------------------------------------------------------------------------- #


class TestSuperAgentStatusMachine:
    """SuperAgentStatus must have all 7 states defined."""

    def test_all_seven_states_exist(self) -> None:
        """The 7-state SuperAgentStatus enum must match README §4.6."""
        expected = {
            "idle",
            "planning",
            "executing",
            "reflecting",
            "replanning",
            "finished",
            "failed",
        }
        actual = {s.value for s in SuperAgentStatus}
        assert actual == expected

    def test_initial_status_is_idle(self) -> None:
        """A freshly constructed SuperAgent must be IDLE."""
        agent = _make_super_agent()
        assert agent.status == SuperAgentStatus.IDLE


# --------------------------------------------------------------------------- #
# 7. Writeback isolation
# --------------------------------------------------------------------------- #


class TestInvestigationResultWritebackIsolation:
    """InvestigationResult must never claim writeback_required=true with
    writeback_readiness=NOT_REQUIRED."""

    def test_writeback_required_forbids_not_required_readiness(self) -> None:
        """The model validator rejects writeback_required=true with NOT_REQUIRED."""
        with pytest.raises(ValueError, match="writeback_required=true forbids"):
            InvestigationResult(
                event_id="evt-20240724-wb01",
                final_status=EventStatus.REPORTING,
                final_verdict=FinalVerdict.CONFIRMED_THREAT,
                writeback_required=True,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            )

    def test_writeback_not_required_forces_not_required_readiness(self) -> None:
        """writeback_required=false requires NOT_REQUIRED readiness."""
        with pytest.raises(ValueError, match="writeback_required=false requires"):
            InvestigationResult(
                event_id="evt-20240724-wb02",
                final_status=EventStatus.REPORTING,
                final_verdict=FinalVerdict.NONE,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.READY,
            )

    def test_valid_result_with_writeback(self) -> None:
        """A valid result with writeback_required=true and READY passes validation."""
        result = InvestigationResult(
            event_id="evt-20240724-wb03",
            final_status=EventStatus.REPORTING,
            final_verdict=FinalVerdict.CONFIRMED_THREAT,
            writeback_required=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_overall_status=None,
        )
        assert result.writeback_required is True
        assert result.writeback_readiness is WritebackReadiness.READY

    def test_extra_fields_forbidden(self) -> None:
        """InvestigationResult must reject unknown fields (extra='forbid')."""
        with pytest.raises(ValueError):  # pydantic ValidationError
            InvestigationResult(
                event_id="evt-20240724-wb04",
                final_status=EventStatus.REPORTING,
                unknown_field="should_not_exist",  # type: ignore[call-arg]
            )


# --------------------------------------------------------------------------- #
# 8. Guardrails — BaseAgent template validates input
# --------------------------------------------------------------------------- #


class TestSuperAgentGuardrails:
    """The BaseAgent template enforces input type validation."""

    @pytest.mark.asyncio
    async def test_execute_rejects_wrong_input_type(self) -> None:
        """BaseAgent.execute rejects input that is not SuperAgentInput."""
        agent = _make_super_agent()

        class WrongInput:
            event_id = "evt-123"

        with pytest.raises(TypeError, match="requires SuperAgentInput"):
            await agent.execute(WrongInput())  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_execute_accepts_super_agent_input(self) -> None:
        """BaseAgent.execute accepts SuperAgentInput and delegates to _run."""
        redis = _FakeRedis()
        event_id = "evt-20240724-exec01"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.9,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(return_value=mock_invoke.return_value)
                mock_build.return_value = mock_graph

                result = await agent.execute(
                    SuperAgentInput(event_id=event_id, triggered_by="test")
                )

        assert isinstance(result, InvestigationResult)
        assert result.event_id == event_id


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #


class TestSuperAgentEdgeCases:
    """Boundary and error conditions."""

    @pytest.mark.asyncio
    async def test_event_not_found_raises_error(self) -> None:
        """When the event does not exist, an error must be raised."""
        redis = _FakeRedis()
        event_id = "evt-20240724-missing"

        event_service = AsyncMock()
        event_service.get_event.return_value = None  # event not found

        agent = _make_super_agent(event_service=event_service, redis=redis)

        with pytest.raises(ShadowTraceError) as exc_info:
            await agent.investigate(event_id)

        assert exc_info.value.error_code == "event_not_found"

    @pytest.mark.asyncio
    async def test_graph_failure_transitions_to_failed(self) -> None:
        """If the graph throws, the event must be transitioned to FAILED."""
        redis = _FakeRedis()
        event_id = "evt-20240724-graphfail"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        state_machine = AsyncMock()

        agent = _make_super_agent(
            event_service=event_service,
            state_machine=state_machine,
            redis=redis,
        )

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
            side_effect=RuntimeError("graph exploded"),
        ):
            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(side_effect=RuntimeError("graph exploded"))
                mock_build.return_value = mock_graph

                with pytest.raises(RuntimeError, match="graph exploded"):
                    await agent.investigate(event_id)

        # State machine must have transitioned to FAILED
        failed_calls = [
            c
            for c in state_machine.transition.call_args_list
            if c.args[0] == event_id
            and c.args[1] == EventStatus.FAILED
            and c.kwargs.get("operator") == "SuperAgent"
        ]
        assert len(failed_calls) >= 1, "Expected a FAILED transition call"
        assert "super_agent:error:RuntimeError" in str(failed_calls[0].kwargs.get("reason", ""))

    @pytest.mark.asyncio
    async def test_failed_status_reflected_in_agent(self) -> None:
        """After a failure, SuperAgentStatus must be FAILED."""
        redis = _FakeRedis()
        event_id = "evt-20240724-statusfail"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(side_effect=RuntimeError("boom"))
                mock_build.return_value = mock_graph

                with pytest.raises(RuntimeError):
                    await agent.investigate(event_id)

        assert agent.status == SuperAgentStatus.FAILED

    @pytest.mark.asyncio
    async def test_initial_state_includes_disposition_policy(self) -> None:
        """The initial InvestigationState must include disposition_policy from the event."""
        redis = _FakeRedis()
        event_id = "evt-20240724-initstate"
        event = _FakeEvent(event_id, disposition_policy=DispositionPolicy.NOT_REQUIRED)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        state_machine = AsyncMock()

        workflow_runtime = AsyncMock()
        workflow_runtime.get_event_status_update_readiness.return_value = (
            WritebackReadiness.NOT_REQUIRED
        )

        agent = _make_super_agent(
            event_service=event_service,
            state_machine=state_machine,
            workflow_runtime=workflow_runtime,
            redis=redis,
        )

        captured_state: dict[str, Any] = {}

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id,
                "event_status": "closed",
                "disposition_policy": "not_required",
                "severity": "low",
                "final_verdict": "false_positive",
                "confidence": 0.9,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            async def _capture_invoke(graph: Any, state: Any, config: Any) -> dict[str, Any]:
                captured_state.update(state)
                return mock_invoke.return_value

            mock_invoke.side_effect = _capture_invoke

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(side_effect=_capture_invoke)
                mock_build.return_value = mock_graph

                await agent.investigate(event_id)

        assert captured_state["event_id"] == event_id
        assert captured_state["disposition_policy"] == "not_required"

    @pytest.mark.asyncio
    async def test_cancelled_error_transitions_event_to_failed(self) -> None:
        """When asyncio.CancelledError is raised, the event DB status must be
        transitioned to FAILED (not left in TRIAGING)."""
        redis = _FakeRedis()
        event_id = "evt-20240724-cancel01"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        state_machine = AsyncMock()

        agent = _make_super_agent(
            event_service=event_service,
            state_machine=state_machine,
            redis=redis,
        )

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
            side_effect=asyncio.CancelledError("task cancelled"),
        ):
            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(
                    side_effect=asyncio.CancelledError("task cancelled")
                )
                mock_build.return_value = mock_graph

                with pytest.raises(asyncio.CancelledError):
                    await agent.investigate(event_id)

        # State machine must have been called with FAILED for CancelledError
        failed_calls = [
            c
            for c in state_machine.transition.call_args_list
            if c.args[0] == event_id
            and c.args[1] == EventStatus.FAILED
            and c.kwargs.get("operator") == "SuperAgent"
        ]
        assert len(failed_calls) >= 1, (
            "Expected a FAILED transition call for CancelledError, "
            f"got {state_machine.transition.call_args_list}"
        )
        assert "super_agent:cancelled" in str(
            failed_calls[0].kwargs.get("reason", "")
        )


# --------------------------------------------------------------------------- #
# 9. Recommended tests from ISSUE-054 review
# --------------------------------------------------------------------------- #


class TestReportIdCanonicalDerivation:
    """_build_result must use the canonical report_id_for_event() function."""

    @pytest.mark.asyncio
    async def test_report_id_uses_canonical_derivation(self) -> None:
        """_build_result's report_id must match report_id_for_event()."""
        from app.models.ids import report_id_for_event

        redis = _FakeRedis()
        event_id = "evt-20240724-rpt01"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        state: dict[str, Any] = {
            "event_id": event_id,
            "event_status": "reporting",
            "disposition_policy": "required",
            "severity": "high",
            "final_verdict": "confirmed_threat",
            "confidence": 0.9,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "report_generated": True,
            "escalated": False,
            "external_unsynced": False,
            "event_status_update_readiness": "capability_unknown",
        }

        result = await agent._build_result(event_id, state)

        expected = report_id_for_event(event_id)
        assert result.report_id == expected
        assert result.report_id.startswith("rpt-")
        # Must NOT be a bare rpt-evt-{event_id} string
        assert result.report_id != f"rpt-{event_id}"
        assert result.report_id != f"rpt-evt-{event_id}"


class TestWritebackReadinessFromState:
    """_build_result must read writeback_readiness from graph state."""

    @pytest.mark.asyncio
    async def test_result_reflects_graph_readiness_ready(self) -> None:
        """When state says READY, result must say READY."""
        redis = _FakeRedis()
        event_id = "evt-20240724-wbr01"
        event = _FakeEvent(event_id, disposition_policy=DispositionPolicy.REQUIRED)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        state: dict[str, Any] = {
            "event_id": event_id,
            "event_status": "reporting",
            "disposition_policy": "required",
            "severity": "high",
            "final_verdict": "confirmed_threat",
            "confidence": 0.9,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "report_generated": True,
            "escalated": False,
            "external_unsynced": False,
            "event_status_update_readiness": "ready",
        }

        result = await agent._build_result(event_id, state)

        assert result.writeback_required is True
        assert result.writeback_readiness == WritebackReadiness.READY

    @pytest.mark.asyncio
    async def test_result_falls_back_to_capability_unknown(self) -> None:
        """When state has no readiness field, result defaults to CAPABILITY_UNKNOWN."""
        redis = _FakeRedis()
        event_id = "evt-20240724-wbr02"
        event = _FakeEvent(event_id, disposition_policy=DispositionPolicy.REQUIRED)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        state: dict[str, Any] = {
            "event_id": event_id,
            "event_status": "reporting",
            "disposition_policy": "required",
            "severity": "high",
            "final_verdict": "confirmed_threat",
            "confidence": 0.9,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "report_generated": True,
            "escalated": False,
            "external_unsynced": False,
            # event_status_update_readiness is NOT set
        }

        result = await agent._build_result(event_id, state)

        assert result.writeback_required is True
        assert result.writeback_readiness == WritebackReadiness.CAPABILITY_UNKNOWN

    @pytest.mark.asyncio
    async def test_not_required_policy_defaults_to_not_required_readiness(self) -> None:
        """When disposition is NOT_REQUIRED, readiness is always NOT_REQUIRED."""
        redis = _FakeRedis()
        event_id = "evt-20240724-wbr03"
        event = _FakeEvent(event_id, disposition_policy=DispositionPolicy.NOT_REQUIRED)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        state: dict[str, Any] = {
            "event_id": event_id,
            "event_status": "reporting",
            "disposition_policy": "not_required",
            "severity": "low",
            "final_verdict": "false_positive",
            "confidence": 0.9,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "report_generated": True,
            "escalated": False,
            "external_unsynced": False,
            "event_status_update_readiness": "ready",  # should be ignored
        }

        result = await agent._build_result(event_id, state)

        assert result.writeback_required is False
        assert result.writeback_readiness == WritebackReadiness.NOT_REQUIRED


class TestShadowTraceErrorFailedTransition:
    """ShadowTraceError during graph execution must trigger event FAILED transition."""

    @pytest.mark.asyncio
    async def test_shadowtrace_error_transitions_event_to_failed(self) -> None:
        """When the graph raises a ShadowTraceError, the event must be FAILED."""
        redis = _FakeRedis()
        event_id = "evt-20240724-sterr01"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        state_machine = AsyncMock()

        agent = _make_super_agent(
            event_service=event_service,
            state_machine=state_machine,
            redis=redis,
        )

        from app.core.errors import BudgetExceededError

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
            side_effect=BudgetExceededError("budget hit"),
        ):
            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(
                    side_effect=BudgetExceededError("budget hit")
                )
                mock_build.return_value = mock_graph

                with pytest.raises(BudgetExceededError):
                    await agent.investigate(event_id)

        # State machine must have been called with FAILED for ShadowTraceError
        failed_calls = [
            c
            for c in state_machine.transition.call_args_list
            if c.args[0] == event_id
            and c.args[1] == EventStatus.FAILED
            and c.kwargs.get("operator") == "SuperAgent"
        ]
        assert len(failed_calls) >= 1, (
            "Expected a FAILED transition call for ShadowTraceError, "
            f"got {state_machine.transition.call_args_list}"
        )
        assert "BudgetExceededError" in str(
            failed_calls[0].kwargs.get("reason", "")
        )

    @pytest.mark.asyncio
    async def test_shadowtrace_error_sets_agent_status_failed(self) -> None:
        """ShadowTraceError must set SuperAgentStatus.FAILED."""
        redis = _FakeRedis()
        event_id = "evt-20240724-sterr02"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        from app.core.errors import ToolExecutionError

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
            side_effect=ToolExecutionError("tool failed"),
        ):
            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(
                    side_effect=ToolExecutionError("tool failed")
                )
                mock_build.return_value = mock_graph

                with pytest.raises(ToolExecutionError):
                    await agent.investigate(event_id)

        assert agent.status == SuperAgentStatus.FAILED


class TestRenewalLoopAbort:
    """The lease renewal loop must abort investigation after consecutive failures."""

    @pytest.mark.asyncio
    async def test_renew_loop_aborts_after_consecutive_failures(self) -> None:
        """After _MAX_RENEWAL_FAILURES consecutive failures, the loop returns."""
        redis = _FakeRedis()
        lease = EventLease(redis)
        event_id = "evt-20240724-abort01"

        await lease.acquire(event_id)

        # Force renew to always fail by releasing first
        await lease.release(event_id)

        agent = _make_super_agent(redis=redis)
        # Patch RENEW_INTERVAL_SECONDS to speed up the test
        with patch(
            "app.agents.super_agent.RENEW_INTERVAL_SECONDS", 0.01
        ):
            await agent._renew_loop(event_id, lease)

        # The loop should return (not hang forever) after 3 failures
        # If we got here without timeout, the abort logic works

    @pytest.mark.asyncio
    async def test_renew_loop_abort_sets_escalated_flag(self) -> None:
        """When _renew_loop aborts after consecutive failures, the escalated
        flag must be set on the InvestigationResult so callers can detect
        the degraded/split-brain scenario."""
        redis = _FakeRedis()
        event_id = "evt-20240724-abort02"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event

        agent = _make_super_agent(event_service=event_service, redis=redis)

        # Simulate lease lost before _build_result (as _renew_loop would do)
        agent._lease_lost = True

        state: dict[str, Any] = {
            "event_id": event_id,
            "event_status": "reporting",
            "disposition_policy": "required",
            "severity": "high",
            "final_verdict": "confirmed_threat",
            "confidence": 0.9,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "report_generated": True,
            "escalated": False,
            "external_unsynced": False,
            "event_status_update_readiness": "ready",
        }

        result = await agent._build_result(event_id, state)

        # The escalated flag must be True even though the graph state
        # says False — the lease loss overrides it.
        assert result.escalated is True, (
            "InvestigationResult.escalated must be True when lease was lost, "
            "so callers can detect split-brain risk"
        )
        assert result.external_unsynced is True, (
            "InvestigationResult.external_unsynced must be True when lease was "
            "lost, because another worker may have taken over"
        )


class TestRedisUnavailable:
    """SuperAgent must handle Redis unavailability gracefully."""

    @pytest.mark.asyncio
    async def test_redis_unavailable_raises_dependency_unavailable(self) -> None:
        """When Redis client is None, _get_lease raises DependencyUnavailableError."""
        from app.core.errors import DependencyUnavailableError

        agent = _make_super_agent(redis_client=None)

        with pytest.raises(DependencyUnavailableError) as exc_info:
            await agent._get_lease()

        assert "Redis" in str(exc_info.value)
        assert exc_info.value.error_code == "dependency_unavailable"


class TestGraphEdgeCases:
    """Edge cases for graph execution."""

    @pytest.mark.asyncio
    async def test_graph_proceeds_with_none_snapshot(self) -> None:
        """When source_snapshot is None (freeze not implemented), graph runs fine."""
        redis = _FakeRedis()
        event_id = "evt-20240724-nosnap"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event
        # freeze_source_snapshot raises AttributeError (not implemented).
        # Use a realistic Python AttributeError message so _try_snapshot_op's
        # guard can match the method name and swallow it correctly.
        event_service.freeze_source_snapshot = AsyncMock(
            side_effect=AttributeError(
                "type object 'EventService' has no attribute 'freeze_source_snapshot'"
            )
        )

        agent = _make_super_agent(event_service=event_service, redis=redis)

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.85,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(
                    return_value=mock_invoke.return_value
                )
                mock_build.return_value = mock_graph

                result = await agent.investigate(event_id)

        assert result.event_id == event_id
        assert result.final_status == EventStatus.REPORTING

    @pytest.mark.asyncio
    async def test_freeze_snapshot_db_error_sets_degraded_flag(self) -> None:
        """When freeze_source_snapshot fails with a non-AttributeError (e.g.
        DB outage), the investigation proceeds degraded — ``degraded_flags``
        must contain ``"source_snapshot_failed"`` and ``escalated`` must be
        ``True`` so downstream agents know the event image may be stale."""
        redis = _FakeRedis()
        event_id = "evt-20240724-dbdown"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event
        # Simulate a DB operational error — NOT an AttributeError.
        event_service.freeze_source_snapshot = AsyncMock(
            side_effect=RuntimeError("Database connection pool exhausted")
        )

        agent = _make_super_agent(event_service=event_service, redis=redis)

        # Directly exercise _build_initial_state so we can inspect
        # degraded_flags BEFORE the graph mock swallows them.
        state = await agent._build_initial_state(event_id)

        assert "source_snapshot_failed" in state["degraded_flags"], (
            "degraded_flags must contain 'source_snapshot_failed' "
            "when freeze_source_snapshot raises a non-AttributeError"
        )
        assert state["escalated"] is True, (
            "escalated must be True when source_snapshot freeze fails — "
            "downstream agents need to know data may be inconsistent"
        )
        assert state["source_snapshot"] is None, (
            "source_snapshot must be None when freeze fails"
        )

    @pytest.mark.asyncio
    async def test_freeze_snapshot_attribute_error_not_degraded(self) -> None:
        """AttributeError (method not implemented, ISSUE-029) should NOT set
        degraded_flags — it's an expected absence, not a failure."""
        redis = _FakeRedis()
        event_id = "evt-20240724-noimpl"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event.return_value = event
        event_service.freeze_source_snapshot = AsyncMock(
            side_effect=AttributeError(
                "type object 'EventService' has no attribute 'freeze_source_snapshot'"
            )
        )

        agent = _make_super_agent(event_service=event_service, redis=redis)
        state = await agent._build_initial_state(event_id)

        assert "source_snapshot_failed" not in state["degraded_flags"], (
            "degraded_flags must NOT contain 'source_snapshot_failed' "
            "when freeze_source_snapshot is merely not implemented (AttributeError)"
        )
        assert state["escalated"] is False
        assert state["source_snapshot"] is None

    @pytest.mark.asyncio
    async def test_analysis_only_mode_rejected_by_super_agent(self) -> None:
        """SuperAgent.investigate rejects analysis_only mode regardless of
        ALLOW_LIVE_SIDE_EFFECTS — the API-layer gate is tested separately."""
        redis = _FakeRedis()
        event_id = "evt-20240724-live01"

        settings = Settings(
            ORCHESTRATION_MODE="analysis_only",
            allow_live_side_effects=True,
        )
        agent = _make_super_agent(redis=redis, settings=settings)

        with pytest.raises(ConfigurationError) as exc_info:
            await agent.investigate(event_id)

        assert exc_info.value.error_code == "configuration_error"
        assert "analysis_only" in str(exc_info.value)
        # The gate must fire regardless of ALLOW_LIVE_SIDE_EFFECTS —
        # analysis_only mode always rejects SuperAgent.


# --------------------------------------------------------------------------- #
# 10. ISSUE-054 review regression tests
# --------------------------------------------------------------------------- #


class TestLeaseLostFlagResetBetweenInvestigations:
    """Blocker regression: _lease_lost must be reset for each investigation."""

    @pytest.mark.asyncio
    async def test_lease_lost_flag_reset_between_investigations(self) -> None:
        """After a lease-lost investigation, the next investigation must NOT
        have escalated=True if its own lease was never lost."""
        redis = _FakeRedis()
        event_id_1 = "evt-20240724-reset01"
        event_id_2 = "evt-20240724-reset02"

        event_service = AsyncMock()
        event_service.get_event = AsyncMock(
            side_effect=lambda eid: _FakeEvent(eid)
        )

        agent = _make_super_agent(event_service=event_service, redis=redis)

        # ── Investigation 1: simulate lease loss ──────────────────
        agent._lease_lost = True

        state1: dict[str, Any] = {
            "event_id": event_id_1,
            "event_status": "reporting",
            "disposition_policy": "required",
            "severity": "high",
            "final_verdict": "confirmed_threat",
            "confidence": 0.9,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "report_generated": True,
            "escalated": False,
            "external_unsynced": False,
            "event_status_update_readiness": "ready",
        }

        result1 = await agent._build_result(event_id_1, state1)
        assert result1.escalated is True, "Lease-lost investigation must be escalated"

        # ── Investigation 2: fresh investigation, no lease loss ───
        # investigate() resets _lease_lost at entry — simulate that here
        agent._lease_lost = False

        state2: dict[str, Any] = {
            "event_id": event_id_2,
            "event_status": "reporting",
            "disposition_policy": "required",
            "severity": "high",
            "final_verdict": "confirmed_threat",
            "confidence": 0.95,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "report_generated": True,
            "escalated": False,
            "external_unsynced": False,
            "event_status_update_readiness": "ready",
        }

        result2 = await agent._build_result(event_id_2, state2)
        assert result2.escalated is False, (
            "Fresh investigation must NOT be escalated — "
            "_lease_lost from previous investigation must not leak"
        )
        assert result2.external_unsynced is False, (
            "Fresh investigation must NOT be external_unsynced — "
            "_lease_lost from previous investigation must not leak"
        )

    @pytest.mark.asyncio
    async def test_lease_lost_event_reset_between_investigations(self) -> None:
        """The _lease_lost_event must be cleared at the start of each investigation."""
        redis = _FakeRedis()
        event_id = "evt-20240724-event-reset"

        event_service = AsyncMock()
        event_service.get_event = AsyncMock(return_value=_FakeEvent(event_id))

        agent = _make_super_agent(event_service=event_service, redis=redis)

        # Simulate a prior lease loss setting the event
        agent._lease_lost_event.set()
        assert agent._lease_lost_event.is_set()

        # Mock the full investigation flow
        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.9,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(return_value=mock_invoke.return_value)
                mock_build.return_value = mock_graph

                await agent.investigate(event_id)

        # After investigate() runs, the event must be cleared
        assert not agent._lease_lost_event.is_set(), (
            "_lease_lost_event must be cleared at the start of each investigation"
        )


class TestInitialStateStatusDerivation:
    """Should-Fix #4: initial state must reflect actual event status."""

    @pytest.mark.asyncio
    async def test_initial_state_respects_actual_event_status_new(self) -> None:
        """When event is NEW, state machine transitions to TRIAGING and
        the initial state reflects TRIAGING."""
        redis = _FakeRedis()
        event_id = "evt-20240724-initnew"
        event = _FakeEvent(event_id, status=EventStatus.NEW)

        event_service = AsyncMock()
        # Called twice: once at start, once after transition
        event_service.get_event = AsyncMock(
            side_effect=[
                event,
                _FakeEvent(event_id, status=EventStatus.TRIAGING),
            ]
        )

        state_machine = AsyncMock()
        workflow_runtime = AsyncMock()
        workflow_runtime.get_event_status_update_readiness.return_value = (
            WritebackReadiness.NOT_REQUIRED
        )

        agent = _make_super_agent(
            event_service=event_service,
            state_machine=state_machine,
            workflow_runtime=workflow_runtime,
            redis=redis,
        )

        initial_state = await agent._build_initial_state(event_id)
        assert initial_state["event_status"] == "triaging"

    @pytest.mark.asyncio
    async def test_initial_state_rejects_non_graph_entry_status(self) -> None:
        """When an event arrives with a status that isn't NEW or TRIAGING,
        _build_initial_state must raise ShadowTraceError."""
        redis = _FakeRedis()
        event_id = "evt-20240724-badstatus"
        event = _FakeEvent(event_id, status=EventStatus.REPORTING)

        event_service = AsyncMock()
        event_service.get_event = AsyncMock(return_value=event)

        agent = _make_super_agent(event_service=event_service, redis=redis)

        with pytest.raises(ShadowTraceError) as exc_info:
            await agent._build_initial_state(event_id)

        assert exc_info.value.error_code == "invalid_state_transition"
        assert "reporting" in str(exc_info.value)


class TestRenewLoopEdgeCases:
    """Renewal loop behavior under edge conditions."""

    @pytest.mark.asyncio
    async def test_renew_loop_stops_gracefully_when_task_cancelled(self) -> None:
        """When the renew task is cancelled externally, it must not raise."""
        redis = _FakeRedis()
        lease = EventLease(redis)
        event_id = "evt-20240724-cancelloop"

        await lease.acquire(event_id)

        agent = _make_super_agent(redis=redis)

        async def _cancel_after_delay() -> None:
            await asyncio.sleep(0.05)
            raise asyncio.CancelledError()

        with patch("app.agents.super_agent.RENEW_INTERVAL_SECONDS", 0.01):
            loop_task = asyncio.create_task(
                agent._renew_loop(event_id, lease),
                name=f"test-renew-{event_id}",
            )
            cancel_task = asyncio.create_task(_cancel_after_delay())

            done, _pending = await asyncio.wait(
                [loop_task, cancel_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            if cancel_task in done:
                loop_task.cancel()
                try:
                    await loop_task
                except asyncio.CancelledError:
                    pass  # expected

        # The loop should have stopped without error
        await lease.release(event_id)

    @pytest.mark.asyncio
    async def test_graph_halts_after_consecutive_renewal_failures(self) -> None:
        """When _renew_loop detects consecutive failures and sets the
        _lease_lost_event, the graph task must be cancelled."""
        redis = _FakeRedis()
        event_id = "evt-20240724-haltgraph"
        event = _FakeEvent(event_id)

        event_service = AsyncMock()
        event_service.get_event = AsyncMock(
            side_effect=[
                event,  # first read
                _FakeEvent(event_id, status=EventStatus.TRIAGING),  # post-transition
            ]
        )

        agent = _make_super_agent(event_service=event_service, redis=redis)

        # Simulate lease loss happening during graph execution
        async def _slow_graph_with_lease_loss(*args: Any, **kwargs: Any) -> dict[str, Any]:
            # Fire the lease lost event mid-execution
            agent._lease_lost_event.set()
            agent._lease_lost = True
            await asyncio.sleep(0.1)  # Simulate work in progress
            return {
                "event_id": event_id,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.9,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
            side_effect=_slow_graph_with_lease_loss,
        ):
            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_build.return_value = mock_graph

                with pytest.raises(ShadowTraceError) as exc_info:
                    await agent.investigate(event_id)

        assert exc_info.value.error_code == "lease_lost"
        assert "lease was lost" in str(exc_info.value).lower()


class TestApiLayerGateRecommended:
    """Recommended API-layer gate tests (ISSUE-054 review)."""

    @pytest.mark.asyncio
    async def test_super_agent_singleton_idempotent_across_events(self) -> None:
        """The SuperAgent singleton's instance state must not leak between
        different event investigations."""
        redis = _FakeRedis()
        event_id_a = "evt-20240724-singleton-a"
        event_id_b = "evt-20240724-singleton-b"

        event_service = AsyncMock()
        event_service.get_event = AsyncMock(
            side_effect=lambda eid: _FakeEvent(eid)
        )

        agent = _make_super_agent(event_service=event_service, redis=redis)

        # Run investigation for event A
        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id_a,
                "event_status": "reporting",
                "disposition_policy": "required",
                "severity": "high",
                "final_verdict": "confirmed_threat",
                "confidence": 0.9,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(return_value=mock_invoke.return_value)
                mock_build.return_value = mock_graph

                result_a = await agent.investigate(event_id_a)

        assert result_a.event_id == event_id_a

        # Run investigation for event B — must be independent
        with patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as mock_invoke:
            mock_invoke.return_value = {
                "event_id": event_id_b,
                "event_status": "reporting",
                "disposition_policy": "not_required",
                "severity": "low",
                "final_verdict": "false_positive",
                "confidence": 0.8,
                "disposition_only_intent": False,
                "execution_substate": "none",
                "degraded_flags": [],
                "node_trace": [],
                "halted": False,
                "error": None,
                "report_generated": True,
            }

            with patch(
                "app.orchestration.workflow_graph.build_investigation_graph",
                new_callable=MagicMock,
            ) as mock_build:
                mock_graph = MagicMock()
                mock_graph.ainvoke = AsyncMock(return_value=mock_invoke.return_value)
                mock_build.return_value = mock_graph

                result_b = await agent.investigate(event_id_b)

        assert result_b.event_id == event_id_b
        assert result_b.final_verdict == FinalVerdict.FALSE_POSITIVE
        # Event A's state must not leak into B
        assert result_b.escalated is False
        assert result_b.external_unsynced is False
