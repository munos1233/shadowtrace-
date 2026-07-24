"""SuperAgent tests (ISSUE-054).

Covers:
1. Golden path: NEW → REPORTING through the full graph
2. Concurrent trigger: second caller receives 409
3. Crash recovery: expired lease allows re-trigger
4. REACT_ENABLED toggle
5. ORCHESTRATION_MODE=analysis_only env gate
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from app.agents.super_agent import SuperAgent
from app.core.errors import InvestigationInProgressError
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ExecutionPlan,
    PlanBudget,
    PlanStep,
    RAGOutput,
    RiskAssessment,
    ScoringMode,
    SuperAgentInput,
    TriageResult,
)
from app.models.enums import DispositionPolicy, EventStatus, EventType, Severity
from app.models.evidence import Evidence
from app.models.report import InvestigationReport
from app.orchestration.lease import generate_owner_id

# --------------------------------------------------------------------------- #
# In-memory EventLease for deterministic testing
# --------------------------------------------------------------------------- #


class _InMemoryEventLease:
    """Drop-in EventLease replacement backed by a dict for unit tests.

    Supports acquire / renew / release with identical semantics to the
    Redis EventLease, including TTL expiry.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float]] = {}

    async def acquire(self, event_id: str, owner_id: str, ttl_s: int = 600) -> bool:
        now = time.monotonic()
        entry = self._store.get(event_id)
        if entry is not None:
            current_owner, expiry = entry
            if now < expiry and current_owner != owner_id:
                return False
        self._store[event_id] = (owner_id, now + ttl_s)
        return True

    async def renew(self, event_id: str, owner_id: str) -> bool:
        now = time.monotonic()
        entry = self._store.get(event_id)
        if entry is None:
            # Lease expired / released — cannot renew.
            return False
        current_owner, _expiry = entry
        if current_owner != owner_id:
            return False
        self._store[event_id] = (owner_id, now + 600)
        return True

    async def release(self, event_id: str, owner_id: str) -> bool:
        entry = self._store.get(event_id)
        if entry is None:
            return True
        if entry[0] != owner_id:
            return False
        del self._store[event_id]
        return True

    async def get_owner(self, event_id: str) -> str | None:
        entry = self._store.get(event_id)
        if entry is None:
            return None
        current_owner, expiry = entry
        if time.monotonic() >= expiry:
            del self._store[event_id]
            return None
        return current_owner

    async def start_renewal(
        self,
        event_id: str,
        owner_id: str,
        *,
        on_renewal_failed: asyncio.Event | None = None,
    ) -> asyncio.Task[None]:
        """No-op renewal for testing."""

        async def _noop() -> None:
            pass

        return asyncio.create_task(_noop())


# --------------------------------------------------------------------------- #
# Mock event service for tests
# --------------------------------------------------------------------------- #


class _MockEventService:
    """Minimal event service backed by a dict so ``SuperAgent._transition``
    actually updates event status during tests."""

    def __init__(self, events: dict[str, dict[str, object]] | None = None) -> None:
        self.events: dict[str, dict[str, object]] = events or {}

    async def transition_status(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: object | None = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> None:
        del context, operator, reason
        entry = self.events.get(event_id)
        if entry is not None:
            entry["status"] = target

    async def get_event(self, event_id: str) -> dict[str, object] | None:
        return self.events.get(event_id)


# --------------------------------------------------------------------------- #
# Stub agents
# --------------------------------------------------------------------------- #

_EVENT_ID = "evt-20260724-a1b2c3d4"
_EVENT_ID_2 = "evt-20260724-b2c3d4e5"


def _make_triage(
    event_type: EventType = EventType.DATA_EXFILTRATION,
    severity: Severity = Severity.HIGH,
) -> TriageResult:
    return TriageResult(
        event_type=event_type,
        severity=severity,
        need_investigation=True,
        reasoning="Test triage — data exfiltration detected",
    )


def _make_evidence(event_id: str = _EVENT_ID) -> EvidenceOutput:
    return EvidenceOutput(
        evidence_list=[
            Evidence(
                evidence_id=f"evd-{event_id[-8:]}01",
                event_id=event_id,
                evidence_type="network_flow",
                source="endpoint",  # type: ignore[arg-type]
                description="Suspicious outbound connection",
                confidence=0.85,
            )
        ],
        conflicts=[],
        gaps=[],
        success_sources=["network_flow", "endpoint"],
        failed_sources=[],
        overall_confidence=0.85,
        collection_status=CollectionStatus.COMPLETED,
    )


def _make_plan(event_id: str = _EVENT_ID) -> ExecutionPlan:
    return ExecutionPlan(
        plan_id=f"pln-{event_id[-8:]}01",
        event_id=event_id,
        steps=[
            PlanStep(
                step_order=1,
                step_goal="Collect evidence",
                assigned_agent="evidence_agent",
                required_tools=["query_network_flow"],
                success_criteria="at least 1 evidence source",
            ),
            PlanStep(
                step_order=2,
                step_goal="RAG enhancement",
                assigned_agent="rag_agent",
                required_tools=[],
                success_criteria="retrieved relevant knowledge",
            ),
            PlanStep(
                step_order=3,
                step_goal="Risk assessment",
                assigned_agent="risk_agent",
                required_tools=[],
                success_criteria="risk_score >= 70",
            ),
        ],
        budget=PlanBudget(),
        revision=0,
    )


def _make_risk(event_id: str = _EVENT_ID) -> RiskAssessment:
    return RiskAssessment(
        risk_score=85,
        severity=Severity.HIGH,
        confidence=0.9,
        risk_factors=[],
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _make_rag() -> RAGOutput:
    return RAGOutput(
        attack_techniques=[],
        similar_cases=[],
        playbook_refs=[],
        citations=[],
        degraded=False,
    )


def _make_report(event_id: str = _EVENT_ID) -> InvestigationReport:
    from app.models.ids import report_id_for_event

    return InvestigationReport(
        report_id=report_id_for_event(event_id),
        event_id=event_id,
        title="Investigation Report",
    )


class _StubTriageAgent:
    """Returns a pre-configured TriageResult."""

    agent_name = "triage_agent"

    def __init__(self, result: TriageResult | None = None) -> None:
        self.result = result or _make_triage()

    async def execute(self, input: Any) -> Any:
        return self.result


class _StubEvidenceAgent:
    agent_name = "evidence_agent"

    def __init__(self, result: EvidenceOutput | None = None) -> None:
        self.result = result or _make_evidence()

    async def execute(self, input: Any) -> Any:
        return self.result


class _StubRiskAgent:
    agent_name = "risk_agent"

    def __init__(self, result: RiskAssessment | None = None) -> None:
        self.result = result or _make_risk()

    async def execute(self, input: Any) -> Any:
        return self.result


class _StubReportAgent:
    agent_name = "report_agent"

    def __init__(self, result: InvestigationReport | None = None) -> None:
        self.result = result or _make_report()

    async def execute(self, input: Any) -> Any:
        return self.result


class _StubRAGAgent:
    agent_name = "rag_agent"

    def __init__(self, result: RAGOutput | None = None) -> None:
        self.result = result or _make_rag()

    async def execute(self, input: Any) -> Any:
        return self.result


class _FailingRAGAgent:
    agent_name = "rag_agent"

    async def execute(self, input: Any) -> Any:
        raise RuntimeError("rag unavailable")


class _StubPlannerAgent:
    agent_name = "planner_agent"

    def __init__(self, plan: ExecutionPlan | None = None) -> None:
        self.plan = plan or _make_plan()

    async def execute(self, input: Any) -> ExecutionPlan:
        return self.plan


# --------------------------------------------------------------------------- #
# SuperAgent builder helper
# --------------------------------------------------------------------------- #


def _build_super_agent(
    *,
    event_id: str = _EVENT_ID,
    triage: TriageResult | None = None,
    evidence: EvidenceOutput | None = None,
    plan: ExecutionPlan | None = None,
    risk: RiskAssessment | None = None,
    report: InvestigationReport | None = None,
    rag: Any | None = None,
    lease: _InMemoryEventLease | None = None,
    event_service: _MockEventService | None = None,
    react_enabled: bool = False,
) -> SuperAgent:
    """Build a SuperAgent with stub agents for isolated testing."""
    return SuperAgent(
        triage_agent=_StubTriageAgent(triage or _make_triage()),
        evidence_agent=_StubEvidenceAgent(evidence or _make_evidence(event_id)),
        planner_agent=_StubPlannerAgent(plan or _make_plan(event_id)),  # type: ignore[arg-type]
        rag_agent=rag if rag is not None else _StubRAGAgent(),  # type: ignore[arg-type]
        risk_agent=_StubRiskAgent(risk or _make_risk(event_id)),
        report_agent=_StubReportAgent(report or _make_report(event_id)),
        lease=lease,  # type: ignore[arg-type]
        event_service=event_service,  # type: ignore[arg-type]
        react_enabled=react_enabled,
    )


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

pytestmark = pytest.mark.asyncio


class TestSuperAgentGoldenPath:
    """Scenario 1: The graph drives a full investigation NEW → REPORTING."""

    async def test_graph_runs_to_reporting(self) -> None:
        """A basic golden-path run reaches REPORTING status."""
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)
        agent = _build_super_agent(event_service=event_service)
        await agent.investigate(_EVENT_ID)

        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING

    async def test_investigate_via_base_agent_execute(self) -> None:
        """``SuperAgent.execute(SuperAgentInput)`` returns AgentOutput."""
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)
        agent = _build_super_agent(event_service=event_service)
        input = SuperAgentInput(event_id=_EVENT_ID)
        result = await agent.execute(input)

        assert result.agent_name == "super_agent"
        assert result.success is True
        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING

    async def test_graph_survives_rag_failure(self) -> None:
        """RAG failure must not block the main pipeline (降级策略)."""
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)
        agent = _build_super_agent(rag=_FailingRAGAgent(), event_service=event_service)
        await agent.investigate(_EVENT_ID)

        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING
        # Graph completed despite RAG failure.

    async def test_graph_with_different_event_types(self) -> None:
        """The graph works with different event types and severities."""
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)
        triage = _make_triage(EventType.HOST_COMPROMISE, Severity.CRITICAL)
        agent = _build_super_agent(triage=triage, event_service=event_service)
        await agent.investigate(_EVENT_ID)

        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING

    async def test_graph_fast_close_when_no_investigation_needed(self) -> None:
        """When triage returns need_investigation=False, the graph fast-closes."""
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {
                "status": EventStatus.NEW,
                "disposition_policy": DispositionPolicy.NOT_REQUIRED,
            },
        }
        event_service = _MockEventService(events)
        triage = TriageResult(
            event_type=EventType.OTHER,
            severity=Severity.LOW,
            need_investigation=False,
            reasoning="False positive — known test traffic",
        )
        agent = _build_super_agent(triage=triage, event_service=event_service)
        await agent.investigate(_EVENT_ID)

        # Should go directly to CLOSED via close_node, not REPORTING.
        assert events[_EVENT_ID]["status"] == EventStatus.CLOSED


class TestConcurrentTrigger:
    """Scenario 2: Two concurrent calls — only one acquires the lease."""

    async def test_second_trigger_raises_investigation_in_progress(self) -> None:
        """The first caller holds the lease; the second must get a 409."""
        lease = _InMemoryEventLease()
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)
        agent2 = _build_super_agent(lease=lease, event_service=event_service)

        # Acquire the lease manually to simulate a running orchestration.
        owner = generate_owner_id()
        acquired = await lease.acquire(_EVENT_ID, owner)
        assert acquired is True

        # Now agent2 tries to investigate — should fail.
        with pytest.raises(InvestigationInProgressError) as exc:
            await agent2.investigate(_EVENT_ID)
        assert exc.value.error_code == "investigation_in_progress"

        # Release and re-trigger should succeed.
        await lease.release(_EVENT_ID, owner)
        agent3 = _build_super_agent(lease=lease, event_service=event_service)
        await agent3.investigate(_EVENT_ID)
        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING


class TestLeaseExpiryRecovery:
    """Scenario 3: Expired or released lease allows re-trigger."""

    async def test_expired_lease_allows_retrigger(self) -> None:
        """After a short TTL, a new caller can acquire the lease."""
        lease = _InMemoryEventLease()
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)

        # Acquire with a very short TTL — immediately expired.
        owner1 = generate_owner_id()
        acquired = await lease.acquire(_EVENT_ID, owner1, ttl_s=0)  # immediately expired
        assert acquired is True

        # Lease expired — investigation should succeed.
        agent2 = _build_super_agent(lease=lease, event_service=event_service)
        await agent2.investigate(_EVENT_ID)
        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING

    async def test_release_after_completion_allows_retrigger(self) -> None:
        """After a successful run the lease is released."""
        lease = _InMemoryEventLease()
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)
        agent1 = _build_super_agent(lease=lease, event_service=event_service)

        await agent1.investigate(_EVENT_ID)
        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING

        # Lease should be released; subsequent investigation succeeds.
        events[_EVENT_ID]["status"] = EventStatus.NEW  # reset for re-run
        agent2 = _build_super_agent(lease=lease, event_service=event_service)
        await agent2.investigate(_EVENT_ID)
        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING

    async def test_different_events_no_conflict(self) -> None:
        """Different event IDs do not interfere with each other."""
        lease = _InMemoryEventLease()
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
            _EVENT_ID_2: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)

        # Should be possible to investigate two different events concurrently.
        owner = generate_owner_id()
        ok = await lease.acquire(_EVENT_ID, owner)
        assert ok is True

        agent2 = _build_super_agent(event_id=_EVENT_ID_2, lease=lease, event_service=event_service)
        # Different event_id — no conflict.
        await agent2.investigate(_EVENT_ID_2)
        assert events[_EVENT_ID_2]["status"] == EventStatus.REPORTING


class TestReactEnabled:
    """Scenario 4: REACT_ENABLED toggle behaviour."""

    async def test_react_disabled_by_default(self) -> None:
        """When REACT_ENABLED is False, the graph runs without ReAct."""
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)
        agent = _build_super_agent(react_enabled=False, event_service=event_service)
        await agent.investigate(_EVENT_ID)
        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING

    async def test_react_enabled_without_executor_raises_at_startup(self) -> None:
        """REACT_ENABLED=true without executor must fail closed at startup."""
        from app.core.config import Settings
        from app.core.errors import ConfigurationError
        from app.orchestration.orchestration_config import assert_graph_orchestration_config

        settings = Settings(REACT_ENABLED=True)
        with pytest.raises(ConfigurationError) as exc:
            assert_graph_orchestration_config(settings)
        assert exc.value.error_code == "configuration_error"


class TestOrchestrationModeGate:
    """Scenario 5: ORCHESTRATION_MODE=analysis_only env gate."""

    async def test_analysis_only_mode_blocks_live_side_effects(self) -> None:
        """analysis_only with live switches must fail at startup."""
        from app.core.config import Settings
        from app.core.errors import ConfigurationError
        from app.services.analysis_only_pipeline import assert_analysis_only_mode

        # Simulate a live config.
        settings = Settings(
            SOURCE_MODE="mock_xdr",
            DISPOSITION_MODE="mock_xdr",
            ALLOW_LIVE_SIDE_EFFECTS="true",
            ALLOW_XDR_WRITEBACK="false",
        )
        with pytest.raises(ConfigurationError):
            assert_analysis_only_mode(settings)

    async def test_analysis_only_mode_ok_with_mock(self) -> None:
        """analysis_only mode with pure mock settings passes."""
        from app.core.config import Settings
        from app.services.analysis_only_pipeline import assert_analysis_only_mode

        settings = Settings(
            SOURCE_MODE="mock_xdr",
            DISPOSITION_MODE="mock_xdr",
            ALLOW_LIVE_SIDE_EFFECTS="false",
            ALLOW_XDR_WRITEBACK="false",
        )
        # Should not raise.
        assert_analysis_only_mode(settings)

    async def test_graph_mode_ok_without_react(self) -> None:
        """graph mode with REACT_ENABLED=false passes startup gate."""
        from app.core.config import Settings
        from app.orchestration.orchestration_config import assert_orchestration_mode

        settings = Settings(
            ORCHESTRATION_MODE="graph",
            REACT_ENABLED=False,
        )
        assert_orchestration_mode(settings)

    async def test_unsupported_orchestration_mode_raises(self) -> None:
        from app.core.config import Settings
        from app.core.errors import ConfigurationError
        from app.orchestration.orchestration_config import assert_orchestration_mode

        settings = Settings(ORCHESTRATION_MODE="celery")
        with pytest.raises(ConfigurationError):
            assert_orchestration_mode(settings)


class TestEventLeaseInterface:
    """Unit tests for the in-memory EventLease contract."""

    async def test_acquire_release_cycle(self) -> None:
        lease = _InMemoryEventLease()
        owner = generate_owner_id()

        assert await lease.acquire(_EVENT_ID, owner) is True
        assert await lease.get_owner(_EVENT_ID) == owner
        assert await lease.acquire(_EVENT_ID, "worker-other") is False
        assert await lease.release(_EVENT_ID, owner) is True
        assert await lease.get_owner(_EVENT_ID) is None

    async def test_renew_maintains_ownership(self) -> None:
        lease = _InMemoryEventLease()
        owner = generate_owner_id()

        await lease.acquire(_EVENT_ID, owner, ttl_s=600)
        assert await lease.renew(_EVENT_ID, owner) is True
        assert await lease.renew(_EVENT_ID, "worker-other") is False

    async def test_owner_id_format(self) -> None:
        owner = generate_owner_id()
        assert owner.startswith("worker-")
        assert len(owner) == len("worker-") + 8  # 8 hex chars


class TestGraphWithoutLease:
    """SuperAgent without a lease should still complete (dev/test mode)."""

    async def test_no_lease_runs_graph(self) -> None:
        events: dict[str, dict[str, object]] = {
            _EVENT_ID: {"status": EventStatus.NEW},
        }
        event_service = _MockEventService(events)
        agent = _build_super_agent(lease=None, event_service=event_service)
        await agent.investigate(_EVENT_ID)
        assert events[_EVENT_ID]["status"] == EventStatus.REPORTING
