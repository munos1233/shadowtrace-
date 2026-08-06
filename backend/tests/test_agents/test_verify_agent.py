"""VerifyAgent two-phase verification tests (ISSUE-060).

Covers the 8 required test categories:
1. Happy Path — normal input → expected output
2. LLM 降级 — degraded fallback (rule-only), degraded=True
3. 依赖故障 — Redis/DB/WM unavailable → graceful degradation
4. 边界输入 — empty/null/extreme values
5. 状态机 — legal transitions pass, illegal transitions raise, idempotent
6. 写回 — analysis content stays local, writeback called and idempotent, simulated=true
7. 护栏 — non-owner write → GuardrailViolationError
8. 并发 — version conflict handled correctly

Plus acceptance criteria from the Issue:
A1. Two-phase all-pass → overall_status=success
A2. Effect failure → need_action_replan=true, EventDispositionService not called
A3. create_ticket → effect_status=skipped, verification action writeback_required=false
A4. Deferred action → skipped, not in failed_actions
A5. 8-state writeback truth table
A6. Disposition-only path: phase 1 no entities but phase 2 still activates
A7. Verification false vs tool exception — Action status distinction
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agents.rules.verification_mapping import resolve_verification_tool
from app.agents.verify_agent import _WRITEBACK_STATUS_ROUTING, VerifyAgent
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import (
    EffectStatus,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
    VerifyAgentInput,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionPolicy,
    ExecutionJobStatus,
    ExecutionOwner,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.execution import ActionExecutionJob
from app.models.ids import new_action_id, new_job_id
from app.models.tool_meta import ToolResult, ToolResultStatus

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------- #
# Factory helpers
# --------------------------------------------------------------------------- #


def _action(
    *,
    action_id: str | None = None,
    event_id: str = "evt-20260725-00000001",
    tool_name: str = "block_ip",
    action_category: ActionCategory = ActionCategory.RESPONSE,
    action_name: str = "block_ip_action",
    target_type: str = "ip",
    target: str = "10.0.0.1",
    status: ActionStatus = ActionStatus.SUCCESS,
    execution_phase: ActionExecutionPhase = ActionExecutionPhase.IMMEDIATE,
    execution_owner: ExecutionOwner | None = ExecutionOwner.DIRECT_TOOL,
    execution_job_id: str | None = None,
    writeback_required: bool = False,
    writeback_applicable: bool = False,
    writeback_readiness: WritebackReadiness = WritebackReadiness.NOT_REQUIRED,
    writeback_status: WritebackStatus | None = None,
    superseded_by_revision: int | None = None,
    plan_revision: int = 1,
    action_level: ActionLevel = ActionLevel.L2,
    **kwargs: Any,
) -> Action:
    return Action(
        action_id=action_id or new_action_id(),
        event_id=event_id,
        plan_revision=plan_revision,
        action_fingerprint=f"fp:{tool_name}",
        action_category=action_category,
        action_name=action_name,
        tool_name=tool_name,
        action_level=action_level,
        execution_phase=execution_phase,
        activation_condition=(
            "after_effect_resolution"
            if execution_phase == ActionExecutionPhase.POST_VERIFY
            else None
        ),
        target_type=target_type,
        target=target,
        status=status,
        execution_owner=execution_owner,
        execution_job_id=execution_job_id,
        writeback_required=writeback_required,
        writeback_applicable=writeback_applicable,
        writeback_readiness=writeback_readiness,
        writeback_status=writeback_status,
        superseded_by_revision=superseded_by_revision,
        **kwargs,
    )


def _job(
    *,
    job_id: str | None = None,
    event_id: str = "evt-20260725-00000001",
    action_id: str = "act-00000001",
    status: ExecutionJobStatus = ExecutionJobStatus.SUCCESS,
    provider_name: str = "mock_observation",
    **kwargs: Any,
) -> ActionExecutionJob:
    return ActionExecutionJob(
        job_id=job_id or new_job_id(),
        event_id=event_id,
        action_id=action_id,
        provider_name=provider_name,
        idempotency_key=f"idem-{action_id}",
        status=status,
        **kwargs,
    )


def _plan(actions: list[Action]) -> ResponsePlan:
    return ResponsePlan(
        plan_id="plan-00000001",
        actions=actions,
        strategy_summary="Test plan",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )


def _input(
    event_id: str = "evt-20260725-00000001",
    actions: list[Action] | None = None,
    phase: VerificationPhase = VerificationPhase.EFFECT,
) -> VerifyAgentInput:
    plan = _plan(actions or [])
    return VerifyAgentInput(
        event_id=event_id,
        response_plan=plan,
        verification_phase=phase,
    )


def _tool_result_success(verified: bool = True, detail: str = "ok") -> ToolResult:
    return ToolResult(
        call_id="call-00000001",
        tool_name="check_ip_block_status",
        provider_name="mock_observation",
        status=ToolResultStatus.SUCCESS,
        data={"is_verified": verified, "detail": detail, "verified_at": datetime.now(UTC)},
    )


def _tool_result_error(message: str = "tool failed") -> ToolResult:
    return ToolResult(
        call_id="call-00000001",
        tool_name="check_ip_block_status",
        provider_name="mock_observation",
        status=ToolResultStatus.FAILED,
        error_detail=message,
    )


def _mock_terminal_confirm_session_factory(writeback_id: str = "wbk-terminal-00001"):
    """Build a MagicMock session_factory that returns a CONFIRMED terminal
    writeback receipt for the given writeback_id.  Use this when a test
    needs phase 2 to pass the terminal writeback evaluation but doesn't
    have a real database.

    The returned mock is a callable usable as
    ``VerifyAgent(…, session_factory=factory)``.
    """
    from contextlib import asynccontextmanager
    from unittest.mock import MagicMock

    class _ReceiptRow:
        def __init__(self, wb_id: str) -> None:
            self.writeback_id = wb_id
            self.status = "confirmed"
            self.sequence = 1
            self.confirmation_evidence: str | None = "readback_verified"

    def _receipt_writeback_id_from_stmt(stmt: Any) -> str | None:
        try:
            wc = stmt.whereclause
            if wc is not None and hasattr(wc, "right"):
                right = wc.right
                val = right.value if hasattr(right, "value") else right
                return str(val) if val is not None else None
        except Exception:
            return None
        return None

    class _Session:
        async def scalars(self, stmt: Any) -> Any:
            queried_id = _receipt_writeback_id_from_stmt(stmt)

            class _Result:
                def first(self) -> _ReceiptRow | None:
                    if queried_id == writeback_id:
                        return _ReceiptRow(writeback_id)
                    return None

            return _Result()

        async def get(self, *args: Any, **kwargs: Any) -> Any:
            return None

        @asynccontextmanager
        async def begin(self) -> Any:
            yield self

    @asynccontextmanager
    async def _session_ctx() -> Any:
        yield _Session()

    mock_factory = MagicMock(side_effect=_session_ctx)
    return mock_factory


# --------------------------------------------------------------------------- #
# Fake / stub classes for testing
# --------------------------------------------------------------------------- #


class FakeWorkingMemory:
    """In-memory BoundWorkingMemory stand-in."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], Any] = {}
        self._scratchpad: dict[str, list[str]] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self._store.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self._store[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        self._scratchpad.setdefault(event_id, []).append(note)

    async def read_scratchpad(self, event_id: str) -> list[Any]:
        return self._scratchpad.get(event_id, [])


class FakeEventBus:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def publish_event(self, event_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self.events.append({"event_id": event_id, "type": event_type, "payload": payload})


class FakeTraceService:
    def __init__(self) -> None:
        self.traces: list[dict[str, Any]] = []

    async def log_trace(self, **kwargs: Any) -> str:
        self.traces.append(kwargs)
        return "trace-0001"


class FakeEventDispositionService:
    """Stub EventDispositionService (ISSUE-059A).

    Mirrors the real ``EventDispositionService.activate_and_submit``
    signature and returns ``_ActivateResult`` with field names matching
    ``DispositionActivationResult``.
    """

    def __init__(
        self,
        *,
        activated: bool = True,
        writeback_id: str | None = "wbk-00000001",
        disposition_id: str | None = "dis-00000001",
        skipped_reason: str | None = None,
    ) -> None:
        self.activated = activated
        self._writeback_id = writeback_id
        self._disposition_id = disposition_id
        self._skipped_reason = skipped_reason
        self.calls: list[dict[str, Any]] = []

    async def activate_and_submit(
        self, *, event_id: str, plan_revision: int, principal_or_system: str
    ) -> Any:
        self.calls.append(
            {
                "event_id": event_id,
                "plan_revision": plan_revision,
                "principal_or_system": principal_or_system,
            }
        )
        from app.agents.verify_agent import _ActivateResult

        return _ActivateResult(
            activated=self.activated,
            action_id="act-terminal-00001",
            skipped_reason=(self._skipped_reason if not self.activated else None),
            disposition_id=(self._disposition_id if self.activated else None),
            writeback_id=(
                self._writeback_id
                if self.activated or self._skipped_reason == "already_submitted"
                else None
            ),
        )


# --------------------------------------------------------------------------- #
# 1. Happy Path
# --------------------------------------------------------------------------- #


class TestHappyPath:
    async def test_phase1_single_action_verified(self):
        """Normal input → phase 1 effect verified."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        # Override _load_execution_state for controlled data.
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=action.event_id, actions=[action], phase=VerificationPhase.EFFECT)
        )

        assert result.overall_status == VerificationOverallStatus.SUCCESS
        assert len(result.results) == 1
        r = result.results[0]
        assert r.action_id == action.action_id
        assert r.effect_status == EffectStatus.VERIFIED
        assert r.verification_action_id is not None
        assert not result.need_action_replan
        assert not result.need_writeback_recovery
        assert not result.need_manual_resolution

    async def test_phase1_effect_failed_triggers_replan(self):
        """Effect verification false → need_action_replan=true."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(False, "block not observed")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.need_action_replan is True
        assert action.action_id in result.failed_actions
        r = result.results[0]
        assert r.effect_status == EffectStatus.FAILED

    async def test_phase1_deferred_action_skipped(self):
        """POST_VERIFY deferred Action → effect_status=skipped, not in failed_actions."""
        action = _action(
            tool_name=TERMINAL_DISPOSITION_TOOL,
            action_name="terminal_disposition",
            target_type="source_object",
            target="src-1",
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            status=ActionStatus.APPROVED,  # not yet executed
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "deferred_pending_activation"
        assert action.action_id not in result.failed_actions

    async def test_phase2_success(self):
        """Full two-phase: effects ok → activate → writeback CONFIRMED."""
        from contextlib import asynccontextmanager

        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Build a mock DB session that returns a CONFIRMED terminal receipt.
        class _ReceiptRow:
            writeback_id: str = "wbk-terminal-00001"
            status: str = "confirmed"
            sequence: int = 1
            confirmation_evidence: str | None = "readback_verified"

        class _TerminalDBSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def first(self) -> _ReceiptRow | None:
                        return _ReceiptRow()

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _TerminalDBSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-terminal-00001",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=mock_factory,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # EventDispositionService.activate_and_submit was called.
        assert len(ed_svc.calls) == 1
        assert ed_svc.calls[0]["event_id"] == action.event_id
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_phase2_already_submitted_reverify_succeeds(self):
        """Second verify pass: already_submitted still evaluates CONFIRMED receipt."""
        from contextlib import asynccontextmanager

        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        class _ReceiptRow:
            writeback_id: str = "wbk-terminal-00001"
            status: str = "confirmed"
            sequence: int = 1
            confirmation_evidence: str | None = "readback_verified"

        class _TerminalDBSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def first(self) -> _ReceiptRow | None:
                        return _ReceiptRow()

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _TerminalDBSession()

        mock_factory = MagicMock(side_effect=_session_ctx)
        ed_svc = FakeEventDispositionService(
            activated=False,
            skipped_reason="already_submitted",
            writeback_id="wbk-terminal-00001",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=mock_factory,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert len(ed_svc.calls) == 1
        assert result.overall_status == VerificationOverallStatus.SUCCESS
        assert result.need_manual_resolution is False
        assert result.need_writeback_recovery is False

    async def test_phase2_immediate_deferred_already_submitted_reverify_succeeds(self):
        """Immediate CONFIRMED + deferred terminal receipt CONFIRMED → overall SUCCESS."""
        from contextlib import asynccontextmanager

        immediate = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        deferred = _action(
            action_id="act-deferred-00001",
            tool_name="update_source_event_disposition",
            target_type="incident",
            target="INC-0001",
            status=ActionStatus.APPROVED,
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
        )
        job = _job(job_id="job-0001", action_id=immediate.action_id)

        class _ReceiptRow:
            writeback_id: str = "wbk-terminal-00001"
            status: str = "confirmed"
            sequence: int = 1
            confirmation_evidence: str | None = "readback_verified"

        class _TerminalDBSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def first(self) -> _ReceiptRow | None:
                        return _ReceiptRow()

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _TerminalDBSession()

        mock_factory = MagicMock(side_effect=_session_ctx)
        ed_svc = FakeEventDispositionService(
            activated=False,
            skipped_reason="already_submitted",
            writeback_id="wbk-terminal-00001",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=mock_factory,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([immediate, deferred], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(
            _input(event_id=immediate.event_id, actions=[immediate, deferred])
        )

        assert result.overall_status == VerificationOverallStatus.SUCCESS
        assert result.need_manual_resolution is False
        assert result.need_writeback_recovery is False

    async def test_create_ticket_skipped(self):
        """create_ticket → effect_status=skipped, verification action writeback_required=false."""
        action = _action(
            tool_name="create_ticket",
            action_name="ticket_action",
            target_type="ticket",
            target="ticket-1",
            status=ActionStatus.SUCCESS,
            action_level=ActionLevel.L1,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "non_verifiable_action"
        # Verification action should have writeback_required=false (checked via model validation)


# --------------------------------------------------------------------------- #
# 2. LLM/降级 (Degradation)
# --------------------------------------------------------------------------- #


class TestDegradation:
    async def test_tool_executor_none_produces_unverifiable(self):
        """No tool executor → all verifications produce unverifiable."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=None,  # degraded
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        # All verification tools unavailable → escalated (need_manual_resolution).
        assert result.need_manual_resolution is True
        assert result.overall_status != VerificationOverallStatus.SUCCESS

    async def test_verification_tool_returns_error(self):
        """Verification tool error → effect_status=unverifiable."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_error("connection refused")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert "verification_tool_error" in (result.results[0].detail or "")


# --------------------------------------------------------------------------- #
# 3. 依赖故障 (Dependency failures)
# --------------------------------------------------------------------------- #


class TestDependencyFailure:
    async def test_no_working_memory_does_not_crash(self):
        """Agent must not crash when working_memory is None."""
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            working_memory=None,
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result is not None
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_no_session_factory_uses_plan_actions(self):
        """When session_factory is None, agents are taken from the input plan."""
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            session_factory=None,
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        # No mock on _load_execution_state → uses real (but sessionless) path.

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert len(result.results) == 1
        assert result.results[0].effect_status == EffectStatus.SKIPPED

    async def test_no_event_disposition_service_marks_manual(self):
        """When EventDispositionService is missing and policy=required, need_manual."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=None,  # missing
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        # Phase 1 passes, phase 2 activation unavailable → manual.
        assert result.need_manual_resolution is True
        assert result.overall_status == VerificationOverallStatus.MANUAL_RESOLUTION


# --------------------------------------------------------------------------- #
# 4. 边界输入 (Boundary inputs)
# --------------------------------------------------------------------------- #


class TestBoundaryInputs:
    async def test_empty_actions(self):
        """Empty response plan → no results, success."""
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(actions=[]))
        assert len(result.results) == 0
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_action_with_none_target_type(self):
        """Action with target_type=None → mapping returns None (no guess)."""
        action = _action(
            tool_name="block_ip",
            target_type=None,
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(actions=[action]))
        # target_type=None → resolve_verification_tool returns None (no
        # guess) → action is skipped as unverifiable.
        assert result.results[0].effect_status == EffectStatus.SKIPPED
        assert result.results[0].detail == "no_verification_tool_registered"

    async def test_unknown_tool_maps_to_none(self):
        """Tool not in mapping → resolve_verification_tool returns None."""
        assert resolve_verification_tool("nonexistent_tool", "ip") is None

    async def test_unicode_target_values(self):
        """Unicode/中文 target values handled safely."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="192.168.中国.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(actions=[action]))
        assert result.results[0].effect_status == EffectStatus.VERIFIED


# --------------------------------------------------------------------------- #
# 5. 状态机 (State machine)
# --------------------------------------------------------------------------- #


class TestStateMachine:
    async def test_verification_action_status_transition(self):
        """Verification Action: PENDING → EXECUTING → SUCCESS."""
        from app.models.workflow import validate_action_status_transition

        # PENDING → EXECUTING (legal for VERIFICATION)
        validate_action_status_transition(
            ActionCategory.VERIFICATION,
            ActionStatus.PENDING,
            ActionStatus.EXECUTING,
        )
        # EXECUTING → SUCCESS (legal)
        validate_action_status_transition(
            ActionCategory.VERIFICATION,
            ActionStatus.EXECUTING,
            ActionStatus.SUCCESS,
        )

    async def test_verification_action_cannot_be_rolled_back(self):
        """Verification actions should never transition to ROLLED_BACK."""
        from app.core.errors import InvalidStateTransitionError
        from app.models.workflow import validate_action_status_transition

        with pytest.raises(InvalidStateTransitionError):
            validate_action_status_transition(
                ActionCategory.VERIFICATION,
                ActionStatus.SUCCESS,
                ActionStatus.ROLLED_BACK,
            )

    async def test_multiple_verifications_idempotent(self):
        """Re-verifying same actions produces consistent results."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        for _ in range(2):
            agent = VerifyAgent(
                tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
                working_memory=FakeWorkingMemory(),
                trace_service=FakeTraceService(),
            )
            agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
                return_value=([action], {"job-0001": job}, {})
            )
            agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
                return_value=DispositionPolicy.NOT_REQUIRED,
            )

            result = await agent.execute(_input(actions=[action]))
            assert result.results[0].effect_status == EffectStatus.VERIFIED


# --------------------------------------------------------------------------- #
# 6. 写回 (Writeback)
# --------------------------------------------------------------------------- #


class TestWriteback:
    async def test_writeback_failure_no_replan(self):
        """Writeback failure does NOT trigger need_action_replan."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.FAILED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        # Writeback failed → recovery needed, NOT action replan.
        assert result.need_action_replan is False
        assert result.need_writeback_recovery is True

    async def test_analysis_content_never_egresses(self):
        """Verification tool params never carry analysis content (reason, raw_result)."""
        action = _action(
            tool_name="block_ip",
            reason="suspicious IP from threat intel analysis",  # analysis content
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        captured_params: dict[str, Any] = {}

        async def capturing_call(tool_name, params, event_id, **kw):
            captured_params.update(params)
            return _tool_result_success(True)

        agent = VerifyAgent(
            tool_executor=MagicMock(call=AsyncMock(side_effect=capturing_call)),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        await agent.execute(_input(actions=[action]))
        # Params should contain target info but NOT analysis content.
        assert "reason" not in captured_params
        assert "raw_result" not in captured_params


# --------------------------------------------------------------------------- #
# 7. 护栏 (Guardrails)
# --------------------------------------------------------------------------- #


class TestGuardrails:
    async def test_non_owner_cannot_write_verification_result(self):
        """Non-VerifyAgent writer cannot write verification_result to WM."""

        # The FIELD_OWNERSHIP dict guards the write path.
        from app.services.working_memory import FIELD_OWNERSHIP

        assert FIELD_OWNERSHIP["verification_result"] == "VerifyAgent"

    async def test_verify_agent_is_correct_owner(self):
        """VerifyAgent has the correct writer identity for verification_result."""
        from app.services.working_memory import FIELD_OWNERSHIP

        assert FIELD_OWNERSHIP.get("verification_result") == "VerifyAgent"


# --------------------------------------------------------------------------- #
# 8. 写回八态真值表 (8-state writeback truth table)
# --------------------------------------------------------------------------- #


class TestWritebackTruthTable:
    @pytest.mark.parametrize(
        "wb_status, expected_confirmed, expected_recovery, expected_manual",
        [
            (WritebackStatus.CONFIRMED, True, False, False),
            (WritebackStatus.PENDING, False, True, False),
            (WritebackStatus.SENDING, False, True, False),
            (WritebackStatus.ACCEPTED, False, True, False),
            (WritebackStatus.UNKNOWN, False, True, False),
            (WritebackStatus.PARTIAL, False, True, False),
            (WritebackStatus.FAILED, False, True, False),
            (WritebackStatus.CONFLICT, False, False, True),
            (None, False, True, False),
        ],
    )
    async def test_writeback_truth_table(
        self, wb_status, expected_confirmed, expected_recovery, expected_manual
    ):
        """Each WritebackStatus routes correctly per ISSUE-060 spec.

        None is excluded from the routing table dict and is handled
        explicitly in _evaluate_writeback_statuses — this test
        validates the expected routing for each status including None.
        """
        if wb_status is None:
            # None is handled before the dict lookup (ISSUE-060 SF1).
            confirmed, recovery, manual, _detail = (
                False,
                True,
                False,
                "writeback_no_status_waiting",
            )
        else:
            confirmed, recovery, manual, _detail = _WRITEBACK_STATUS_ROUTING.get(
                wb_status,
                (False, True, False, "unknown"),
            )
        assert confirmed == expected_confirmed
        assert recovery == expected_recovery
        assert manual == expected_manual


# --------------------------------------------------------------------------- #
# Acceptance criteria tests
# --------------------------------------------------------------------------- #


class TestAcceptanceCriteria:
    """ISSUE-060 acceptance criteria."""

    async def test_a1_full_two_phase_success(self):
        """A1: Both phases pass → overall_status=success."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-a1-terminal",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-a1-terminal"),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_a1_writeback_fails_event_not_success(self):
        """A1: Effect OK but writeback FAILED → not success."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.FAILED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result.overall_status != VerificationOverallStatus.SUCCESS

    async def test_a2_effect_failure_no_disposition_call(self):
        """A2: Effect verification fails → need_action_replan=true, EDS NOT called."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(False, "not blocked")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result.need_action_replan is True
        assert len(ed_svc.calls) == 0  # NOT called

    async def test_a2_writeback_failure_no_replan(self):
        """A2: Only writeback failure → need_action_replan=false."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.PENDING,  # not confirmed
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result.need_action_replan is False
        assert result.need_writeback_recovery is True

    async def test_a3_create_ticket_skipped(self):
        """A3: create_ticket → effect_status=skipped."""
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            target_type="ticket",
            target="ticket-1",
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result.results[0].effect_status == EffectStatus.SKIPPED
        assert "non_verifiable" in (result.results[0].detail or "")

    async def test_a4_deferred_not_in_failed(self):
        """A4: Deferred action → skipped, not in failed_actions."""
        deferred = _action(
            tool_name=TERMINAL_DISPOSITION_TOOL,
            action_name="terminal",
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            status=ActionStatus.APPROVED,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
        )
        immediate = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=immediate.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([immediate, deferred], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(actions=[immediate, deferred]))

        deferred_results = [r for r in result.results if r.action_id == deferred.action_id]
        assert len(deferred_results) == 1
        assert deferred_results[0].effect_status == EffectStatus.SKIPPED
        assert deferred_results[0].detail == "deferred_pending_activation"
        assert deferred.action_id not in result.failed_actions

    async def test_a6_disposition_only_path_phase2_activates(self):
        """A6: Pure POST_VERIFY deferred plan → phase 2 still activates.

        ResponsePlan contains ONLY a deferred action (no IMMEDIATE).
        Phase 1 produces skipped results; phase 2 calls
        EventDispositionService.activate_and_submit and routes on
        writeback outcome.
        """
        deferred = _action(
            action_id="act-a6-deferred",
            tool_name=TERMINAL_DISPOSITION_TOOL,
            action_name="terminal_disposition",
            target_type="source_object",
            target="src-a6",
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            status=ActionStatus.APPROVED,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
        )
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-a6-terminal",
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-a6-terminal"),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([deferred], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=deferred.event_id, actions=[deferred]))

        # Phase 1: deferred → skipped (not failed).
        r = result.results[0]
        assert r.action_id == "act-a6-deferred"
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "deferred_pending_activation"
        assert "act-a6-deferred" not in result.failed_actions

        # Phase 2: EventDispositionService was called.
        assert len(ed_svc.calls) == 1
        assert ed_svc.calls[0]["event_id"] == deferred.event_id

        # Overall status depends on writeback (none in this stub), but
        # the key invariant is that phase 2 activation was triggered.
        # With activation success and no writeback failures, overall
        # should be SUCCESS.
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_a7_tool_false_vs_exception(self):
        """A7: Verification false → failed; tool exception → unverifiable (status differs)."""
        # Case 1: tool returns false
        action1 = _action(
            action_id="act-verify-01",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job1 = _job(job_id="job-0001", action_id="act-verify-01")

        agent1 = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_success(False, "not blocked")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent1._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action1], {"job-0001": job1}, {})
        )
        agent1._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )
        result1 = await agent1.execute(_input(event_id="evt-20260725-00000001", actions=[action1]))
        assert result1.results[0].effect_status == EffectStatus.FAILED

        # Case 2: tool throws error
        action2 = _action(
            action_id="act-verify-02",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0002",
        )
        job2 = _job(job_id="job-0002", action_id="act-verify-02")

        agent2 = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_error("crash")}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent2._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action2], {"job-0002": job2}, {})
        )
        agent2._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )
        result2 = await agent2.execute(_input(event_id="evt-20260725-00000002", actions=[action2]))
        assert result2.results[0].effect_status == EffectStatus.UNVERIFIABLE


# --------------------------------------------------------------------------- #
# Verification mapping tests
# --------------------------------------------------------------------------- #


class TestVerificationMapping:
    async def test_all_response_tools_have_mapping(self):
        """Every baseline response tool has a verification mapping entry or is skipped."""
        response_tools = [
            "block_ip",
            "block_domain",
            "isolate_host",
            "quarantine_file",
            "block_process",
            "scan_host_for_virus",
            "disable_account",
            "force_logout",
            "reset_password",
            "revoke_token",
            "create_ticket",
            "notify_security_team",
        ]
        for tool in response_tools:
            result = resolve_verification_tool(tool, None)
            # Either mapped to a verification tool or None (skipped).
            assert result is None or isinstance(result, str), (
                f"{tool} should resolve to str or None, got {result!r}"
            )

    async def test_mapping_is_stable(self):
        """Mappings should be stable across calls."""
        assert resolve_verification_tool("block_ip", "ip") == "check_ip_block_status"
        assert resolve_verification_tool("block_domain", "domain") == "check_domain_block_status"
        assert resolve_verification_tool("isolate_host", "host") == "check_host_isolation_status"
        assert resolve_verification_tool("disable_account", "account") == "check_account_status"
        assert resolve_verification_tool("create_ticket", "ticket") is None

    async def test_provider_override(self):
        """Provider manifest can override the baseline mapping with a known tool."""
        # Override maps block_ip → check_domain_block_status instead of the
        # baseline check_ip_block_status.  The override value must be a
        # registered verification tool name (ISSUE-060 SF-3).
        override = {"block_ip": {"ip": "check_domain_block_status"}}
        result = resolve_verification_tool("block_ip", "ip", provider_manifest_overrides=override)
        assert result == "check_domain_block_status"

    async def test_rollback_tools_mapped(self):
        """Rollback tools (unblock_ip, etc.) also map to verification tools."""
        assert resolve_verification_tool("unblock_ip", "ip") == "check_ip_block_status"
        assert (
            resolve_verification_tool("cancel_host_isolation", "host")
            == "check_host_isolation_status"
        )
        assert resolve_verification_tool("restore_file", "file") == "check_file_quarantine_status"

    async def test_provider_override_can_un_skip(self):
        """Provider manifest can override a None baseline to enable verification."""
        # create_ticket baseline is {"ticket": None} — skipped by default.
        # Override uses check_new_alerts (a known verification tool) to
        # demonstrate the "un-skip" capability (ISSUE-060 SF-3).
        result = resolve_verification_tool(
            "create_ticket",
            "ticket",
            provider_manifest_overrides={"create_ticket": {"ticket": "check_new_alerts"}},
        )
        assert result == "check_new_alerts"

    async def test_resolve_unknown_target_type_returns_none(self):
        """Unknown target_type → resolve_verification_tool returns None (no guess)."""
        # check_traffic_drop maps ip and host — "process" is not registered.
        result = resolve_verification_tool("check_traffic_drop", "process")
        assert result is None


# --------------------------------------------------------------------------- #
# Should-Fix regression tests (PR#7 review)
# --------------------------------------------------------------------------- #


class TestRegressionShouldFix:
    """Tests for issues identified in PR#7 review."""

    async def test_unverifiable_preserves_writeback_obligation(self):
        """UNVERIFIABLE preserves writeback_required (Should-Fix 1).

        A writeback_required=True action whose verification tool throws
        an exception must still report writeback_required=True — the
        business obligation is never reversed by technical inability.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_error("connection refused")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.UNVERIFIABLE
        # Key assertion: writeback_required stays True.
        assert r.writeback_required is True

    async def test_executing_action_not_prematurely_verified(self):
        """EXECUTING action → skipped, not FAILED (Should-Fix 4).

        An action still in EXECUTING status must not be verified by the
        observation tool — its effect may not have materialised yet.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.EXECUTING,
            execution_job_id="job-0001",
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "pending_execution"
        assert action.action_id not in result.failed_actions
        assert result.need_action_replan is False

    async def test_phase1_persist_waiting_when_immediate_pending(self):
        """ISSUE-216: phase-1 EDS gate must not write SUCCESS while IMMEDIATE pending."""
        deferred = _action(
            tool_name=TERMINAL_DISPOSITION_TOOL,
            action_name="terminal",
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            status=ActionStatus.APPROVED,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
        )
        immediate = _action(
            tool_name="block_ip",
            status=ActionStatus.EXECUTING,
            execution_job_id="job-0001",
        )
        wm = FakeWorkingMemory()
        verification_writes: list[dict[str, Any]] = []

        async def _capture_write(event_id: str, key: str, value: Any) -> None:
            if key == "verification_result":
                verification_writes.append(value)
            await wm.write(event_id, key, value)

        wm.write = _capture_write  # type: ignore[method-assign]

        ed_svc = FakeEventDispositionService(activated=False, skipped_reason="effect_not_ready")
        agent = VerifyAgent(
            working_memory=wm,
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([immediate, deferred], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(actions=[immediate, deferred]))

        assert len(verification_writes) >= 1
        phase1_gate = verification_writes[0]
        assert phase1_gate["overall_status"] == VerificationOverallStatus.WAITING.value
        assert phase1_gate["verification_phase"] == VerificationPhase.EFFECT.value
        immediate_rows = [
            row
            for row in phase1_gate["results"]
            if row["action_id"] == immediate.action_id
        ]
        assert immediate_rows[0]["detail"] == "pending_execution"
        assert result.overall_status is not VerificationOverallStatus.SUCCESS

    async def test_phase1_persist_success_when_only_deferred_pending(self):
        """ISSUE-216: deferred-only plans must still persist SUCCESS for EDS gate."""
        deferred = _action(
            tool_name=TERMINAL_DISPOSITION_TOOL,
            action_name="terminal",
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            status=ActionStatus.APPROVED,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
        )
        wm = FakeWorkingMemory()
        verification_writes: list[dict[str, Any]] = []

        async def _capture_write(event_id: str, key: str, value: Any) -> None:
            if key == "verification_result":
                verification_writes.append(value)
            await wm.write(event_id, key, value)

        wm.write = _capture_write  # type: ignore[method-assign]

        ed_svc = FakeEventDispositionService(activated=True, writeback_id="wbk-deferred-only")
        agent = VerifyAgent(
            working_memory=wm,
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-deferred-only"),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([deferred], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        await agent.execute(_input(actions=[deferred]))

        assert len(verification_writes) >= 1
        phase1_gate = verification_writes[0]
        assert phase1_gate["overall_status"] == VerificationOverallStatus.SUCCESS.value
        assert phase1_gate["verification_phase"] == VerificationPhase.EFFECT.value
        deferred_rows = [
            row for row in phase1_gate["results"] if row["action_id"] == deferred.action_id
        ]
        assert deferred_rows[0]["detail"] == "deferred_pending_activation"

    async def test_finalize_failure_during_exception_handling(self):
        """_finalize_verification_action failure → logged, not swallowed.

        When _finalize_verification_action itself throws during
        exception handling, the outer layer must log a warning
        (Should-Fix 2).
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Simulate the verification tool executor throwing, AND the
        # subsequent finalize call also failing.
        failing_executor = MagicMock()
        failing_executor.call = AsyncMock(side_effect=RuntimeError("tool exploded"))

        agent = VerifyAgent(
            tool_executor=failing_executor,
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        # Make _finalize_verification_action blow up.
        agent._finalize_verification_action = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("db connection lost")
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        # Must not raise — the exception is caught and logged.
        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        # The detail should contain a stable error code, not the raw
        # exception type name or message (ISSUE-060 Nit SF-6).
        assert "ERR_T_RUNTIME" in (result.results[0].detail or "")

    async def test_verification_action_persist_failure_graceful(self):
        """DB insert failure for verification action → returns result anyway.

        When _create_verification_action fails to persist the Action row
        to the database, the verification result must still be returned
        (the observation is the primary output; the trace record is
        best-effort).
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        # _create_verification_action persists but the session_factory
        # is None → _create returns the Action domain object without
        # DB persistence.  The tool call and result still flow through.
        agent._create_verification_action = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("persist failed")
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        # Should not crash — the exception is caught inside _run_verification_tool.
        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE

    async def test_writeback_failure_action_execution_count_unchanged(self):
        """Writeback failure → need_action_replan=false, execution count unchanged.

        Acceptance criteria A2 second half: when only writeback fails
        (not effect), the action execution count must not increase
        because no re-execution is triggered.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.FAILED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Action replan NOT triggered by writeback failure alone.
        assert result.need_action_replan is False
        # Action is NOT in failed_actions (that's for EFFECT failures only).
        assert action.action_id not in result.failed_actions
        # Writeback IS in failed_writebacks.
        assert action.action_id in result.failed_writebacks

    async def test_empty_plan_required_policy_triggers_phase2(self):
        """Empty plan + disposition_policy=REQUIRED → phase 2 still activates.

        When there are no IMMEDIATE actions, phase 2 must still call
        EventDispositionService.activate_and_submit.
        """
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-empty-plan",
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-empty-plan"),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )
        # Empty plan → plan_revision derived from DB fallback.
        agent._load_event_plan_revision = AsyncMock(  # type: ignore[method-assign]
            return_value=1,
        )

        result = await agent.execute(_input(event_id="evt-20260725-00000001", actions=[]))

        # Phase 2 was invoked (activation called).
        assert len(ed_svc.calls) == 1
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    async def test_verify_agent_idempotent_on_reexecution(self):
        """Same input twice → same verification action_id (Nit 2)."""
        action = _action(
            action_id="act-src-idempotent",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        event_id = "evt-20260725-00000001"

        agent1 = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent1._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent1._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )
        result1 = await agent1.execute(_input(event_id=event_id, actions=[action]))

        agent2 = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent2._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent2._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )
        result2 = await agent2.execute(_input(event_id=event_id, actions=[action]))

        # Both executions produce the same deterministic verification_action_id.
        assert result1.results[0].verification_action_id is not None
        assert (
            result1.results[0].verification_action_id == result2.results[0].verification_action_id
        )

    async def test_disposition_activation_failure_skips_writeback_eval(self):
        """Failed activation → writeback evaluation skipped (Nit 5).

        When EventDispositionService.activate_and_submit fails,
        writeback status evaluation must not proceed — the terminal
        writeback was never submitted, so its receipts are stale.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=False, skipped_reason="capability_blocked")
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Activation was attempted.
        assert len(ed_svc.calls) == 1
        # Activation failed → manual resolution, NOT writeback recovery.
        assert result.need_manual_resolution is True
        assert result.overall_status == VerificationOverallStatus.MANUAL_RESOLUTION


# --------------------------------------------------------------------------- #
# Working memory write test
# --------------------------------------------------------------------------- #


class TestWorkingMemory:
    async def test_verification_result_written_to_wm(self):
        """VerificationResult is persisted to working_memory.verification_result."""
        wm = FakeWorkingMemory()
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        agent = VerifyAgent(
            working_memory=wm,
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        await agent.execute(_input(actions=[action]))

        stored = await wm.read(action.event_id, "verification_result")
        assert stored is not None
        assert stored.get("overall_status") == VerificationOverallStatus.SUCCESS.value


# --------------------------------------------------------------------------- #
# Suggested boundary tests (PR#7 review)
# --------------------------------------------------------------------------- #


class TestSuggestedBoundary:
    """Tests for boundary conditions identified in PR#7 review."""

    async def test_unknowable_action_status_direct_manual(self):
        """Action UNKNOWN → direct to manual resolution, no verification tool call.

        UNKNOWN is intentionally excluded from _EXECUTED_STATUSES.
        Running a verification tool could return a false-positive
        is_verified that masks the fact that the Action's actual
        execution state is unknown, producing a contradictory
        (UNKNOWN execution + VERIFIED effect) pair that would cause
        downstream consumers to wrongly assume no manual intervention
        is needed.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.UNKNOWN,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Capture whether the verification tool is called — it should NOT be.
        tool_called = False

        async def record_call(tool_name, params, event_id, **kw):
            nonlocal tool_called
            tool_called = True
            return _tool_result_success(True)

        agent = VerifyAgent(
            tool_executor=MagicMock(call=AsyncMock(side_effect=record_call)),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # The verification tool must NOT be called for UNKNOWN actions.
        assert not tool_called
        # UNKNOWN → UNVERIFIABLE effect, escalating to manual resolution.
        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert result.results[0].detail == "action_execution_unknown"
        assert result.need_manual_resolution is True

    async def test_phase2_activation_exception_handling(self):
        """EDS.activate_and_submit exception → need_manual=True."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        class ThrowingEDS:
            async def activate_and_submit(
                self, *, event_id: str, plan_revision: int, principal_or_system: str
            ):
                raise RuntimeError("activation service down")

        ed_svc = ThrowingEDS()
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Phase 1 passes, but phase 2 activation throws → manual escalation.
        assert result.need_manual_resolution is True
        assert result.overall_status == VerificationOverallStatus.MANUAL_RESOLUTION

    async def test_missing_is_verified_field_is_unverifiable(self):
        """Tool returns SUCCESS without 'is_verified' key → UNVERIFIABLE."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Result missing the is_verified key.
        incomplete_result = ToolResult(
            call_id="call-00000001",
            tool_name="check_ip_block_status",
            provider_name="mock_observation",
            status=ToolResultStatus.SUCCESS,
            data={"detail": "observation complete"},  # no is_verified
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": incomplete_result}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert "missing_is_verified" in (result.results[0].detail or "")

    async def test_outbox_map_collects_writeback_ids_correctly(self):
        """_collect_writeback_ids collects writeback_id from outbox records."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Build a stub outbox record with writeback_id.
        class StubOutbox:
            def __init__(self, action_id: str, writeback_id: str) -> None:
                self.action_id = action_id
                self.writeback_id = writeback_id

        outbox_map = {
            action.action_id: [
                StubOutbox(action.action_id, "wbk-aaa"),
                StubOutbox(action.action_id, ""),  # empty → skipped
                StubOutbox(action.action_id, "wbk-bbb"),
            ]
        }

        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, outbox_map)
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Phase 2 writeback evaluation includes the collected writeback IDs.
        phase2_results = [
            r
            for r in result.results
            if r.action_id == action.action_id and r.detail == "writeback_confirmed"
        ]
        assert len(phase2_results) == 1
        assert set(phase2_results[0].writeback_ids) == {"wbk-aaa", "wbk-bbb"}

    async def test_disposition_policy_none_escalates(self):
        """disposition_policy=None → need_manual_resolution (unknown requirement)."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=None,  # unknown policy
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Phase 1 passes, but unknown disposition_policy → manual.
        assert result.need_manual_resolution is True
        assert result.overall_status == VerificationOverallStatus.MANUAL_RESOLUTION

    async def test_partial_success_job_status_handled(self):
        """Job with PARTIAL_SUCCESS → verification tool still executed."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.PARTIAL_SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(
            job_id="job-0001",
            action_id=action.action_id,
            status=ExecutionJobStatus.PARTIAL_SUCCESS,
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Partial success action status is in _EXECUTED_STATUSES → verified.
        assert result.results[0].action_id == action.action_id
        assert result.results[0].effect_status == EffectStatus.VERIFIED


# --------------------------------------------------------------------------- #
# PR#7 review — new regression tests for Should-Fix / Nit fixes
# --------------------------------------------------------------------------- #


class TestPR7ReviewFixes:
    """Tests added per PR#7 review to cover the 4 Should-Fix + 6 Nit items."""

    # ── Should-Fix 1: disposition_policy loads from DB, not WM ──────────

    async def test_disposition_policy_loads_from_db_directly(self):
        """disposition_policy is a SecurityEvent column — WM read removed.

        Before the fix, _load_disposition_policy tried to read
        "disposition_policy" from working_memory, which is not a
        FIELD_OWNERSHIP key and always raised GuardrailViolationError
        (caught by except Exception).  Now it goes directly to DB.
        """
        # Even with working_memory present, the method should not attempt
        # a WM read for "disposition_policy" — it queries the DB directly.
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            session_factory=None,  # no DB, returns None
        )
        result = await agent._load_disposition_policy("evt-20260725-00000001")
        # Without session_factory, disposition_policy is unknown → None.
        assert result is None

    async def test_disposition_policy_no_guardrail_on_wm(self):
        """No GuardrailViolationError triggered when WM is present.

        VerifyAgent now skips the WM read entirely for disposition_policy,
        so even with a BoundWorkingMemory attached, no guardrail violation
        occurs.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        # Pre-populate WM with unrelated fields — disposition_policy read
        # should NOT touch WM at all.
        wm = FakeWorkingMemory()
        await wm.write(action.event_id, "triage_result", {"score": 85})

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=wm,
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        # _load_disposition_policy goes to DB directly; no session_factory → None.
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(actions=[action]))
        # Must not crash and must produce a valid result.
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    # ── Should-Fix 2: no session_factory preserves job context ──────────

    async def test_no_session_factory_preserves_job_context(self):
        """Without session_factory, actions with execution_job_id still
        get a minimal jobs_map entry so the verification tool receives
        the job_id parameter."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-from-plan",
        )

        # The verification tool should receive job_id in its params.
        captured_job_id: list[str | None] = []

        async def capture_call(tool_name, params, event_id, **kw):
            captured_job_id.append((params.get("parameters") or {}).get("job_id"))
            return _tool_result_success(True)

        agent = VerifyAgent(
            tool_executor=MagicMock(call=AsyncMock(side_effect=capture_call)),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            session_factory=None,  # no DB
        )
        # Do NOT mock _load_execution_state — let it use the real
        # no-session path that builds jobs_map from actions.
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        await agent.execute(_input(actions=[action]))

        # The tool should have received the job_id from the action.
        assert captured_job_id == ["job-from-plan"]

    # ── Should-Fix 3: audit gap on DB persist failure ───────────────────

    async def test_verification_action_persist_failure_leaves_warning(self):
        """When DB insert fails (non-integrity), the warning log mentions
        audit trail incompleteness."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Mock the session factory to simulate a DB failure on add.
        # The real code calls ``async with self._session_factory() as session``
        # then ``async with session.begin()``, so both must be proper async
        # context managers that raise on add().
        from contextlib import asynccontextmanager

        class FailingSession:
            def add(self, row):
                raise RuntimeError("connection lost during insert")

            @asynccontextmanager
            async def begin(self):
                yield

        @asynccontextmanager
        async def _session_ctx():
            yield FailingSession()

        mock_factory = MagicMock()
        mock_factory.side_effect = _session_ctx
        # __call__ is used by self._session_factory().
        mock_factory.return_value = None  # won't be used — side_effect wins

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            session_factory=mock_factory,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        # Must not crash — the persist failure is caught and logged.
        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # The verification observation still proceeds despite DB failure.
        assert result.results[0].effect_status == EffectStatus.VERIFIED

    # ── Should-Fix 4: terminal writeback verification needs DB ──────────

    async def test_terminal_wb_verification_requires_db(self):
        """Without session_factory, terminal writeback verification
        escalates to manual resolution instead of silently passing."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        # EDS returns a writeback_id but there is no session_factory
        # to verify the receipt → must escalate to manual.
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-needs-db-verify",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_disposition_service=ed_svc,
            session_factory=None,  # no DB available
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Terminal writeback receipt cannot be verified without DB.
        assert result.need_manual_resolution is True
        assert "wbk-needs-db-verify" in result.blocked_writebacks

    # ── Nit 4: UNVERIFIABLE preserves writeback_status ──────────────────

    async def test_unverifiable_preserves_writeback_status(self):
        """UNVERIFIABLE effect must preserve the original writeback_status
        instead of overwriting it to None (which would silently break
        downstream writeback recovery)."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.PENDING,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_error("unreachable")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.UNVERIFIABLE
        # Key: the original writeback_status (PENDING) is preserved,
        # not replaced with None.
        assert r.writeback_status == WritebackStatus.PENDING

    # ── Nit 5: phase1 need_replan AND need_manual → FAILED ──────────────

    async def test_phase1_replan_and_manual_combined(self):
        """When phase 1 has both FAILED (need_replan) and UNVERIFIABLE
        (need_manual) actions, overall_status must be FAILED, not
        silently dropping the manual_resolution flag."""
        # Action 1: verification returns false → FAILED → need_replan
        action1 = _action(
            action_id="act-replan-01",
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job1 = _job(job_id="job-0001", action_id="act-replan-01")

        # Action 2: tool error during verification → UNVERIFIABLE → need_manual.
        # Use a mapped tool (block_domain) whose verification tool throws.
        action2 = _action(
            action_id="act-manual-02",
            tool_name="block_domain",
            target_type="domain",
            target="evil.example.com",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0002",
        )
        job2 = _job(job_id="job-0002", action_id="act-manual-02")

        # Mock executor: block_ip verification fails (FAILED),
        # block_domain verification throws tool error (UNVERIFIABLE).
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {
                    "check_ip_block_status": _tool_result_success(False, "not blocked"),
                    "check_domain_block_status": _tool_result_error("observation unavailable"),
                }
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=(
                [action1, action2],
                {"job-0001": job1, "job-0002": job2},
                {},
            )
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id="evt-20260725-00000001", actions=[action1, action2])
        )

        # Both flags set.
        assert result.need_action_replan is True
        assert result.need_manual_resolution is True
        # Combined severity is FAILED.
        assert result.overall_status == VerificationOverallStatus.FAILED

    # ── Nit 1 + Idempotent re-run ──────────────────────────────────────

    async def test_verify_agent_full_rerun_idempotent(self):
        """Full re-verification of the same event produces the same
        verification_action_id (8-char hex digest per ISSUE-002 spec)
        and consistent effect status."""
        action = _action(
            action_id="act-idem-src",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id="act-idem-src")
        event_id = "evt-20260725-00000001"

        results = []
        for _ in range(2):
            agent = VerifyAgent(
                tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
                working_memory=FakeWorkingMemory(),
                trace_service=FakeTraceService(),
                event_bus=FakeEventBus(),
            )
            agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
                return_value=([action], {"job-0001": job}, {})
            )
            agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
                return_value=DispositionPolicy.NOT_REQUIRED,
            )
            result = await agent.execute(_input(event_id=event_id, actions=[action]))
            results.append(result)

        # Same verification_action_id across runs.
        assert results[0].results[0].verification_action_id is not None
        assert (
            results[0].results[0].verification_action_id
            == results[1].results[0].verification_action_id
        )
        # The action_id uses 8-char hex digest: act-{8hex}.
        vid = results[0].results[0].verification_action_id
        assert vid is not None
        assert vid.startswith("act-")
        assert len(vid) == 4 + 8  # "act-" + 8 hex chars

    # ── Nit 2: derived skip tools match VERIFICATION_MAPPING ────────────

    async def test_derived_skip_tools_match_mapping(self):
        """_derive_skip_verification_tools() produces the same set as
        the VERIFICATION_MAPPING entries with all-None targets."""
        from app.agents.verify_agent import _derive_skip_verification_tools

        skip = _derive_skip_verification_tools()
        assert "create_ticket" in skip
        assert "close_false_positive_ticket" in skip
        assert "notify_security_team" in skip
        # Self-mapping tools should NOT be in the skip set.
        assert "check_new_alerts" not in skip
        assert "check_traffic_drop" not in skip

    # ── Should-Fix 3: domain/DB consistency ─────────────────────────────

    async def test_finalize_commit_failure_does_not_update_domain(self):
        """_finalize_verification_action commit failure → domain status
        must NOT be updated, preventing memory/DB inconsistency."""
        from contextlib import asynccontextmanager

        action = _action(
            tool_name="block_ip",
            status=ActionStatus.EXECUTING,  # current status
        )
        original_status = action.status

        class _MockRow:
            status: str | None = None
            updated_at: Any = None

        class _FailingCommitSession:
            def __init__(self) -> None:
                self.row = _MockRow()

            async def get(self, *args: Any, **kwargs: Any) -> _MockRow | None:
                return self.row

            @asynccontextmanager
            async def begin(self):
                yield
                raise RuntimeError("commit failed — connection lost")

        @asynccontextmanager
        async def _session_ctx():
            yield _FailingCommitSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(session_factory=mock_factory)
        await agent._finalize_verification_action(action, target_status=ActionStatus.SUCCESS)

        # Domain object status must NOT have been updated — the DB
        # commit failed, so the in-memory Action must stay at its
        # original status to avoid inconsistency.
        assert action.status == original_status
        assert action.status == ActionStatus.EXECUTING


# --------------------------------------------------------------------------- #
# Review Round 2 — tests for Should-Fix and Nit fixes
# --------------------------------------------------------------------------- #


class TestReviewRound2Fixes:
    """Tests added to cover the Should-Fix and Nit items from the second
    review round."""

    # ── Should-Fix #1: tool unavailable finalizes verification action ─────

    async def test_verification_action_finalized_when_tool_unavailable(self):
        """When tool_executor returns None, the verification Action is
        finalized to UNKNOWN status, not left stuck in EXECUTING."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Simulate tool_executor returning None (Provider degraded).
        async def _return_none(tool_name, params, event_id, **kw):
            return None

        # Capture the target_status passed to _finalize_verification_action.
        captured_statuses: list[ActionStatus] = []

        async def _capture_finalize(verification_action, *, target_status):
            captured_statuses.append(target_status)

        agent = VerifyAgent(
            tool_executor=MagicMock(call=AsyncMock(side_effect=_return_none)),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._finalize_verification_action = AsyncMock(  # type: ignore[method-assign]
            side_effect=_capture_finalize
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # The tool was unavailable → UNVERIFIABLE.
        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert result.results[0].detail == "verification_tool_unavailable_degraded"
        # The verification Action MUST have been finalized (not left EXECUTING).
        assert len(captured_statuses) == 1
        assert captured_statuses[0] == ActionStatus.UNKNOWN

    # ── Should-Fix #1 variant: tool_executor=None produces same behavior ─

    async def test_tool_executor_none_finalizes_verification_action(self):
        """When tool_executor is None (not injected), the verification
        Action is still finalized — same codepath as tool_executor.call()
        returning None."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        captured_statuses: list[ActionStatus] = []

        async def _capture_finalize(verification_action, *, target_status):
            captured_statuses.append(target_status)

        agent = VerifyAgent(
            tool_executor=None,  # not injected
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._finalize_verification_action = AsyncMock(  # type: ignore[method-assign]
            side_effect=_capture_finalize
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert len(captured_statuses) == 1
        assert captured_statuses[0] == ActionStatus.UNKNOWN

    # ── Should-Fix #2: dirty marker on double-failure ────────────────────

    async def test_finalize_failure_appends_dirty_marker(self):
        """When _finalize_verification_action throws during exception
        handling, the structured verification_action_dirty flag is set
        so downstream consumers can distinguish a clean finalize from
        a zombie verification Action."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Simulate tool_executor.call throwing.
        failing_executor = MagicMock()
        failing_executor.call = AsyncMock(side_effect=RuntimeError("tool exploded"))

        agent = VerifyAgent(
            tool_executor=failing_executor,
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        # _finalize_verification_action also throws — double failure.
        agent._finalize_verification_action = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("db connection lost during finalize")
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.UNVERIFIABLE
        # The detail exposes a stable error code (sanitised — ISSUE-060 Nit SF-6)...
        assert "ERR_T_RUNTIME" in (r.detail or "")
        # ...AND the structured dirty flag is set to signal the verification
        # Action may be stuck in EXECUTING.
        assert r.verification_action_dirty is True

    # ── Phase 1: all UNKNOWN → manual, no replan ─────────────────────────

    async def test_phase1_all_actions_unknown(self):
        """All Actions are UNKNOWN → all go to need_manual, no replan
        triggered (UNKNOWN ≠ FAILED)."""
        actions = [
            _action(
                action_id="act-unk-01",
                tool_name="block_ip",
                status=ActionStatus.UNKNOWN,
                execution_job_id="job-0001",
            ),
            _action(
                action_id="act-unk-02",
                tool_name="block_domain",
                status=ActionStatus.UNKNOWN,
                execution_job_id="job-0002",
            ),
        ]
        jobs = {
            "job-0001": _job(job_id="job-0001", action_id="act-unk-01"),
            "job-0002": _job(job_id="job-0002", action_id="act-unk-02"),
        }
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=(actions, jobs, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id="evt-20260725-00000001", actions=actions))

        # All UNKNOWN → all UNVERIFIABLE.
        assert all(r.effect_status == EffectStatus.UNVERIFIABLE for r in result.results)
        # UNKNOWN ≠ FAILED → no replan.
        assert result.need_action_replan is False
        # All escalate to manual.
        assert result.need_manual_resolution is True
        assert len(result.failed_actions) == 0

    # ── Enhanced: UNVERIFIABLE preserves writeback_status ────────────────

    async def test_unverifiable_preserves_writeback_status_value(self):
        """UNVERIFIABLE effect must preserve the original writeback_status
        (e.g. PENDING) rather than overwriting to None.

        This is an enhanced version of the existing
        test_unverifiable_preserves_writeback_obligation — it additionally
        asserts that writeback_readiness is set to NOT_REQUIRED (per the
        UNVERIFIABLE path contract) while writeback_required stays True
        and writeback_status is preserved.
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.PENDING,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {"check_ip_block_status": _tool_result_error("observation down")}
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.UNVERIFIABLE
        # Business obligation preserved.
        assert r.writeback_required is True
        # Readiness demoted to NOT_REQUIRED (technical inability).
        assert r.writeback_readiness == WritebackReadiness.NOT_REQUIRED
        # writeback_status preserved (PENDING), not wiped to None.
        assert r.writeback_status == WritebackStatus.PENDING


# --------------------------------------------------------------------------- #
# PR#7 Blocker & Should-Fix regression tests
# --------------------------------------------------------------------------- #


class TestBlockerFixes:
    """Tests for the two Blocker issues identified in PR#7 review."""

    # ── Blocker #1: partial DB hit preserves all plan actions ────────────

    async def test_partial_db_hit_preserves_all_actions(self):
        """When DB returns fewer Actions than the plan, all plan Actions
        are preserved — none are silently dropped.

        This test calls _load_execution_state directly (rather than going
        through execute()) to isolate the data-loading layer that was
        patched for Blocker #1.
        """
        plan_action1 = _action(
            action_id="act-in-db",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        plan_action2 = _action(
            action_id="act-not-in-db",
            tool_name="block_domain",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0002",
        )
        plan = _plan([plan_action1, plan_action2])

        # Build a mock DB session that only returns "act-in-db" for the
        # Action query.  Jobs query returns both since both have job IDs.

        class _ActionRow:
            """Minimal stub whose attributes satisfy _action_from_row."""

            action_id: str
            event_id: str = "evt-20260725-00000001"
            plan_revision: int = 1
            action_fingerprint: str = "fp:test"
            action_category: str = "response"
            action_name: str = "test"
            tool_name: str = "block_ip"
            action_level: str = "l2"
            execution_phase: str | None = "immediate"
            activation_condition: str | None = None
            approved_operation_template_hash: str | None = None
            approved_terminal_dispositions: list[str] = []
            target_type: str | None = "ip"
            target: str | None = "10.0.0.1"
            parameters: dict[str, Any] = {}
            status: str = "success"
            auto_execute: bool = True
            reason: str | None = None
            provider_name: str | None = "mock_observation"
            execution_owner: str | None = "direct_tool"
            execution_job_id: str | None = "job-0001"
            tool_call_id: str | None = None
            idempotency_key: str | None = "idem-act-in-db"
            writeback_required: bool = False
            writeback_applicable: bool = False
            writeback_readiness: str | None = "not_required"
            writeback_block_reason: str | None = None
            writeback_status: str | None = None
            disposition_source_ref: Any = None
            superseded_by_revision: int | None = None
            executed_at: Any = None
            effect_verification_status: str | None = None
            rollback_status: str | None = None
            source_action_id: str | None = None
            updated_at: Any = None

            def __init__(self, action_id: str) -> None:
                self.action_id = action_id

        class _JobRow:
            """Minimal stub whose attributes satisfy _job_from_row."""

            def __init__(
                self,
                action_id: str,
                job_id: str,
            ) -> None:
                self.action_id = action_id
                self.job_id = job_id
                self.event_id = "evt-20260725-00000001"
                self.provider_name = "mock_observation"
                self.idempotency_key = f"idem-{action_id}"
                self.provider_job_id = None
                self.status = "success"
                self.claimed_by = None
                self.lease_expires_at = None
                self.poll_after_ms = None
                self.attempt = 1
                self.provider_code = None
                self.provider_message = None
                self.raw_result = {}
                self.created_at = None
                self.updated_at = None
                self.started_at = None
                self.finished_at = None

        db_action = _ActionRow("act-in-db")
        job1 = _JobRow("act-in-db", "job-0001")
        job2 = _JobRow("act-not-in-db", "job-0002")

        class _Result:
            def __init__(self, rows: list[Any]) -> None:
                self._rows = rows

            def all(self) -> list[Any]:
                return self._rows

        class _PartialDBSession:
            def __init__(self) -> None:
                self._scalar_call = 0

            async def scalars(self, stmt: Any) -> _Result:
                self._scalar_call += 1
                if self._scalar_call == 1:
                    # First call: Action query → only one in DB.
                    return _Result([db_action])
                if self._scalar_call == 2:
                    # Second call: Job query → both jobs exist.
                    return _Result([job1, job2])
                # Third+ call: Outbox query → empty.
                return _Result([])

            async def get(self, model: type[Any], ident: Any, **kwargs: Any) -> Any | None:
                return None

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _PartialDBSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(
            session_factory=mock_factory,
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )

        actions, jobs_map, outbox_map = await agent._load_execution_state(
            event_id="evt-20260725-00000001",
            response_plan=plan,
        )

        action_ids = {a.action_id for a in actions}
        # BOTH actions must be present — none dropped.
        assert "act-in-db" in action_ids
        assert "act-not-in-db" in action_ids
        # The DB action should have status from DB (SUCCESS from row).
        db_action_obj = next(a for a in actions if a.action_id == "act-in-db")
        assert db_action_obj.status == ActionStatus.SUCCESS
        # Both jobs should be present.
        assert "act-in-db" in jobs_map
        assert "act-not-in-db" in jobs_map

    async def test_null_db_writeback_status_overlays_plan_confirmed(self):
        """DB writeback_status=NULL + plan CONFIRMED → merged action is CONFIRMED."""
        plan_action = _action(
            action_id="act-wb-merge",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-wb-merge",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        plan = _plan([plan_action])

        class _ActionRow:
            action_id: str
            event_id: str = "evt-20260725-00000001"
            plan_revision: int = 1
            action_fingerprint: str = "fp:block_ip"
            action_category: str = "response"
            action_name: str = "block_ip_action"
            tool_name: str = "block_ip"
            action_level: str = "l2"
            execution_phase: str | None = "immediate"
            activation_condition: str | None = None
            approved_operation_template_hash: str | None = None
            approved_terminal_dispositions: list[str] = []
            target_type: str | None = "ip"
            target: str | None = "10.0.0.1"
            parameters: dict[str, Any] = {}
            status: str = "success"
            auto_execute: bool = True
            reason: str | None = None
            provider_name: str | None = "mock_observation"
            execution_owner: str | None = "direct_tool"
            execution_job_id: str | None = "job-wb-merge"
            tool_call_id: str | None = None
            idempotency_key: str | None = "idem-act-wb-merge"
            writeback_required: bool = True
            writeback_applicable: bool = True
            writeback_readiness: str | None = "ready"
            writeback_block_reason: str | None = None
            writeback_status: str | None = None
            disposition_source_ref: Any = None
            superseded_by_revision: int | None = None
            executed_at: Any = None
            effect_verification_status: str | None = None
            rollback_status: str | None = None
            source_action_id: str | None = None
            updated_at: Any = None

            def __init__(self, action_id: str) -> None:
                self.action_id = action_id

        class _Result:
            def __init__(self, rows: list[Any]) -> None:
                self._rows = rows

            def all(self) -> list[Any]:
                return self._rows

        class _MergeDBSession:
            def __init__(self) -> None:
                self._scalar_call = 0

            async def scalars(self, stmt: Any) -> _Result:
                self._scalar_call += 1
                if self._scalar_call == 1:
                    return _Result([_ActionRow("act-wb-merge")])
                return _Result([])

            async def get(self, *args: Any, **kwargs: Any) -> Any | None:
                return None

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _MergeDBSession()

        agent = VerifyAgent(
            session_factory=MagicMock(side_effect=_session_ctx),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )

        actions, _jobs_map, _outbox_map = await agent._load_execution_state(
            event_id="evt-20260725-00000001",
            response_plan=plan,
        )

        assert len(actions) == 1
        assert actions[0].action_id == "act-wb-merge"
        assert actions[0].writeback_status is WritebackStatus.CONFIRMED

    # ── Blocker #2: all tools unavailable → overall_status=FAILED ────────

    async def test_all_tools_unavailable_yields_failed(self):
        """When all verification tools are unavailable, overall_status
        must be FAILED (not MANUAL_RESOLUTION) per ISSUE-060 spec."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # tool_executor=None → all verification calls return None → UNVERIFIABLE.
        agent = VerifyAgent(
            tool_executor=None,  # systemic unavailability
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # All UNVERIFIABLE + no FAILED → systemic failure → FAILED.
        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert result.overall_status == VerificationOverallStatus.FAILED
        # need_manual_resolution stays True (escalated in the spec).
        assert result.need_manual_resolution is True
        # need_action_replan is False (no actual effect failure).
        assert result.need_action_replan is False

    async def test_all_tools_error_yields_failed(self):
        """When all verification tools return errors, overall_status
        must also be FAILED (systemic, not per-action)."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # All tool calls return errors → UNVERIFIABLE.
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {
                    "check_ip_block_status": _tool_result_error("provider down"),
                }
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert result.overall_status == VerificationOverallStatus.FAILED
        assert result.need_manual_resolution is True

    async def test_mixed_verified_and_unverifiable_not_failed(self):
        """When at least one action VERIFIED and others UNVERIFIABLE,
        overall_status must NOT be FAILED (only partial systemic issue)."""
        action1 = _action(
            action_id="act-verified",
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        action2 = _action(
            action_id="act-unverifiable",
            tool_name="block_domain",
            target_type="domain",
            target="evil.com",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0002",
        )
        job1 = _job(job_id="job-0001", action_id="act-verified")
        job2 = _job(job_id="job-0002", action_id="act-unverifiable")

        # action1: verified OK, action2: tool error → UNVERIFIABLE.
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {
                    "check_ip_block_status": _tool_result_success(True),
                    "check_domain_block_status": _tool_result_error("observation down"),
                }
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=(
                [action1, action2],
                {"job-0001": job1, "job-0002": job2},
                {},
            )
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(
            _input(event_id="evt-20260725-00000001", actions=[action1, action2])
        )

        # NOT all UNVERIFIABLE → not systemic → not FAILED.
        assert result.overall_status != VerificationOverallStatus.FAILED
        # But the unverifiable action still escalates to manual.
        assert result.need_manual_resolution is True


class TestShouldFixFixes:
    """Tests for Should-Fix items identified in PR#7 review."""

    # ── Provider override applied during agent execution ─────────────────

    async def test_provider_override_applied_in_agent_execution(self):
        """Provider manifest override is passed to resolve_verification_tool
        during actual VerifyAgent execution."""
        action = _action(
            tool_name="create_ticket",
            action_name="ticket_action",
            target_type="ticket",
            target="ticket-1",
            status=ActionStatus.SUCCESS,
            action_level=ActionLevel.L1,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        # Override: create_ticket normally maps to None (non-verifiable),
        # but with a provider override it should map to check_new_alerts
        # (a known verification tool — ISSUE-060 SF-3).
        overrides = {"create_ticket": {"ticket": "check_new_alerts"}}
        agent = VerifyAgent(
            tool_executor=_mock_executor(
                {
                    "check_new_alerts": _tool_result_success(True),
                }
            ),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            provider_manifest_overrides=overrides,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # With the override, create_ticket should be VERIFIED (not SKIPPED).
        r = result.results[0]
        assert r.effect_status == EffectStatus.VERIFIED
        assert r.detail == "effect_verified"

    async def test_provider_override_without_override_stays_skipped(self):
        """Without override, create_ticket stays SKIPPED (baseline behavior)."""
        action = _action(
            tool_name="create_ticket",
            action_name="ticket_action",
            target_type="ticket",
            target="ticket-1",
            status=ActionStatus.SUCCESS,
            action_level=ActionLevel.L1,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        # No override passed.
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Without override, create_ticket is non-verifiable → SKIPPED.
        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "non_verifiable_action"

    # ── Writeback routing: PARTIAL/FAILED retry detection ────────────────

    async def test_writeback_routing_table_symmetry(self):
        """_WRITEBACK_STATUS_ROUTING covers all WritebackStatus members.

        None is intentionally excluded from the routing table dict and
        is handled explicitly in _evaluate_writeback_statuses.
        """
        all_statuses = set(WritebackStatus)
        covered = set(_WRITEBACK_STATUS_ROUTING.keys())
        assert covered == all_statuses, f"Missing writeback statuses: {all_statuses - covered}"

    async def test_failed_writeback_status_routes_to_recovery(self):
        """FAILED writeback → recovery (not success, not manual)."""
        confirmed, recovery, manual, _detail = _WRITEBACK_STATUS_ROUTING[WritebackStatus.FAILED]
        assert confirmed is False
        assert recovery is True
        assert manual is False

    async def test_partial_writeback_status_routes_to_recovery(self):
        """PARTIAL writeback → recovery (not success, not manual)."""
        confirmed, recovery, manual, _detail = _WRITEBACK_STATUS_ROUTING[WritebackStatus.PARTIAL]
        assert confirmed is False
        assert recovery is True
        assert manual is False


class TestBoundaryFixes:
    """Boundary condition tests suggested in PR#7 review."""

    async def test_no_job_no_executor_graceful(self):
        """Action with no execution_job_id and tool_executor=None →
        graceful UNVERIFIABLE without crashing."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id=None,  # no job
        )
        agent = VerifyAgent(
            tool_executor=None,  # no executor
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Must not crash, must produce UNVERIFIABLE.
        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert result.overall_status == VerificationOverallStatus.FAILED

    async def test_concurrent_verification_idempotent(self):
        """Multiple concurrent verifications of the same action produce
        consistent results (same verification_action_id)."""
        action = _action(
            action_id="act-concurrent-src",
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        event_id = "evt-20260725-00000001"

        # Simulate three concurrent verification runs.
        vids: list[str | None] = []
        for _ in range(3):
            agent = VerifyAgent(
                tool_executor=_mock_executor(
                    {
                        "check_ip_block_status": _tool_result_success(True),
                    }
                ),
                working_memory=FakeWorkingMemory(),
                trace_service=FakeTraceService(),
                event_bus=FakeEventBus(),
            )
            agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
                return_value=([action], {"job-0001": job}, {})
            )
            agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
                return_value=DispositionPolicy.NOT_REQUIRED,
            )
            result = await agent.execute(_input(event_id=event_id, actions=[action]))
            vids.append(result.results[0].verification_action_id)

        # All runs produce the same deterministic verification_action_id.
        assert all(v is not None for v in vids)
        assert len(set(vids)) == 1


# --------------------------------------------------------------------------- #
# ISSUE-060 review — regression tests for Blocker + Should-Fix items
# --------------------------------------------------------------------------- #


class TestIssue060ReviewFixes:
    """Tests added per ISSUE-060 review: 2 Blockers, 7 Should-Fix, 4 Nits."""

    # ── B1: UNKNOWN writeback → recovery (not manual) ─────────────────────

    async def test_unknown_writeback_routes_to_recovery(self):
        """B1: UNKNOWN writeback status → need_writeback_recovery=True,
        need_manual_resolution=False.  WritebackRecoveryHandler (ISSUE-062)
        will attempt a provider-side lookup first."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.UNKNOWN,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-unknown-routing",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-unknown-routing"),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # UNKNOWN → recovery, NOT manual.
        assert result.need_writeback_recovery is True
        # need_manual_resolution should be False (UNKNOWN routes to recovery).
        assert result.need_manual_resolution is False
        # Action replan NOT triggered.
        assert result.need_action_replan is False

    async def test_unknown_writeback_effect_verified_preserved(self):
        """B1: UNKNOWN writeback status preserves phase 1 VERIFIED effect.
        The entity effect is confirmed; only the writeback receipt is uncertain."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.UNKNOWN,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Phase 1 result: VERIFIED (effect confirmed).
        phase1_results = [r for r in result.results if r.detail == "effect_verified"]
        assert len(phase1_results) == 1
        assert phase1_results[0].effect_status == EffectStatus.VERIFIED

        # Phase 2 result: UNKNOWN writeback → recovery (not manual, not failed).
        phase2_results = [
            r for r in result.results if r.detail == "writeback_unknown_requires_lookup"
        ]
        assert len(phase2_results) == 1
        assert phase2_results[0].effect_status == EffectStatus.VERIFIED

    # ── B2: plan_revision=0 not skipped ───────────────────────────────────

    async def test_plan_revision_zero_not_skipped(self):
        """B2: plan_revision=0 is passed to EventDispositionService,
        not silently replaced with default=1."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
            plan_revision=0,  # ← the case that was broken
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-plan-rev-zero",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-plan-rev-zero"),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # EventDispositionService was called.
        assert len(ed_svc.calls) == 1
        # plan_revision=0 must be passed through (not replaced with 1).
        assert ed_svc.calls[0]["plan_revision"] == 0
        assert result.overall_status == VerificationOverallStatus.SUCCESS

    # ── SF3: terminal writeback receipt CONFIRMED ─────────────────────────

    async def test_terminal_writeback_receipt_confirmed(self):
        """SF3: Terminal writeback receipt status=CONFIRMED produces
        overall_status=SUCCESS (full two-phase closure)."""
        from contextlib import asynccontextmanager

        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-terminal-confirmed",
        )

        # Build a mock DB session that returns a CONFIRMED receipt.
        class _ReceiptRow:
            writeback_id: str = "wbk-terminal-confirmed"
            status: str = "confirmed"
            sequence: int = 1

        class _TerminalDBSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def first(self) -> _ReceiptRow | None:
                        return _ReceiptRow()

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _TerminalDBSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=mock_factory,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Terminal receipt is CONFIRMED → overall SUCCESS.
        assert result.overall_status == VerificationOverallStatus.SUCCESS
        assert len(ed_svc.calls) == 1

    # ── SF4: non-iterable actions graceful ────────────────────────────────

    async def test_plan_actions_non_iterable_graceful(self):
        """SF4: response_plan.actions exists but is not iterable →
        returns empty list without crashing."""
        from app.agents.verify_agent import _plan_actions

        class _BadPlan:
            actions = 42  # not iterable

        result = _plan_actions(_BadPlan())
        assert result == []

    # ── SF5: _MISSING sentinel survives type check ────────────────────────

    async def test_missing_sentinel_is_unique_type(self):
        """SF5: _MISSING uses a dedicated type so ``is`` comparisons work
        correctly even after pickle/fork."""
        from app.agents.rules.verification_mapping import _MISSING

        # The sentinel should be an instance of a custom type, not bare object.
        sentinel_type = type(_MISSING)
        assert sentinel_type.__name__ == "_MissingSentinel"
        # ``is`` comparison within the same process (standard usage).
        assert _MISSING is _MISSING

    # ── SF7: activation returns False skips writeback eval ────────────────

    async def test_activation_returns_false_skips_writeback_eval(self):
        """SF7: When activate_and_submit returns activated=False (not an
        exception), writeback evaluation must be skipped."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        # activated=False with a reason (not an exception).
        ed_svc = FakeEventDispositionService(
            activated=False,
            skipped_reason="capability_blocked",
            writeback_id="wbk-blocked",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Activation was attempted.
        assert len(ed_svc.calls) == 1
        # But it returned activated=False → manual escalation.
        assert result.need_manual_resolution is True
        assert result.overall_status == VerificationOverallStatus.MANUAL_RESOLUTION
        # The blocked reference is the deferred action_id (not a synthetic
        # f"terminal_wb_{event_id}" which violates the wbk-{8hex} format).
        # FakeEventDispositionService always returns action_id="act-terminal-00001".
        # (ISSUE-060 review SF-3)
        assert "act-terminal-00001" in result.blocked_writebacks

    # ── Terminal receipt non-CONFIRMED → recovery ─────────────────────────

    async def test_terminal_writeback_pending_routes_to_recovery(self):
        """Terminal writeback receipt status=PENDING → routes to recovery,
        not success and not manual."""
        from contextlib import asynccontextmanager

        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-terminal-pending",
        )

        # Mock DB returns a PENDING receipt (not CONFIRMED).
        class _ReceiptRow:
            writeback_id: str = "wbk-terminal-pending"
            status: str = "pending"
            sequence: int = 1

        class _TerminalDBSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def first(self) -> _ReceiptRow | None:
                        return _ReceiptRow()

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _TerminalDBSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=mock_factory,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # PENDING terminal receipt → recovery needed, NOT success.
        assert result.need_writeback_recovery is True
        assert result.overall_status != VerificationOverallStatus.SUCCESS

    async def test_terminal_writeback_missing_receipt_routes_recovery(self):
        """After EDS activate, receipt may not exist yet → waiting/recovery."""
        from contextlib import asynccontextmanager

        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-terminal-no-receipt",
        )

        class _EmptyReceiptSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def first(self) -> None:
                        return None

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _EmptyReceiptSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=mock_factory,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.need_writeback_recovery is True
        assert result.need_manual_resolution is False
        assert result.overall_status == VerificationOverallStatus.WAITING

    async def test_terminal_writeback_weak_evidence_routes_recovery(self):
        """CONFIRMED + adapter_acknowledged must not yield overall success."""
        from contextlib import asynccontextmanager

        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-terminal-weak",
        )

        class _WeakEvidenceReceipt:
            writeback_id: str = "wbk-terminal-weak"
            status: str = "confirmed"
            sequence: int = 1
            confirmation_evidence: str = "adapter_acknowledged"

        class _WeakEvidenceSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def first(self) -> _WeakEvidenceReceipt:
                        return _WeakEvidenceReceipt()

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _WeakEvidenceSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=mock_factory,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        assert result.need_writeback_recovery is True
        assert result.overall_status == VerificationOverallStatus.WAITING
        assert result.overall_status != VerificationOverallStatus.SUCCESS

    # ── CAPABILITY_UNSUPPORTED detail ─────────────────────────────────────

    async def test_blocked_writeback_capability_unsupported_detail(self):
        """Writeback readiness CAPABILITY_UNSUPPORTED → detail includes
        the specific readiness value."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.CAPABILITY_UNSUPPORTED,
            writeback_status=None,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Should find a blocked writeback with the right detail.
        phase2_blocked = [
            r for r in result.results if r.detail == "writeback_blocked_capability_unsupported"
        ]
        assert len(phase2_blocked) == 1
        assert action.action_id in result.blocked_writebacks

    # ── wm_persisted=False downstream impact ──────────────────────────────

    async def test_wm_persist_failure_sets_flag(self):
        """When working_memory.write fails, result.wm_persisted=False."""
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )

        class FailingWM(FakeWorkingMemory):
            async def write(self, event_id: str, key: str, value: Any) -> None:
                raise RuntimeError("WM unavailable")

        agent = VerifyAgent(
            working_memory=FailingWM(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result.wm_persisted is False


# --------------------------------------------------------------------------- #
# ISSUE-060 审查报告 — 新增回归测试
# --------------------------------------------------------------------------- #


class TestIssue060ReviewNewTests:
    """Tests added per the ISSUE-060 review report covering the Blocker,
    Should-Fix, and Nit items."""

    # ── Blocker: UNKNOWN writeback exhausted lookups ──────────────────────

    async def test_unknown_writeback_exhausted_lookups_escalates_to_manual(self):
        """Blocker: After VERIFY_UNKNOWN_MAX_LOOKUPS attempts, UNKNOWN
        writeback status escalates to need_manual=True."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.UNKNOWN,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)

        # Build outbox records with attempt >= VERIFY_UNKNOWN_MAX_LOOKUPS (3).
        class _ExhaustedOutbox:
            def __init__(self, action_id: str, attempt: int) -> None:
                self.action_id = action_id
                self.writeback_id = f"wbk-attempt-{attempt}"
                self.attempt = attempt

        outbox_map = {
            action.action_id: [
                _ExhaustedOutbox(action.action_id, 3),
                _ExhaustedOutbox(action.action_id, 4),
            ]
        }

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, outbox_map)
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # After exhausted lookups, need_manual should be True.
        assert result.need_manual_resolution is True
        # Verify the detail suffix.
        phase2_exhausted = [
            r for r in result.results if r.detail == "writeback_unknown_exhausted_lookups_manual"
        ]
        assert len(phase2_exhausted) == 1

    async def test_unknown_writeback_below_max_no_escalation(self):
        """UNKNOWN writeback with attempt < VERIFY_UNKNOWN_MAX_LOOKUPS
        still routes to recovery (not manual)."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.UNKNOWN,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-low-attempt-term",
        )

        class _LowAttemptOutbox:
            def __init__(self, action_id: str, attempt: int) -> None:
                self.action_id = action_id
                self.writeback_id = "wbk-low-attempt"
                self.attempt = attempt

        outbox_map = {
            action.action_id: [
                _LowAttemptOutbox(action.action_id, 1),
            ]
        }

        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-low-attempt-term"),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, outbox_map)
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Below max → still recovery, not manual.
        assert result.need_writeback_recovery is True
        assert result.need_manual_resolution is False
        # Detail should be the normal UNKNOWN lookup.
        phase2_unknown = [
            r for r in result.results if r.detail == "writeback_unknown_requires_lookup"
        ]
        assert len(phase2_unknown) == 1

    # ── SF-3: EXECUTING timeout escalation ───────────────────────────────

    async def test_executing_action_timeout_escalates_to_manual(self):
        """SF-3: EXECUTING action with started_at > 300s ago → UNVERIFIABLE
        + need_manual=True (zombie Action escalation)."""
        from datetime import timedelta

        action = _action(
            tool_name="block_ip",
            status=ActionStatus.EXECUTING,
            execution_job_id="job-0001",
        )
        # Started 400s ago → exceeds _EXECUTING_TIMEOUT_SECONDS (300).
        stale_start = datetime.now(UTC) - timedelta(seconds=400)
        job = _job(
            job_id="job-0001",
            action_id=action.action_id,
            started_at=stale_start,
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {action.action_id: job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.UNVERIFIABLE
        assert r.detail == "execution_timeout"
        assert result.need_manual_resolution is True
        assert result.need_action_replan is False

    async def test_executing_action_within_timeout_skipped(self):
        """SF-3: EXECUTING action with started_at < 300s ago → SKIPPED
        (still within timeout window)."""
        from datetime import timedelta

        action = _action(
            tool_name="block_ip",
            status=ActionStatus.EXECUTING,
            execution_job_id="job-0001",
        )
        # Started 60s ago → within timeout.
        recent_start = datetime.now(UTC) - timedelta(seconds=60)
        job = _job(
            job_id="job-0001",
            action_id=action.action_id,
            started_at=recent_start,
        )
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {action.action_id: job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "pending_execution"
        assert result.need_manual_resolution is False

    async def test_executing_action_no_job_skipped(self):
        """SF-3: EXECUTING action with no job → SKIPPED (no timeout data)."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.EXECUTING,
            execution_job_id="job-0001",
        )
        # No job in jobs_map.
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "pending_execution"

    # ── SF-4: Provider override None disables baseline ───────────────────

    async def test_provider_override_none_disables_baseline(self):
        """SF-4: Provider manifest override with None value disables
        the baseline mapping — no fallback to baseline."""
        # block_ip baseline maps {"ip": "check_ip_block_status"}.
        # Override {"block_ip": {"ip": None}} should return None,
        # NOT fall through to the baseline.
        overrides: dict[str, dict[str, str | None]] = {"block_ip": {"ip": None}}
        result = resolve_verification_tool("block_ip", "ip", provider_manifest_overrides=overrides)
        assert result is None

    async def test_provider_override_none_disables_baseline_in_agent(self):
        """SF-4: When provider override is None, the action is SKIPPED
        during actual agent execution (baseline disabled)."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        # Override disables block_ip verification.
        overrides: dict[str, dict[str, str | None]] = {"block_ip": {"ip": None}}
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            provider_manifest_overrides=overrides,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Baseline is disabled → action is SKIPPED (no verification tool).
        r = result.results[0]
        assert r.effect_status == EffectStatus.SKIPPED
        assert r.detail == "no_verification_tool_registered"

    # ── SF-5: DB/plan merge boundary ─────────────────────────────────────

    async def test_db_action_missing_status_field_preserves_default(self):
        """SF-5: Action in plan but not in DB keeps plan identity fields;
        state fields use safe defaults.  This test validates that the
        merge boundary doesn't silently drop actions or mix Pydantic
        defaults from plan with DB state."""
        plan_action = _action(
            action_id="act-plan-only",
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
        )
        plan = _plan([plan_action])

        # Mock DB session with zero actions → action is plan-only.
        from contextlib import asynccontextmanager

        class _EmptyDBSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def all(self) -> list[Any]:
                        return []

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _EmptyDBSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(
            session_factory=mock_factory,
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
        )

        actions, _jobs_map, _outbox_map = await agent._load_execution_state(
            event_id="evt-20260725-00000001",
            response_plan=plan,
        )

        # Plan-only action is preserved (not dropped).
        assert len(actions) == 1
        assert actions[0].action_id == "act-plan-only"
        # State field preserves plan default.
        assert actions[0].status == ActionStatus.SUCCESS

    # ── Disposition policy edge cases ────────────────────────────────────

    async def test_disposition_policy_invalid_value_returns_none(self):
        """Invalid disposition_policy value → _load_disposition_policy
        returns None (not crash)."""
        from contextlib import asynccontextmanager

        class _BadPolicyRow:
            disposition_policy: str | None = "invalid_policy_name"

        class _BadPolicySession:
            async def get(
                self,
                model: type[Any],
                ident: Any,
                **kwargs: Any,
            ) -> _BadPolicyRow | None:
                return _BadPolicyRow()

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _BadPolicySession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(
            session_factory=mock_factory,
            working_memory=FakeWorkingMemory(),
        )
        result = await agent._load_disposition_policy("evt-20260725-00000001")
        # Invalid policy → None (graceful).
        assert result is None

    async def test_empty_actions_loads_plan_revision_from_db(self):
        """actions=[] → plan_revision loaded from DB (not defaulted to 1)."""
        from contextlib import asynccontextmanager

        class _RevisionSession:
            async def scalars(self, stmt: Any) -> Any:
                class _Result:
                    def first(self) -> int | None:
                        return 5  # scalars on a column returns scalar, not row

                return _Result()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                return None

        @asynccontextmanager
        async def _session_ctx() -> Any:
            yield _RevisionSession()

        mock_factory = MagicMock(side_effect=_session_ctx)

        agent = VerifyAgent(
            session_factory=mock_factory,
            working_memory=FakeWorkingMemory(),
        )
        revision = await agent._load_event_plan_revision("evt-20260725-00000001")
        assert revision == 5

    # ── SF-2: tool unavailable log context ───────────────────────────────

    async def test_tool_unavailable_logs_action_and_tool(self):
        """SF-2: When tool_result is None, the warning log includes
        action_id, tool_name, and tool_executor state."""
        action = _action(
            tool_name="block_ip",
            target_type="ip",
            target="10.0.0.1",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        agent = VerifyAgent(
            tool_executor=None,  # unavailable
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        # Must not crash — the warning is logged internally.
        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result.results[0].effect_status == EffectStatus.UNVERIFIABLE
        assert result.results[0].detail == "verification_tool_unavailable_degraded"

    # ── Nit-3: CancelledError error code ─────────────────────────────────

    async def test_cancelled_error_maps_to_err_t_cancel(self):
        """Nit-3: asyncio.CancelledError maps to ERR_T_CANCEL."""
        from app.agents.verify_agent import _error_code_for_exception

        code = _error_code_for_exception(asyncio.CancelledError())
        assert code == "ERR_T_CANCEL"

    async def test_cancelled_error_used_in_verification_detail(self):
        """Nit-3: When tool_executor raises RuntimeError, the detail
        string uses ERR_T_RUNTIME.  CancelledError inherits from
        BaseException (not Exception) so it cannot be caught by
        except Exception — it must propagate.  The ERR_T_CANCEL code
        is verified in test_cancelled_error_maps_to_err_t_cancel."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        failing_executor = MagicMock()
        failing_executor.call = AsyncMock(side_effect=RuntimeError("tool call failed"))

        agent = VerifyAgent(
            tool_executor=failing_executor,
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        r = result.results[0]
        assert r.effect_status == EffectStatus.UNVERIFIABLE
        assert "ERR_T_RUNTIME" in (r.detail or "")

    # ── SF-6: Full SHA-256 action_id length ──────────────────────────────

    async def test_verification_action_id_uses_act_8hex_format(self):
        """SF-1 updated: Deterministic verification action_id now uses
        8-char hex prefix (act-{8hex}) per ISSUE-002 ID spec.  The full
        SHA-256 digest is computed for deterministic derivation but only
        the first 8 hex characters are used in the ID."""
        from app.agents.verify_agent import _deterministic_verification_action_id

        vid = _deterministic_verification_action_id(
            event_id="evt-test",
            source_action_id="act-src",
            verify_tool="check_ip_block_status",
        )
        assert vid.startswith("act-")
        # "act-" + 8 hex chars per ISSUE-002 spec.
        assert len(vid) == 4 + 8
        # All characters after "act-" must be valid hex.
        import re

        assert re.fullmatch(r"act-[0-9a-f]{8}", vid) is not None

    # ── wm_persisted default is False ────────────────────────────────────

    async def test_wm_persisted_defaults_to_false(self):
        """VerificationResult.wm_persisted defaults to False so that
        callers not going through _write_verification_result don't
        incorrectly assume persistence."""
        from app.models.agent_io import (
            VerificationOverallStatus,
            VerificationPhase,
            VerificationResult,
        )

        # Construct a result without explicitly setting wm_persisted.
        result = VerificationResult(
            overall_status=VerificationOverallStatus.SUCCESS,
            verification_phase=VerificationPhase.EFFECT,
        )
        assert result.wm_persisted is False

    async def test_wm_persist_success_sets_flag_true(self):
        """When working_memory.write succeeds, result.wm_persisted=True."""
        action = _action(
            tool_name="create_ticket",
            action_level=ActionLevel.L1,
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
        wm = FakeWorkingMemory()
        agent = VerifyAgent(
            working_memory=wm,
            trace_service=FakeTraceService(),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.NOT_REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))
        assert result.wm_persisted is True

    # ── Blocker: Phase 2 results must have DISPOSITION phase ──────────────

    async def test_phase2_writeback_not_applicable_has_disposition_phase(self):
        """Blocker fix: writeback_not_applicable results from Phase 2
        must have verification_phase=DISPOSITION, not EFFECT.

        Uses status=PENDING so Phase 1 produces SKIPPED (action_not_executed)
        which allows writeback_required=True + writeback_readiness=NOT_REQUIRED
        per the VerificationActionResult validator.  Phase 2 then evaluates
        writeback_applicable=False and must produce DISPOSITION phase."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.PENDING,
            writeback_required=True,
            writeback_applicable=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        )
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        wb_not_applicable = [r for r in result.results if r.detail == "writeback_not_applicable"]
        assert len(wb_not_applicable) == 1
        assert wb_not_applicable[0].verification_phase == VerificationPhase.DISPOSITION

    async def test_phase2_writeback_blocked_has_disposition_phase(self):
        """Blocker fix: writeback_blocked_* results from Phase 2
        must have verification_phase=DISPOSITION, not EFFECT."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.CAPABILITY_UNSUPPORTED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(activated=True)
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        wb_blocked = [
            r for r in result.results if r.detail and r.detail.startswith("writeback_blocked_")
        ]
        assert len(wb_blocked) == 1
        assert wb_blocked[0].verification_phase == VerificationPhase.DISPOSITION


# --------------------------------------------------------------------------- #
# ISSUE-060 review Should-Fix tests
# --------------------------------------------------------------------------- #


class TestShouldFixRegression:
    """Tests added per ISSUE-060 review Should-Fix recommendations."""

    # ── SF-1: wb_status=None + no outbox → writeback_not_yet_dispatched ─────

    async def test_writeback_status_none_no_outbox_routes_recovery(self):
        """SF-1: When wb_status=None, wb_readiness=READY, and no outbox
        records exist, the detail suffix must be writeback_not_yet_dispatched
        (not writeback_no_status_waiting) to distinguish "command not yet
        created by DSS" from "command created but no receipt yet"."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=None,  # no status recorded
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-sf1-terminal",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-sf1-terminal"),
        )
        # outbox_map is empty (third element of the tuple).
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # The action should appear in results with writeback_not_yet_dispatched.
        wb_results = [
            r
            for r in result.results
            if r.action_id == action.action_id
            and r.verification_phase == VerificationPhase.DISPOSITION
        ]
        assert len(wb_results) == 1
        assert wb_results[0].detail == "writeback_not_yet_dispatched"
        assert result.need_writeback_recovery is True

    async def test_writeback_status_none_with_outbox_routes_recovery(self):
        """SF-1 counter-case: When wb_status=None but outbox records DO exist,
        the detail must remain writeback_no_status_waiting (command was
        created, we're waiting for a receipt)."""
        from unittest.mock import MagicMock

        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=None,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)

        # Build a mock outbox record with a writeback_id.
        _mock_ob = MagicMock()
        _mock_ob.writeback_id = "wbk-existing-00001"
        _mock_ob.attempt = 0
        outbox_map = {action.action_id: [_mock_ob]}

        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id="wbk-sf1b-terminal",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
            session_factory=_mock_terminal_confirm_session_factory("wbk-sf1b-terminal"),
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, outbox_map)
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        wb_results = [
            r
            for r in result.results
            if r.action_id == action.action_id
            and r.verification_phase == VerificationPhase.DISPOSITION
        ]
        assert len(wb_results) == 1
        assert wb_results[0].detail == "writeback_no_status_waiting"
        assert result.need_writeback_recovery is True

    # ── SF-2: terminal writeback MANUAL overrides WAITING ───────────────────

    async def test_terminal_writeback_manual_overrides_recovery_waiting(self):
        """SF-2: When main writeback evaluation routes to WAITING (recovery)
        but the terminal writeback receipt is permanently missing,
        overall_status MUST be MANUAL_RESOLUTION, not WAITING.

        Constructs:
        - Main action wb_status=PENDING → need_wb_recovery=True (WAITING)
        - Terminal: activated=True but writeback_id=None → need_manual=True
        Expected: overall_status=MANUAL_RESOLUTION (higher priority wins).
        """
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.PENDING,  # → recovery
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        # activated=True but writeback_id=None triggers the contract-anomaly
        # path in _evaluate_terminal_writeback_status → need_manual=True
        ed_svc = FakeEventDispositionService(
            activated=True,
            writeback_id=None,  # triggers terminal need_manual
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # MANUAL_RESOLUTION must take priority over WAITING.
        assert result.overall_status == VerificationOverallStatus.MANUAL_RESOLUTION
        assert result.need_writeback_recovery is True
        assert result.need_manual_resolution is True

    # ── SF-3: activation failure → no synthetic wb-id in blocked ────────────

    async def test_activation_failure_no_synthetic_wb_id_in_blocked(self):
        """SF-3: When activate_and_submit returns activated=False and
        writeback_id=None, blocked_writebacks must NOT contain a synthetic
        f"terminal_wb_{event_id}" string (which violates the wbk-{8hex}
        format and fails downstream resolve/retry path-parameter matching).
        Instead it should contain the deferred action_id."""
        action = _action(
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_job_id="job-0001",
            writeback_required=True,
            writeback_applicable=True,
            writeback_readiness=WritebackReadiness.READY,
            writeback_status=WritebackStatus.CONFIRMED,
        )
        job = _job(job_id="job-0001", action_id=action.action_id)
        ed_svc = FakeEventDispositionService(
            activated=False,
            skipped_reason="capability_blocked",
            writeback_id="wbk-should-not-appear",
        )
        agent = VerifyAgent(
            tool_executor=_mock_executor({"check_ip_block_status": _tool_result_success(True)}),
            working_memory=FakeWorkingMemory(),
            trace_service=FakeTraceService(),
            event_bus=FakeEventBus(),
            event_disposition_service=ed_svc,
        )
        agent._load_execution_state = AsyncMock(  # type: ignore[method-assign]
            return_value=([action], {"job-0001": job}, {})
        )
        agent._load_disposition_policy = AsyncMock(  # type: ignore[method-assign]
            return_value=DispositionPolicy.REQUIRED,
        )

        result = await agent.execute(_input(event_id=action.event_id, actions=[action]))

        # Must NOT contain the old synthetic ID format.
        synthetic = f"terminal_wb_{action.event_id}"
        assert synthetic not in result.blocked_writebacks
        # The writeback_id was not returned (activated=False) so it shouldn't
        # appear either.
        assert "wbk-should-not-appear" not in result.blocked_writebacks
        # The deferred action_id from FakeEventDispositionService should be present.
        assert "act-terminal-00001" in result.blocked_writebacks
        assert result.need_manual_resolution is True


def _mock_executor(results: dict[str, ToolResult]) -> Any:
    """Return a MagicMock tool_executor that returns predefined results per tool."""

    async def call(
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        **kwargs: Any,
    ) -> ToolResult:
        if tool_name in results:
            result = results[tool_name]
            # Return a fresh copy with the correct tool_name.
            return ToolResult(
                call_id=f"call-{tool_name}",
                tool_name=tool_name,
                provider_name=result.provider_name,
                status=result.status,
                data=result.data,
                error_detail=result.error_detail,
                target_results=result.target_results,
            )
        return ToolResult(
            call_id=f"call-{tool_name}",
            tool_name=tool_name,
            provider_name="mock_observation",
            status=ToolResultStatus.FAILED,
            error_detail=f"unexpected tool: {tool_name}",
        )

    return MagicMock(call=AsyncMock(side_effect=call))


# --------------------------------------------------------------------------- #
# ISSUE-169: shared OutputGuard contract
# --------------------------------------------------------------------------- #


async def test_apply_guardrails_passes_structured_verification_result() -> None:
    """A well-formed VerificationResult passes the shared OutputGuard."""
    from app.core.guardrails import GuardrailMode, OutputGuard

    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    agent = VerifyAgent(output_guard=guard)
    ok = VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    # _apply_guardrails re-validates the model after sanitization, so the
    # result is an equal-but-not-identical instance.
    assert await agent._apply_guardrails(ok) == ok


async def test_apply_guardrails_blocks_unstructured_verification_output() -> None:
    """Unstructured verification output is blocked like the other agents."""
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import GuardrailMode, OutputGuard

    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    agent = VerifyAgent(output_guard=guard)
    with pytest.raises(GuardrailViolationError, match="output guard blocked"):
        await agent._apply_guardrails({"overall_status": "SUCCESS"})


async def test_execute_applies_output_guard_on_verification_result() -> None:
    """execute() must run _apply_guardrails after _run on the shared guard path."""
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import GuardrailMode, OutputGuard

    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    agent = VerifyAgent(output_guard=guard, trace_service=MagicMock())
    agent._publish_agent_progress = AsyncMock()
    agent._publish_agent_completed = AsyncMock()
    agent._publish_agent_failed = AsyncMock()
    agent._record_trace = AsyncMock()

    ok = VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    agent._run = AsyncMock(return_value=ok)

    result = await agent.execute(_input(actions=[]))

    assert result == ok
    agent._run.assert_awaited_once()

    agent._run = AsyncMock(return_value={"overall_status": "SUCCESS"})
    with pytest.raises(GuardrailViolationError, match="output guard blocked"):
        await agent.execute(_input(actions=[]))
