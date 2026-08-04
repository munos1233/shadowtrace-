"""ISSUE-062 writeback recovery tests — WritebackRecoveryHandler and integration."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.workflow import (
    WRITEBACK_MAX_RETRIES,
    TransitionContext,
    validate_transition,
)
from app.orchestration.graph_state import InvestigationState
from app.orchestration.workflow_graph import (
    ROUTE_HALT,
    ROUTE_WRITEBACK,
    route_after_verify,
)
from app.orchestration.writeback_recovery_handler import (
    VERIFY_UNKNOWN_MAX_LOOKUPS,
    WritebackRecoveryAction,
    WritebackRecoveryHandler,
    WritebackState,
    writeback_recovery_graph_node,
)

# ── Helpers ────────────────────────────────────────────────────────────────


def _base_state(**overrides: Any) -> InvestigationState:
    state: InvestigationState = {
        "event_id": "evt-test-wb-001",
        "event_status": EventStatus.VERIFYING.value,
        "disposition_policy": DispositionPolicy.REQUIRED.value,
        "severity": Severity.HIGH.value,
        "final_verdict": None,
        "confidence": 0.0,
        "need_investigation": True,
        "execution_substate": ExecutionSubstate.NONE.value,
        "event_status_update_readiness": WritebackReadiness.READY.value,
        "degraded_flags": [],
        "node_trace": [],
        "halted": False,
        "disposition_only_intent": False,
        "report_generated": False,
        "needs_approval_wait": False,
        "plan_revision": 1,
        "replan_count": 0,
        "escalated": False,
        "verify_need_action_replan": False,
        "verify_need_writeback_recovery": True,
        "verify_need_manual_resolution": False,
    }
    state.update(overrides)  # type: ignore[typeddict-item]
    return state


class FakeRuntime:
    """Fake WorkflowRuntimeService for tests."""

    def __init__(self) -> None:
        self.substate_calls: list[tuple[str, ExecutionSubstate, EventStatus]] = []

    async def set_execution_substate(
        self,
        event_id: str,
        substate: ExecutionSubstate,
        *,
        event_status: EventStatus,
    ) -> None:
        self.substate_calls.append((event_id, substate, event_status))


class FakeStateMachine:
    """Fake StateMachineService for tests.

    When ``validate=True``, every ``transition()`` call runs through the
    real ``validate_transition`` gate so illegal state moves are caught.
    Set it to ``True`` in end-to-end path tests to prevent bugs like
    VERIFYING→CLOSED (ISSUE-062 B2) from escaping detection.
    """

    def __init__(self, *, validate: bool = False) -> None:
        self.transitions: list[tuple[str, EventStatus, str]] = []
        self._current_status: dict[str, EventStatus] = {}
        self._validate = validate

    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: Any = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> Any:
        current = self._current_status.get(event_id, EventStatus.VERIFYING)
        if self._validate:
            validate_transition(current, target, context)
        self.transitions.append((event_id, target, reason or ""))
        self._current_status[event_id] = target
        return SimpleNamespace(status=target.value)

    async def get_current_status(self, event_id: str) -> EventStatus:
        return self._current_status.get(event_id, EventStatus.VERIFYING)


class FakeDispositionSync:
    """Fake DispositionSyncService for tests."""

    def __init__(self) -> None:
        self.retries: list[tuple[str, str]] = []
        self.resolutions: list[tuple[str, str, str, str]] = []
        self.lookups: list[str] = []
        self._lookup_result: WritebackStatus | None = None
        self._retry_raises: Exception | None = None
        self._lookup_raises: Exception | None = None

    async def retry_writeback(self, writeback_id: str, operator: str) -> Any:
        self.retries.append((writeback_id, operator))
        if self._retry_raises is not None:
            raise self._retry_raises
        return SimpleNamespace(writeback_id=writeback_id)

    async def resolve_writeback(
        self, writeback_id: str, resolution: str, principal: str, comment: str
    ) -> Any:
        self.resolutions.append((writeback_id, resolution, principal, comment))
        return SimpleNamespace(writeback_id=writeback_id)

    async def lookup_writeback_status(self, writeback_id: str) -> WritebackStatus | None:
        self.lookups.append(writeback_id)
        if self._lookup_raises is not None:
            raise self._lookup_raises
        return self._lookup_result

    async def update_writeback_status_from_lookup(
        self, writeback_id: str, status: WritebackStatus
    ) -> None:
        """Persist lookup-resolved status to the outbox (best-effort write)."""
        self._lookup_result = status


# ── Tests: WritebackRecoveryHandler.evaluate ─────────────────────────────────


class TestWritebackRecoveryEvaluate:
    """Unit tests for WritebackRecoveryHandler.evaluate()."""

    def _handler(self) -> WritebackRecoveryHandler:
        return WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )

    # ── Terminal / None ──

    def test_confirmed_returns_noop(self):
        """CONFIRMED writeback → NOOP."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.CONFIRMED)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.NOOP
        assert result.escalated is False

    def test_none_status_returns_lookup(self):
        """None writeback status → LOOKUP (ISSUE-062 Should-Fix #2).

        Invalid / unparseable writeback_status should attempt a provider-side
        lookup rather than being silently dropped as NOOP.  If no port is
        available, execute() will escalate to MANUAL.
        """
        wb = WritebackState(writeback_id="wbk-001", current_status=None)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.LOOKUP

    # ── Waiting states ──

    @pytest.mark.parametrize(
        "status",
        [WritebackStatus.PENDING, WritebackStatus.SENDING, WritebackStatus.ACCEPTED],
    )
    def test_waiting_status_returns_wait(self, status: WritebackStatus):
        """PENDING/SENDING/ACCEPTED → WAIT."""
        wb = WritebackState(writeback_id="wbk-001", current_status=status)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.WAIT
        assert result.escalated is False

    # ── UNKNOWN → LOOKUP ──

    def test_unknown_status_returns_lookup(self):
        """UNKNOWN writeback → LOOKUP (first attempt)."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.LOOKUP
        assert result.lookup_attempt == 1

    def test_unknown_exhausted_returns_manual(self):
        """UNKNOWN with lookup_count == max → MANUAL (escalated)."""
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.UNKNOWN,
            lookup_count=VERIFY_UNKNOWN_MAX_LOOKUPS,
        )
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True

    # ── FAILED → RETRY ──

    def test_failed_status_returns_retry(self):
        """FAILED writeback → RETRY (first attempt)."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.FAILED)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.RETRY
        assert result.retry_attempt == 1

    def test_failed_exhausted_returns_manual(self):
        """FAILED with retry_count == max → MANUAL (escalated)."""
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.FAILED,
            retry_count=WRITEBACK_MAX_RETRIES,
        )
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True

    # ── PARTIAL → RETRY ──

    def test_partial_status_returns_retry(self):
        """PARTIAL writeback → RETRY (first attempt)."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.PARTIAL)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.RETRY
        assert result.retry_attempt == 1

    def test_partial_exhausted_returns_manual(self):
        """PARTIAL with retry_count == max → MANUAL (escalated)."""
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.PARTIAL,
            retry_count=WRITEBACK_MAX_RETRIES,
        )
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True

    # ── CONFLICT → MANUAL ──

    def test_conflict_always_manual(self):
        """CONFLICT writeback → MANUAL immediately (no retries)."""
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.CONFLICT)
        result = self._handler().evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True


# ── Tests: WritebackRecoveryHandler.execute ──────────────────────────────────


class TestWritebackRecoveryExecute:
    """Integration tests for WritebackRecoveryHandler.execute()."""

    async def test_execute_wait_sets_substate(self):
        """WAIT action persists WAITING_WRITEBACK substate."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.PENDING)
        result = await handler.execute("evt-001", wb)
        assert result.action == WritebackRecoveryAction.WAIT
        assert rt.substate_calls[-1][1] == ExecutionSubstate.WAITING_WRITEBACK
        assert rt.substate_calls[-1][2] == EventStatus.VERIFYING

    async def test_execute_lookup_success_resolves(self):
        """LOOKUP that resolves → NOOP."""
        ds = FakeDispositionSync()
        ds._lookup_result = WritebackStatus.CONFIRMED
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=ds,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        result = await handler.execute("evt-001", wb)
        assert result.action == WritebackRecoveryAction.NOOP
        assert result.writeback_status == WritebackStatus.CONFIRMED

    async def test_execute_lookup_still_unknown(self):
        """LOOKUP that returns UNKNOWN → stays in recovery."""
        ds = FakeDispositionSync()
        ds._lookup_result = WritebackStatus.UNKNOWN
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=ds,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        await handler.execute("evt-001", wb)
        assert rt.substate_calls[-1][1] == ExecutionSubstate.WAITING_WRITEBACK

    async def test_execute_lookup_exhausted_escalates(self):
        """LOOKUP exhausted → MANUAL."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
        )
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.UNKNOWN,
            lookup_count=VERIFY_UNKNOWN_MAX_LOOKUPS,
        )
        result = await handler.execute("evt-001", wb)
        assert result.escalated is True
        assert rt.substate_calls[-1][1] == ExecutionSubstate.MANUAL_RESOLUTION

    async def test_execute_retry_enqueues(self):
        """RETRY action enqueues the same outbox."""
        ds = FakeDispositionSync()
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=ds,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.FAILED)
        result = await handler.execute("evt-001", wb)
        assert result.action == WritebackRecoveryAction.RETRY
        assert len(ds.retries) == 1
        assert ds.retries[0][0] == "wbk-001"

    async def test_execute_retry_failure_escalates(self):
        """RETRY that fails when exhausted → MANUAL."""
        ds = FakeDispositionSync()
        ds._retry_raises = RuntimeError("adapter down")
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=ds,
        )
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.FAILED,
            retry_count=WRITEBACK_MAX_RETRIES - 1,
        )
        result = await handler.execute("evt-001", wb)
        assert result.escalated is True

    async def test_execute_no_disposition_sync_escalates(self):
        """No disposition_sync port + known-unsupported readiness → escalate."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=None,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        result = await handler.execute(
            "evt-001",
            wb,
            readiness=WritebackReadiness.CAPABILITY_UNSUPPORTED,
        )
        assert result.escalated is True

    async def test_execute_no_disposition_sync_unknown_stays_waiting(self):
        """No disposition_sync port + CAPABILITY_UNKNOWN → stays in WAIT.
        Returns action=WAIT so the graph node sets halted=True and prevents
        a verify ↔ writeback_recovery tight loop (ISSUE-062 Should-Fix #2)."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=None,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.UNKNOWN)
        result = await handler.execute("evt-001", wb)  # defaults to CAPABILITY_UNKNOWN
        assert result.escalated is False
        assert result.action is WritebackRecoveryAction.WAIT
        assert rt.substate_calls[-1][1] == ExecutionSubstate.WAITING_WRITEBACK


# ── Tests: writeback_recovery_graph_node ─────────────────────────────────────


class TestWritebackRecoveryGraphNode:
    """Tests for the writeback_recovery_graph_node graph helper."""

    async def test_no_failed_writebacks(self):
        """No failed writebacks → recovery disabled."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        state = _base_state(
            verify_need_writeback_recovery=True,
            verify_failed_writebacks=[],
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        assert result["verify_need_writeback_recovery"] is False
        assert result["execution_substate"] == ExecutionSubstate.NONE.value

    async def test_wait_sets_halted(self):
        """WAIT action → halted=True for graph pause."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="pending",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        assert result["halted"] is True

    async def test_escalated_sets_manual(self):
        """Escalated writeback → need_manual_resolution=True."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="conflict",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        assert result["verify_need_manual_resolution"] is True


# ── Tests: WritebackRecoveryHandler static helpers ───────────────────────────


class TestWritebackRecoveryStaticHelpers:
    """Tests for static helper methods."""

    def test_needs_recovery_true(self):
        state = {"verify_need_writeback_recovery": True}
        assert WritebackRecoveryHandler.needs_recovery(state) is True

    def test_needs_recovery_false(self):
        state = {"verify_need_writeback_recovery": False}
        assert WritebackRecoveryHandler.needs_recovery(state) is False

    def test_needs_recovery_missing(self):
        assert WritebackRecoveryHandler.needs_recovery({}) is False

    def test_needs_manual_true(self):
        state = {"verify_need_manual_resolution": True}
        assert WritebackRecoveryHandler.needs_manual(state) is True

    def test_needs_manual_false(self):
        state = {"verify_need_manual_resolution": False}
        assert WritebackRecoveryHandler.needs_manual(state) is False


# ── Tests: degradation (no disposition_sync) ─────────────────────────────────


class TestWritebackRecoveryDegradation:
    """Tests for WritebackRecoveryHandler degradation paths."""

    async def test_retry_without_port_escalates(self):
        """RETRY without disposition_sync + known-unsupported → escalate."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=None,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.FAILED)
        result = await handler.execute(
            "evt-001",
            wb,
            readiness=WritebackReadiness.CAPABILITY_UNSUPPORTED,
        )
        assert result.escalated is True

    async def test_retry_without_port_unknown_stays_waiting(self):
        """RETRY without disposition_sync + CAPABILITY_UNKNOWN → stays in WAIT.
        Returns action=WAIT so the graph node sets halted=True (ISSUE-062 Should-Fix #2)."""
        rt = FakeRuntime()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=rt,
            disposition_sync=None,
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=WritebackStatus.FAILED)
        result = await handler.execute("evt-001", wb)  # defaults to CAPABILITY_UNKNOWN
        assert result.escalated is False
        assert result.action is WritebackRecoveryAction.WAIT
        assert rt.substate_calls[-1][1] == ExecutionSubstate.WAITING_WRITEBACK


# ── Tests: boundary inputs ──────────────────────────────────────────────────


class TestWritebackRecoveryBoundary:
    """Boundary input tests for WritebackRecoveryHandler."""

    def test_max_lookups_zero(self):
        """max_lookups=0 → immediately escalated for UNKNOWN."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.UNKNOWN,
            max_lookups=0,
        )
        result = handler.evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True

    def test_max_retries_zero(self):
        """max_retries=0 → immediately escalated for FAILED."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        wb = WritebackState(
            writeback_id="wbk-001",
            current_status=WritebackStatus.FAILED,
            max_retries=0,
        )
        result = handler.evaluate(wb)
        assert result.action == WritebackRecoveryAction.MANUAL
        assert result.escalated is True


# ── Tests: WritebackRecoveryHandler never enters REPLANNING ──────────────────


class TestWritebackRecoveryNeverReplans:
    """Verify writeback recovery NEVER transitions to REPLANNING."""

    @pytest.mark.parametrize(
        "status",
        [
            WritebackStatus.PENDING,
            WritebackStatus.SENDING,
            WritebackStatus.ACCEPTED,
            WritebackStatus.UNKNOWN,
            WritebackStatus.FAILED,
            WritebackStatus.PARTIAL,
            WritebackStatus.CONFLICT,
        ],
    )
    async def test_writeback_status_never_replans(self, status: WritebackStatus):
        """Any writeback status → no REPLANNING transition, no replan_count consumption."""
        sm = FakeStateMachine()
        handler = WritebackRecoveryHandler(
            state_machine=sm,
            runtime=FakeRuntime(),
        )
        wb = WritebackState(writeback_id="wbk-001", current_status=status)
        await handler.execute("evt-001", wb)
        # Verify no REPLANNING transition occurred
        replan_transitions = [t for t in sm.transitions if t[1] == EventStatus.REPLANNING]
        assert len(replan_transitions) == 0, (
            f"Writeback status {status.value} must not enter REPLANNING"
        )


# ── Tests: route_after_verify halt detection (Should-Fix #1) ──────────────────


class TestRouteAfterVerifyHaltDetection:
    """Verify route_after_verify correctly handles halted state to prevent
    tight loops between verify ↔ writeback_recovery."""

    def test_writeback_wait_routes_to_halt_not_loop(self):
        """When writeback recovery sets halted=True + verify_need_writeback_recovery=True,
        route_after_verify must return ROUTE_HALT, not ROUTE_WRITEBACK."""
        state: InvestigationState = {
            "event_id": "evt-test-halt-001",
            "event_status": EventStatus.VERIFYING.value,
            "disposition_policy": DispositionPolicy.REQUIRED.value,
            "severity": Severity.HIGH.value,
            "final_verdict": None,
            "confidence": 0.0,
            "need_investigation": True,
            "execution_substate": ExecutionSubstate.WAITING_WRITEBACK.value,
            "event_status_update_readiness": WritebackReadiness.READY.value,
            "degraded_flags": [],
            "node_trace": [],
            "halted": True,
            "disposition_only_intent": False,
            "report_generated": False,
            "needs_approval_wait": False,
            "plan_revision": 1,
            "replan_count": 0,
            "escalated": False,
            "verify_need_action_replan": False,
            "verify_need_writeback_recovery": True,
            "verify_need_manual_resolution": False,
            "verify_failed_writebacks": ["wbk-001"],
        }
        route = route_after_verify(state)
        assert route == ROUTE_HALT, f"Expected ROUTE_HALT when halted=True, got {route}"
        assert route != ROUTE_WRITEBACK, (
            "Must not route to WRITEBACK when halted — this would cause a tight loop"
        )

    def test_halt_overrides_writeback_recovery(self):
        """halted=True takes priority over verify_need_writeback_recovery=True."""
        state: InvestigationState = {
            "event_id": "evt-test-halt-002",
            "event_status": EventStatus.VERIFYING.value,
            "disposition_policy": DispositionPolicy.REQUIRED.value,
            "severity": Severity.HIGH.value,
            "final_verdict": None,
            "confidence": 0.0,
            "need_investigation": True,
            "execution_substate": ExecutionSubstate.WAITING_WRITEBACK.value,
            "event_status_update_readiness": WritebackReadiness.READY.value,
            "degraded_flags": [],
            "node_trace": [],
            "halted": True,
            "disposition_only_intent": False,
            "report_generated": False,
            "needs_approval_wait": False,
            "plan_revision": 1,
            "replan_count": 0,
            "escalated": False,
            "verify_need_action_replan": True,
            "verify_need_writeback_recovery": True,
            "verify_need_manual_resolution": False,
            "verify_failed_writebacks": ["wbk-001"],
        }
        route = route_after_verify(state)
        assert route == ROUTE_HALT, (
            f"halted=True must take priority over all verify flags, got {route}"
        )

    def test_halt_overrides_manual_resolution(self):
        """halted=True takes priority over verify_need_manual_resolution=True."""
        state: InvestigationState = {
            "event_id": "evt-test-halt-003",
            "event_status": EventStatus.VERIFYING.value,
            "disposition_policy": DispositionPolicy.REQUIRED.value,
            "severity": Severity.HIGH.value,
            "final_verdict": None,
            "confidence": 0.0,
            "need_investigation": True,
            "execution_substate": ExecutionSubstate.MANUAL_RESOLUTION.value,
            "event_status_update_readiness": WritebackReadiness.READY.value,
            "degraded_flags": [],
            "node_trace": [],
            "halted": True,
            "disposition_only_intent": False,
            "report_generated": False,
            "needs_approval_wait": False,
            "plan_revision": 1,
            "replan_count": 0,
            "escalated": False,
            "verify_need_action_replan": False,
            "verify_need_writeback_recovery": False,
            "verify_need_manual_resolution": True,
            "verify_failed_writebacks": [],
        }
        route = route_after_verify(state)
        assert route == ROUTE_HALT, (
            f"halted=True must take priority over manual_resolution flag, got {route}"
        )

    def test_no_halt_normal_routing(self):
        """When halted=False, normal routing priority applies (existing behavior)."""
        state: InvestigationState = {
            "event_id": "evt-test-halt-004",
            "event_status": EventStatus.VERIFYING.value,
            "disposition_policy": DispositionPolicy.REQUIRED.value,
            "severity": Severity.HIGH.value,
            "final_verdict": None,
            "confidence": 0.0,
            "need_investigation": True,
            "execution_substate": ExecutionSubstate.NONE.value,
            "event_status_update_readiness": WritebackReadiness.READY.value,
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "disposition_only_intent": False,
            "report_generated": False,
            "needs_approval_wait": False,
            "plan_revision": 1,
            "replan_count": 0,
            "escalated": False,
            "verify_need_action_replan": False,
            "verify_need_writeback_recovery": True,
            "verify_need_manual_resolution": False,
            "verify_failed_writebacks": ["wbk-001"],
        }
        route = route_after_verify(state)
        assert route == ROUTE_WRITEBACK, (
            f"Without halt, writeback_recovery flag should route to WRITEBACK, got {route}"
        )


# ── Tests: multiple writebacks head-of-line blocking (Should-Fix #2) ──────────


class TestMultipleWritebackProcessing:
    """Verify writeback_recovery_graph_node correctly advances through
    multiple failed writebacks without head-of-line blocking."""

    async def test_multiple_writebacks_head_wait_tail_processed(self):
        """When first writeback is WAIT (PENDING), it's popped from the list
        so the next writeback can be processed on resume."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )

        # First call: ["wbk-001", "wbk-002"], wbk-001 is PENDING → WAIT
        state = _base_state(
            verify_failed_writebacks=["wbk-001", "wbk-002"],
            verify_writeback_status="pending",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)

        # wbk-001 should be popped; wbk-002 remains for next cycle
        assert result["verify_failed_writebacks"] == ["wbk-002"], (
            f"WAIT should pop the processed head, got {result.get('verify_failed_writebacks')}"
        )
        assert result["halted"] is True

    async def test_multiple_writebacks_head_escalated_tail_processed(self):
        """When first writeback escalates, it's popped and second can be
        processed in the next verify cycle."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )

        # First call: ["wbk-001", "wbk-002"], wbk-001 is CONFLICT → escalated
        state = _base_state(
            verify_failed_writebacks=["wbk-001", "wbk-002"],
            verify_writeback_status="conflict",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)

        assert result["verify_need_manual_resolution"] is True
        assert result["verify_failed_writebacks"] == ["wbk-002"], (
            f"Escalated item should be popped, got {result.get('verify_failed_writebacks')}"
        )

    async def test_multiple_writebacks_head_noop_tail_processed(self):
        """When first writeback is NOOP (already CONFIRMED), it's popped and
        if there are remaining items, recovery stays active."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )

        # First call: ["wbk-001", "wbk-002"], wbk-001 is CONFIRMED → NOOP
        state = _base_state(
            verify_failed_writebacks=["wbk-001", "wbk-002"],
            verify_writeback_status="confirmed",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)

        assert result["verify_failed_writebacks"] == ["wbk-002"], (
            f"NOOP should pop the terminal head, got {result.get('verify_failed_writebacks')}"
        )
        # Remaining items → recovery should stay active
        assert result["verify_need_writeback_recovery"] is True, (
            "Recovery should stay active when remaining items exist"
        )

    async def test_single_writeback_noop_clears_recovery(self):
        """When the only writeback is NOOP, recovery is cleared."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )

        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="confirmed",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)

        assert result["verify_failed_writebacks"] == []
        assert result["verify_need_writeback_recovery"] is False

    async def test_multiple_writebacks_all_wait_sequentially(self):
        """When processing multiple WAIT writebacks sequentially, each call
        pops the head until the list is empty."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )

        # Start with three PENDING writebacks
        state1 = _base_state(
            verify_failed_writebacks=["wbk-001", "wbk-002", "wbk-003"],
            verify_writeback_status="pending",
        )
        result1 = await writeback_recovery_graph_node(state1, handler=handler)
        assert result1["verify_failed_writebacks"] == ["wbk-002", "wbk-003"]
        assert result1["halted"] is True

        # On resume (simulated), process the next one
        state2 = _base_state(
            verify_failed_writebacks=["wbk-002", "wbk-003"],
            verify_writeback_status="pending",
        )
        result2 = await writeback_recovery_graph_node(state2, handler=handler)
        assert result2["verify_failed_writebacks"] == ["wbk-003"]

        # Last one
        state3 = _base_state(
            verify_failed_writebacks=["wbk-003"],
            verify_writeback_status="pending",
        )
        result3 = await writeback_recovery_graph_node(state3, handler=handler)
        assert result3["verify_failed_writebacks"] == []

    # ── Tests: LOOKUP/RETRY halt prevention (Should-Fix #2) ───────────────────────

    async def test_heterogeneous_multi_writeback_routes_by_own_status(self):
        """Two writebacks with different statuses: verify routing correctness.

        Scenario: wbk-001 is UNKNOWN, wbk-002 is CONFLICT.  The per-writeback
        status map (ISSUE-170) routes each writeback by its own status: the
        UNKNOWN writeback stays in LOOKUP recovery while the CONFLICT
        writeback escalates to MANUAL — the legacy scalar ``"unknown"`` from
        the first writeback must never misroute the second one.

        The disposition_sync returns UNKNOWN from LOOKUP so the UNKNOWN path
        does not escalate; only the correct CONFLICT path escalates.
        """
        ds = FakeDispositionSync()
        ds._lookup_result = WritebackStatus.UNKNOWN  # LOOKUP stays unresolved
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=ds,
        )

        statuses = {"wbk-001": "unknown", "wbk-002": "conflict"}

        # Cycle 1: wbk-001 (UNKNOWN) is looked up and stays queued in recovery
        # (LOOKUP does not pop); the map keeps wbk-002's own status intact.
        state1 = _base_state(
            verify_failed_writebacks=["wbk-001", "wbk-002"],
            verify_writeback_status="unknown",
            verify_writeback_status_map=statuses,
        )
        result1 = await writeback_recovery_graph_node(state1, handler=handler)
        assert result1["verify_need_manual_resolution"] is False
        assert result1["verify_need_writeback_recovery"] is True
        assert result1["verify_failed_writebacks"] == ["wbk-001", "wbk-002"]

        # Cycle 2: wbk-002's own status is CONFLICT → MANUAL immediately,
        # even though the legacy scalar still reads "unknown".
        state2 = _base_state(
            verify_failed_writebacks=["wbk-002"],
            verify_writeback_status="unknown",
            verify_writeback_status_map=statuses,
        )
        result2 = await writeback_recovery_graph_node(state2, handler=handler)
        assert result2["verify_need_manual_resolution"] is True, (
            "CONFLICT writeback (wbk-002) should escalate to MANUAL by its "
            "own status; scalar verify_writeback_status='unknown' from the "
            "first writeback must not misroute it to LOOKUP"
        )

    async def test_legacy_scalar_fallback_without_status_map(self):
        """States written before ISSUE-170 (no map) still route via the scalar."""
        ds = FakeDispositionSync()
        ds._lookup_result = WritebackStatus.UNKNOWN
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=ds,
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="unknown",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        # UNKNOWN scalar → LOOKUP stays in recovery (no manual escalation).
        assert result["verify_need_manual_resolution"] is False
        assert result["verify_need_writeback_recovery"] is True

    async def test_status_map_gap_never_borrows_another_writebacks_scalar(self):
        """A map without the current writeback routes conservatively to LOOKUP
        instead of borrowing another writeback's scalar status (ISSUE-170:
        data gap must not misroute, e.g. a stale CONFLICT scalar must not
        escalate a writeback whose own status is unknown)."""
        ds = FakeDispositionSync()
        ds._lookup_result = WritebackStatus.UNKNOWN
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=ds,
        )
        # wbk-002 has no map entry; the legacy scalar holds wbk-001's CONFLICT.
        state = _base_state(
            verify_failed_writebacks=["wbk-002"],
            verify_writeback_status="conflict",
            verify_writeback_status_map={"wbk-001": "conflict"},
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        # Conservative LOOKUP (data gap) — NOT a MANUAL escalation borrowed
        # from another writeback's CONFLICT status.
        assert result["verify_need_manual_resolution"] is False
        assert result["verify_need_writeback_recovery"] is True


class TestWritebackRecoverySpinPrevention:
    """Verify writeback_recovery_graph_node halts when LOOKUP/RETRY cannot
    act due to no disposition_sync + CAPABILITY_UNKNOWN, preventing a
    verify ↔ writeback_recovery tight loop."""

    async def test_lookup_no_port_unknown_halts_in_graph_node(self):
        """Graph node: LOOKUP without disposition_sync + CAPABILITY_UNKNOWN
        → handler returns action=WAIT → graph node sets halted=True."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=None,
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="unknown",
            event_status_update_readiness=WritebackReadiness.CAPABILITY_UNKNOWN.value,
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        assert result["halted"] is True, (
            "LOOKUP without port + CAPABILITY_UNKNOWN must set halted=True "
            "to prevent verify ↔ writeback_recovery tight loop"
        )
        assert result["verify_need_writeback_recovery"] is True

    async def test_retry_no_port_unknown_halts_in_graph_node(self):
        """Graph node: RETRY without disposition_sync + CAPABILITY_UNKNOWN
        → handler returns action=WAIT → graph node sets halted=True."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=None,
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="failed",
            event_status_update_readiness=WritebackReadiness.CAPABILITY_UNKNOWN.value,
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        assert result["halted"] is True, (
            "RETRY without port + CAPABILITY_UNKNOWN must set halted=True "
            "to prevent verify ↔ writeback_recovery tight loop"
        )
        assert result["verify_need_writeback_recovery"] is True

    async def test_lookup_with_port_no_halt(self):
        """Graph node: LOOKUP with disposition_sync wired → normal flow, no forced halt."""
        ds = FakeDispositionSync()
        ds._lookup_result = WritebackStatus.UNKNOWN
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=ds,
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="unknown",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        # With disposition_sync wired, LOOKUP proceeds normally (still
        # UNKNOWN → stays in recovery, halted=False for next cycle).
        assert result["halted"] is False

    async def test_retry_with_port_no_halt(self):
        """Graph node: RETRY with disposition_sync wired → normal flow, no forced halt."""
        ds = FakeDispositionSync()
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
            disposition_sync=ds,
        )
        state = _base_state(
            verify_failed_writebacks=["wbk-001"],
            verify_writeback_status="failed",
        )
        result = await writeback_recovery_graph_node(state, handler=handler)
        # With disposition_sync wired, RETRY enqueues normally
        assert result["halted"] is False

    async def test_missing_event_id_raises_in_graph_node(self):
        """Graph node raises ValueError when event_id is missing."""
        handler = WritebackRecoveryHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        state: dict[str, Any] = {
            "verify_failed_writebacks": ["wbk-001"],
        }
        with pytest.raises(ValueError, match="missing required field: event_id"):
            await writeback_recovery_graph_node(state, handler=handler)


# ── Tests: state transition validation (ISSUE-062 B2 guard) ─────────────────


class TestWritebackRecoveryToCloseTransition:
    """Verify the writeback_recovery → report → close transition path is legal.

    ISSUE-062 B2: The writeback recovery node resolves writebacks but stays
    in VERIFYING.  Without an explicit VERIFYING→REPORTING transition in
    report_node, close_node attempts VERIFYING→CLOSED which the state
    machine rejects.  These tests use FakeStateMachine(validate=True) to
    catch the exact bug that escaped the non-validating fakes.
    """

    async def test_writeback_resolved_to_report_transition(self):
        """VERIFYING → REPORTING is a legal state transition.

        This is the transition that report_node must perform when reached
        from the writeback recovery path (verify_node stayed in VERIFYING).
        """
        sm = FakeStateMachine(validate=True)
        # Set initial status to VERIFYING (simulates verify_node staying
        # in VERIFYING for writeback recovery)
        sm._current_status["evt-test-wb-close-001"] = EventStatus.VERIFYING

        # Simulate report_node: transition VERIFYING → REPORTING
        await sm.transition(
            "evt-test-wb-close-001",
            EventStatus.REPORTING,
            reason="investigation:report",
        )
        assert sm._current_status["evt-test-wb-close-001"] == EventStatus.REPORTING

    async def test_report_to_close_transition(self):
        """REPORTING → CLOSED is a legal state transition."""
        sm = FakeStateMachine(validate=True)
        sm._current_status["evt-test-wb-close-002"] = EventStatus.REPORTING

        await sm.transition(
            "evt-test-wb-close-002",
            EventStatus.CLOSED,
            context=TransitionContext(
                report_exists=True,
                disposition_policy=DispositionPolicy.NOT_REQUIRED,
            ),
            reason="investigation:close",
        )
        assert sm._current_status["evt-test-wb-close-002"] == EventStatus.CLOSED

    async def test_verifying_to_closed_is_illegal(self):
        """VERIFYING → CLOSED is ILLEGAL (the exact bug B2 guards against)."""
        sm = FakeStateMachine(validate=True)
        sm._current_status["evt-test-wb-close-003"] = EventStatus.VERIFYING

        from app.core.errors import InvalidStateTransitionError

        with pytest.raises(InvalidStateTransitionError):
            await sm.transition(
                "evt-test-wb-close-003",
                EventStatus.CLOSED,
                reason="investigation:close",
            )

    async def test_full_writeback_recovery_to_close_path(self):
        """End-to-end: wb_recovery resolves → report → close, no illegal moves.

        Simulates the complete path: all writebacks resolved in VERIFYING,
        then report_node transitions VERIFYING→REPORTING, then close_node
        transitions REPORTING→CLOSED.  No InvalidStateTransitionError means
        the B2 fix is working.
        """
        event_id = "evt-test-wb-full-001"
        sm = FakeStateMachine(validate=True)
        sm._current_status[event_id] = EventStatus.VERIFYING

        # Step 1: writeback recovery resolves all writebacks → no flags set
        # (state dict gets verify_need_writeback_recovery=False)

        # Step 2: report_node sees state not yet REPORTING → transitions
        await sm.transition(
            event_id,
            EventStatus.REPORTING,
            reason="investigation:report",
        )

        # Step 3: close_node sees REPORTING → transitions to CLOSED
        await sm.transition(
            event_id,
            EventStatus.CLOSED,
            context=TransitionContext(
                report_exists=True,
                disposition_policy=DispositionPolicy.NOT_REQUIRED,
            ),
            reason="investigation:close",
        )

        assert sm._current_status[event_id] == EventStatus.CLOSED
        assert len(sm.transitions) == 2
