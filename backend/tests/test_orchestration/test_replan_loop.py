"""ISSUE-062 replan loop tests — ReplanHandler, replan_graph_node, and graph integration."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import InvalidStateTransitionError, ReplanCountExceededError
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    Severity,
    WritebackReadiness,
)
from app.models.workflow import MAX_REPLAN_COUNT, validate_transition
from app.orchestration.graph_state import InvestigationState
from app.orchestration.replan_handler import (
    ReplanDecision,
    ReplanHandler,
    replan_graph_node,
)
from app.orchestration.workflow_graph import (
    route_after_replan,
)

# ── Helpers ────────────────────────────────────────────────────────────────


def _base_state(**overrides: Any) -> InvestigationState:
    state: InvestigationState = {
        "event_id": "evt-test-replan-001",
        "event_status": EventStatus.VERIFYING.value,
        "disposition_policy": DispositionPolicy.NOT_REQUIRED.value,
        "severity": Severity.HIGH.value,
        "final_verdict": None,
        "confidence": 0.0,
        "need_investigation": True,
        "execution_substate": ExecutionSubstate.NONE.value,
        "event_status_update_readiness": WritebackReadiness.NOT_REQUIRED.value,
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
        "verify_need_writeback_recovery": False,
        "verify_need_manual_resolution": False,
    }
    state.update(overrides)  # type: ignore[typeddict-item]
    return state


def _noop_rollback() -> MagicMock:
    return MagicMock(compensate=AsyncMock(return_value=[]))


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

    async def get_event_status_update_readiness(self, event_id: str) -> WritebackReadiness:
        return WritebackReadiness.NOT_REQUIRED

    async def begin_disposition_only(self, event_id: str) -> None:
        pass

    async def read_disposition_only_intent(self, event_id: str) -> bool:
        return False

    async def assert_disposition_only_transition_allowed(
        self, event_id: str, *, current: EventStatus, target: EventStatus
    ) -> None:
        pass


class FakeStateMachine:
    """Fake StateMachineService for tests.

    When ``validate=True``, every ``transition()`` call runs through the
    real ``validate_transition`` gate so illegal state moves are caught.
    """

    def __init__(self, *, validate: bool = False) -> None:
        self.transitions: list[tuple[str, EventStatus, str]] = []
        self._replan_count = 0
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
            validate_transition(current, target)
        # Simulate replan_count enforcement from StateMachineService
        if target is EventStatus.REPLANNING:
            self._replan_count += 1
            if self._replan_count > MAX_REPLAN_COUNT:
                raise InvalidStateTransitionError(
                    f"replan_count exceeded {MAX_REPLAN_COUNT}",
                    current=EventStatus.VERIFYING,
                    target=target,
                    details={"replan_count": self._replan_count},
                )
        self.transitions.append((event_id, target, reason or ""))
        self._current_status[event_id] = target
        return SimpleNamespace(status=target.value)


# ── Tests: ReplanHandler.evaluate_replan ────────────────────────────────────


class TestReplanHandlerEvaluate:
    """Unit tests for ReplanHandler.evaluate_replan()."""

    def test_continue_when_below_limit(self):
        """replan_count < MAX_REPLAN_COUNT → CONTINUE."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        result = handler.evaluate_replan(0)
        assert result.decision == ReplanDecision.CONTINUE
        assert result.escalated is False
        assert result.replan_count == 1

    def test_continue_at_second_cycle(self):
        """replan_count=1 (second cycle) → CONTINUE."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        result = handler.evaluate_replan(1)
        assert result.decision == ReplanDecision.CONTINUE
        assert result.replan_count == 2

    def test_continue_at_last_allowed(self):
        """replan_count=2 (last allowed) → CONTINUE."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        result = handler.evaluate_replan(2)
        assert result.decision == ReplanDecision.CONTINUE
        assert result.replan_count == 3

    def test_escalate_when_limit_exceeded(self):
        """replan_count=3 would exceed MAX_REPLAN_COUNT → ESCALATE."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        result = handler.evaluate_replan(3)
        assert result.decision == ReplanDecision.ESCALATE
        assert result.escalated is True

    def test_escalate_beyond_limit(self):
        """replan_count=5 far exceeds limit → ESCALATE."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        result = handler.evaluate_replan(5)
        assert result.decision == ReplanDecision.ESCALATE
        assert result.escalated is True


# ── Tests: ReplanHandler.execute_replan ─────────────────────────────────────


class TestReplanHandlerExecute:
    """Integration tests for ReplanHandler.execute_replan()."""

    async def test_execute_replan_success(self):
        """Valid replan transitions to REPLANNING."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        result = await handler.execute_replan(
            "evt-001",
            current_replan_count=0,
            failed_actions=["act-001"],
        )
        assert result.decision == ReplanDecision.CONTINUE
        assert sm.transitions[-1][1] == EventStatus.REPLANNING
        assert sm.transitions[-1][0] == "evt-001"

    async def test_execute_replan_escalate(self):
        """Max replan exceeded → ESCALATE without transition."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        result = await handler.execute_replan(
            "evt-001",
            current_replan_count=3,
            failed_actions=["act-001"],
        )
        assert result.decision == ReplanDecision.ESCALATE
        # No REPLANNING transition should have been attempted
        replan_transitions = [t for t in sm.transitions if t[1] == EventStatus.REPLANNING]
        assert len(replan_transitions) == 0

    async def test_execute_replan_hits_state_machine_limit(self):
        """State machine enforces MAX_REPLAN_COUNT inside transaction."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())

        # First 3 replans succeed
        for i in range(3):
            result = await handler.execute_replan("evt-001", current_replan_count=i)
            if result.decision == ReplanDecision.ESCALATE:
                break

        # 4th should be caught by evaluate_replan before transition
        result = await handler.execute_replan(
            "evt-001",
            current_replan_count=3,
        )
        assert result.decision == ReplanDecision.ESCALATE


# ── Tests: ReplanHandler.escalate ───────────────────────────────────────────


class TestReplanHandlerEscalate:
    """Tests for ReplanHandler.escalate().

    ISSUE-062 Should-Fix #1: escalate() now raises ReplanCountExceededError
    after persisting the state-machine transition (dual-write pattern).
    """

    async def test_escalate_with_partial_success(self):
        """Partial success → CONTAINED (raises ReplanCountExceededError)."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        with pytest.raises(ReplanCountExceededError) as exc_info:
            await handler.escalate(
                "evt-001",
                has_partial_success=True,
                failed_actions=["act-001"],
            )
        assert exc_info.value.target_status == EventStatus.CONTAINED
        assert exc_info.value.error_code == "replan_count_exceeded"
        assert sm.transitions[-1][1] == EventStatus.CONTAINED

    async def test_escalate_with_all_failed(self):
        """All failed → FAILED (raises ReplanCountExceededError)."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        with pytest.raises(ReplanCountExceededError) as exc_info:
            await handler.escalate(
                "evt-001",
                has_partial_success=False,
                failed_actions=["act-001", "act-002"],
            )
        assert exc_info.value.target_status == EventStatus.FAILED
        assert exc_info.value.error_code == "replan_count_exceeded"
        assert sm.transitions[-1][1] == EventStatus.FAILED


# ── Tests: replan_graph_node ────────────────────────────────────────────────


class TestReplanGraphNode:
    """Tests for the replan_graph_node graph helper."""

    async def test_continue_path(self):
        """replan_graph_node returns CONTINUE with replan_count=1."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        state = _base_state(
            replan_count=0,
            verify_failed_actions=["act-001"],
        )
        result = await replan_graph_node(state, handler=handler, rollback=_noop_rollback())
        assert result["event_status"] == EventStatus.REPLANNING.value
        assert result["replan_count"] == 1
        assert result["escalated"] is False

    async def test_escalated_path(self):
        """replan_graph_node returns escalated=True when limit exceeded."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        state = _base_state(
            replan_count=3,
            verify_failed_actions=["act-001"],
            verify_has_partial_success=False,
        )
        result = await replan_graph_node(state, handler=handler, rollback=_noop_rollback())
        assert result["escalated"] is True

    async def test_compensate_receives_all_failed_actions(self):
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        rollback = MagicMock()
        rollback.compensate = AsyncMock(
            return_value=[SimpleNamespace(rolled_back=True, warning=None)]
        )
        state = _base_state(
            replan_count=0,
            verify_failed_actions=["act-fail", "act-other"],
        )
        result = await replan_graph_node(state, handler=handler, rollback=rollback)
        rollback.compensate.assert_awaited_once_with(
            "evt-test-replan-001",
            ["act-fail", "act-other"],
            operator="SagaCompensation",
            reason="verify need_action_replan — compensating prior SUCCESS actions",
        )
        assert result["event_status"] == EventStatus.REPLANNING.value
        assert result["rollback_results"]

    async def test_compensate_skipped_without_failed_actions(self):
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        rollback = MagicMock()
        rollback.compensate = AsyncMock()
        state = _base_state(replan_count=0, verify_failed_actions=[])
        result = await replan_graph_node(state, handler=handler, rollback=rollback)
        rollback.compensate.assert_not_called()
        assert "rollback_results" not in result

    async def test_compensate_failure_blocks_replan(self):
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        rollback = MagicMock()
        rollback.compensate = AsyncMock(side_effect=RuntimeError("adapter down"))
        state = _base_state(
            replan_count=0,
            verify_failed_actions=["act-fail"],
        )
        result = await replan_graph_node(state, handler=handler, rollback=rollback)
        assert result["halted"] is True
        assert result["replan_count"] == 0
        assert route_after_replan(result) == "manual"
        assert "saga_compensation_incomplete" in (result.get("degraded_flags") or [])

    async def test_missing_rollback_service_blocks_replan(self):
        handler = MagicMock(execute_replan=AsyncMock())
        state = _base_state(verify_failed_actions=["act-fail"])

        result = await replan_graph_node(state, handler=handler, rollback=None)

        handler.execute_replan.assert_not_awaited()
        assert result["halted"] is True
        assert result["verify_need_manual_resolution"] is True
        assert "saga_compensation_incomplete" in result["degraded_flags"]


# ── Tests: route_after_replan ───────────────────────────────────────────────


class TestRouteAfterReplan:
    """Tests for the route_after_replan routing function."""

    def test_replan_routes_to_planner(self):
        """Not escalated → ROUTE_INVESTIGATE (back to planner)."""
        state = _base_state(replan_count=1, escalated=False)
        route = route_after_replan(state)
        assert route == "investigate"

    def test_resolved_saga_tombstone_ignores_union_merged_stale_flag(self):
        state = _base_state(
            degraded_flags=["saga_compensation_incomplete=True"],
            saga_compensation_resolved=True,
        )
        assert route_after_replan(state) == "investigate"

    def test_escalated_routes_to_report(self):
        """Escalated → ROUTE_REPORT."""
        state = _base_state(replan_count=3, escalated=True)
        route = route_after_replan(state)
        assert route == "report"


# ── Tests: ReplanHandler.needs_replan ───────────────────────────────────────


class TestNeedsReplan:
    """Tests for static needs_replan helper."""

    def test_needs_replan_true(self):
        state = {"verify_need_action_replan": True}
        assert ReplanHandler.needs_replan(state) is True

    def test_needs_replan_false(self):
        state = {"verify_need_action_replan": False}
        assert ReplanHandler.needs_replan(state) is False

    def test_needs_replan_missing_key(self):
        state: dict[str, Any] = {}
        assert ReplanHandler.needs_replan(state) is False


# ── Tests: degradation (no LLM path) ───────────────────────────────────────


class TestReplanDegradation:
    """Tests that ReplanHandler works without LLM — pure rule fallback."""

    def test_evaluate_replan_no_llm(self):
        """ReplanHandler.evaluate_replan is pure rule-based (no LLM)."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        # Should work identically with or without LLM
        result = handler.evaluate_replan(2)
        assert result.decision == ReplanDecision.CONTINUE
        result2 = handler.evaluate_replan(5)
        assert result2.decision == ReplanDecision.ESCALATE


# ── Tests: boundary inputs ─────────────────────────────────────────────────


class TestReplanBoundaryInputs:
    """Boundary input tests for ReplanHandler."""

    def test_negative_replan_count(self):
        """Negative replan_count raises ValueError — it is a caller bug."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        with pytest.raises(ValueError, match="replan_count must be >= 0"):
            handler.evaluate_replan(-1)

    def test_none_failed_actions(self):
        """None failed_actions is handled gracefully."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        result = handler.evaluate_replan(1, failed_actions=None)
        assert result.decision == ReplanDecision.CONTINUE

    def test_empty_failed_actions(self):
        """Empty failed_actions list is handled gracefully."""
        handler = ReplanHandler(
            state_machine=FakeStateMachine(),
            runtime=FakeRuntime(),
        )
        result = handler.evaluate_replan(1, failed_actions=[])
        assert result.decision == ReplanDecision.CONTINUE


# ── Tests: state machine raises ────────────────────────────────────────────


class TestReplanStateMachineErrors:
    """Tests for state machine errors during replan."""

    async def test_transition_raises_propagates(self):
        """State machine error propagates through execute_replan."""
        sm = MagicMock()
        sm.transition = AsyncMock(
            side_effect=InvalidStateTransitionError(
                "test error",
                current="VERIFYING",
                target="REPLANNING",
            )
        )
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        with pytest.raises(InvalidStateTransitionError):
            await handler.execute_replan("evt-001", current_replan_count=0)


# ── Tests: convergence guard blocks replan (Should-Fix #1) ────────────────────


class TestConvergenceGuardBlocksReplan:
    """Verify convergence_guard.should_stop() prevents replan from proceeding."""

    async def test_should_stop_blocks_replan_and_escalates(self):
        """When convergence guard returns stop=True, replan is aborted and
        the event escalates directly without entering REPLANNING."""
        from app.orchestration.convergence_guard import StopDecision, StopReason

        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())

        # Simulate a convergence guard that records steps and then orders stop
        guard = MagicMock()
        guard.record_step = AsyncMock()
        guard.should_stop = AsyncMock(
            return_value=StopDecision(
                stop=True,
                reason=StopReason.GLOBAL_MAX_STEPS,
                detail="total_steps=100 >= GLOBAL_MAX_STEPS=100",
            )
        )

        state = _base_state(
            replan_count=0,
            verify_failed_actions=["act-001"],
            verify_has_partial_success=False,
        )
        result = await replan_graph_node(
            state,
            handler=handler,
            convergence_guard=guard,
            rollback=_noop_rollback(),
        )

        # Must have called record_step AND should_stop
        guard.record_step.assert_awaited_once()
        guard.should_stop.assert_awaited_once()

        # Must be escalated, not continuing to replan
        assert result["escalated"] is True
        assert result["halted"] is True

        # Must NOT have attempted a REPLANNING transition
        replan_transitions = [t for t in sm.transitions if t[1] == EventStatus.REPLANNING]
        assert len(replan_transitions) == 0, (
            "Convergence guard stop must prevent REPLANNING transition"
        )

    async def test_should_stop_false_allows_replan(self):
        """When convergence guard returns stop=False, replan proceeds normally."""
        from app.orchestration.convergence_guard import StopDecision, StopReason

        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())

        guard = MagicMock()
        guard.record_step = AsyncMock()
        guard.should_stop = AsyncMock(return_value=StopDecision(stop=False, reason=StopReason.NONE))

        state = _base_state(
            replan_count=0,
            verify_failed_actions=["act-001"],
        )
        result = await replan_graph_node(
            state,
            handler=handler,
            convergence_guard=guard,
            rollback=_noop_rollback(),
        )

        guard.record_step.assert_awaited_once()
        guard.should_stop.assert_awaited_once()

        # Should continue to replan
        assert result["escalated"] is False
        assert result["replan_count"] == 1


# ── Tests: missing event_id raises (Should-Fix #4) ────────────────────────────


class TestReplanGraphNodeValidation:
    """Verify replan_graph_node validates required state fields."""

    async def test_missing_event_id_raises(self):
        """Missing event_id in InvestigationState raises ValueError."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        # State without event_id key
        state: dict[str, Any] = {
            "replan_count": 0,
            "verify_failed_actions": ["act-001"],
        }
        with pytest.raises(ValueError, match="missing required field: event_id"):
            await replan_graph_node(state, handler=handler)

    async def test_none_event_id_raises(self):
        """None event_id in InvestigationState raises ValueError."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        state = _base_state(event_id=None, replan_count=0)
        with pytest.raises(ValueError, match="missing required field: event_id"):
            await replan_graph_node(state, handler=handler)

    async def test_empty_string_event_id_raises(self):
        """Empty string event_id raises ValueError."""
        sm = FakeStateMachine()
        handler = ReplanHandler(state_machine=sm, runtime=FakeRuntime())
        state = _base_state(event_id="", replan_count=0)
        with pytest.raises(ValueError, match="missing required field: event_id"):
            await replan_graph_node(state, handler=handler)


@pytest.mark.parametrize("warning", ["awaiting_approval", "not_rollbackable", "rollback_error"])
@pytest.mark.asyncio
async def test_incomplete_compensation_never_calls_planner_transition(warning):
    handler = MagicMock(execute_replan=AsyncMock())
    rollback = MagicMock(
        compensate=AsyncMock(
            return_value=[
                {
                    "action_id": "act-old",
                    "rollback_action_id": "act-rollback",
                    "rolled_back": False,
                    "warning": warning,
                }
            ]
        )
    )
    result = await replan_graph_node(
        _base_state(replan_count=0, verify_failed_actions=["act-fail"]),
        handler=handler,
        rollback=rollback,
    )
    handler.execute_replan.assert_not_awaited()
    assert result["halted"] is True
    assert result["replan_count"] == 0
    assert route_after_replan(result) == "manual"
    assert result["rollback_results"][0]["warning"] == warning


@pytest.mark.parametrize(
    "results",
    [
        None,
        [
            {
                "action_id": "act-old",
                "rolled_back": True,
                "compensation_writeback_required": True,
                "compensation_writeback_status": "pending",
            }
        ],
    ],
)
@pytest.mark.asyncio
async def test_missing_result_or_pending_compensation_writeback_blocks_replan(results):
    handler = MagicMock(execute_replan=AsyncMock())
    rollback = MagicMock(compensate=AsyncMock(return_value=results))
    result = await replan_graph_node(
        _base_state(verify_failed_actions=["act-fail"]),
        handler=handler,
        rollback=rollback,
    )
    handler.execute_replan.assert_not_awaited()
    assert route_after_replan(result) == "manual"
