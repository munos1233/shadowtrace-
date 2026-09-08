"""ReplanHandler — replan trigger, constraint enforcement, and escalation (ISSUE-062).

ReplanHandler ONLY handles ``execution_failed`` / ``effect_not_verified`` action
problems.  Writeback waiting/failed/unknown/conflict is handled separately by
``WritebackRecoveryHandler`` and must NEVER enter REPLANNING.

When ``replan_count`` reaches ``MAX_REPLAN_COUNT`` and the plan still fails, the
handler sets ``security_event.escalated=true``, routes the event through
CONTAINED (partial success) or FAILED (all failed), and proceeds to report
generation with a mandatory human-escalation note.

Design
------
* ``evaluate_replan(…)`` — returns the replan decision (continue / escalate).
* ``execute_replan(…)`` — transitions state to REPLANNING and increments the
  counter.  Actual plan revision is done by ``planner_node()`` which already
  calls ``PlannerAgent.revise()`` when ``replan_count > 0``.
* ``escalate(…)`` — marks ``escalated=true`` and transitions through CONTAINED
  or FAILED into REPORTING.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, NoReturn, Protocol, cast

from app.core.errors import (
    DependencyUnavailableError,
    ReplanCountExceededError,
)
from app.models.enums import EventStatus
from app.models.workflow import MAX_REPLAN_COUNT, TransitionContext
from app.orchestration.graph_state import InvestigationState
from app.orchestration.ports import StateMachinePort

SAGA_COMPENSATION_INCOMPLETE_FLAG = "saga_compensation_incomplete"
_SAGA_OPERATOR = "SagaCompensation"
_SAGA_REASON = "verify need_action_replan — compensating prior SUCCESS actions"

logger = logging.getLogger(__name__)

_REPLAN_OPERATOR = "ReplanHandler"


# --------------------------------------------------------------------------- #
# Ports
# --------------------------------------------------------------------------- #


class _WorkflowRuntimePort(Protocol):
    async def set_execution_substate(
        self,
        event_id: str,
        substate: Any,
        *,
        event_status: EventStatus,
    ) -> None: ...


class _ConvergenceGuardPort(Protocol):
    """Protocol for the optional convergence guard injected into replan_graph_node.

    Matches the ``record_step`` / ``should_stop`` interface used by
    ``ConvergenceGuard`` (convergence_guard.py) and its test doubles.
    """

    async def record_step(
        self,
        event_id: str,
        step_type: str,
        *,
        signature: str | None = None,
        **kwargs: Any,
    ) -> None: ...

    async def should_stop(self, event_id: str) -> Any: ...


# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #


class ReplanDecision(StrEnum):
    CONTINUE = "continue"
    ESCALATE = "escalate"


@dataclass
class ReplanResult:
    """Outcome of ``ReplanHandler.evaluate_replan()``."""

    decision: ReplanDecision
    replan_count: int
    max_replan_count: int = MAX_REPLAN_COUNT
    escalated: bool = False
    reason: str = ""


@dataclass
class EscalationResult:
    """Outcome of ``ReplanHandler.escalate()``."""

    escalated: bool
    target_status: EventStatus
    reason: str


# --------------------------------------------------------------------------- #
# Handler
# --------------------------------------------------------------------------- #


class ReplanHandler:
    """Enforce ``MAX_REPLAN_COUNT`` and escalate when the limit is hit.

    Only **execution_failed** and **effect_not_verified** action problems
    should enter this handler.  Writeback issues go to
    ``WritebackRecoveryHandler`` — they do NOT consume replan_count and do
    NOT trigger REPLANNING.
    """

    def __init__(
        self,
        *,
        state_machine: StateMachinePort,
        runtime: _WorkflowRuntimePort,
    ) -> None:
        self._state_machine = state_machine
        self._runtime = runtime

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def evaluate_replan(
        self,
        current_replan_count: int,
        *,
        failed_actions: list[str] | None = None,
    ) -> ReplanResult:
        """Decide whether another replan cycle is allowed.

        Parameters
        ----------
        current_replan_count:
            The replan_count from the current InvestigationState or event row.
            Values from the row are authoritative; the state copy is used
            only when the row is not yet committed.
        failed_actions:
            Action IDs that failed verification; used only for logging.

        Returns
        -------
        ReplanResult
            ``decision=CONTINUE`` when another cycle is allowed;
            ``decision=ESCALATE`` when the limit has been reached.
        """
        if current_replan_count < 0:
            raise ValueError(f"replan_count must be >= 0, got {current_replan_count}")
        next_count = current_replan_count + 1
        if next_count > MAX_REPLAN_COUNT:
            logger.warning(
                "replan_count=%d exceeds MAX_REPLAN_COUNT=%d for failed_actions=%s; escalating",
                next_count,
                MAX_REPLAN_COUNT,
                failed_actions or [],
            )
            return ReplanResult(
                decision=ReplanDecision.ESCALATE,
                replan_count=current_replan_count,
                max_replan_count=MAX_REPLAN_COUNT,
                escalated=True,
                reason=f"replan_count_exceeded:{next_count}>{MAX_REPLAN_COUNT}",
            )

        logger.info(
            "replan allowed: count=%d/%d for failed_actions=%s",
            next_count,
            MAX_REPLAN_COUNT,
            failed_actions or [],
        )
        return ReplanResult(
            decision=ReplanDecision.CONTINUE,
            replan_count=next_count,
            max_replan_count=MAX_REPLAN_COUNT,
            escalated=False,
            reason=f"replan_cycle_{next_count}",
        )

    async def execute_replan(
        self,
        event_id: str,
        *,
        current_replan_count: int,
        failed_actions: list[str] | None = None,
    ) -> ReplanResult:
        """Validate, transition to REPLANNING, increment counter, and return result.

        The transition to REPLANNING is performed by the state machine so the
        ``replan_count`` bump is atomic with the status write.  After this
        returns with ``decision=CONTINUE``, the graph edge from
        ``NODE_REPLAN`` to ``NODE_PLANNER`` takes over — ``planner_node()``
        already calls ``PlannerAgent.revise()`` when ``replan_count > 0``.

        Raises
        ------
        InvalidStateTransitionError
            If the state machine rejects the REPLANNING transition (e.g.
            replan_count would exceed MAX_REPLAN_COUNT inside the row-locked
            pre-transition check).
        """
        result = self.evaluate_replan(current_replan_count, failed_actions=failed_actions)

        if result.decision is ReplanDecision.ESCALATE:
            return result

        reason = f"replan:cycle_{result.replan_count}:{','.join(failed_actions or ['unknown'])}"
        await self._state_machine.transition(
            event_id,
            EventStatus.REPLANNING,
            operator=_REPLAN_OPERATOR,
            reason=reason,
        )

        return result

    async def escalate(
        self,
        event_id: str,
        *,
        has_partial_success: bool = False,
        failed_actions: list[str] | None = None,
    ) -> NoReturn:
        """Escalate after replan_count exhausted.

        Sets ``escalated=true`` on the event row and transitions through
        CONTAINED (when any action partially succeeded) or FAILED (all failed)
        into REPORTING.  The report generator reads ``escalated`` to include
        a mandatory human-escalation section.

        Callers must subsequently route to ``report_node``.

        Raises
        ------
        ReplanCountExceededError
            After the state-machine transition is persisted.  Callers in
            graph nodes should catch this and convert to state patches
            (dual-write: state + exception for diagnostics).
        """
        target = EventStatus.CONTAINED if has_partial_success else EventStatus.FAILED
        reason = (
            f"replan:escalated:max_replan_count={MAX_REPLAN_COUNT}:"
            f"{','.join(failed_actions or ['unknown'])}"
        )
        await self._state_machine.transition(
            event_id,
            target,
            context=TransitionContext(escalated=True),
            operator=_REPLAN_OPERATOR,
            reason=reason,
        )

        logger.warning(
            "replan escalation: event=%s target=%s has_partial=%s",
            event_id,
            target.value,
            has_partial_success,
        )
        raise ReplanCountExceededError(
            reason,
            target_status=target,
            details={
                "event_id": event_id,
                "has_partial_success": has_partial_success,
                "failed_actions": failed_actions or [],
                "max_replan_count": MAX_REPLAN_COUNT,
            },
        )

    @staticmethod
    def needs_replan(state: dict[str, Any]) -> bool:
        """Return True when the verification result signals need_action_replan.

        This is a convenience function for external callers that need to
        check whether a replan is required without importing the full graph
        routing logic.  Internal graph routing is handled by
        ``route_after_verify``, which is the single source of truth for the
        verify → replan / writeback / report decision.
        """
        return bool(state.get("verify_need_action_replan"))


# --------------------------------------------------------------------------- #
# Graph-node helper
# --------------------------------------------------------------------------- #


def _rollback_result_dump(item: Any) -> dict[str, Any]:
    dump = getattr(item, "model_dump", None)
    if callable(dump):
        payload = dump(mode="json")
        if isinstance(payload, dict):
            return payload
    if isinstance(item, dict):
        return item
    return {"repr": repr(item)}


def _compensation_incomplete(results: list[Any]) -> bool:
    if not results:
        return False
    for item in results:
        rolled_back = bool(getattr(item, "rolled_back", None))
        warning = getattr(item, "warning", None)
        if isinstance(item, dict):
            rolled_back = bool(item.get("rolled_back"))
            warning = item.get("warning")
        if not rolled_back:
            return True
        if warning:
            return True
    return False


async def _persist_rollback_results(
    event_id: str,
    results: list[Any],
    working_memory: Any | None,
) -> list[dict[str, Any]]:
    dumps = [_rollback_result_dump(item) for item in results]
    if working_memory is None or not dumps:
        return dumps
    writer = working_memory
    for_writer = getattr(working_memory, "for_writer", None)
    if callable(for_writer):
        try:
            writer = for_writer("RollbackService")
        except Exception:
            logger.warning(
                "replan_graph_node: failed to bind RollbackService writer event=%s",
                event_id,
                exc_info=True,
            )
            return dumps
    try:
        existing = await writer.read(event_id, "rollback_results")
    except Exception:
        existing = None
    merged = list(existing) if isinstance(existing, list) else []
    merged.extend(dumps)
    try:
        await writer.write(event_id, "rollback_results", merged)
    except Exception:
        logger.warning(
            "replan_graph_node: failed to persist rollback_results event=%s",
            event_id,
            exc_info=True,
        )
    return dumps


async def _compensate_before_replan(
    event_id: str,
    failed_actions: list[str],
    *,
    rollback: Any | None,
    working_memory: Any | None,
    existing_degraded: list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Best-effort saga compensate; never blocks the subsequent replan."""
    if rollback is None or not failed_actions:
        return [], existing_degraded
    failed_action_id = failed_actions[0].strip()
    if not failed_action_id:
        return [], existing_degraded
    compensate = getattr(rollback, "compensate", None)
    if not callable(compensate):
        return [], existing_degraded
    try:
        results = await compensate(
            event_id,
            failed_action_id,
            operator=_SAGA_OPERATOR,
            reason=_SAGA_REASON,
        )
    except Exception:
        logger.exception(
            "saga compensate failed event=%s failed_action=%s — replan continues",
            event_id,
            failed_action_id,
        )
        if SAGA_COMPENSATION_INCOMPLETE_FLAG not in existing_degraded:
            existing_degraded.append(SAGA_COMPENSATION_INCOMPLETE_FLAG)
        return [], existing_degraded
    serialized = await _persist_rollback_results(event_id, list(results or []), working_memory)
    if _compensation_incomplete(list(results or [])):
        if SAGA_COMPENSATION_INCOMPLETE_FLAG not in existing_degraded:
            existing_degraded.append(SAGA_COMPENSATION_INCOMPLETE_FLAG)
    return serialized, existing_degraded


async def replan_graph_node(
    state: InvestigationState,
    *,
    handler: ReplanHandler,
    convergence_guard: _ConvergenceGuardPort | None = None,
    rollback: Any | None = None,
    working_memory: Any | None = None,
) -> InvestigationState:
    """Graph node entry point for ``NODE_REPLAN``.

    This replaces the ISSUE-048 placeholder ``replan_node``.  It evaluates
    the replan count, transitions to REPLANNING (or escalates), and returns
    the state patches the graph needs to route correctly.

    Parameters
    ----------
    state:
        Current InvestigationState dict.
    handler:
        Configured ReplanHandler instance.
    convergence_guard:
        Optional ConvergenceGuard for recording replan steps (ISSUE-062).

    Returns
    -------
    dict
        State patches including ``replan_count``, ``escalated``, and
        ``event_status`` so the conditional edge after this node can route
        to PLANNER (continue) or REPORT (escalated).
    """
    raw_event_id = state.get("event_id")
    if not raw_event_id:
        raise ValueError("InvestigationState missing required field: event_id")
    event_id = str(raw_event_id)
    current_count = int(state.get("replan_count", 0))

    # Type-safe extraction of failed_actions (ISSUE-062: guard against
    # non-iterable values in the state dict).
    raw_failed = state.get("verify_failed_actions")
    if raw_failed is None:
        failed_actions: list[str] = []
    elif isinstance(raw_failed, (list, tuple)):
        failed_actions = [str(a) for a in raw_failed]
    else:
        logger.warning(
            "replan_graph_node: unexpected type for verify_failed_actions: %s",
            type(raw_failed).__name__,
        )
        failed_actions = []

    # Carry forward existing degraded_flags so callers can append.
    existing_degraded = list(state.get("degraded_flags") or [])
    rollback_dumps, existing_degraded = await _compensate_before_replan(
        event_id,
        failed_actions,
        rollback=rollback,
        working_memory=working_memory,
        existing_degraded=existing_degraded,
    )

    def _build_escalate_patches(target_status: EventStatus, *, halted: bool) -> dict[str, Any]:
        """Build state patches for an escalated replan result."""
        return {
            "event_status": target_status.value,
            "replan_count": current_count,
            "escalated": True,
            "halted": halted,
        }

    # Record replan step in convergence guard (ISSUE-062) and check
    # whether any stop condition (global_max_steps, oscillation, etc.)
    # has been hit.  When the guard orders a stop the replan is aborted
    # and the event is escalated immediately — the convergence_state is
    # already persisted by the guard.
    if convergence_guard is not None:
        try:
            await convergence_guard.record_step(event_id, "replan")
            stop = await convergence_guard.should_stop(event_id)
            if stop:
                logger.warning(
                    "ConvergenceGuard ordered stop for event=%s reason=%s detail=%s",
                    event_id,
                    stop.reason.value,
                    stop.detail,
                )
                has_partial = bool(state.get("verify_has_partial_success"))
                try:
                    await handler.escalate(
                        event_id,
                        has_partial_success=has_partial,
                        failed_actions=failed_actions,
                    )
                except ReplanCountExceededError as exc:
                    escalate_patches = _build_escalate_patches(exc.target_status, halted=True)
                    if existing_degraded:
                        escalate_patches["degraded_flags"] = existing_degraded
                    if rollback_dumps:
                        escalate_patches["rollback_results"] = rollback_dumps
                    return cast(InvestigationState, escalate_patches)
        except DependencyUnavailableError:
            logger.warning(
                "ConvergenceGuard unavailable for event=%s — replan continues degraded",
                event_id,
            )
            # Attach degraded flag so operators can observe the guard failure
            # even though replan continues.
            degraded_entry = "convergence_guard_degraded"
            if degraded_entry not in existing_degraded:
                existing_degraded.append(degraded_entry)
        except Exception:
            logger.exception(
                "ConvergenceGuard unexpected error for event=%s",
                event_id,
            )
            # Attach degraded flag so operators can observe the guard failure
            # even though replan continues (ISSUE-062 Nit #2).  The guard
            # failure does not block replan — the convergence check is a
            # safeguard, not a hard gate.
            degraded_entry = "convergence_guard_degraded"
            if degraded_entry not in existing_degraded:
                existing_degraded.append(degraded_entry)

    result = await handler.execute_replan(
        event_id,
        current_replan_count=current_count,
        failed_actions=failed_actions,
    )

    if result.decision is ReplanDecision.ESCALATE:
        has_partial = bool(state.get("verify_has_partial_success"))
        try:
            await handler.escalate(
                event_id,
                has_partial_success=has_partial,
                failed_actions=failed_actions,
            )
        except ReplanCountExceededError as exc:
            # NOTE: replan_count is NOT incremented on escalate — the over-limit
            # detection happens in evaluate_replan() which checks "would the next
            # attempt exceed MAX_REPLAN_COUNT?" before the increment is committed.
            # Returning current_count (not current_count + 1) is correct: no
            # successful replan consumed this count.  The CONTINUE path below
            # returns result.replan_count which IS incremented.
            escalate_patches = _build_escalate_patches(exc.target_status, halted=False)
            if existing_degraded:
                escalate_patches["degraded_flags"] = existing_degraded
            if rollback_dumps:
                escalate_patches["rollback_results"] = rollback_dumps
            return cast(InvestigationState, escalate_patches)

    # Continue: the graph edge NODE_REPLAN → NODE_PLANNER takes over.
    patches: dict[str, Any] = {
        "event_status": EventStatus.REPLANNING.value,
        "replan_count": result.replan_count,
        "escalated": False,
        "halted": False,
    }
    if existing_degraded:
        patches["degraded_flags"] = existing_degraded
    if rollback_dumps:
        patches["rollback_results"] = rollback_dumps
    return cast(InvestigationState, patches)


__all__ = [
    "EscalationResult",
    "ReplanDecision",
    "ReplanHandler",
    "ReplanResult",
    "SAGA_COMPENSATION_INCOMPLETE_FLAG",
    "replan_graph_node",
]
