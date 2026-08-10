"""Session-backed side-effect convergence for the CLOSED gate (ISSUE-302)."""

from __future__ import annotations

from typing import NoReturn

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import InvalidStateTransitionError
from app.db import models as orm
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    DispositionPolicy,
    EventStatus,
    ExecutionJobStatus,
    OutboxDeliveryStatus,
    WritebackStatus,
)
from app.models.side_effect_convergence import (
    OutstandingSideEffectView,
    SideEffectConvergenceReason,
    SideEffectConvergenceSummary,
    SideEffectConvergenceViolation,
    SideEffectScope,
)
from app.services.writeback_close_gate import load_active_outboxes

_TERMINAL_ACTION_STATUSES = frozenset(
    {
        ActionStatus.SUCCESS,
        ActionStatus.PARTIAL_SUCCESS,
        ActionStatus.FAILED,
        ActionStatus.REJECTED,
        ActionStatus.SUPERSEDED,
        ActionStatus.UNKNOWN,
    }
)
_ACTIVE_JOB_STATUSES = frozenset(
    {
        ExecutionJobStatus.QUEUED,
        ExecutionJobStatus.RUNNING,
    }
)
_UNDELIVERED_OUTBOX_STATUSES = frozenset(
    {
        OutboxDeliveryStatus.READY,
        OutboxDeliveryStatus.LEASED,
        OutboxDeliveryStatus.WAITING_RETRY,
    }
)


def raise_side_effect_convergence_error(violation: SideEffectConvergenceViolation) -> NoReturn:
    """Map a convergence violation to StateMachine InvalidStateTransitionError."""
    raise InvalidStateTransitionError(
        "required CLOSED gate: gate-applicable side effects have not converged",
        target=EventStatus.CLOSED,
        details={
            "action_id": violation.action_id,
            "reason": violation.reason.value,
            "scope": violation.scope.value,
        },
        error_code="closed_side_effects_pending",
    )


def _parse_action_status(raw: str) -> ActionStatus:
    try:
        return ActionStatus(raw)
    except ValueError:
        return ActionStatus.PENDING


def _parse_exec_phase(raw: str | None) -> ActionExecutionPhase:
    if not raw:
        return ActionExecutionPhase.IMMEDIATE
    try:
        return ActionExecutionPhase(raw)
    except ValueError:
        return ActionExecutionPhase.IMMEDIATE


def _action_has_active_job(
    action_id: str,
    jobs_by_action: dict[str, orm.ActionExecutionJob],
) -> ExecutionJobStatus | None:
    job = jobs_by_action.get(action_id)
    if job is None:
        return None
    try:
        status = ExecutionJobStatus(job.status)
    except ValueError:
        return None
    if status in _ACTIVE_JOB_STATUSES:
        return status
    return None


def _outbox_blocks_convergence(
    outbox: orm.DispositionOutbox,
) -> tuple[bool, SideEffectConvergenceReason | None]:
    wb_raw = outbox.latest_writeback_status
    if wb_raw and wb_raw != WritebackStatus.CONFIRMED.value:
        try:
            WritebackStatus(wb_raw)
        except ValueError:
            pass
        else:
            return True, SideEffectConvergenceReason.OUTBOX_NOT_CONFIRMED
    try:
        delivery = OutboxDeliveryStatus(outbox.delivery_status)
    except ValueError:
        delivery = None
    if delivery in _UNDELIVERED_OUTBOX_STATUSES:
        return True, SideEffectConvergenceReason.OUTBOX_UNDELIVERED
    return False, None


def _action_blocks_convergence(
    action_row: orm.Action,
    *,
    jobs_by_action: dict[str, orm.ActionExecutionJob],
    active_outboxes: list[orm.DispositionOutbox],
) -> SideEffectConvergenceReason | None:
    status = _parse_action_status(action_row.status)
    if status in _TERMINAL_ACTION_STATUSES:
        return None
    if status is ActionStatus.EXECUTING:
        return SideEffectConvergenceReason.EXECUTING_ACTION
    if _action_has_active_job(action_row.action_id, jobs_by_action) is not None:
        return SideEffectConvergenceReason.IN_FLIGHT_JOB
    for outbox in active_outboxes:
        blocks, reason = _outbox_blocks_convergence(outbox)
        if blocks and reason is not None:
            return reason
    return None


def _classify_scope(
    *,
    action_row: orm.Action,
    current_revision: int | None,
    disposition_policy: DispositionPolicy,
) -> SideEffectScope:
    if current_revision is None:
        return SideEffectScope.BACKGROUND_DETACHED
    if action_row.superseded_by_revision is not None:
        return SideEffectScope.BACKGROUND_DETACHED
    if int(action_row.plan_revision) != int(current_revision):
        return SideEffectScope.BACKGROUND_DETACHED
    if disposition_policy is DispositionPolicy.NOT_REQUIRED:
        return SideEffectScope.BACKGROUND_DETACHED
    return SideEffectScope.GATE_APPLICABLE


async def build_side_effect_convergence_summary(
    session: AsyncSession,
    event_id: str,
    *,
    current_revision: int | None,
    disposition_policy: DispositionPolicy,
) -> SideEffectConvergenceSummary:
    """Collect outstanding response/rollback side effects for CLOSED semantics."""
    if current_revision is None:
        return SideEffectConvergenceSummary(event_id=event_id)

    action_rows: list[orm.Action] = list(
        (
            await session.scalars(
                select(orm.Action).where(
                    orm.Action.event_id == event_id,
                    orm.Action.action_category.in_(
                        (ActionCategory.RESPONSE.value, ActionCategory.ROLLBACK.value)
                    ),
                )
            )
        ).all()
    )
    jobs: list[orm.ActionExecutionJob] = list(
        (
            await session.scalars(
                select(orm.ActionExecutionJob).where(
                    orm.ActionExecutionJob.event_id == event_id
                )
            )
        ).all()
    )
    jobs_by_action = {job.action_id: job for job in jobs}

    outstanding: list[OutstandingSideEffectView] = []
    gate_count = 0
    background_count = 0

    for action_row in action_rows:
        if action_row.status == ActionStatus.REJECTED.value:
            continue
        active_outboxes = await load_active_outboxes(session, action_row.action_id)
        if _action_blocks_convergence(
            action_row,
            jobs_by_action=jobs_by_action,
            active_outboxes=active_outboxes,
        ) is None:
            continue

        scope = _classify_scope(
            action_row=action_row,
            current_revision=current_revision,
            disposition_policy=disposition_policy,
        )
        job = jobs_by_action.get(action_row.action_id)
        job_status: ExecutionJobStatus | None = None
        if job is not None:
            try:
                job_status = ExecutionJobStatus(job.status)
            except ValueError:
                job_status = None

        outbox_delivery: OutboxDeliveryStatus | None = None
        outbox_wb: WritebackStatus | None = None
        if active_outboxes:
            head = active_outboxes[0]
            try:
                outbox_delivery = OutboxDeliveryStatus(head.delivery_status)
            except ValueError:
                outbox_delivery = None
            if head.latest_writeback_status:
                try:
                    outbox_wb = WritebackStatus(head.latest_writeback_status)
                except ValueError:
                    outbox_wb = None

        view = OutstandingSideEffectView(
            action_id=action_row.action_id,
            scope=scope,
            action_status=_parse_action_status(action_row.status),
            execution_phase=_parse_exec_phase(action_row.execution_phase),
            writeback_applicable=bool(action_row.writeback_applicable),
            job_status=job_status,
            outbox_delivery_status=outbox_delivery,
            outbox_writeback_status=outbox_wb,
            plan_revision=int(action_row.plan_revision),
            superseded=action_row.superseded_by_revision is not None,
        )
        outstanding.append(view)
        if scope is SideEffectScope.GATE_APPLICABLE:
            gate_count += 1
        else:
            background_count += 1

    return SideEffectConvergenceSummary(
        event_id=event_id,
        current_plan_revision=current_revision,
        gate_applicable_outstanding_count=gate_count,
        background_outstanding_count=background_count,
        outstanding_actions=outstanding,
        background_side_effects_pending=background_count > 0,
    )


def check_gate_applicable_side_effect_convergence(
    summary: SideEffectConvergenceSummary,
) -> SideEffectConvergenceViolation | None:
    """Return the first gate-applicable outstanding side effect, if any."""
    for view in summary.outstanding_actions:
        if view.scope is not SideEffectScope.GATE_APPLICABLE:
            continue
        if view.action_status is ActionStatus.EXECUTING:
            return SideEffectConvergenceViolation(
                reason=SideEffectConvergenceReason.EXECUTING_ACTION,
                action_id=view.action_id,
            )
        if view.job_status in _ACTIVE_JOB_STATUSES:
            return SideEffectConvergenceViolation(
                reason=SideEffectConvergenceReason.IN_FLIGHT_JOB,
                action_id=view.action_id,
            )
        if view.outbox_writeback_status is not None and (
            view.outbox_writeback_status is not WritebackStatus.CONFIRMED
        ):
            return SideEffectConvergenceViolation(
                reason=SideEffectConvergenceReason.OUTBOX_NOT_CONFIRMED,
                action_id=view.action_id,
            )
        if view.outbox_delivery_status in _UNDELIVERED_OUTBOX_STATUSES:
            return SideEffectConvergenceViolation(
                reason=SideEffectConvergenceReason.OUTBOX_UNDELIVERED,
                action_id=view.action_id,
            )
    return None


async def reconcile_stale_executions_before_close(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    limit: int = 20,
) -> int:
    """Reclaim lease-expired jobs before evaluating the CLOSED gate (ISSUE-302)."""
    from app.services.action_execution_service import reconcile_stale_executions_for_event

    return await reconcile_stale_executions_for_event(
        session_factory,
        event_id=event_id,
        limit=limit,
    )


__all__ = [
    "build_side_effect_convergence_summary",
    "check_gate_applicable_side_effect_convergence",
    "raise_side_effect_convergence_error",
    "reconcile_stale_executions_before_close",
]
