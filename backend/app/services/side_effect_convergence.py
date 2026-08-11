"""Session-backed side-effect convergence for the CLOSED gate (ISSUE-302 / ISSUE-312)."""

from __future__ import annotations

from typing import Any, NoReturn

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import InvalidStateTransitionError
from app.db import models as orm
from app.models.agent_io import VerificationResult
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    ExecutionJobStatus,
    ExecutionOwner,
    OutboxDeliveryStatus,
    WritebackStatus,
)
from app.models.side_effect_convergence import (
    OutstandingSideEffectView,
    SideEffectConvergencePolicy,
    SideEffectConvergenceReason,
    SideEffectConvergenceSummary,
    SideEffectConvergenceViolation,
    SideEffectScope,
)
from app.models.verification_readiness import entity_effect_verified_for_action
from app.services.writeback_close_gate import load_active_outboxes

_ACTIVE_JOB_STATUSES = frozenset(
    {
        ExecutionJobStatus.QUEUED,
        ExecutionJobStatus.RUNNING,
    }
)
_TERMINAL_JOB_STATUSES = frozenset(
    {
        ExecutionJobStatus.SUCCESS,
        ExecutionJobStatus.PARTIAL_SUCCESS,
    }
)
_UNDELIVERED_OUTBOX_STATUSES = frozenset(
    {
        OutboxDeliveryStatus.READY,
        OutboxDeliveryStatus.LEASED,
        OutboxDeliveryStatus.WAITING_RETRY,
        OutboxDeliveryStatus.PAUSED,
        OutboxDeliveryStatus.DEAD_LETTER,
    }
)
_UNCONFIRMED_WRITEBACK_PRIORITIES: tuple[WritebackStatus, ...] = (
    WritebackStatus.CONFLICT,
    WritebackStatus.FAILED,
    WritebackStatus.SENDING,
    WritebackStatus.PENDING,
)
_ENTITY_OUTBOX_FAILURE_STATUSES = frozenset(
    {
        WritebackStatus.FAILED,
        WritebackStatus.CONFLICT,
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


def _resolve_convergence_policy(
    action_row: orm.Action,
    active_outboxes: list[orm.DispositionOutbox],
) -> SideEffectConvergencePolicy:
    """Classify side-effect convergence evidence by action/outbox kind."""
    if action_row.writeback_applicable:
        return SideEffectConvergencePolicy.TERMINAL_WRITEBACK
    if any(
        outbox.intent_kind == DispositionIntentKind.ENTITY_ACTION_SUBMIT.value
        for outbox in active_outboxes
    ):
        return SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT
    if (
        action_row.execution_owner == ExecutionOwner.XDR_MANAGED.value
        and action_row.writeback_required
    ):
        return SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT
    return SideEffectConvergencePolicy.EXECUTION_JOB_ONLY


def _job_terminal_success(job: orm.ActionExecutionJob | None) -> bool:
    if job is None:
        return False
    try:
        status = ExecutionJobStatus(job.status)
    except ValueError:
        return False
    return status in _TERMINAL_JOB_STATUSES


def _action_terminal_success(action_row: orm.Action) -> bool:
    status = _parse_action_status(action_row.status)
    return status in {ActionStatus.SUCCESS, ActionStatus.PARTIAL_SUCCESS}


def _outbox_blocks_terminal_writeback(
    outbox: orm.DispositionOutbox,
) -> tuple[bool, SideEffectConvergenceReason | None]:
    wb_raw = outbox.latest_writeback_status
    if wb_raw and wb_raw != WritebackStatus.CONFIRMED.value:
        try:
            WritebackStatus(wb_raw)
        except ValueError:
            return True, SideEffectConvergenceReason.TERMINAL_WRITEBACK_UNCONFIRMED
        return True, SideEffectConvergenceReason.TERMINAL_WRITEBACK_UNCONFIRMED
    try:
        delivery = OutboxDeliveryStatus(outbox.delivery_status)
    except ValueError:
        delivery = None
    if delivery in _UNDELIVERED_OUTBOX_STATUSES:
        return True, SideEffectConvergenceReason.OUTBOX_UNDELIVERED
    return False, None


def _outbox_blocks_entity_effect(
    outbox: orm.DispositionOutbox,
) -> tuple[bool, SideEffectConvergenceReason | None]:
    try:
        delivery = OutboxDeliveryStatus(outbox.delivery_status)
    except ValueError:
        delivery = None
    if delivery in _UNDELIVERED_OUTBOX_STATUSES:
        return True, SideEffectConvergenceReason.OUTBOX_UNDELIVERED

    wb_raw = outbox.latest_writeback_status
    if not wb_raw:
        return False, None
    try:
        wb_status = WritebackStatus(wb_raw)
    except ValueError:
        return True, SideEffectConvergenceReason.OUTBOX_NOT_CONFIRMED
    if wb_status in _ENTITY_OUTBOX_FAILURE_STATUSES:
        return True, SideEffectConvergenceReason.OUTBOX_NOT_CONFIRMED
    # ACCEPTED / CONFIRMED / PENDING do not block entity-effect convergence alone.
    return False, None


def _scan_outboxes_for_block(
    active_outboxes: list[orm.DispositionOutbox],
    *,
    policy: SideEffectConvergencePolicy,
) -> SideEffectConvergenceReason | None:
    checker = (
        _outbox_blocks_terminal_writeback
        if policy is SideEffectConvergencePolicy.TERMINAL_WRITEBACK
        else _outbox_blocks_entity_effect
    )
    for outbox in active_outboxes:
        blocks, reason = checker(outbox)
        if blocks and reason is not None:
            return reason
    return None


def _summarize_outbox_fields(
    active_outboxes: list[orm.DispositionOutbox],
) -> tuple[OutboxDeliveryStatus | None, WritebackStatus | None]:
    """Pick representative delivery/writeback across all active outboxes (worst-first)."""
    if not active_outboxes:
        return None, None

    deliveries: list[OutboxDeliveryStatus] = []
    writebacks: list[WritebackStatus] = []
    for outbox in active_outboxes:
        try:
            deliveries.append(OutboxDeliveryStatus(outbox.delivery_status))
        except ValueError:
            continue
    for outbox in active_outboxes:
        raw = outbox.latest_writeback_status
        if not raw:
            continue
        try:
            writebacks.append(WritebackStatus(raw))
        except ValueError:
            writebacks.append(WritebackStatus.PENDING)

    outbox_delivery: OutboxDeliveryStatus | None = None
    for delivery_candidate in (
        OutboxDeliveryStatus.DEAD_LETTER,
        OutboxDeliveryStatus.READY,
        OutboxDeliveryStatus.LEASED,
        OutboxDeliveryStatus.WAITING_RETRY,
        OutboxDeliveryStatus.PAUSED,
    ):
        if delivery_candidate in deliveries:
            outbox_delivery = delivery_candidate
            break
    if outbox_delivery is None and deliveries:
        outbox_delivery = deliveries[0]

    outbox_wb: WritebackStatus | None = None
    for writeback_candidate in _UNCONFIRMED_WRITEBACK_PRIORITIES:
        if writeback_candidate in writebacks:
            outbox_wb = writeback_candidate
            break
    if outbox_wb is None and writebacks:
        outbox_wb = writebacks[0]

    return outbox_delivery, outbox_wb


def _build_jobs_by_action(
    jobs: list[orm.ActionExecutionJob],
) -> dict[str, orm.ActionExecutionJob]:
    """Map action_id → job, preferring active (QUEUED/RUNNING) over terminal rows."""
    result: dict[str, orm.ActionExecutionJob] = {}
    for job in jobs:
        existing = result.get(job.action_id)
        if existing is None:
            result[job.action_id] = job
            continue
        try:
            new_status = ExecutionJobStatus(job.status)
            old_status = ExecutionJobStatus(existing.status)
        except ValueError:
            continue
        if new_status in _ACTIVE_JOB_STATUSES and old_status not in _ACTIVE_JOB_STATUSES:
            result[job.action_id] = job
    return result


async def _load_verification_result(
    session: AsyncSession,
    event_id: str,
) -> VerificationResult | None:
    row = await session.scalar(
        select(orm.EventContextJournal.value)
        .where(
            orm.EventContextJournal.event_id == event_id,
            orm.EventContextJournal.field_name == "verification_result",
        )
        .order_by(orm.EventContextJournal.version.desc())
        .limit(1)
    )
    if row is not None:
        try:
            return VerificationResult.model_validate(row)
        except Exception:
            pass

    event_row = await session.get(orm.SecurityEvent, event_id)
    if event_row is None or not isinstance(event_row.event_context_snapshot, dict):
        return None
    raw = event_row.event_context_snapshot.get("verification_result")
    if raw is None:
        return None
    try:
        return VerificationResult.model_validate(raw)
    except Exception:
        return None


def _action_side_effect_blocks_convergence(
    action_row: orm.Action,
    *,
    jobs_by_action: dict[str, orm.ActionExecutionJob],
    active_outboxes: list[orm.DispositionOutbox],
    verification: VerificationResult | None,
) -> tuple[SideEffectConvergenceReason | None, SideEffectConvergencePolicy]:
    """Return a blocking reason when jobs/outboxes/effects for an action have not converged."""
    policy = _resolve_convergence_policy(action_row, active_outboxes)
    status = _parse_action_status(action_row.status)
    if status is ActionStatus.EXECUTING:
        return SideEffectConvergenceReason.EXECUTING_ACTION, policy
    if _action_has_active_job(action_row.action_id, jobs_by_action) is not None:
        return SideEffectConvergenceReason.IN_FLIGHT_JOB, policy

    job = jobs_by_action.get(action_row.action_id)

    if policy is SideEffectConvergencePolicy.EXECUTION_JOB_ONLY:
        if _job_terminal_success(job) or _action_terminal_success(action_row):
            return None, policy
        if job is not None:
            return SideEffectConvergenceReason.IN_FLIGHT_JOB, policy
        return SideEffectConvergenceReason.IN_FLIGHT_JOB, policy

    if policy is SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT:
        outbox_reason = _scan_outboxes_for_block(active_outboxes, policy=policy)
        if outbox_reason is not None:
            return outbox_reason, policy
        if not _job_terminal_success(job) and not _action_terminal_success(action_row):
            return SideEffectConvergenceReason.IN_FLIGHT_JOB, policy
        if not entity_effect_verified_for_action(verification, action_row.action_id):
            return SideEffectConvergenceReason.EFFECT_UNVERIFIED, policy
        return None, policy

    outbox_reason = _scan_outboxes_for_block(active_outboxes, policy=policy)
    if outbox_reason is not None:
        return outbox_reason, policy
    return None, policy


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
                select(orm.ActionExecutionJob).where(orm.ActionExecutionJob.event_id == event_id)
            )
        ).all()
    )
    jobs_by_action = _build_jobs_by_action(jobs)
    verification = await _load_verification_result(session, event_id)

    outstanding: list[OutstandingSideEffectView] = []
    gate_count = 0
    background_count = 0

    for action_row in action_rows:
        if action_row.status == ActionStatus.REJECTED.value:
            continue

        scope = _classify_scope(
            action_row=action_row,
            current_revision=current_revision,
            disposition_policy=disposition_policy,
        )
        active_outboxes = await load_active_outboxes(session, action_row.action_id)
        blocking_reason, policy = _action_side_effect_blocks_convergence(
            action_row,
            jobs_by_action=jobs_by_action,
            active_outboxes=active_outboxes,
            verification=verification,
        )
        if blocking_reason is None:
            continue

        job = jobs_by_action.get(action_row.action_id)
        job_status: ExecutionJobStatus | None = None
        if job is not None:
            try:
                job_status = ExecutionJobStatus(job.status)
            except ValueError:
                job_status = None

        outbox_delivery, outbox_wb = _summarize_outbox_fields(active_outboxes)

        view = OutstandingSideEffectView(
            action_id=action_row.action_id,
            scope=scope,
            action_status=_parse_action_status(action_row.status),
            execution_phase=_parse_exec_phase(action_row.execution_phase),
            writeback_applicable=bool(action_row.writeback_applicable),
            convergence_policy=policy,
            job_status=job_status,
            outbox_delivery_status=outbox_delivery,
            outbox_writeback_status=outbox_wb,
            plan_revision=int(action_row.plan_revision),
            superseded=action_row.superseded_by_revision is not None,
            blocking_reason=blocking_reason,
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
        if view.blocking_reason is not None:
            return SideEffectConvergenceViolation(
                reason=view.blocking_reason,
                action_id=view.action_id,
                scope=view.scope,
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

    try:
        return await reconcile_stale_executions_for_event(
            session_factory,
            event_id=event_id,
            limit=limit,
            force=True,
        )
    except Exception as exc:
        raise InvalidStateTransitionError(
            "stale execution reconcile failed before CLOSED gate",
            target=EventStatus.CLOSED,
            error_code="closed_side_effects_pending",
            details={"event_id": event_id, "reason": "stale_reconcile_failed"},
        ) from exc


__all__ = [
    "build_side_effect_convergence_summary",
    "check_gate_applicable_side_effect_convergence",
    "raise_side_effect_convergence_error",
    "reconcile_stale_executions_before_close",
]
