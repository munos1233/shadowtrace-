"""Session-backed CLOSED gate projections and Close API error mapping (ISSUE-171)."""

from __future__ import annotations

from typing import NoReturn

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import (
    WritebackConflictError,
    WritebackFailedError,
    WritebackPendingError,
    WritebackUnsupportedError,
)
from app.db import models as orm
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    SourceDisposition,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.workflow import (
    ClosedGateActionView,
    WritebackCloseGateReason,
    WritebackCloseGateViolation,
)


def raise_api_writeback_gate_error(
    violation: WritebackCloseGateViolation,
    *,
    event_id: str,
) -> NoReturn:
    """Map a shared violation to Close API HTTP domain errors.

    Close API calls this only after side-effect convergence passes (ISSUE-302).
    ``writeback_*`` codes here reflect the writeback predicate, not outstanding
    convergence on unconfirmed outboxes.
    """
    details: dict[str, str] = {"event_id": event_id}
    if violation.action_id is not None:
        details["action_id"] = violation.action_id
    if violation.writeback_readiness is not None:
        details["readiness"] = violation.writeback_readiness
    if violation.writeback_status is not None:
        details["writeback_status"] = violation.writeback_status

    if violation.reason is WritebackCloseGateReason.NO_APPLICABLE:
        raise WritebackUnsupportedError(
            "required disposition_policy but no disposition Action configured",
            details=details,
        )
    if violation.reason is WritebackCloseGateReason.READINESS_NOT_READY:
        raise WritebackUnsupportedError(
            f"writeback readiness is {violation.writeback_readiness}",
            details=details,
        )
    if violation.reason is WritebackCloseGateReason.NO_COMMAND:
        raise WritebackUnsupportedError(
            "required writeback Action has no disposition command",
            details=details,
        )
    if violation.reason is WritebackCloseGateReason.INTENTS_NOT_CONFIRMED:
        status = violation.writeback_status
        if status == WritebackStatus.FAILED.value:
            raise WritebackFailedError("writeback failed", details=details)
        if status == WritebackStatus.CONFLICT.value:
            raise WritebackConflictError("writeback conflict", details=details)
        raise WritebackPendingError(
            "required writeback intents are not all CONFIRMED",
            details=details,
        )

    status = violation.writeback_status
    if status == WritebackStatus.FAILED.value:
        raise WritebackFailedError("writeback failed", details=details)
    if status == WritebackStatus.CONFLICT.value:
        raise WritebackConflictError("writeback conflict", details=details)
    pending_label = status or WritebackStatus.PENDING.value
    raise WritebackPendingError(
        f"writeback is {pending_label}",
        details=details,
    )


async def all_intents_confirmed_for_action(session: AsyncSession, action_id: str) -> bool:
    """Return True when every active outbox record for *action_id* is CONFIRMED."""
    outboxes = (
        await session.scalars(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.action_id == action_id,
                orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
            )
        )
    ).all()
    if not outboxes:
        return False
    return all(
        outbox.latest_writeback_status == WritebackStatus.CONFIRMED.value for outbox in outboxes
    )


def worst_unconfirmed_outbox_status(
    outboxes: list[orm.DispositionOutbox],
) -> WritebackStatus | None:
    """Pick the most severe non-CONFIRMED outbox status for API error mapping."""
    parsed: list[WritebackStatus] = []
    for outbox in outboxes:
        raw = outbox.latest_writeback_status
        if raw is None or raw == WritebackStatus.CONFIRMED.value:
            continue
        try:
            parsed.append(WritebackStatus(raw))
        except ValueError:
            continue
    if not parsed:
        return None
    if WritebackStatus.CONFLICT in parsed:
        return WritebackStatus.CONFLICT
    if WritebackStatus.FAILED in parsed:
        return WritebackStatus.FAILED
    return parsed[0]


async def load_active_outboxes(
    session: AsyncSession, action_id: str
) -> list[orm.DispositionOutbox]:
    return list(
        (
            await session.scalars(
                select(orm.DispositionOutbox)
                .where(
                    orm.DispositionOutbox.action_id == action_id,
                    orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                )
                .order_by(
                    orm.DispositionOutbox.created_at.asc(),
                    orm.DispositionOutbox.outbox_id.asc(),
                )
            )
        ).all()
    )


async def action_has_job_or_outbox(session: AsyncSession, action_id: str) -> bool:
    job = await session.scalar(
        select(orm.ActionExecutionJob.job_id)
        .where(orm.ActionExecutionJob.action_id == action_id)
        .limit(1)
    )
    if job is not None:
        return True
    outbox = await session.scalar(
        select(orm.DispositionOutbox.outbox_id)
        .where(orm.DispositionOutbox.action_id == action_id)
        .limit(1)
    )
    return outbox is not None


async def build_closed_gate_actions(
    session: AsyncSession,
    event_id: str,
    current_revision: int | None,
) -> list[ClosedGateActionView]:
    """Collect applicable-required response/rollback Actions for the CLOSED gate."""
    if current_revision is None:
        return []

    actions: list[orm.Action] = list(
        (
            await session.scalars(
                select(orm.Action).where(
                    orm.Action.event_id == event_id,
                    orm.Action.plan_revision == current_revision,
                    orm.Action.action_category.in_(
                        (ActionCategory.RESPONSE.value, ActionCategory.ROLLBACK.value)
                    ),
                    orm.Action.superseded_by_revision.is_(None),
                )
            )
        ).all()
    )

    result: list[ClosedGateActionView] = []
    for action_row in actions:
        cat = ActionCategory(action_row.action_category)

        readiness_raw = action_row.writeback_readiness
        try:
            readiness = (
                WritebackReadiness(readiness_raw)
                if readiness_raw
                else WritebackReadiness.NOT_CONFIGURED
            )
        except ValueError:
            readiness = WritebackReadiness.NOT_CONFIGURED

        wb_status: WritebackStatus | None = None
        if action_row.writeback_status:
            try:
                wb_status = WritebackStatus(action_row.writeback_status)
            except ValueError:
                pass

        active_outboxes = await load_active_outboxes(session, action_row.action_id)
        # ``has_command`` must mean an *active* command exists. A stale outbox
        # whose only rows are superseded is not a live command: treating it as
        # one would make ``all(active_outboxes)`` over an empty list evaluate to
        # True (vacuum CONFIRMED) and wrongly satisfy the CLOSED gate (ISSUE-185).
        has_command = bool(active_outboxes)
        all_confirmed = False
        worst_outbox: WritebackStatus | None = None
        if has_command:
            all_confirmed = all(
                o.latest_writeback_status == WritebackStatus.CONFIRMED.value
                for o in active_outboxes
            )
            worst_outbox = worst_unconfirmed_outbox_status(active_outboxes)

        approved_terminal: list[SourceDisposition] = []
        for raw in action_row.approved_terminal_dispositions or []:
            try:
                approved_terminal.append(SourceDisposition(str(raw)))
            except ValueError:
                pass

        has_job_or_outbox = await action_has_job_or_outbox(session, action_row.action_id)

        execution_phase_raw = action_row.execution_phase or "immediate"
        try:
            exec_phase = ActionExecutionPhase(execution_phase_raw)
        except ValueError:
            exec_phase = ActionExecutionPhase.IMMEDIATE

        result.append(
            ClosedGateActionView(
                action_id=action_row.action_id,
                action_category=cat,
                writeback_required=bool(action_row.writeback_required),
                writeback_applicable=bool(action_row.writeback_applicable),
                writeback_readiness=readiness,
                writeback_status=wb_status,
                has_command=has_command,
                all_required_intents_confirmed=all_confirmed,
                worst_unconfirmed_outbox_status=worst_outbox,
                execution_phase=exec_phase,
                tool_name=action_row.tool_name,
                approved_terminal_dispositions=approved_terminal,
                superseded=bool(action_row.superseded_by_revision),
                rejected=action_row.status == ActionStatus.REJECTED.value,
                has_job_or_outbox=has_job_or_outbox,
            )
        )

    return result


__all__ = [
    "action_has_job_or_outbox",
    "all_intents_confirmed_for_action",
    "build_closed_gate_actions",
    "load_active_outboxes",
    "raise_api_writeback_gate_error",
    "worst_unconfirmed_outbox_status",
]
