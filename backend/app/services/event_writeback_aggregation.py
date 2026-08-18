"""Event-level writeback channels aligned with ISSUE-312 CLOSED gates.

Terminal writeback (``writeback_applicable=true``) must reach CONFIRMED.
Independent entity submits (``writeback_applicable=false``) may remain
ACCEPTED after effect verification — they must not pollute EventDetail
``pending_writeback_count`` / ``writeback_overall_status``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import (
    ActionCategory,
    DispositionPolicy,
    WritebackReadiness,
    WritebackStatus,
)
from app.services.context_service import READINESS_AGGREGATE_PRIORITY, _pick_by_priority

_RESPONSE_CATEGORIES = (ActionCategory.RESPONSE.value, ActionCategory.ROLLBACK.value)
_TERMINAL_PENDING_STATUSES = (
    WritebackStatus.PENDING.value,
    WritebackStatus.SENDING.value,
    WritebackStatus.ACCEPTED.value,
    WritebackStatus.UNKNOWN.value,
)


@dataclass(frozen=True, slots=True)
class EventWritebackChannels:
    """Split EventDetail writeback projection (terminal vs entity)."""

    terminal_readiness: WritebackReadiness
    terminal_overall_status: WritebackStatus | None
    terminal_pending_count: int
    entity_writeback_accepted_count: int


def _parse_writeback_status(raw: str | None) -> WritebackStatus | None:
    if not raw:
        return None
    try:
        return WritebackStatus(str(raw))
    except ValueError:
        return None


def _overall_from_statuses(parsed: list[WritebackStatus]) -> WritebackStatus | None:
    if not parsed:
        return None
    if any(s is WritebackStatus.FAILED for s in parsed):
        return WritebackStatus.FAILED
    if any(s is WritebackStatus.CONFLICT for s in parsed):
        return WritebackStatus.CONFLICT
    if any(s is WritebackStatus.UNKNOWN for s in parsed):
        return WritebackStatus.UNKNOWN
    if any(
        s in (WritebackStatus.PENDING, WritebackStatus.SENDING, WritebackStatus.ACCEPTED)
        for s in parsed
    ):
        return WritebackStatus.PENDING
    if all(s is WritebackStatus.CONFIRMED for s in parsed):
        return WritebackStatus.CONFIRMED
    return None


async def aggregate_event_writeback_channels(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    policy: DispositionPolicy,
) -> EventWritebackChannels:
    """Aggregate current-plan writeback into ISSUE-312 terminal vs entity channels."""
    if policy is DispositionPolicy.NOT_REQUIRED:
        return EventWritebackChannels(
            terminal_readiness=WritebackReadiness.NOT_REQUIRED,
            terminal_overall_status=None,
            terminal_pending_count=0,
            entity_writeback_accepted_count=0,
        )

    async with session_factory() as session:
        current_revision = await session.scalar(
            select(func.max(orm.Action.plan_revision)).where(orm.Action.event_id == event_id)
        )
        action_rows = list(
            (
                await session.scalars(
                    select(orm.Action).where(
                        orm.Action.event_id == event_id,
                        orm.Action.plan_revision == current_revision,
                        orm.Action.action_category.in_(_RESPONSE_CATEGORIES),
                        orm.Action.superseded_by_revision.is_(None),
                        orm.Action.status.not_in(("rejected", "superseded")),
                    )
                )
            ).all()
        )
        terminal_ids = {row.action_id for row in action_rows if row.writeback_applicable}
        entity_ids = {
            row.action_id
            for row in action_rows
            if row.writeback_required and not row.writeback_applicable
        }

        terminal_readiness = WritebackReadiness.NOT_CONFIGURED
        if terminal_ids:
            present: set[WritebackReadiness] = set()
            for row in action_rows:
                if row.action_id not in terminal_ids:
                    continue
                try:
                    present.add(WritebackReadiness(row.writeback_readiness))
                except ValueError:
                    present.add(WritebackReadiness.CAPABILITY_UNKNOWN)
            picked = _pick_by_priority(present, READINESS_AGGREGATE_PRIORITY)
            terminal_readiness = (
                picked if isinstance(picked, WritebackReadiness) else WritebackReadiness.READY
            )
        elif any(row.writeback_required for row in action_rows):
            # REQUIRED policy with only non-applicable entity rows — never invent READY.
            terminal_readiness = WritebackReadiness.CAPABILITY_UNKNOWN

        current_plan_filter = (
            orm.Action.plan_revision == current_revision,
            orm.Action.superseded_by_revision.is_(None),
        )

        terminal_pending = 0
        if terminal_ids:
            terminal_pending = int(
                await session.scalar(
                    select(func.count(orm.DispositionOutbox.outbox_id))
                    .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
                    .where(
                        orm.DispositionOutbox.event_id == event_id,
                        *current_plan_filter,
                        orm.DispositionOutbox.action_id.in_(terminal_ids),
                        orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                        orm.DispositionOutbox.latest_writeback_status.in_(
                            _TERMINAL_PENDING_STATUSES
                        ),
                    )
                )
                or 0
            )

        entity_accepted = 0
        if entity_ids:
            entity_accepted = int(
                await session.scalar(
                    select(func.count(orm.DispositionOutbox.outbox_id))
                    .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
                    .where(
                        orm.DispositionOutbox.event_id == event_id,
                        *current_plan_filter,
                        orm.DispositionOutbox.action_id.in_(entity_ids),
                        orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                        orm.DispositionOutbox.latest_writeback_status
                        == WritebackStatus.ACCEPTED.value,
                    )
                )
                or 0
            )

        parsed_terminal: list[WritebackStatus] = []
        if terminal_ids:
            status_rows = (
                await session.scalars(
                    select(orm.DispositionOutbox.latest_writeback_status)
                    .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
                    .where(
                        orm.DispositionOutbox.event_id == event_id,
                        *current_plan_filter,
                        orm.DispositionOutbox.action_id.in_(terminal_ids),
                        orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                    )
                )
            ).all()
            for raw in status_rows:
                parsed = _parse_writeback_status(raw)
                if parsed is not None:
                    parsed_terminal.append(parsed)

        return EventWritebackChannels(
            terminal_readiness=terminal_readiness,
            terminal_overall_status=_overall_from_statuses(parsed_terminal),
            terminal_pending_count=terminal_pending,
            entity_writeback_accepted_count=entity_accepted,
        )
