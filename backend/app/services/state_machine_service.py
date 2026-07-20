"""StateMachineService — sole write path for EventStatus transitions (ISSUE-037).

Every status change flows through ``transition()`` which validates, acquires a
row lock, updates PostgreSQL, writes an audit log, syncs the EventContext, and
publishes a ``state_change`` event.  ``force_close()`` is the only admin-only
bypass that sets ``external_unsynced=true``.

References
----------
* ``validate_transition`` / ``TransitionContext`` — ``app.models.workflow``
* ``EventContextStore`` — ``app.services.context_service``
* ``EventAuditLogService`` — ``app.services.event_audit_log_service``
* ``DegradedFlagService`` — ``app.services.degraded_flag_service``
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import (
    EventNotFoundError,
    InvalidStateTransitionError,
)
from app.core.event_bus import EventBus
from app.db import models as orm
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    FinalVerdict,
    SourceDisposition,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.security_event import SecurityEvent
from app.models.workflow import (
    MAX_REPLAN_COUNT,
    STATE_TRANSITIONS,
    ClosedGateActionView,
    TerminalEventWritebackView,
    TransitionContext,
    validate_transition,
)
from app.services.context_service import (
    EventContextStore,
    event_summary_from_security_event,
)
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_audit_log_service import EventAuditLogService

logger = logging.getLogger(__name__)

_STATE_MACHINE_OPERATOR = "StateMachineService"


def _utc_now() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Row → domain model
# --------------------------------------------------------------------------- #


def _security_event_from_row(row: orm.SecurityEvent) -> SecurityEvent:
    """Mapper kept self-contained to avoid circular imports with EventService.

    Must stay byte-identical with ``EventService._security_event_from_row``.
    """
    from app.models.entities import EntitySet
    from app.models.source import SourceReference

    creation = SourceReference.model_validate(row.creation_source_ref)
    snapshots = [SourceReference.model_validate(s) for s in (row.source_reference_snapshots or [])]
    disposition = None
    if row.disposition_source_ref:
        from app.models.disposition import SourceObjectLocator

        disposition = SourceObjectLocator.model_validate(row.disposition_source_ref)
    entities_raw = row.entities or {}
    try:
        entities = EntitySet.model_validate(entities_raw)
    except Exception:  # noqa: BLE001
        entities = EntitySet()
    return SecurityEvent(
        event_id=row.event_id,
        event_type=row.event_type,  # type: ignore[arg-type]
        title=row.title,
        description=row.description or "",
        status=EventStatus(row.status),
        severity=row.severity,  # type: ignore[arg-type]
        risk_score=int(row.risk_score or 0),
        confidence=float(row.confidence or 0.0),
        final_verdict=FinalVerdict(row.final_verdict),
        entities=entities,
        creation_source_ref=creation,
        source_reference_snapshots=snapshots,
        current_primary_source_record_id=row.current_primary_source_record_id,
        disposition_source_ref=disposition,
        disposition_policy=DispositionPolicy(row.disposition_policy),
        raw_alert_ids=list(row.raw_alert_ids or []),
        raw_alert_snapshot=row.raw_alert_snapshot,
        source_type=row.source_type,
        occurred_at=row.occurred_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        closed_at=row.closed_at,
        replan_count=int(row.replan_count or 0),
        degraded_flags=[str(f) for f in (row.degraded_flags or [])],
        escalated=bool(row.escalated),
        external_unsynced=bool(row.external_unsynced),
        event_context_snapshot=row.event_context_snapshot,
        row_version=int(row.row_version or 1),
    )


# --------------------------------------------------------------------------- #
# Authoritative TransitionContext builder
# --------------------------------------------------------------------------- #


async def _build_authoritative_context(
    session: AsyncSession,
    event_id: str,
    row: orm.SecurityEvent,
    caller_context: TransitionContext | None,
) -> TransitionContext:
    """Rebuild trusted transition gates from PostgreSQL.

    Only *business inputs* (recommendation, need_investigation) are taken from
    the caller.  CLOSED gate projections are read from live DB state — never
    from API / LLM self-report.
    """
    caller = caller_context or TransitionContext()

    from app.models.tool_meta import TERMINAL_DISPOSITION_TOOL

    # --- verdict-level gates ---

    journal_value = await session.scalar(
        select(orm.EventContextJournal.value)
        .where(
            orm.EventContextJournal.event_id == event_id,
            orm.EventContextJournal.field_name == "disposition_only_intent",
        )
        .order_by(orm.EventContextJournal.version.desc())
        .limit(1)
    )
    if isinstance(journal_value, dict) and set(journal_value) == {"_scalar"}:
        journal_value = journal_value["_scalar"]
    disposition_only_intent = journal_value is True

    current_revision = await session.scalar(
        select(func.max(orm.Action.plan_revision)).where(orm.Action.event_id == event_id)
    )
    response_actions: list[orm.Action] = []
    if current_revision is not None:
        response_actions = list(
            (
                await session.scalars(
                    select(orm.Action).where(
                        orm.Action.event_id == event_id,
                        orm.Action.plan_revision == current_revision,
                        orm.Action.action_category == ActionCategory.RESPONSE.value,
                        orm.Action.superseded_by_revision.is_(None),
                    )
                )
            ).all()
        )

    response_actions_are_disposition_only: bool | None = None
    has_entity_side_effect_actions = False
    if response_actions:
        response_actions_are_disposition_only = all(
            a.action_name == TERMINAL_DISPOSITION_TOOL for a in response_actions
        )
        has_entity_side_effect_actions = any(
            a.action_name != TERMINAL_DISPOSITION_TOOL for a in response_actions
        )

    # --- CLOSED gate projections ---

    report_exists = await _check_report_exists(session, event_id)
    applicable_required_actions = await _build_closed_gate_actions(
        session, event_id, current_revision
    )
    terminal_event_writeback = await _build_terminal_writeback_view(
        session, event_id, current_revision
    )
    current_closure_cycle = await _read_closure_cycle(session, event_id)

    return TransitionContext(
        final_verdict=FinalVerdict(row.final_verdict),
        disposition_policy=DispositionPolicy(row.disposition_policy),
        severity=row.severity,  # type: ignore[arg-type]
        disposition_only_intent=disposition_only_intent,
        response_actions_are_disposition_only=response_actions_are_disposition_only,
        has_entity_side_effect_actions=has_entity_side_effect_actions,
        report_exists=report_exists,
        force_close=False,
        applicable_required_actions=applicable_required_actions,
        terminal_event_writeback=terminal_event_writeback,
        current_plan_revision=current_revision,
        current_closure_cycle=current_closure_cycle,
        need_investigation=caller.need_investigation,
        recommendation=caller.recommendation,
    )


async def _check_report_exists(session: AsyncSession, event_id: str) -> bool:
    row = await session.scalar(
        select(orm.Report.report_id).where(orm.Report.event_id == event_id).limit(1)
    )
    return row is not None


async def _build_closed_gate_actions(
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
    for a in actions:
        cat = ActionCategory(a.action_category)

        # writeback_readiness
        readiness_raw = a.writeback_readiness
        try:
            readiness = (
                WritebackReadiness(readiness_raw)
                if readiness_raw
                else WritebackReadiness.NOT_CONFIGURED
            )
        except ValueError:
            readiness = WritebackReadiness.NOT_CONFIGURED

        # writeback_status
        wb_status: WritebackStatus | None = None
        if a.writeback_status:
            try:
                wb_status = WritebackStatus(a.writeback_status)
            except ValueError:
                pass

        # Determine if this action has an outbox record.
        outbox = await session.scalar(
            select(orm.DispositionOutbox.outbox_id)
            .where(orm.DispositionOutbox.action_id == a.action_id)
            .limit(1)
        )
        has_command = outbox is not None

        # Check if all linked outbox records are CONFIRMED.
        all_confirmed = False
        if has_command:
            all_confirmed = await _all_intents_confirmed_for_action(session, a.action_id)

        # Approved terminal dispositions from the action.
        approved_terminal: list[SourceDisposition] = []
        for raw in a.approved_terminal_dispositions or []:
            try:
                approved_terminal.append(SourceDisposition(str(raw)))
            except ValueError:
                pass

        # Check if this action has a job or outbox record.
        has_job_or_outbox = await _action_has_job_or_outbox(session, a.action_id)

        execution_phase_raw = a.execution_phase or "immediate"
        try:
            exec_phase = ActionExecutionPhase(execution_phase_raw)
        except ValueError:
            exec_phase = ActionExecutionPhase.IMMEDIATE

        view = ClosedGateActionView(
            action_id=a.action_id,
            action_category=cat,
            writeback_required=bool(a.writeback_required),
            writeback_applicable=bool(a.writeback_applicable),
            writeback_readiness=readiness,
            writeback_status=wb_status,
            has_command=has_command,
            all_required_intents_confirmed=all_confirmed,
            execution_phase=exec_phase,
            tool_name=a.action_name,
            approved_terminal_dispositions=approved_terminal,
            superseded=bool(a.superseded_by_revision),
            rejected=a.status == ActionStatus.REJECTED.value,
            has_job_or_outbox=has_job_or_outbox,
        )
        result.append(view)

    return result


async def _all_intents_confirmed_for_action(session: AsyncSession, action_id: str) -> bool:
    """Return True when every outbox record for *action_id* is CONFIRMED."""
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
    return all(o.latest_writeback_status == WritebackStatus.CONFIRMED.value for o in outboxes)


async def _action_has_job_or_outbox(session: AsyncSession, action_id: str) -> bool:
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


async def _build_terminal_writeback_view(
    session: AsyncSession,
    event_id: str,
    current_revision: int | None,
) -> TerminalEventWritebackView | None:
    """Find the single active EVENT_STATUS_UPDATE outbox for the CLOSED gate."""
    if current_revision is None:
        return None

    from app.models.tool_meta import TERMINAL_DISPOSITION_TOOL

    # Find the deferred update_source_event_disposition Action.
    deferred_action = await session.scalar(
        select(orm.Action)
        .where(
            orm.Action.event_id == event_id,
            orm.Action.plan_revision == current_revision,
            orm.Action.action_name == TERMINAL_DISPOSITION_TOOL,
            orm.Action.execution_phase == ActionExecutionPhase.POST_VERIFY.value,
            orm.Action.superseded_by_revision.is_(None),
        )
        .limit(1)
    )
    if deferred_action is None:
        return None

    # Find the non-superseded EVENT_STATUS_UPDATE outbox for this action.
    outbox = await session.scalar(
        select(orm.DispositionOutbox)
        .where(
            orm.DispositionOutbox.action_id == deferred_action.action_id,
            orm.DispositionOutbox.intent_kind == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
        )
        .limit(1)
    )
    if outbox is None:
        return None

    # Parse writeback status.
    wb_status = WritebackStatus.PENDING
    if outbox.latest_writeback_status:
        try:
            wb_status = WritebackStatus(outbox.latest_writeback_status)
        except ValueError:
            pass

    # Parse approved disposition from action template.
    approved = SourceDisposition.PENDING
    approved_list = deferred_action.approved_terminal_dispositions or []
    if approved_list:
        try:
            approved = SourceDisposition(str(approved_list[0]))
        except (ValueError, IndexError):
            pass

    # Parse actual disposition from command_payload.
    actual_enum = approved
    payload = outbox.command_payload or {}
    actual_raw = payload.get("target_disposition")
    if actual_raw:
        try:
            actual_enum = SourceDisposition(str(actual_raw))
        except ValueError:
            pass

    return TerminalEventWritebackView(
        action_id=deferred_action.action_id,
        disposition_id=outbox.disposition_id,
        writeback_id=outbox.writeback_id,
        closure_cycle=int(outbox.closure_cycle or 0),
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        approved_disposition=approved,
        actual_disposition=actual_enum,
        receipt_status=wb_status,
        plan_revision=current_revision,
    )


async def _read_closure_cycle(session: AsyncSession, event_id: str) -> int | None:
    """Return the current max closure_cycle from disposition outbox records."""
    row = await session.scalar(
        select(func.max(orm.DispositionOutbox.closure_cycle)).where(
            orm.DispositionOutbox.event_id == event_id
        )
    )
    return int(row) if row is not None else None


# --------------------------------------------------------------------------- #
# StateMachineService
# --------------------------------------------------------------------------- #


class StateMachineService:
    """Sole write path for ``security_event.status`` transitions.

    Every status mutation is validated, row-locked, audited, and published.
    Direct callers (orchestration, admin API) call ``transition()``; the
    convenience wrapper ``EventService.transition_status()`` pre-validates
    simple edges and delegates here.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        store: EventContextStore,
        *,
        event_bus: EventBus | None = None,
        audit_log: EventAuditLogService | None = None,
        degraded_flags: DegradedFlagService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._store = store
        self._bus = event_bus
        self._audit_log = audit_log
        self._degraded = degraded_flags

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: TransitionContext | None = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> SecurityEvent:
        """Validate and execute one EventStatus transition.

        Parameters
        ----------
        event_id:
            The event to transition.
        target:
            The desired EventStatus.
        context:
            Caller-supplied *business inputs* only (recommendation,
            need_investigation).  Trusted gate projections are rebuilt from
            PostgreSQL inside the row lock — callers must not set
            ``force_close``, ``report_exists``, or writeback gate fields.
        operator:
            Agent/service name or ``principal:{subject}`` for human actions.
        reason:
            Human-readable reason for the transition (audited).

        Returns
        -------
        SecurityEvent
            The event row *after* the transition has been committed.

        Raises
        ------
        InvalidStateTransitionError
            If the edge is illegal or a CLOSED gate fails.
        EventNotFoundError
            If *event_id* does not exist.
        """
        op = operator or _STATE_MACHINE_OPERATOR

        async with self._session_factory() as session:
            async with session.begin():
                # 1. Row-lock the event.
                row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if row is None:
                    raise EventNotFoundError(
                        f"security_event not found: {event_id}",
                        details={"event_id": event_id},
                    )

                current = EventStatus(row.status)

                # 2. Build authoritative TransitionContext from DB state.
                authoritative_ctx = await _build_authoritative_context(
                    session, event_id, row, context
                )

                # 3. Validate the edge.
                validate_transition(current, target, authoritative_ctx)

                # 4. Pre-status-write side effects (e.g. replan_count bump).
                await self._apply_pre_transition_side_effects(session, row, current, target)

                # 5. Write the new status.
                from_status = row.status
                row.status = target.value
                row.row_version = int(row.row_version or 1) + 1
                row.updated_at = _utc_now()

                # 6. Post-status-write side effects in same TX.
                await self._apply_post_transition_side_effects(session, row, target)

                # 7. Write audit log in the same transaction.
                if self._audit_log is not None:
                    await self._audit_log.log_transition_in_session(
                        session,
                        event_id,
                        from_status=from_status,
                        to_status=target.value,
                        operator=op,
                        reason=reason,
                    )

                await session.flush()
                await session.refresh(row)
                result = _security_event_from_row(row)

        # --- post-commit side effects (best-effort, never roll back) ---

        # 8. Sync EventContext (event summary + state_history).
        await self._sync_context_after_transition(event_id, row, current, target, op, reason)

        # 9. Publish state_change via EventBus.
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "state_change",
                {
                    "from_status": current.value,
                    "to_status": target.value,
                    "operator": op,
                },
            )

        return result

    async def force_close(
        self,
        event_id: str,
        principal: str,
        reason: str,
    ) -> SecurityEvent:
        """Admin-only forced local close with ``external_unsynced=true``.

        Bypasses the normal CLOSED writeback gate.  The *principal* must be a
        traceable identity; it is normalised to ``principal:{subject}`` if not
        already prefixed.
        """
        if not principal.startswith("principal:"):
            principal = f"principal:{principal}"

        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if row is None:
                    raise EventNotFoundError(
                        f"security_event not found: {event_id}",
                        details={"event_id": event_id},
                    )

                current = EventStatus(row.status)
                if current is EventStatus.CLOSED:
                    raise InvalidStateTransitionError(
                        "force_close: event is already CLOSED",
                        current=current,
                        target=EventStatus.CLOSED,
                    )

                # Only validate the raw edge exists; skip writeback gate.
                allowed = STATE_TRANSITIONS.get(current, set())
                if EventStatus.CLOSED not in allowed:
                    raise InvalidStateTransitionError(
                        f"force_close: illegal transition {current.value} → closed",
                        current=current,
                        target=EventStatus.CLOSED,
                    )

                from_status = row.status
                now = _utc_now()

                row.status = EventStatus.CLOSED.value
                row.closed_at = now
                row.external_unsynced = True
                row.row_version = int(row.row_version or 1) + 1
                row.updated_at = now

                reason_text = (
                    f"force_close by {principal}: {reason}"
                    if reason
                    else f"force_close by {principal}"
                )

                if self._audit_log is not None:
                    await self._audit_log.log_transition_in_session(
                        session,
                        event_id,
                        from_status=from_status,
                        to_status=EventStatus.CLOSED.value,
                        operator=principal,
                        reason=reason_text,
                    )

                await session.flush()
                await session.refresh(row)
                result = _security_event_from_row(row)

        # --- post-commit ---

        # Sync EventContext (state_history + event summary) so Redis consumers
        # see the force-close consistently with transition().  This also handles
        # refresh_closed_snapshot + set_closed_ttl for the CLOSED target — no
        # need to duplicate those calls here.
        await self._sync_context_after_transition(
            event_id, row, current, EventStatus.CLOSED, principal, reason_text
        )

        # Publish state_change.
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "state_change",
                {
                    "from_status": current.value,
                    "to_status": EventStatus.CLOSED.value,
                    "operator": principal,
                    "external_unsynced": True,
                },
            )

        return result

    async def get_current_status(self, event_id: str) -> EventStatus:
        """Return the current EventStatus, or raise EventNotFoundError."""
        async with self._session_factory() as session:
            row = await session.get(orm.SecurityEvent, event_id)
            if row is None:
                raise EventNotFoundError(
                    f"security_event not found: {event_id}",
                    details={"event_id": event_id},
                )
            return EventStatus(row.status)

    async def get_transition_history(self, event_id: str) -> list[dict[str, Any]]:
        """Return the audit log entries for *event_id* as dicts."""
        if self._audit_log is None:
            return []
        rows = await self._audit_log.get_logs_by_event(event_id)
        return [
            {
                "id": r.id,
                "event_id": r.event_id,
                "from_status": r.from_status,
                "to_status": r.to_status,
                "operator": r.operator,
                "reason": r.reason,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]

    # ------------------------------------------------------------------ #
    # Side-effect helpers
    # ------------------------------------------------------------------ #

    async def _apply_pre_transition_side_effects(
        self,
        session: AsyncSession,
        row: orm.SecurityEvent,
        current: EventStatus,
        target: EventStatus,
    ) -> None:
        """Side effects that must happen BEFORE the status column is written."""

        if target is EventStatus.REPLANNING:
            new_count = int(row.replan_count or 0) + 1
            if new_count > MAX_REPLAN_COUNT:
                raise InvalidStateTransitionError(
                    f"replan_count would exceed MAX_REPLAN_COUNT ({MAX_REPLAN_COUNT})",
                    current=current,
                    target=target,
                    details={
                        "current_replan_count": int(row.replan_count or 0),
                        "max_replan_count": MAX_REPLAN_COUNT,
                    },
                )
            row.replan_count = new_count

    async def _apply_post_transition_side_effects(
        self,
        session: AsyncSession,
        row: orm.SecurityEvent,
        target: EventStatus,
    ) -> None:
        """Side effects applied after the status write, still inside the TX."""

        if target is EventStatus.CLOSED:
            row.closed_at = _utc_now()
            # refresh_closed_snapshot is deferred to _sync_context_after_transition
            # (post-commit) to avoid cross-connection deadlock — the snapshot's
            # own session would block on the row lock held by the current TX.

    async def _sync_context_after_transition(
        self,
        event_id: str,
        row: orm.SecurityEvent,
        current: EventStatus,
        target: EventStatus,
        operator: str | None,
        reason: str | None,
    ) -> None:
        """Sync EventContext (event summary + state_history) after commit.

        Redis failures are logged and degrade the event but never roll back
        the PostgreSQL transaction.
        """
        # 1. Sync the event summary.
        summary = event_summary_from_security_event(row)
        summary_result = await self._store.set(event_id, "event", summary)

        # 2. Append to state_history.
        history_entry: dict[str, Any] = {
            "from_status": current.value,
            "to_status": target.value,
            "operator": operator or _STATE_MACHINE_OPERATOR,
            "reason": reason,
            "timestamp": _utc_now().isoformat(),
        }
        try:
            current_history = await self._store.get(event_id, "state_history")
            if not isinstance(current_history, list):
                current_history = []
        except (KeyError, ConnectionError, TimeoutError, OSError):
            current_history = []
        updated_history = list(current_history) + [history_entry]
        history_result = await self._store.set(event_id, "state_history", updated_history)

        # 3. Sync replan_count into EventContext (journal).
        replan_result = None
        if target is EventStatus.REPLANNING:
            replan_result = await self._store.set(
                event_id, "replan_count", int(row.replan_count or 0)
            )

        # 4. Mark degraded if Redis is unavailable.
        redis_ok = summary_result.redis_ok and history_result.redis_ok
        if replan_result is not None:
            redis_ok = redis_ok and replan_result.redis_ok
        if not redis_ok:
            logger.warning(
                "Redis context sync failed for event_id=%s after transition "
                "%s→%s; marking degraded",
                event_id,
                current.value,
                target.value,
            )
            if self._degraded is not None:
                await self._degraded.set_flag(
                    event_id,
                    "redis_context_unavailable",
                    True,
                    writer="StateMachineService",
                )

        # 5. Snapshot + TTL for CLOSED events (post-commit — avoids cross-connection
        #    deadlock with the row lock held by the main transaction).
        if target is EventStatus.CLOSED:
            await self._store.refresh_closed_snapshot(event_id)
            ttl_ok = await self._store.set_closed_ttl(event_id)
            if not ttl_ok:
                logger.warning("set_closed_ttl failed for event_id=%s", event_id)
