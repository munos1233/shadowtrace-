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
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, TypeVar

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import (
    EventNotFoundError,
    InvalidStateTransitionError,
)
from app.core.event_bus import EventBus
from app.db import models as orm
from app.models.disposition import DispositionCommand, SetEventDispositionParams
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    FinalVerdict,
    SourceDisposition,
    WritebackStatus,
)
from app.models.security_event import SecurityEvent
from app.models.workflow import (
    MAX_REPLAN_COUNT,
    STATE_TRANSITIONS,
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
from app.services.event_service import _security_event_from_row
from app.services.writeback_close_gate import build_closed_gate_actions

logger = logging.getLogger(__name__)

_STATE_MACHINE_OPERATOR = "StateMachineService"
_REDIS_CONTEXT_UNAVAILABLE_FLAG = "redis_context_unavailable"
_STATE_TRANSITION_PROJECTION_DEGRADED_FLAG = "state_transition_projection_degraded"

ProjectionFailureKind = Literal["exception", "redis_degraded"]
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class ContextProjectionStepResult:
    """Outcome of one post-commit EventContext projection step."""

    step: str
    ok: bool
    degraded: bool
    failure_kind: ProjectionFailureKind | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ContextSyncResult:
    """Post-commit projection outcome — transition is already committed in PostgreSQL."""

    projection_ok: bool
    steps: tuple[ContextProjectionStepResult, ...]

    @property
    def has_exception_failure(self) -> bool:
        return any(step.failure_kind == "exception" for step in self.steps if step.degraded)

    @property
    def has_redis_degraded_failure(self) -> bool:
        return any(step.failure_kind == "redis_degraded" for step in self.steps if step.degraded)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _actual_disposition_from_command_payload(
    payload: dict[str, Any],
) -> SourceDisposition | None:
    """Read EVENT_STATUS_UPDATE target from nested ``operation_params`` (ISSUE-184)."""
    if not payload:
        return None
    try:
        command = DispositionCommand.model_validate(payload)
    except ValidationError:
        op_params = payload.get("operation_params")
        if isinstance(op_params, dict):
            raw = op_params.get("target_disposition")
            if raw is not None:
                try:
                    return SourceDisposition(str(raw))
                except ValueError:
                    return None
        return None
    if command.intent_kind is not DispositionIntentKind.EVENT_STATUS_UPDATE:
        return None
    params = command.operation_params
    if isinstance(params, SetEventDispositionParams):
        return params.target_disposition
    return None


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
    applicable_required_actions = await build_closed_gate_actions(
        session, event_id, current_revision
    )
    terminal_event_writeback = await _build_terminal_writeback_view(
        session, event_id, current_revision
    )
    current_closure_cycle = await _read_closure_cycle(session, event_id)

    # Derive disposition_is_mock from active config (ISSUE-227 CLOSED gate).
    from app.core.config import get_settings

    settings = get_settings()
    disposition_is_mock = "mock" in settings.disposition_mode.strip().lower()

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
        escalated=caller.escalated,
        disposition_is_mock=disposition_is_mock,
    )


async def _check_report_exists(session: AsyncSession, event_id: str) -> bool:
    row = await session.scalar(
        select(orm.Report.report_id).where(orm.Report.event_id == event_id).limit(1)
    )
    return row is not None


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

    # Parse actual disposition from denormalized command_payload (nested path).
    payload = outbox.command_payload or {}
    actual_parsed = _actual_disposition_from_command_payload(payload)
    actual_enum = actual_parsed if actual_parsed is not None else SourceDisposition.PENDING

    # Read simulated flag from the latest receipt for this writeback (ISSUE-227).
    simulated: bool | None = None
    latest_receipt = await session.scalar(
        select(orm.DispositionReceipt)
        .where(orm.DispositionReceipt.writeback_id == outbox.writeback_id)
        .order_by(orm.DispositionReceipt.sequence.desc())
        .limit(1)
    )
    if latest_receipt is not None:
        simulated = bool(latest_receipt.simulated)

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
        simulated=simulated,
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
    ``EventService.transition_status()`` delegates here without pre-validation
    so all gates are evaluated under the same row lock.
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

                # 4. Pre-status-write side effects (e.g. replan_count bump, escalated flag).
                await self._apply_pre_transition_side_effects(
                    session, row, current, target, authoritative_ctx
                )

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
        sync_result = await self._sync_context_after_transition(
            event_id, row, current, target, op, reason
        )
        if not sync_result.projection_ok:
            logger.warning(
                "transition committed with degraded projection event_id=%s "
                "%s→%s steps=%s",
                event_id,
                current.value,
                target.value,
                [step.step for step in sync_result.steps if step.degraded],
            )

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
        sync_result = await self._sync_context_after_transition(
            event_id, row, current, EventStatus.CLOSED, principal, reason_text
        )
        if not sync_result.projection_ok:
            logger.warning(
                "force_close committed with degraded projection event_id=%s steps=%s",
                event_id,
                [step.step for step in sync_result.steps if step.degraded],
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

    async def repair_transition_projection(self, event_id: str) -> ContextSyncResult:
        """Idempotently rebuild EventContext projection from authoritative PostgreSQL state.

        Does **not** replay status transitions, audit entries, or external side
        effects. Safe to retry after post-commit projection degradation.
        """
        async with self._session_factory() as session:
            row = await session.get(orm.SecurityEvent, event_id)
            if row is None:
                raise EventNotFoundError(
                    f"security_event not found: {event_id}",
                    details={"event_id": event_id},
                )

        target = EventStatus(row.status)
        history = await self._state_history_from_audit_log(event_id)
        return await self._project_context(
            event_id,
            row,
            target=target,
            history=history,
            sync_replan_count=int(row.replan_count or 0) > 0,
        )

    # ------------------------------------------------------------------ #
    # Side-effect helpers
    # ------------------------------------------------------------------ #

    async def _apply_pre_transition_side_effects(
        self,
        session: AsyncSession,
        row: orm.SecurityEvent,
        current: EventStatus,
        target: EventStatus,
        ctx: TransitionContext | None = None,
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

        # Escalation persistence (ISSUE-062): when the caller signals that
        # replan_count is exhausted via TransitionContext.escalated=True
        # and the target is CONTAINED or FAILED, write the flag to the DB
        # row so report generation and the UI can surface human-escalation.
        if (
            ctx is not None
            and ctx.escalated
            and target in (EventStatus.CONTAINED, EventStatus.FAILED)
        ):
            row.escalated = True
            logger.info(
                "escalated=true written for event=%s target=%s",
                row.event_id,
                target.value,
            )

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
    ) -> ContextSyncResult:
        """Sync EventContext after commit; never raise to callers."""
        history_entry: dict[str, Any] = {
            "from_status": current.value,
            "to_status": target.value,
            "operator": operator or _STATE_MACHINE_OPERATOR,
            "reason": reason,
            "timestamp": _utc_now().isoformat(),
        }
        history = await self._append_state_history_entry(event_id, history_entry)
        return await self._project_context(
            event_id,
            row,
            target=target,
            history=history,
            sync_replan_count=target is EventStatus.REPLANNING,
        )

    async def _append_state_history_entry(
        self,
        event_id: str,
        history_entry: dict[str, Any],
    ) -> list[dict[str, Any]]:
        current_history: list[dict[str, Any]] = []
        try:
            loaded = await self._store.get(event_id, "state_history")
            if isinstance(loaded, list):
                current_history = list(loaded)
        except Exception:  # noqa: BLE001 — best-effort read before append
            logger.warning(
                "state_history read failed during transition projection event_id=%s",
                event_id,
                exc_info=True,
            )
        return [*current_history, history_entry]

    async def _state_history_from_audit_log(self, event_id: str) -> list[dict[str, Any]]:
        if self._audit_log is None:
            return []
        rows = await self._audit_log.get_logs_by_event(event_id)
        history: list[dict[str, Any]] = []
        for row in rows:
            if row.from_status is None and row.to_status is None:
                continue
            history.append(
                {
                    "from_status": row.from_status,
                    "to_status": row.to_status,
                    "operator": row.operator,
                    "reason": row.reason,
                    "timestamp": row.created_at.isoformat() if row.created_at else None,
                }
            )
        return history

    async def _project_context(
        self,
        event_id: str,
        row: orm.SecurityEvent,
        *,
        target: EventStatus,
        history: list[dict[str, Any]],
        sync_replan_count: bool = False,
    ) -> ContextSyncResult:
        """Project EventContext fields from authoritative PostgreSQL state."""
        steps: list[ContextProjectionStepResult] = []

        summary = event_summary_from_security_event(row)
        _, summary_step = await self._run_projection_step(
            event_id,
            "event_summary",
            lambda: self._store.set(event_id, "event", summary),
        )
        steps.append(summary_step)

        _, history_step = await self._run_projection_step(
            event_id,
            "state_history",
            lambda: self._store.set(event_id, "state_history", history),
        )
        steps.append(history_step)

        replan_step = ContextProjectionStepResult(
            step="replan_count",
            ok=True,
            degraded=False,
        )
        if sync_replan_count:
            _, replan_step = await self._run_projection_step(
                event_id,
                "replan_count",
                lambda: self._store.set(event_id, "replan_count", int(row.replan_count or 0)),
            )
        steps.append(replan_step)

        if target is EventStatus.CLOSED:
            _, snapshot_step = await self._run_projection_step(
                event_id,
                "closed_snapshot",
                lambda: self._store.refresh_closed_snapshot(event_id),
            )
            steps.append(snapshot_step)

            _, ttl_step = await self._run_closed_ttl_step(event_id)
            steps.append(ttl_step)

        result = ContextSyncResult(
            projection_ok=all(step.ok for step in steps),
            steps=tuple(steps),
        )
        if result.projection_ok:
            await self._clear_projection_degradation_flags(event_id)
        else:
            await self._record_projection_degradation(event_id, target, result)
        return result

    async def _run_projection_step(
        self,
        event_id: str,
        step: str,
        action: Callable[[], Awaitable[Any]],
    ) -> tuple[Any | None, ContextProjectionStepResult]:
        try:
            outcome = await action()
        except Exception as exc:  # noqa: BLE001 — post-commit projection must not bubble
            logger.warning(
                "post-commit context projection raised event_id=%s step=%s",
                event_id,
                step,
                exc_info=True,
            )
            return None, ContextProjectionStepResult(
                step=step,
                ok=False,
                degraded=True,
                failure_kind="exception",
                error=f"{type(exc).__name__}: {exc}",
            )

        if hasattr(outcome, "redis_ok") and not outcome.redis_ok:
            return outcome, ContextProjectionStepResult(
                step=step,
                ok=False,
                degraded=True,
                failure_kind="redis_degraded",
                error="redis_unavailable",
            )

        return outcome, ContextProjectionStepResult(
            step=step,
            ok=True,
            degraded=False,
        )

    async def _run_closed_ttl_step(
        self, event_id: str
    ) -> tuple[bool | None, ContextProjectionStepResult]:
        try:
            ttl_ok = await self._store.set_closed_ttl(event_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "post-commit closed TTL projection raised event_id=%s",
                event_id,
                exc_info=True,
            )
            return None, ContextProjectionStepResult(
                step="closed_ttl",
                ok=False,
                degraded=True,
                failure_kind="exception",
                error=f"{type(exc).__name__}: {exc}",
            )

        if not ttl_ok:
            logger.warning("set_closed_ttl failed for event_id=%s", event_id)
            return ttl_ok, ContextProjectionStepResult(
                step="closed_ttl",
                ok=False,
                degraded=True,
                failure_kind="redis_degraded",
                error="redis_unavailable",
            )

        return ttl_ok, ContextProjectionStepResult(
            step="closed_ttl",
            ok=True,
            degraded=False,
        )

    async def _record_projection_degradation(
        self,
        event_id: str,
        target: EventStatus,
        result: ContextSyncResult,
    ) -> None:
        if result.projection_ok or self._degraded is None:
            return

        if result.has_redis_degraded_failure:
            try:
                await self._degraded.set_flag(
                    event_id,
                    _REDIS_CONTEXT_UNAVAILABLE_FLAG,
                    True,
                    writer="StateMachineService",
                )
            except Exception:  # noqa: BLE001 — observability must not undo commit
                logger.warning(
                    "failed to set redis_context_unavailable event_id=%s target=%s",
                    event_id,
                    target.value,
                    exc_info=True,
                )

        if result.has_exception_failure:
            failed_steps = [
                f"{step.step}:{step.error}"
                for step in result.steps
                if step.failure_kind == "exception" and step.error
            ]
            detail = ",".join(failed_steps)[:240] if failed_steps else "unknown"
            try:
                await self._degraded.set_flag(
                    event_id,
                    _STATE_TRANSITION_PROJECTION_DEGRADED_FLAG,
                    detail,
                    writer="StateMachineService",
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "failed to set state_transition_projection_degraded "
                    "event_id=%s target=%s detail=%s",
                    event_id,
                    target.value,
                    detail,
                    exc_info=True,
                )

    async def _clear_projection_degradation_flags(self, event_id: str) -> None:
        if self._degraded is None:
            return
        try:
            await self._degraded.set_flag(
                event_id,
                _STATE_TRANSITION_PROJECTION_DEGRADED_FLAG,
                False,
                writer="StateMachineService",
            )
        except Exception:  # noqa: BLE001
            logger.debug(
                "failed to clear state_transition_projection_degraded event_id=%s",
                event_id,
                exc_info=True,
            )
