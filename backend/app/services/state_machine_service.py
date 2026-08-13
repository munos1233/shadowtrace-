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

import asyncio
import logging
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.auth import ROLE_ADMIN, AuthorizationError, Principal
from app.core.errors import (
    EventNotFoundError,
    InvalidStateTransitionError,
)
from app.core.event_bus import EventBus
from app.core.metrics import (
    record_force_close,
    record_state_projection_failure,
    record_state_projection_repair,
)
from app.db import models as orm
from app.models.disposition import DispositionCommand, SetEventDispositionParams
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ConfirmationEvidence,
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
from app.services.side_effect_convergence import (
    build_side_effect_convergence_summary,
    reconcile_stale_executions_before_close,
)
from app.services.writeback_close_gate import build_closed_gate_actions

logger = logging.getLogger(__name__)

_STATE_MACHINE_OPERATOR = "StateMachineService"
STATE_TRANSITION_PROJECTION_DEGRADED_FLAG = "state_transition_projection_degraded"
_PROJECTION_REPAIR_MAX_ATTEMPTS = 3
_PROJECTION_REPAIR_BACKOFF_SECONDS = 0.05
_EVENT_STATUS_VALUES = frozenset(status.value for status in EventStatus)

ProjectionFailureMode = Literal["raised", "returned_degraded"]


@dataclass(frozen=True, slots=True)
class ProjectionFailure:
    """One isolated failure after the authoritative transition committed."""

    step: str
    mode: ProjectionFailureMode
    error_type: str | None = None


@dataclass(frozen=True, slots=True)
class PostCommitProjectionOutcome:
    """Unambiguous result for a context projection or repair attempt."""

    committed: bool
    projection_id: str
    failures: tuple[ProjectionFailure, ...] = ()
    attempts: int = 1

    @property
    def degraded(self) -> bool:
        return bool(self.failures)


@dataclass(frozen=True, slots=True)
class _ProjectionRepairSource:
    row: orm.SecurityEvent
    current: EventStatus
    target: EventStatus
    operator: str | None
    reason: str | None
    projection_id: str
    history: tuple[dict[str, Any], ...] | None


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
            a.tool_name == TERMINAL_DISPOSITION_TOOL for a in response_actions
        )
        has_entity_side_effect_actions = any(
            a.tool_name != TERMINAL_DISPOSITION_TOOL for a in response_actions
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
    side_effect_convergence = await build_side_effect_convergence_summary(
        session,
        event_id,
        current_revision=current_revision,
        disposition_policy=DispositionPolicy(row.disposition_policy),
    )

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
        side_effect_convergence=side_effect_convergence,
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
            orm.Action.tool_name == TERMINAL_DISPOSITION_TOOL,
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
    confirmation_evidence: ConfirmationEvidence | None = None
    latest_receipt = await session.scalar(
        select(orm.DispositionReceipt)
        .where(orm.DispositionReceipt.writeback_id == outbox.writeback_id)
        .order_by(orm.DispositionReceipt.sequence.desc())
        .limit(1)
    )
    if latest_receipt is not None:
        simulated = bool(latest_receipt.simulated)
        if latest_receipt.confirmation_evidence:
            try:
                confirmation_evidence = ConfirmationEvidence(
                    latest_receipt.confirmation_evidence
                )
            except ValueError:
                confirmation_evidence = None

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
        confirmation_evidence=confirmation_evidence,
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
        self._projection_locks: dict[str, asyncio.Lock] = {}

    def _projection_lock(self, event_id: str) -> asyncio.Lock:
        lock = self._projection_locks.get(event_id)
        if lock is None:
            lock = asyncio.Lock()
            self._projection_locks[event_id] = lock
        return lock

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
        projection_id = ""

        if target is EventStatus.CLOSED:
            await reconcile_stale_executions_before_close(
                self._session_factory,
                event_id,
            )

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
                    audit_id = await self._audit_log.log_transition_in_session(
                        session,
                        event_id,
                        from_status=from_status,
                        to_status=target.value,
                        operator=op,
                        reason=reason,
                    )
                    projection_id = f"audit:{audit_id}"

                await session.flush()
                await session.refresh(row)
                if not projection_id:
                    projection_id = f"row-version:{int(row.row_version or 1)}"
                result = _security_event_from_row(row)

        # --- post-commit side effects (best-effort, never roll back) ---

        # 8. Sync EventContext (event summary + state_history).
        projection = await self._sync_context_after_transition(
            event_id,
            row,
            current,
            target,
            op,
            reason,
            projection_id=projection_id,
        )
        if projection.degraded:
            result = await self._reload_committed_result(event_id, result, projection)

        # 9. Publish state_change via EventBus (best-effort; never imply rollback).
        await self._publish_state_change(
            event_id,
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
        principal: Principal,
        reason: str,
    ) -> SecurityEvent:
        """Admin-only forced local close with ``external_unsynced=true``.

        Bypasses the normal CLOSED writeback gate.  Requires ``ROLE_ADMIN`` on
        *principal* (fail-closed at the service layer).  The audit operator is
        normalised to ``principal:{subject}``.
        """
        if not principal.has_any_role([ROLE_ADMIN]):
            record_force_close(result="denied")
            raise AuthorizationError([ROLE_ADMIN])

        operator = principal.subject
        if not operator.startswith("principal:"):
            operator = f"principal:{operator}"
        projection_id = ""

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
                    f"force_close subject={principal.subject}: {reason}"
                    if reason
                    else f"force_close subject={principal.subject}"
                )

                if self._audit_log is not None:
                    audit_id = await self._audit_log.log_transition_in_session(
                        session,
                        event_id,
                        from_status=from_status,
                        to_status=EventStatus.CLOSED.value,
                        operator=operator,
                        reason=reason_text,
                    )
                    projection_id = f"audit:{audit_id}"

                await session.flush()
                await session.refresh(row)
                if not projection_id:
                    projection_id = f"row-version:{int(row.row_version or 1)}"
                result = _security_event_from_row(row)

        # --- post-commit ---

        # Sync EventContext (state_history + event summary) so Redis consumers
        # see the force-close consistently with transition().  This also handles
        # refresh_closed_snapshot + set_closed_ttl for the CLOSED target — no
        # need to duplicate those calls here.
        projection = await self._sync_context_after_transition(
            event_id,
            row,
            current,
            EventStatus.CLOSED,
            operator,
            reason_text,
            projection_id=projection_id,
        )
        if projection.degraded:
            result = await self._reload_committed_result(event_id, result, projection)

        await self._publish_state_change(
            event_id,
            {
                "from_status": current.value,
                "to_status": EventStatus.CLOSED.value,
                "operator": operator,
                "external_unsynced": True,
            },
        )

        record_force_close(result="success")
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

    async def repair_post_commit_projection(
        self,
        event_id: str,
        *,
        max_attempts: int = _PROJECTION_REPAIR_MAX_ATTEMPTS,
        backoff_seconds: float = _PROJECTION_REPAIR_BACKOFF_SECONDS,
    ) -> PostCommitProjectionOutcome:
        """Rebuild only the committed event's context projection.

        The source of truth is the current PostgreSQL row plus its append-only
        transition audit.  This method never validates or writes a status,
        creates an audit entry, publishes an event, or reruns transition side
        effects.  The exact audit-derived history is replaced atomically by the
        context store, so repeated repair attempts are bounded and idempotent.
        """
        async with self._projection_lock(event_id):
            return await self._repair_post_commit_projection_locked(
                event_id,
                max_attempts=max_attempts,
                backoff_seconds=backoff_seconds,
            )

    async def _repair_post_commit_projection_locked(
        self,
        event_id: str,
        *,
        max_attempts: int,
        backoff_seconds: float,
    ) -> PostCommitProjectionOutcome:
        attempts = max(1, min(int(max_attempts), _PROJECTION_REPAIR_MAX_ATTEMPTS))
        source = await self._load_projection_repair_source(event_id)
        last: PostCommitProjectionOutcome | None = None

        for attempt in range(1, attempts + 1):
            last = await self._sync_context_after_transition_locked(
                event_id,
                source.row,
                source.current,
                source.target,
                source.operator,
                source.reason,
                projection_id=source.projection_id,
                repair=True,
                history_override=source.history,
            )
            last = replace(last, attempts=attempt)
            if not last.degraded:
                clear_failure = await self._clear_projection_degraded(
                    event_id,
                    expected_projection_id=source.projection_id,
                )
                if clear_failure is None:
                    record_state_projection_repair(outcome="success")
                    return last
                if clear_failure.step == "degraded_flag_stale":
                    # Newer degradation replaced our marker; projection rebuild itself OK.
                    record_state_projection_repair(outcome="success")
                    return replace(last, failures=())
                last = replace(last, failures=last.failures + (clear_failure,))
                record_state_projection_repair(outcome="marker_clear_failed")
            if attempt < attempts and backoff_seconds > 0:
                await asyncio.sleep(backoff_seconds * (2 ** (attempt - 1)))

        assert last is not None
        record_state_projection_repair(outcome="exhausted")
        return last

    async def list_projection_degraded_event_ids(self, *, limit: int = 20) -> list[str]:
        """Return event ids that still carry the ISSUE-285 degraded marker."""
        pattern = f"%{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=%"
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(orm.SecurityEvent.event_id)
                .where(cast(orm.SecurityEvent.degraded_flags, String).like(pattern))
                .order_by(orm.SecurityEvent.updated_at.asc().nulls_last())
                .limit(max(1, min(int(limit), 100)))
            )
            return [str(event_id) for event_id in rows.all()]

    async def repair_degraded_projections(self, *, limit: int = 20) -> dict[str, int]:
        """Production entry: scan degraded markers and run bounded repairs."""
        event_ids = await self.list_projection_degraded_event_ids(limit=limit)
        repaired = 0
        exhausted = 0
        for event_id in event_ids:
            outcome = await self.repair_post_commit_projection(
                event_id,
                backoff_seconds=_PROJECTION_REPAIR_BACKOFF_SECONDS,
            )
            if outcome.degraded:
                exhausted += 1
            else:
                repaired += 1
        return {
            "scanned": len(event_ids),
            "repaired": repaired,
            "exhausted": exhausted,
        }

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

    async def _publish_state_change(
        self,
        event_id: str,
        payload: dict[str, Any],
    ) -> None:
        if self._bus is None:
            return
        try:
            await self._bus.publish_event(event_id, "state_change", payload)
        except Exception:  # noqa: BLE001 - committed transition must still return
            logger.exception(
                "state_change publish failed after committed transition event_id=%s",
                event_id,
            )

    async def _sync_context_after_transition(
        self,
        event_id: str,
        row: orm.SecurityEvent,
        current: EventStatus,
        target: EventStatus,
        operator: str | None,
        reason: str | None,
        *,
        projection_id: str,
        repair: bool = False,
        history_override: tuple[dict[str, Any], ...] | None = None,
    ) -> PostCommitProjectionOutcome:
        async with self._projection_lock(event_id):
            return await self._sync_context_after_transition_locked(
                event_id,
                row,
                current,
                target,
                operator,
                reason,
                projection_id=projection_id,
                repair=repair,
                history_override=history_override,
            )

    async def _sync_context_after_transition_locked(
        self,
        event_id: str,
        row: orm.SecurityEvent,
        current: EventStatus,
        target: EventStatus,
        operator: str | None,
        reason: str | None,
        *,
        projection_id: str,
        repair: bool = False,
        history_override: tuple[dict[str, Any], ...] | None = None,
    ) -> PostCommitProjectionOutcome:
        """Project a committed transition without ever changing its outcome.

        Each store await is isolated so a direct exception is observably
        different from a store result that reports degraded Redis.  Later
        projection steps still run, and no exception escapes as a misleading
        rollback-shaped API/graph failure.
        """
        failures: list[ProjectionFailure] = []

        def fail(step: str, mode: ProjectionFailureMode, exc: BaseException | None = None) -> None:
            failure = ProjectionFailure(
                step=step,
                mode=mode,
                error_type=type(exc).__name__ if exc is not None else None,
            )
            failures.append(failure)
            record_state_projection_failure(step=step, mode=mode)
            logger.warning(
                "Committed state projection degraded event_id=%s projection_id=%s "
                "step=%s mode=%s transition=%s→%s",
                event_id,
                projection_id,
                step,
                mode,
                current.value,
                target.value,
                exc_info=(type(exc), exc, exc.__traceback__) if exc is not None else None,
            )

        async def project_set(step: str, key: str, value: Any) -> None:
            try:
                result = await self._store.set(event_id, key, value)
            except Exception as exc:  # noqa: BLE001 - post-commit isolation boundary
                fail(step, "raised", exc)
                return
            if not result.redis_ok:
                fail(step, "returned_degraded")

        # 1. Current summary. Journal persistence and Redis degradation are
        # intentionally reported separately by EventContextStore's SetResult.
        try:
            summary = event_summary_from_security_event(row)
        except Exception as exc:  # noqa: BLE001 - malformed committed row is observable
            fail("summary", "raised", exc)
        else:
            await project_set("summary", "event", summary)

        # 2. Transition history. Normal writes append once using a stable audit
        # identity. Repair replaces it from the authoritative audit log, making
        # repeated repair attempts semantically idempotent.
        if repair:
            if history_override is None:
                fail("history", "raised", RuntimeError("transition audit unavailable"))
            else:
                await project_set("history", "state_history", list(history_override))
        else:
            try:
                current_history = await self._store.get(event_id, "state_history")
                if not isinstance(current_history, list):
                    current_history = []
            except Exception as exc:  # noqa: BLE001 - never overwrite unknown history
                fail("history", "raised", exc)
            else:
                already_projected = any(
                    isinstance(item, dict) and item.get("transition_id") == projection_id
                    for item in current_history
                )
                if not already_projected:
                    history_entry: dict[str, Any] = {
                        "transition_id": projection_id,
                        "from_status": current.value,
                        "to_status": target.value,
                        "operator": operator or _STATE_MACHINE_OPERATOR,
                        "reason": reason,
                        "timestamp": _utc_now().isoformat(),
                    }
                    await project_set(
                        "history",
                        "state_history",
                        list(current_history) + [history_entry],
                    )

        # 3. REPLANNING's journal mirror is also a projection, not a second
        # transition. Only rewrite on REPLANNING (or repair of that target).
        if target is EventStatus.REPLANNING:
            await project_set("replan_count", "replan_count", int(row.replan_count or 0))

        # 4. CLOSED snapshot and TTL are isolated independently. Snapshot
        # refresh is a deterministic rebuild from PostgreSQL/journal data.
        if target is EventStatus.CLOSED:
            try:
                await self._store.refresh_closed_snapshot(event_id)
            except Exception as exc:  # noqa: BLE001 - committed transition must be returned
                fail("snapshot", "raised", exc)
            try:
                ttl_ok = await self._store.set_closed_ttl(event_id)
            except Exception as exc:  # noqa: BLE001 - fault-injection stores may raise
                fail("closed_ttl", "raised", exc)
            else:
                if not ttl_ok:
                    fail("closed_ttl", "returned_degraded")
            await self._persist_side_effect_convergence_on_close(event_id, row, fail)

        outcome = PostCommitProjectionOutcome(
            committed=True,
            projection_id=projection_id,
            failures=tuple(failures),
        )
        if outcome.degraded:
            await self._mark_projection_degraded(event_id, outcome)
        return outcome

    async def _persist_side_effect_convergence_on_close(
        self,
        event_id: str,
        row: orm.SecurityEvent,
        fail: Any,
    ) -> None:
        """Persist side-effect convergence summary and background flags (ISSUE-302)."""
        try:
            async with self._session_factory() as session:
                current_revision = await session.scalar(
                    select(func.max(orm.Action.plan_revision)).where(
                        orm.Action.event_id == event_id
                    )
                )
                summary = await build_side_effect_convergence_summary(
                    session,
                    event_id,
                    current_revision=current_revision,
                    disposition_policy=DispositionPolicy(row.disposition_policy),
                )
        except Exception as exc:  # noqa: BLE001
            fail("side_effect_convergence", "returned_degraded", exc)
            return

        try:
            await self._store.set(
                event_id,
                "side_effect_convergence",
                summary.model_dump(mode="json"),
            )
        except Exception as exc:  # noqa: BLE001
            fail("side_effect_convergence", "returned_degraded", exc)

        if summary.background_side_effects_pending and self._degraded is not None:
            try:
                await self._degraded.set_flag(
                    event_id,
                    "background_side_effects_pending",
                    {
                        "count": summary.background_outstanding_count,
                        "action_ids": [
                            view.action_id
                            for view in summary.outstanding_actions
                            if view.scope.value == "background_detached"
                        ],
                    },
                    writer="StateMachineService",
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "failed to persist background_side_effects_pending event_id=%s",
                    event_id,
                    exc_info=True,
                )

    async def _mark_projection_degraded(
        self,
        event_id: str,
        outcome: PostCommitProjectionOutcome,
    ) -> None:
        value = _projection_degraded_value(outcome.failures, outcome.projection_id)
        logger.error(
            "transition committed with degraded projection event_id=%s projection_id=%s "
            "failures=%s",
            event_id,
            outcome.projection_id,
            value,
        )
        if self._degraded is None:
            return
        try:
            await self._degraded.set_flag(
                event_id,
                STATE_TRANSITION_PROJECTION_DEGRADED_FLAG,
                value,
                writer="StateMachineService",
            )
        except Exception:  # noqa: BLE001 - observability cannot change committed semantics
            logger.exception(
                "failed to persist state projection degraded flag event_id=%s",
                event_id,
            )

        if any(failure.mode == "returned_degraded" for failure in outcome.failures):
            try:
                await self._degraded.set_flag(
                    event_id,
                    "redis_context_unavailable",
                    True,
                    writer="StateMachineService",
                )
            except Exception:  # noqa: BLE001 - primary marker was already attempted
                logger.exception(
                    "failed to persist Redis degraded flag after projection event_id=%s",
                    event_id,
                )

    async def _clear_projection_degraded(
        self,
        event_id: str,
        *,
        expected_projection_id: str,
    ) -> ProjectionFailure | None:
        """Clear only this repair generation's marker; never touch foreign Redis flags."""
        if self._degraded is None:
            return None
        try:
            current = await self._degraded.get_flag_value(
                event_id,
                STATE_TRANSITION_PROJECTION_DEGRADED_FLAG,
            )
        except Exception as exc:  # noqa: BLE001 - repair result must remain explicit
            record_state_projection_failure(step="degraded_flag", mode="raised")
            logger.exception(
                "failed to read projection degraded flag event_id=%s",
                event_id,
            )
            return ProjectionFailure(
                step="degraded_flag",
                mode="raised",
                error_type=type(exc).__name__,
            )
        if current is None:
            return None
        token = f"proj={expected_projection_id}"
        if token not in current:
            return ProjectionFailure(
                step="degraded_flag_stale",
                mode="raised",
                error_type="StaleProjectionMarker",
            )
        try:
            await self._degraded.set_flag(
                event_id,
                STATE_TRANSITION_PROJECTION_DEGRADED_FLAG,
                False,
                writer="StateMachineService",
            )
        except Exception as exc:  # noqa: BLE001 - repair result must remain explicit
            record_state_projection_failure(step="degraded_flag", mode="raised")
            logger.exception(
                "failed to clear projection degraded flag event_id=%s",
                event_id,
            )
            return ProjectionFailure(
                step="degraded_flag",
                mode="raised",
                error_type=type(exc).__name__,
            )
        return None

    async def _reload_committed_result(
        self,
        event_id: str,
        result: SecurityEvent,
        outcome: PostCommitProjectionOutcome,
    ) -> SecurityEvent:
        """Return committed DB state with the durable degraded marker when possible."""
        try:
            async with self._session_factory() as session:
                row = await session.get(orm.SecurityEvent, event_id)
                if row is not None:
                    return _security_event_from_row(row)
        except Exception:  # noqa: BLE001 - never replace committed semantics with read failure
            logger.exception("failed to reload committed transition event_id=%s", event_id)

        marker = (
            f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}="
            f"{_projection_degraded_value(outcome.failures, outcome.projection_id)}"
        )
        flags = [
            flag
            for flag in result.degraded_flags
            if not flag.startswith(f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=")
        ]
        return result.model_copy(update={"degraded_flags": flags + [marker]})

    async def _load_projection_repair_source(
        self,
        event_id: str,
    ) -> _ProjectionRepairSource:
        async with self._session_factory() as session:
            row = await session.get(orm.SecurityEvent, event_id)
            if row is None:
                raise EventNotFoundError(
                    f"security_event not found: {event_id}",
                    details={"event_id": event_id},
                )
            audits = list(
                (
                    await session.scalars(
                        select(orm.EventAuditLog)
                        .where(orm.EventAuditLog.event_id == event_id)
                        .order_by(
                            orm.EventAuditLog.created_at.asc(),
                            orm.EventAuditLog.id.asc(),
                        )
                    )
                ).all()
            )

        transition_audits = [
            audit
            for audit in audits
            if audit.from_status in _EVENT_STATUS_VALUES
            and audit.to_status in _EVENT_STATUS_VALUES
            and audit.from_status != audit.to_status
        ]
        history = tuple(
            {
                "transition_id": f"audit:{audit.id}",
                "from_status": audit.from_status,
                "to_status": audit.to_status,
                "operator": audit.operator or _STATE_MACHINE_OPERATOR,
                "reason": audit.reason,
                "timestamp": (
                    audit.created_at.isoformat() if audit.created_at else _utc_now().isoformat()
                ),
            }
            for audit in transition_audits
        )
        latest = transition_audits[-1] if transition_audits else None
        target = EventStatus(row.status)
        if latest is None or latest.from_status is None:
            return _ProjectionRepairSource(
                row=row,
                current=target,
                target=target,
                operator=None,
                reason=None,
                projection_id=f"row-version:{int(row.row_version or 1)}",
                history=None,
            )
        return _ProjectionRepairSource(
            row=row,
            current=EventStatus(latest.from_status),
            target=target,
            operator=latest.operator,
            reason=latest.reason,
            projection_id=f"audit:{latest.id}",
            history=history,
        )


def _projection_degraded_value(
    failures: tuple[ProjectionFailure, ...],
    projection_id: str,
) -> str:
    """Bounded marker including the projection generation token for safe clear."""
    parts = sorted({f"{failure.step}:{failure.mode}" for failure in failures})
    base = "|".join(parts) or "unknown"
    token = f"proj={projection_id}"
    # Keep room for the generation token used by repair clear fencing.
    max_base = max(1, 512 - len(token) - 1)
    return f"{base[:max_base]}|{token}"[:512]
