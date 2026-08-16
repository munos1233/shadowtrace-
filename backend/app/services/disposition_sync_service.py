"""Reliable disposition outbox delivery (ISSUE-059)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters._util import sanitize_disposition_receipt, sanitize_raw_result
from app.adapters.disposition.base import BaseDispositionAdapter
from app.adapters.disposition.error_classification import (
    DispositionDeliveryErrorKind,
    classify_disposition_delivery_error,
    is_deterministic_adapter_rejection_code,
)
from app.adapters.registry import DispositionAdapterRegistry
from app.core.config import get_settings
from app.core.errors import (
    DependencyUnavailableError,
    EventNotFoundError,
    GuardrailViolationError,
    ValidationError,
    WritebackConflictError,
    WritebackUnsupportedError,
)
from app.core.event_bus import EventBus
from app.core.guardrails import OutboundDispositionGuard
from app.core.metrics import (
    observe_writeback_queue_age,
    record_action_unknown,
    record_writeback,
    record_writeback_dead_letter,
    record_writeback_retry,
)
from app.core.telemetry import disposition_span
from app.db import models as orm
from app.models.disposition import (
    DispositionCommand,
    DispositionOutboxRecord,
    DispositionReceipt,
    EntityEffectCompletion,
    parse_entity_effect_target,
)
from app.models.enums import (
    ActionStatus,
    ConfirmationEvidence,
    DispositionIntentKind,
    ExecutionJobStatus,
    ExecutionOwner,
    ExecutionSubstate,
    OutboxDeliveryStatus,
    TargetExecutionStatus,
    WritebackStatus,
)
from app.models.execution import ActionExecutionJob, TargetExecutionResult
from app.models.ids import new_writeback_id
from app.models.workflow import (
    delivery_status_eligible_for_operator_retry_pause,
    is_operator_retry_terminal_success,
    operator_retry_writeback_status_blocked,
    validate_job_status_transition,
    validate_outbox_delivery_transition,
    validate_writeback_status_transition,
)
from app.services.context_service import (
    EventContextStore,
    append_context_journal_in_session,
    append_list_context_journal_in_session,
)
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_guard_context import resolve_approved_action_ids
from app.services.execution_job_persistence import (
    job_from_row,
    load_target_results_for_job,
    sync_target_results_in_tx,
)
from app.services.writeback_side_effect_fence import (
    WRITEBACK_FENCE_BLOCKED_ERROR_CODE,
    assert_writeback_side_effects_allowed,
)

logger = logging.getLogger(__name__)

_TERMINAL_JOB_STATUSES = frozenset(
    {
        ExecutionJobStatus.PARTIAL_SUCCESS,
        ExecutionJobStatus.SUCCESS,
        ExecutionJobStatus.FAILED,
        ExecutionJobStatus.TIMED_OUT,
        ExecutionJobStatus.CANCELLED,
    }
)

ResumeInvestigationHook = Callable[[str], Awaitable[None]]
_DEFAULT_LEASE_SECONDS = 30
_ERROR_DETAIL_MAX_LEN = 500
OUTBOX_SUPERSEDED_ERROR_CODE = "superseded_by_new_head"
_OPERATOR_RETRY_REPLAY_PREFIX = "operator_retry:replay"
_OPERATOR_RETRY_OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class _PausedLookupKind(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class _PausedLookupClaim:
    outbox_id: str
    token: str
    event_id: str
    action_id: str
    disposition_id: str
    writeback_id: str
    idempotency_key: str
    command_payload_sha256: str
    command: DispositionCommand
    adapter: BaseDispositionAdapter
    provider_job_id: str | None


@dataclass(frozen=True)
class _PausedLookupOutcome:
    kind: _PausedLookupKind
    receipt: DispositionReceipt | None = None
    error_code: str | None = None
    detail: str | None = None


class _OperatorRetryAction(StrEnum):
    RE_ENQUEUE = "re_enqueue"
    RECONCILE_TERMINAL = "reconcile_terminal"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class _OperatorRetryDecision:
    action: _OperatorRetryAction
    reason: str = ""
    target_status: WritebackStatus | None = None
    receipt: DispositionReceipt | None = None
    lookup_never_accepted: bool = False
    adapter_allows_safe_retry: bool = False


class _NullResumeHook:
    async def __call__(self, event_id: str) -> None:
        return None


def _new_outbox_id() -> str:
    return f"obx-{secrets.token_hex(4)}"


def _payload_sha256(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _mirror_writeback_status_to_action(action: orm.Action | None, status: str) -> None:
    """Denormalize outbox writeback status onto the bound action when allowed.

    ``Action`` forbids ``writeback_status`` when ``writeback_applicable`` is
    false (ISSUE-195). Disposition sync still updates outbox/receipt state for
    entity-action submits bound to non-applicable rows; only the action mirror
    is skipped.
    """
    if action is not None and action.writeback_applicable:
        action.writeback_status = status


# ISSUE-235 / ISSUE-290 / ISSUE-307: intents that must re-check action approval at deliver time.
_DELIVERY_APPROVAL_RECHECK_INTENTS: frozenset[DispositionIntentKind] = frozenset(
    {
        DispositionIntentKind.ENTITY_ACTION_SUBMIT,
        DispositionIntentKind.EXECUTION_RESULT_RECORD,
        DispositionIntentKind.EVENT_STATUS_UPDATE,
        DispositionIntentKind.COMPENSATION_RECORD,
    }
)


def _action_still_approved_for_delivery(action: orm.Action) -> bool:
    """True when the action row is still in the effective approved set (ISSUE-235).

    Includes post-execution SUCCESS for EXECUTION_RESULT_RECORD and COMPENSATION_RECORD.
    """
    return (
        action.status
        in {
            ActionStatus.APPROVED.value,
            ActionStatus.EXECUTING.value,
            ActionStatus.SUCCESS.value,
            ActionStatus.PARTIAL_SUCCESS.value,
        }
        and action.superseded_by_revision is None
    )


class DispositionSyncService:
    """Owns disposition_commands/receipts/writeback_summary WorkingMemory fields."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        context_store: EventContextStore,
        adapter_registry: DispositionAdapterRegistry,
        command_factory: DispositionCommandFactory | None = None,
        outbound_guard: OutboundDispositionGuard | None = None,
        event_bus: EventBus | None = None,
        resume_investigation: ResumeInvestigationHook | None = None,
        manual_resolution: Any | None = None,
        worker_id: str = "outbox-worker-1",
    ) -> None:
        self._session_factory = session_factory
        self._context_store = context_store
        self._adapters = adapter_registry
        self._factory = command_factory or DispositionCommandFactory()
        self._guard = outbound_guard or OutboundDispositionGuard()
        self._bus = event_bus
        self._resume = resume_investigation or _NullResumeHook()
        self._manual_resolution = manual_resolution
        self._worker_id = worker_id

    def _adapter_label(self, outbox: orm.DispositionOutbox) -> str:
        try:
            return self._resolve_adapter(outbox).name
        except Exception:
            return "unknown"

    async def enqueue_command(
        self,
        session: AsyncSession,
        *,
        command: DispositionCommand,
        event_id: str,
        source_record_id: str,
        logical_slot: str = "default",
        guard_context: dict[str, Any] | None = None,
    ) -> DispositionOutboxRecord:
        ctx = {
            "event_id": event_id,
            "source_locator": command.source_locator,
            **(guard_context or {}),
        }
        if "approved_action_ids" not in ctx:
            ctx["approved_action_ids"] = await resolve_approved_action_ids(
                session,
                event_id=event_id,
                plan_revision=command.closure_cycle,
            )
        await self._guard.validate(command, ctx)

        event_row = await session.get(
            orm.SecurityEvent,
            event_id,
            with_for_update=True,
        )
        if event_row is None:
            raise ValidationError(
                "security_event not found for outbox enqueue",
                details={"event_id": event_id},
            )

        source_row = await session.get(
            orm.SourceObject,
            source_record_id,
            with_for_update=True,
        )
        if source_row is None:
            raise ValidationError(
                "source_record not found for outbox enqueue",
                details={"source_record_id": source_record_id},
            )
        source_row.next_outbox_sequence = int(source_row.next_outbox_sequence or 0) + 1
        source_sequence = int(source_row.next_outbox_sequence)
        await session.flush()

        # ISSUE-219: supersede the existing active EVENT_STATUS_UPDATE head for
        # the same (event_id, closure_cycle, logical_slot) inside this same
        # transaction, before inserting the new head.  FOR UPDATE serializes
        # concurrent prior-head reads; the partial unique index
        # (superseded_by_disposition_id IS NULL) remains the final invariant,
        # so a racing loser surfaces as an IntegrityError for the caller to
        # handle rather than a silent second active head.  Only heads of the
        # same closure_cycle are touched — history heads from earlier cycles
        # are never superseded.
        prior_head: orm.DispositionOutbox | None = None
        if command.intent_kind is DispositionIntentKind.EVENT_STATUS_UPDATE:
            prior_head = await session.scalar(
                select(orm.DispositionOutbox)
                .where(
                    orm.DispositionOutbox.event_id == event_id,
                    orm.DispositionOutbox.closure_cycle == command.closure_cycle,
                    orm.DispositionOutbox.intent_kind == command.intent_kind.value,
                    orm.DispositionOutbox.logical_slot == logical_slot,
                    orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                )
                .with_for_update()
                .limit(1)
            )
            if prior_head is not None:
                tentative_payload = command.model_dump(mode="json")
                tentative_hash = _payload_sha256(tentative_payload)
                if (
                    prior_head.idempotency_key == command.idempotency_key
                    and prior_head.command_payload_sha256 == tentative_hash
                ):
                    return DispositionOutboxRecord.model_validate(
                        {
                            "outbox_id": prior_head.outbox_id,
                            "writeback_id": prior_head.writeback_id,
                            "disposition_id": prior_head.disposition_id,
                            "action_id": prior_head.action_id,
                            "event_id": prior_head.event_id,
                            "closure_cycle": prior_head.closure_cycle,
                            "source_record_id": prior_head.source_record_id,
                            "source_locator_hash": prior_head.source_locator_hash,
                            "source_sequence": prior_head.source_sequence,
                            "intent_kind": prior_head.intent_kind,
                            "logical_slot": prior_head.logical_slot,
                            "supersedes_disposition_id": prior_head.supersedes_disposition_id,
                            "superseded_by_disposition_id": (
                                prior_head.superseded_by_disposition_id
                            ),
                            "idempotency_key": prior_head.idempotency_key,
                            "command_payload": prior_head.command_payload,
                            "command_payload_sha256": prior_head.command_payload_sha256,
                            "delivery_status": prior_head.delivery_status,
                        }
                    )
                # Propagate lineage onto the wire payload so the adapter / Mock
                # XDR can honor its supersede contract (old head deactivated).
                command = command.model_copy(
                    update={"supersedes_disposition_id": prior_head.disposition_id}
                )

        payload = command.model_dump(mode="json")
        outbox = orm.DispositionOutbox(
            outbox_id=_new_outbox_id(),
            writeback_id=new_writeback_id(),
            disposition_id=command.disposition_id,
            action_id=command.action_id,
            event_id=event_id,
            closure_cycle=command.closure_cycle,
            source_record_id=source_record_id,
            source_locator_hash=self._factory.locator_hash(command.source_locator),
            source_sequence=source_sequence,
            intent_kind=command.intent_kind.value,
            logical_slot=logical_slot,
            supersedes_disposition_id=command.supersedes_disposition_id,
            idempotency_key=command.idempotency_key,
            command_payload=payload,
            command_payload_sha256=_payload_sha256(payload),
            delivery_status=OutboxDeliveryStatus.READY.value,
        )
        if prior_head is not None:
            # Atomic lineage + non-deliverable terminal state for the old head
            # (ISSUE-273): superseded rows must never be claimable or egressed.
            self._finalize_superseded_head(
                prior_head,
                superseded_by_disposition_id=command.disposition_id,
                now=datetime.now(UTC),
            )
        session.add(outbox)
        await session.flush()
        await append_list_context_journal_in_session(
            session,
            event_id,
            "disposition_commands",
            payload,
        )
        return DispositionOutboxRecord.model_validate(
            {
                "outbox_id": outbox.outbox_id,
                "writeback_id": outbox.writeback_id,
                "disposition_id": outbox.disposition_id,
                "action_id": outbox.action_id,
                "event_id": outbox.event_id,
                "closure_cycle": outbox.closure_cycle,
                "source_record_id": outbox.source_record_id,
                "source_locator_hash": outbox.source_locator_hash,
                "source_sequence": outbox.source_sequence,
                "intent_kind": outbox.intent_kind,
                "logical_slot": outbox.logical_slot,
                "supersedes_disposition_id": outbox.supersedes_disposition_id,
                "superseded_by_disposition_id": outbox.superseded_by_disposition_id,
                "idempotency_key": outbox.idempotency_key,
                "command_payload": outbox.command_payload,
                "command_payload_sha256": outbox.command_payload_sha256,
                "delivery_status": outbox.delivery_status,
            }
        )

    async def retry_writeback(
        self,
        writeback_id: str,
        *,
        operator: str,
        operation_id: str | None = None,
        reason: str | None = None,
    ) -> WritebackStatus:
        result: WritebackStatus
        sync_event_id: str | None = None
        blocked_error: WritebackConflictError | None = None
        if operation_id is not None and not _OPERATOR_RETRY_OPERATION_ID_RE.fullmatch(
            operation_id,
        ):
            raise ValidationError(
                "operation_id must be 1-128 chars of [A-Za-z0-9._:-]",
                details={"operation_id": operation_id},
            )
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.writeback_id == writeback_id)
                    .with_for_update()
                )
                if outbox is None:
                    raise EventNotFoundError(
                        f"writeback not found: {writeback_id}",
                        details={"writeback_id": writeback_id},
                    )

                delivery = OutboxDeliveryStatus(outbox.delivery_status)
                latest = (
                    WritebackStatus(outbox.latest_writeback_status)
                    if outbox.latest_writeback_status
                    else None
                )

                # CONFIRMED is forever denied — check before operation replay.
                if operator_retry_writeback_status_blocked(latest):
                    raise WritebackConflictError(
                        "CONFIRMED writeback cannot be retried",
                        details={
                            "writeback_id": writeback_id,
                            "status": latest.value if latest else None,
                        },
                    )

                if outbox.superseded_by_disposition_id is not None:
                    raise WritebackConflictError(
                        "superseded outbox head cannot be retried",
                        details={
                            "writeback_id": writeback_id,
                            "superseded_by_disposition_id": (outbox.superseded_by_disposition_id),
                        },
                    )

                if operation_id is not None:
                    replay_status = await self._find_operator_retry_replay(
                        session,
                        event_id=outbox.event_id,
                        writeback_id=writeback_id,
                        operation_id=operation_id,
                    )
                    if replay_status is not None:
                        return replay_status

                if latest is WritebackStatus.UNKNOWN and delivery is OutboxDeliveryStatus.DELIVERED:
                    raise WritebackConflictError(
                        "UNKNOWN writeback must be verified before retry",
                        details={"writeback_id": writeback_id, "status": latest.value},
                    )

                if delivery in {
                    OutboxDeliveryStatus.LEASED,
                    OutboxDeliveryStatus.WAITING_RETRY,
                }:
                    raise WritebackConflictError(
                        "outbox delivery in progress; operator retry not allowed",
                        details={
                            "writeback_id": writeback_id,
                            "delivery_status": delivery.value,
                        },
                    )

                if delivery is OutboxDeliveryStatus.READY:
                    result = WritebackStatus.PENDING
                    await self._record_operator_retry_audit(
                        session,
                        outbox,
                        operator=operator,
                        operation_id=operation_id,
                        reason=reason,
                        audit_reason="operator_retry:idempotent-ready",
                        from_delivery=delivery.value,
                        to_delivery=delivery.value,
                        result_status=result,
                    )
                    record_writeback_retry(adapter=self._adapter_label(outbox))
                else:
                    if not delivery_status_eligible_for_operator_retry_pause(delivery, latest):
                        raise WritebackConflictError(
                            "illegal outbox state for operator retry",
                            details={
                                "writeback_id": writeback_id,
                                "delivery_status": delivery.value,
                                "writeback_status": latest.value if latest else None,
                            },
                        )

                    paused_from = delivery.value
                    if delivery in {
                        OutboxDeliveryStatus.DEAD_LETTER,
                        OutboxDeliveryStatus.DELIVERED,
                    }:
                        validate_outbox_delivery_transition(
                            delivery,
                            OutboxDeliveryStatus.PAUSED,
                            operator_retry_pause=True,
                        )
                        outbox.delivery_status = OutboxDeliveryStatus.PAUSED.value
                        outbox.locked_by = None
                        outbox.locked_at = None
                        outbox.lease_expires_at = None
                        outbox.next_retry_at = None
                        outbox.updated_at = datetime.now(UTC)
                        session.add(
                            orm.EventAuditLog(
                                event_id=outbox.event_id,
                                from_status=paused_from,
                                to_status=OutboxDeliveryStatus.PAUSED.value,
                                operator=operator,
                                reason=self._operator_retry_pause_reason(reason),
                            )
                        )
                        delivery = OutboxDeliveryStatus.PAUSED

                    decision = await self._evaluate_operator_retry_lookup(session, outbox)
                    if decision.action is _OperatorRetryAction.RECONCILE_TERMINAL:
                        assert decision.target_status is not None
                        assert decision.receipt is not None
                        validate_outbox_delivery_transition(
                            OutboxDeliveryStatus.PAUSED,
                            OutboxDeliveryStatus.DELIVERED,
                            lookup_confirmed_submission=True,
                        )
                        await self._append_receipt(session, outbox, receipt=decision.receipt)
                        outbox.latest_writeback_status = decision.target_status.value
                        outbox.delivery_status = OutboxDeliveryStatus.DELIVERED.value
                        outbox.delivered_at = outbox.delivered_at or datetime.now(UTC)
                        outbox.updated_at = datetime.now(UTC)
                        action = await session.get(
                            orm.Action, outbox.action_id, with_for_update=True
                        )
                        _mirror_writeback_status_to_action(action, decision.target_status.value)
                        await self._record_operator_retry_audit(
                            session,
                            outbox,
                            operator=operator,
                            operation_id=operation_id,
                            reason=reason,
                            audit_reason=(
                                f"operator_retry:reconcile:{decision.target_status.value}"
                            ),
                            from_delivery=OutboxDeliveryStatus.PAUSED.value,
                            to_delivery=OutboxDeliveryStatus.DELIVERED.value,
                            result_status=decision.target_status,
                        )
                        record_writeback(
                            status=decision.target_status.value,
                            adapter=self._adapter_label(outbox),
                        )
                        result = decision.target_status
                        sync_event_id = outbox.event_id
                    elif decision.action is _OperatorRetryAction.BLOCKED:
                        # Commit PAUSED gate + audit, then raise 409 outside the txn.
                        # Do not attach operation_id — a blocked attempt must not replay
                        # as a successful WritebackStatus response.
                        await self._record_operator_retry_audit(
                            session,
                            outbox,
                            operator=operator,
                            operation_id=None,
                            reason=reason,
                            audit_reason=(f"operator_retry:blocked:{decision.reason or 'lookup'}"),
                            from_delivery=OutboxDeliveryStatus.PAUSED.value,
                            to_delivery=OutboxDeliveryStatus.PAUSED.value,
                            result_status=latest or WritebackStatus.FAILED,
                        )
                        blocked_error = WritebackConflictError(
                            decision.reason or "operator retry blocked after lookup",
                            details={
                                "writeback_id": writeback_id,
                                "delivery_status": OutboxDeliveryStatus.PAUSED.value,
                            },
                        )
                        result = latest or WritebackStatus.FAILED
                    else:
                        current_writeback = latest or WritebackStatus.FAILED
                        target_writeback = WritebackStatus.PENDING
                        validate_writeback_status_transition(
                            current_writeback,
                            target_writeback,
                            lookup_never_accepted=decision.lookup_never_accepted,
                            adapter_allows_safe_retry=decision.adapter_allows_safe_retry,
                        )
                        validate_outbox_delivery_transition(
                            OutboxDeliveryStatus.PAUSED,
                            OutboxDeliveryStatus.READY,
                        )
                        outbox.delivery_status = OutboxDeliveryStatus.READY.value
                        outbox.latest_writeback_status = target_writeback.value
                        outbox.attempt = 0
                        outbox.locked_by = None
                        outbox.locked_at = None
                        outbox.lease_expires_at = None
                        outbox.next_retry_at = None
                        outbox.updated_at = datetime.now(UTC)
                        action = await session.get(
                            orm.Action, outbox.action_id, with_for_update=True
                        )
                        _mirror_writeback_status_to_action(action, target_writeback.value)
                        await self._record_operator_retry_audit(
                            session,
                            outbox,
                            operator=operator,
                            operation_id=operation_id,
                            reason=reason,
                            audit_reason="operator_retry:re-enqueued",
                            from_delivery=OutboxDeliveryStatus.PAUSED.value,
                            to_delivery=OutboxDeliveryStatus.READY.value,
                            result_status=target_writeback,
                        )
                        record_writeback_retry(adapter=self._adapter_label(outbox))
                        result = target_writeback

        if blocked_error is not None:
            raise blocked_error
        if sync_event_id is not None:
            await self._sync_writeback_summary(sync_event_id)
            await self._maybe_resume(sync_event_id)
        return result

    async def lookup_writeback_status(self, writeback_id: str) -> WritebackStatus | None:
        """Look up writeback status, preferring provider query when declared.

        Used by WritebackRecoveryHandler (ISSUE-062) when a writeback is in
        UNKNOWN status. When the adapter declares ``supports_status_query`` or
        ``supports_lookup_by_idempotency``, queries the provider inside a
        ``disposition.query_status`` span (ISSUE-092); otherwise returns the
        cached outbox status only (no span).
        """
        async with self._session_factory() as session:
            outbox = await session.scalar(
                select(orm.DispositionOutbox).where(
                    orm.DispositionOutbox.writeback_id == writeback_id
                )
            )
            if outbox is None:
                return None

            adapter = self._resolve_adapter(outbox)
            caps = adapter.capabilities()
            if caps.supports_status_query or caps.supports_lookup_by_idempotency:
                command = DispositionCommand.model_validate(outbox.command_payload)
                latest_receipt = await session.scalar(
                    select(orm.DispositionReceipt)
                    .where(orm.DispositionReceipt.writeback_id == writeback_id)
                    .order_by(orm.DispositionReceipt.sequence.desc())
                    .limit(1)
                )
                provider_job_id = (
                    latest_receipt.provider_job_id if latest_receipt is not None else None
                )
                with disposition_span(
                    "disposition.query_status",
                    event_id=outbox.event_id,
                    action_id=outbox.action_id,
                    disposition_id=outbox.disposition_id,
                    writeback_id=outbox.writeback_id,
                ):
                    receipt: DispositionReceipt | None = None
                    if caps.supports_lookup_by_idempotency:
                        receipt = await adapter.lookup_submission(
                            command.idempotency_key,
                            command.source_locator,
                        )
                    if receipt is None and caps.supports_status_query and provider_job_id:
                        receipt = await adapter.get_status(provider_job_id)
                if receipt is not None:
                    return receipt.status

            if not outbox.latest_writeback_status:
                return None
            try:
                return WritebackStatus(outbox.latest_writeback_status)
            except ValueError:
                logger.warning(
                    "invalid writeback_status in outbox %s: %s",
                    writeback_id,
                    outbox.latest_writeback_status,
                )
                return WritebackStatus.UNKNOWN

    async def update_writeback_status_from_lookup(
        self, writeback_id: str, status: WritebackStatus
    ) -> None:
        """Update outbox writeback status from a provider-side lookup (ISSUE-062).

        This bypasses the :meth:`resolve_writeback` validation gate because
        the status comes from a provider-side query, not a human adjudication.
        Only call this when the provider has confirmed the actual writeback
        status via :meth:`lookup_writeback_status`.

        Should-Fix #1: the previous implementation called ``resolve_writeback``
        with ``resolution="status_queried:..."``, which was always rejected by
        the validation gate (only ``manual_confirmed`` / ``mark_failed`` /
        ``abandon`` are accepted).  This method writes the resolved status
        directly without the adjudication gate.
        """
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.writeback_id == writeback_id)
                    .with_for_update()
                )
                if outbox is None:
                    logger.warning(
                        "update_writeback_status_from_lookup: outbox not found for writeback_id=%s",
                        writeback_id,
                    )
                    return
                # ISSUE-062 Blocker #1 fix: validate the state transition
                # before writing the provider-resolved status.  The lookup
                # result is accepted as evidence_adjudication because it comes
                # from a provider-side query (not a fallible local guess).
                current_status = (
                    WritebackStatus(outbox.latest_writeback_status)
                    if outbox.latest_writeback_status
                    else WritebackStatus.PENDING
                )
                validate_writeback_status_transition(
                    current_status,
                    status,
                    evidence_adjudication=True,
                )
                outbox.latest_writeback_status = status.value
                outbox.updated_at = datetime.now(UTC)
                # Fence undelivered outboxes when provider lookup proves terminal success
                # so a concurrent operator-retry READY claim cannot re-egress (ISSUE-274).
                if is_operator_retry_terminal_success(status):
                    delivery = OutboxDeliveryStatus(outbox.delivery_status)
                    if delivery in {
                        OutboxDeliveryStatus.READY,
                        OutboxDeliveryStatus.PAUSED,
                        OutboxDeliveryStatus.WAITING_RETRY,
                    }:
                        validate_outbox_delivery_transition(
                            delivery,
                            OutboxDeliveryStatus.DELIVERED,
                            lookup_confirmed_submission=True,
                        )
                        outbox.delivery_status = OutboxDeliveryStatus.DELIVERED.value
                        outbox.delivered_at = outbox.delivered_at or datetime.now(UTC)
                        outbox.locked_by = None
                        outbox.locked_at = None
                        outbox.lease_expires_at = None
                        outbox.next_retry_at = None
                    elif delivery is OutboxDeliveryStatus.LEASED:
                        validate_outbox_delivery_transition(
                            delivery,
                            OutboxDeliveryStatus.DELIVERED,
                        )
                        outbox.delivery_status = OutboxDeliveryStatus.DELIVERED.value
                        outbox.delivered_at = outbox.delivered_at or datetime.now(UTC)
                        outbox.locked_by = None
                        outbox.locked_at = None
                        outbox.lease_expires_at = None
                        outbox.next_retry_at = None
                action = await session.get(orm.Action, outbox.action_id, with_for_update=True)
                _mirror_writeback_status_to_action(action, status.value)
                event_id = outbox.event_id
                adapter_label = self._adapter_label(outbox)
        record_writeback(status=status.value, adapter=adapter_label)
        await self._sync_writeback_summary(event_id)
        await self._maybe_resume(event_id)
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "writeback_updated",
                {"writeback_id": writeback_id, "status": status.value},
            )

    async def activate_deferred_disposition(
        self,
        event_id: str,
        *,
        operator: str,
        plan_revision: str | None = None,
    ) -> WritebackStatus:
        """Re-enqueue the deferred disposition writeback for *event_id*.

        Used by ``verify_node`` when ``disposition_only=True`` or
        ``disposition_policy=required`` but no ``verify_agent`` is wired:
        instead of passing an ``event_id`` where a ``writeback_id`` is expected
        (the bug fixed in ISSUE-062 Blocker #1), this method resolves the
        actual ``writeback_id`` from the most recent
        ``intent_kind=EVENT_STATUS_UPDATE`` outbox for the event and then
        delegates to :meth:`retry_writeback`.

        NOTE: The query filters by ``event_id`` and
        ``intent_kind=EVENT_STATUS_UPDATE`` ordered by ``created_at DESC LIMIT 1``.
        In multi-replan scenarios where a single event produces multiple
        ``EVENT_STATUS_UPDATE`` outbox rows across different plan revisions,
        this may resolve to a non-current revision's disposition.  The current
        single-disposition-per-event flow is unaffected.

        TODO(ISSUE-092): persist ``plan_revision`` / ``closure_cycle`` on the
        ``DispositionOutbox`` row so this method can add a WHERE filter on the
        current revision rather than relying on ``created_at DESC LIMIT 1``
        ordering alone.
        """
        if plan_revision is None:
            logger.warning(
                "activate_deferred_disposition: plan_revision not provided "
                "for event=%s — LIMIT 1 query may resolve to a non-current "
                "revision's writeback in multi-replan scenarios; see ISSUE-092",
                event_id,
            )

        async with self._session_factory() as session:
            outbox = await session.scalar(
                select(orm.DispositionOutbox)
                .where(
                    orm.DispositionOutbox.event_id == event_id,
                    orm.DispositionOutbox.intent_kind
                    == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                )
                .order_by(orm.DispositionOutbox.created_at.desc())
                .limit(1)
            )
            if outbox is None:
                raise EventNotFoundError(
                    f"no disposition outbox found for event: {event_id}",
                    details={"event_id": event_id},
                )
            writeback_id = outbox.writeback_id
            logger.debug(
                "activate_deferred_disposition: resolved event=%s → writeback=%s",
                event_id,
                writeback_id,
            )

        return await self.retry_writeback(writeback_id, operator=operator)

    async def resolve_writeback(
        self,
        writeback_id: str,
        resolution: str,
        *,
        principal: str,
        comment: str,
        evidence_ref: str | None = None,
        operation_id: str | None = None,
    ) -> WritebackStatus:
        if resolution not in {"manual_confirmed", "mark_failed", "abandon"}:
            raise ValidationError(
                "unsupported writeback resolution",
                details={"resolution": resolution},
            )
        if resolution == "manual_confirmed" and not evidence_ref:
            raise ValidationError(
                "manual_confirmed requires evidence_ref",
                details={"writeback_id": writeback_id},
            )
        target = (
            WritebackStatus.CONFIRMED
            if resolution == "manual_confirmed"
            else WritebackStatus.FAILED
        )
        should_dispatch = False
        fallthrough_resume = False
        already_terminal = False
        resume_intent_id: str | None = None
        event_id = ""
        adapter_label = "unknown"
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.writeback_id == writeback_id)
                    .with_for_update()
                )
                if outbox is None:
                    raise EventNotFoundError(
                        f"writeback not found: {writeback_id}",
                        details={"writeback_id": writeback_id},
                    )
                current_status = WritebackStatus(
                    outbox.latest_writeback_status or WritebackStatus.UNKNOWN.value
                )
                event_id = outbox.event_id
                adapter_label = self._adapter_label(outbox)
                # Idempotency guard (ISSUE-064): If the outbox already
                # reached the target terminal status (e.g. CONFIRMED from
                # synchronous delivery in activate_and_submit), the
                # transition is a no-op.  CONFIRMED → CONFIRMED is NOT
                # in the transition matrix because CONFIRMED is terminal;
                # we short-circuit here to keep the resolve call safe.
                # ISSUE-277: still re-dispatch durable resume intents that
                # were committed before a process kill.
                if current_status is target:
                    already_terminal = True
                else:
                    validate_writeback_status_transition(
                        current_status,
                        target,
                        evidence_adjudication=True,
                    )
                    await self._append_receipt(
                        session,
                        outbox,
                        status=target,
                        confirmation_evidence=(
                            ConfirmationEvidence.MANUAL_CONFIRMED
                            if target is WritebackStatus.CONFIRMED
                            else None
                        ),
                        provider_message=comment,
                    )
                    outbox.latest_writeback_status = target.value
                    outbox.delivery_status = OutboxDeliveryStatus.DELIVERED.value
                    action = await session.get(orm.Action, outbox.action_id, with_for_update=True)
                    _mirror_writeback_status_to_action(action, target.value)
                    if self._manual_resolution is not None:
                        from app.core.errors import IdempotencyKeyReuseError
                        from app.services.manual_resolution_service import (
                            RESOLUTION_SOURCE_WRITEBACK_MANUAL,
                            SUBJECT_KIND_WRITEBACK,
                        )

                        try:
                            create_resume = (
                                self._manual_resolution.create_or_replay_resume_intent_in_session
                            )
                            resume_intent = await create_resume(
                                session,
                                event_id,
                                resolution_source=RESOLUTION_SOURCE_WRITEBACK_MANUAL,
                                subject_kind=SUBJECT_KIND_WRITEBACK,
                                subject_id=writeback_id,
                                resolution=resolution,
                                principal=principal,
                                comment=comment,
                                evidence_ref=evidence_ref,
                                operation_id=operation_id,
                            )
                            should_dispatch = True
                            resume_intent_id = resume_intent.intent_id
                        except IdempotencyKeyReuseError:
                            raise
                        except ValidationError:
                            # Non-manual holds fall through to classic _maybe_resume.
                            fallthrough_resume = True
                            logger.info(
                                "resolve_writeback did not enqueue manual resume "
                                "intent writeback=%s",
                                writeback_id,
                                exc_info=True,
                            )
                    else:
                        fallthrough_resume = True
        if already_terminal:
            if self._manual_resolution is not None:
                from app.core.errors import IdempotencyKeyReuseError
                from app.services.manual_resolution_service import (
                    RESOLUTION_SOURCE_WRITEBACK_MANUAL,
                    SUBJECT_KIND_WRITEBACK,
                )

                try:
                    resume_intent = await self._manual_resolution.create_or_replay_resume_intent(
                        event_id,
                        resolution_source=RESOLUTION_SOURCE_WRITEBACK_MANUAL,
                        subject_kind=SUBJECT_KIND_WRITEBACK,
                        subject_id=writeback_id,
                        resolution=resolution,
                        principal=principal,
                        comment=comment,
                        evidence_ref=evidence_ref,
                        operation_id=operation_id,
                    )
                    self._manual_resolution.schedule_dispatch(
                        event_id=event_id,
                        intent_id=resume_intent.intent_id,
                        trigger="resolve_writeback",
                    )
                except IdempotencyKeyReuseError:
                    raise
                except ValidationError:
                    if await self._manual_resolution.has_schedulable_intent(event_id):
                        self._manual_resolution.schedule_dispatch(
                            event_id=event_id,
                            trigger="resolve_writeback_validation",
                        )
            if self._bus is not None:
                await self._bus.publish_event(
                    event_id,
                    "writeback_updated",
                    {"writeback_id": writeback_id, "status": target.value},
                )
            return target
        record_writeback(status=target.value, adapter=adapter_label)
        await self._sync_writeback_summary(event_id)
        if should_dispatch and self._manual_resolution is not None:
            self._manual_resolution.schedule_dispatch(
                event_id=event_id,
                intent_id=resume_intent_id,
                trigger="resolve_writeback",
            )
        elif fallthrough_resume:
            await self._maybe_resume(event_id)
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "writeback_updated",
                {"writeback_id": writeback_id, "status": target.value},
            )
        return target

    async def get_writeback(
        self, writeback_id: str
    ) -> tuple[DispositionOutboxRecord, DispositionReceipt | None]:
        async with self._session_factory() as session:
            outbox = await session.scalar(
                select(orm.DispositionOutbox).where(
                    orm.DispositionOutbox.writeback_id == writeback_id
                )
            )
            if outbox is None:
                raise EventNotFoundError(
                    f"writeback not found: {writeback_id}",
                    details={"writeback_id": writeback_id},
                )
            receipt = await session.scalar(
                select(orm.DispositionReceipt)
                .where(orm.DispositionReceipt.writeback_id == writeback_id)
                .order_by(orm.DispositionReceipt.sequence.desc())
                .limit(1)
            )
        record = DispositionOutboxRecord.model_validate(
            {
                "outbox_id": outbox.outbox_id,
                "writeback_id": outbox.writeback_id,
                "disposition_id": outbox.disposition_id,
                "action_id": outbox.action_id,
                "event_id": outbox.event_id,
                "closure_cycle": outbox.closure_cycle,
                "source_record_id": outbox.source_record_id,
                "source_locator_hash": outbox.source_locator_hash,
                "source_sequence": outbox.source_sequence,
                "intent_kind": outbox.intent_kind,
                "logical_slot": outbox.logical_slot,
                "supersedes_disposition_id": outbox.supersedes_disposition_id,
                "superseded_by_disposition_id": outbox.superseded_by_disposition_id,
                "idempotency_key": outbox.idempotency_key,
                "command_payload": outbox.command_payload,
                "command_payload_sha256": outbox.command_payload_sha256,
                "delivery_status": outbox.delivery_status,
                "latest_writeback_status": outbox.latest_writeback_status,
            }
        )
        parsed_receipt = None
        if receipt is not None:
            parsed_receipt = DispositionReceipt.model_validate(
                {
                    "writeback_id": receipt.writeback_id,
                    "sequence": receipt.sequence,
                    "disposition_id": receipt.disposition_id,
                    "action_id": receipt.action_id,
                    "source_record_id": receipt.source_record_id,
                    "status": receipt.status,
                    "confirmation_evidence": receipt.confirmation_evidence,
                    "provider_record_id": receipt.provider_record_id,
                    "provider_job_id": receipt.provider_job_id,
                    "provider_code": receipt.provider_code,
                    "provider_message": receipt.provider_message,
                    "observed_at": receipt.observed_at,
                    "submitted_at": receipt.submitted_at,
                    "confirmed_at": receipt.confirmed_at,
                    "target_results": receipt.target_results or [],
                    "raw_result": receipt.raw_result or {},
                    "truncated": receipt.truncated,
                    "simulated": receipt.simulated,
                }
            )
        return record, parsed_receipt

    async def list_event_dispositions(
        self, event_id: str
    ) -> list[tuple[DispositionCommand, WritebackStatus | None]]:
        async with self._session_factory() as session:
            rows = (
                await session.scalars(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.event_id == event_id)
                    .order_by(orm.DispositionOutbox.created_at.asc())
                )
            ).all()
        items: list[tuple[DispositionCommand, WritebackStatus | None]] = []
        for row in rows:
            command = DispositionCommand.model_validate(row.command_payload)
            status = (
                WritebackStatus(row.latest_writeback_status)
                if row.latest_writeback_status
                else None
            )
            items.append((command, status))
        return items

    async def get_disposition(
        self, disposition_id: str
    ) -> tuple[DispositionCommand, WritebackStatus | None]:
        async with self._session_factory() as session:
            outbox = await session.scalar(
                select(orm.DispositionOutbox).where(
                    orm.DispositionOutbox.disposition_id == disposition_id
                )
            )
        if outbox is None:
            raise EventNotFoundError(
                f"disposition not found: {disposition_id}",
                details={"disposition_id": disposition_id},
            )
        command = DispositionCommand.model_validate(outbox.command_payload)
        status = (
            WritebackStatus(outbox.latest_writeback_status)
            if outbox.latest_writeback_status
            else None
        )
        return command, status

    async def process_ready_outboxes(self, *, limit: int = 10) -> int:
        delivered = await OutboxWorker(self).run_once(limit=limit)
        await self.reconcile_pending_entity_effects(limit=limit)
        return delivered

    async def deliver_outbox(self, outbox_id: str) -> None:
        """Public entry point for synchronous outbox delivery (ISSUE-064).

        Exists so that EventDispositionService can trigger same-turn
        delivery without reaching into the private ``_deliver_outbox``.

        ISSUE-355: do not wrap this path in ``run_with_db_retry``.  Adapter
        ``submit`` runs inside the delivery transaction; retrying the whole
        method can double-submit after a post-submit deadlock.
        """
        await self._deliver_outbox(outbox_id)

    async def _deliver_outbox(self, outbox_id: str) -> None:
        command: DispositionCommand
        receipt: DispositionReceipt
        event_id: str
        reconcile_entity_effect = False
        receipt_job_projection: ActionExecutionJob | None = None
        async with self._session_factory() as session:
            async with session.begin():
                outbox_event_id = await session.scalar(
                    select(orm.DispositionOutbox.event_id).where(
                        orm.DispositionOutbox.outbox_id == outbox_id
                    )
                )
                if outbox_event_id is not None:
                    await session.get(
                        orm.SecurityEvent,
                        outbox_event_id,
                        with_for_update=True,
                    )
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    return
                # ISSUE-273: superseded heads are non-deliverable from commit time.
                if outbox.superseded_by_disposition_id is not None:
                    self._block_superseded_outbox(
                        outbox,
                        now=datetime.now(UTC),
                    )
                    return
                delivery_status = OutboxDeliveryStatus(outbox.delivery_status)
                if delivery_status is OutboxDeliveryStatus.PAUSED:
                    logger.info(
                        "outbox delivery skipped: paused pending lookup outbox=%s",
                        outbox_id,
                    )
                    return
                if delivery_status not in {
                    OutboxDeliveryStatus.READY,
                    OutboxDeliveryStatus.LEASED,
                    OutboxDeliveryStatus.WAITING_RETRY,
                }:
                    return
                now = datetime.now(UTC)
                if delivery_status is OutboxDeliveryStatus.LEASED:
                    if outbox.locked_by != self._worker_id:
                        logger.warning(
                            "outbox delivery blocked: lease owner mismatch outbox=%s "
                            "locked_by=%s worker=%s",
                            outbox_id,
                            outbox.locked_by,
                            self._worker_id,
                        )
                        return
                    if outbox.lease_expires_at is None or outbox.lease_expires_at <= now:
                        self._release_leased_outbox_after_lease_expiry(outbox, now=now)
                        return
                # ISSUE-235: lock the action row for the delivery-time approval
                # re-check so a concurrent revoke cannot slip in between the
                # check and the adapter submit (TOCTOU 纵深防御).
                execution_job_id = await session.scalar(
                    select(orm.Action.execution_job_id).where(
                        orm.Action.action_id == outbox.action_id
                    )
                )
                if execution_job_id:
                    await session.get(
                        orm.ActionExecutionJob,
                        execution_job_id,
                        with_for_update=True,
                    )
                action_row = await session.get(
                    orm.Action,
                    outbox.action_id,
                    with_for_update=True,
                )
                if action_row is None:
                    logger.warning(
                        "outbox delivery blocked: action row missing outbox=%s action_id=%s",
                        outbox_id,
                        outbox.action_id,
                    )
                    self._block_outbox_for_writeback_fence(
                        outbox,
                        now=datetime.now(UTC),
                        error_detail=(
                            f"action row not found for writeback fence: {outbox.action_id}"
                        ),
                    )
                    return
                raw_execution_owner = action_row.execution_owner
                if raw_execution_owner is None:
                    logger.warning(
                        "outbox delivery blocked: missing execution_owner outbox=%s action_id=%s",
                        outbox_id,
                        outbox.action_id,
                    )
                    self._block_outbox_for_writeback_fence(
                        outbox,
                        now=datetime.now(UTC),
                        error_detail=(
                            "action missing execution_owner for writeback fence: "
                            f"{outbox.action_id}"
                        ),
                    )
                    return
                execution_owner = ExecutionOwner(raw_execution_owner)
                try:
                    assert_writeback_side_effects_allowed(
                        action_id=outbox.action_id,
                        execution_owner=execution_owner,
                    )
                except ValidationError as exc:
                    self._block_outbox_for_writeback_fence(
                        outbox,
                        now=datetime.now(UTC),
                        error_detail=str(exc),
                    )
                    return
                command = DispositionCommand.model_validate(outbox.command_payload)
                if not await self._assert_active_head_for_delivery(session, outbox, command):
                    self._block_superseded_outbox(
                        outbox,
                        now=datetime.now(UTC),
                    )
                    return
                current_delivery = OutboxDeliveryStatus(outbox.delivery_status)
                if (
                    current_delivery is OutboxDeliveryStatus.LEASED
                    and outbox.locked_by is not None
                    and outbox.locked_by != self._worker_id
                ):
                    logger.warning(
                        "outbox delivery skipped: lease owned by another worker "
                        "outbox=%s locked_by=%s worker=%s",
                        outbox_id,
                        outbox.locked_by,
                        self._worker_id,
                    )
                    return
                # ISSUE-235 / ISSUE-290 / ISSUE-307 (SUS-301): TOCTOU 纵深防御 —
                # deliver relies on the enqueue-time approved_action_ids snapshot
                # and does not re-derive it; an approval revoked between enqueue
                # and delivery would still go out.  Re-check side-effect intents
                # (entity-class, EXECUTION_RESULT_RECORD, COMPENSATION_RECORD,
                # terminal EVENT_STATUS_UPDATE) right before delivery: the bound
                # action must still be in the effective approved set
                # (APPROVED/EXECUTING/SUCCESS, not superseded).
                # Fail-closed → DEAD_LETTER, never delivered.
                if command.intent_kind in _DELIVERY_APPROVAL_RECHECK_INTENTS:
                    if not _action_still_approved_for_delivery(action_row):
                        logger.warning(
                            "outbox delivery blocked: approval revoked before delivery "
                            "outbox=%s action_id=%s status=%s superseded_by=%s",
                            outbox_id,
                            outbox.action_id,
                            action_row.status,
                            action_row.superseded_by_revision,
                        )
                        self._block_outbox_for_writeback_fence(
                            outbox,
                            now=datetime.now(UTC),
                            error_detail=(
                                "approval revoked before delivery: "
                                f"action status={action_row.status}"
                            ),
                        )
                        return
                # ISSUE-224: enqueue validated against resolve_approved_action_ids;
                # delivery-time guard re-validates source_locator, message_code,
                # and analysis content but does not re-derive the approved list.
                # ISSUE-235/290 adds a separate action-row status/supersede
                # re-check for side-effect intents above.
                await self._guard.validate(
                    command,
                    {
                        "event_id": outbox.event_id,
                        "source_locator": command.source_locator,
                    },
                )
                adapter = self._resolve_adapter(outbox)
                adapter.validate_command(command)
                adapter_label = adapter.name
                with disposition_span(
                    "disposition.submit",
                    event_id=outbox.event_id,
                    action_id=outbox.action_id,
                    disposition_id=outbox.disposition_id,
                    writeback_id=outbox.writeback_id,
                ):
                    receipt = await adapter.submit(command)
                parsed_receipt = await self._append_receipt(session, outbox, receipt=receipt)
                receipt = parsed_receipt

                # B1 fix (ISSUE-064): For EVENT_STATUS_UPDATE intents,
                # perform readback confirmation to produce the P0
                # CONFIRMED+readback_verified receipt.  The submit
                # above produces ACCEPTED; the readback converts it to
                # CONFIRMED by verifying the provider-side state
                # transition actually occurred (provider truth).
                if (
                    command.intent_kind == DispositionIntentKind.EVENT_STATUS_UPDATE
                    and adapter.capabilities().supports_readback_confirmation
                ):
                    try:
                        with disposition_span(
                            "disposition.readback",
                            event_id=outbox.event_id,
                            action_id=outbox.action_id,
                            disposition_id=outbox.disposition_id,
                            writeback_id=outbox.writeback_id,
                        ):
                            confirmed = await adapter.confirm_readback(command)
                        if confirmed is not None:
                            receipt = await self._append_receipt(
                                session,
                                outbox,
                                receipt=confirmed,
                            )
                    except Exception as exc:
                        logger.warning(
                            "readback confirmation failed for %s; receipt stays at %s",
                            command.disposition_id,
                            receipt.status.value,
                        )
                        if self._bus is not None:
                            await self._bus.publish_event(
                                outbox.event_id,
                                "writeback_readback_failed",
                                {
                                    "disposition_id": command.disposition_id,
                                    "writeback_id": outbox.writeback_id,
                                    "receipt_status": receipt.status.value,
                                    "error_summary": f"{type(exc).__name__}: {exc}",
                                    "severity": "warn",
                                },
                            )

                outbox.latest_writeback_status = receipt.status.value
                if receipt.status is WritebackStatus.UNKNOWN:
                    self._pause_outbox_after_unknown_submission(
                        outbox,
                        now=datetime.now(UTC),
                        error_code="submission_unknown",
                        error_detail=(
                            "provider submission result unknown; lookup required before retry"
                        ),
                    )
                    event_id = outbox.event_id
                    writeback_id = outbox.writeback_id
                else:
                    outbox.delivery_status = OutboxDeliveryStatus.DELIVERED.value
                    outbox.delivered_at = datetime.now(UTC)
                    record_writeback(status=receipt.status.value, adapter=adapter_label)
                    event_id = outbox.event_id
                    writeback_id = outbox.writeback_id
                action = await session.get(orm.Action, outbox.action_id, with_for_update=True)
                if action is not None:
                    _mirror_writeback_status_to_action(action, receipt.status.value)
                    receipt_job_projection = await self._apply_receipt_execution_projection(
                        session,
                        action,
                        outbox,
                        command,
                        receipt,
                        adapter_label=adapter_label,
                    )
                    reconcile_entity_effect = (
                        command.intent_kind is DispositionIntentKind.ENTITY_ACTION_SUBMIT
                        and receipt.status is WritebackStatus.ACCEPTED
                    )
        if receipt_job_projection is not None and receipt.simulated and not reconcile_entity_effect:
            await self._publish_mock_job_projection(receipt_job_projection)
        if reconcile_entity_effect:
            await self._reconcile_entity_effect_for_outbox(outbox_id)
        await self._sync_writeback_summary(event_id)
        await self._maybe_resume(event_id)
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "disposition_submitted",
                {
                    "disposition_id": command.disposition_id,
                    "intent_kind": command.intent_kind.value,
                },
            )
            await self._bus.publish_event(
                event_id,
                "writeback_updated",
                {"writeback_id": writeback_id, "status": receipt.status.value},
            )

    async def _append_receipt(
        self,
        session: AsyncSession,
        outbox: orm.DispositionOutbox,
        *,
        receipt: DispositionReceipt | None = None,
        status: WritebackStatus | None = None,
        confirmation_evidence: ConfirmationEvidence | None = None,
        provider_message: str | None = None,
    ) -> DispositionReceipt:
        seq_row = await session.scalar(
            select(orm.DispositionReceipt.sequence)
            .where(orm.DispositionReceipt.writeback_id == outbox.writeback_id)
            .order_by(orm.DispositionReceipt.sequence.desc())
            .limit(1)
        )
        sequence = int(seq_row or 0) + 1
        if receipt is not None:
            provider_writeback_id = receipt.writeback_id
            parsed = receipt.model_copy(
                update={
                    "sequence": sequence,
                    "writeback_id": outbox.writeback_id,
                    "disposition_id": outbox.disposition_id,
                    "action_id": outbox.action_id,
                    "source_record_id": outbox.source_record_id,
                    "raw_result": {
                        **dict(receipt.raw_result or {}),
                        "provider_writeback_id": provider_writeback_id,
                    },
                }
            )
        else:
            assert status is not None
            now = datetime.now(UTC)
            parsed = DispositionReceipt(
                writeback_id=outbox.writeback_id,
                sequence=sequence,
                disposition_id=outbox.disposition_id,
                action_id=outbox.action_id,
                source_record_id=outbox.source_record_id,
                status=status,
                confirmation_evidence=confirmation_evidence,
                provider_message=provider_message,
                observed_at=now,
                submitted_at=now,
                confirmed_at=now if status is WritebackStatus.CONFIRMED else None,
            )
        parsed = sanitize_disposition_receipt(parsed)
        session.add(
            orm.DispositionReceipt(
                writeback_id=parsed.writeback_id,
                sequence=sequence,
                disposition_id=parsed.disposition_id,
                action_id=parsed.action_id,
                source_record_id=parsed.source_record_id,
                status=parsed.status.value,
                confirmation_evidence=(
                    parsed.confirmation_evidence.value
                    if parsed.confirmation_evidence is not None
                    else None
                ),
                provider_record_id=parsed.provider_record_id,
                provider_job_id=parsed.provider_job_id,
                provider_code=parsed.provider_code,
                provider_message=parsed.provider_message,
                observed_at=parsed.observed_at,
                submitted_at=parsed.submitted_at,
                confirmed_at=parsed.confirmed_at,
                target_results=[item.model_dump(mode="json") for item in parsed.target_results],
                raw_result=parsed.raw_result,
                truncated=parsed.truncated,
                simulated=parsed.simulated,
            )
        )
        await append_list_context_journal_in_session(
            session,
            outbox.event_id,
            "disposition_receipts",
            parsed.model_dump(mode="json"),
        )
        return parsed

    async def _apply_action_terminal_from_receipt(
        self,
        session: AsyncSession,
        action: orm.Action,
        receipt: DispositionReceipt,
        *,
        adapter_label: str = "unknown",
    ) -> None:
        from app.models.enums import ActionCategory, ActionStatus
        from app.models.workflow import validate_action_status_transition

        current = ActionStatus(action.status)
        if current is not ActionStatus.EXECUTING:
            return
        if receipt.status in {WritebackStatus.CONFIRMED, WritebackStatus.ACCEPTED}:
            target = ActionStatus.SUCCESS
        elif receipt.status is WritebackStatus.PARTIAL:
            target = ActionStatus.PARTIAL_SUCCESS
        elif receipt.status is WritebackStatus.UNKNOWN:
            target = ActionStatus.UNKNOWN
            record_action_unknown(adapter=adapter_label)
        else:
            target = ActionStatus.FAILED
        validate_action_status_transition(
            ActionCategory(action.action_category),
            current,
            target,
        )
        action.status = target.value
        action.executed_at = datetime.now(UTC)

    async def _apply_receipt_execution_projection(
        self,
        session: AsyncSession,
        action: orm.Action,
        outbox: orm.DispositionOutbox,
        command: DispositionCommand,
        receipt: DispositionReceipt,
        *,
        adapter_label: str,
    ) -> ActionExecutionJob | None:
        entity_effect_pending = (
            command.intent_kind is DispositionIntentKind.ENTITY_ACTION_SUBMIT
            and receipt.status is WritebackStatus.ACCEPTED
            and bool(action.execution_job_id)
        )
        if not entity_effect_pending:
            await self._apply_action_terminal_from_receipt(
                session,
                action,
                receipt,
                adapter_label=adapter_label,
            )
        return await self._persist_execution_job_from_receipt(
            session,
            action,
            receipt,
            command=command,
            outbox=outbox,
        )

    async def _persist_execution_job_from_receipt(
        self,
        session: AsyncSession,
        action: orm.Action,
        receipt: DispositionReceipt,
        *,
        command: DispositionCommand,
        outbox: orm.DispositionOutbox,
    ) -> ActionExecutionJob | None:
        if (
            action.execution_owner is None
            or ExecutionOwner(action.execution_owner) is not ExecutionOwner.XDR_MANAGED
        ):
            return None
        job_id = action.execution_job_id
        if not job_id:
            return None
        row = await session.get(orm.ActionExecutionJob, job_id, with_for_update=True)
        if row is None:
            return None
        from app.providers.tools.mock_provider import map_disposition_receipt_to_job
        from app.services.action_execution_service import _apply_job_row

        current = ExecutionJobStatus(row.status)
        mapped = map_disposition_receipt_to_job(
            receipt,
            event_id=outbox.event_id,
            idempotency_key=row.idempotency_key,
            job_id=job_id,
            action_id=action.action_id,
        ).model_copy(
            update={
                "attempt": row.attempt,
                "claimed_by": row.claimed_by,
                "lease_expires_at": row.lease_expires_at,
                "poll_after_ms": row.poll_after_ms,
                "provider_name": row.provider_name,
            }
        )
        if (
            current is ExecutionJobStatus.RUNNING
            and receipt.status is WritebackStatus.ACCEPTED
            and mapped.status is ExecutionJobStatus.QUEUED
        ):
            mapped = mapped.model_copy(update={"status": ExecutionJobStatus.RUNNING})
        if mapped.status is not current:
            validate_job_status_transition(
                current,
                mapped.status,
                provider_confirmed_terminal=receipt.status is WritebackStatus.CONFIRMED,
            )
        if mapped.target_results:
            synced = await sync_target_results_in_tx(
                session,
                job_id=job_id,
                attempt=row.attempt,
                targets=mapped.target_results,
            )
            if not synced:
                logger.warning(
                    "execution job target sync failed event=%s job=%s writeback=%s",
                    outbox.event_id,
                    job_id,
                    receipt.writeback_id,
                )
        _apply_job_row(row, mapped)
        _ = command  # correlation for future live adapters
        return mapped

    @staticmethod
    def _mock_entity_effect_readback_enabled(
        adapter: BaseDispositionAdapter,
        receipt: DispositionReceipt,
    ) -> bool:
        settings = get_settings()
        if settings.disposition_mode.strip().lower() != "mock_xdr":
            return False
        if not settings.simulation_enabled:
            return False
        if adapter.name != "mock_xdr":
            return False
        if not receipt.simulated:
            return False
        caps = adapter.capabilities()
        return caps.supports_entity_effect_readback

    async def reconcile_pending_entity_effects(self, *, limit: int = 10) -> int:
        """Poll independently-applied provider effects for delivered entity commands."""
        async with self._session_factory() as session:
            pending_projection = orm.ActionExecutionJob.raw_result[
                "effect_projection_pending"
            ].as_boolean()
            outbox_ids = list(
                await session.scalars(
                    select(orm.DispositionOutbox.outbox_id)
                    .join(
                        orm.Action,
                        orm.Action.action_id == orm.DispositionOutbox.action_id,
                    )
                    .join(
                        orm.ActionExecutionJob,
                        orm.ActionExecutionJob.job_id == orm.Action.execution_job_id,
                    )
                    .where(
                        orm.DispositionOutbox.intent_kind
                        == DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                        orm.DispositionOutbox.delivery_status
                        == OutboxDeliveryStatus.DELIVERED.value,
                        orm.DispositionOutbox.latest_writeback_status
                        == WritebackStatus.ACCEPTED.value,
                        or_(
                            orm.ActionExecutionJob.status.in_(
                                [
                                    ExecutionJobStatus.QUEUED.value,
                                    ExecutionJobStatus.RUNNING.value,
                                ]
                            ),
                            pending_projection.is_(True),
                        ),
                    )
                    .order_by(orm.DispositionOutbox.created_at)
                    .limit(limit)
                )
            )
        reconciled = 0
        for outbox_id in outbox_ids:
            try:
                if await self._reconcile_entity_effect_for_outbox(outbox_id):
                    reconciled += 1
            except Exception:
                logger.exception(
                    "entity effect reconcile skipped for durable retry outbox=%s",
                    outbox_id,
                )
        return reconciled

    async def _reconcile_entity_effect_for_outbox(self, outbox_id: str) -> bool:
        async with self._session_factory() as session:
            outbox = await session.get(orm.DispositionOutbox, outbox_id)
            if outbox is None:
                return False
            action = await session.get(orm.Action, outbox.action_id)
            receipt_row = await session.scalar(
                select(orm.DispositionReceipt)
                .where(orm.DispositionReceipt.writeback_id == outbox.writeback_id)
                .order_by(orm.DispositionReceipt.sequence.desc())
                .limit(1)
            )
            if action is None or receipt_row is None:
                return False
            command = DispositionCommand.model_validate(outbox.command_payload)
            receipt = DispositionReceipt.model_validate(
                {
                    "writeback_id": receipt_row.writeback_id,
                    "sequence": receipt_row.sequence,
                    "disposition_id": receipt_row.disposition_id,
                    "action_id": receipt_row.action_id,
                    "source_record_id": receipt_row.source_record_id,
                    "status": receipt_row.status,
                    "confirmation_evidence": receipt_row.confirmation_evidence,
                    "provider_record_id": receipt_row.provider_record_id,
                    "provider_job_id": receipt_row.provider_job_id,
                    "provider_code": receipt_row.provider_code,
                    "provider_message": receipt_row.provider_message,
                    "observed_at": receipt_row.observed_at,
                    "submitted_at": receipt_row.submitted_at,
                    "confirmed_at": receipt_row.confirmed_at,
                    "target_results": receipt_row.target_results or [],
                    "raw_result": receipt_row.raw_result or {},
                    "truncated": receipt_row.truncated,
                    "simulated": receipt_row.simulated,
                }
            )
            adapter = self._resolve_adapter(outbox)
            action_id = action.action_id
            job_id = action.execution_job_id
        try:
            completion = await self._maybe_complete_entity_effect(
                action,
                command,
                receipt,
                adapter,
            )
        except DependencyUnavailableError as exc:
            logger.warning(
                "entity effect readback unavailable; will retry outbox=%s error=%s",
                outbox_id,
                type(exc).__name__,
            )
            return False
        if completion is None:
            return False
        if not completion.verified and completion.provider_code == "effect_not_applied":
            return False
        if completion.verified and not self._entity_effect_completion_matches(
            action,
            command,
            receipt,
            completion,
        ):
            completion = completion.model_copy(
                update={
                    "verified": False,
                    "provider_code": "effect_correlation_mismatch",
                    "provider_message": "entity effect completion correlation mismatch",
                }
            )
        projection: ActionExecutionJob | None = None
        async with self._session_factory() as session:
            async with session.begin():
                if job_id:
                    await session.get(
                        orm.ActionExecutionJob,
                        job_id,
                        with_for_update=True,
                    )
                locked_action = await session.get(
                    orm.Action,
                    action_id,
                    with_for_update=True,
                )
                locked_outbox = await session.get(
                    orm.DispositionOutbox,
                    outbox_id,
                    with_for_update=True,
                )
                if locked_action is None or locked_outbox is None:
                    return False
                if completion.verified:
                    projection = await self._finalize_entity_effect_completion(
                        session,
                        locked_action,
                        locked_outbox,
                        receipt,
                        completion,
                    )
                else:
                    projection = await self._mark_entity_effect_unverified(
                        session,
                        locked_action,
                        locked_outbox,
                        receipt,
                        completion,
                    )
        if projection is None:
            return False
        try:
            await self._publish_entity_effect_projection(
                projection,
                command,
                completion,
            )
            async with self._session_factory() as session:
                async with session.begin():
                    row = await session.get(
                        orm.ActionExecutionJob,
                        projection.job_id,
                        with_for_update=True,
                    )
                    if row is not None:
                        raw_result = dict(row.raw_result or {})
                        raw_result["effect_projection_pending"] = False
                        row.raw_result = sanitize_raw_result(raw_result)
        except Exception:
            logger.exception(
                "entity effect projection deferred for durable retry outbox=%s job=%s",
                outbox_id,
                projection.job_id,
            )
            return False
        return completion.verified

    async def _publish_entity_effect_projection(
        self,
        projection: ActionExecutionJob,
        command: DispositionCommand,
        completion: EntityEffectCompletion,
    ) -> None:
        settings = get_settings()
        if (
            not settings.simulation_enabled
            or settings.disposition_mode.strip().lower() != "mock_xdr"
            or projection.provider_name != "mock_xdr"
        ):
            return
        from app.providers.tools.mock_provider import (
            get_mock_tool_provider,
            write_xdr_entity_effect_observation,
        )

        provider_state = get_mock_tool_provider().state
        await provider_state.set_job(
            projection.job_id,
            projection.model_dump(mode="json"),
        )
        if completion.verified:
            await write_xdr_entity_effect_observation(
                provider_state,
                entity_action_code=completion.entity_action_code,
                target_type=completion.target_type,
                target=completion.target,
                applied_status=completion.applied_status,
                job_id=projection.job_id,
                action_id=projection.action_id,
                writeback_id=completion.writeback_id,
                provider_record_id=completion.provider_record_id,
                observed_version=completion.observed_version,
                connector=command.source_locator.connector_id,
            )

    @staticmethod
    async def _publish_mock_job_projection(projection: ActionExecutionJob) -> None:
        settings = get_settings()
        if (
            not settings.simulation_enabled
            or settings.disposition_mode.strip().lower() != "mock_xdr"
            or projection.provider_name != "mock_xdr"
        ):
            return
        from app.providers.tools.mock_provider import get_mock_tool_provider

        await get_mock_tool_provider().state.set_job(
            projection.job_id,
            projection.model_dump(mode="json"),
        )

    async def _maybe_complete_entity_effect(
        self,
        action: orm.Action,
        command: DispositionCommand,
        receipt: DispositionReceipt,
        adapter: BaseDispositionAdapter,
    ) -> EntityEffectCompletion | None:
        if command.intent_kind is not DispositionIntentKind.ENTITY_ACTION_SUBMIT:
            return None
        if receipt.status is not WritebackStatus.ACCEPTED:
            return None
        if not self._mock_entity_effect_readback_enabled(adapter, receipt):
            return None
        completion = await adapter.read_entity_effect_completion(command, receipt)
        return completion

    @staticmethod
    def _entity_effect_completion_matches(
        action: orm.Action,
        command: DispositionCommand,
        receipt: DispositionReceipt,
        completion: EntityEffectCompletion,
    ) -> bool:
        params = command.operation_params
        entity_action_code = getattr(params, "entity_action_code", None)
        canonical_target = getattr(params, "canonical_target", None)
        if not isinstance(entity_action_code, str) or not isinstance(canonical_target, str):
            return False
        try:
            expected_type, expected_target, expected_status = parse_entity_effect_target(
                entity_action_code,
                canonical_target,
            )
        except ValueError:
            return False
        provider_writeback_id = receipt.raw_result.get("provider_writeback_id")
        if not isinstance(provider_writeback_id, str) or not provider_writeback_id:
            provider_writeback_id = receipt.writeback_id
        return (
            completion.disposition_id == command.disposition_id
            and completion.action_id == action.action_id == command.action_id
            and completion.writeback_id == receipt.writeback_id
            and completion.provider_writeback_id == provider_writeback_id
            and completion.entity_action_code == entity_action_code
            and completion.canonical_target == canonical_target
            and completion.target_type == expected_type
            and completion.target == expected_target
            and completion.applied_status == expected_status
            and bool(completion.provider_record_id)
            and completion.observed_version > 0
        )

    async def _mark_entity_effect_unverified(
        self,
        session: AsyncSession,
        action: orm.Action,
        outbox: orm.DispositionOutbox,
        receipt: DispositionReceipt,
        completion: EntityEffectCompletion | None,
    ) -> ActionExecutionJob | None:
        job_id = action.execution_job_id
        if not job_id:
            return None
        row = await session.get(orm.ActionExecutionJob, job_id, with_for_update=True)
        if row is None:
            return None
        current = ExecutionJobStatus(row.status)
        if current in _TERMINAL_JOB_STATUSES or current is ExecutionJobStatus.UNKNOWN:
            return None
        validate_job_status_transition(
            current,
            ExecutionJobStatus.UNKNOWN,
            provider_confirmed_terminal=False,
        )
        now = datetime.now(UTC)
        canonical_target = (
            completion.canonical_target
            if completion is not None and completion.canonical_target
            else (
                f"{action.target_type}:{action.target}"
                if action.target_type and action.target
                else (action.target or "")
            )
        )
        target_result = TargetExecutionResult(
            canonical_target=canonical_target,
            status=TargetExecutionStatus.UNKNOWN,
            code=(
                completion.provider_code
                if completion is not None and completion.provider_code
                else "effect_readback_unavailable"
            ),
            message=completion.provider_message if completion is not None else None,
            raw_result={"writeback_id": receipt.writeback_id},
        )
        await sync_target_results_in_tx(
            session,
            job_id=job_id,
            attempt=row.attempt,
            targets=[target_result],
        )
        row.status = ExecutionJobStatus.UNKNOWN.value
        row.claimed_by = None
        row.lease_expires_at = None
        row.updated_at = now
        row.provider_code = target_result.code
        row.provider_message = target_result.message
        row.raw_result = sanitize_raw_result(
            {
                **dict(row.raw_result or {}),
                "effect_completion": (
                    completion.model_dump(mode="json") if completion is not None else None
                ),
                "writeback_id": receipt.writeback_id,
                "effect_projection_pending": True,
                "simulated": receipt.simulated,
            }
        )
        job_projection = ActionExecutionJob(
            job_id=job_id,
            event_id=outbox.event_id,
            action_id=action.action_id,
            provider_name=row.provider_name,
            idempotency_key=row.idempotency_key,
            provider_job_id=row.provider_job_id,
            status=ExecutionJobStatus.UNKNOWN,
            claimed_by=None,
            lease_expires_at=None,
            created_at=row.created_at,
            updated_at=now,
            started_at=row.started_at,
            finished_at=None,
            poll_after_ms=row.poll_after_ms,
            attempt=row.attempt,
            target_results=[target_result],
            provider_code=row.provider_code,
            provider_message=row.provider_message,
            raw_result=dict(row.raw_result or {}),
        )
        return job_projection

    async def _finalize_entity_effect_completion(
        self,
        session: AsyncSession,
        action: orm.Action,
        outbox: orm.DispositionOutbox,
        receipt: DispositionReceipt,
        completion: EntityEffectCompletion,
    ) -> ActionExecutionJob | None:
        job_id = action.execution_job_id
        if not job_id:
            return None
        row = await session.get(orm.ActionExecutionJob, job_id, with_for_update=True)
        if row is None:
            return None
        current = ExecutionJobStatus(row.status)
        if current in _TERMINAL_JOB_STATUSES:
            if current is ExecutionJobStatus.SUCCESS and bool(
                (row.raw_result or {}).get("effect_projection_pending")
            ):
                targets = await load_target_results_for_job(
                    session,
                    job_id,
                    row.attempt,
                )
                return job_from_row(row, target_results=targets)
            return None
        now = datetime.now(UTC)
        target_result = TargetExecutionResult(
            canonical_target=completion.canonical_target,
            status=TargetExecutionStatus.SUCCESS,
            code=completion.provider_code or "effect_readback_verified",
            message=completion.provider_message,
            artifact_id=completion.provider_record_id or None,
            raw_result={
                "writeback_id": completion.writeback_id,
                "disposition_id": completion.disposition_id,
                "observed_version": completion.observed_version,
                "entity_action_code": completion.entity_action_code,
            },
        )
        validate_job_status_transition(
            current,
            ExecutionJobStatus.SUCCESS,
            provider_confirmed_terminal=True,
        )
        synced = await sync_target_results_in_tx(
            session,
            job_id=job_id,
            attempt=row.attempt,
            targets=[target_result],
        )
        if not synced:
            logger.warning(
                "entity effect target sync failed event=%s job=%s writeback=%s",
                outbox.event_id,
                job_id,
                completion.writeback_id,
            )
            return None
        row.status = ExecutionJobStatus.SUCCESS.value
        row.claimed_by = None
        row.lease_expires_at = None
        row.finished_at = now
        row.updated_at = now
        row.provider_code = completion.provider_code
        row.provider_message = completion.provider_message
        row.raw_result = sanitize_raw_result(
            {
                **dict(row.raw_result or {}),
                "effect_completion": completion.model_dump(mode="json"),
                "writeback_id": receipt.writeback_id,
                "effect_projection_pending": True,
                "simulated": receipt.simulated,
            }
        )
        if ActionStatus(action.status) is ActionStatus.EXECUTING:
            from app.models.enums import ActionCategory
            from app.models.workflow import validate_action_status_transition

            validate_action_status_transition(
                ActionCategory(action.action_category),
                ActionStatus.EXECUTING,
                ActionStatus.SUCCESS,
            )
            action.status = ActionStatus.SUCCESS.value
            action.executed_at = now
        job_projection = ActionExecutionJob(
            job_id=job_id,
            event_id=outbox.event_id,
            action_id=action.action_id,
            provider_name=row.provider_name,
            idempotency_key=row.idempotency_key,
            provider_job_id=row.provider_job_id,
            status=ExecutionJobStatus.SUCCESS,
            claimed_by=None,
            lease_expires_at=None,
            created_at=row.created_at,
            updated_at=now,
            started_at=row.started_at,
            finished_at=now,
            poll_after_ms=row.poll_after_ms,
            attempt=row.attempt,
            target_results=[target_result],
            provider_code=row.provider_code,
            provider_message=row.provider_message,
            raw_result=dict(row.raw_result or {}),
        )
        return job_projection

    @staticmethod
    def _operator_retry_pause_reason(reason: str | None) -> str:
        detail = (reason or "operator-initiated").strip()
        return f"operator_retry:pause:{detail}"

    async def _find_operator_retry_replay(
        self,
        session: AsyncSession,
        *,
        event_id: str,
        writeback_id: str,
        operation_id: str,
    ) -> WritebackStatus | None:
        prefix = f"{_OPERATOR_RETRY_REPLAY_PREFIX}:{writeback_id}:{operation_id}:"
        row = await session.scalar(
            select(orm.EventAuditLog.to_status)
            .where(
                orm.EventAuditLog.event_id == event_id,
                orm.EventAuditLog.reason.like(f"{prefix}%"),
            )
            .order_by(orm.EventAuditLog.id.desc())
            .limit(1)
        )
        if row is None:
            return None
        try:
            return WritebackStatus(row)
        except ValueError:
            logger.warning(
                "invalid operator retry replay status event=%s writeback=%s op=%s status=%s",
                event_id,
                writeback_id,
                operation_id,
                row,
            )
            return None

    async def _record_operator_retry_audit(
        self,
        session: AsyncSession,
        outbox: orm.DispositionOutbox,
        *,
        operator: str,
        operation_id: str | None,
        reason: str | None,
        audit_reason: str,
        from_delivery: str,
        to_delivery: str,
        result_status: WritebackStatus,
    ) -> None:
        note = (reason or "").strip()
        if operation_id is not None:
            replay_reason = (
                f"{_OPERATOR_RETRY_REPLAY_PREFIX}:{outbox.writeback_id}:"
                f"{operation_id}:{result_status.value}"
            )
            if note:
                replay_reason = f"{replay_reason}|note:{note}"
        else:
            replay_reason = audit_reason
            if note and note not in replay_reason:
                replay_reason = f"{replay_reason}|note:{note}"
        session.add(
            orm.EventAuditLog(
                event_id=outbox.event_id,
                from_status=from_delivery,
                to_status=result_status.value,
                operator=operator,
                reason=replay_reason,
            )
        )
        _ = to_delivery

    async def _evaluate_operator_retry_lookup(
        self,
        session: AsyncSession,
        outbox: orm.DispositionOutbox,
    ) -> _OperatorRetryDecision:
        adapter = self._resolve_adapter(outbox)
        caps = adapter.capabilities()
        safe_retry = adapter.allows_safe_retry()
        if not (caps.supports_lookup_by_idempotency or caps.supports_status_query):
            return _OperatorRetryDecision(
                action=_OperatorRetryAction.BLOCKED,
                reason="lookup capability unavailable; cannot prove safe retry",
            )

        if is_deterministic_adapter_rejection_code(getattr(outbox, "last_error_code", None)):
            return _OperatorRetryDecision(
                action=_OperatorRetryAction.BLOCKED,
                reason=(
                    "deterministic adapter rejection is not safely retryable; "
                    f"error_code={outbox.last_error_code}"
                ),
            )

        command = DispositionCommand.model_validate(outbox.command_payload)
        receipt: DispositionReceipt | None = None
        lookup_degraded = False
        idempotency_lookup_done = False
        try:
            if caps.supports_lookup_by_idempotency:
                receipt = await adapter.lookup_submission(
                    command.idempotency_key,
                    command.source_locator,
                )
                idempotency_lookup_done = True
            if receipt is None and caps.supports_status_query:
                latest_receipt = await session.scalar(
                    select(orm.DispositionReceipt)
                    .where(orm.DispositionReceipt.writeback_id == outbox.writeback_id)
                    .order_by(orm.DispositionReceipt.sequence.desc())
                    .limit(1)
                )
                provider_job_id = (
                    latest_receipt.provider_job_id if latest_receipt is not None else None
                )
                if provider_job_id:
                    receipt = await adapter.get_status(provider_job_id)
        except Exception as exc:
            logger.warning(
                "operator retry lookup degraded writeback=%s: %s",
                outbox.writeback_id,
                type(exc).__name__,
            )
            lookup_degraded = True

        if lookup_degraded:
            return _OperatorRetryDecision(
                action=_OperatorRetryAction.BLOCKED,
                reason="lookup degraded; outbox remains PAUSED",
            )

        if receipt is not None:
            if is_operator_retry_terminal_success(receipt.status):
                return _OperatorRetryDecision(
                    action=_OperatorRetryAction.RECONCILE_TERMINAL,
                    target_status=receipt.status,
                    receipt=receipt,
                )
            if receipt.status is WritebackStatus.UNKNOWN:
                return _OperatorRetryDecision(
                    action=_OperatorRetryAction.BLOCKED,
                    reason="lookup still UNKNOWN; manual adjudication required",
                )
            if receipt.status in {WritebackStatus.FAILED, WritebackStatus.PARTIAL}:
                if safe_retry:
                    return _OperatorRetryDecision(
                        action=_OperatorRetryAction.RE_ENQUEUE,
                        adapter_allows_safe_retry=True,
                    )
                return _OperatorRetryDecision(
                    action=_OperatorRetryAction.BLOCKED,
                    reason="adapter does not allow safe retry after failed lookup",
                )
            return _OperatorRetryDecision(
                action=_OperatorRetryAction.BLOCKED,
                reason=f"lookup returned non-retryable status {receipt.status.value}",
            )

        # Never-accepted only when idempotency lookup authoritatively returned None.
        if idempotency_lookup_done:
            if safe_retry:
                return _OperatorRetryDecision(
                    action=_OperatorRetryAction.RE_ENQUEUE,
                    lookup_never_accepted=True,
                    adapter_allows_safe_retry=True,
                )
            return _OperatorRetryDecision(
                action=_OperatorRetryAction.BLOCKED,
                reason="lookup proves never-accepted but adapter lacks safe-retry",
            )
        return _OperatorRetryDecision(
            action=_OperatorRetryAction.BLOCKED,
            reason="cannot prove never-accepted without idempotency lookup",
        )

    def _resolve_adapter(self, outbox: orm.DispositionOutbox) -> BaseDispositionAdapter:
        payload = outbox.command_payload or {}
        locator = payload.get("source_locator") or {}
        product = str(locator.get("source_product") or "mock_xdr")
        return self._adapters.get(product)

    async def _sync_writeback_summary(self, event_id: str) -> None:
        summary_payload: dict[str, Any] | None = None
        async with self._session_factory() as session:
            async with session.begin():
                se = await session.get(orm.SecurityEvent, event_id)
                if se is None:
                    return
                summary = await self._context_store._merge_writeback_summary(session, se)
                if summary is not None:
                    summary_payload = summary.model_dump(mode="json")
                    await append_context_journal_in_session(
                        session,
                        event_id,
                        "writeback_summary",
                        summary_payload,
                    )
        if summary_payload is not None:
            await self._context_store.set(event_id, "writeback_summary", summary_payload)

    async def _maybe_resume(self, event_id: str) -> None:
        async with self._session_factory() as session:
            substate_raw = await session.scalar(
                select(orm.EventContextJournal.value)
                .where(
                    orm.EventContextJournal.event_id == event_id,
                    orm.EventContextJournal.field_name == "execution_substate",
                )
                .order_by(orm.EventContextJournal.version.desc())
                .limit(1)
            )
        if isinstance(substate_raw, dict) and set(substate_raw) == {"_scalar"}:
            substate_raw = substate_raw["_scalar"]
        should_resume = substate_raw in {
            ExecutionSubstate.WAITING_WRITEBACK.value,
            ExecutionSubstate.WAITING_EXECUTION.value,
        }
        is_manual = substate_raw == ExecutionSubstate.MANUAL_RESOLUTION.value
        if is_manual and self._manual_resolution is not None:
            from app.services.manual_resolution_service import (
                RESOLUTION_SOURCE_WRITEBACK_AUTO,
                SUBJECT_KIND_EVENT,
            )

            try:
                resume_intent = await self._manual_resolution.create_or_replay_resume_intent(
                    event_id,
                    resolution_source=RESOLUTION_SOURCE_WRITEBACK_AUTO,
                    subject_kind=SUBJECT_KIND_EVENT,
                    subject_id=event_id,
                    resolution="writeback_progress",
                    principal="DispositionSyncService",
                )
                intent_id = getattr(resume_intent, "intent_id", None)
                if not intent_id:
                    raise AttributeError("resume intent missing intent_id")
                self._manual_resolution.schedule_dispatch(
                    event_id=event_id,
                    intent_id=intent_id,
                    trigger="writeback_progress",
                )
            except Exception:
                logger.warning(
                    "failed to enqueue durable graph resume intent event=%s",
                    event_id,
                    exc_info=True,
                )
            return
        if should_resume:
            try:
                await self._resume(event_id)
            except Exception as exc:
                from app.orchestration.graph_resume_observability import GraphResumeFailedError

                if isinstance(exc, GraphResumeFailedError):
                    logger.warning(
                        "resume_investigation hook failed event=%s error_type=%s",
                        event_id,
                        exc.error_type,
                    )
                    return
                logger.warning(
                    "resume_investigation hook failed event=%s",
                    event_id,
                    exc_info=True,
                )

    @staticmethod
    def _truncate_error_detail(detail: str) -> str:
        if len(detail) <= _ERROR_DETAIL_MAX_LEN:
            return detail
        return detail[: _ERROR_DETAIL_MAX_LEN - 3] + "..."

    @staticmethod
    def _outbox_retry_backoff_seconds(attempt: int) -> float:
        settings = get_settings()
        raw = settings.outbox_retry_backoff_seconds * attempt
        return min(raw, settings.outbox_retry_backoff_max_seconds)

    def _release_leased_outbox_after_failure(
        self,
        outbox: orm.DispositionOutbox,
        *,
        now: datetime,
        error_code: str,
        error_detail: str | None = None,
    ) -> OutboxDeliveryStatus:
        """Move a leased outbox to WAITING_RETRY (with backoff) or DEAD_LETTER."""
        current = OutboxDeliveryStatus(outbox.delivery_status)
        if current is not OutboxDeliveryStatus.LEASED:
            return current
        if outbox.lease_expires_at is None or outbox.lease_expires_at <= now:
            return self._release_leased_outbox_after_lease_expiry(outbox, now=now)

        settings = get_settings()
        attempt = int(outbox.attempt) + 1
        outbox.attempt = attempt
        outbox.last_error_code = error_code
        if error_detail is not None:
            outbox.last_error_detail = self._truncate_error_detail(error_detail)
        outbox.locked_by = None
        outbox.locked_at = None
        outbox.lease_expires_at = None
        outbox.updated_at = now

        if attempt >= settings.outbox_max_attempts:
            validate_outbox_delivery_transition(current, OutboxDeliveryStatus.DEAD_LETTER)
            outbox.delivery_status = OutboxDeliveryStatus.DEAD_LETTER.value
            outbox.next_retry_at = None
            record_writeback_dead_letter(
                adapter=self._adapter_label(outbox),
                error_code=error_code,
            )
            return OutboxDeliveryStatus.DEAD_LETTER

        validate_outbox_delivery_transition(
            current,
            OutboxDeliveryStatus.WAITING_RETRY,
            known_pre_egress_failure=True,
        )
        outbox.delivery_status = OutboxDeliveryStatus.WAITING_RETRY.value
        outbox.next_retry_at = now + timedelta(
            seconds=self._outbox_retry_backoff_seconds(attempt),
        )
        record_writeback_retry(adapter=self._adapter_label(outbox))
        return OutboxDeliveryStatus.WAITING_RETRY

    def _release_leased_outbox_after_lease_expiry(
        self,
        outbox: orm.DispositionOutbox,
        *,
        now: datetime,
    ) -> OutboxDeliveryStatus:
        """Pause an expired lease for lookup-first reconciliation (ISSUE-260).

        External submission may have succeeded before the worker crashed;
        never re-queue via WAITING_RETRY (two-hop bypass of PAUSED contract).
        """
        current = OutboxDeliveryStatus(outbox.delivery_status)
        if current is not OutboxDeliveryStatus.LEASED:
            return current

        outbox.last_error_code = "lease_expired"
        outbox.last_error_detail = self._truncate_error_detail(
            "idempotency_key_sha256="
            f"{hashlib.sha256(outbox.idempotency_key.encode()).hexdigest()}; "
            f"locked_by={outbox.locked_by}; attempt={outbox.attempt}"
        )
        outbox.locked_by = None
        outbox.locked_at = None
        outbox.lease_expires_at = None
        outbox.next_retry_at = None
        outbox.updated_at = now
        outbox.latest_writeback_status = WritebackStatus.UNKNOWN.value
        validate_outbox_delivery_transition(
            current,
            OutboxDeliveryStatus.PAUSED,
            lease_expired_resend=True,
        )
        outbox.delivery_status = OutboxDeliveryStatus.PAUSED.value
        return OutboxDeliveryStatus.PAUSED

    def _pause_outbox_after_unknown_submission(
        self,
        outbox: orm.DispositionOutbox,
        *,
        now: datetime,
        error_code: str,
        error_detail: str,
    ) -> OutboxDeliveryStatus:
        """Pause delivery when provider submission result is UNKNOWN."""
        current = OutboxDeliveryStatus(outbox.delivery_status)
        if current not in {
            OutboxDeliveryStatus.READY,
            OutboxDeliveryStatus.LEASED,
            OutboxDeliveryStatus.WAITING_RETRY,
        }:
            return current

        outbox.last_error_code = error_code
        outbox.last_error_detail = self._truncate_error_detail(error_detail)
        outbox.locked_by = None
        outbox.locked_at = None
        outbox.lease_expires_at = None
        outbox.next_retry_at = None
        outbox.updated_at = now
        validate_outbox_delivery_transition(current, OutboxDeliveryStatus.PAUSED)
        outbox.delivery_status = OutboxDeliveryStatus.PAUSED.value
        return OutboxDeliveryStatus.PAUSED

    async def reconcile_paused_outboxes(self, *, limit: int = 10) -> int:
        """Lookup-first reconciliation with per-row fencing (ISSUE-260)."""
        reconciled = 0
        claims = await self._claim_paused_outboxes(limit=limit)
        for claim in claims:
            outcome = await self._lookup_paused_outbox(claim)
            try:
                applied, event_id, status = await self._apply_paused_lookup_outcome(
                    claim,
                    outcome,
                )
            except Exception as exc:
                logger.warning(
                    "paused outbox reconcile apply failed outbox=%s error=%s",
                    claim.outbox_id,
                    type(exc).__name__,
                    exc_info=True,
                )
                await self._release_paused_lookup_claim(
                    claim,
                    error_code="lookup_apply_failed",
                    detail=f"{type(exc).__name__}: {exc}",
                )
                await self._sync_writeback_summary(claim.event_id)
                await self._maybe_resume(claim.event_id)
                if self._bus is not None:
                    await self._bus.publish_event(
                        claim.event_id,
                        "writeback_updated",
                        {
                            "writeback_id": claim.writeback_id,
                            "status": WritebackStatus.UNKNOWN.value,
                        },
                    )
                continue
            if event_id is not None:
                await self._sync_writeback_summary(event_id)
                await self._maybe_resume(event_id)
                if status is not None and self._bus is not None:
                    await self._bus.publish_event(
                        event_id,
                        "writeback_updated",
                        {"writeback_id": claim.writeback_id, "status": status.value},
                    )
            if applied:
                reconciled += 1
        return reconciled

    async def _claim_paused_outboxes(self, *, limit: int) -> list[_PausedLookupClaim]:
        """Acquire short-lived reconciliation leases without network I/O."""
        now = datetime.now(UTC)
        claims: list[_PausedLookupClaim] = []
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.DispositionOutbox)
                        .where(
                            orm.DispositionOutbox.delivery_status
                            == OutboxDeliveryStatus.PAUSED.value,
                            orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                            or_(
                                orm.DispositionOutbox.locked_by.is_(None),
                                orm.DispositionOutbox.lease_expires_at.is_(None),
                                orm.DispositionOutbox.lease_expires_at <= now,
                            ),
                        )
                        .order_by(orm.DispositionOutbox.updated_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    try:
                        command = DispositionCommand.model_validate(row.command_payload)
                        adapter = self._resolve_adapter(row)
                    except Exception as exc:
                        row.last_error_code = "lookup_claim_invalid"
                        row.last_error_detail = self._truncate_error_detail(
                            f"{type(exc).__name__}: {exc}"
                        )
                        row.updated_at = now
                        continue
                    latest_receipt = await session.scalar(
                        select(orm.DispositionReceipt)
                        .where(orm.DispositionReceipt.writeback_id == row.writeback_id)
                        .order_by(orm.DispositionReceipt.sequence.desc())
                        .limit(1)
                    )
                    token = f"{self._worker_id}:reconcile:{secrets.token_hex(8)}"
                    row.locked_by = token
                    row.locked_at = now
                    row.lease_expires_at = now + timedelta(seconds=_DEFAULT_LEASE_SECONDS)
                    row.updated_at = now
                    action = await session.get(orm.Action, row.action_id, with_for_update=True)
                    _mirror_writeback_status_to_action(action, WritebackStatus.UNKNOWN.value)
                    claims.append(
                        _PausedLookupClaim(
                            outbox_id=row.outbox_id,
                            token=token,
                            event_id=row.event_id,
                            action_id=row.action_id,
                            disposition_id=row.disposition_id,
                            writeback_id=row.writeback_id,
                            idempotency_key=row.idempotency_key,
                            command_payload_sha256=row.command_payload_sha256,
                            command=command,
                            adapter=adapter,
                            provider_job_id=(
                                latest_receipt.provider_job_id
                                if latest_receipt is not None
                                else None
                            ),
                        )
                    )
        return claims

    async def _lookup_paused_outbox(
        self,
        claim: _PausedLookupClaim,
    ) -> _PausedLookupOutcome:
        """Perform provider lookup outside any database transaction."""
        caps = claim.adapter.capabilities()
        if not (caps.supports_lookup_by_idempotency or caps.supports_status_query):
            return _PausedLookupOutcome(
                kind=_PausedLookupKind.DEGRADED,
                error_code="lookup_unsupported",
                detail="adapter lacks lookup/status capability; manual adjudication required",
            )
        try:
            with disposition_span(
                "disposition.lookup_reconcile",
                event_id=claim.event_id,
                action_id=claim.action_id,
                disposition_id=claim.disposition_id,
                writeback_id=claim.writeback_id,
            ):
                lookup_receipt: DispositionReceipt | None = None
                if caps.supports_lookup_by_idempotency:
                    lookup_receipt = await claim.adapter.lookup_submission(
                        claim.idempotency_key,
                        claim.command.source_locator,
                    )
                if lookup_receipt is None and caps.supports_status_query and claim.provider_job_id:
                    lookup_receipt = await claim.adapter.get_status(claim.provider_job_id)
        except Exception as exc:
            logger.warning(
                "paused outbox lookup degraded outbox=%s error=%s",
                claim.outbox_id,
                type(exc).__name__,
            )
            return _PausedLookupOutcome(
                kind=_PausedLookupKind.DEGRADED,
                error_code="lookup_degraded",
                detail=f"{type(exc).__name__}: {exc}",
            )
        if lookup_receipt is not None:
            return _PausedLookupOutcome(
                kind=_PausedLookupKind.FOUND,
                receipt=lookup_receipt,
            )
        if caps.supports_lookup_by_idempotency:
            return _PausedLookupOutcome(kind=_PausedLookupKind.NOT_FOUND)
        return _PausedLookupOutcome(
            kind=_PausedLookupKind.DEGRADED,
            error_code="lookup_inconclusive",
            detail="status query unavailable without a provider job id",
        )

    async def _apply_paused_lookup_outcome(
        self,
        claim: _PausedLookupClaim,
        outcome: _PausedLookupOutcome,
    ) -> tuple[bool, str | None, WritebackStatus | None]:
        """Apply a lookup result only if the reconciliation lease still matches."""
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == claim.outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    return False, None, None
                if (
                    OutboxDeliveryStatus(outbox.delivery_status) is not OutboxDeliveryStatus.PAUSED
                    or outbox.locked_by != claim.token
                    or outbox.superseded_by_disposition_id is not None
                    or outbox.idempotency_key != claim.idempotency_key
                    or outbox.command_payload_sha256 != claim.command_payload_sha256
                ):
                    return False, None, None

                outbox.locked_by = None
                outbox.locked_at = None
                outbox.lease_expires_at = None
                outbox.next_retry_at = None
                outbox.updated_at = now
                action = await session.get(orm.Action, outbox.action_id, with_for_update=True)

                if outcome.kind is _PausedLookupKind.DEGRADED:
                    outbox.latest_writeback_status = WritebackStatus.UNKNOWN.value
                    outbox.last_error_code = outcome.error_code or "lookup_degraded"
                    outbox.last_error_detail = self._truncate_error_detail(
                        outcome.detail or "lookup inconclusive; outbox remains paused"
                    )
                    _mirror_writeback_status_to_action(action, WritebackStatus.UNKNOWN.value)
                    return False, outbox.event_id, WritebackStatus.UNKNOWN

                if outcome.kind is _PausedLookupKind.NOT_FOUND:
                    if is_deterministic_adapter_rejection_code(
                        getattr(outbox, "last_error_code", None),
                    ):
                        rejection_code = outbox.last_error_code or "adapter_validation_error"
                        await self._apply_deterministic_rejection_terminal_state(
                            session,
                            outbox,
                            action,
                            now=now,
                            from_status=OutboxDeliveryStatus.PAUSED,
                            error_code=rejection_code,
                            error_detail=(
                                "pre-submit deterministic rejection; lookup retry blocked"
                            ),
                            adapter_label=claim.adapter.name,
                        )
                        return True, outbox.event_id, WritebackStatus.FAILED
                    if not claim.adapter.allows_safe_retry():
                        outbox.latest_writeback_status = WritebackStatus.UNKNOWN.value
                        outbox.last_error_code = "lookup_not_found"
                        outbox.last_error_detail = self._truncate_error_detail(
                            "lookup found no submission and adapter does not allow safe retry"
                        )
                        _mirror_writeback_status_to_action(action, WritebackStatus.UNKNOWN.value)
                        return False, outbox.event_id, WritebackStatus.UNKNOWN
                    current_status = (
                        WritebackStatus(outbox.latest_writeback_status)
                        if outbox.latest_writeback_status
                        else WritebackStatus.UNKNOWN
                    )
                    validate_writeback_status_transition(
                        current_status,
                        WritebackStatus.PENDING,
                        lookup_never_accepted=True,
                        adapter_allows_safe_retry=True,
                    )
                    outbox.latest_writeback_status = WritebackStatus.PENDING.value
                    outbox.last_error_code = "lookup_never_accepted"
                    outbox.last_error_detail = self._truncate_error_detail(
                        "lookup confirmed never-accepted; safe-retry re-enqueued"
                    )
                    validate_outbox_delivery_transition(
                        OutboxDeliveryStatus.PAUSED,
                        OutboxDeliveryStatus.READY,
                    )
                    outbox.delivery_status = OutboxDeliveryStatus.READY.value
                    _mirror_writeback_status_to_action(action, WritebackStatus.PENDING.value)
                    record_writeback_retry(adapter=claim.adapter.name)
                    return True, outbox.event_id, WritebackStatus.PENDING

                lookup_receipt = outcome.receipt
                assert lookup_receipt is not None
                if lookup_receipt.status is WritebackStatus.UNKNOWN:
                    outbox.latest_writeback_status = WritebackStatus.UNKNOWN.value
                    outbox.last_error_code = "lookup_unknown"
                    outbox.last_error_detail = self._truncate_error_detail(
                        "lookup inconclusive; outbox remains paused"
                    )
                    _mirror_writeback_status_to_action(action, WritebackStatus.UNKNOWN.value)
                    return False, outbox.event_id, WritebackStatus.UNKNOWN

                current_status = (
                    WritebackStatus(outbox.latest_writeback_status)
                    if outbox.latest_writeback_status
                    else WritebackStatus.UNKNOWN
                )
                validate_writeback_status_transition(
                    current_status,
                    lookup_receipt.status,
                    evidence_adjudication=True,
                )
                parsed_receipt = await self._append_receipt(
                    session,
                    outbox,
                    receipt=lookup_receipt,
                )
                outbox.latest_writeback_status = parsed_receipt.status.value
                validate_outbox_delivery_transition(
                    OutboxDeliveryStatus.PAUSED,
                    OutboxDeliveryStatus.DELIVERED,
                    lookup_confirmed_submission=True,
                )
                outbox.delivery_status = OutboxDeliveryStatus.DELIVERED.value
                outbox.delivered_at = now
                outbox.last_error_code = None
                outbox.last_error_detail = None
                _mirror_writeback_status_to_action(action, parsed_receipt.status.value)
                if action is not None:
                    await self._apply_receipt_execution_projection(
                        session,
                        action,
                        outbox,
                        claim.command,
                        parsed_receipt,
                        adapter_label=claim.adapter.name,
                    )
                record_writeback(
                    status=parsed_receipt.status.value,
                    adapter=claim.adapter.name,
                )
                return True, outbox.event_id, parsed_receipt.status

    async def _release_paused_lookup_claim(
        self,
        claim: _PausedLookupClaim,
        *,
        error_code: str,
        detail: str,
    ) -> None:
        """Release a failed reconciliation token without exposing the row to delivery."""
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == claim.outbox_id)
                    .with_for_update()
                )
                if (
                    outbox is None
                    or OutboxDeliveryStatus(outbox.delivery_status)
                    is not OutboxDeliveryStatus.PAUSED
                    or outbox.locked_by != claim.token
                ):
                    return
                outbox.locked_by = None
                outbox.locked_at = None
                outbox.lease_expires_at = None
                outbox.last_error_code = error_code
                outbox.last_error_detail = self._truncate_error_detail(detail)
                outbox.updated_at = datetime.now(UTC)

    def _release_leased_outbox_to_dead_letter(
        self,
        outbox: orm.DispositionOutbox,
        *,
        now: datetime,
        error_code: str,
        error_detail: str | None = None,
    ) -> OutboxDeliveryStatus:
        """Terminal outbox state for non-retryable delivery failures (e.g. guardrail)."""
        current = OutboxDeliveryStatus(outbox.delivery_status)
        if current is not OutboxDeliveryStatus.LEASED:
            return current

        outbox.last_error_code = error_code
        if error_detail is not None:
            outbox.last_error_detail = self._truncate_error_detail(error_detail)
        outbox.locked_by = None
        outbox.locked_at = None
        outbox.lease_expires_at = None
        outbox.updated_at = now
        validate_outbox_delivery_transition(current, OutboxDeliveryStatus.DEAD_LETTER)
        outbox.delivery_status = OutboxDeliveryStatus.DEAD_LETTER.value
        outbox.next_retry_at = None
        record_writeback_dead_letter(
            adapter=self._adapter_label(outbox),
            error_code=error_code,
        )
        return OutboxDeliveryStatus.DEAD_LETTER

    def _block_outbox_for_writeback_fence(
        self,
        outbox: orm.DispositionOutbox,
        *,
        now: datetime,
        error_detail: str,
    ) -> OutboxDeliveryStatus:
        """Fail-closed delivery block when live/XDR writeback fences are closed (ISSUE-222)."""
        current = OutboxDeliveryStatus(outbox.delivery_status)
        if current is OutboxDeliveryStatus.LEASED:
            return self._release_leased_outbox_to_dead_letter(
                outbox,
                now=now,
                error_code=WRITEBACK_FENCE_BLOCKED_ERROR_CODE,
                error_detail=error_detail,
            )

        outbox.last_error_code = WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        outbox.last_error_detail = self._truncate_error_detail(error_detail)
        outbox.updated_at = now
        outbox.next_retry_at = None
        validate_outbox_delivery_transition(current, OutboxDeliveryStatus.DEAD_LETTER)
        outbox.delivery_status = OutboxDeliveryStatus.DEAD_LETTER.value
        record_writeback_dead_letter(
            adapter=self._adapter_label(outbox),
            error_code=WRITEBACK_FENCE_BLOCKED_ERROR_CODE,
        )
        return OutboxDeliveryStatus.DEAD_LETTER

    @staticmethod
    async def _lock_action_after_execution_job(
        session: AsyncSession,
        action_id: str,
    ) -> orm.Action | None:
        execution_job_id = await session.scalar(
            select(orm.Action.execution_job_id).where(orm.Action.action_id == action_id)
        )
        if execution_job_id:
            await session.get(
                orm.ActionExecutionJob,
                execution_job_id,
                with_for_update=True,
            )
        return await session.get(orm.Action, action_id, with_for_update=True)

    async def _apply_deterministic_rejection_terminal_state(
        self,
        session: AsyncSession,
        outbox: orm.DispositionOutbox,
        action: orm.Action | None,
        *,
        now: datetime,
        from_status: OutboxDeliveryStatus,
        error_code: str,
        error_detail: str,
        adapter_label: str,
    ) -> DispositionReceipt:
        """Shared DEAD_LETTER terminalization for definitive adapter rejections (ISSUE-300)."""
        detail = self._truncate_error_detail(error_detail)
        outbox.last_error_code = error_code
        outbox.last_error_detail = detail
        outbox.latest_writeback_status = WritebackStatus.FAILED.value
        outbox.locked_by = None
        outbox.locked_at = None
        outbox.lease_expires_at = None
        outbox.next_retry_at = None
        outbox.updated_at = now
        validate_outbox_delivery_transition(from_status, OutboxDeliveryStatus.DEAD_LETTER)
        outbox.delivery_status = OutboxDeliveryStatus.DEAD_LETTER.value
        receipt = await self._append_receipt(
            session,
            outbox,
            status=WritebackStatus.FAILED,
            provider_message=detail,
        )
        _mirror_writeback_status_to_action(action, WritebackStatus.FAILED.value)
        if action is not None:
            await self._apply_action_terminal_from_receipt(
                session,
                action,
                receipt,
                adapter_label=adapter_label,
            )
            command = DispositionCommand.model_validate(outbox.command_payload)
            await self._persist_execution_job_from_receipt(
                session,
                action,
                receipt,
                command=command,
                outbox=outbox,
            )
        record_writeback(status=WritebackStatus.FAILED.value, adapter=adapter_label)
        record_writeback_dead_letter(adapter=adapter_label, error_code=error_code)
        return receipt

    async def _mark_delivery_deterministic_rejection(
        self,
        outbox_id: str,
        *,
        error_code: str,
        error_detail: str,
    ) -> None:
        """Terminalize a definitive adapter rejection without PAUSED/lookup retry."""
        now = datetime.now(UTC)
        event_id: str | None = None
        writeback_id: str | None = None
        adapter_label = "unknown"
        detail = self._truncate_error_detail(error_detail)
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    return
                current = OutboxDeliveryStatus(outbox.delivery_status)
                if current is not OutboxDeliveryStatus.LEASED:
                    return
                adapter_label = self._adapter_label(outbox)
                action = await self._lock_action_after_execution_job(
                    session,
                    outbox.action_id,
                )
                await self._apply_deterministic_rejection_terminal_state(
                    session,
                    outbox,
                    action,
                    now=now,
                    from_status=current,
                    error_code=error_code,
                    error_detail=detail,
                    adapter_label=adapter_label,
                )
                event_id = outbox.event_id
                writeback_id = outbox.writeback_id

        if event_id is None or writeback_id is None:
            return
        await self._sync_writeback_summary(event_id)
        await self._maybe_resume(event_id)
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "writeback_updated",
                {"writeback_id": writeback_id, "status": WritebackStatus.FAILED.value},
            )

    async def _mark_delivery_conflict(
        self,
        outbox_id: str,
        *,
        error_code: str,
        error_detail: str,
    ) -> None:
        """Persist a definitive provider conflict without ambiguous PAUSED recovery."""
        now = datetime.now(UTC)
        event_id: str | None = None
        writeback_id: str | None = None
        adapter_label = "unknown"
        detail = self._truncate_error_detail(error_detail)
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    return
                current = OutboxDeliveryStatus(outbox.delivery_status)
                if current is not OutboxDeliveryStatus.LEASED:
                    return
                outbox.last_error_code = error_code
                outbox.last_error_detail = detail
                outbox.latest_writeback_status = WritebackStatus.CONFLICT.value
                outbox.locked_by = None
                outbox.locked_at = None
                outbox.lease_expires_at = None
                outbox.next_retry_at = None
                outbox.updated_at = now
                receipt = await self._append_receipt(
                    session,
                    outbox,
                    status=WritebackStatus.CONFLICT,
                    provider_message=detail,
                )
                validate_outbox_delivery_transition(
                    current,
                    OutboxDeliveryStatus.DELIVERED,
                )
                outbox.delivery_status = OutboxDeliveryStatus.DELIVERED.value
                outbox.delivered_at = now
                action = await self._lock_action_after_execution_job(
                    session,
                    outbox.action_id,
                )
                _mirror_writeback_status_to_action(action, WritebackStatus.CONFLICT.value)
                if action is not None:
                    await self._apply_action_terminal_from_receipt(
                        session,
                        action,
                        receipt,
                        adapter_label=self._adapter_label(outbox),
                    )
                    command = DispositionCommand.model_validate(outbox.command_payload)
                    await self._persist_execution_job_from_receipt(
                        session,
                        action,
                        receipt,
                        command=command,
                        outbox=outbox,
                    )
                event_id = outbox.event_id
                writeback_id = outbox.writeback_id
                adapter_label = self._adapter_label(outbox)

        if event_id is None or writeback_id is None:
            return
        record_writeback(status=WritebackStatus.CONFLICT.value, adapter=adapter_label)
        await self._sync_writeback_summary(event_id)
        await self._maybe_resume(event_id)
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "writeback_updated",
                {"writeback_id": writeback_id, "status": WritebackStatus.CONFLICT.value},
            )

    async def _mark_delivery_paused_unknown(
        self,
        outbox_id: str,
        *,
        error_code: str,
        error_detail: str,
    ) -> None:
        """Persist an ambiguous delivery outcome as UNKNOWN + PAUSED."""
        now = datetime.now(UTC)
        event_id: str | None = None
        writeback_id: str | None = None
        adapter_label = "unknown"
        detail = self._truncate_error_detail(error_detail)
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    return
                current = OutboxDeliveryStatus(outbox.delivery_status)
                if current is not OutboxDeliveryStatus.LEASED:
                    return
                outbox.latest_writeback_status = WritebackStatus.UNKNOWN.value
                self._pause_outbox_after_unknown_submission(
                    outbox,
                    now=now,
                    error_code=error_code,
                    error_detail=detail,
                )
                await self._append_receipt(
                    session,
                    outbox,
                    status=WritebackStatus.UNKNOWN,
                    provider_message=detail,
                )
                action = await session.get(orm.Action, outbox.action_id, with_for_update=True)
                _mirror_writeback_status_to_action(action, WritebackStatus.UNKNOWN.value)
                event_id = outbox.event_id
                writeback_id = outbox.writeback_id
                adapter_label = self._adapter_label(outbox)

        if event_id is None or writeback_id is None:
            return
        record_writeback(status=WritebackStatus.UNKNOWN.value, adapter=adapter_label)
        await self._sync_writeback_summary(event_id)
        await self._maybe_resume(event_id)
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "writeback_updated",
                {"writeback_id": writeback_id, "status": WritebackStatus.UNKNOWN.value},
            )

    def _finalize_superseded_head(
        self,
        prior_head: orm.DispositionOutbox,
        *,
        superseded_by_disposition_id: str,
        now: datetime,
    ) -> None:
        """Write lineage and terminate undelivered delivery for a superseded head (ISSUE-273)."""
        prior_head.superseded_by_disposition_id = superseded_by_disposition_id
        raw_status = prior_head.delivery_status or OutboxDeliveryStatus.READY.value
        current = OutboxDeliveryStatus(raw_status)
        if current in {OutboxDeliveryStatus.DELIVERED, OutboxDeliveryStatus.DEAD_LETTER}:
            return
        prior_head.last_error_code = OUTBOX_SUPERSEDED_ERROR_CODE
        prior_head.last_error_detail = self._truncate_error_detail(
            f"superseded by disposition {superseded_by_disposition_id}",
        )
        prior_head.locked_by = None
        prior_head.locked_at = None
        prior_head.lease_expires_at = None
        prior_head.next_retry_at = None
        prior_head.updated_at = now
        validate_outbox_delivery_transition(current, OutboxDeliveryStatus.DEAD_LETTER)
        prior_head.delivery_status = OutboxDeliveryStatus.DEAD_LETTER.value
        record_writeback_dead_letter(
            adapter=self._adapter_label(prior_head),
            error_code=OUTBOX_SUPERSEDED_ERROR_CODE,
        )

    def _block_superseded_outbox(
        self,
        outbox: orm.DispositionOutbox,
        *,
        now: datetime,
    ) -> OutboxDeliveryStatus:
        """Fail-closed pre-egress block for superseded or stale active heads (ISSUE-273)."""
        current = OutboxDeliveryStatus(outbox.delivery_status)
        if current is OutboxDeliveryStatus.LEASED:
            return self._release_leased_outbox_to_dead_letter(
                outbox,
                now=now,
                error_code=OUTBOX_SUPERSEDED_ERROR_CODE,
                error_detail="superseded outbox head cannot egress",
            )

        outbox.last_error_code = OUTBOX_SUPERSEDED_ERROR_CODE
        outbox.last_error_detail = self._truncate_error_detail(
            "superseded outbox head cannot egress",
        )
        outbox.updated_at = now
        outbox.next_retry_at = None
        if current is not OutboxDeliveryStatus.DEAD_LETTER:
            validate_outbox_delivery_transition(current, OutboxDeliveryStatus.DEAD_LETTER)
            outbox.delivery_status = OutboxDeliveryStatus.DEAD_LETTER.value
            record_writeback_dead_letter(
                adapter=self._adapter_label(outbox),
                error_code=OUTBOX_SUPERSEDED_ERROR_CODE,
            )
        return OutboxDeliveryStatus.DEAD_LETTER

    async def _assert_active_head_for_delivery(
        self,
        session: AsyncSession,
        outbox: orm.DispositionOutbox,
        command: DispositionCommand,
    ) -> bool:
        """Pre-egress CAS: only the current active head may egress (ISSUE-273)."""
        if command.intent_kind is not DispositionIntentKind.EVENT_STATUS_UPDATE:
            return True
        active_head_id = await session.scalar(
            select(orm.DispositionOutbox.disposition_id)
            .where(
                orm.DispositionOutbox.event_id == outbox.event_id,
                orm.DispositionOutbox.closure_cycle == outbox.closure_cycle,
                orm.DispositionOutbox.intent_kind == command.intent_kind.value,
                orm.DispositionOutbox.logical_slot == outbox.logical_slot,
                orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
            )
            .order_by(orm.DispositionOutbox.created_at.desc())
            .limit(1)
        )
        return active_head_id == outbox.disposition_id

    async def _mark_delivery_waiting_retry(
        self,
        outbox_id: str,
        *,
        error_code: str = "delivery_failed",
        error_detail: str | None = None,
    ) -> None:
        """Release a leased outbox back to the retry queue after a failed delivery attempt."""
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    return
                self._release_leased_outbox_after_failure(
                    outbox,
                    now=now,
                    error_code=error_code,
                    error_detail=error_detail,
                )

    async def _mark_delivery_dead_letter(
        self,
        outbox_id: str,
        *,
        error_code: str,
        error_detail: str | None = None,
    ) -> None:
        """Move a leased outbox to DEAD_LETTER for non-retryable failures."""
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                outbox = await session.scalar(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.outbox_id == outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    return
                self._release_leased_outbox_to_dead_letter(
                    outbox,
                    now=now,
                    error_code=error_code,
                    error_detail=error_detail,
                )


class OutboxWorker:
    def __init__(self, service: DispositionSyncService) -> None:
        self._service = service

    async def run_once(self, *, limit: int = 10) -> int:
        await self._service.reconcile_paused_outboxes(limit=limit)
        claimed = await self._claim_batch(limit=limit)
        for outbox_id in claimed:
            try:
                await self._service._deliver_outbox(outbox_id)
            except (
                GuardrailViolationError,
                WritebackConflictError,
                ValidationError,
                WritebackUnsupportedError,
            ) as exc:
                kind, code = classify_disposition_delivery_error(exc)
                if kind is DispositionDeliveryErrorKind.GUARDRAIL:
                    logger.warning("outbox delivery blocked by guard outbox=%s", outbox_id)
                    await self._service._mark_delivery_dead_letter(
                        outbox_id,
                        error_code="guardrail_blocked",
                        error_detail=str(exc),
                    )
                elif kind is DispositionDeliveryErrorKind.CONFLICT:
                    logger.warning(
                        "outbox delivery conflict outbox=%s error_code=%s",
                        outbox_id,
                        code,
                    )
                    await self._service._mark_delivery_conflict(
                        outbox_id,
                        error_code=code or "version_conflict",
                        error_detail=str(exc),
                    )
                elif kind is DispositionDeliveryErrorKind.DETERMINISTIC_REJECTION:
                    logger.warning(
                        "outbox delivery deterministic rejection outbox=%s error_code=%s",
                        outbox_id,
                        code,
                    )
                    await self._service._mark_delivery_deterministic_rejection(
                        outbox_id,
                        error_code=code or "adapter_validation_error",
                        error_detail=str(exc),
                    )
                else:
                    logger.exception(
                        "outbox delivery validation outcome ambiguous; pausing for lookup "
                        "outbox=%s",
                        outbox_id,
                    )
                    await self._service._mark_delivery_paused_unknown(
                        outbox_id,
                        error_code="delivery_outcome_unknown",
                        error_detail=f"{type(exc).__name__}: {exc}",
                    )
            except Exception as exc:
                logger.exception(
                    "outbox delivery outcome ambiguous; pausing for lookup outbox=%s",
                    outbox_id,
                )
                await self._service._mark_delivery_paused_unknown(
                    outbox_id,
                    error_code="delivery_outcome_unknown",
                    error_detail=f"{type(exc).__name__}: {exc}",
                )
        return len(claimed)

    async def _claim_batch(self, *, limit: int) -> list[str]:
        now = datetime.now(UTC)
        claimed: list[str] = []
        paused_updates: list[tuple[str, str]] = []
        async with self._service._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.DispositionOutbox)
                        .where(
                            orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                            or_(
                                and_(
                                    orm.DispositionOutbox.delivery_status
                                    == OutboxDeliveryStatus.READY.value,
                                    or_(
                                        orm.DispositionOutbox.next_retry_at.is_(None),
                                        orm.DispositionOutbox.next_retry_at <= now,
                                    ),
                                ),
                                and_(
                                    orm.DispositionOutbox.delivery_status
                                    == OutboxDeliveryStatus.WAITING_RETRY.value,
                                    orm.DispositionOutbox.next_retry_at.is_not(None),
                                    orm.DispositionOutbox.next_retry_at <= now,
                                ),
                                and_(
                                    orm.DispositionOutbox.delivery_status
                                    == OutboxDeliveryStatus.WAITING_RETRY.value,
                                    orm.DispositionOutbox.next_retry_at.is_(None),
                                ),
                                and_(
                                    orm.DispositionOutbox.delivery_status
                                    == OutboxDeliveryStatus.LEASED.value,
                                    or_(
                                        orm.DispositionOutbox.lease_expires_at.is_(None),
                                        orm.DispositionOutbox.lease_expires_at <= now,
                                    ),
                                ),
                            ),
                        )
                        .order_by(orm.DispositionOutbox.created_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    if row.superseded_by_disposition_id is not None:
                        continue
                    current = OutboxDeliveryStatus(row.delivery_status)
                    if current is OutboxDeliveryStatus.WAITING_RETRY and row.next_retry_at is None:
                        backoff_attempt = max(1, int(row.attempt) + 1)
                        row.next_retry_at = now + timedelta(
                            seconds=self._service._outbox_retry_backoff_seconds(
                                backoff_attempt,
                            ),
                        )
                        row.updated_at = now
                        continue
                    if current is OutboxDeliveryStatus.LEASED and (
                        row.lease_expires_at is None or row.lease_expires_at <= now
                    ):
                        self._service._release_leased_outbox_after_lease_expiry(
                            row,
                            now=now,
                        )
                        action = await session.get(
                            orm.Action,
                            row.action_id,
                            with_for_update=True,
                        )
                        _mirror_writeback_status_to_action(
                            action,
                            WritebackStatus.UNKNOWN.value,
                        )
                        paused_updates.append((row.event_id, row.writeback_id))
                        continue
                    validate_outbox_delivery_transition(
                        current,
                        OutboxDeliveryStatus.LEASED,
                    )
                    row.delivery_status = OutboxDeliveryStatus.LEASED.value
                    row.locked_by = self._service._worker_id
                    row.locked_at = now
                    row.lease_expires_at = now + timedelta(seconds=_DEFAULT_LEASE_SECONDS)
                    if row.created_at is not None:
                        observe_writeback_queue_age((now - row.created_at).total_seconds())
                    claimed.append(row.outbox_id)
        for event_id, writeback_id in paused_updates:
            await self._service._sync_writeback_summary(event_id)
            await self._service._maybe_resume(event_id)
            if self._service._bus is not None:
                await self._service._bus.publish_event(
                    event_id,
                    "writeback_updated",
                    {"writeback_id": writeback_id, "status": WritebackStatus.UNKNOWN.value},
                )
        return claimed


__all__ = ["DispositionSyncService", "OutboxWorker", "ResumeInvestigationHook"]
