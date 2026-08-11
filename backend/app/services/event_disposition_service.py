"""Activate deferred terminal disposition actions (ISSUE-059A)."""

from __future__ import annotations

import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.response_agent import compute_template_hash, derive_disposition_idempotency_key
from app.core.errors import GuardrailViolationError, ShadowTraceError, ValidationError
from app.core.event_bus import EventBus
from app.db import models as orm
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import VerificationPhase, VerificationResult
from app.models.context import EventContext
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    DispositionIntentKind,
    DispositionPolicy,
    FinalVerdict,
    SourceDisposition,
    WritebackReadiness,
)
from app.models.ids import new_disposition_id
from app.models.verification_readiness import has_immediate_effect_pending
from app.models.workflow import validate_action_status_transition
from app.services.context_service import EventContextStore
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.terminal_disposition_resolver import TerminalDispositionResolver

logger = logging.getLogger(__name__)

_OPERATOR = "EventDispositionService"
_LOGICAL_SLOT = "terminal"
_ACTIVE_HEAD_UNIQUE_INDEX = "uq_disposition_outbox_event_status_active_head"


def _is_active_head_unique_violation(exc: IntegrityError) -> bool:
    """True when exc is the event-scoped terminal active-head partial unique index."""
    orig = exc.orig
    if orig is not None:
        diag = getattr(orig, "diag", None)
        if diag is not None:
            name = getattr(diag, "constraint_name", None)
            if name == _ACTIVE_HEAD_UNIQUE_INDEX:
                return True
        if _ACTIVE_HEAD_UNIQUE_INDEX in str(orig):
            return True
    return _ACTIVE_HEAD_UNIQUE_INDEX in str(exc)


class DispositionActivationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str | None = None
    activated: bool
    skipped_reason: (
        Literal[
            "not_required",
            "already_submitted",
            "effect_not_ready",
            "not_approved",
            "capability_blocked",
            "terminal_not_in_approved_set",
            "concurrent_head_conflict",
        ]
        | None
    ) = None
    derived_disposition: SourceDisposition | None = None
    disposition_id: str | None = None
    writeback_id: str | None = None


def _action_from_row(row: orm.Action) -> Action:
    return Action.model_validate(
        {
            "action_id": row.action_id,
            "event_id": row.event_id,
            "plan_revision": row.plan_revision,
            "action_fingerprint": row.action_fingerprint,
            "action_category": row.action_category,
            "action_name": row.action_name,
            "tool_name": row.tool_name,
            "action_level": row.action_level,
            "execution_phase": row.execution_phase,
            "activation_condition": row.activation_condition,
            "approved_operation_template_hash": row.approved_operation_template_hash,
            "approved_terminal_dispositions": row.approved_terminal_dispositions or [],
            "target_type": row.target_type,
            "target": row.target,
            "parameters": row.parameters or {},
            "status": row.status,
            "auto_execute": row.auto_execute,
            "reason": row.reason,
            "impact_assessment": row.impact_assessment,
            "playbook_id": row.playbook_id,
            "provider_name": row.provider_name,
            "execution_owner": row.execution_owner,
            "execution_job_id": row.execution_job_id,
            "tool_call_id": row.tool_call_id,
            "idempotency_key": row.idempotency_key,
            "writeback_required": row.writeback_required,
            "writeback_applicable": row.writeback_applicable,
            "writeback_readiness": row.writeback_readiness,
            "writeback_block_reason": row.writeback_block_reason,
            "writeback_status": row.writeback_status,
            "disposition_source_ref": row.disposition_source_ref,
            "superseded_by_revision": row.superseded_by_revision,
            "executed_at": row.executed_at,
            "effect_verification_status": row.effect_verification_status,
            "rollback_status": row.rollback_status,
            "source_action_id": row.source_action_id,
        }
    )


class EventDispositionService:
    """Activate POST_VERIFY deferred terminal disposition and enqueue EVENT_STATUS_UPDATE."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        disposition_sync: DispositionSyncService,
        context_store: EventContextStore,
        resolver: TerminalDispositionResolver | None = None,
        factory: DispositionCommandFactory | None = None,
        event_bus: EventBus | None = None,
        event_disposition_supported: bool = True,
        decision_record_service: Any | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._sync = disposition_sync
        self._store = context_store
        self._resolver = resolver or TerminalDispositionResolver()
        self._factory = factory or DispositionCommandFactory()
        self._bus = event_bus
        self._event_disposition_supported = event_disposition_supported
        self._decision_records = decision_record_service

    async def get_deferred_action(self, event_id: str, plan_revision: int) -> Action | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.Action)
                .where(
                    orm.Action.event_id == event_id,
                    orm.Action.plan_revision == plan_revision,
                    orm.Action.tool_name == TERMINAL_DISPOSITION_TOOL,
                    orm.Action.execution_phase == ActionExecutionPhase.POST_VERIFY.value,
                    orm.Action.superseded_by_revision.is_(None),
                )
                .order_by(orm.Action.action_id.asc())
                .limit(1)
            )
        if row is None:
            return None
        return _action_from_row(row)

    async def derive_terminal_disposition(self, event_id: str) -> SourceDisposition:
        event_row, context, deferred = await self._load_activation_context(event_id)
        if deferred is None:
            raise ValidationError(
                "no deferred terminal disposition action",
                details={"event_id": event_id},
            )
        approved = _approved_list(deferred)
        resolve = self._resolver.resolve(
            final_verdict=FinalVerdict(event_row.final_verdict),
            verification=_verification_from_context(context),
            approved_terminal_dispositions=approved,
            disposition_only=bool(context.disposition_only_intent),
            disposition_policy=DispositionPolicy(event_row.disposition_policy),
            writeback_readiness=WritebackReadiness(deferred.writeback_readiness),
            event_disposition_supported=self._event_disposition_supported,
        )
        if resolve.skipped_reason == "terminal_not_in_approved_set":
            raise ValidationError(
                "derived terminal disposition not in approved set",
                details={"event_id": event_id},
            )
        if resolve.skipped_reason == "capability_blocked" or resolve.need_manual_resolution:
            raise ValidationError(
                "terminal disposition cannot be derived safely",
                details={"event_id": event_id},
            )
        if resolve.disposition is None:
            raise ValidationError(
                "terminal disposition not required",
                details={"event_id": event_id},
            )
        return resolve.disposition

    async def activate_and_submit(
        self,
        event_id: str,
        plan_revision: int,
        principal_or_system: str,
    ) -> DispositionActivationResult:
        operator = principal_or_system or _OPERATOR
        event_row, context, deferred = await self._load_activation_context(
            event_id,
            plan_revision=plan_revision,
        )
        if deferred is None:
            return DispositionActivationResult(
                activated=False,
                skipped_reason="not_required",
            )
        if DispositionPolicy(event_row.disposition_policy) is DispositionPolicy.NOT_REQUIRED:
            return DispositionActivationResult(
                action_id=deferred.action_id,
                activated=False,
                skipped_reason="not_required",
            )

        approved = _approved_list(deferred)
        verification = _verification_from_context(context)
        resolve = self._resolver.resolve(
            final_verdict=FinalVerdict(event_row.final_verdict),
            verification=verification,
            approved_terminal_dispositions=approved,
            disposition_only=bool(context.disposition_only_intent),
            disposition_policy=DispositionPolicy(event_row.disposition_policy),
            writeback_readiness=WritebackReadiness(deferred.writeback_readiness),
            event_disposition_supported=self._event_disposition_supported,
        )
        if resolve.skipped_reason == "terminal_not_in_approved_set":
            return DispositionActivationResult(
                action_id=deferred.action_id,
                activated=False,
                skipped_reason="terminal_not_in_approved_set",
            )
        if resolve.skipped_reason == "capability_blocked":
            return DispositionActivationResult(
                action_id=deferred.action_id,
                activated=False,
                skipped_reason="capability_blocked",
            )
        if resolve.need_manual_resolution or resolve.disposition is None:
            return DispositionActivationResult(
                action_id=deferred.action_id,
                activated=False,
                skipped_reason="effect_not_ready",
            )

        effect_resolution_ready = await self._after_effect_resolution_ready(
            event_row=event_row,
            context=context,
            plan_revision=plan_revision,
        )
        if not effect_resolution_ready:
            return DispositionActivationResult(
                action_id=deferred.action_id,
                activated=False,
                skipped_reason="effect_not_ready",
                derived_disposition=resolve.disposition,
            )

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    row = await session.get(
                        orm.Action,
                        deferred.action_id,
                        with_for_update=True,
                    )
                    if row is None:
                        raise ValidationError(
                            "deferred action missing at activation",
                            details={"action_id": deferred.action_id},
                        )
                    action = _action_from_row(row)
                    closure_cycle = int(action.plan_revision)

                    existing = await _find_active_terminal_outbox(
                        session,
                        action_id=action.action_id,
                        closure_cycle=closure_cycle,
                    )
                    if existing is not None:
                        return DispositionActivationResult(
                            action_id=action.action_id,
                            activated=False,
                            skipped_reason="already_submitted",
                            derived_disposition=resolve.disposition,
                            disposition_id=existing.disposition_id,
                            writeback_id=existing.writeback_id,
                        )

                    status = ActionStatus(action.status)
                    if status is not ActionStatus.APPROVED:
                        return DispositionActivationResult(
                            action_id=action.action_id,
                            activated=False,
                            skipped_reason="not_approved",
                            derived_disposition=resolve.disposition,
                        )
                    if not action.writeback_applicable:
                        return DispositionActivationResult(
                            action_id=action.action_id,
                            activated=False,
                            skipped_reason="not_required",
                            derived_disposition=resolve.disposition,
                        )
                    readiness = WritebackReadiness(action.writeback_readiness)
                    if readiness is not WritebackReadiness.READY:
                        if readiness in {
                            WritebackReadiness.CAPABILITY_UNSUPPORTED,
                            WritebackReadiness.CAPABILITY_UNKNOWN,
                            WritebackReadiness.NOT_CONFIGURED,
                        }:
                            return DispositionActivationResult(
                                action_id=action.action_id,
                                activated=False,
                                skipped_reason="capability_blocked",
                                derived_disposition=resolve.disposition,
                            )
                        return DispositionActivationResult(
                            action_id=action.action_id,
                            activated=False,
                            skipped_reason="effect_not_ready",
                            derived_disposition=resolve.disposition,
                        )

                    if self._decision_records is not None:
                        await self._decision_records.assert_auto_disposition_allowed(
                            event_id,
                            session=session,
                        )

                    template_unchanged = _template_unchanged(action)
                    validate_action_status_transition(
                        ActionCategory(action.action_category),
                        status,
                        ActionStatus.EXECUTING,
                        execution_phase=ActionExecutionPhase.POST_VERIFY,
                        after_effect_resolution=True,
                        template_unchanged=template_unchanged,
                        has_job_or_outbox=False,
                    )

                    locator, source_record_id = await self._resolve_source(session, action)
                    token_row = await session.get(orm.SourceObject, source_record_id)
                    token = token_row.current_concurrency_token if token_row else None
                    disposition_id = new_disposition_id()
                    command = self._factory.build_event_status_update(
                        action,
                        source_locator=locator,
                        source_concurrency_token=token,
                        operator_id=operator,
                        disposition_id=disposition_id,
                        closure_cycle=closure_cycle,
                        target_disposition=resolve.disposition,
                    )
                    try:
                        await self._sync.enqueue_command(
                            session,
                            command=command,
                            event_id=event_id,
                            source_record_id=source_record_id,
                            logical_slot=_LOGICAL_SLOT,
                        )
                    except GuardrailViolationError:
                        return DispositionActivationResult(
                            action_id=action.action_id,
                            activated=False,
                            skipped_reason="capability_blocked",
                            derived_disposition=resolve.disposition,
                        )
                    row.status = ActionStatus.EXECUTING.value
                    outbox = await _find_active_terminal_outbox(
                        session,
                        action_id=action.action_id,
                        closure_cycle=closure_cycle,
                    )
                    if outbox is None:
                        raise ValidationError(
                            "outbox missing after enqueue",
                            details={"action_id": action.action_id},
                        )
                    result_disposition_id = outbox.disposition_id
                    result_writeback_id = outbox.writeback_id
                    result_action_id = action.action_id
                    result_outbox_id: str = outbox.outbox_id
        except IntegrityError as exc:
            # ISSUE-219: a concurrent activation of the same
            # (event_id, closure_cycle, logical_slot) won the active-head race;
            # the partial unique index rejected this insert and the transaction
            # has already been rolled back by the begin() context.  The winner's
            # head stays active — treat this activation as an idempotent no-op
            # carrying the winner's lineage (disposition_id/writeback_id).
            if _is_active_head_unique_violation(exc):
                async with self._session_factory() as conflict_session:
                    winner = await conflict_session.scalar(
                        select(orm.DispositionOutbox)
                        .where(
                            orm.DispositionOutbox.event_id == event_id,
                            orm.DispositionOutbox.closure_cycle == int(deferred.plan_revision),
                            orm.DispositionOutbox.intent_kind
                            == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                            orm.DispositionOutbox.logical_slot == _LOGICAL_SLOT,
                            orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                        )
                        .limit(1)
                    )
                return DispositionActivationResult(
                    action_id=deferred.action_id,
                    activated=False,
                    skipped_reason="concurrent_head_conflict",
                    derived_disposition=resolve.disposition,
                    disposition_id=winner.disposition_id if winner is not None else None,
                    writeback_id=winner.writeback_id if winner is not None else None,
                )
            raise

        # B1 fix (ISSUE-064): Synchronously deliver the outbox so the
        # adapter produces a receipt.  Without this the outbox row sits
        # in READY state forever and the P0 CONFIRMED receipt (via
        # readback) is never created.
        #
        # Delivery is best-effort in-process: if it fails the outbox
        # stays at READY and the outbox worker will retry.
        try:
            await self._sync.deliver_outbox(result_outbox_id)
        except (ShadowTraceError, OSError):
            logger.warning(
                "synchronous outbox delivery failed for %s; outbox worker will retry",
                result_outbox_id,
                exc_info=True,
            )

        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "disposition_submitted",
                {
                    "disposition_id": result_disposition_id,
                    "intent_kind": DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                },
            )

        return DispositionActivationResult(
            action_id=result_action_id,
            activated=True,
            derived_disposition=resolve.disposition,
            disposition_id=result_disposition_id,
            writeback_id=result_writeback_id,
        )

    async def _load_activation_context(
        self,
        event_id: str,
        *,
        plan_revision: int | None = None,
    ) -> tuple[orm.SecurityEvent, EventContext, Action | None]:
        revision = plan_revision
        async with self._session_factory() as session:
            event_row = await session.get(orm.SecurityEvent, event_id)
            if event_row is None:
                raise ValidationError("event not found", details={"event_id": event_id})
            if revision is None:
                value = await session.scalar(
                    select(func.max(orm.Action.plan_revision)).where(
                        orm.Action.event_id == event_id
                    )
                )
                revision = int(value or 1)
        context = await self._store.get_full_context(event_id)
        deferred = await self.get_deferred_action(event_id, int(revision))
        return event_row, context, deferred

    async def _after_effect_resolution_ready(
        self,
        *,
        event_row: orm.SecurityEvent,
        context: EventContext,
        plan_revision: int,
    ) -> bool:
        """Return True when POST_VERIFY terminal disposition may activate.

        Uses the same VerifyAgent ``effect`` phase facts that ISSUE-312 relies on
        for entity side-effect CLOSED convergence; entity submit receipts may
        remain ``ACCEPTED`` while this gate waits for independent effect proof.
        """
        if context.disposition_only_intent:
            if FinalVerdict(event_row.final_verdict) is not FinalVerdict.FALSE_POSITIVE:
                return False
            async with self._session_factory() as session:
                immediate_count = await session.scalar(
                    select(func.count())
                    .select_from(orm.Action)
                    .where(
                        orm.Action.event_id == event_row.event_id,
                        orm.Action.plan_revision == plan_revision,
                        orm.Action.execution_phase == ActionExecutionPhase.IMMEDIATE.value,
                        orm.Action.superseded_by_revision.is_(None),
                        orm.Action.tool_name != TERMINAL_DISPOSITION_TOOL,
                    )
                )
            return int(immediate_count or 0) == 0

        verification = _verification_from_context(context)
        if verification is None:
            return False
        if verification.verification_phase is not VerificationPhase.EFFECT:
            return False
        if verification.need_action_replan or verification.need_manual_resolution:
            return False
        if verification.overall_status.value in {
            "failed",
            "waiting",
            "manual_resolution",
        }:
            return False
        if has_immediate_effect_pending(verification):
            return False
        return True

    async def _resolve_source(
        self,
        session: AsyncSession,
        action: Action,
    ) -> tuple[SourceObjectLocator, str]:
        if action.disposition_source_ref is None:
            raise ValidationError(
                "action missing disposition_source_ref",
                details={"action_id": action.action_id},
            )
        locator = SourceObjectLocator.model_validate(action.disposition_source_ref)
        row = await session.scalar(
            select(orm.SourceObject.source_record_id).where(
                orm.SourceObject.source_product == locator.source_product,
                orm.SourceObject.source_tenant_id == locator.source_tenant_id,
                orm.SourceObject.connector_id == locator.connector_id,
                orm.SourceObject.source_kind == locator.source_kind.value,
                orm.SourceObject.source_object_id == locator.source_object_id,
            )
        )
        if row is None:
            raise ValidationError(
                "source object not found for disposition activation",
                details={"action_id": action.action_id},
            )
        return locator, str(row)


def _approved_list(action: Action) -> list[SourceDisposition]:
    result: list[SourceDisposition] = []
    for raw in action.approved_terminal_dispositions or []:
        try:
            result.append(
                raw if isinstance(raw, SourceDisposition) else SourceDisposition(str(raw))
            )
        except ValueError:
            continue
    return result


def _verification_from_context(context: EventContext) -> VerificationResult | None:
    raw = context.verification_result
    if raw is None:
        return None
    return VerificationResult.model_validate(raw)


def _template_unchanged(action: Action) -> bool:
    approved = _approved_list(action)
    current = compute_template_hash(approved)
    stored = action.approved_operation_template_hash or ""
    return stored == current


async def _find_active_terminal_outbox(
    session: AsyncSession,
    *,
    action_id: str,
    closure_cycle: int,
) -> orm.DispositionOutbox | None:
    """Return the active terminal outbox for this Action (idempotent replay).

    Scoped by ``action_id`` so a *different* Action on the same
    ``(event_id, closure_cycle)`` can still reach ``enqueue_command`` and
    supersede the prior event-level head (replan / concurrent activation).
    The event-scoped partial unique index remains the final single-head
    invariant; ``enqueue_command`` writes ``superseded_by_disposition_id``.
    """
    outbox: orm.DispositionOutbox | None = await session.scalar(
        select(orm.DispositionOutbox)
        .where(
            orm.DispositionOutbox.action_id == action_id,
            orm.DispositionOutbox.intent_kind == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            orm.DispositionOutbox.logical_slot == _LOGICAL_SLOT,
            orm.DispositionOutbox.closure_cycle == closure_cycle,
            orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
        )
        .limit(1)
    )
    return outbox


def ensure_terminal_idempotency_key(action: Action, *, plan_revision: int) -> str:
    """Align deferred action idempotency with outbox slot (tests/helpers)."""
    return derive_disposition_idempotency_key(
        action_id=action.action_id,
        plan_revision=plan_revision,
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        logical_slot=_LOGICAL_SLOT,
    )


__all__ = [
    "DispositionActivationResult",
    "EventDispositionService",
    "ensure_terminal_idempotency_key",
]
