"""Rollback compensation service with Saga support (ISSUE-061).

Implements ``rollback_action``, ``rollback_event`` and ``compensate`` as defined
in the ShadowTrace implementation plan §ISSUE-061.

Key invariants
--------------
* Rollback is not deletion — every rollback creates a persistent
  ``action_category=rollback`` Action row with ``source_action_id`` pointing
  to the original Action.
* The original Action is CAS'd SUCCESS/PARTIAL_SUCCESS → ROLLED_BACK only
  *after* the rollback effect has been independently verified.
* Compensation writebacks (COMPENSATION_RECORD) are created only for
  applicable original writebacks (ENTITY_ACTION_SUBMIT / EXECUTION_RESULT_RECORD).
* Non-rollbackable actions return ``rolled_back=False``,
  ``warning="not_rollbackable"`` without creating a rollback Action.
* UNKNOWN / PARTIAL_SUCCESS actions must never be auto-rollbacked.
* POST_VERIFY deferred Actions are excluded from entity rollback.

Scope boundaries (not in this service)
------------------------------------
* **Orchestration wiring**: ``get_rollback_service()`` in deps exposes the
  service for production injection; LangGraph / SuperAgent / false-positive
  CLOSED paths do not call ``rollback_event`` yet — that remains a follow-up
  orchestration Issue.
* **P1 late false-positive CLOSED gate**: requiring all COMPENSATION_RECORD
  writebacks to reach CONFIRMED before activating deferred EVENT_STATUS_UPDATE
  is enforced in EventDispositionService / workflow orchestration, not here.
  This service never fabricates terminal disposition Actions.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.rules.rollback_mapping import (
    get_rollback_tool,
    get_rollback_verify_tool,
    is_rollbackable,
)
from app.core.config import get_settings
from app.core.errors import AdapterNotFoundError
from app.core.event_bus import EventBus
from app.db import models as orm
from app.models.action import Action as ActionModel
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    CapabilityState,
    DispositionIntentKind,
    ExecutionOwner,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.ids import new_action_id, new_disposition_id
from app.models.rollback_result import (
    CompensationWritebackItem,
    RollbackEffectStatus,
    RollbackResult,
)
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.event_audit_log_service import EventAuditLogService
from app.tools.specs import baseline_tool_index

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _action_from_row(row: orm.Action) -> ActionModel:
    return ActionModel.model_validate(
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
            "updated_at": row.updated_at,
        }
    )


def _compute_rollback_fingerprint(
    event_id: str,
    plan_revision: int,
    source_action_id: str,
    rollback_tool: str,
) -> str:
    material = "|".join(
        (event_id, str(int(plan_revision)), "rollback", source_action_id, rollback_tool)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# Callback hook for executing a rollback action after it is persisted.
# Called with the rollback action_id and the operator; should return
# the updated Action model after execution.
ExecuteRollbackHook = Callable[
    [str, str],  # (rollback_action_id, operator)
    Awaitable[ActionModel],
]

# Callback hook for independently verifying rollback effect after execution.
VerifyRollbackEffectHook = Callable[
    [ActionModel, ActionModel],  # (original_action, rollback_action)
    Awaitable[RollbackEffectStatus],
]


class RollbackService:
    """Service for action rollback and Saga compensation (ISSUE-061)."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        audit: EventAuditLogService,
        execute_rollback: ExecuteRollbackHook | None = None,
        verify_rollback_effect: VerifyRollbackEffectHook | None = None,
        disposition_sync: Any = None,
        event_bus: EventBus | None = None,
        command_factory: DispositionCommandFactory | None = None,
        adapter_registry: Any = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit = audit
        self._execute_rollback = execute_rollback or _default_execute_rollback
        self._verify_rollback_effect = verify_rollback_effect or _default_verify_rollback_effect
        self._disposition_sync = disposition_sync
        self._bus = event_bus
        self._factory = command_factory or DispositionCommandFactory()
        self._adapter_registry = adapter_registry

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    async def rollback_action(
        self,
        action_id: str,
        operator: str,
        reason: str,
        *,
        automated: bool = False,
    ) -> RollbackResult:
        """Rollback a single response Action end-to-end.

        Creates a rollback Action, executes it, verifies the effect, and
        optionally CAS's the original Action to ROLLED_BACK.  Compensation
        writebacks are created for each applicable original writeback.
        """
        # --- Load & validate original Action ---------------------------------
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.Action, action_id, with_for_update=True)
                if row is None:
                    logger.warning(
                        "rollback_action called for non-existent action: %s by %s",
                        action_id,
                        operator,
                    )
                    return RollbackResult(
                        action_id=action_id,
                        rolled_back=False,
                        warning="action_not_found",
                    )
                original = _action_from_row(row)

                pre_check = _pre_check_rollbackable(original)
                if pre_check is not None:
                    # Audit the rejected rollback attempt per spec §降级策略
                    await self._audit.log_transition_in_session(
                        session,
                        original.event_id,
                        from_status=original.status.value,
                        to_status=None,
                        operator=operator,
                        reason=(
                            f"Rollback rejected for {action_id}: {pre_check.warning} — {reason}"
                        ),
                    )
                    await self._publish_rollback_event(
                        event_id=original.event_id,
                        action_id=action_id,
                        source_action_id=action_id,
                        operator=operator,
                        rolled_back=False,
                        rollback_effect_status=None,
                        warning=pre_check.warning,
                        rejected=True,
                    )
                    return pre_check

                rollback_tool = get_rollback_tool(original.tool_name)
                if rollback_tool is None:  # pragma: no cover — pre_check guarantees this
                    raise RuntimeError(
                        f"Rollback tool not found for {original.tool_name}; "
                        f"pre_check should have caught this for action {action_id}"
                    )

                # --- Create rollback Action ---------------------------------------
                comp_required = original.writeback_required and original.writeback_applicable
                plan_revision = original.plan_revision
                original_owner = original.execution_owner or ExecutionOwner.DIRECT_TOOL
                execution_owner, adapter_supports_comp = _resolve_rollback_owner_and_compensation(
                    original,
                    adapter_registry=self._adapter_registry,
                )

                fingerprint = _compute_rollback_fingerprint(
                    original.event_id, plan_revision, action_id, rollback_tool
                )

                tool_index = baseline_tool_index()
                tool_meta = tool_index.get(rollback_tool)
                action_level = str(tool_meta.action_level.value) if tool_meta else "l2"

                # Stable idempotency key: ensures retry safety across executions.
                rb_idem_material = "|".join(
                    (
                        original.event_id,
                        str(int(plan_revision)),
                        action_id,
                        rollback_tool,
                        "rollback",
                    )
                )
                idempotency_key = hashlib.sha256(rb_idem_material.encode("utf-8")).hexdigest()

                # Inherit disposition_source_ref from the original Action so the
                # rollback targets the same source object for XDR_MANAGED execution
                # and compensation writebacks (ISSUE-059 §_validate_claim_preconditions).
                # Convert Pydantic model → dict for SQLAlchemy JSONB storage.
                disposition_source_ref_raw = original.disposition_source_ref
                disposition_source_ref: dict[str, Any] | None = None
                if disposition_source_ref_raw is not None:
                    if hasattr(disposition_source_ref_raw, "model_dump"):
                        disposition_source_ref = disposition_source_ref_raw.model_dump(mode="json")
                    else:
                        disposition_source_ref = disposition_source_ref_raw  # type: ignore[assignment]

                readiness = _resolve_compensation_readiness(
                    comp_required=comp_required,
                    original_owner=original_owner,
                    adapter_supports_compensation=adapter_supports_comp,
                )

                rb_status, rb_auto_execute = _rollback_initial_status(
                    action_level=action_level,
                    automated=automated,
                )

                rollback_action_id = new_action_id()
                rb_row = orm.Action(
                    action_id=rollback_action_id,
                    event_id=original.event_id,
                    plan_revision=plan_revision,
                    action_fingerprint=fingerprint,
                    action_category=ActionCategory.ROLLBACK.value,
                    action_name=rollback_tool,
                    tool_name=rollback_tool,
                    action_level=action_level,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    target_type=original.target_type,
                    target=original.target,
                    parameters=original.parameters,
                    status=rb_status.value,
                    auto_execute=rb_auto_execute,
                    reason=f"Rollback of {action_id}: {reason}"[:4096],
                    execution_owner=execution_owner.value,
                    source_action_id=action_id,
                    idempotency_key=idempotency_key,
                    disposition_source_ref=disposition_source_ref,
                    writeback_required=comp_required,
                    writeback_applicable=comp_required,
                    writeback_readiness=readiness.value,
                    writeback_status=None,
                    rollback_status=None,
                )
                session.add(rb_row)
                await session.flush()

                audit_log_id = await self._audit.log_transition_in_session(
                    session,
                    original.event_id,
                    from_status=original.status.value,
                    to_status=None,
                    operator=operator,
                    reason=f"Rollback initiated for {action_id}: {reason}",
                )

        if rb_status is ActionStatus.PENDING:
            pending_result = RollbackResult(
                action_id=action_id,
                rollback_action_id=rollback_action_id,
                rollback_tool=rollback_tool,
                rollback_effect_status=None,
                compensation_writeback_required=comp_required,
                compensation_writeback_readiness=readiness,
                rolled_back=False,
                warning="awaiting_approval",
                audit_log_id=audit_log_id,
            )
            await self._publish_rollback_event(
                event_id=original.event_id,
                action_id=rollback_action_id,
                source_action_id=action_id,
                operator=operator,
                rolled_back=False,
                rollback_effect_status=None,
                warning="awaiting_approval",
            )
            return pending_result

        # --- Execute rollback ---------------------------------------------------
        try:
            executed = await self._execute_rollback(rollback_action_id, operator)
        except Exception as exc:
            logger.exception("Rollback execution failed: %s", rollback_action_id)
            # Mark the rollback action as FAILED
            await self._update_action_status(rollback_action_id, ActionStatus.FAILED)
            await self._publish_rollback_event(
                event_id=original.event_id,
                action_id=rollback_action_id,
                source_action_id=action_id,
                operator=operator,
                rolled_back=False,
                rollback_effect_status="failed",
                warning=f"rollback_execution_error: {exc}",
            )
            return RollbackResult(
                action_id=action_id,
                rollback_action_id=rollback_action_id,
                rollback_tool=rollback_tool,
                rollback_effect_status="failed",
                compensation_writeback_required=comp_required,
                compensation_writeback_readiness=readiness,
                rolled_back=False,
                warning=f"rollback_execution_error: {exc}",
                audit_log_id=audit_log_id,
            )

        # --- Verify rollback effect ----------------------------------------------
        effect_status = await self._verify_rollback_effect(original, executed)

        if effect_status not in ("verified", "skipped") and executed.status is ActionStatus.SUCCESS:
            await self._update_action_status(rollback_action_id, ActionStatus.FAILED)

        # --- CAS original Action → ROLLED_BACK ----------------------------------
        if effect_status in ("verified", "skipped"):
            rolled_back = await self._cas_rollback_status(action_id, original)
        else:
            rolled_back = False

        # --- Create compensation writebacks --------------------------------------
        if effect_status in ("verified", "skipped"):
            comp_result = await self._create_compensation_writebacks(
                original_action=original,
                rollback_action=executed,
                operator=operator,
            )
        else:
            comp_result = _CompensationResult(writebacks=[], aggregate_status=None)

        warning: str | None = None
        if (
            not rolled_back
            and executed.status is ActionStatus.SUCCESS
            and effect_status == "failed"
        ):
            warning = "rollback_effect_not_verified"

        result = RollbackResult(
            action_id=action_id,
            rollback_action_id=rollback_action_id,
            rollback_tool=rollback_tool,
            rollback_effect_status=effect_status,
            compensation_writeback_required=comp_required,
            compensation_writeback_readiness=readiness,
            compensation_writebacks=comp_result.writebacks,
            compensation_writeback_status=comp_result.aggregate_status,
            rolled_back=rolled_back,
            warning=warning,
            audit_log_id=audit_log_id,
        )

        # --- Publish event -------------------------------------------------------
        await self._publish_rollback_event(
            event_id=original.event_id,
            action_id=rollback_action_id,
            source_action_id=action_id,
            operator=operator,
            rolled_back=rolled_back,
            rollback_effect_status=effect_status,
            warning=warning,
        )

        return result

    async def rollback_event(
        self,
        event_id: str,
        operator: str,
        reason: str,
    ) -> list[RollbackResult]:
        """Rollback all eligible IMMEDIATE response Actions for *event_id*
        in reverse execution order.
        """
        current_revision = await self._current_revision(event_id)
        async with self._session_factory() as session:
            rows = list(
                await session.scalars(
                    select(orm.Action)
                    .where(
                        orm.Action.event_id == event_id,
                        orm.Action.plan_revision == current_revision,
                        orm.Action.action_category == ActionCategory.RESPONSE.value,
                        orm.Action.execution_phase == ActionExecutionPhase.IMMEDIATE.value,
                        orm.Action.status == ActionStatus.SUCCESS.value,
                        # Only rollback actions whose effect has been
                        # independently confirmed (ISSUE-061 §统一命名 point 7).
                        orm.Action.effect_verification_status == "verified",
                        orm.Action.source_action_id.is_(None),
                        orm.Action.superseded_by_revision.is_(None),
                    )
                    .order_by(orm.Action.executed_at.desc().nulls_last())
                )
            )

        results: list[RollbackResult] = []
        for row in rows:
            action = _action_from_row(row)
            if not is_rollbackable(action.tool_name):
                # Per spec §实现步骤 point 2: every rollback attempt (even a
                # skipped one) must leave an audit log.
                async with self._session_factory() as audit_session:
                    async with audit_session.begin():
                        await self._audit.log_transition_in_session(
                            audit_session,
                            event_id,
                            from_status=action.status.value,
                            to_status=None,
                            operator=operator,
                            reason=(
                                f"Rollback skipped for {action.action_id}: "
                                f"not_rollbackable ({action.tool_name}) — {reason}"
                            ),
                        )
                results.append(
                    RollbackResult(
                        action_id=action.action_id,
                        rolled_back=False,
                        warning="not_rollbackable",
                    )
                )
                continue

            try:
                result = await self.rollback_action(
                    action.action_id,
                    operator=operator,
                    reason=reason,
                )
                results.append(result)
            except Exception:
                logger.exception(
                    "rollback_event: failed to rollback action %s in event %s",
                    action.action_id,
                    event_id,
                )
                # Per spec §降级策略: write failure details to audit log.
                async with self._session_factory() as audit_session:
                    async with audit_session.begin():
                        await self._audit.log_transition_in_session(
                            audit_session,
                            event_id,
                            from_status=action.status.value,
                            to_status=None,
                            operator=operator,
                            reason=(
                                f"Rollback error for {action.action_id}: "
                                f"unexpected exception — {reason}"
                            ),
                        )
                results.append(
                    RollbackResult(
                        action_id=action.action_id,
                        rolled_back=False,
                        warning="rollback_error",
                    )
                )

        return results

    async def compensate(
        self,
        event_id: str,
        failed_action_id: str,
        operator: str = "SagaCompensation",
        reason: str = "Saga compensation for failed action",
    ) -> list[RollbackResult]:
        """Saga compensation: rollback successful actions executed
        *before* *failed_action_id* in reverse execution order.
        """
        async with self._session_factory() as session:
            failed_row = await session.get(orm.Action, failed_action_id)
            if failed_row is None:
                logger.warning(
                    "compensate: failed_action_id not found: %s",
                    failed_action_id,
                )
                return []
            failed_at = failed_row.executed_at or _utc_now()
            failed_revision = int(failed_row.plan_revision)

            rows = list(
                await session.scalars(
                    select(orm.Action)
                    .where(
                        orm.Action.event_id == event_id,
                        orm.Action.plan_revision == failed_revision,
                        orm.Action.action_category == ActionCategory.RESPONSE.value,
                        orm.Action.execution_phase == ActionExecutionPhase.IMMEDIATE.value,
                        orm.Action.status == ActionStatus.SUCCESS.value,
                        orm.Action.effect_verification_status == "verified",
                        orm.Action.source_action_id.is_(None),
                        orm.Action.superseded_by_revision.is_(None),
                        orm.Action.action_id != failed_action_id,
                        orm.Action.executed_at < failed_at,
                    )
                    .order_by(orm.Action.executed_at.desc().nulls_last())
                )
            )

        results: list[RollbackResult] = []
        for row in rows:
            action = _action_from_row(row)
            if not is_rollbackable(action.tool_name):
                logger.warning(
                    "compensate: skipping non-rollbackable action %s (%s)",
                    action.action_id,
                    action.tool_name,
                )
                # Per spec §实现步骤 point 2: every rollback attempt must
                # leave an audit log, even for skipped actions.
                async with self._session_factory() as audit_session:
                    async with audit_session.begin():
                        await self._audit.log_transition_in_session(
                            audit_session,
                            event_id,
                            from_status=action.status.value,
                            to_status=None,
                            operator=operator,
                            reason=(
                                f"Saga compensation skipped for {action.action_id}: "
                                f"not_rollbackable ({action.tool_name}) — "
                                f"failed action: {failed_action_id}"
                            ),
                        )
                results.append(
                    RollbackResult(
                        action_id=action.action_id,
                        rolled_back=False,
                        warning="not_rollbackable",
                    )
                )
                continue

            try:
                result = await self.rollback_action(
                    action.action_id,
                    operator=operator,
                    reason=f"{reason} (failed: {failed_action_id})",
                    automated=True,
                )
                results.append(result)
            except Exception:
                logger.exception(
                    "compensate: failed to rollback %s for event %s",
                    action.action_id,
                    event_id,
                )
                # Per spec §降级策略: write failure details to audit log.
                async with self._session_factory() as audit_session:
                    async with audit_session.begin():
                        await self._audit.log_transition_in_session(
                            audit_session,
                            event_id,
                            from_status=action.status.value,
                            to_status=None,
                            operator=operator,
                            reason=(
                                f"Saga compensation error for {action.action_id}: "
                                f"unexpected exception — failed action: {failed_action_id}"
                            ),
                        )
                results.append(
                    RollbackResult(
                        action_id=action.action_id,
                        rolled_back=False,
                        warning="rollback_error",
                    )
                )

        return results

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    async def _current_revision(self, event_id: str) -> int:
        """Return the latest plan_revision for *event_id*."""
        async with self._session_factory() as session:
            from sqlalchemy import func

            value = await session.scalar(
                select(func.max(orm.Action.plan_revision)).where(orm.Action.event_id == event_id)
            )
        return int(value or 1)

    async def _cas_rollback_status(
        self,
        source_action_id: str,
        original: ActionModel,
    ) -> bool:
        """CAS the original Action SUCCESS/PARTIAL_SUCCESS → ROLLED_BACK."""
        allowed = {ActionStatus.SUCCESS, ActionStatus.PARTIAL_SUCCESS}
        if original.status not in allowed:
            return False

        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.Action, source_action_id, with_for_update=True)
                if row is None:
                    return False
                if ActionStatus(row.status) not in allowed:
                    return False
                row.status = ActionStatus.ROLLED_BACK.value
                row.rollback_status = "completed"
                row.updated_at = _utc_now()
                await session.flush()
        return True

    async def _update_action_status(self, action_id: str, status: ActionStatus) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.Action, action_id, with_for_update=True)
                if row is not None:
                    row.status = status.value
                    row.updated_at = _utc_now()
                    await session.flush()

    async def _publish_rollback_event(
        self,
        *,
        event_id: str,
        action_id: str,
        source_action_id: str | None,
        operator: str,
        rolled_back: bool,
        rollback_effect_status: RollbackEffectStatus | None,
        warning: str | None = None,
        rejected: bool = False,
    ) -> None:
        """Publish ``action_executed`` for rollback lifecycle visibility."""
        if self._bus is None:
            return
        payload: dict[str, Any] = {
            "action_id": action_id,
            "rollback": True,
            "rollback_action_id": action_id,
            "source_action_id": source_action_id,
            "rolled_back": rolled_back,
            "rollback_effect_status": rollback_effect_status,
            "operator": operator,
        }
        if warning is not None:
            payload["warning"] = warning
        if rejected:
            payload["rejected"] = True
        await self._bus.publish_event(event_id, "action_executed", payload)

    async def _create_compensation_writebacks(
        self,
        *,
        original_action: ActionModel,
        rollback_action: ActionModel,
        operator: str,
    ) -> _CompensationResult:
        """Create COMPENSATION_RECORD writebacks for each applicable
        original writeback (ENTITY_ACTION_SUBMIT / EXECUTION_RESULT_RECORD).
        """
        if (
            not original_action.writeback_required
            or not original_action.writeback_applicable
            or self._disposition_sync is None
        ):
            return _CompensationResult(writebacks=[], aggregate_status=None)

        # Live-mode gate: do not attempt compensation writebacks when XDR
        # writeback is not confirmed/allowed (ISSUE-061 §降级策略).
        if not _xdr_writeback_allowed():
            logger.warning(
                "Skipping COMPENSATION_RECORD for action %s: XDR writeback not allowed",
                original_action.action_id,
            )
            return _CompensationResult(writebacks=[], aggregate_status=None)

        # Use the *original* action's disposition_source_ref — compensation
        # targets the same source object the original writeback used.
        source_locator = original_action.disposition_source_ref
        if source_locator is None:
            logger.warning(
                "Cannot create COMPENSATION_RECORD for action %s: "
                "original action has no disposition_source_ref",
                original_action.action_id,
            )
            return _CompensationResult(writebacks=[], aggregate_status=None)

        async with self._session_factory() as session:
            async with session.begin():
                outbox_rows = list(
                    await session.scalars(
                        select(orm.DispositionOutbox).where(
                            orm.DispositionOutbox.action_id == original_action.action_id,
                            orm.DispositionOutbox.intent_kind.in_(
                                [
                                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                                    DispositionIntentKind.EXECUTION_RESULT_RECORD.value,
                                ]
                            ),
                            orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                        )
                    )
                )

                if not outbox_rows:
                    return _CompensationResult(writebacks=[], aggregate_status=None)

                source_record_id = outbox_rows[0].source_record_id

                writebacks: list[CompensationWritebackItem] = []
                comp_owner = _compensation_execution_owner(
                    original_action,
                    adapter_registry=self._adapter_registry,
                )
                rollback_for_comp = rollback_action.model_copy(
                    update={"execution_owner": comp_owner},
                )
                for outbox in outbox_rows:
                    disposition_id = new_disposition_id()

                    cmd = self._factory.build_compensation_record(
                        rollback_for_comp,
                        source_locator=source_locator,
                        source_concurrency_token=None,
                        operator_id=operator,
                        disposition_id=disposition_id,
                        closure_cycle=original_action.plan_revision,
                        parent_disposition_id=outbox.disposition_id,
                    )

                    try:
                        record = await self._disposition_sync.enqueue_command(
                            session,
                            command=cmd,
                            event_id=rollback_action.event_id,
                            source_record_id=source_record_id,
                            logical_slot=f"compensation:{original_action.action_id}",
                            guard_context={
                                "approved_action_ids": [rollback_action.action_id],
                            },
                        )
                        writebacks.append(
                            CompensationWritebackItem(
                                writeback_id=record.writeback_id,
                                disposition_id=disposition_id,
                                status=WritebackStatus.PENDING,
                                intent_kind=DispositionIntentKind.COMPENSATION_RECORD.value,
                            )
                        )
                    except Exception:
                        logger.exception(
                            "Failed to enqueue COMPENSATION_RECORD for disposition %s",
                            outbox.disposition_id,
                        )

                if not writebacks:
                    return _CompensationResult(writebacks=[], aggregate_status=None)

                statuses = [w.status for w in writebacks if w.status is not None]
                aggregate = _aggregate_writeback_status(statuses) if statuses else None

                return _CompensationResult(
                    writebacks=writebacks,
                    aggregate_status=aggregate,
                )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _CompensationResult:
    __slots__ = ("writebacks", "aggregate_status")

    def __init__(
        self,
        writebacks: list[CompensationWritebackItem],
        aggregate_status: WritebackStatus | None,
    ) -> None:
        self.writebacks = writebacks
        self.aggregate_status = aggregate_status


def _source_product(disposition_source_ref: Any) -> str | None:
    if disposition_source_ref is None:
        return None
    if hasattr(disposition_source_ref, "source_product"):
        return str(disposition_source_ref.source_product)
    if isinstance(disposition_source_ref, dict):
        product = disposition_source_ref.get("source_product")
        return str(product) if product else None
    return None


def _adapter_supports_xdr_compensation(
    original: ActionModel,
    adapter_registry: Any | None,
) -> bool:
    if adapter_registry is None:
        return False
    product = _source_product(original.disposition_source_ref)
    if not product:
        return False
    try:
        adapter = adapter_registry.get(product)
    except AdapterNotFoundError:
        return False
    caps = adapter.capabilities()
    comp = caps.intents.get(DispositionIntentKind.COMPENSATION_RECORD)
    entity = caps.intents.get(DispositionIntentKind.ENTITY_ACTION_SUBMIT)
    record_op = caps.operations.get("record_compensation")
    return (
        comp is CapabilityState.SUPPORTED
        and entity is CapabilityState.SUPPORTED
        and record_op is CapabilityState.SUPPORTED
    )


def _resolve_rollback_owner_and_compensation(
    original: ActionModel,
    *,
    adapter_registry: Any | None,
) -> tuple[ExecutionOwner, bool]:
    """Local effect rollback always uses DIRECT_TOOL; adapter gates compensation.

    Issue §实现步骤 point 1: DIRECT_TOOL path executes the rollback tool locally;
    XDR_MANAGED compensation entity sync is handled separately via
    COMPENSATION_RECORD when the disposition adapter declares support.
    """
    adapter_supports = _adapter_supports_xdr_compensation(original, adapter_registry)
    return ExecutionOwner.DIRECT_TOOL, adapter_supports


def _compensation_execution_owner(
    original: ActionModel,
    *,
    adapter_registry: Any | None,
) -> ExecutionOwner:
    original_owner = original.execution_owner or ExecutionOwner.DIRECT_TOOL
    if original_owner is ExecutionOwner.XDR_MANAGED and _adapter_supports_xdr_compensation(
        original, adapter_registry
    ):
        return ExecutionOwner.XDR_MANAGED
    return ExecutionOwner.DIRECT_TOOL


def _resolve_compensation_readiness(
    *,
    comp_required: bool,
    original_owner: ExecutionOwner,
    adapter_supports_compensation: bool,
) -> WritebackReadiness:
    if not comp_required:
        return WritebackReadiness.NOT_REQUIRED
    if not _xdr_writeback_allowed():
        return WritebackReadiness.CAPABILITY_UNSUPPORTED
    if original_owner is ExecutionOwner.XDR_MANAGED and not adapter_supports_compensation:
        return WritebackReadiness.CAPABILITY_UNSUPPORTED
    return WritebackReadiness.READY


def _rollback_initial_status(
    *,
    action_level: str,
    automated: bool,
) -> tuple[ActionStatus, bool]:
    """Human rollback approves inline; automated Saga L2+ waits for ApprovalEngine."""
    if automated and action_level.lower() in {"l2", "l3", "l4"}:
        return ActionStatus.PENDING, False
    return ActionStatus.APPROVED, True


def build_execute_rollback_hook(action_execution: Any) -> ExecuteRollbackHook:
    """Wire RollbackService local effect execution to ActionExecutionService.

    Rollback actions are persisted with ``execution_owner=DIRECT_TOOL`` so
    ``execute_action`` runs the rollback tool (e.g. unblock_ip) on the device
    path.  External COMPENSATION_RECORD sync uses XDR_MANAGED separately in
    ``_create_compensation_writebacks`` when the adapter supports it.
    """

    async def _execute(rollback_action_id: str, operator: str) -> ActionModel:
        executed = await action_execution.execute_action(
            rollback_action_id,
            operator=operator,
        )
        return ActionModel.model_validate(executed.model_dump(mode="python"))

    return _execute


async def _default_execute_rollback(rollback_action_id: str, operator: str) -> ActionModel:
    """Default execution hook — production must inject ActionExecutionService."""
    raise NotImplementedError(
        "Real rollback execution requires ActionExecutionService integration. "
        "Inject an `execute_rollback` hook in production."
    )


async def _default_verify_rollback_effect(
    original: ActionModel,
    rollback_action: ActionModel,
) -> RollbackEffectStatus:
    """Verify rollback effect via independent readback tools when available."""
    execution_status = _execution_effect_status(rollback_action)
    if execution_status != "verified":
        return execution_status

    verify_tool = get_rollback_verify_tool(rollback_action.tool_name)
    if verify_tool is None:
        return "skipped"

    from app.tools.verify._common import execute_verification_tool

    params = {
        "target_type": rollback_action.target_type,
        "target": rollback_action.target,
        "parameters": dict(rollback_action.parameters or {}),
    }
    try:
        verify_result = await execute_verification_tool(verify_tool, params)
    except Exception:
        logger.exception(
            "Rollback readback verification failed: rollback=%s verify_tool=%s",
            rollback_action.action_id,
            verify_tool,
        )
        return "failed"

    if _readback_confirms_rollback(verify_result):
        return "verified"
    return "failed"


def _execution_effect_status(action: ActionModel) -> RollbackEffectStatus:
    """Grade rollback execution outcome before independent readback."""
    if action.status is ActionStatus.SUCCESS:
        return "verified"
    if action.status is ActionStatus.PARTIAL_SUCCESS:
        return "unverifiable"
    if action.status is ActionStatus.UNKNOWN:
        return "unverifiable"
    return "failed"


_READBACK_FAILURE_DETAILS = frozenset(
    {
        "forced_failure_override",
        "execution_job_not_found",
        "observation_not_visible",
        "observation_job_mismatch",
    }
)


def _readback_confirms_rollback(verify_result: dict[str, Any]) -> bool:
    """Return True when readback shows the original forward effect is gone."""
    status = str(verify_result.get("status", "")).lower()
    if status in {"failed", "timeout", "unknown"}:
        return False

    data = verify_result.get("data")
    if not isinstance(data, dict):
        return False

    # Forward verification tools return is_verified=True when the effect is
    # still present.  After a successful rollback the effect must be absent.
    if data.get("is_verified") is True:
        return False

    detail = str(data.get("detail", ""))
    if detail in _READBACK_FAILURE_DETAILS:
        return False
    if detail.startswith(("execution_job_", "execution_target_")):
        return False
    return True


def _pre_check_rollbackable(action: ActionModel) -> RollbackResult | None:
    """Return a non-null RollbackResult if *action* cannot be rolled back."""
    tool_name = action.tool_name

    if action.action_category != ActionCategory.RESPONSE:
        return RollbackResult(
            action_id=action.action_id,
            rolled_back=False,
            warning="not_response_action",
        )

    if action.execution_phase is ActionExecutionPhase.POST_VERIFY:
        return RollbackResult(
            action_id=action.action_id,
            rolled_back=False,
            warning="post_verify_not_rollbackable",
        )

    if action.status is ActionStatus.UNKNOWN:
        return RollbackResult(
            action_id=action.action_id,
            rolled_back=False,
            warning="unknown_status_cannot_rollback",
        )

    if action.status is ActionStatus.PARTIAL_SUCCESS:
        # Per spec §统一命名 point 7: PARTIAL_SUCCESS must not be
        # auto-rollbacked until per-target state is confirmed.  Callers
        # should inspect ActionTargetResult rows for individual targets
        # and only rollback the subset that actually succeeded.
        return RollbackResult(
            action_id=action.action_id,
            rolled_back=False,
            warning="partial_success_cannot_rollback_inspect_targets_first",
        )

    if action.rollback_status == "completed":
        return RollbackResult(
            action_id=action.action_id,
            rolled_back=False,
            warning="already_rolled_back",
        )

    if action.status is not ActionStatus.SUCCESS:
        return RollbackResult(
            action_id=action.action_id,
            rolled_back=False,
            warning=f"status_{action.status.value}_cannot_rollback",
        )

    if not is_rollbackable(tool_name):
        return RollbackResult(
            action_id=action.action_id,
            rolled_back=False,
            warning="not_rollbackable",
        )

    return None


def _xdr_writeback_allowed() -> bool:
    """Return True when XDR writeback is permitted by current settings.

    In mock mode writeback is always allowed. In live mode it requires the
    ``ALLOW_XDR_WRITEBACK`` flag to be explicitly enabled (ISSUE-061 §降级策略).
    """
    settings = get_settings()
    disposition_mode = settings.disposition_mode.strip().lower()
    if "mock" in disposition_mode:
        return True
    return bool(settings.allow_xdr_writeback)


def _aggregate_writeback_status(
    statuses: list[WritebackStatus],
) -> WritebackStatus:
    """Aggregate multiple writeback statuses into a single summary.

    Callers must guarantee *statuses* is non-empty; an empty list
    indicates a logic error upstream (there should be no call to
    aggregate when there are no writebacks).
    """
    if not statuses:
        return WritebackStatus.UNKNOWN
    status_set = set(statuses)
    if status_set == {WritebackStatus.CONFIRMED}:
        return WritebackStatus.CONFIRMED
    if status_set & {WritebackStatus.FAILED, WritebackStatus.CONFLICT}:
        return WritebackStatus.FAILED
    if WritebackStatus.UNKNOWN in status_set:
        return WritebackStatus.UNKNOWN
    if status_set & {
        WritebackStatus.PENDING,
        WritebackStatus.SENDING,
        WritebackStatus.ACCEPTED,
    }:
        return WritebackStatus.PENDING
    return WritebackStatus.PARTIAL


__all__ = ["RollbackService", "build_execute_rollback_hook"]
