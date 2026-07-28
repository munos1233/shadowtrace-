"""Trusted workflow side effects for the ISSUE-048 StateGraph."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.response_agent import compute_template_hash
from app.core.errors import ValidationError
from app.db import models as orm
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionOwner,
    ExecutionSubstate,
    FinalVerdict,
    Severity,
    SourceDisposition,
    WritebackReadiness,
)
from app.models.ids import new_action_id
from app.models.workflow import (
    TransitionContext,
    validate_execution_substate,
    validate_transition,
)
from app.services.context_service import append_context_journal_in_session

logger = logging.getLogger(__name__)

_RUNTIME_OPERATOR = "WorkflowRuntimeService"

# Audit log reason codes (structured classification for queryability).
_AUDIT_DISPOSITION_ONLY_CONFIDENCE = "disposition_only_confidence"
_AUDIT_DISPOSITION_ONLY_DEFERRED = "disposition_only_deferred_action"


class _EventServicePort(Protocol):
    async def apply_final_verdict_in_session(
        self,
        session: AsyncSession,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
    ) -> tuple[bool, Any, Any]: ...

    async def publish_final_verdict_mutation(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        result: Any,
        summary: Any,
    ) -> None: ...

    async def sync_event_summary_mutation(
        self,
        event_id: str,
        *,
        result: Any,
        summary: Any,
    ) -> None: ...


class WorkflowRuntimeService:
    """Sole writer for disposition-only intent and execution substate."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        event_service: _EventServicePort,
        readiness_resolver: (Callable[[str], Awaitable[WritebackReadiness]] | None) = None,
    ) -> None:
        self._session_factory = session_factory
        self._event_service = event_service
        self._readiness_resolver = readiness_resolver

    async def begin_disposition_only(self, event_id: str) -> None:
        """Atomically persist FP verdict, confidence floor, and trusted intent."""
        readiness = await self.get_event_status_update_readiness(event_id)
        if readiness is not WritebackReadiness.READY:
            raise ValidationError(
                "EVENT_STATUS_UPDATE is not ready for disposition-only",
                details={"event_id": event_id, "readiness": readiness.value},
            )
        verdict_changed = False
        confidence_changed = False
        result: Any = None
        summary: Any = None

        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if row is None:
                    raise KeyError(f"security_event not found: {event_id}")

                # Idempotency guard: if a prior begin_disposition_only call
                # already persisted the intent (and created the deferred
                # action), treat a subsequent call as a no-op.
                if bool(
                    await self._journal_scalar(
                        session,
                        event_id,
                        "disposition_only_intent",
                    )
                ):
                    return  # idempotent no-op

                if DispositionPolicy(row.disposition_policy) != DispositionPolicy.REQUIRED:
                    raise ValidationError(
                        "disposition-only requires disposition_policy=required",
                        details={"event_id": event_id},
                    )
                if EventStatus(row.status) != EventStatus.TRIAGING:
                    raise ValidationError(
                        "disposition-only must begin from TRIAGING",
                        details={"event_id": event_id, "status": row.status},
                    )
                if EventType(row.event_type) == EventType.INSIDER_THREAT:
                    raise ValidationError(
                        "INSIDER_THREAT events must follow full investigation path "
                        "and are not eligible for disposition-only",
                        details={"event_id": event_id, "event_type": row.event_type},
                    )

                fp = await self._journal_value(session, event_id, "false_positive_match")
                if not isinstance(fp, dict) or fp.get("recommendation") != "close_as_fp":
                    raise ValidationError(
                        "begin_disposition_only requires close_as_fp false_positive_match",
                        details={"event_id": event_id},
                    )
                try:
                    fp_score = max(0.0, min(1.0, float(fp.get("max_score") or 0.0)))
                except (TypeError, ValueError):
                    fp_score = 0.0

                previous_confidence = float(row.confidence or 0.0)
                confidence = max(previous_confidence, fp_score)
                confidence_changed = confidence != previous_confidence
                if confidence_changed:
                    row.confidence = confidence
                    row.row_version = int(row.row_version or 1) + 1
                    row.updated_at = datetime.now(UTC)
                    session.add(
                        orm.EventAuditLog(
                            event_id=event_id,
                            from_status=row.status,
                            to_status=row.status,
                            operator=_RUNTIME_OPERATOR,
                            reason=(
                                f"{_AUDIT_DISPOSITION_ONLY_CONFIDENCE}:"
                                f"{previous_confidence}->{confidence}"
                            ),
                        )
                    )

                (
                    verdict_changed,
                    result,
                    summary,
                ) = await self._event_service.apply_final_verdict_in_session(
                    session,
                    event_id,
                    FinalVerdict.FALSE_POSITIVE,
                    operator=_RUNTIME_OPERATOR,
                )
                # Idempotency guard (line 112) already confirms
                # disposition_only_intent is not set, so always
                # record it now (SF-1: removed redundant re-query).
                await append_context_journal_in_session(
                    session,
                    event_id,
                    "disposition_only_intent",
                    True,
                )

                # ISSUE-064: For disposition-only FP events with REQUIRED
                # policy, create a deferred update_source_event_disposition
                # Action so the standard execute → VERIFYING →
                # activate_and_submit → EVENT_STATUS_UPDATE →
                # CONFIRMED(readback_verified) → CLOSED chain produces a
                # proper disposition writeback.  The policy stays REQUIRED;
                # the deferred action carries IGNORED as the pre-approved
                # terminal disposition.
                approved_dispositions = [SourceDisposition.IGNORED]
                approved_hash = compute_template_hash(approved_dispositions)

                deferred_action_id = new_action_id()
                session.add(
                    orm.Action(
                        action_id=deferred_action_id,
                        event_id=event_id,
                        plan_revision=1,
                        action_fingerprint=f"fp-disposition-only-{event_id}",
                        action_category=ActionCategory.RESPONSE.value,
                        action_name="update_source_event_disposition",
                        tool_name="update_source_event_disposition",
                        action_level=ActionLevel.L2.value,
                        execution_phase=ActionExecutionPhase.POST_VERIFY.value,
                        activation_condition="after_effect_resolution",
                        approved_operation_template_hash=approved_hash,
                        approved_terminal_dispositions=[d.value for d in approved_dispositions],
                        status=ActionStatus.APPROVED.value,
                        execution_owner=ExecutionOwner.XDR_MANAGED.value,
                        writeback_required=True,
                        writeback_applicable=True,
                        writeback_readiness=WritebackReadiness.READY.value,
                        reason="disposition_only: FP → IGNORED deferred disposition",
                        disposition_source_ref=row.disposition_source_ref,
                    )
                )
                session.add(
                    orm.EventAuditLog(
                        event_id=event_id,
                        from_status=row.status,
                        to_status=row.status,
                        operator=_RUNTIME_OPERATOR,
                        reason=(
                            f"{_AUDIT_DISPOSITION_ONLY_DEFERRED}:"
                            f"created {deferred_action_id}"
                            " (POST_VERIFY update_source_event_disposition"
                            ", approved=[IGNORED])"
                        ),
                    )
                )

                await session.flush()

        if verdict_changed:
            await self._event_service.publish_final_verdict_mutation(
                event_id,
                FinalVerdict.FALSE_POSITIVE,
                result=result,
                summary=summary,
            )
        elif confidence_changed:
            await self._event_service.sync_event_summary_mutation(
                event_id,
                result=result,
                summary=summary,
            )

    async def get_event_status_update_readiness(
        self,
        event_id: str,
    ) -> WritebackReadiness:
        """Resolve Adapter readiness server-side; missing resolver fails closed."""
        if self._readiness_resolver is None:
            return WritebackReadiness.CAPABILITY_UNKNOWN
        try:
            return WritebackReadiness(await self._readiness_resolver(event_id))
        except Exception:
            logger.warning(
                "EVENT_STATUS_UPDATE readiness lookup failed event=%s",
                event_id,
                exc_info=True,
            )
            return WritebackReadiness.CAPABILITY_UNKNOWN

    async def read_disposition_only_intent(self, event_id: str) -> bool:
        """Read the server-persisted intent, never a client or LLM claim."""
        async with self._session_factory() as session:
            value = await self._journal_scalar(session, event_id, "disposition_only_intent")
        return bool(value)

    async def set_execution_substate(
        self,
        event_id: str,
        substate: ExecutionSubstate,
        *,
        event_status: EventStatus,
    ) -> None:
        """Validate against locked EventStatus and persist the resumable substate."""
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if row is None:
                    raise KeyError(f"security_event not found: {event_id}")
                authoritative_status = EventStatus(row.status)
                if event_status is not authoritative_status:
                    raise ValidationError(
                        "caller EventStatus does not match authoritative state",
                        details={
                            "event_id": event_id,
                            "caller_status": event_status.value,
                            "authoritative_status": authoritative_status.value,
                        },
                    )
                raw = await self._journal_scalar(
                    session,
                    event_id,
                    "execution_substate",
                )
                try:
                    current = ExecutionSubstate(raw or ExecutionSubstate.NONE.value)
                except ValueError:
                    current = ExecutionSubstate.NONE
                validate_execution_substate(authoritative_status, current, substate)
                if current is not substate:
                    await append_context_journal_in_session(
                        session,
                        event_id,
                        "execution_substate",
                        substate.value,
                    )

    async def assert_disposition_only_transition_allowed(
        self,
        event_id: str,
        *,
        current: EventStatus,
        target: EventStatus,
    ) -> None:
        """Reject forged intent by rebuilding transition context from PostgreSQL."""
        async with self._session_factory() as session:
            row = await session.get(orm.SecurityEvent, event_id)
            if row is None:
                raise KeyError(f"security_event not found: {event_id}")
            intent = await self._journal_scalar(session, event_id, "disposition_only_intent")
            fp = await self._journal_value(session, event_id, "false_positive_match")
        validate_transition(
            current,
            target,
            TransitionContext(
                final_verdict=FinalVerdict(row.final_verdict),
                disposition_only_intent=bool(intent),
                disposition_policy=DispositionPolicy(row.disposition_policy),
                severity=Severity(row.severity),
                recommendation=fp.get("recommendation") if isinstance(fp, dict) else None,
            ),
        )

    async def _journal_scalar(
        self,
        session: AsyncSession,
        event_id: str,
        field_name: str,
    ) -> Any:
        """Read the latest journal value for *field_name*.

        Returns the unwrapped scalar when the stored value is a
        ``{"_scalar": ...}`` dict, otherwise returns the raw value
        (which may be a dict, list, or scalar).
        """
        row = await session.scalar(
            select(orm.EventContextJournal)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == field_name,
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        if row is None:
            return None
        value = row.value
        if isinstance(value, dict) and set(value) == {"_scalar"}:
            return value["_scalar"]
        return value

    async def _journal_value(
        self,
        session: AsyncSession,
        event_id: str,
        field_name: str,
    ) -> dict[str, Any] | None:
        """Read the latest journal entry and return it only if it is a dict.

        This is a convenience wrapper around ``_journal_scalar`` that
        filters non-dict values (scalars, lists) to ``None``.
        """
        value = await self._journal_scalar(session, event_id, field_name)
        return value if isinstance(value, dict) else None


__all__ = ["WorkflowRuntimeService"]
