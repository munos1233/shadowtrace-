"""Unified manual resolution + durable graph resume intent (ISSUE-277 / #873)."""

from __future__ import annotations

import hashlib
import logging
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.errors import ManualResolutionConflictError
from app.db import models as orm
from app.models.enums import EventStatus, ExecutionSubstate, InvestigationIntentStatus
from app.models.graph_resume_intent import (
    TERMINAL_INTENT_STATUSES,
    GraphResumeDeliveryAdmission,
    validate_intent_transition,
)
from app.services.context_service import (
    append_context_journal_in_session,
    unwrap_journal_value,
)

logger = logging.getLogger(__name__)

_DISPATCH_WORKER_ID = "graph-resume-dispatcher-1"
_STARTED_STALE_MIN_S = 660

ResumeInvestigationHook = Callable[[str], Awaitable[None]]


def new_graph_resume_intent_id() -> str:
    return f"gri-{secrets.token_hex(8)}"


def deterministic_graph_resume_task_id(intent_id: str, revision: int) -> str:
    return hashlib.sha256(f"graph-resume:{intent_id}:{revision}".encode()).hexdigest()


def stable_operation_id(
    *,
    resolution_kind: str,
    subject_id: str,
    resolution: str,
    principal: str,
    comment: str,
) -> str:
    payload = f"{resolution_kind}|{subject_id}|{resolution}|{principal}|{comment}"
    return f"op-{hashlib.sha256(payload.encode()).hexdigest()[:24]}"


@dataclass(frozen=True)
class ManualHoldSnapshot:
    generation: int
    reason: str | None
    pending_action_ids: list[str]
    pending_writeback_ids: list[str]
    checkpoint_version: int | None
    execution_substate: str | None


@dataclass(frozen=True)
class ResolutionResumeResult:
    intent_id: str
    operation_id: str
    hold_generation: int
    idempotent_replay: bool


async def _read_journal_scalar(
    session: AsyncSession,
    event_id: str,
    field_name: str,
) -> Any:
    raw = await session.scalar(
        select(orm.EventContextJournal.value)
        .where(
            orm.EventContextJournal.event_id == event_id,
            orm.EventContextJournal.field_name == field_name,
        )
        .order_by(orm.EventContextJournal.version.desc())
        .limit(1)
    )
    return unwrap_journal_value(raw) if raw is not None else None


class ManualResolutionService:
    """Owns manual hold metadata and graph_resume_intent durable dispatch."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        workflow_runtime: Any | None = None,
        resume_investigation: ResumeInvestigationHook | None = None,
        settings: Settings | None = None,
        worker_id: str = _DISPATCH_WORKER_ID,
    ) -> None:
        self._session_factory = session_factory
        self._runtime = workflow_runtime
        self._resume = resume_investigation
        self._settings = settings or get_settings()
        self._worker_id = worker_id

    async def read_manual_hold(self, event_id: str) -> ManualHoldSnapshot | None:
        async with self._session_factory() as session:
            generation = await _read_journal_scalar(session, event_id, "manual_hold_generation")
            if generation is None:
                return None
            detail = await _read_journal_scalar(session, event_id, "manual_hold_detail")
            substate = await _read_journal_scalar(session, event_id, "execution_substate")
        if not isinstance(detail, dict):
            detail = {}
        return ManualHoldSnapshot(
            generation=int(generation),
            reason=str(detail.get("reason")) if detail.get("reason") else None,
            pending_action_ids=[str(x) for x in detail.get("pending_action_ids") or []],
            pending_writeback_ids=[str(x) for x in detail.get("pending_writeback_ids") or []],
            checkpoint_version=(
                int(detail["checkpoint_version"])
                if detail.get("checkpoint_version") is not None
                else int(generation)
            ),
            execution_substate=str(substate) if substate is not None else None,
        )

    async def establish_manual_hold(
        self,
        event_id: str,
        *,
        reason: str,
        pending_action_ids: list[str],
        pending_writeback_ids: list[str],
        checkpoint_version: int | None = None,
    ) -> int:
        """Persist MANUAL_RESOLUTION substate and monotonic hold generation."""
        async with self._session_factory() as session:
            async with session.begin():
                current = await _read_journal_scalar(session, event_id, "manual_hold_generation")
                generation = int(current or 0) + 1
                detail = {
                    "reason": reason,
                    "pending_action_ids": pending_action_ids,
                    "pending_writeback_ids": pending_writeback_ids,
                    "checkpoint_version": checkpoint_version or generation,
                }
                await append_context_journal_in_session(
                    session,
                    event_id,
                    "manual_hold_generation",
                    generation,
                )
                await append_context_journal_in_session(
                    session,
                    event_id,
                    "manual_hold_detail",
                    detail,
                )
        if self._runtime is not None:
            await self._runtime.set_execution_substate(
                event_id,
                ExecutionSubstate.MANUAL_RESOLUTION,
                event_status=EventStatus.VERIFYING,
            )
        return generation

    async def create_resume_intent_after_resolution(
        self,
        *,
        event_id: str,
        resolution_kind: str,
        subject_id: str,
        operation_id: str | None,
        resolution: str,
        principal: str,
        comment: str,
    ) -> ResolutionResumeResult | None:
        """Create durable resume intent when event is on manual hold; None if not applicable."""
        op_id = operation_id or stable_operation_id(
            resolution_kind=resolution_kind,
            subject_id=subject_id,
            resolution=resolution,
            principal=principal,
            comment=comment,
        )
        hold = await self.read_manual_hold(event_id)
        if hold is None or hold.execution_substate != ExecutionSubstate.MANUAL_RESOLUTION.value:
            return None

        async with self._session_factory() as session:
            existing = await session.scalar(
                select(orm.GraphResumeIntent).where(orm.GraphResumeIntent.operation_id == op_id)
            )
            if existing is not None:
                return ResolutionResumeResult(
                    intent_id=existing.intent_id,
                    operation_id=existing.operation_id,
                    hold_generation=int(existing.hold_generation),
                    idempotent_replay=True,
                )

        async with self._session_factory() as session:
            async with session.begin():
                active = (
                    await session.scalars(
                        select(orm.GraphResumeIntent)
                        .where(
                            orm.GraphResumeIntent.event_id == event_id,
                            orm.GraphResumeIntent.status.not_in(
                                tuple(status.value for status in TERMINAL_INTENT_STATUSES)
                            ),
                        )
                        .with_for_update()
                    )
                ).all()
                for row in active:
                    if row.operation_id != op_id:
                        raise ManualResolutionConflictError(
                            "conflicting graph resume intent already active",
                            details={
                                "event_id": event_id,
                                "existing_operation_id": row.operation_id,
                                "operation_id": op_id,
                            },
                        )

                current_gen = await _read_journal_scalar(
                    session,
                    event_id,
                    "manual_hold_generation",
                )
                if current_gen is None or int(current_gen) != hold.generation:
                    raise ManualResolutionConflictError(
                        "manual hold generation mismatch",
                        details={
                            "event_id": event_id,
                            "expected_generation": hold.generation,
                            "current_generation": current_gen,
                        },
                    )

                intent_id = new_graph_resume_intent_id()
                row = orm.GraphResumeIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    operation_id=op_id,
                    resolution_kind=resolution_kind,
                    subject_id=subject_id,
                    hold_generation=hold.generation,
                    checkpoint_version=hold.checkpoint_version,
                    status=InvestigationIntentStatus.PENDING.value,
                )
                session.add(row)
                try:
                    await session.flush()
                except IntegrityError as exc:
                    raise ManualResolutionConflictError(
                        "graph resume operation_id conflict",
                        details={"operation_id": op_id},
                    ) from exc

        self.schedule_dispatch()
        return ResolutionResumeResult(
            intent_id=intent_id,
            operation_id=op_id,
            hold_generation=hold.generation,
            idempotent_replay=False,
        )

    def schedule_dispatch(self) -> None:
        try:
            from app.tasks.graph_resume_intent_tasks import dispatch_pending_graph_resume_intents

            dispatch_pending_graph_resume_intents.delay()
        except Exception:
            logger.warning("failed to enqueue graph resume intent dispatch", exc_info=True)

    async def dispatch_sync_batch(self, *, limit: int = 10) -> int:
        """Synchronously claim and execute pending intents (tests / management)."""
        claimed = await self._claim_batch(limit=limit)
        executed = 0
        for intent_id in claimed:
            if await self._execute_claimed_intent(intent_id):
                executed += 1
        return executed

    async def claim_and_execute_batch(self, *, limit: int = 10) -> int:
        return await self.dispatch_sync_batch(limit=limit)

    async def mark_started(
        self,
        intent_id: str,
        *,
        broker_task_id: str,
    ) -> GraphResumeDeliveryAdmission:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.GraphResumeIntent, intent_id)
                if row is None:
                    return GraphResumeDeliveryAdmission.MISSING
                current = InvestigationIntentStatus(row.status)
                if current in TERMINAL_INTENT_STATUSES:
                    return GraphResumeDeliveryAdmission.ALREADY_TERMINAL
                if current is InvestigationIntentStatus.STARTED:
                    if row.broker_task_id == broker_task_id:
                        return GraphResumeDeliveryAdmission.ACCEPTED
                    expected = deterministic_graph_resume_task_id(
                        row.intent_id,
                        int(row.revision or 1),
                    )
                    if broker_task_id == expected:
                        return GraphResumeDeliveryAdmission.ACCEPTED
                    return GraphResumeDeliveryAdmission.STALE_SUPERSEDED
                if current is not InvestigationIntentStatus.ENQUEUED:
                    return GraphResumeDeliveryAdmission.STALE_SUPERSEDED
                validate_intent_transition(current, InvestigationIntentStatus.STARTED)
                row.status = InvestigationIntentStatus.STARTED.value
                row.broker_task_id = broker_task_id
                row.claim_owner = None
                row.claim_expires_at = None
                return GraphResumeDeliveryAdmission.ACCEPTED

    async def execute_intent_delivery(
        self,
        intent_id: str,
        *,
        broker_task_id: str,
    ) -> GraphResumeDeliveryAdmission:
        admission = await self.mark_started(intent_id, broker_task_id=broker_task_id)
        if admission is not GraphResumeDeliveryAdmission.ACCEPTED:
            return admission
        if await self._execute_claimed_intent(intent_id):
            return GraphResumeDeliveryAdmission.ACCEPTED
        return GraphResumeDeliveryAdmission.HOLD_MISMATCH

    async def reconcile_stale(self, *, limit: int = 20) -> int:
        now = datetime.now(UTC)
        lease_s = int(self._settings.graph_resume_claim_lease_s)
        max_attempts = int(self._settings.graph_resume_max_attempts)
        reconciled = 0
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.GraphResumeIntent)
                        .where(
                            orm.GraphResumeIntent.status.in_(
                                (
                                    InvestigationIntentStatus.CLAIMED.value,
                                    InvestigationIntentStatus.ENQUEUED.value,
                                    InvestigationIntentStatus.STARTED.value,
                                )
                            )
                        )
                        .order_by(orm.GraphResumeIntent.updated_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    status = InvestigationIntentStatus(row.status)
                    stale = self._is_stale_row(row, status=status, now=now, lease_seconds=lease_s)
                    if not stale:
                        continue
                    if await self._reconcile_stale_row(
                        row,
                        status=status,
                        max_attempts=max_attempts,
                    ):
                        reconciled += 1
        if reconciled:
            self.schedule_dispatch()
        return reconciled

    async def _execute_claimed_intent(self, intent_id: str) -> bool:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.GraphResumeIntent, intent_id, with_for_update=True)
                if row is None:
                    return False
                current = InvestigationIntentStatus(row.status)
                if current not in {
                    InvestigationIntentStatus.CLAIMED,
                    InvestigationIntentStatus.ENQUEUED,
                    InvestigationIntentStatus.STARTED,
                }:
                    return False
                hold_gen = await _read_journal_scalar(
                    session,
                    row.event_id,
                    "manual_hold_generation",
                )
                substate = await _read_journal_scalar(
                    session,
                    row.event_id,
                    "execution_substate",
                )
                if hold_gen is None or int(hold_gen) != int(row.hold_generation):
                    validate_intent_transition(current, InvestigationIntentStatus.SKIPPED)
                    row.status = InvestigationIntentStatus.SKIPPED.value
                    row.skip_reason = "hold_generation_mismatch"
                    return False
                if substate != ExecutionSubstate.MANUAL_RESOLUTION.value:
                    validate_intent_transition(current, InvestigationIntentStatus.SKIPPED)
                    row.status = InvestigationIntentStatus.SKIPPED.value
                    row.skip_reason = "not_manual_resolution"
                    return False
                if current is InvestigationIntentStatus.CLAIMED:
                    validate_intent_transition(current, InvestigationIntentStatus.ENQUEUED)
                    row.status = InvestigationIntentStatus.ENQUEUED.value
                    row.broker_task_id = deterministic_graph_resume_task_id(
                        row.intent_id,
                        int(row.revision or 1),
                    )
                    validate_intent_transition(
                        InvestigationIntentStatus.ENQUEUED,
                        InvestigationIntentStatus.STARTED,
                    )
                    row.status = InvestigationIntentStatus.STARTED.value
                event_id = row.event_id

        if self._resume is None:
            await self._transition(
                intent_id,
                InvestigationIntentStatus.DEAD,
                last_error="no_resume_hook",
            )
            return False

        try:
            await self._resume(event_id)
        except Exception as exc:
            logger.warning(
                "graph resume hook failed event=%s intent=%s",
                event_id,
                intent_id,
                exc_info=True,
            )
            await self._handle_execution_failure(intent_id, exc)
            return False

        await self._transition(intent_id, InvestigationIntentStatus.TERMINAL, clear_claim=True)
        return True

    async def _handle_execution_failure(self, intent_id: str, exc: Exception) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.GraphResumeIntent, intent_id)
                if row is None:
                    return
                current = InvestigationIntentStatus(row.status)
                if current in TERMINAL_INTENT_STATUSES:
                    return
                next_attempt = int(row.attempt or 0) + 1
                if next_attempt >= int(self._settings.graph_resume_max_attempts):
                    validate_intent_transition(current, InvestigationIntentStatus.DEAD)
                    row.status = InvestigationIntentStatus.DEAD.value
                    row.last_error = str(exc)
                else:
                    validate_intent_transition(current, InvestigationIntentStatus.RETRY)
                    row.status = InvestigationIntentStatus.RETRY.value
                    row.attempt = next_attempt
                    row.revision = int(row.revision or 1) + 1
                    row.last_error = str(exc)
                row.broker_task_id = None
                row.claim_owner = None
                row.claim_expires_at = None

    async def _claim_batch(self, *, limit: int) -> list[str]:
        now = datetime.now(UTC)
        lease = timedelta(seconds=int(self._settings.graph_resume_claim_lease_s))
        claimed: list[str] = []
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.GraphResumeIntent)
                        .where(
                            or_(
                                orm.GraphResumeIntent.status.in_(
                                    (
                                        InvestigationIntentStatus.PENDING.value,
                                        InvestigationIntentStatus.RETRY.value,
                                    )
                                ),
                                and_(
                                    orm.GraphResumeIntent.status
                                    == InvestigationIntentStatus.CLAIMED.value,
                                    orm.GraphResumeIntent.claim_expires_at.is_not(None),
                                    orm.GraphResumeIntent.claim_expires_at < now,
                                ),
                            )
                        )
                        .order_by(orm.GraphResumeIntent.created_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    current = InvestigationIntentStatus(row.status)
                    if (
                        current is InvestigationIntentStatus.CLAIMED
                        and row.claim_expires_at is not None
                        and row.claim_expires_at < now
                    ):
                        validate_intent_transition(current, InvestigationIntentStatus.RETRY)
                        row.status = InvestigationIntentStatus.RETRY.value
                        row.attempt = int(row.attempt or 0) + 1
                        current = InvestigationIntentStatus.RETRY
                    validate_intent_transition(current, InvestigationIntentStatus.CLAIMED)
                    row.status = InvestigationIntentStatus.CLAIMED.value
                    row.claim_owner = self._worker_id
                    row.claim_expires_at = now + lease
                    claimed.append(row.intent_id)
        return claimed

    async def _transition(
        self,
        intent_id: str,
        target: InvestigationIntentStatus,
        *,
        last_error: str | None = None,
        clear_claim: bool = False,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.GraphResumeIntent, intent_id)
                if row is None:
                    return
                current = InvestigationIntentStatus(row.status)
                if current in TERMINAL_INTENT_STATUSES:
                    return
                validate_intent_transition(current, target)
                row.status = target.value
                if last_error is not None:
                    row.last_error = last_error
                if clear_claim:
                    row.claim_owner = None
                    row.claim_expires_at = None
                    row.broker_task_id = None

    @staticmethod
    def _is_stale_row(
        row: orm.GraphResumeIntent,
        *,
        status: InvestigationIntentStatus,
        now: datetime,
        lease_seconds: int,
    ) -> bool:
        if row.claim_expires_at is not None and row.claim_expires_at < now:
            return True
        if status is InvestigationIntentStatus.ENQUEUED:
            return (now - row.updated_at) > timedelta(seconds=lease_seconds * 4)
        if status is InvestigationIntentStatus.STARTED:
            return (now - row.updated_at) > timedelta(seconds=_STARTED_STALE_MIN_S)
        return False

    async def _reconcile_stale_row(
        self,
        row: orm.GraphResumeIntent,
        *,
        status: InvestigationIntentStatus,
        max_attempts: int,
    ) -> bool:
        next_attempt = int(row.attempt or 0) + 1
        if next_attempt >= max_attempts:
            validate_intent_transition(status, InvestigationIntentStatus.DEAD)
            row.status = InvestigationIntentStatus.DEAD.value
            row.last_error = row.last_error or "max_attempts_exceeded"
        else:
            validate_intent_transition(status, InvestigationIntentStatus.RETRY)
            row.status = InvestigationIntentStatus.RETRY.value
            row.attempt = next_attempt
            row.last_error = row.last_error or "stale_graph_resume_reconciled"
        row.broker_task_id = None
        row.claim_owner = None
        row.claim_expires_at = None
        row.revision = int(row.revision or 1) + 1
        return True


__all__ = [
    "ManualHoldSnapshot",
    "ManualResolutionService",
    "ResolutionResumeResult",
    "deterministic_graph_resume_task_id",
    "new_graph_resume_intent_id",
    "stable_operation_id",
]
