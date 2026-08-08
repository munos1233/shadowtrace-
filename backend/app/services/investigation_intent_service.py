"""PostgreSQL durable auto-investigate intent dispatcher (ISSUE-108 / #612)."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import NamedTuple, cast

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.errors import (
    DependencyUnavailableError,
    EventNotFoundError,
    InvestigationInProgressError,
    InvestigationIntentConflictError,
    InvalidStateTransitionError,
)
from app.db import models as orm
from app.models.enums import EventStatus, InvestigationIntentStatus
from app.models.investigation_intent import (
    INTENT_KIND_AUTO_INVESTIGATE,
    INTENT_KIND_HTTP_INVESTIGATE,
    INTENT_VERSION_ISSUE108_V1,
    INTENT_VERSION_ISSUE276_V1,
    PRIMARY_LINK_ROLE,
    PROVISIONAL_LINK_ROLE,
    TERMINAL_INTENT_STATUSES,
    UNKNOWN_LINK_ROLE,
    IntentDeliveryAdmission,
    validate_intent_transition,
)
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.auto_response_policy import (
    AutoResponsePolicyService,
    format_auto_response_audit_reason,
)
from app.services.degraded_flag_service import DegradedFlagService

logger = logging.getLogger(__name__)

_DISPATCH_WORKER_ID = "intent-dispatcher-1"

# Event left NEW while intent is STARTED beyond this window → worker crash / retry.
_STARTED_STALE_MIN_S = 660

_EVENT_INVESTIGATION_UNDERWAY = frozenset(
    {
        EventStatus.TRIAGING.value,
        EventStatus.COLLECTING_EVIDENCE.value,
        EventStatus.ANALYZING.value,
        EventStatus.SCORING.value,
        EventStatus.PLANNING_RESPONSE.value,
        EventStatus.WAITING_APPROVAL.value,
        EventStatus.EXECUTING_RESPONSE.value,
        EventStatus.VERIFYING.value,
        EventStatus.REPLANNING.value,
        EventStatus.CONTAINED.value,
        EventStatus.REPORTING.value,
        EventStatus.CLOSED.value,
    }
)


def new_intent_id() -> str:
    return f"iin-{secrets.token_hex(8)}"


def deterministic_investigation_task_id(intent_id: str, revision: int) -> str:
    """Stable Celery task id derived from intent identity (#612)."""
    return hashlib.sha256(f"{intent_id}:{revision}".encode()).hexdigest()


def default_http_investigate_idempotency_key(event_id: str) -> str:
    return f"http_investigate:{event_id}"


def compute_http_investigate_payload_hash(
    *,
    orchestration_mode: str,
    include_response_execution: bool,
    generate_report: bool,
) -> str:
    payload = json.dumps(
        {
            "orchestration_mode": orchestration_mode.strip().lower(),
            "include_response_execution": bool(include_response_execution),
            "generate_report": bool(generate_report),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class HttpInvestigateIntentResult(NamedTuple):
    intent_id: str
    task_id: str
    replayed: bool


async def _resolve_response_link_role(
    session: AsyncSession,
    event_id: str,
) -> str:
    """Resolve source link role for auto-response gating (fail closed on provisional)."""
    roles = (
        await session.scalars(
            select(orm.SourceEventLink.role).where(
                orm.SourceEventLink.event_id == event_id,
                orm.SourceEventLink.role.in_(
                    (PROVISIONAL_LINK_ROLE, PRIMARY_LINK_ROLE),
                ),
            )
        )
    ).all()
    role_set = {str(role) for role in roles}
    if PROVISIONAL_LINK_ROLE in role_set:
        return PROVISIONAL_LINK_ROLE
    if PRIMARY_LINK_ROLE in role_set:
        return PRIMARY_LINK_ROLE
    return UNKNOWN_LINK_ROLE


class _EnqueuedPublishTarget(NamedTuple):
    event_id: str
    task_id: str
    intent_id: str
    include_response_execution: bool
    generate_report: bool
    orchestration_mode: str


class InvestigationIntentService:
    """Owns investigation_intent rows and broker dispatch bookkeeping."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        policy: AutoInvestigatePolicyService | None = None,
        auto_response_policy: AutoResponsePolicyService | None = None,
        degraded_flags: DegradedFlagService | None = None,
        settings: Settings | None = None,
        worker_id: str = _DISPATCH_WORKER_ID,
    ) -> None:
        self._session_factory = session_factory
        self._policy = policy or AutoInvestigatePolicyService(settings)
        self._auto_response = auto_response_policy or AutoResponsePolicyService(settings)
        self._degraded = degraded_flags
        self._settings = settings or get_settings()
        self._worker_id = worker_id

    @property
    def policy(self) -> AutoInvestigatePolicyService:
        return self._policy

    @property
    def auto_response_policy(self) -> AutoResponsePolicyService:
        return self._auto_response

    def _http_intent_task_id(self, row: orm.InvestigationIntent) -> str:
        return deterministic_investigation_task_id(row.intent_id, int(row.revision or 1))

    def _resolve_http_intent_replay(
        self,
        row: orm.InvestigationIntent,
        *,
        payload_hash: str,
        idempotency_key: str,
        event_id: str,
    ) -> HttpInvestigateIntentResult | None:
        if row.payload_hash != payload_hash:
            raise InvestigationIntentConflictError(
                message="investigation idempotency key reused with different payload",
                error_code="investigation_intent_conflict",
                details={
                    "event_id": event_id,
                    "idempotency_key": idempotency_key,
                    "intent_id": row.intent_id,
                },
            )
        return HttpInvestigateIntentResult(
            intent_id=row.intent_id,
            task_id=self._http_intent_task_id(row),
            replayed=True,
        )

    async def submit_http_investigate_intent(
        self,
        *,
        event_id: str,
        idempotency_key: str,
        orchestration_mode: str,
        include_response_execution: bool,
        generate_report: bool,
    ) -> HttpInvestigateIntentResult:
        """Create or replay a durable HTTP investigation intent before returning 202."""
        normalized_mode = orchestration_mode.strip().lower()
        payload_hash = compute_http_investigate_payload_hash(
            orchestration_mode=normalized_mode,
            include_response_execution=include_response_execution,
            generate_report=generate_report,
        )
        async with self._session_factory() as session:
            async with session.begin():
                event = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if event is None:
                    raise EventNotFoundError(
                        f"event {event_id} not found",
                        details={"event_id": event_id},
                    )
                if event.status != EventStatus.NEW.value:
                    raise InvalidStateTransitionError(
                        (
                            "event must be in NEW status to start investigation, "
                            f"current: {event.status}"
                        ),
                        current=EventStatus(event.status),
                        target=EventStatus.TRIAGING,
                        details={"event_id": event_id},
                    )

                existing_by_key = await session.scalar(
                    select(orm.InvestigationIntent).where(
                        orm.InvestigationIntent.idempotency_key == idempotency_key
                    )
                )
                if existing_by_key is not None:
                    replay = self._resolve_http_intent_replay(
                        existing_by_key,
                        payload_hash=payload_hash,
                        idempotency_key=idempotency_key,
                        event_id=event_id,
                    )
                    if replay is not None:
                        return replay

                existing_by_event = await session.scalar(
                    select(orm.InvestigationIntent).where(
                        orm.InvestigationIntent.event_id == event_id,
                        orm.InvestigationIntent.intent_kind == INTENT_KIND_HTTP_INVESTIGATE,
                        orm.InvestigationIntent.intent_version == INTENT_VERSION_ISSUE276_V1,
                    )
                )
                if existing_by_event is not None:
                    status = InvestigationIntentStatus(existing_by_event.status)
                    if existing_by_event.idempotency_key == idempotency_key:
                        replay = self._resolve_http_intent_replay(
                            existing_by_event,
                            payload_hash=payload_hash,
                            idempotency_key=idempotency_key,
                            event_id=event_id,
                        )
                        if replay is not None:
                            return replay
                    if status not in TERMINAL_INTENT_STATUSES:
                        raise InvestigationInProgressError(
                            message="investigation already in progress for this event",
                            error_code="investigation_in_progress",
                            details={"event_id": event_id, "intent_id": existing_by_event.intent_id},
                        )
                    if existing_by_event.payload_hash != payload_hash:
                        raise InvestigationIntentConflictError(
                            message="investigation intent already exists with different payload",
                            error_code="investigation_intent_conflict",
                            details={
                                "event_id": event_id,
                                "idempotency_key": idempotency_key,
                                "intent_id": existing_by_event.intent_id,
                            },
                        )
                    return self._resolve_http_intent_replay(
                        existing_by_event,
                        payload_hash=payload_hash,
                        idempotency_key=idempotency_key,
                        event_id=event_id,
                    )

                intent_id = new_intent_id()
                row = orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind=INTENT_KIND_HTTP_INVESTIGATE,
                    intent_version=INTENT_VERSION_ISSUE276_V1,
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=include_response_execution,
                    generate_report=generate_report,
                    idempotency_key=idempotency_key,
                    payload_hash=payload_hash,
                    orchestration_mode=normalized_mode,
                )
                session.add(row)
                try:
                    await session.flush()
                except IntegrityError as exc:
                    raise InvestigationInProgressError(
                        message="investigation already in progress for this event",
                        error_code="investigation_in_progress",
                        details={"event_id": event_id},
                    ) from exc

        self.schedule_dispatch()
        return HttpInvestigateIntentResult(
            intent_id=intent_id,
            task_id=deterministic_investigation_task_id(intent_id, 1),
            replayed=False,
        )

    async def maybe_create_pending_in_session(
        self,
        session: AsyncSession,
        event: orm.SecurityEvent,
        *,
        link_role: str,
        source_product: str | None,
        created_or_promoted: bool,
    ) -> str | None:
        """Insert a pending intent in the same transaction as event create/promote."""
        if not created_or_promoted or not self._policy.enabled:
            return None
        decision = self._policy.evaluate(
            event,
            link_role=link_role,
            source_product=source_product,
        )
        if not decision.eligible:
            return None
        existing = await session.scalar(
            select(orm.InvestigationIntent.intent_id).where(
                orm.InvestigationIntent.event_id == event.event_id,
                orm.InvestigationIntent.intent_kind == INTENT_KIND_AUTO_INVESTIGATE,
                orm.InvestigationIntent.intent_version == INTENT_VERSION_ISSUE108_V1,
            )
        )
        if existing is not None:
            return None
        intent_id = new_intent_id()
        row = orm.InvestigationIntent(
            intent_id=intent_id,
            event_id=event.event_id,
            intent_kind=INTENT_KIND_AUTO_INVESTIGATE,
            intent_version=INTENT_VERSION_ISSUE108_V1,
            status=InvestigationIntentStatus.PENDING.value,
            revision=1,
            attempt=0,
            include_response_execution=False,
            generate_report=False,
        )
        session.add(row)
        session.add(
            orm.EventAuditLog(
                event_id=event.event_id,
                from_status=event.status,
                to_status=event.status,
                operator="AutoInvestigatePolicyService",
                reason=decision.reason,
            )
        )
        try:
            await session.flush()
        except IntegrityError:
            logger.info(
                "investigation intent already exists event=%s kind=%s",
                event.event_id,
                INTENT_KIND_AUTO_INVESTIGATE,
            )
            return None
        return intent_id

    def schedule_dispatch(self) -> None:
        """Best-effort async dispatch trigger; must never raise to ingest callers."""
        if not self._policy.enabled:
            return
        try:
            from app.tasks.investigation_intent_tasks import dispatch_pending_investigation_intents

            dispatch_pending_investigation_intents.delay()
        except Exception:
            logger.warning(
                "failed to enqueue investigation intent dispatch",
                exc_info=True,
            )

    async def dispatch_sync_batch(self, *, limit: int = 10) -> dict[str, int]:
        """Synchronously claim and publish pending intents (#612 management API).

        Raises ``DependencyUnavailableError`` when broker/metadata is unavailable
        and no investigation task was accepted by the broker in this batch.
        """
        claimed = await self._claim_batch(limit=limit)
        published = 0
        transient_failure = False
        for intent_id in claimed:
            try:
                if await self._publish_claimed_intent(intent_id, strict=True):
                    published += 1
            except DependencyUnavailableError:
                transient_failure = True
        if transient_failure and published == 0:
            raise DependencyUnavailableError(
                message="celery broker unavailable",
                error_code="dependency_unavailable",
                details={"dependency": "celery_broker", "claimed": len(claimed)},
            )
        return {"claimed": len(claimed), "published": published}

    async def skip_active_intents_for_event_in_session(
        self,
        session: AsyncSession,
        event_id: str,
        *,
        reason: str,
    ) -> int:
        """Mark non-terminal auto-investigate intents skipped (e.g. event merged away)."""
        rows = (
            await session.scalars(
                select(orm.InvestigationIntent).where(
                    orm.InvestigationIntent.event_id == event_id,
                    orm.InvestigationIntent.intent_kind == INTENT_KIND_AUTO_INVESTIGATE,
                    orm.InvestigationIntent.intent_version == INTENT_VERSION_ISSUE108_V1,
                    orm.InvestigationIntent.status.not_in(
                        tuple(status.value for status in TERMINAL_INTENT_STATUSES)
                    ),
                )
            )
        ).all()
        skipped = 0
        for row in rows:
            current = InvestigationIntentStatus(row.status)
            validate_intent_transition(current, InvestigationIntentStatus.SKIPPED)
            row.status = InvestigationIntentStatus.SKIPPED.value
            row.skip_reason = reason
            row.broker_task_id = None
            row.claim_owner = None
            row.claim_expires_at = None
            skipped += 1
        return skipped

    async def claim_and_publish_batch(self, *, limit: int = 10) -> int:
        claimed = await self._claim_batch(limit=limit)
        published = 0
        for intent_id in claimed:
            if await self._publish_claimed_intent(intent_id):
                published += 1
        return published

    async def mark_started(self, intent_id: str, *, broker_task_id: str) -> IntentDeliveryAdmission:
        """Admit or reject a Celery delivery against the durable intent ledger."""
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return IntentDeliveryAdmission.MISSING
                current = InvestigationIntentStatus(row.status)
                if current in TERMINAL_INTENT_STATUSES:
                    return IntentDeliveryAdmission.ALREADY_TERMINAL
                if current is InvestigationIntentStatus.STARTED:
                    if row.broker_task_id == broker_task_id:
                        return IntentDeliveryAdmission.ACCEPTED
                    expected = deterministic_investigation_task_id(
                        row.intent_id,
                        int(row.revision or 1),
                    )
                    if broker_task_id == expected:
                        row.broker_task_id = broker_task_id
                        return IntentDeliveryAdmission.ACCEPTED
                    logger.warning(
                        "investigation intent already started intent=%s "
                        "existing_task=%s new_task=%s",
                        intent_id,
                        row.broker_task_id,
                        broker_task_id,
                    )
                    return IntentDeliveryAdmission.STALE_SUPERSEDED
                if current is not InvestigationIntentStatus.ENQUEUED:
                    logger.warning(
                        "broker task ignored for non-enqueued intent=%s status=%s task=%s",
                        intent_id,
                        current.value,
                        broker_task_id,
                    )
                    return IntentDeliveryAdmission.STALE_SUPERSEDED
                if row.broker_task_id and row.broker_task_id != broker_task_id:
                    logger.warning(
                        "stale broker task ignored intent=%s expected=%s got=%s",
                        intent_id,
                        row.broker_task_id,
                        broker_task_id,
                    )
                    return IntentDeliveryAdmission.STALE_SUPERSEDED
                validate_intent_transition(current, InvestigationIntentStatus.STARTED)
                row.status = InvestigationIntentStatus.STARTED.value
                row.broker_task_id = broker_task_id
                row.claim_owner = None
                row.claim_expires_at = None
                return IntentDeliveryAdmission.ACCEPTED

    async def mark_terminal(self, intent_id: str) -> None:
        await self._transition(intent_id, InvestigationIntentStatus.TERMINAL, clear_claim=True)

    async def mark_skipped(self, intent_id: str, *, reason: str) -> None:
        await self._transition(
            intent_id,
            InvestigationIntentStatus.SKIPPED,
            skip_reason=reason,
            clear_claim=True,
        )

    async def mark_retry(self, intent_id: str, *, error: str) -> None:
        await self._transition(
            intent_id,
            InvestigationIntentStatus.RETRY,
            last_error=error,
            increment_attempt=True,
            clear_claim=True,
        )

    async def mark_dead(self, intent_id: str, *, error: str) -> None:
        await self._transition(
            intent_id,
            InvestigationIntentStatus.DEAD,
            last_error=error,
            clear_claim=True,
        )

    async def reconcile_stale(self, *, limit: int = 20) -> int:
        now = datetime.now(UTC)
        lease_seconds = int(self._settings.auto_investigate_claim_lease_s)
        max_attempts = int(self._settings.auto_investigate_max_attempts)
        started_stale_s = max(lease_seconds * 4, _STARTED_STALE_MIN_S)
        reconciled = 0
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.InvestigationIntent)
                        .where(
                            orm.InvestigationIntent.status.in_(
                                (
                                    InvestigationIntentStatus.CLAIMED.value,
                                    InvestigationIntentStatus.ENQUEUED.value,
                                    InvestigationIntentStatus.STARTED.value,
                                )
                            )
                        )
                        .order_by(orm.InvestigationIntent.updated_at.asc())
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                for row in rows:
                    status = InvestigationIntentStatus(row.status)
                    if not self._is_stale_intent_row(
                        row,
                        status=status,
                        now=now,
                        lease_seconds=lease_seconds,
                        started_stale_s=started_stale_s,
                    ):
                        continue
                    event = await session.get(orm.SecurityEvent, row.event_id)
                    if await self._reconcile_stale_row(
                        row,
                        status=status,
                        event=event,
                        max_attempts=max_attempts,
                    ):
                        reconciled += 1
        if reconciled:
            self.schedule_dispatch()
        provisional_created = await self._materialize_provisional_intents(
            limit=int(self._settings.auto_investigate_materialize_batch_size)
        )
        return reconciled + provisional_created

    def _is_stale_intent_row(
        self,
        row: orm.InvestigationIntent,
        *,
        status: InvestigationIntentStatus,
        now: datetime,
        lease_seconds: int,
        started_stale_s: int,
    ) -> bool:
        if row.claim_expires_at is not None and row.claim_expires_at < now:
            return True
        if status is InvestigationIntentStatus.ENQUEUED:
            return (now - row.updated_at) > timedelta(seconds=lease_seconds * 4)
        if status is InvestigationIntentStatus.STARTED:
            return (now - row.updated_at) > timedelta(seconds=started_stale_s)
        return False

    async def _reconcile_stale_row(
        self,
        row: orm.InvestigationIntent,
        *,
        status: InvestigationIntentStatus,
        event: orm.SecurityEvent | None,
        max_attempts: int,
    ) -> bool:
        if status is InvestigationIntentStatus.STARTED and event is not None:
            if event.status in _EVENT_INVESTIGATION_UNDERWAY:
                validate_intent_transition(status, InvestigationIntentStatus.TERMINAL)
                row.status = InvestigationIntentStatus.TERMINAL.value
                row.claim_owner = None
                row.claim_expires_at = None
                return True
            if event.status == EventStatus.FAILED.value:
                validate_intent_transition(status, InvestigationIntentStatus.SKIPPED)
                row.status = InvestigationIntentStatus.SKIPPED.value
                row.skip_reason = "event_failed"
                row.claim_owner = None
                row.claim_expires_at = None
                return True

        next_attempt = int(row.attempt or 0) + 1
        if next_attempt >= max_attempts:
            validate_intent_transition(status, InvestigationIntentStatus.DEAD)
            row.status = InvestigationIntentStatus.DEAD.value
            row.last_error = row.last_error or "max_attempts_exceeded"
        else:
            validate_intent_transition(status, InvestigationIntentStatus.RETRY)
            row.status = InvestigationIntentStatus.RETRY.value
            row.attempt = next_attempt
            row.last_error = row.last_error or "stale_intent_reconciled"
        row.broker_task_id = None
        row.claim_owner = None
        row.claim_expires_at = None
        row.revision = int(row.revision or 1) + 1
        return True

    async def lookup_by_broker_task_id(self, broker_task_id: str) -> orm.InvestigationIntent | None:
        async with self._session_factory() as session:
            return cast(
                orm.InvestigationIntent | None,
                await session.scalar(
                    select(orm.InvestigationIntent).where(
                        orm.InvestigationIntent.broker_task_id == broker_task_id
                    )
                ),
            )

    async def lookup_active_for_event(self, event_id: str) -> orm.InvestigationIntent | None:
        """Return the latest auto-investigate intent for an event (at most one per uq)."""
        async with self._session_factory() as session:
            return cast(
                orm.InvestigationIntent | None,
                await session.scalar(
                    select(orm.InvestigationIntent)
                    .where(
                        orm.InvestigationIntent.event_id == event_id,
                        orm.InvestigationIntent.intent_kind == INTENT_KIND_AUTO_INVESTIGATE,
                        orm.InvestigationIntent.intent_version == INTENT_VERSION_ISSUE108_V1,
                    )
                    .order_by(orm.InvestigationIntent.created_at.desc())
                    # Explicit limit aligns scalar() semantics; uq allows <=1 row anyway.
                    .limit(1)
                ),
            )

    async def _claim_batch(self, *, limit: int) -> list[str]:
        now = datetime.now(UTC)
        lease = timedelta(seconds=int(self._settings.auto_investigate_claim_lease_s))
        claimed: list[str] = []
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.InvestigationIntent)
                        .where(
                            or_(
                                orm.InvestigationIntent.status.in_(
                                    (
                                        InvestigationIntentStatus.PENDING.value,
                                        InvestigationIntentStatus.RETRY.value,
                                    )
                                ),
                                and_(
                                    orm.InvestigationIntent.status
                                    == InvestigationIntentStatus.CLAIMED.value,
                                    orm.InvestigationIntent.claim_expires_at.is_not(None),
                                    orm.InvestigationIntent.claim_expires_at < now,
                                ),
                            )
                        )
                        .order_by(orm.InvestigationIntent.created_at.asc())
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

    async def _handle_publish_transient_failure(
        self,
        row: orm.InvestigationIntent,
        exc: Exception,
    ) -> None:
        if int(row.attempt or 0) + 1 >= int(self._settings.auto_investigate_max_attempts):
            await self._set_status_in_session(
                row,
                InvestigationIntentStatus.DEAD,
                last_error=str(exc),
            )
        else:
            await self._set_status_in_session(
                row,
                InvestigationIntentStatus.RETRY,
                last_error=str(exc),
                increment_attempt=True,
            )
        if self._degraded is not None:
            await self._degraded.set_flag(
                row.event_id,
                "auto_investigate_dispatch_unavailable",
                True,
                writer="InvestigationIntentService",
            )

    async def _set_auto_response_dispatch_degraded(self, event_id: str) -> None:
        if self._degraded is not None:
            await self._degraded.set_flag(
                event_id,
                "auto_response_dispatch_unavailable",
                True,
                writer="InvestigationIntentService",
            )

    async def _commit_enqueued_publish_target(
        self,
        intent_id: str,
    ) -> _EnqueuedPublishTarget | None:
        """Persist ENQUEUED before broker publish so workers never see pre-commit rows."""
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return None
                if InvestigationIntentStatus(row.status) is not InvestigationIntentStatus.CLAIMED:
                    return None
                event = await session.get(orm.SecurityEvent, row.event_id)
                if event is None:
                    await self._set_status_in_session(
                        row,
                        InvestigationIntentStatus.SKIPPED,
                        skip_reason="event_missing",
                    )
                    return None
                if event.status != EventStatus.NEW.value:
                    await self._set_status_in_session(
                        row,
                        InvestigationIntentStatus.SKIPPED,
                        skip_reason="event_not_new",
                    )
                    return None
                orchestration_mode = (row.orchestration_mode or "graph").strip().lower()
                if row.intent_kind == INTENT_KIND_HTTP_INVESTIGATE:
                    include_response = bool(row.include_response_execution)
                else:
                    source_product = None
                    if event.creation_source_ref:
                        raw = event.creation_source_ref.get("source_product")
                        if isinstance(raw, str):
                            source_product = raw
                    link_role = await _resolve_response_link_role(session, event.event_id)
                    response_decision = self._auto_response.evaluate(
                        event,
                        link_role=link_role,
                        source_product=source_product,
                    )
                    include_response = response_decision.eligible
                    row.include_response_execution = include_response
                    if self._auto_response.enabled:
                        session.add(
                            orm.EventAuditLog(
                                event_id=event.event_id,
                                from_status=event.status,
                                to_status=event.status,
                                operator="AutoResponsePolicyService",
                                reason=format_auto_response_audit_reason(response_decision),
                            )
                        )
                task_id = deterministic_investigation_task_id(row.intent_id, int(row.revision))
                validate_intent_transition(
                    InvestigationIntentStatus.CLAIMED,
                    InvestigationIntentStatus.ENQUEUED,
                )
                row.status = InvestigationIntentStatus.ENQUEUED.value
                row.broker_task_id = task_id
                row.claim_owner = None
                row.claim_expires_at = None
                row.last_error = None
                return _EnqueuedPublishTarget(
                    row.event_id,
                    task_id,
                    row.intent_id,
                    include_response,
                    bool(row.generate_report),
                    orchestration_mode,
                )

    async def _revert_enqueued_after_publish_failure(
        self,
        intent_id: str,
        exc: Exception,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return
                if InvestigationIntentStatus(row.status) is not InvestigationIntentStatus.ENQUEUED:
                    return
                await self._handle_publish_transient_failure(row, exc)
                row.broker_task_id = None

    async def _revert_enqueued_after_unexpected_failure(
        self,
        intent_id: str,
        exc: Exception,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return
                if InvestigationIntentStatus(row.status) is not InvestigationIntentStatus.ENQUEUED:
                    return
                await self._set_status_in_session(
                    row,
                    InvestigationIntentStatus.DEAD,
                    last_error=str(exc),
                )
                row.broker_task_id = None

    async def _publish_claimed_intent(self, intent_id: str, *, strict: bool = False) -> bool:
        target = await self._commit_enqueued_publish_target(intent_id)
        if target is None:
            return False

        from kombu.exceptions import OperationalError

        from app.tasks.investigation_tasks import (
            delete_task_metadata,
            publish_analysis_only_for_intent,
            publish_investigation_for_intent,
            register_task_metadata,
        )

        try:
            await register_task_metadata(target.task_id, target.event_id)
            if target.orchestration_mode == "analysis_only":
                publish_analysis_only_for_intent(
                    event_id=target.event_id,
                    task_id=target.task_id,
                    intent_id=target.intent_id,
                    generate_report=target.generate_report,
                )
            else:
                publish_investigation_for_intent(
                    event_id=target.event_id,
                    task_id=target.task_id,
                    intent_id=target.intent_id,
                    include_response_execution=target.include_response_execution,
                    generate_report=target.generate_report,
                )
        except DependencyUnavailableError as exc:
            await delete_task_metadata(target.task_id)
            logger.warning(
                "task metadata store unavailable intent=%s event=%s",
                target.intent_id,
                target.event_id,
                exc_info=True,
            )
            await self._revert_enqueued_after_publish_failure(target.intent_id, exc)
            if target.include_response_execution:
                await self._set_auto_response_dispatch_degraded(target.event_id)
            if strict:
                raise
            return False
        except (OperationalError, OSError, ConnectionError) as exc:
            await delete_task_metadata(target.task_id)
            logger.warning(
                "broker publish failed intent=%s event=%s err=%s",
                target.intent_id,
                target.event_id,
                exc,
                exc_info=True,
            )
            await self._revert_enqueued_after_publish_failure(target.intent_id, exc)
            if target.include_response_execution:
                await self._set_auto_response_dispatch_degraded(target.event_id)
            if strict:
                raise DependencyUnavailableError(
                    message="celery broker unavailable",
                    error_code="dependency_unavailable",
                    details={
                        "dependency": "celery_broker",
                        "event_id": target.event_id,
                        "intent_id": target.intent_id,
                    },
                ) from exc
            return False
        except Exception as exc:
            await delete_task_metadata(target.task_id)
            logger.error(
                "unexpected publish failure intent=%s event=%s",
                target.intent_id,
                target.event_id,
                exc_info=True,
            )
            await self._revert_enqueued_after_unexpected_failure(target.intent_id, exc)
            if target.include_response_execution:
                await self._set_auto_response_dispatch_degraded(target.event_id)
            return False
        return True

    async def _transition(
        self,
        intent_id: str,
        target: InvestigationIntentStatus,
        *,
        broker_task_id: str | None = None,
        skip_reason: str | None = None,
        last_error: str | None = None,
        increment_attempt: bool = False,
        clear_claim: bool = False,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return
                current = InvestigationIntentStatus(row.status)
                if current in TERMINAL_INTENT_STATUSES:
                    return
                validate_intent_transition(current, target)
                row.status = target.value
                if broker_task_id is not None:
                    row.broker_task_id = broker_task_id
                if skip_reason is not None:
                    row.skip_reason = skip_reason
                if last_error is not None:
                    row.last_error = last_error
                if increment_attempt:
                    row.attempt = int(row.attempt or 0) + 1
                    row.revision = int(row.revision or 1) + 1
                if clear_claim:
                    row.claim_owner = None
                    row.claim_expires_at = None

    async def _set_status_in_session(
        self,
        row: orm.InvestigationIntent,
        target: InvestigationIntentStatus,
        *,
        skip_reason: str | None = None,
        last_error: str | None = None,
        increment_attempt: bool = False,
    ) -> None:
        current = InvestigationIntentStatus(row.status)
        validate_intent_transition(current, target)
        row.status = target.value
        if skip_reason is not None:
            row.skip_reason = skip_reason
        if last_error is not None:
            row.last_error = last_error
        if increment_attempt:
            row.attempt = int(row.attempt or 0) + 1
            row.revision = int(row.revision or 1) + 1
        row.claim_owner = None
        row.claim_expires_at = None

    async def _materialize_provisional_intents(self, *, limit: int) -> int:
        if not self._policy.enabled:
            return 0
        window = timedelta(seconds=int(self._settings.auto_investigate_provisional_window_s))
        cutoff = datetime.now(UTC) - window
        intent_exists = (
            select(orm.InvestigationIntent.intent_id)
            .where(
                orm.InvestigationIntent.event_id == orm.SecurityEvent.event_id,
                orm.InvestigationIntent.intent_kind == INTENT_KIND_AUTO_INVESTIGATE,
                orm.InvestigationIntent.intent_version == INTENT_VERSION_ISSUE108_V1,
            )
            .exists()
        )
        created = 0
        async with self._session_factory() as session:
            async with session.begin():
                links = (
                    await session.scalars(
                        select(orm.SourceEventLink)
                        .join(
                            orm.SecurityEvent,
                            orm.SecurityEvent.event_id == orm.SourceEventLink.event_id,
                        )
                        .where(
                            orm.SourceEventLink.role == PROVISIONAL_LINK_ROLE,
                            orm.SecurityEvent.status == EventStatus.NEW.value,
                            orm.SecurityEvent.created_at <= cutoff,
                            ~intent_exists,
                        )
                        .order_by(orm.SecurityEvent.created_at.asc())
                        .limit(limit)
                    )
                ).all()
                for link in links:
                    event = await session.get(orm.SecurityEvent, link.event_id)
                    if event is None:
                        continue
                    source_product = None
                    if event.creation_source_ref:
                        raw = event.creation_source_ref.get("source_product")
                        if isinstance(raw, str):
                            source_product = raw
                    # Window path: link may still be provisional in DB; policy uses
                    # PRIMARY role so aged NEW events become eligible (#612).
                    intent_id = await self.maybe_create_pending_in_session(
                        session,
                        event,
                        link_role=PRIMARY_LINK_ROLE,
                        source_product=source_product,
                        created_or_promoted=True,
                    )
                    if intent_id is not None:
                        created += 1
        if created:
            self.schedule_dispatch()
        return created


__all__ = [
    "HttpInvestigateIntentResult",
    "InvestigationIntentService",
    "compute_http_investigate_payload_hash",
    "default_http_investigate_idempotency_key",
    "deterministic_investigation_task_id",
    "new_intent_id",
]
