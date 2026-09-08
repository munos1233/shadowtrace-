"""PostgreSQL durable auto-investigate intent dispatcher (ISSUE-108 / #612)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import NamedTuple, cast

from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, TaskMode, get_settings
from app.core.db_retry import run_with_db_retry
from app.core.errors import (
    DependencyUnavailableError,
    IdempotencyKeyReuseError,
    InvalidStateTransitionError,
    InvestigationInProgressError,
    ValidationError,
)
from app.core.metrics import record_dispatch_schedule, record_investigation_intent_enqueue
from app.db import models as orm
from app.models.enums import EventStatus, InvestigationIntentStatus, WritebackStatus
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
from app.services.cmu_scheduler import priority_order_columns
from app.services.degraded_flag_service import DegradedFlagService

logger = logging.getLogger(__name__)

_DISPATCH_WORKER_ID = "intent-dispatcher-1"

# ISSUE-324: one bounded in-process fallback when Celery enqueue fails after
# SoftTimeLimit RECOVERED. Conditions: pure investigation phase, no response
# execution, no UNKNOWN outbox. Other triggers rely on beat reconcile.
# Fallback publish failure must return RETRY without burning attempt/DEAD —
# SoftTimeLimit already counted this recovery.
_DISPATCH_IN_PROCESS_FALLBACK_TRIGGERS = frozenset({"soft_time_limit_recovered"})


def _safe_dispatch_error(exc: BaseException) -> str:
    """Broker/AMQP exceptions often embed credentials; persist the type only."""
    return type(exc).__name__


_PURE_INVESTIGATION_DISPATCH_STATUSES = frozenset(
    {
        EventStatus.TRIAGING.value,
        EventStatus.COLLECTING_EVIDENCE.value,
        EventStatus.ANALYZING.value,
        EventStatus.SCORING.value,
    }
)

# Event left NEW while intent is STARTED beyond this window → worker crash / retry.
_STARTED_STALE_MIN_S = 660

_EVENT_INVESTIGATION_RESUMABLE = frozenset(
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
    }
)

_EVENT_INVESTIGATION_COMPLETED = frozenset(
    {
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
    resume_from_checkpoint: bool


class HttpInvestigationIntentResult(NamedTuple):
    intent_id: str
    event_id: str
    task_id: str
    revision: int
    status: InvestigationIntentStatus
    created: bool


def http_investigation_payload_sha256(
    *,
    event_id: str,
    force_replan: bool,
    include_response_execution: bool,
    generate_report: bool,
    orchestration_mode: str,
) -> str:
    """Hash the complete semantic HTTP investigation request deterministically."""
    payload = {
        "event_id": event_id,
        "force_replan": bool(force_replan),
        "generate_report": bool(generate_report),
        "include_response_execution": bool(include_response_execution),
        "orchestration_mode": orchestration_mode,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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

    async def create_or_replay_http_intent(
        self,
        event_id: str,
        *,
        requested_by: str,
        request_idempotency_key: str,
        request_payload_sha256: str,
        orchestration_mode: str,
        include_response_execution: bool,
        generate_report: bool,
    ) -> HttpInvestigationIntentResult:
        """Commit or replay one durable HTTP intake intent before returning 202."""
        key = request_idempotency_key.strip()
        subject = requested_by.strip()
        if not key or len(key) > 200:
            raise ValidationError(
                "Idempotency-Key must contain 1 to 200 characters",
                details={"field": "Idempotency-Key"},
            )
        if not subject:
            raise ValidationError("authenticated principal subject is required")

        async def _commit() -> HttpInvestigationIntentResult:
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        event = await session.scalar(
                            select(orm.SecurityEvent)
                            .where(orm.SecurityEvent.event_id == event_id)
                            .with_for_update()
                        )
                        if event is None:
                            raise ValidationError(
                                f"event {event_id} not found",
                                error_code="event_not_found",
                                details={"event_id": event_id},
                            )

                        existing = await session.scalar(
                            select(orm.InvestigationIntent)
                            .where(
                                orm.InvestigationIntent.requested_by == subject,
                                orm.InvestigationIntent.request_idempotency_key == key,
                            )
                            .with_for_update()
                        )
                        if existing is not None:
                            return self._replay_http_intent(
                                existing,
                                event_id=event_id,
                                request_payload_sha256=request_payload_sha256,
                            )
                        if event.status != EventStatus.NEW.value:
                            raise InvalidStateTransitionError(
                                "event must be in NEW status to start investigation, "
                                f"current: {event.status}",
                                current=EventStatus(event.status),
                                target=EventStatus.TRIAGING,
                                details={"event_id": event_id},
                            )

                        active = await session.scalar(
                            select(orm.InvestigationIntent)
                            .where(
                                orm.InvestigationIntent.event_id == event_id,
                                orm.InvestigationIntent.intent_kind == INTENT_KIND_HTTP_INVESTIGATE,
                                orm.InvestigationIntent.intent_version
                                == INTENT_VERSION_ISSUE276_V1,
                            )
                            .with_for_update()
                        )
                        if active is not None:
                            status = InvestigationIntentStatus(active.status)
                            if status in {
                                InvestigationIntentStatus.DEAD,
                                InvestigationIntentStatus.SKIPPED,
                            }:
                                return self._rearm_http_intent(
                                    active,
                                    request_idempotency_key=key,
                                    request_payload_sha256=request_payload_sha256,
                                    requested_by=subject,
                                    orchestration_mode=orchestration_mode,
                                    include_response_execution=include_response_execution,
                                    generate_report=generate_report,
                                )
                            raise InvestigationInProgressError(
                                "investigation already accepted for this event",
                                details={
                                    "event_id": event_id,
                                    "intent_id": active.intent_id,
                                },
                            )

                        # ISSUE-276: HTTP intake is the operator-authoritative path —
                        # supersede any non-terminal auto_investigate siblings first.
                        await self.skip_active_intents_for_event_in_session(
                            session,
                            event_id,
                            reason="superseded_by_http_investigate",
                        )

                        intent_id = new_intent_id()
                        row = orm.InvestigationIntent(
                            intent_id=intent_id,
                            event_id=event_id,
                            intent_kind=INTENT_KIND_HTTP_INVESTIGATE,
                            intent_version=INTENT_VERSION_ISSUE276_V1,
                            status=InvestigationIntentStatus.PENDING.value,
                            revision=1,
                            broker_task_id=deterministic_investigation_task_id(intent_id, 1),
                            request_idempotency_key=key,
                            request_payload_sha256=request_payload_sha256,
                            requested_by=subject,
                            orchestration_mode=orchestration_mode,
                            attempt=0,
                            include_response_execution=include_response_execution,
                            generate_report=generate_report,
                        )
                        session.add(row)
                        await session.flush()
                        return self._http_intent_result(row, created=True)
            except IntegrityError as exc:
                # A concurrent request may win either the request-key or per-event
                # unique constraint after our initial locked lookups.
                async with self._session_factory() as session:
                    async with session.begin():
                        event = await session.scalar(
                            select(orm.SecurityEvent)
                            .where(orm.SecurityEvent.event_id == event_id)
                            .with_for_update()
                        )
                        if event is None:
                            raise ValidationError(
                                f"event {event_id} not found",
                                error_code="event_not_found",
                                details={"event_id": event_id},
                            ) from exc

                        existing = await session.scalar(
                            select(orm.InvestigationIntent)
                            .where(
                                orm.InvestigationIntent.requested_by == subject,
                                orm.InvestigationIntent.request_idempotency_key == key,
                            )
                            .with_for_update()
                        )
                        if existing is not None:
                            return self._replay_http_intent(
                                existing,
                                event_id=event_id,
                                request_payload_sha256=request_payload_sha256,
                            )
                        active = await session.scalar(
                            select(orm.InvestigationIntent)
                            .where(
                                orm.InvestigationIntent.event_id == event_id,
                                orm.InvestigationIntent.intent_kind == INTENT_KIND_HTTP_INVESTIGATE,
                                orm.InvestigationIntent.intent_version
                                == INTENT_VERSION_ISSUE276_V1,
                            )
                            .with_for_update()
                        )
                        if active is not None:
                            status = InvestigationIntentStatus(active.status)
                            if status in {
                                InvestigationIntentStatus.DEAD,
                                InvestigationIntentStatus.SKIPPED,
                            }:
                                return self._rearm_http_intent(
                                    active,
                                    request_idempotency_key=key,
                                    request_payload_sha256=request_payload_sha256,
                                    requested_by=subject,
                                    orchestration_mode=orchestration_mode,
                                    include_response_execution=include_response_execution,
                                    generate_report=generate_report,
                                )
                            raise InvestigationInProgressError(
                                "investigation already accepted for this event",
                                details={"event_id": event_id, "intent_id": active.intent_id},
                            ) from exc
                raise

        return await run_with_db_retry(
            _commit,
            operation="create_or_replay_http_intent",
        )

    async def mark_inline_started(self, intent_id: str) -> str:
        """Fence a dev/test inline worker using the durable status/revision ledger."""
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.scalar(
                    select(orm.InvestigationIntent)
                    .where(orm.InvestigationIntent.intent_id == intent_id)
                    .with_for_update()
                )
                if row is None:
                    raise ValidationError(
                        "investigation intent not found",
                        details={"intent_id": intent_id},
                    )
                current = InvestigationIntentStatus(row.status)
                if current not in {
                    InvestigationIntentStatus.PENDING,
                    InvestigationIntentStatus.RETRY,
                }:
                    raise InvestigationInProgressError(
                        "investigation intent is not available for inline claim",
                        details={"intent_id": intent_id, "status": current.value},
                    )
                validate_intent_transition(current, InvestigationIntentStatus.CLAIMED)
                row.status = InvestigationIntentStatus.CLAIMED.value
                row.claim_owner = f"http-inline-{secrets.token_hex(8)}"
                row.claim_expires_at = now + timedelta(
                    seconds=int(self._settings.auto_investigate_claim_lease_s)
                )
                task_id = deterministic_investigation_task_id(
                    row.intent_id,
                    int(row.revision or 1),
                )
                validate_intent_transition(
                    InvestigationIntentStatus.CLAIMED,
                    InvestigationIntentStatus.ENQUEUED,
                )
                row.status = InvestigationIntentStatus.ENQUEUED.value
                row.broker_task_id = task_id
                validate_intent_transition(
                    InvestigationIntentStatus.ENQUEUED,
                    InvestigationIntentStatus.STARTED,
                )
                row.status = InvestigationIntentStatus.STARTED.value
                row.claim_owner = None
                row.claim_expires_at = None
                return task_id

    @staticmethod
    def _http_intent_result(
        row: orm.InvestigationIntent,
        *,
        created: bool,
    ) -> HttpInvestigationIntentResult:
        revision = int(row.revision or 1)
        return HttpInvestigationIntentResult(
            intent_id=row.intent_id,
            event_id=row.event_id,
            task_id=deterministic_investigation_task_id(row.intent_id, revision),
            revision=revision,
            status=InvestigationIntentStatus(row.status),
            created=created,
        )

    def _replay_http_intent(
        self,
        row: orm.InvestigationIntent,
        *,
        event_id: str,
        request_payload_sha256: str,
    ) -> HttpInvestigationIntentResult:
        if row.event_id != event_id or row.request_payload_sha256 != request_payload_sha256:
            raise IdempotencyKeyReuseError(
                "Idempotency-Key was already used with a different investigation request",
                details={
                    "event_id": event_id,
                    "existing_event_id": row.event_id,
                    "intent_id": row.intent_id,
                },
            )
        status = InvestigationIntentStatus(row.status)
        if row.intent_kind == INTENT_KIND_HTTP_INVESTIGATE and status in {
            InvestigationIntentStatus.DEAD,
            InvestigationIntentStatus.SKIPPED,
        }:
            return self._rearm_http_intent(row)
        return self._http_intent_result(row, created=False)

    def _rearm_http_intent(
        self,
        row: orm.InvestigationIntent,
        *,
        request_idempotency_key: str | None = None,
        request_payload_sha256: str | None = None,
        requested_by: str | None = None,
        orchestration_mode: str | None = None,
        include_response_execution: bool | None = None,
        generate_report: bool | None = None,
    ) -> HttpInvestigationIntentResult:
        """Re-arm a DEAD/SKIPPED HTTP intent so durable intake can retry."""
        current = InvestigationIntentStatus(row.status)
        validate_intent_transition(current, InvestigationIntentStatus.RETRY)
        row.status = InvestigationIntentStatus.RETRY.value
        row.revision = int(row.revision or 1) + 1
        row.attempt = 0
        row.broker_task_id = deterministic_investigation_task_id(
            row.intent_id,
            int(row.revision),
        )
        row.claim_owner = None
        row.claim_expires_at = None
        row.skip_reason = None
        row.last_error = None
        if request_idempotency_key is not None:
            row.request_idempotency_key = request_idempotency_key
        if request_payload_sha256 is not None:
            row.request_payload_sha256 = request_payload_sha256
        if requested_by is not None:
            row.requested_by = requested_by
        if orchestration_mode is not None:
            row.orchestration_mode = orchestration_mode
        if include_response_execution is not None:
            row.include_response_execution = include_response_execution
        if generate_report is not None:
            row.generate_report = generate_report
        return self._http_intent_result(row, created=False)

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
        orchestration_mode = (
            str(getattr(self._settings, "orchestration_mode", None) or "graph").strip().lower()
            or "graph"
        )
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
            orchestration_mode=orchestration_mode,
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

    def schedule_dispatch(
        self,
        *,
        event_id: str | None = None,
        intent_id: str | None = None,
        trigger: str = "unspecified",
    ) -> None:
        """Best-effort trigger for any committed pending intent; never raises.

        SoftTimeLimit RECOVERED callers should prefer
        :meth:`schedule_dispatch_async` so the bounded in-process fallback is
        awaited before ``asyncio.run`` tears down the loop (ISSUE-324).
        """
        if self._settings.task_mode is not TaskMode.CELERY:
            return
        try:
            self._enqueue_celery_dispatch()
        except Exception as exc:
            self._record_dispatch_enqueue_failure(
                exc,
                event_id=event_id,
                intent_id=intent_id,
                trigger=trigger,
            )
            if event_id is not None:
                self._schedule_dispatch_degraded_flag(event_id)
            self._maybe_schedule_in_process_fallback(
                event_id=event_id,
                intent_id=intent_id,
                trigger=trigger,
            )
            return
        record_investigation_intent_enqueue(result="success")
        logger.debug(
            "investigation intent dispatch enqueued trigger=%s intent_id=%s event_id=%s",
            trigger,
            intent_id or "-",
            event_id or "-",
        )

    async def schedule_dispatch_async(
        self,
        *,
        event_id: str | None = None,
        intent_id: str | None = None,
        trigger: str = "unspecified",
    ) -> None:
        """Async dispatch trigger that awaits the SoftTimeLimit in-process fallback."""
        if self._settings.task_mode is not TaskMode.CELERY:
            return
        try:
            self._enqueue_celery_dispatch()
        except Exception as exc:
            self._record_dispatch_enqueue_failure(
                exc,
                event_id=event_id,
                intent_id=intent_id,
                trigger=trigger,
            )
            if event_id is not None:
                await self._set_dispatch_degraded_flag(event_id)
            await self._run_in_process_dispatch_fallback(
                event_id=event_id,
                intent_id=intent_id,
                trigger=trigger,
            )
            return
        record_investigation_intent_enqueue(result="success")
        logger.debug(
            "investigation intent dispatch enqueued trigger=%s intent_id=%s event_id=%s",
            trigger,
            intent_id or "-",
            event_id or "-",
        )

    def _enqueue_celery_dispatch(self) -> None:
        from app.tasks.investigation_intent_tasks import dispatch_pending_investigation_intents

        dispatch_pending_investigation_intents.delay()

    def _record_dispatch_enqueue_failure(
        self,
        exc: Exception,
        *,
        event_id: str | None,
        intent_id: str | None,
        trigger: str,
    ) -> None:
        record_investigation_intent_enqueue(result="failure")
        logger.error(
            "investigation intent dispatch enqueue failed trigger=%s intent_id=%s "
            "event_id=%s error=%s",
            trigger,
            intent_id or "-",
            event_id or "-",
            type(exc).__name__,
        )

    def _maybe_schedule_in_process_fallback(
        self,
        *,
        event_id: str | None,
        intent_id: str | None,
        trigger: str,
    ) -> None:
        if trigger not in _DISPATCH_IN_PROCESS_FALLBACK_TRIGGERS:
            return
        if event_id is None or intent_id is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # Sync Celery/context without a loop: run the bounded fallback to
            # completion so SoftTimeLimit recovery does not depend on beat.
            try:
                asyncio.run(
                    self._run_in_process_dispatch_fallback(
                        event_id=event_id,
                        intent_id=intent_id,
                        trigger=trigger,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "investigation intent in-process dispatch fallback failed "
                    "trigger=%s intent_id=%s event_id=%s error=%s",
                    trigger,
                    intent_id,
                    event_id,
                    _safe_dispatch_error(exc),
                )
            return
        loop.create_task(
            self._run_in_process_dispatch_fallback(
                event_id=event_id,
                intent_id=intent_id,
                trigger=trigger,
            )
        )

    async def _run_in_process_dispatch_fallback(
        self,
        *,
        event_id: str | None,
        intent_id: str | None,
        trigger: str,
    ) -> int:
        if trigger not in _DISPATCH_IN_PROCESS_FALLBACK_TRIGGERS:
            return 0
        if event_id is None or intent_id is None:
            return 0
        try:
            if not await self._is_safe_for_in_process_dispatch_fallback(
                event_id=event_id,
                intent_id=intent_id,
            ):
                return 0
            # Bind to the recovered intent — never steal an older global backlog row.
            published = await self.claim_and_publish_intent(
                intent_id,
                conserve_retry_budget=True,
            )
            if published:
                record_dispatch_schedule(
                    domain="investigation_intent",
                    outcome="dispatch_fallback_started",
                )
            logger.info(
                "investigation intent in-process dispatch fallback trigger=%s "
                "intent_id=%s event_id=%s published=%s",
                trigger,
                intent_id,
                event_id,
                int(published),
            )
            return int(published)
        except Exception as exc:
            logger.warning(
                "investigation intent in-process dispatch fallback failed "
                "trigger=%s intent_id=%s event_id=%s error=%s",
                trigger,
                intent_id,
                event_id,
                _safe_dispatch_error(exc),
            )
            return 0

    async def _is_safe_for_in_process_dispatch_fallback(
        self,
        *,
        event_id: str,
        intent_id: str,
    ) -> bool:
        async with self._session_factory() as session:
            intent_row = await session.get(orm.InvestigationIntent, intent_id)
            event_row = await session.get(orm.SecurityEvent, event_id)
            if intent_row is None or event_row is None:
                return False
            if intent_row.event_id != event_id:
                return False
            status = InvestigationIntentStatus(intent_row.status)
            if status not in {
                InvestigationIntentStatus.PENDING,
                InvestigationIntentStatus.RETRY,
            }:
                return False
            if bool(intent_row.include_response_execution):
                return False
            if event_row.status not in _PURE_INVESTIGATION_DISPATCH_STATUSES:
                return False
            unknown_rows = (
                await session.scalars(
                    select(orm.DispositionOutbox.latest_writeback_status).where(
                        orm.DispositionOutbox.event_id == event_id,
                        orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                    )
                )
            ).all()
            if any(status == WritebackStatus.UNKNOWN.value for status in unknown_rows):
                return False
        return True

    async def claim_and_publish_intent(
        self,
        intent_id: str,
        *,
        conserve_retry_budget: bool = False,
    ) -> bool:
        """Claim and publish one specific intent (ISSUE-324 SoftTimeLimit fallback)."""
        claimed = await self._claim_intent(intent_id)
        if claimed is None:
            return False
        return await self._publish_claimed_intent(
            claimed,
            conserve_retry_budget=conserve_retry_budget,
        )

    async def _claim_intent(self, intent_id: str) -> str | None:
        """Claim a single PENDING/RETRY (or expired CLAIMED) intent by id."""
        now = datetime.now(UTC)
        lease = timedelta(seconds=int(self._settings.auto_investigate_claim_lease_s))
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.InvestigationIntent,
                    intent_id,
                    with_for_update=True,
                )
                if row is None:
                    return None
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
                if current not in {
                    InvestigationIntentStatus.PENDING,
                    InvestigationIntentStatus.RETRY,
                }:
                    return None
                validate_intent_transition(current, InvestigationIntentStatus.CLAIMED)
                row.status = InvestigationIntentStatus.CLAIMED.value
                row.claim_owner = self._worker_id
                row.claim_expires_at = now + lease
                return row.intent_id

    async def _set_dispatch_degraded_flag(self, event_id: str) -> None:
        degraded = self._degraded
        if degraded is None:
            return
        try:
            await degraded.set_flag(
                event_id,
                "auto_investigate_dispatch_unavailable",
                True,
                writer="InvestigationIntentService",
            )
        except Exception:
            logger.warning(
                "failed to set auto_investigate_dispatch_unavailable event=%s",
                event_id,
                exc_info=True,
            )

    def _schedule_dispatch_degraded_flag(self, event_id: str) -> None:
        """Best-effort event degraded flag when the dispatch trigger cannot enqueue."""
        degraded = self._degraded
        if degraded is None:
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                asyncio.run(self._set_dispatch_degraded_flag(event_id))
            except Exception:
                logger.warning(
                    "failed to set auto_investigate_dispatch_unavailable event=%s",
                    event_id,
                    exc_info=True,
                )
            return
        loop.create_task(self._set_dispatch_degraded_flag(event_id))

    async def pending_dispatch_stats(self) -> dict[str, int | float | None]:
        """Return pending/retry backlog count and oldest age for health probes."""
        now = datetime.now(UTC)
        pending_statuses = (
            InvestigationIntentStatus.PENDING.value,
            InvestigationIntentStatus.RETRY.value,
        )
        async with self._session_factory() as session:
            pending_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(orm.InvestigationIntent)
                    .where(orm.InvestigationIntent.status.in_(pending_statuses))
                )
                or 0
            )
            oldest_created = await session.scalar(
                select(orm.InvestigationIntent.created_at)
                .where(orm.InvestigationIntent.status.in_(pending_statuses))
                .order_by(orm.InvestigationIntent.created_at.asc())
                .limit(1)
            )
        oldest_pending_age_s: float | None = None
        if oldest_created is not None:
            oldest_pending_age_s = max(0.0, (now - oldest_created).total_seconds())
        return {
            "pending_count": pending_count,
            "oldest_pending_age_s": oldest_pending_age_s,
        }

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
                row = await session.get(
                    orm.InvestigationIntent,
                    intent_id,
                    with_for_update=True,
                )
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

    async def mark_terminal(
        self,
        intent_id: str,
        *,
        broker_task_id: str | None = None,
    ) -> bool:
        return await self._transition(
            intent_id,
            InvestigationIntentStatus.TERMINAL,
            clear_claim=True,
            expected_broker_task_id=broker_task_id,
        )

    async def mark_skipped(
        self,
        intent_id: str,
        *,
        reason: str,
        broker_task_id: str | None = None,
    ) -> bool:
        return await self._transition(
            intent_id,
            InvestigationIntentStatus.SKIPPED,
            skip_reason=reason,
            clear_claim=True,
            expected_broker_task_id=broker_task_id,
        )

    async def mark_retry(
        self,
        intent_id: str,
        *,
        error: str,
        broker_task_id: str | None = None,
    ) -> bool:
        return await self._transition(
            intent_id,
            InvestigationIntentStatus.RETRY,
            last_error=error,
            increment_attempt=True,
            clear_claim=True,
            expected_broker_task_id=broker_task_id,
        )

    async def mark_dead(
        self,
        intent_id: str,
        *,
        error: str,
        broker_task_id: str | None = None,
    ) -> bool:
        return await self._transition(
            intent_id,
            InvestigationIntentStatus.DEAD,
            last_error=error,
            clear_claim=True,
            expected_broker_task_id=broker_task_id,
        )

    async def reconcile_stale(self, *, limit: int = 20) -> int:
        now = datetime.now(UTC)
        lease_seconds = int(self._settings.auto_investigate_claim_lease_s)
        max_attempts = int(self._settings.auto_investigate_max_attempts)
        started_stale_s = max(lease_seconds * 4, _STARTED_STALE_MIN_S)
        reconciled = 0
        abandoned_task_ids: list[str] = []
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
                        started_stale_s=started_stale_s,
                        lease_seconds=lease_seconds,
                    ):
                        continue
                    event = await session.get(orm.SecurityEvent, row.event_id)
                    previous_task_id = row.broker_task_id
                    if await self._reconcile_stale_row(
                        row,
                        status=status,
                        event=event,
                        max_attempts=max_attempts,
                    ):
                        reconciled += 1
                        if previous_task_id and row.broker_task_id != previous_task_id:
                            abandoned_task_ids.append(previous_task_id)
        if abandoned_task_ids:
            from app.tasks.investigation_tasks import delete_task_metadata

            for task_id in abandoned_task_ids:
                try:
                    await delete_task_metadata(task_id)
                except Exception:
                    logger.warning(
                        "failed to delete stale investigation task metadata task=%s",
                        task_id,
                        exc_info=True,
                    )
        if reconciled:
            self.schedule_dispatch(trigger="reconcile_stale")
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
        started_stale_s: int,
        lease_seconds: int,
    ) -> bool:
        if row.claim_expires_at is not None and row.claim_expires_at < now:
            return True
        if status is InvestigationIntentStatus.ENQUEUED:
            # Broker enqueue can stall well before the STARTED crash window.
            # Use the claim lease (floored at 30s), not the 11-minute STARTED floor.
            enqueued_stale_s = max(lease_seconds * 4, 30)
            return (now - row.updated_at) > timedelta(seconds=enqueued_stale_s)
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
            if event.status in _EVENT_INVESTIGATION_COMPLETED:
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
        row.claim_owner = None
        row.claim_expires_at = None
        row.revision = int(row.revision or 1) + 1
        row.broker_task_id = (
            deterministic_investigation_task_id(row.intent_id, int(row.revision))
            if row.status == InvestigationIntentStatus.RETRY.value
            else None
        )
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
                        .outerjoin(
                            orm.SecurityEvent,
                            orm.SecurityEvent.event_id == orm.InvestigationIntent.event_id,
                        )
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
                        .order_by(*priority_order_columns(now))
                        .limit(limit)
                        .with_for_update(of=orm.InvestigationIntent, skip_locked=True)
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
        *,
        conserve_retry_budget: bool = False,
    ) -> None:
        safe_error = _safe_dispatch_error(exc)
        if conserve_retry_budget:
            await self._set_status_in_session(
                row,
                InvestigationIntentStatus.RETRY,
                last_error=safe_error,
            )
            row.broker_task_id = None
        elif int(row.attempt or 0) + 1 >= int(self._settings.auto_investigate_max_attempts):
            await self._set_status_in_session(
                row,
                InvestigationIntentStatus.DEAD,
                last_error=safe_error,
            )
        else:
            await self._set_status_in_session(
                row,
                InvestigationIntentStatus.RETRY,
                last_error=safe_error,
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

        async def _commit() -> _EnqueuedPublishTarget | None:
            async with self._session_factory() as session:
                async with session.begin():
                    event_id = await session.scalar(
                        select(orm.InvestigationIntent.event_id).where(
                            orm.InvestigationIntent.intent_id == intent_id
                        )
                    )
                    if event_id is None:
                        return None

                    event = await session.get(
                        orm.SecurityEvent,
                        event_id,
                        with_for_update=True,
                    )
                    row = await session.get(
                        orm.InvestigationIntent,
                        intent_id,
                        with_for_update=True,
                    )
                    if row is None:
                        return None
                    claimed_status = InvestigationIntentStatus(row.status)
                    if claimed_status is not InvestigationIntentStatus.CLAIMED:
                        return None
                    if event is None:
                        await self._set_status_in_session(
                            row,
                            InvestigationIntentStatus.SKIPPED,
                            skip_reason="event_missing",
                        )
                        return None
                    resume_from_checkpoint = (
                        int(row.revision or 1) > 1
                        and event.status in _EVENT_INVESTIGATION_RESUMABLE
                    )
                    if event.status != EventStatus.NEW.value and not resume_from_checkpoint:
                        await self._set_status_in_session(
                            row,
                            InvestigationIntentStatus.SKIPPED,
                            skip_reason="event_not_new",
                        )
                        return None
                    sibling_blocking = await session.scalar(
                        select(orm.InvestigationIntent.intent_id).where(
                            orm.InvestigationIntent.event_id == row.event_id,
                            orm.InvestigationIntent.intent_id != row.intent_id,
                            orm.InvestigationIntent.status.in_(
                                (
                                    InvestigationIntentStatus.CLAIMED.value,
                                    InvestigationIntentStatus.ENQUEUED.value,
                                    InvestigationIntentStatus.STARTED.value,
                                )
                            ),
                        )
                    )
                    if sibling_blocking is not None:
                        await self._set_status_in_session(
                            row,
                            InvestigationIntentStatus.RETRY,
                            last_error="sibling_intent_active",
                            increment_attempt=True,
                        )
                        return None
                    include_response = bool(row.include_response_execution)
                    if row.intent_kind == INTENT_KIND_AUTO_INVESTIGATE:
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
                        str(row.orchestration_mode or "graph"),
                        resume_from_checkpoint,
                    )

        return await run_with_db_retry(
            _commit,
            operation="commit_enqueued_publish_target",
        )

    async def _revert_enqueued_after_publish_failure(
        self,
        intent_id: str,
        exc: Exception,
        *,
        conserve_retry_budget: bool = False,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return
                if InvestigationIntentStatus(row.status) is not InvestigationIntentStatus.ENQUEUED:
                    return
                await self._handle_publish_transient_failure(
                    row,
                    exc,
                    conserve_retry_budget=conserve_retry_budget,
                )

    async def _revert_enqueued_after_unexpected_failure(
        self,
        intent_id: str,
        exc: Exception,
        *,
        conserve_retry_budget: bool = False,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.InvestigationIntent, intent_id)
                if row is None:
                    return
                if InvestigationIntentStatus(row.status) is not InvestigationIntentStatus.ENQUEUED:
                    return
                if conserve_retry_budget:
                    await self._set_status_in_session(
                        row,
                        InvestigationIntentStatus.RETRY,
                        last_error=_safe_dispatch_error(exc),
                    )
                else:
                    await self._set_status_in_session(
                        row,
                        InvestigationIntentStatus.DEAD,
                        last_error=_safe_dispatch_error(exc),
                    )
                row.broker_task_id = None

    async def _publish_claimed_intent(
        self,
        intent_id: str,
        *,
        strict: bool = False,
        conserve_retry_budget: bool = False,
    ) -> bool:
        target = await self._commit_enqueued_publish_target(intent_id)
        if target is None:
            return False

        from kombu.exceptions import OperationalError

        from app.tasks.investigation_tasks import (
            delete_task_metadata,
            publish_analysis_only_investigation_for_intent,
            publish_investigation_for_intent,
            register_task_metadata,
        )

        try:
            await register_task_metadata(target.task_id, target.event_id)
            if target.orchestration_mode == "analysis_only":
                publish_analysis_only_investigation_for_intent(
                    event_id=target.event_id,
                    task_id=target.task_id,
                    intent_id=target.intent_id,
                    generate_report=target.generate_report,
                    resume_from_checkpoint=target.resume_from_checkpoint,
                )
            else:
                publish_investigation_for_intent(
                    event_id=target.event_id,
                    task_id=target.task_id,
                    intent_id=target.intent_id,
                    include_response_execution=target.include_response_execution,
                    generate_report=target.generate_report,
                    resume_from_checkpoint=target.resume_from_checkpoint,
                )
        except DependencyUnavailableError as exc:
            await delete_task_metadata(target.task_id)
            logger.warning(
                "task metadata store unavailable intent=%s event=%s error=%s",
                target.intent_id,
                target.event_id,
                _safe_dispatch_error(exc),
            )
            await self._revert_enqueued_after_publish_failure(
                target.intent_id,
                exc,
                conserve_retry_budget=conserve_retry_budget,
            )
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
                _safe_dispatch_error(exc),
            )
            await self._revert_enqueued_after_publish_failure(
                target.intent_id,
                exc,
                conserve_retry_budget=conserve_retry_budget,
            )
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
                "unexpected publish failure intent=%s event=%s error=%s",
                target.intent_id,
                target.event_id,
                _safe_dispatch_error(exc),
            )
            await self._revert_enqueued_after_unexpected_failure(
                target.intent_id,
                exc,
                conserve_retry_budget=conserve_retry_budget,
            )
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
        expected_broker_task_id: str | None = None,
    ) -> bool:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.InvestigationIntent,
                    intent_id,
                    with_for_update=True,
                )
                if row is None:
                    return False
                current = InvestigationIntentStatus(row.status)
                if expected_broker_task_id is not None and (
                    current is not InvestigationIntentStatus.STARTED
                    or row.broker_task_id != expected_broker_task_id
                ):
                    logger.info(
                        "stale intent completion ignored intent=%s current=%s "
                        "expected_task=%s actual_task=%s",
                        intent_id,
                        current.value,
                        expected_broker_task_id,
                        row.broker_task_id,
                    )
                    return False
                if current in TERMINAL_INTENT_STATUSES:
                    return False
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
                    row.broker_task_id = (
                        deterministic_investigation_task_id(
                            row.intent_id,
                            int(row.revision),
                        )
                        if target is InvestigationIntentStatus.RETRY
                        else None
                    )
                if clear_claim:
                    row.claim_owner = None
                    row.claim_expires_at = None
                return True

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
            row.broker_task_id = (
                deterministic_investigation_task_id(
                    row.intent_id,
                    int(row.revision),
                )
                if target is InvestigationIntentStatus.RETRY
                else None
            )
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
            self.schedule_dispatch(trigger="materialize_provisional")
        return created


__all__ = [
    "InvestigationIntentService",
    "deterministic_investigation_task_id",
    "new_intent_id",
]
