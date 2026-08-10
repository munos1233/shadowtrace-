"""Celery investigation task (ISSUE-056)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any, NoReturn

from celery import uuid as celery_uuid
from celery.exceptions import SoftTimeLimitExceeded
from kombu.exceptions import OperationalError

from app.core.celery_app import celery_app
from app.core.celery_delivery import (
    CELERY_REDELIVERY_MAX_RETRIES,
    DEFER_RETRY_HEADER,
    DEFER_RETRY_MAX_ATTEMPTS,
    LOOKUP_RETRY_HEADER,
    LOOKUP_RETRY_MAX_ATTEMPTS,
    REDELIVERY_RESUME_STATUSES,
    RedeliveryDecision,
    RedeliveryDeferRetry,
    RedeliveryHandoffAction,
    RedeliveryLookupRetry,
    celery_task_owner_id,
    defer_retry_count,
    defer_retry_countdown,
    evaluate_redelivered_investigation_decision,
    evaluate_redelivery_handoff,
    lookup_retry_count,
    lookup_retry_countdown,
    normalize_public_task_state,
    record_redelivery_recovery_needed,
)
from app.core.errors import (
    DependencyUnavailableError,
    InvestigationInProgressError,
    InvestigationLeaseLostError,
)
from app.core.redis_client import RedisClient
from app.models.enums import EventStatus
from app.models.investigation_intent import IntentDeliveryAdmission
from app.tasks.investigation_task_contract import (
    build_analysis_only_dispatch_kwargs,
    build_investigation_dispatch_kwargs,
)

logger = logging.getLogger(__name__)

TASK_NAME = "shadowtrace.run_investigation"
TASK_QUEUE = "investigation"
TASK_META_PREFIX = "shadowtrace:celery:task:"
TASK_META_TTL_SECONDS = 86_400


def _release_celery_task_loop_resources() -> None:
    """Strategy B (#623 / ISSUE-252): drop loop-bound clients after each asyncio.run task.

    Must discard redis.asyncio clients (and redis-backed singletons) — not only the
    investigation stack — otherwise the next task hits ``Event loop is closed`` on
    checkpoint persist/load and sticks in memory_fallback.
    """
    from app.api.v1.deps import (
        reset_investigation_stack_cache,
        reset_loop_bound_redis_resources,
    )
    from app.core.embedding.factory import reset_embedding_client
    from app.playbook.resources import reset_playbook_resources_cache
    from app.rag.resources import reset_loaded_retrieval_resources

    reset_investigation_stack_cache()
    reset_loop_bound_redis_resources()
    reset_loaded_retrieval_resources()
    reset_playbook_resources_cache()
    reset_embedding_client()


def _task_meta_key(task_id: str) -> str:
    return f"{TASK_META_PREFIX}{task_id}"


async def register_task_metadata(
    task_id: str,
    event_id: str,
    *,
    redis_url: str | None = None,
) -> None:
    """Persist ``task_id → event_id`` so status queries can resolve unknown tasks."""
    from app.core.config import get_settings

    url = redis_url or get_settings().redis_url
    client = RedisClient(url=url)
    try:
        if not await client.ping():
            raise DependencyUnavailableError(
                message="task metadata store unavailable",
                error_code="dependency_unavailable",
                details={"dependency": "redis"},
            )
        redis = client.get_client()
        await redis.set(_task_meta_key(task_id), event_id, ex=TASK_META_TTL_SECONDS)
    finally:
        await client.aclose()


async def delete_task_metadata(task_id: str, *, redis_url: str | None = None) -> None:
    """Best-effort cleanup when Celery dispatch fails after metadata registration."""
    from app.core.config import get_settings

    url = redis_url or get_settings().redis_url
    client = RedisClient(url=url)
    try:
        if await client.ping():
            redis = client.get_client()
            await redis.delete(_task_meta_key(task_id))
    finally:
        await client.aclose()


async def lookup_task_event_id(task_id: str) -> str | None:
    from app.core.config import get_settings

    client = RedisClient(url=get_settings().redis_url)
    try:
        if not await client.ping():
            return None
        redis = client.get_client()
        value = await redis.get(_task_meta_key(task_id))
        if value is None:
            return None
        return value.decode() if isinstance(value, bytes) else str(value)
    finally:
        await client.aclose()


async def execute_investigation(
    event_id: str,
    *,
    include_response_execution: bool = False,
    generate_report: bool = True,
    owner_id: str | None = None,
    lease_acquired: bool = False,
) -> dict[str, str]:
    """Run SuperAgent investigation (called from Celery worker via ``asyncio.run``).

    When *lease_acquired* is True the HTTP layer already holds the lease for
    *event_id* with *owner_id*; SuperAgent will skip its own acquire and only
    start renewal (ISSUE-186).
    """
    from app.api.v1.deps import _get_session_factory, get_super_agent
    from app.services.evidence_projection import EvidenceProjection, bind_evidence_projection
    from app.services.investigation_guidance import record_investigation_workflow_path

    session_factory = _get_session_factory()
    if include_response_execution:
        await record_investigation_workflow_path(
            session_factory,
            event_id,
            workflow_path="full_loop",
            include_response_execution=True,
        )

    try:
        agent = await get_super_agent()
        projection = EvidenceProjection(session_factory)
        with bind_evidence_projection(projection):
            await agent.investigate(
                event_id,
                owner_id=owner_id,
                lease_acquired=lease_acquired,
                include_response_execution=include_response_execution,
                generate_report=generate_report,
            )
        return {"status": "completed", "event_id": event_id}
    except InvestigationInProgressError:
        logger.info(
            "run_investigation skipped for event=%s — lease already held",
            event_id,
        )
        return {
            "status": "skipped",
            "event_id": event_id,
            "reason": "investigation_in_progress",
        }
    except InvestigationLeaseLostError:
        logger.info(
            "run_investigation stopped for event=%s — lease lost mid-run",
            event_id,
        )
        return {
            "status": "skipped",
            "event_id": event_id,
            "reason": "investigation_lease_lost",
        }


async def dispatch_investigation(
    event_id: str,
    *,
    include_response_execution: bool = False,
    generate_report: bool = True,
    owner_id: str | None = None,
    lease_acquired: bool = False,
) -> str:
    """Enqueue ``run_investigation`` and return the Celery task id.

    When *owner_id* and *lease_acquired* are set the HTTP layer has already
    acquired the lease; the worker will skip its own acquire (ISSUE-186).
    """
    task_id = str(celery_uuid())
    await register_task_metadata(task_id, event_id)
    try:
        kwargs = build_investigation_dispatch_kwargs(
            include_response_execution=include_response_execution,
            generate_report=generate_report,
            owner_id=owner_id,
            lease_acquired=lease_acquired,
        )
        run_investigation.apply_async(
            args=[event_id],
            kwargs=kwargs,
            task_id=task_id,
            queue=TASK_QUEUE,
        )
    except (OperationalError, OSError, ConnectionError) as exc:
        await delete_task_metadata(task_id)
        raise DependencyUnavailableError(
            message="celery broker unavailable",
            error_code="task_unavailable",
            details={"dependency": "celery_broker", "event_id": event_id},
        ) from exc
    return task_id


def publish_investigation_for_intent(
    *,
    event_id: str,
    task_id: str,
    intent_id: str,
    include_response_execution: bool = False,
    generate_report: bool = True,
    resume_from_checkpoint: bool = False,
) -> None:
    """Publish a deterministic Celery task for a claimed investigation intent.

    ``include_response_execution`` is resolved by AutoResponsePolicyService at
    ENQUEUED commit time (#613); auto-investigate intent creation never sets it.

    ``generate_report`` is stored on the intent row (ISSUE-204); auto paths
    default False at intent creation.

    Raises broker connectivity errors to the caller; ingest paths must catch.
    """
    kwargs = build_investigation_dispatch_kwargs(
        include_response_execution=include_response_execution,
        generate_report=generate_report,
        intent_id=intent_id,
        resume_from_checkpoint=resume_from_checkpoint,
    )
    run_investigation.apply_async(
        args=[event_id],
        kwargs=kwargs,
        task_id=task_id,
        queue=TASK_QUEUE,
    )


def publish_analysis_only_investigation_for_intent(
    *,
    event_id: str,
    task_id: str,
    intent_id: str,
    generate_report: bool = True,
    resume_from_checkpoint: bool = False,
) -> None:
    """Publish an analysis-only worker delivery fenced by a durable intent."""
    kwargs = build_analysis_only_dispatch_kwargs(
        generate_report=generate_report,
        intent_id=intent_id,
        resume_from_checkpoint=resume_from_checkpoint,
    )
    run_analysis_only_investigation.apply_async(
        args=[event_id],
        kwargs=kwargs,
        task_id=task_id,
        queue=ANALYSIS_ONLY_TASK_QUEUE,
    )


async def _admit_intent_delivery(intent_id: str, broker_task_id: str) -> IntentDeliveryAdmission:
    from app.db.session import get_session_factory
    from app.services.investigation_intent_service import InvestigationIntentService

    service = InvestigationIntentService(get_session_factory())
    return await service.mark_started(intent_id, broker_task_id=broker_task_id)


def _skipped_delivery_result(
    event_id: str,
    *,
    reason: str,
) -> dict[str, str]:
    return {
        "status": "skipped",
        "event_id": event_id,
        "reason": reason,
    }


def _redelivery_retry_headers(
    request_headers: dict[str, object] | None,
    *,
    lookup_attempt: int | None = None,
    defer_attempt: int | None = None,
) -> dict[str, object]:
    headers = dict(request_headers or {})
    if lookup_attempt is not None:
        headers[LOOKUP_RETRY_HEADER] = lookup_attempt
    if defer_attempt is not None:
        headers[DEFER_RETRY_HEADER] = defer_attempt
    return headers


def _raise_lookup_retry(
    event_id: str,
    *,
    attempt: int,
    cause: BaseException | None = None,
) -> NoReturn:
    raise RedeliveryLookupRetry(event_id, attempt=attempt, cause=cause)


def _raise_defer_retry(event_id: str, *, reason: str, attempt: int) -> NoReturn:
    raise RedeliveryDeferRetry(event_id, reason=reason, attempt=attempt)


def _celery_redelivery_retry(
    task: Any,
    exc: RedeliveryLookupRetry | RedeliveryDeferRetry,
    *,
    request_headers: dict[str, object] | None,
) -> NoReturn:
    """Retry broker redelivery without ack; propagate typed retry counters via headers."""
    if isinstance(exc, RedeliveryLookupRetry):
        countdown = lookup_retry_countdown(exc.attempt)
        headers = _redelivery_retry_headers(
            request_headers,
            lookup_attempt=exc.attempt,
        )
    else:
        countdown = defer_retry_countdown(exc.attempt)
        headers = _redelivery_retry_headers(
            request_headers,
            defer_attempt=exc.attempt,
        )
    logger.info(
        "run_investigation redelivery retry event=%s countdown=%.2fs attempt=%s",
        exc.event_id,
        countdown,
        exc.attempt,
    )
    raise task.retry(
        exc=exc,
        countdown=countdown,
        headers=headers,
        max_retries=CELERY_REDELIVERY_MAX_RETRIES,
    ) from exc


async def execute_redelivery_resume(
    event_id: str,
    *,
    owner_id: str,
    event_status: EventStatus | None,
    lease_acquired: bool = False,
    analysis_only: bool = False,
    generate_report: bool = True,
) -> dict[str, str]:
    """Resume investigation from checkpoint when broker redelivery proves handoff."""
    from app.api.v1.deps import (
        _get_degraded_flags,
        _get_session_factory,
        get_super_agent,
        get_workflow_runtime,
    )
    from app.orchestration.graph_resume_observability import execute_graph_resume_with_retry

    if analysis_only or event_status not in REDELIVERY_RESUME_STATUSES:
        if analysis_only:
            return await execute_analysis_only_investigation(
                event_id,
                generate_report=generate_report,
                owner_id=owner_id,
                lease_acquired=lease_acquired,
            )
        return await execute_investigation(
            event_id,
            owner_id=owner_id,
            lease_acquired=lease_acquired,
        )

    await execute_graph_resume_with_retry(
        event_id,
        session_factory=_get_session_factory(),
        get_super_agent=get_super_agent,
        get_workflow_runtime=get_workflow_runtime,
        degraded_flags=_get_degraded_flags(),
    )
    return {"status": "completed", "event_id": event_id}


async def _handle_redelivered_investigation(
    event_id: str,
    *,
    task_id: str,
    owner_id: str,
    request_headers: dict[str, object] | None,
    lease_acquired: bool,
    analysis_only: bool = False,
    generate_report: bool = True,
) -> dict[str, str] | None:
    """Return a terminal skip payload or resume result for broker redelivery."""
    decision, event_status = await evaluate_redelivered_investigation_decision(event_id)

    if decision is RedeliveryDecision.RETRY_LOOKUP:
        attempt = lookup_retry_count(request_headers) + 1
        if attempt >= LOOKUP_RETRY_MAX_ATTEMPTS:
            await record_redelivery_recovery_needed(
                event_id,
                task_id=task_id,
                reason="lookup_retry_exhausted",
            )
            # Durable recovery recorded — stop retrying (ack this delivery).
            return _skipped_delivery_result(event_id, reason="lookup_retry_exhausted")
        _raise_lookup_retry(event_id, attempt=attempt)

    if decision is RedeliveryDecision.ACK_TERMINAL:
        logger.info(
            "run_investigation redelivery ack_terminal event=%s status=%s",
            event_id,
            event_status.value if event_status is not None else None,
        )
        return _skipped_delivery_result(event_id, reason="terminal_event")

    handoff = await evaluate_redelivery_handoff(
        event_id,
        task_id=task_id,
        owner_id=owner_id,
        event_status=event_status,
    )
    if handoff.action is RedeliveryHandoffAction.RETRY_DEFER:
        attempt = defer_retry_count(request_headers) + 1
        if attempt >= DEFER_RETRY_MAX_ATTEMPTS:
            await record_redelivery_recovery_needed(
                event_id,
                task_id=task_id,
                reason=handoff.reason or "defer_retry_exhausted",
            )
            return _skipped_delivery_result(
                event_id,
                reason=handoff.reason or "defer_retry_exhausted",
            )
        _raise_defer_retry(
            event_id,
            reason=handoff.reason or "defer",
            attempt=attempt,
        )

    logger.info(
        "run_investigation redelivery resume event=%s reason=%s status=%s",
        event_id,
        handoff.reason,
        event_status.value if event_status is not None else None,
    )
    return await execute_redelivery_resume(
        event_id,
        owner_id=owner_id,
        event_status=event_status,
        lease_acquired=lease_acquired or handoff.reason == "lease_acquired",
        analysis_only=analysis_only,
        generate_report=generate_report,
    )


async def _finalize_intent_from_result(
    intent_id: str,
    result: dict[str, str],
    *,
    broker_task_id: str,
) -> None:
    from app.db.session import get_session_factory
    from app.services.investigation_intent_service import InvestigationIntentService

    service = InvestigationIntentService(get_session_factory())
    status = str(result.get("status") or "")
    if status == "skipped":
        reason = str(result.get("reason") or "investigation_skipped")
        if reason in {"investigation_in_progress", "investigation_lease_lost"}:
            # Lease contention / loss before this delivery owns execution — keep
            # the durable intent recoverable instead of a terminal SKIPPED hole.
            await service.mark_retry(
                intent_id,
                error=reason,
                broker_task_id=broker_task_id,
            )
            return
        await service.mark_skipped(
            intent_id,
            reason=reason,
            broker_task_id=broker_task_id,
        )
    else:
        await service.mark_terminal(
            intent_id,
            broker_task_id=broker_task_id,
        )


async def resolve_task_state(task_id: str) -> tuple[str, str | None]:
    """Return Celery state and optional event_id for a dispatched task."""
    from celery.result import AsyncResult

    result = AsyncResult(task_id, app=celery_app)
    event_id = await lookup_task_event_id(task_id)
    if event_id is None and isinstance(result.info, dict):
        event_id = result.info.get("event_id")
    if event_id is None and result.args:
        event_id = str(result.args[0])
    if event_id is None:
        from app.db.session import get_session_factory
        from app.services.investigation_intent_service import InvestigationIntentService

        intent = await InvestigationIntentService(get_session_factory()).lookup_by_broker_task_id(
            task_id
        )
        if intent is not None:
            event_id = intent.event_id
    return normalize_public_task_state(result.state), event_id


async def _run_investigation_body(
    event_id: str,
    *,
    include_response_execution: bool,
    generate_report: bool = True,
    owner_id: str,
    task_id: str,
    redelivered: bool,
    lease_acquired: bool = False,
    request_headers: dict[str, object] | None = None,
) -> dict[str, str]:
    if redelivered:
        redelivery_result = await _handle_redelivered_investigation(
            event_id,
            task_id=task_id,
            owner_id=owner_id,
            request_headers=request_headers,
            lease_acquired=lease_acquired,
        )
        if redelivery_result is not None:
            return redelivery_result
    return await execute_investigation(
        event_id,
        include_response_execution=include_response_execution,
        generate_report=generate_report,
        owner_id=owner_id,
        lease_acquired=lease_acquired,
    )


@celery_app.task(  # type: ignore[untyped-decorator]
    name=TASK_NAME,
    bind=True,
    acks_late=True,
    max_retries=CELERY_REDELIVERY_MAX_RETRIES,
    retry_backoff=True,
    soft_time_limit=600,
    queue=TASK_QUEUE,
)
def run_investigation(
    self: Any,
    event_id: str,
    include_response_execution: bool = False,
    generate_report: bool = True,
    intent_id: str | None = None,
    resume_from_checkpoint: bool = False,
    owner_id: str | None = None,
    lease_acquired: bool = False,
) -> dict[str, str]:
    """Execute SuperAgent investigation for *event_id* (idempotent when lease held).

    When *owner_id* is set by the caller (HTTP-layer pre-lease, ISSUE-186) use it
    directly; otherwise derive a stable owner from the Celery task id so redelivery
    can reclaim the same lease.
    """
    resolved_owner = owner_id or celery_task_owner_id(str(self.request.id))
    task_id = str(self.request.id)
    request_headers = getattr(self.request, "headers", None)
    redelivered = bool(getattr(self.request, "delivery_info", {}).get("redelivered"))
    if redelivered:
        logger.info(
            "run_investigation redelivery for event=%s task=%s owner=%s",
            event_id,
            self.request.id,
            resolved_owner,
        )
    if intent_id:
        from app.models.investigation_intent import IntentDeliveryAdmission

        admission = asyncio.run(_admit_intent_delivery(intent_id, str(self.request.id)))
        if admission is not IntentDeliveryAdmission.ACCEPTED:
            reason = {
                IntentDeliveryAdmission.STALE_SUPERSEDED: "stale_broker_task",
                IntentDeliveryAdmission.ALREADY_TERMINAL: "intent_already_terminal",
                IntentDeliveryAdmission.MISSING: "intent_missing",
            }[admission]
            logger.info(
                "run_investigation delivery rejected event=%s intent=%s admission=%s",
                event_id,
                intent_id,
                admission.value,
            )
            return _skipped_delivery_result(event_id, reason=reason)
    try:
        try:
            result = asyncio.run(
                _run_investigation_body(
                    event_id,
                    include_response_execution=bool(include_response_execution),
                    generate_report=bool(generate_report),
                    owner_id=resolved_owner,
                    task_id=task_id,
                    redelivered=redelivered or resume_from_checkpoint,
                    lease_acquired=lease_acquired,
                    request_headers=request_headers,
                )
            )
            if intent_id:
                asyncio.run(
                    _finalize_intent_from_result(
                        intent_id,
                        result,
                        broker_task_id=task_id,
                    )
                )
            return result
        finally:
            _release_celery_task_loop_resources()
    except SoftTimeLimitExceeded:
        logger.warning("run_investigation soft time limit exceeded for event=%s", event_id)
        try:
            from app.api.v1.deps import get_event_lease

            lease = get_event_lease()
            asyncio.run(lease.release(event_id, resolved_owner))
        except Exception:
            logger.warning(
                "run_investigation: best-effort lease release failed after soft limit "
                "event=%s owner=%s",
                event_id,
                resolved_owner,
                exc_info=True,
            )
        try:
            from app.orchestration.checkpointer import invalidate_event_checkpoint

            asyncio.run(invalidate_event_checkpoint(event_id))
        except Exception:
            logger.warning(
                "run_investigation: checkpoint fence advance failed after soft limit event=%s",
                event_id,
                exc_info=True,
            )
        if intent_id:
            from app.db.session import get_session_factory
            from app.services.investigation_intent_service import InvestigationIntentService

            asyncio.run(
                InvestigationIntentService(get_session_factory()).mark_dead(
                    intent_id,
                    error="soft_time_limit_exceeded",
                    broker_task_id=task_id,
                )
            )
        raise
    except (RedeliveryLookupRetry, RedeliveryDeferRetry) as exc:
        _celery_redelivery_retry(self, exc, request_headers=request_headers)
    except (DependencyUnavailableError, OperationalError, OSError, ConnectionError) as exc:
        logger.warning(
            "run_investigation transient failure for event=%s; retry=%s",
            event_id,
            self.request.retries,
            exc_info=True,
        )
        if intent_id and self.request.retries >= self.max_retries:
            from app.db.session import get_session_factory
            from app.services.investigation_intent_service import InvestigationIntentService

            asyncio.run(
                InvestigationIntentService(get_session_factory()).mark_retry(
                    intent_id,
                    error=str(exc),
                    broker_task_id=task_id,
                )
            )
            raise
        # Keep intent in STARTED during Celery in-flight retries; dispatcher owns RETRY.
        raise self.retry(exc=exc) from exc
    except Exception as exc:
        logger.error(
            "run_investigation failed for event=%s intent=%s",
            event_id,
            intent_id,
            exc_info=True,
        )
        if intent_id:
            from app.db.session import get_session_factory
            from app.services.investigation_intent_service import InvestigationIntentService

            asyncio.run(
                InvestigationIntentService(get_session_factory()).mark_dead(
                    intent_id,
                    error=str(exc),
                    broker_task_id=task_id,
                )
            )
        raise


# --------------------------------------------------------------------------- #
# Analysis-only Celery task (ISSUE-225)
# --------------------------------------------------------------------------- #

ANALYSIS_ONLY_TASK_NAME = "shadowtrace.run_analysis_only_investigation"
ANALYSIS_ONLY_TASK_QUEUE = "investigation"


async def _run_analysis_only_body(
    event_id: str,
    *,
    generate_report: bool,
    owner_id: str,
    task_id: str,
    redelivered: bool,
    lease_acquired: bool = False,
    request_headers: dict[str, object] | None = None,
) -> dict[str, str]:
    if redelivered:
        redelivery_result = await _handle_redelivered_investigation(
            event_id,
            task_id=task_id,
            owner_id=owner_id,
            request_headers=request_headers,
            lease_acquired=lease_acquired,
            analysis_only=True,
            generate_report=generate_report,
        )
        if redelivery_result is not None:
            return redelivery_result
    return await execute_analysis_only_investigation(
        event_id,
        generate_report=generate_report,
        owner_id=owner_id,
        lease_acquired=lease_acquired,
    )


async def execute_analysis_only_investigation(
    event_id: str,
    *,
    generate_report: bool = True,
    owner_id: str,
    lease_acquired: bool = False,
) -> dict[str, str]:
    """Run AnalysisOnlyPipeline (called from Celery worker via ``asyncio.run``).

    Lease semantics mirror ``execute_investigation``: when *lease_acquired* is
    True the HTTP layer already holds the lease; the pipeline skips its own
    acquire and starts renewal (ISSUE-186 / ISSUE-225).

    ISSUE-225: a background renewal loop keeps the lease alive while the
    pipeline runs.  When renewal fails (stolen or consecutive Redis errors)
    the orchestration is cancelled and ``InvestigationLeaseLostError`` is
    raised, matching the SuperAgent behaviour.
    """
    from app.agents.super_agent import _run_orchestration_with_renewal_watch
    from app.api.v1.deps import (
        _get_session_factory,
        get_event_lease,
        get_pipeline,
        get_state_machine,
    )
    from app.core.errors import (
        InvalidStateTransitionError,
        InvestigationInProgressError,
        InvestigationLeaseLostError,
    )
    from app.models.enums import EventStatus
    from app.services.evidence_projection import EvidenceProjection, bind_evidence_projection
    from app.services.investigation_guidance import record_investigation_workflow_path

    lease = get_event_lease()
    renewal_failed: asyncio.Event | None = None
    renewal_task: asyncio.Task[None] | None = None
    owns_lease = bool(lease_acquired)
    try:
        if not lease_acquired:
            acquired = await lease.acquire(event_id, owner_id)
            if not acquired:
                raise InvestigationInProgressError(
                    message="investigation already in progress for this event",
                    error_code="investigation_in_progress",
                    details={"event_id": event_id},
                )
            owns_lease = True

        # Start background renewal so the lease does not expire during a long
        # pipeline run (ISSUE-225).  Mirrors SuperAgent.investigate().
        if lease is not None:
            renewal_failed = asyncio.Event()
            renewal_task = await lease.start_renewal(
                event_id,
                owner_id,
                on_renewal_failed=renewal_failed,
            )

        pipeline = await get_pipeline()
        projection = EvidenceProjection(_get_session_factory())
        with bind_evidence_projection(projection):
            await _run_orchestration_with_renewal_watch(
                pipeline.run(event_id, generate_report=generate_report),
                renewal_failed,
                event_id=event_id,
            )
        # Record workflow path for investigation guidance (ISSUE-225).
        await record_investigation_workflow_path(
            _get_session_factory(),
            event_id,
            workflow_path="analysis_only",
            include_response_execution=False,
        )
        return {"status": "completed", "event_id": event_id}
    except InvalidStateTransitionError as exc:
        logger.warning(
            "AnalysisOnlyPipeline skipped for event=%s (stale transition): %s",
            event_id,
            exc,
        )
        return {
            "status": "skipped",
            "event_id": event_id,
            "reason": "invalid_state_transition",
        }
    except InvestigationLeaseLostError:
        logger.info(
            "run_analysis_only stopped for event=%s — lease lost mid-run",
            event_id,
        )
        return {
            "status": "skipped",
            "event_id": event_id,
            "reason": "investigation_lease_lost",
        }
    except Exception as exc:
        logger.error(
            "AnalysisOnlyPipeline failed for event=%s: %s",
            event_id,
            exc,
        )
        try:
            state_machine = await get_state_machine()
            await state_machine.transition(
                event_id,
                EventStatus.FAILED,
                operator="AnalysisOnlyPipeline",
                reason=f"pipeline_failed: {exc}",
            )
        except Exception:
            logger.exception("Failed to mark event as FAILED: %s", event_id)
        raise
    finally:
        if renewal_task is not None:
            renewal_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await renewal_task
        if owns_lease:
            await lease.release(event_id, owner_id)


async def dispatch_analysis_only_investigation(
    event_id: str,
    *,
    generate_report: bool = True,
    owner_id: str | None = None,
    lease_acquired: bool = False,
) -> str:
    """Enqueue ``run_analysis_only_investigation`` and return the Celery task id.

    Same contract as ``dispatch_investigation``: the HTTP layer acquires the
    lease and passes *owner_id* + *lease_acquired=True* so the worker inherits
    the existing lease (ISSUE-225).
    """
    task_id = str(celery_uuid())
    await register_task_metadata(task_id, event_id)
    try:
        kwargs = build_analysis_only_dispatch_kwargs(
            generate_report=generate_report,
            owner_id=owner_id,
            lease_acquired=lease_acquired,
        )
        run_analysis_only_investigation.apply_async(
            args=[event_id],
            kwargs=kwargs,
            task_id=task_id,
            queue=ANALYSIS_ONLY_TASK_QUEUE,
        )
    except (OperationalError, OSError, ConnectionError) as exc:
        await delete_task_metadata(task_id)
        raise DependencyUnavailableError(
            message="celery broker unavailable",
            error_code="task_unavailable",
            details={"dependency": "celery_broker", "event_id": event_id},
        ) from exc
    return task_id


@celery_app.task(  # type: ignore[untyped-decorator]
    name=ANALYSIS_ONLY_TASK_NAME,
    bind=True,
    acks_late=True,
    max_retries=CELERY_REDELIVERY_MAX_RETRIES,
    retry_backoff=True,
    soft_time_limit=600,
    queue=ANALYSIS_ONLY_TASK_QUEUE,
)
def run_analysis_only_investigation(
    self: Any,
    event_id: str,
    generate_report: bool = True,
    intent_id: str | None = None,
    resume_from_checkpoint: bool = False,
    owner_id: str | None = None,
    lease_acquired: bool = False,
) -> dict[str, str]:
    """Execute AnalysisOnlyPipeline for *event_id* (ISSUE-225).

    When *owner_id* is set the HTTP layer already holds the lease; the worker
    skips its own acquire and only starts renewal.
    """
    resolved_owner = owner_id or celery_task_owner_id(str(self.request.id))
    task_id = str(self.request.id)
    request_headers = getattr(self.request, "headers", None)
    redelivered = bool(getattr(self.request, "delivery_info", {}).get("redelivered"))
    if redelivered:
        logger.info(
            "run_analysis_only redelivery for event=%s task=%s owner=%s",
            event_id,
            self.request.id,
            resolved_owner,
        )
    if intent_id:
        from app.models.investigation_intent import IntentDeliveryAdmission

        admission = asyncio.run(_admit_intent_delivery(intent_id, task_id))
        if admission is not IntentDeliveryAdmission.ACCEPTED:
            reason = {
                IntentDeliveryAdmission.STALE_SUPERSEDED: "stale_broker_task",
                IntentDeliveryAdmission.ALREADY_TERMINAL: "intent_already_terminal",
                IntentDeliveryAdmission.MISSING: "intent_missing",
            }[admission]
            return _skipped_delivery_result(event_id, reason=reason)
    try:
        try:
            result = asyncio.run(
                _run_analysis_only_body(
                    event_id,
                    generate_report=bool(generate_report),
                    owner_id=resolved_owner,
                    task_id=task_id,
                    redelivered=redelivered or resume_from_checkpoint,
                    lease_acquired=lease_acquired,
                    request_headers=request_headers,
                )
            )
            if intent_id:
                asyncio.run(
                    _finalize_intent_from_result(
                        intent_id,
                        result,
                        broker_task_id=task_id,
                    )
                )
            return result
        finally:
            _release_celery_task_loop_resources()
    except SoftTimeLimitExceeded:
        logger.warning("run_analysis_only soft time limit exceeded for event=%s", event_id)
        try:
            from app.api.v1.deps import get_event_lease

            lease = get_event_lease()
            asyncio.run(lease.release(event_id, resolved_owner))
        except Exception:
            logger.warning(
                "run_analysis_only: best-effort lease release failed after "
                "soft limit event=%s owner=%s",
                event_id,
                resolved_owner,
                exc_info=True,
            )
        try:
            from app.orchestration.checkpointer import invalidate_event_checkpoint

            asyncio.run(invalidate_event_checkpoint(event_id))
        except Exception:
            logger.warning(
                "run_analysis_only: checkpoint fence advance failed after soft limit event=%s",
                event_id,
                exc_info=True,
            )
        if intent_id:
            from app.db.session import get_session_factory
            from app.services.investigation_intent_service import InvestigationIntentService

            asyncio.run(
                InvestigationIntentService(get_session_factory()).mark_dead(
                    intent_id,
                    error="soft_time_limit_exceeded",
                    broker_task_id=task_id,
                )
            )
        raise
    except (RedeliveryLookupRetry, RedeliveryDeferRetry) as exc:
        _celery_redelivery_retry(self, exc, request_headers=request_headers)
    except InvestigationInProgressError:
        logger.info(
            "run_analysis_only skipped for event=%s — lease already held",
            event_id,
        )
        return _skipped_delivery_result(event_id, reason="investigation_in_progress")
    except (DependencyUnavailableError, OperationalError, OSError, ConnectionError) as exc:
        logger.warning(
            "run_analysis_only transient failure for event=%s; retry=%s",
            event_id,
            self.request.retries,
            exc_info=True,
        )
        if intent_id and self.request.retries >= self.max_retries:
            from app.db.session import get_session_factory
            from app.services.investigation_intent_service import InvestigationIntentService

            asyncio.run(
                InvestigationIntentService(get_session_factory()).mark_retry(
                    intent_id,
                    error=str(exc),
                    broker_task_id=task_id,
                )
            )
            raise
        raise self.retry(exc=exc) from exc
    except Exception as exc:
        logger.error(
            "run_analysis_only failed for event=%s intent=%s",
            event_id,
            intent_id,
            exc_info=True,
        )
        if intent_id:
            from app.db.session import get_session_factory
            from app.services.investigation_intent_service import InvestigationIntentService

            asyncio.run(
                InvestigationIntentService(get_session_factory()).mark_dead(
                    intent_id,
                    error=str(exc),
                    broker_task_id=task_id,
                )
            )
        raise


__all__ = [
    "ANALYSIS_ONLY_TASK_NAME",
    "ANALYSIS_ONLY_TASK_QUEUE",
    "TASK_NAME",
    "TASK_QUEUE",
    "delete_task_metadata",
    "dispatch_analysis_only_investigation",
    "dispatch_investigation",
    "execute_analysis_only_investigation",
    "execute_investigation",
    "lookup_task_event_id",
    "publish_analysis_only_investigation_for_intent",
    "publish_investigation_for_intent",
    "register_task_metadata",
    "resolve_task_state",
    "run_analysis_only_investigation",
    "run_investigation",
]
