"""Celery investigation task (ISSUE-056)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from celery import uuid as celery_uuid
from celery.exceptions import SoftTimeLimitExceeded
from kombu.exceptions import OperationalError

from app.core.celery_app import celery_app
from app.core.celery_delivery import (
    celery_task_owner_id,
    evaluate_redelivered_investigation_skip,
    normalize_public_task_state,
)
from app.core.errors import DependencyUnavailableError, InvestigationInProgressError
from app.core.redis_client import RedisClient
from app.models.investigation_intent import IntentDeliveryAdmission

logger = logging.getLogger(__name__)

TASK_NAME = "shadowtrace.run_investigation"
TASK_QUEUE = "investigation"
TASK_META_PREFIX = "shadowtrace:celery:task:"
TASK_META_TTL_SECONDS = 86_400


def _release_celery_task_loop_resources() -> None:
    """Strategy B (#623): drop loop-bound clients after each asyncio.run task."""
    from app.api.v1.deps import reset_investigation_stack_cache
    from app.core.embedding.factory import reset_embedding_client
    from app.playbook.resources import reset_playbook_resources_cache
    from app.rag.resources import reset_loaded_retrieval_resources

    reset_investigation_stack_cache()
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


async def dispatch_investigation(
    event_id: str,
    *,
    include_response_execution: bool = False,
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
        kwargs: dict[str, object] = {
            "include_response_execution": include_response_execution,
        }
        if owner_id is not None:
            kwargs["owner_id"] = owner_id
        if lease_acquired:
            kwargs["lease_acquired"] = True
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
) -> None:
    """Publish a deterministic Celery task for a claimed investigation intent.

    ``include_response_execution`` is resolved by AutoResponsePolicyService at
    ENQUEUED commit time (#613); auto-investigate intent creation never sets it.

    Raises broker connectivity errors to the caller; ingest paths must catch.
    """
    run_investigation.apply_async(
        args=[event_id],
        kwargs={
            "include_response_execution": bool(include_response_execution),
            "intent_id": intent_id,
        },
        task_id=task_id,
        queue=TASK_QUEUE,
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


async def _finalize_intent_from_result(intent_id: str, result: dict[str, str]) -> None:
    from app.db.session import get_session_factory
    from app.services.investigation_intent_service import InvestigationIntentService

    service = InvestigationIntentService(get_session_factory())
    status = str(result.get("status") or "")
    if status == "skipped":
        await service.mark_skipped(
            intent_id,
            reason=str(result.get("reason") or "investigation_skipped"),
        )
    else:
        await service.mark_terminal(intent_id)


async def resolve_task_state(task_id: str) -> tuple[str, str | None]:
    """Return Celery state and optional event_id for a dispatched task."""
    from celery.result import AsyncResult

    result = AsyncResult(task_id, app=celery_app)
    event_id = await lookup_task_event_id(task_id)
    if event_id is None and isinstance(result.info, dict):
        event_id = result.info.get("event_id")
    if event_id is None and result.args:
        event_id = str(result.args[0])
    return normalize_public_task_state(result.state), event_id


async def _run_investigation_body(
    event_id: str,
    *,
    include_response_execution: bool,
    owner_id: str,
    redelivered: bool,
    lease_acquired: bool = False,
) -> dict[str, str]:
    if redelivered:
        skip, skip_reason = await evaluate_redelivered_investigation_skip(event_id)
        if skip:
            logger.info(
                "run_investigation redelivery skipped event=%s reason=%s",
                event_id,
                skip_reason,
            )
            return {
                "status": "skipped",
                "event_id": event_id,
                "reason": skip_reason or "lookup_degraded",
            }
    return await execute_investigation(
        event_id,
        include_response_execution=include_response_execution,
        owner_id=owner_id,
        lease_acquired=lease_acquired,
    )


@celery_app.task(  # type: ignore[untyped-decorator]
    name=TASK_NAME,
    bind=True,
    acks_late=True,
    max_retries=2,
    retry_backoff=True,
    soft_time_limit=600,
    queue=TASK_QUEUE,
)
def run_investigation(
    self: Any,
    event_id: str,
    include_response_execution: bool = False,
    intent_id: str | None = None,
    owner_id: str | None = None,
    lease_acquired: bool = False,
) -> dict[str, str]:
    """Execute SuperAgent investigation for *event_id* (idempotent when lease held).

    When *owner_id* is set by the caller (HTTP-layer pre-lease, ISSUE-186) use it
    directly; otherwise derive a stable owner from the Celery task id so redelivery
    can reclaim the same lease.
    """
    resolved_owner = owner_id or celery_task_owner_id(str(self.request.id))
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
                    owner_id=resolved_owner,
                    redelivered=redelivered,
                    lease_acquired=lease_acquired,
                )
            )
            if intent_id:
                asyncio.run(_finalize_intent_from_result(intent_id, result))
            return result
        finally:
            _release_celery_task_loop_resources()
    except SoftTimeLimitExceeded:
        logger.warning("run_investigation soft time limit exceeded for event=%s", event_id)
        if intent_id:
            from app.db.session import get_session_factory
            from app.services.investigation_intent_service import InvestigationIntentService

            asyncio.run(
                InvestigationIntentService(get_session_factory()).mark_dead(
                    intent_id,
                    error="soft_time_limit_exceeded",
                )
            )
        raise
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
                )
            )
        raise


__all__ = [
    "TASK_NAME",
    "TASK_QUEUE",
    "delete_task_metadata",
    "dispatch_investigation",
    "execute_investigation",
    "lookup_task_event_id",
    "publish_investigation_for_intent",
    "register_task_metadata",
    "resolve_task_state",
    "run_investigation",
]
