"""Celery delivery/reconciliation for durable disposition outboxes."""

from __future__ import annotations

import asyncio
from typing import Any

from app.core.celery_app import celery_app

PROCESS_DISPOSITION_OUTBOXES_TASK = "shadowtrace.process_disposition_outboxes"
OUTBOX_QUEUE = "investigation"


async def _process_once_async() -> dict[str, Any]:
    # Use the production dependency graph: successful delivery may need to
    # persist degraded flags, resolve a manual hold, and enqueue graph resume.
    from app.api.v1 import deps
    from app.core.config import get_settings

    redis = deps._get_redis()
    try:
        settings = get_settings()
        rollback = await deps.get_rollback_service()
        repaired = await rollback.repair_completed_rollbacks(
            limit=settings.outbox_delivery_batch_size,
        )
        sync = await deps.get_disposition_sync()
        delivered = await sync.process_ready_outboxes(
            limit=settings.outbox_delivery_batch_size,
        )
        return {"delivered": delivered, "rollback_compensations_repaired": repaired}
    finally:
        await redis.aclose()
        deps.reset_loop_bound_redis_resources()


@celery_app.task(  # type: ignore[untyped-decorator]
    name=PROCESS_DISPOSITION_OUTBOXES_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=OUTBOX_QUEUE,
)
def process_disposition_outboxes() -> dict[str, Any]:
    """Deliver READY outboxes and reconcile accepted entity effects."""
    return asyncio.run(_process_once_async())


__all__ = [
    "OUTBOX_QUEUE",
    "PROCESS_DISPOSITION_OUTBOXES_TASK",
    "process_disposition_outboxes",
]
