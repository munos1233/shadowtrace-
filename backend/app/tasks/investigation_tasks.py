"""Celery investigation task — async wrapper around SuperAgent (ISSUE-056).

The Celery worker runs in its own process, so every task execution creates
a fresh event loop and re-wires the full dependency stack via
``app.api.v1.deps``.  The lease is managed inside ``SuperAgent.investigate``;
the task only needs to call it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    name="shadowtrace.run_investigation",
    bind=True,
    acks_late=True,
    max_retries=2,
    default_retry_delay=30,
    retry_backoff=True,
    soft_time_limit=600,
    queue="investigation",
)
def run_investigation(self: Any, event_id: str) -> dict[str, str]:
    """Execute ``SuperAgent.investigate(event_id)`` inside a fresh event loop.

    Duplicate triggers are handled by the distributed lease inside
    ``SuperAgent.investigate`` — the task-body raises
    ``InvestigationInProgressError`` which we catch and treat as a
    successful no-op (idempotent).
    """
    # asyncio.wait_for provides a hard timeout that works even when
    # the Celery soft_time_limit signal is not delivered inside a
    # synchronous asyncio.run() call.  590 s leaves a 10 s margin
    # before the 600 s soft_time_limit to allow cleanup.
    #
    # On timeout the Redis lease acquired by SuperAgent is NOT
    # explicitly released — the cancelled coroutine cannot run
    # cleanup.  The lease expires via its own TTL (600 s), which is
    # acceptable: the event is locked for at most one TTL window,
    # after which another worker can acquire it.
    return asyncio.run(asyncio.wait_for(_investigate(event_id), timeout=590))


async def _investigate(event_id: str) -> dict[str, str]:
    """Wire dependencies and run the investigation."""
    # Lazy imports so the celery worker can boot without loading the full
    # agent stack at import time.
    from app.api.v1.deps import get_super_agent, reset_investigation_layer
    from app.core.errors import InvestigationInProgressError

    # Reset only investigation-layer singletons so each task gets a fresh
    # SuperAgent.  Infrastructure singletons (_session_factory, _redis_client,
    # etc.) are deliberately reused across tasks in the same worker process to
    # avoid leaking database connections and Redis pools.
    reset_investigation_layer()

    try:
        agent = await get_super_agent()
        await agent.investigate(event_id)
    except InvestigationInProgressError:
        logger.info(
            "Celery task skipped for event=%s: investigation already in progress",
            event_id,
        )
        return {"event_id": event_id, "status": "skipped"}
    except Exception:
        logger.exception("Celery investigation task failed for event=%s", event_id)
        raise

    return {"event_id": event_id, "status": "completed"}


__all__ = ["run_investigation"]
