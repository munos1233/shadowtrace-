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
    return asyncio.run(_investigate(event_id))


async def _investigate(event_id: str) -> dict[str, str]:
    """Wire dependencies and run the investigation."""
    # Lazy imports so the celery worker can boot without loading the full
    # agent stack at import time.
    from app.api.v1.deps import get_super_agent, reset_deps
    from app.core.errors import InvestigationInProgressError

    # Reset investigation singletons so each task gets a fresh SuperAgent.
    # Infrastructure singletons (session factory, Redis client, etc.) are
    # reused across tasks in the same worker process.
    reset_deps()

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
