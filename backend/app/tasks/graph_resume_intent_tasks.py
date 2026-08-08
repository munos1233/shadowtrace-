"""Celery tasks for durable graph resume intent dispatch (ISSUE-277 / #873)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import get_session_factory
from app.services.manual_resolution_service import ManualResolutionService

logger = logging.getLogger(__name__)

DISPATCH_GRAPH_RESUME_TASK = "shadowtrace.dispatch_graph_resume_intents"
RECONCILE_GRAPH_RESUME_TASK = "shadowtrace.reconcile_graph_resume_intents"
GRAPH_RESUME_QUEUE = "investigation"


async def _dispatch_once_async() -> dict[str, Any]:
    factory = get_session_factory()
    service = ManualResolutionService(factory)
    executed = await service.claim_and_execute_batch(limit=10)
    return {"executed": executed}


async def _reconcile_once_async() -> dict[str, Any]:
    factory = get_session_factory()
    service = ManualResolutionService(factory)
    reconciled = await service.reconcile_stale(limit=20)
    return {"reconciled": reconciled}


@celery_app.task(  # type: ignore[untyped-decorator]
    name=DISPATCH_GRAPH_RESUME_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=GRAPH_RESUME_QUEUE,
)
def dispatch_pending_graph_resume_intents() -> dict[str, Any]:
    """Claim pending graph resume intents and invoke checkpoint resume."""
    return asyncio.run(_dispatch_once_async())


@celery_app.task(  # type: ignore[untyped-decorator]
    name=RECONCILE_GRAPH_RESUME_TASK,
    acks_late=True,
    soft_time_limit=120,
    queue=GRAPH_RESUME_QUEUE,
)
def reconcile_graph_resume_intents() -> dict[str, Any]:
    """Recover stale graph resume intents after worker crashes."""
    return asyncio.run(_reconcile_once_async())


__all__ = [
    "DISPATCH_GRAPH_RESUME_TASK",
    "GRAPH_RESUME_QUEUE",
    "RECONCILE_GRAPH_RESUME_TASK",
    "dispatch_pending_graph_resume_intents",
    "reconcile_graph_resume_intents",
]
