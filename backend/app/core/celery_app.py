"""Celery application configuration (ISSUE-056).

Redis broker (DB 1) and result backend (DB 2), with task routing to the
``investigation`` queue.  Uses JSON serialisation and late-ack semantics
so that worker crashes do not silently drop tasks.
"""

from __future__ import annotations

import re

from celery import Celery

from app.core.config import get_settings

_settings = get_settings()


def _derive_result_backend(broker_url: str) -> str:
    """Return ``broker_url`` with the Redis DB number incremented by 1.

    Handles URLs with or without an explicit DB path segment::

        redis://host:6379/1  →  redis://host:6379/2
        redis://host:6379    →  redis://host:6379/2   (DB 0 → DB 2)

    """
    return re.sub(
        r"(/(\d+))?$",
        lambda m: f"/{int(m.group(2)) + 1}" if m.group(2) else "/2",
        broker_url,
        count=1,
    )


celery_app = Celery(
    "shadowtrace",
    broker=_settings.celery_broker_url,
    backend=_derive_result_backend(_settings.celery_broker_url),
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_default_queue="investigation",
    task_routes={
        "shadowtrace.run_investigation": {"queue": "investigation"},
    },
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
)

celery_app.autodiscover_tasks(["app.tasks.investigation_tasks"])

__all__ = ["celery_app"]
