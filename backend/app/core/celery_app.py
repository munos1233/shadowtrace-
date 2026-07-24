"""Celery application configuration (ISSUE-056).

Redis broker (DB 1) and result backend (DB 2), with task routing to the
``investigation`` queue.  Uses JSON serialisation and late-ack semantics
so that worker crashes do not silently drop tasks.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from celery import Celery

from app.core.config import get_settings

_settings = get_settings()


def _derive_result_backend(broker_url: str) -> str:
    """Return ``broker_url`` with the Redis DB number incremented by 1.

    Assumes a Redis broker URL whose path is solely a DB number
    (e.g. ``/1``).  Non-Redis backends with nested vhost paths are
    not supported by this helper.

    Uses stdlib ``urlparse`` to safely handle URLs with or without an
    explicit DB path segment, query strings, or fragments::

        redis://host:6379/1                  →  redis://host:6379/2
        redis://host:6379/1?timeout=5        →  redis://host:6379/2?timeout=5
        redis://host:6379                    →  redis://host:6379/1
        redis://host:6379?timeout=5          →  redis://host:6379/1?timeout=5

    """
    parsed = urlparse(broker_url)
    path = parsed.path.rstrip("/")
    if path and path != "/":
        # Path contains a DB number, e.g. "/1"
        parts = path.rsplit("/", 1)
        try:
            db_num = int(parts[-1])
        except (ValueError, IndexError):
            db_num = 0
    else:
        # No explicit DB number — Redis default DB 0.
        db_num = 0
    new_path = f"/{db_num + 1}"
    return urlunparse(parsed._replace(path=new_path))


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

celery_app.autodiscover_tasks(["app.tasks"])

__all__ = ["celery_app"]
