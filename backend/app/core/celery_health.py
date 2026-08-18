"""Celery broker vs worker health probes (ISSUE-117 / #622 Phase A).

Broker liveness and worker consumption are separate signals. These probes are
for operations / health reporting only — never call ``probe_celery_workers`` as
a pre-publish gate (no inspect-before-publish race).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

DEFAULT_INSPECT_TIMEOUT_SECONDS = 2.0


async def check_celery_broker(broker_url: str) -> str:
    """Return ``ok`` when the broker URL accepts PING (Redis broker)."""
    if not broker_url.strip():
        return "error"
    client = Redis.from_url(broker_url, decode_responses=True)
    try:
        pong = await client.ping()
        return "ok" if pong else "error"
    except Exception:  # noqa: BLE001 — health must never raise
        logger.debug("celery broker ping failed", exc_info=True)
        return "error"
    finally:
        await client.aclose()


def probe_celery_workers(*, timeout: float = DEFAULT_INSPECT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Synchronous Celery inspect ping — run via ``asyncio.to_thread`` from async handlers."""
    from app.core.celery_app import celery_app

    try:
        inspector = celery_app.control.inspect(timeout=timeout)
        replies = inspector.ping()
        if not replies:
            return {
                "status": "degraded",
                "workers": 0,
                "worker_ids": [],
                "reason": "no_workers_responding",
            }
        worker_ids = sorted(replies.keys())
        return {
            "status": "ok",
            "workers": len(worker_ids),
            "worker_ids": worker_ids,
        }
    except Exception as exc:  # noqa: BLE001 — health must never raise
        logger.debug("celery worker inspect failed", exc_info=True)
        return {
            "status": "error",
            "workers": 0,
            "worker_ids": [],
            "reason": type(exc).__name__,
        }


async def check_celery_workers(
    *, timeout: float = DEFAULT_INSPECT_TIMEOUT_SECONDS
) -> dict[str, Any]:
    """Async wrapper for worker inspect (non-blocking event loop)."""
    return await asyncio.to_thread(probe_celery_workers, timeout=timeout)


async def build_celery_health(
    *,
    task_mode: str,
    broker_url: str,
    inspect_timeout: float = DEFAULT_INSPECT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Aggregate broker + worker health for ``GET /health``."""
    mode = (task_mode or "background").strip().lower()
    broker_status = await check_celery_broker(broker_url)
    beat_schedule = check_investigation_intent_beat_schedule(task_mode=mode)

    if mode != "celery":
        return {
            "task_mode": mode,
            "broker": broker_status,
            "worker": {"status": "not_applicable", "workers": 0, "worker_ids": []},
            "investigation_intent_beat": beat_schedule,
        }

    worker = await check_celery_workers(timeout=inspect_timeout)
    return {
        "task_mode": mode,
        "broker": broker_status,
        "worker": worker,
        "investigation_intent_beat": beat_schedule,
    }


def check_investigation_intent_beat_schedule(*, task_mode: str) -> dict[str, Any]:
    """Verify durable intent recovery tasks are registered in the beat schedule."""
    mode = (task_mode or "background").strip().lower()
    if mode != "celery":
        return {
            "status": "not_applicable",
            "dispatch_scheduled": False,
            "reconcile_scheduled": False,
        }

    from app.core.celery_app import _build_beat_schedule
    from app.core.config import TaskMode

    try:
        mode_enum = TaskMode(mode)
    except ValueError:
        return {
            "status": "degraded",
            "dispatch_scheduled": False,
            "reconcile_scheduled": False,
        }
    schedule = _build_beat_schedule(task_mode=mode_enum)
    dispatch_key = "shadowtrace-dispatch-investigation-intents"
    reconcile_key = "shadowtrace-reconcile-investigation-intents"
    dispatch_scheduled = dispatch_key in schedule
    reconcile_scheduled = reconcile_key in schedule
    status = "ok" if dispatch_scheduled and reconcile_scheduled else "degraded"
    return {
        "status": status,
        "dispatch_scheduled": dispatch_scheduled,
        "reconcile_scheduled": reconcile_scheduled,
    }
