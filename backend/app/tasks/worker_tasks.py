"""Lightweight Celery worker tasks for ops smoke (ISSUE-117 / #622 Phase A)."""

from __future__ import annotations

import asyncio
import logging
import time

from app.core.celery_app import celery_app
from app.core.redis_client import RedisClient
from app.tasks.investigation_tasks import TASK_QUEUE

logger = logging.getLogger(__name__)

WORKER_PING_TASK = "shadowtrace.worker_ping"
FAULT_INJECTION_BARRIER_TASK = "shadowtrace.fault_injection_barrier"
FAULT_BARRIER_KEY_PREFIX = "shadowtrace:fault:barrier:"


@celery_app.task(  # type: ignore[untyped-decorator]
    name=WORKER_PING_TASK,
    acks_late=True,
    queue=TASK_QUEUE,
)
def worker_ping() -> dict[str, str]:
    """Minimal queue consumer smoke — no DB/Agent side effects."""
    return {"status": "ok", "task": WORKER_PING_TASK}


async def _write_barrier_heartbeat(barrier_id: str, task_id: str, phase: str) -> None:
    from app.core.config import get_settings

    client = RedisClient(url=get_settings().redis_url)
    try:
        if not await client.ping():
            return
        redis = client.get_client()
        key = f"{FAULT_BARRIER_KEY_PREFIX}{barrier_id}"
        await redis.set(
            key,
            f"{phase}|{task_id}|{time.time():.3f}",
            ex=300,
        )
    finally:
        await client.aclose()


@celery_app.task(  # type: ignore[untyped-decorator]
    name=FAULT_INJECTION_BARRIER_TASK,
    bind=True,
    acks_late=True,
    queue=TASK_QUEUE,
)
def fault_injection_barrier(self: object, barrier_id: str, hold_s: float = 60.0) -> dict[str, str]:
    """Hold a worker slot open for real SIGKILL fault-injection tests (ISSUE-283).

    Writes heartbeat keys to Redis so the pytest harness can kill the worker
    mid-flight and assert broker redelivery completes exactly once.
    """
    task_id = str(getattr(getattr(self, "request", None), "id", "unknown"))
    deadline = time.monotonic() + max(hold_s, 1.0)
    asyncio.run(_write_barrier_heartbeat(barrier_id, task_id, "started"))
    while time.monotonic() < deadline:
        asyncio.run(_write_barrier_heartbeat(barrier_id, task_id, "holding"))
        time.sleep(0.5)
    asyncio.run(_write_barrier_heartbeat(barrier_id, task_id, "completed"))
    return {"status": "ok", "barrier_id": barrier_id, "task_id": task_id}


__all__ = [
    "FAULT_BARRIER_KEY_PREFIX",
    "FAULT_INJECTION_BARRIER_TASK",
    "WORKER_PING_TASK",
    "fault_injection_barrier",
    "worker_ping",
]
