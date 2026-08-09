"""ISSUE-283 real-worker SIGKILL probe task.

This module is imported only by the dedicated fault-injection worker.  It uses
the production Celery app, Redis ``EventLease`` and Mock XDR HTTP adapter while
keeping all probe artifacts under an isolated Redis prefix.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import time
from typing import Any, Literal

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.core.celery_app import celery_app
from app.core.redis_client import RedisClient
from app.models.disposition import DispositionCommand, DispositionReceipt
from app.orchestration.lease import EventLease

FAULT_POINTS = ("action", "outbox", "receipt", "terminal")
FaultPoint = Literal["action", "outbox", "receipt", "terminal"]
PROBE_QUEUE = "issue283-sigkill"
PROBE_TASK_NAME = "shadowtrace.issue283_celery_sigkill_probe"
PROBE_KEY_PREFIX = "shadowtrace:issue283:sigkill:"
_FAULT_WAIT_TIMEOUT_S = 180.0

# Redis transport normally keeps an unacked message invisible for 15 minutes.
# The dedicated worker makes it eligible after five seconds; Kombu's periodic
# restore sweep can add roughly 100 seconds before the message is requeued.
celery_app.conf.broker_transport_options = {
    **dict(celery_app.conf.broker_transport_options or {}),
    "visibility_timeout": int(os.environ.get("ISSUE283_VISIBILITY_TIMEOUT_S", "5")),
}


def probe_key(run_id: str) -> str:
    return f"{PROBE_KEY_PREFIX}{run_id}"


def marker_key(run_id: str, point: FaultPoint) -> str:
    return f"{probe_key(run_id)}:marker:{point}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


async def _set_artifact(redis: Any, key: str, field: str, value: Any) -> None:
    await redis.hset(key, field, _json(value))


async def _get_artifact(redis: Any, key: str, field: str) -> Any | None:
    raw = await redis.hget(key, field)
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(str(raw))


async def _pause_for_external_sigkill(
    redis: Any,
    *,
    run_id: str,
    point: FaultPoint,
    payload: dict[str, Any],
) -> None:
    """Publish one durable marker and block until the worker is really killed."""
    latch = f"{probe_key(run_id)}:fired:{point}"
    first = await redis.set(latch, "1", nx=True, ex=900)
    if not first:
        return
    await redis.set(marker_key(run_id, point), _json(payload), ex=900)
    deadline = time.monotonic() + _FAULT_WAIT_TIMEOUT_S
    release_key = f"{probe_key(run_id)}:release:{point}"
    while time.monotonic() < deadline:
        if await redis.get(release_key) is not None:
            return
        await asyncio.sleep(0.2)
    raise TimeoutError(f"external SIGKILL not observed for {point} within timeout")


async def _run_probe(
    *,
    task: Any,
    run_id: str,
    point: FaultPoint,
    command_payload: dict[str, Any],
    mock_xdr_base_url: str,
) -> dict[str, Any]:
    if point not in FAULT_POINTS:
        raise ValueError(f"unsupported fault point: {point}")

    redis_client = RedisClient()
    redis = redis_client.get_client()
    lease = EventLease(redis_client)
    command = DispositionCommand.model_validate(command_payload)
    task_id = str(task.request.id)
    owner_id = f"celery-{task_id}"
    key = probe_key(run_id)
    adapter = MockXDRDispositionAdapter(
        base_url=mock_xdr_base_url,
        read_token="mock-read-token",
        write_token="mock-write-token",
        max_retries=0,
    )
    try:
        attempt = int(await redis.hincrby(key, "attempts", 1))
        redelivered = bool(getattr(task.request, "delivery_info", {}).get("redelivered"))
        worker_attempt = {
            "attempt": attempt,
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
            "redelivered": redelivered,
            "task_id": task_id,
        }
        await redis.rpush(f"{key}:worker_attempts", _json(worker_attempt))
        await _set_artifact(
            redis,
            key,
            "broker",
            {"task_id": task_id, "redelivered": redelivered, "attempt": attempt},
        )

        current_owner = await lease.get_owner(run_id)
        if current_owner is None:
            if not await lease.acquire(run_id, owner_id, ttl_s=120):
                raise RuntimeError("probe lease acquisition lost a race")
        elif current_owner != owner_id:
            raise RuntimeError(
                f"probe lease owner mismatch: expected={owner_id} actual={current_owner}"
            )

        event = await _get_artifact(redis, key, "event")
        if event is None:
            event = {
                "event_id": run_id,
                "source_object_id": command.source_locator.source_object_id,
                "status": "processing",
            }
            await _set_artifact(redis, key, "event", event)

        terminal = await _get_artifact(redis, key, "terminal")
        if terminal is not None:
            await lease.release(run_id, owner_id)
            return {
                "status": "completed",
                "run_id": run_id,
                "terminal_writes": int(await redis.hget(key, "terminal_writes") or 0),
                "replayed_terminal": True,
            }

        action = await _get_artifact(redis, key, "action")
        if action is None:
            action = {
                "action_id": command.action_id,
                "event_id": run_id,
                "status": "executing",
            }
            await _set_artifact(redis, key, "action", action)
        if point == "action":
            await _pause_for_external_sigkill(
                redis,
                run_id=run_id,
                point=point,
                payload={"action": action, "owner": owner_id, "worker": worker_attempt},
            )

        job = await _get_artifact(redis, key, "job")
        if job is None:
            job = {
                "job_id": f"job-{run_id}",
                "action_id": command.action_id,
                "idempotency_key": command.idempotency_key,
                "status": "running",
            }
            await _set_artifact(redis, key, "job", job)

        outbox = await _get_artifact(redis, key, "outbox")
        if outbox is None:
            outbox = {
                "outbox_id": f"out-{run_id}",
                "action_id": command.action_id,
                "idempotency_key": command.idempotency_key,
                "delivery_status": "leased",
            }
            await _set_artifact(redis, key, "outbox", outbox)
        if point == "outbox":
            await _pause_for_external_sigkill(
                redis,
                run_id=run_id,
                point=point,
                payload={"job": job, "outbox": outbox, "owner": owner_id},
            )

        receipt_payload = await _get_artifact(redis, key, "receipt")
        if receipt_payload is None:
            receipt = await adapter.lookup_submission(
                command.idempotency_key,
                command.source_locator,
            )
            provider_path = "lookup"
            if receipt is None:
                receipt = await adapter.submit(command)
                provider_path = "submit"
            if point == "receipt":
                await _pause_for_external_sigkill(
                    redis,
                    run_id=run_id,
                    point=point,
                    payload={
                        "provider_path": provider_path,
                        "receipt": receipt.model_dump(mode="json"),
                        "outbox": outbox,
                    },
                )
            receipt_payload = receipt.model_dump(mode="json")
            await _set_artifact(redis, key, "receipt", receipt_payload)
        else:
            receipt = DispositionReceipt.model_validate(receipt_payload)

        action["status"] = "success"
        job["status"] = "success"
        outbox["delivery_status"] = "delivered"
        outbox["latest_writeback_status"] = receipt.status.value
        event["status"] = "closed"
        await _set_artifact(redis, key, "event", event)
        await _set_artifact(redis, key, "action", action)
        await _set_artifact(redis, key, "job", job)
        await _set_artifact(redis, key, "outbox", outbox)

        terminal = {
            "event_id": run_id,
            "status": "closed",
            "receipt_status": receipt.status.value,
        }
        inserted = await redis.hsetnx(key, "terminal", _json(terminal))
        if inserted:
            await redis.hincrby(key, "terminal_writes", 1)
        if point == "terminal":
            await _pause_for_external_sigkill(
                redis,
                run_id=run_id,
                point=point,
                payload={"terminal": terminal, "owner": owner_id},
            )

        await lease.release(run_id, owner_id)
        return {
            "status": "completed",
            "run_id": run_id,
            "terminal_writes": int(await redis.hget(key, "terminal_writes") or 0),
            "replayed_terminal": False,
        }
    finally:
        await adapter.aclose()
        await redis_client.aclose()


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    name=PROBE_TASK_NAME,
    acks_late=True,
    reject_on_worker_lost=True,
    track_started=True,
    queue=PROBE_QUEUE,
)
def celery_sigkill_probe(
    self: Any,
    run_id: str,
    point: FaultPoint,
    command_payload: dict[str, Any],
    mock_xdr_base_url: str = "http://mock-xdr:8100",
) -> dict[str, Any]:
    """Run one durable probe; the external gate kills this worker at *point*."""
    return asyncio.run(
        _run_probe(
            task=self,
            run_id=run_id,
            point=point,
            command_payload=command_payload,
            mock_xdr_base_url=mock_xdr_base_url,
        )
    )


__all__ = [
    "FAULT_POINTS",
    "PROBE_KEY_PREFIX",
    "PROBE_QUEUE",
    "PROBE_TASK_NAME",
    "celery_sigkill_probe",
    "marker_key",
    "probe_key",
]
