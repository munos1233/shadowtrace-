"""ISSUE-283 real Celery worker SIGKILL/redelivery gate.

The gate starts from an already healthy dedicated Compose stack.  For each
durability boundary it publishes one late-ack task, waits for a durable marker,
SIGKILLs the actual worker container, restarts it, and validates the broker,
lease and Mock XDR artifacts after redelivery.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from celery.result import AsyncResult
from redis import Redis

from app.core.celery_app import celery_app
from app.data_generators.scenarios import build_scenario
from app.models.disposition import (
    DispositionCommand,
    SetEventDispositionParams,
    SourceObjectLocator,
)
from app.models.enums import (
    DispositionIntentKind,
    ExecutionOwner,
    SourceDisposition,
    SourceObjectKind,
)
from tests.fault_injection.celery_sigkill_tasks import (
    FAULT_POINTS,
    PROBE_QUEUE,
    celery_sigkill_probe,
    marker_key,
    probe_key,
)


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, capture_output=True, text=True)


def _compose(args: argparse.Namespace, *command: str) -> subprocess.CompletedProcess[str]:
    base = ["docker", "compose", "--project-name", args.project]
    for compose_file in args.compose_file:
        base.extend(["-f", str(compose_file)])
    base.extend(["--profile", "worker", *command])
    return _run(base)


def _worker_container(args: argparse.Namespace) -> str:
    result = _compose(args, "ps", "-q", "worker")
    container_id = result.stdout.strip().splitlines()
    if len(container_id) != 1 or not container_id[0]:
        raise RuntimeError(f"expected one worker container, got: {result.stdout!r}")
    return container_id[0]


def _wait_for_marker(redis: Redis, run_id: str, point: str, timeout_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    key = marker_key(run_id, point)  # type: ignore[arg-type]
    while time.monotonic() < deadline:
        raw = redis.get(key)
        if raw is not None:
            return json.loads(raw)
        time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for durable {point} marker")


def _decode_hash(redis: Redis, key: str) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for raw_field, raw_value in redis.hgetall(key).items():
        field = raw_field.decode() if isinstance(raw_field, bytes) else str(raw_field)
        value = raw_value.decode() if isinstance(raw_value, bytes) else str(raw_value)
        try:
            decoded[field] = json.loads(value)
        except json.JSONDecodeError:
            decoded[field] = value
    return decoded


def _decode_list(redis: Redis, key: str) -> list[Any]:
    values: list[Any] = []
    for raw in redis.lrange(key, 0, -1):
        text = raw.decode() if isinstance(raw, bytes) else str(raw)
        values.append(json.loads(text))
    return values


def _write_artifact(directory: Path, point: str, payload: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{point}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def _seed_mock_xdr(client: httpx.Client) -> tuple[str, str]:
    scenario = build_scenario("insider_data_exfiltration", seed=283)
    response = client.post(
        "/mock-xdr/v1/control/seed",
        json=scenario.model_dump(mode="json"),
    )
    response.raise_for_status()
    source_object_id = scenario.incidents[0].reference.source_object_id
    source = client.get(
        f"/mock-xdr/v1/incident/{source_object_id}",
        headers={"Authorization": "Bearer mock-read-token"},
    )
    source.raise_for_status()
    concurrency_token = str(source.json()["_mock"]["concurrency_token"])
    return source_object_id, concurrency_token


def _command(
    *,
    run_id: str,
    point: str,
    source_object_id: str,
    concurrency_token: str,
    closure_cycle: int,
) -> DispositionCommand:
    return DispositionCommand(
        disposition_id=f"disp-{run_id}",
        action_id=f"act-{run_id}",
        closure_cycle=closure_cycle,
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-demo",
            connector_id="conn-mock",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id=source_object_id,
        ),
        operation_code="set_event_disposition",
        operation_params=SetEventDispositionParams(
            target_disposition=SourceDisposition.COMPLETED,
        ),
        operator_id="issue283-fault-gate",
        idempotency_key=f"issue283:{point}:{run_id}",
        source_concurrency_token=concurrency_token,
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )


def _captured_provider_requests(client: httpx.Client, idempotency_key: str) -> list[Any]:
    response = client.get("/mock-xdr/v1/control/captured-requests")
    response.raise_for_status()
    return [
        item
        for item in response.json().get("items", [])
        if item.get("idempotency_key") == idempotency_key
    ]


def _run_scenario(
    args: argparse.Namespace,
    *,
    redis: Redis,
    client: httpx.Client,
    point: str,
    source_object_id: str,
    concurrency_token: str,
    closure_cycle: int,
) -> None:
    run_id = f"{point}-{uuid4().hex[:12]}"
    task_id = f"issue283-{run_id}"
    command = _command(
        run_id=run_id,
        point=point,
        source_object_id=source_object_id,
        concurrency_token=concurrency_token,
        closure_cycle=closure_cycle,
    )
    key = probe_key(run_id)
    artifact: dict[str, Any] = {
        "audit_id": "ID-REL-003",
        "issue": "ISSUE-283/#879",
        "fault_point": point,
        "run_id": run_id,
        "task_id": task_id,
        "started_at": datetime.now(UTC).isoformat(),
    }
    try:
        celery_app.conf.task_always_eager = False
        result = celery_sigkill_probe.apply_async(
            args=[
                run_id,
                point,
                command.model_dump(mode="json"),
                args.worker_mock_xdr_url,
            ],
            queue=PROBE_QUEUE,
            task_id=task_id,
        )
        marker = _wait_for_marker(redis, run_id, point, args.marker_timeout)
        worker_before = _worker_container(args)
        artifact["before_sigkill"] = {
            "marker": marker,
            "worker_container": worker_before,
            "task_state": result.state,
            "lease_owner": redis.get(f"shadowtrace:lease:event:{run_id}"),
        }

        _run(["docker", "kill", "--signal=KILL", worker_before])
        killed_logs = _run(
            ["docker", "logs", "--tail", "300", worker_before],
            check=False,
        )
        exit_code = _run(
            ["docker", "inspect", "--format", "{{.State.ExitCode}}", worker_before]
        ).stdout.strip()
        artifact["sigkill"] = {
            "signal": "SIGKILL",
            "worker_container": worker_before,
            "worker_exit_code": int(exit_code),
            "killed_worker_logs": killed_logs.stdout + killed_logs.stderr,
        }
        assert exit_code == "137", artifact["sigkill"]
        _compose(
            args,
            "up",
            "-d",
            "--no-deps",
            "--no-recreate",
            "--wait",
            "--wait-timeout",
            "180",
            "worker",
        )

        final_result = AsyncResult(task_id, app=celery_app).get(
            timeout=args.result_timeout,
            propagate=True,
            disable_sync_subtasks=False,
        )
        worker_after = _worker_container(args)
        provider_requests = _captured_provider_requests(client, command.idempotency_key)
        state = _decode_hash(redis, key)
        worker_attempts = _decode_list(redis, f"{key}:worker_attempts")
        owner_raw = redis.get(f"shadowtrace:lease:event:{run_id}")
        owner = owner_raw.decode() if isinstance(owner_raw, bytes) else owner_raw
        artifact["after_redelivery"] = {
            "result": final_result,
            "task_state": AsyncResult(task_id, app=celery_app).state,
            "worker_container": worker_after,
            "worker_attempts": worker_attempts,
            "state": state,
            "lease_owner": owner,
            "provider_requests": provider_requests,
        }

        assert final_result["status"] == "completed"
        assert state["attempts"] == 2, state
        assert state["terminal_writes"] == 1, state
        assert owner is None, owner
        assert len(worker_attempts) == 2, worker_attempts
        assert worker_attempts[0]["redelivered"] is False, worker_attempts
        assert worker_attempts[1]["redelivered"] is True, worker_attempts
        assert all(
            name in state for name in ("event", "action", "job", "outbox", "receipt", "terminal")
        )
        assert state["event"]["status"] == "closed", state
        assert state["terminal"]["status"] == "closed", state
        assert state["action"]["status"] == "success", state
        assert state["job"]["status"] == "success", state
        assert state["outbox"]["delivery_status"] == "delivered", state
        assert len(provider_requests) == 1, provider_requests
        artifact["result"] = "PASS"
    except BaseException as exc:
        artifact["result"] = "FAIL"
        artifact["error"] = f"{type(exc).__name__}: {exc}"
        try:
            artifact["partial_state"] = _decode_hash(redis, key)
            artifact["worker_attempts"] = _decode_list(redis, f"{key}:worker_attempts")
        except Exception as state_exc:  # noqa: BLE001 - preserve the root failure
            artifact["state_capture_error"] = f"{type(state_exc).__name__}: {state_exc}"
        raise
    finally:
        artifact["finished_at"] = datetime.now(UTC).isoformat()
        try:
            container_id = _worker_container(args)
            logs = _run(
                ["docker", "logs", "--tail", "300", container_id],
                check=False,
            )
            artifact["worker_logs"] = logs.stdout + logs.stderr
        except Exception as log_exc:  # noqa: BLE001 - best-effort failure artifact
            artifact["worker_logs_error"] = f"{type(log_exc).__name__}: {log_exc}"
        _write_artifact(args.artifact_dir, point, artifact)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument(
        "--compose-file",
        action="append",
        type=Path,
        required=True,
    )
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
    )
    parser.add_argument(
        "--mock-xdr-url",
        default=os.environ.get("MOCK_XDR_URL", "http://127.0.0.1:8100"),
    )
    parser.add_argument(
        "--worker-mock-xdr-url",
        default="http://mock-xdr:8100",
    )
    parser.add_argument("--marker-timeout", type=float, default=60.0)
    parser.add_argument("--result-timeout", type=float, default=180.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    redis = Redis.from_url(args.redis_url, decode_responses=False)
    with httpx.Client(base_url=args.mock_xdr_url, timeout=30.0) as client:
        source_object_id, concurrency_token = _seed_mock_xdr(client)
        for index, point in enumerate(FAULT_POINTS, start=1):
            print(
                f"[ISSUE-283] fault point {point}: enqueue → SIGKILL → redelivery",
                flush=True,
            )
            _run_scenario(
                args,
                redis=redis,
                client=client,
                point=point,
                source_object_id=source_object_id,
                concurrency_token=concurrency_token,
                closure_cycle=280 + index,
            )
    print(f"[ISSUE-283] PASS: artifacts={args.artifact_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
