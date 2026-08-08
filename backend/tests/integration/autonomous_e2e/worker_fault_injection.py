"""Real Celery worker SIGKILL fault-injection harness (ISSUE-283 / ID-REL-003)."""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.celery_health import probe_celery_workers
from app.tasks.worker_tasks import FAULT_BARRIER_KEY_PREFIX

ROOT = Path(__file__).resolve().parents[4]
COMPOSE_FILE = ROOT / "infra" / "docker-compose.yml"


@dataclass
class CrashScenarioArtifacts:
    scenario: str
    started_at: str
    finished_at: str | None = None
    worker_kill_succeeded: bool = False
    worker_restart_succeeded: bool = False
    broker_task_id: str | None = None
    broker_task_state: str | None = None
    broker_task_result: Any = None
    event_id: str | None = None
    observability: dict[str, Any] = field(default_factory=dict)
    lease_owner: str | None = None
    lease_released: bool | None = None
    provider_call_count: int | None = None
    notes: str = ""
    worker_logs_tail: str = ""
    coverage_only: bool = False


def compose_project_name() -> str:
    for key in ("INTEGRATION_PROJECT_NAME", "COMPOSE_PROJECT_NAME"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return "shadowtrace-integration"


def _compose_cmd(*args: str) -> list[str]:
    cmd = [
        "docker",
        "compose",
        "--project-name",
        compose_project_name(),
        "-f",
        str(COMPOSE_FILE),
        "--profile",
        "worker",
        *args,
    ]
    return cmd


def worker_container_id() -> str:
    result = subprocess.run(
        _compose_cmd("ps", "-q", "worker"),
        capture_output=True,
        text=True,
        check=False,
    )
    container_id = (result.stdout or "").strip().splitlines()
    if not container_id or result.returncode != 0:
        raise RuntimeError(
            "worker container not found — run `make autonomous-mock-e2e-worker-pytest` "
            f"(project={compose_project_name()})"
        )
    return container_id[0]


def sigkill_worker() -> None:
    container_id = worker_container_id()
    subprocess.run(["docker", "kill", "-s", "SIGKILL", container_id], check=True)


def restart_worker(*, wait_healthy_s: float = 180.0) -> None:
    subprocess.run(_compose_cmd("restart", "worker"), check=True)
    deadline = time.monotonic() + wait_healthy_s
    while time.monotonic() < deadline:
        payload = probe_celery_workers(timeout=3.0)
        if payload.get("status") == "ok" and int(payload.get("workers") or 0) > 0:
            return
        time.sleep(2.0)
    raise TimeoutError(f"worker did not become healthy within {wait_healthy_s}s")


def fetch_worker_logs_tail(*, lines: int = 120) -> str:
    container_id = worker_container_id()
    result = subprocess.run(
        ["docker", "logs", "--tail", str(lines), container_id],
        capture_output=True,
        text=True,
        check=False,
    )
    return (result.stdout or "") + (result.stderr or "")


async def read_barrier_heartbeat(redis_client: Any, barrier_id: str) -> str | None:
    raw = await redis_client.get_client().get(f"{FAULT_BARRIER_KEY_PREFIX}{barrier_id}")
    if raw is None:
        return None
    return raw.decode() if isinstance(raw, bytes) else str(raw)


def artifact_dir(scenario: str) -> Path:
    base = Path(
        os.environ.get(
            "CELERY_CRASH_ARTIFACT_DIR",
            str(ROOT / "backend" / "artifacts" / "celery-crash"),
        )
    )
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = base / run_id / scenario
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_artifacts(path: Path, artifacts: CrashScenarioArtifacts) -> Path:
    payload = asdict(artifacts)
    out = path / "scenario.json"
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    summary = path / "SUMMARY.md"
    summary.write_text(
        "\n".join(
            [
                f"# {artifacts.scenario}",
                "",
                f"- started: {artifacts.started_at}",
                f"- finished: {artifacts.finished_at}",
                f"- worker_kill: {artifacts.worker_kill_succeeded}",
                f"- worker_restart: {artifacts.worker_restart_succeeded}",
                f"- coverage_only: {artifacts.coverage_only}",
                f"- notes: {artifacts.notes or '(none)'}",
                "",
                "See `scenario.json` for full broker/event/outbox snapshots.",
            ]
        ),
        encoding="utf-8",
    )
    return out
