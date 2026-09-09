"""Compose/entrypoint playbook seed wiring guards (ISSUE-245 / #820)."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.yml"
WORKER_COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.worker.yml"
ENTRYPOINT_PATH = REPO_ROOT / "backend" / "docker-entrypoint.sh"
BOOTSTRAP_PATH = REPO_ROOT / "scripts" / "bootstrap.sh"
SMOKE_PATH = REPO_ROOT / "scripts" / "smoke_bootstrap.sh"
MAKEFILE_PATH = REPO_ROOT / "Makefile"
LOAD_SCRIPT = REPO_ROOT / "backend" / "scripts" / "load_playbook_release.py"


def test_load_playbook_release_script_exists() -> None:
    assert LOAD_SCRIPT.is_file()
    text = LOAD_SCRIPT.read_text(encoding="utf-8")
    assert "stage_playbook_bundle" in text
    assert "activate_release" in text
    assert "playbooks.json" in text


def test_entrypoint_seeds_playbook_when_flag_set() -> None:
    text = ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "SEED_PLAYBOOK_RELEASE" in text
    assert "scripts.load_playbook_release" in text


def test_compose_backend_seeds_playbook_by_default() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    backend_env = (data.get("services") or {}).get("backend", {}).get("environment") or {}
    assert "SEED_PLAYBOOK_RELEASE" in backend_env
    assert "true" in str(backend_env["SEED_PLAYBOOK_RELEASE"])
    assert "PLAYBOOK_REQUIRED" in backend_env


def test_compose_workers_do_not_seed_playbook() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    for name in ("worker", "scheduler-beat", "scheduler-worker"):
        env = (services.get(name) or {}).get("environment") or {}
        assert env.get("SEED_PLAYBOOK_RELEASE") == "false", (
            f"{name} must not seed playbook release (backend owns seed)"
        )


def test_scheduler_beat_healthcheck_does_not_require_pgrep() -> None:
    """python:slim images omit procps; PID 1 cmdline is the celery beat process."""
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    beat = (data.get("services") or {}).get("scheduler-beat") or {}
    healthcheck = beat.get("healthcheck") or {}
    test = healthcheck.get("test") or []
    joined = " ".join(str(item) for item in test)
    assert "pgrep" not in joined
    assert "/proc/1/cmdline" in joined
    assert "beat" in joined


def test_compose_workers_skip_db_migrate_and_wait_for_backend() -> None:
    """ISSUE-238 regression: workers must not race backend alembic on cold boot."""
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    for name in ("worker", "scheduler-beat", "scheduler-worker"):
        service = services.get(name) or {}
        env = service.get("environment") or {}
        depends_on = service.get("depends_on") or {}
        assert env.get("SKIP_DB_MIGRATE") == "true", f"{name} must skip alembic migrate"
        assert depends_on.get("backend", {}).get("condition") == "service_healthy", (
            f"{name} must wait for backend healthy before start"
        )


def test_entrypoint_documents_skip_migrate_and_playbook_seed() -> None:
    text = ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "ISSUE-238" in text
    assert "ISSUE-245" in text
    assert "SKIP_DB_MIGRATE" in text
    assert "SEED_PLAYBOOK_RELEASE" in text


def test_makefile_demo_sets_playbook_required() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "PLAYBOOK_REQUIRED=" in text
    assert "DEMO_PLAYBOOK_REQUIRED" in text
    assert "load_playbook_release" in text


def test_bootstrap_always_loads_playbook_release() -> None:
    text = BOOTSTRAP_PATH.read_text(encoding="utf-8")
    assert "load_playbook_release" in text
    assert "playbook_resources" in text
    assert "ensuring playbook release is active" in text
    # Optional LOAD_KB path must not be the only playbook loader.
    assert "for loader in load_attack_kb load_case_kb load_org_context_kb; do" in text
    assert "load_playbook_kb" not in text


def test_smoke_bootstrap_checks_playbook_ready() -> None:
    text = SMOKE_PATH.read_text(encoding="utf-8")
    assert "playbook_resources" in text
    assert "status" in text
    assert "ready" in text
    assert "smoke_event_terminal.py" in text
    assert "SMOKE_TERMINAL_MODE" in text


def test_worker_overlay_pins_backend_task_mode_celery() -> None:
    data = yaml.safe_load(WORKER_COMPOSE_PATH.read_text(encoding="utf-8"))
    env = ((data.get("services") or {}).get("backend") or {}).get("environment") or {}
    assert env.get("TASK_MODE") == "celery"


def test_makefile_up_applies_worker_overlay_when_worker_enabled() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "WORKER_COMPOSE_FILE" in text
    assert "docker-compose.worker.yml" in text
    up_recipe = text[text.index("\nup:") : text.index("\ndown:")]
    assert "WORKER_COMPOSE" in up_recipe
    demo_block = text[text.index("COMPOSE_DEMO") : text.index("WORKER ?=")]
    assert "WORKER_COMPOSE_FILE" in demo_block
