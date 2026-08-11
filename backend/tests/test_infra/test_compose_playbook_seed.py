"""Compose/entrypoint playbook seed wiring guards (ISSUE-245 / #820)."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.yml"
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
    assert "for loader in load_attack_kb load_case_kb; do" in text
    assert "load_playbook_kb" not in text


def test_smoke_bootstrap_checks_playbook_ready() -> None:
    text = SMOKE_PATH.read_text(encoding="utf-8")
    assert "playbook_resources" in text
    assert "status" in text
    assert "ready" in text
    assert "smoke_event_terminal.py" in text
    assert "SMOKE_TERMINAL_MODE" in text
