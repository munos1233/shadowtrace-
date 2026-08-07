"""Compose migration single-flight: only backend runs alembic (ISSUE-238)."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.yml"
ENTRYPOINT_PATH = REPO_ROOT / "backend" / "docker-entrypoint.sh"

# Services that share the backend image ENTRYPOINT but must not race migrate.
NON_MIGRATOR_SERVICES = ("mock-xdr", "worker", "scheduler-beat", "scheduler-worker")


def test_compose_non_migrators_skip_db_migrate() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}

    backend = services.get("backend")
    assert backend is not None, "missing service backend"
    backend_env = backend.get("environment") or {}
    assert backend_env.get("SKIP_DB_MIGRATE") in (None, "", "false"), (
        "backend must remain the Compose migration owner "
        "(do not set SKIP_DB_MIGRATE=true on backend)"
    )

    for name in NON_MIGRATOR_SERVICES:
        service = services.get(name)
        assert service is not None, f"missing service {name}"
        env = service.get("environment") or {}
        assert env.get("SKIP_DB_MIGRATE") == "true", (
            f"{name} must set SKIP_DB_MIGRATE=true so parallel up cannot "
            "race-create alembic_version"
        )


def test_compose_workers_wait_for_backend_healthy() -> None:
    """Workers skip migrate; they must wait for backend (schema ready)."""
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}

    for name in ("worker", "scheduler-beat", "scheduler-worker"):
        service = services.get(name)
        assert service is not None, f"missing service {name}"
        depends_on = service.get("depends_on") or {}
        assert isinstance(depends_on, dict), (
            f"{name}.depends_on must use long syntax with conditions"
        )
        backend_dep = depends_on.get("backend")
        assert isinstance(backend_dep, dict), f"{name} must depend on backend"
        assert backend_dep.get("condition") == "service_healthy", (
            f"{name} must wait for backend healthy (migrations applied)"
        )


def test_entrypoint_honors_skip_db_migrate() -> None:
    text = ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "SKIP_DB_MIGRATE" in text
    assert "alembic upgrade head" in text
    # Fail closed when migrating: no "|| true" / soft-continue after alembic.
    assert "alembic upgrade head ||" not in text
    assert "set -eu" in text
