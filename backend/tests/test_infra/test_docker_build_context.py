"""Docker build context guards (ISSUE-278)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_DOCKERIGNORE = REPO_ROOT / ".dockerignore"
FRONTEND_DOCKERIGNORE = REPO_ROOT / "frontend" / ".dockerignore"
BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.yml"
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check_docker_build_context.py"

_BACKEND_SERVICES = frozenset({"mock-xdr", "backend", "worker", "scheduler-beat", "scheduler-worker"})


def test_root_and_frontend_dockerignore_exist() -> None:
    assert ROOT_DOCKERIGNORE.is_file(), "repo root must ship .dockerignore for backend build context"
    assert FRONTEND_DOCKERIGNORE.is_file(), "frontend must ship .dockerignore for SPA build context"


def test_backend_dockerfile_does_not_copy_full_backend_tree() -> None:
    text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY backend/ ./backend/" not in text, (
        "backend/Dockerfile must not COPY the entire backend/ tree (tests/.venv leak)"
    )
    assert "COPY backend/scripts ./backend/scripts" in text
    assert "ISSUE-278" in text


def test_compose_backend_services_share_root_context() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    for name in sorted(_BACKEND_SERVICES):
        build = (services.get(name) or {}).get("build") or {}
        assert build.get("dockerfile") == "backend/Dockerfile", f"{name} must use backend/Dockerfile"
        assert build.get("context") == "..", (
            f"{name} must use repo-root context (shared, .dockerignore-filtered)"
        )


def test_compose_frontend_uses_frontend_context() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    build = ((data.get("services") or {}).get("frontend") or {}).get("build") or {}
    assert build.get("context") == "../frontend"
    assert build.get("dockerfile") == "Dockerfile"


def test_dockerignore_validation_script_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--validate-dockerignore"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_backend_root_context_within_limit_clean_workspace() -> None:
    proc = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--context", "backend-root"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_backend_root_context_excludes_dirty_workspace_blobs() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(CHECK_SCRIPT),
            "--context",
            "backend-root",
            "--seed-dirty",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_frontend_context_within_limit() -> None:
    proc = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--context", "frontend"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
