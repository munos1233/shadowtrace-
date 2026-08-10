"""Docker build context guards (ISSUE-278, ISSUE-294, ISSUE-297)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_DOCKERIGNORE = REPO_ROOT / ".dockerignore"
FRONTEND_DOCKERIGNORE = REPO_ROOT / "frontend" / ".dockerignore"
BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
COMPOSE_PATH = REPO_ROOT / "infra" / "docker-compose.yml"
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check_docker_build_context.py"

_BACKEND_SERVICES = frozenset(
    {"mock-xdr", "backend", "worker", "scheduler-beat", "scheduler-worker"}
)


def _load_check_module():
    spec = importlib.util.spec_from_file_location("check_docker_build_context", CHECK_SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # dataclasses looks up cls.__module__ in sys.modules during decoration.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_root_and_frontend_dockerignore_exist() -> None:
    assert ROOT_DOCKERIGNORE.is_file(), (
        "repo root must ship .dockerignore for backend build context"
    )
    assert FRONTEND_DOCKERIGNORE.is_file(), "frontend must ship .dockerignore for SPA build context"


def test_backend_dockerfile_does_not_copy_full_backend_tree() -> None:
    text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY backend/ ./backend/" not in text, (
        "backend/Dockerfile must not COPY the entire backend/ tree (tests/.venv leak)"
    )
    assert "COPY backend/scripts ./backend/scripts" in text
    assert "ISSUE-278" in text


def test_backend_dockerfile_copies_contracts_to_runtime() -> None:
    text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY --from=builder /contracts /contracts" in text, (
        "runtime stage must ship /contracts for Socket.IO schema resolution (ISSUE-297)"
    )
    chown_pos = text.index("chown -R shadowtrace:shadowtrace")
    assert "/contracts" in text[chown_pos : chown_pos + 80], (
        "shadowtrace user must own /contracts for non-root schema reads"
    )


def test_compose_backend_services_share_root_context() -> None:
    data = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    for name in sorted(_BACKEND_SERVICES):
        build = (services.get(name) or {}).get("build") or {}
        assert build.get("dockerfile") == "backend/Dockerfile", (
            f"{name} must use backend/Dockerfile"
        )
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


def test_matcher_excludes_worktrees_venv_variants_and_root_caches() -> None:
    mod = _load_check_module()
    matcher = mod.DockerignoreMatcher.from_file(ROOT_DOCKERIGNORE)
    for rel in (
        ".worktrees/probe/blob",
        "artifacts/out.bin",
        "backend/.venv/lib/python/site.py",
        "backend/.venv-review/lib/x",
        ".mypy_cache/3.11/foo.data",
        ".pnpm-store/v3/files/ab",
        "backend/tests/test_x.py",
        ".env.issue278-probe",
    ):
        assert matcher.excludes_path_or_ancestor(rel), f"expected exclude: {rel}"


def test_matcher_keeps_runtime_copy_sources() -> None:
    mod = _load_check_module()
    matcher = mod.DockerignoreMatcher.from_file(ROOT_DOCKERIGNORE)
    for rel in (
        "backend/app/main.py",
        "backend/scripts/load_playbook_release.py",
        "backend/uv.lock",
        "backend/pyproject.toml",
        "contracts/schemas/foo.json",
        "data/playbooks/x.yaml",
        "scripts/check_docker_build_context.py",
    ):
        assert not matcher.excludes_path_or_ancestor(rel), f"must keep in context: {rel}"


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
    assert "dirty-seed OK" in proc.stdout


def test_frontend_context_within_limit() -> None:
    proc = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--context", "frontend"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_frontend_seed_dirty_excludes_local_markers() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(CHECK_SCRIPT),
            "--context",
            "frontend",
            "--seed-dirty",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "dirty-seed OK" in proc.stdout
    # Must not create repo-layout markers under frontend/
    assert not (REPO_ROOT / "frontend" / "backend" / ".venv").exists()
    assert not (REPO_ROOT / "frontend" / "frontend" / "node_modules").exists()


def test_context_fails_when_over_max_bytes() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(CHECK_SCRIPT),
            "--context",
            "backend-root",
            "--max-context-bytes",
            "1",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "exceeds limit" in (proc.stderr or proc.stdout)


def test_canonical_compose_image_ref_matches_compose_default_tag() -> None:
    mod = _load_check_module()
    assert mod.canonical_compose_image_ref("shadowtrace-ci-42-1", "backend") == (
        "shadowtrace-ci-42-1-backend"
    )


def test_resolve_compose_service_image_prefers_label_query() -> None:
    mod = _load_check_module()
    with (
        mock.patch.object(mod, "shutil_which", return_value="/usr/bin/docker"),
        mock.patch.object(
            mod,
            "_resolve_by_compose_labels",
            return_value="sha256:from-labels",
        ) as labels,
        mock.patch.object(mod, "_image_id_from_ref") as canonical,
        mock.patch.object(mod, "_resolve_by_compose_images") as compose_images,
    ):
        image_id = mod.resolve_compose_service_image(
            project_name="shadowtrace-ci-99-1",
            service="backend",
        )
    assert image_id == "sha256:from-labels"
    labels.assert_called_once_with("shadowtrace-ci-99-1", "backend")
    canonical.assert_not_called()
    compose_images.assert_not_called()


def test_resolve_compose_service_image_falls_back_to_canonical_ref() -> None:
    mod = _load_check_module()
    with (
        mock.patch.object(mod, "shutil_which", return_value="/usr/bin/docker"),
        mock.patch.object(mod, "_resolve_by_compose_labels", return_value=None),
        mock.patch.object(mod, "_image_id_from_ref", return_value="sha256:from-ref") as canonical,
        mock.patch.object(mod, "_resolve_by_compose_images", return_value=None),
    ):
        image_id = mod.resolve_compose_service_image(
            project_name="shadowtrace-ci-99-1",
            service="backend",
        )
    assert image_id == "sha256:from-ref"
    canonical.assert_called_once_with("shadowtrace-ci-99-1-backend")


def test_resolve_compose_service_image_prints_diagnostics_on_miss() -> None:
    mod = _load_check_module()
    with (
        mock.patch.object(mod, "shutil_which", return_value="/usr/bin/docker"),
        mock.patch.object(mod, "_resolve_by_compose_labels", return_value=None),
        mock.patch.object(mod, "_image_id_from_ref", return_value=None),
        mock.patch.object(mod, "_resolve_by_compose_images", return_value=None),
        mock.patch.object(mod, "print_compose_image_diagnostics") as diagnostics,
    ):
        with pytest.raises(SystemExit) as exc:
            mod.resolve_compose_service_image(
                project_name="shadowtrace-ci-99-1",
                service="backend",
            )
    assert exc.value.code == 1
    diagnostics.assert_called_once()


def test_resolve_compose_service_image_falls_back_to_compose_images() -> None:
    mod = _load_check_module()
    with (
        mock.patch.object(mod, "shutil_which", return_value="/usr/bin/docker"),
        mock.patch.object(mod, "_resolve_by_compose_labels", return_value=None),
        mock.patch.object(mod, "_image_id_from_ref", return_value=None),
        mock.patch.object(
            mod,
            "_resolve_by_compose_images",
            return_value="sha256:from-compose-images",
        ) as compose_images,
    ):
        image_id = mod.resolve_compose_service_image(
            project_name="shadowtrace-ci-99-1",
            service="backend",
        )
    assert image_id == "sha256:from-compose-images"
    compose_images.assert_called_once_with("shadowtrace-ci-99-1", "backend", None)


def test_resolve_compose_service_image_exits_when_docker_missing() -> None:
    mod = _load_check_module()
    with mock.patch.object(mod, "shutil_which", return_value=None):
        with pytest.raises(SystemExit) as exc:
            mod.resolve_compose_service_image(
                project_name="shadowtrace-ci-99-1",
                service="backend",
            )
    assert exc.value.code == 1


def test_resolve_by_compose_labels_prefers_newest_when_multiple() -> None:
    mod = _load_check_module()

    def docker_cmd_side_effect(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        if args[:3] == ("image", "ls", "-q"):
            return subprocess.CompletedProcess(
                args=["docker", *args],
                returncode=0,
                stdout="sha256:older\nsha256:newer\n",
                stderr="",
            )
        if args[:3] == ("image", "inspect", "--format") and args[3] == "{{.Created}}":
            ref = args[4]
            created = "2024-01-01T00:00:00Z" if ref == "sha256:older" else "2024-06-01T00:00:00Z"
            return subprocess.CompletedProcess(
                args=["docker", *args],
                returncode=0,
                stdout=f"{created}\n",
                stderr="",
            )
        raise AssertionError(f"unexpected _docker_cmd call: {args}")

    with mock.patch.object(mod, "_docker_cmd", side_effect=docker_cmd_side_effect):
        image_id = mod._resolve_by_compose_labels("shadowtrace-ci-99-1", "backend")
    assert image_id == "sha256:newer"


def test_ci_docker_build_resolves_then_inspects_backend_image() -> None:
    ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    makefile_text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    step_marker = "      - name: Build and validate stack"
    step_start = ci_text.index(step_marker)
    step_run = ci_text.index("        run: |", step_start)
    next_step = ci_text.find("\n      - ", step_run + 1)
    step_body = ci_text[step_run : next_step if next_step != -1 else len(ci_text)]

    assert "compose build" in step_body
    assert "--resolve-compose-image backend" in step_body
    assert '--inspect-image "${backend_image}"' in step_body
    assert '--project-name "${COMPOSE_PROJECT_NAME}"' in step_body
    build_pos = step_body.index("compose build")
    resolve_pos = step_body.index("--resolve-compose-image backend")
    inspect_pos = step_body.index('--inspect-image "${backend_image}"')
    assert build_pos < resolve_pos < inspect_pos

    ci_build_start = makefile_text.index("ci-build:")
    ci_build_body = makefile_text[ci_build_start:]
    assert "--resolve-compose-image backend" in ci_build_body
    assert "compose images -q backend" not in ci_build_body


def test_seed_dirty_fails_when_ignore_empty(tmp_path: Path) -> None:
    mod = _load_check_module()
    dockerignore = tmp_path / ".dockerignore"
    dockerignore.write_text("# empty ignore on purpose\n", encoding="utf-8")
    # Minimal tree so measure is small but seed adds 2MiB markers.
    (tmp_path / "keep.txt").write_text("ok\n", encoding="utf-8")
    profile = mod.ContextProfile(
        name="backend-root",
        root=tmp_path,
        dockerignore=dockerignore,
        max_bytes=80 * 1024 * 1024,
    )
    assert mod.check_context(profile, seed_dirty=True) == 1


def test_inspect_backend_image_runs_socketio_schema_probe() -> None:
    mod = _load_check_module()
    with (
        mock.patch.object(mod, "shutil_which", return_value="/usr/bin/docker"),
        mock.patch.object(
            mod,
            "probe_socketio_schema_in_image",
            return_value=0,
        ) as schema_probe,
        mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker", "image", "inspect"],
                returncode=0,
                stdout="1000\n",
                stderr="",
            ),
        ),
    ):
        assert mod.inspect_backend_image("sha256:test", max_bytes=1024 * 1024) == 0
    schema_probe.assert_called_once_with("sha256:test")


def test_probe_socketio_schema_in_image_fails_when_unreadable() -> None:
    mod = _load_check_module()
    with (
        mock.patch.object(mod, "shutil_which", return_value="/usr/bin/docker"),
        mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker", "run"],
                returncode=1,
                stdout="",
                stderr="missing",
            ),
        ),
    ):
        assert mod.probe_socketio_schema_in_image("sha256:missing-schema") == 1
