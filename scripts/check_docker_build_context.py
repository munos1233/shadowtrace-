#!/usr/bin/env python3
"""Docker build context / runtime image guards (ISSUE-278, ISSUE-294, ISSUE-297).

Measures effective build context size (honouring .dockerignore) and optionally
validates a built backend image does not ship host-only trees or secrets.

Usage (CI / local)::

    python scripts/check_docker_build_context.py --context backend-root
    python scripts/check_docker_build_context.py --context frontend --root frontend
    python scripts/check_docker_build_context.py --inspect-image shadowtrace-backend:ci
    python scripts/check_docker_build_context.py --resolve-compose-image backend \\
        --project-name shadowtrace-ci-repro

Exit 0 when within limits; non-zero on violation.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[1]

# Conservative ceilings — dirty workspaces with installed deps must stay well
# below the ~929MB classic-builder context observed in ID-DEMO-001.
DEFAULT_MAX_CONTEXT_BYTES = 80 * 1024 * 1024  # 80 MiB
DEFAULT_MAX_BACKEND_IMAGE_BYTES = 900 * 1024 * 1024  # 900 MiB (docker image inspect Size)

# Runtime paths that must never appear in backend production images.
FORBIDDEN_BACKEND_IMAGE_PATHS = (
    "/app/backend/tests",
    "/app/backend/.venv",
    "/app/backend/.venv-review",
    "/app/.worktrees",
    "/app/artifacts",
    "/app/.env",
    "/app/frontend",
    "/app/node_modules",
)

SOCKETIO_SCHEMA_IMAGE_PATH = "/contracts/socketio/events.schema.json"

# Exercises the same import path and jsonschema gate used by SocketIOManager._dispatch.
_SOCKETIO_SCHEMA_SMOKE_PY = """
import jsonschema
from app.core.socketio_manager import _events_schema

schema = _events_schema()
envelope = {
    "type": "state_change",
    "event_id": "evt-20260101-00000001",
    "sequence": 1,
    "timestamp": "2026-01-01T00:00:00+00:00",
    "payload": {
        "from_status": "NEW",
        "to_status": "TRIAGED",
        "operator": "system",
    },
}
jsonschema.validate(instance=envelope, schema=schema)
print("socketio-schema-smoke OK")
""".strip()


@dataclass(frozen=True)
class ContextProfile:
    name: str
    root: Path
    dockerignore: Path
    max_bytes: int


CONTEXT_PROFILES: dict[str, ContextProfile] = {
    "backend-root": ContextProfile(
        name="backend-root",
        root=REPO_ROOT,
        dockerignore=REPO_ROOT / ".dockerignore",
        max_bytes=DEFAULT_MAX_CONTEXT_BYTES,
    ),
    "frontend": ContextProfile(
        name="frontend",
        root=REPO_ROOT / "frontend",
        dockerignore=REPO_ROOT / "frontend" / ".dockerignore",
        max_bytes=30 * 1024 * 1024,  # 30 MiB — sources + lockfile only
    ),
}


class DockerignoreMatcher:
    """Docker-like dockerignore matcher (gitwildmatch-ish ``**`` semantics)."""

    def __init__(self, patterns: list[str]) -> None:
        self._patterns = [p.strip() for p in patterns if p.strip() and not p.strip().startswith("#")]

    @classmethod
    def from_file(cls, path: Path) -> DockerignoreMatcher:
        if not path.is_file():
            return cls([])
        lines = path.read_text(encoding="utf-8").splitlines()
        return cls(lines)

    def excludes(self, rel_posix: str) -> bool:
        if rel_posix == ".dockerignore":
            return False
        matched = False
        for raw in self._patterns:
            negate = raw.startswith("!")
            pattern = raw[1:] if negate else raw
            if self._match(pattern, rel_posix):
                matched = not negate
        return matched

    def excludes_path_or_ancestor(self, rel_posix: str) -> bool:
        """True if path or any ancestor directory is excluded (walk would prune)."""
        if self.excludes(rel_posix):
            return True
        parts = rel_posix.split("/")
        for i in range(1, len(parts)):
            if self.excludes("/".join(parts[:i])):
                return True
        return False

    @staticmethod
    def _match(pattern: str, rel_posix: str) -> bool:
        dir_only = pattern.endswith("/")
        if dir_only:
            pattern = pattern.rstrip("/")
        if not pattern:
            return False

        if DockerignoreMatcher._glob_match(pattern, rel_posix):
            return True

        # Directory patterns also exclude everything underneath.
        if dir_only or "/" in pattern or "**" in pattern:
            if rel_posix.startswith(pattern.rstrip("*") + "/") and "*" not in pattern and "?" not in pattern:
                return True
            # Prefix directory: pattern matches an ancestor of rel_posix.
            parts = rel_posix.split("/")
            for i in range(1, len(parts)):
                ancestor = "/".join(parts[:i])
                if DockerignoreMatcher._glob_match(pattern, ancestor):
                    return True

        # No-slash patterns match any path segment (Docker).
        if "/" not in pattern and "**" not in pattern:
            parts = rel_posix.split("/")
            if any(fnmatch.fnmatch(part, pattern) for part in parts):
                return True

        return False

    @staticmethod
    def _glob_match(pattern: str, path: str) -> bool:
        """Match path against a dockerignore glob (``**`` crosses directories)."""
        if "**" not in pattern:
            return fnmatch.fnmatch(path, pattern)

        regex_parts: list[str] = ["^"]
        i = 0
        while i < len(pattern):
            if pattern.startswith("**/", i):
                regex_parts.append("(?:.*/)?")
                i += 3
            elif pattern.startswith("**", i):
                regex_parts.append(".*")
                i += 2
            elif pattern[i] == "*":
                regex_parts.append("[^/]*")
                i += 1
            elif pattern[i] == "?":
                regex_parts.append("[^/]")
                i += 1
            else:
                regex_parts.append(re.escape(pattern[i]))
                i += 1
        regex_parts.append("$")
        return re.search("".join(regex_parts), path) is not None


def _human_size(num_bytes: int) -> str:
    units = ("B", "KiB", "MiB", "GiB")
    value = float(num_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{num_bytes} B"


def measure_context(profile: ContextProfile) -> int:
    matcher = DockerignoreMatcher.from_file(profile.dockerignore)
    total = 0
    for dirpath, dirnames, filenames in os.walk(profile.root):
        rel_dir = Path(dirpath).relative_to(profile.root).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        kept: list[str] = []
        for name in dirnames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if not matcher.excludes(rel):
                kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if matcher.excludes(rel):
                continue
            total += (profile.root / rel).stat().st_size
    return total


def dirty_marker_specs(profile: ContextProfile) -> tuple[Path, ...]:
    """Host-only markers relative to the profile context root.

    Markers use synthetic trees (never write into a live ``.venv`` / store install)
    whose relative paths still match the ignore patterns under test.
    """
    root = profile.root
    if profile.name == "frontend":
        return (
            root / "node_modules" / "issue278-host-marker",
            root / "dist" / "issue278-host-marker",
            root / ".env.issue278-probe",
            root / ".worktrees" / "probe" / "issue278-host-marker",
        )
    seed = root / "_issue278_seed"
    return (
        seed / ".venv" / "issue278-host-marker",
        seed / ".venv-review" / "issue278-host-marker",
        seed / ".mypy_cache" / "issue278-host-marker",
        seed / ".pnpm-store" / "issue278-host-marker",
        root / "frontend" / ".issue278-host-marker",
        root / "backend" / "tests" / ".issue278-host-only",
        root / ".worktrees" / "probe" / "issue278-host-marker",
        root / "artifacts" / "issue278-host-marker",
        root / ".env.issue278-probe",
    )


def seed_dirty_workspace(profile: ContextProfile) -> list[Path]:
    """Create obvious host-only trees to prove .dockerignore excludes them."""
    markers: list[Path] = []
    for path in dirty_marker_specs(profile):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ISSUE-278 dirty-workspace probe\n", encoding="utf-8")
        with path.open("ab") as fh:
            fh.write(b"\0" * (2 * 1024 * 1024))
        markers.append(path)
    return markers


def cleanup_markers(markers: list[Path]) -> None:
    for path in markers:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        parent = path.parent
        for _ in range(6):
            if not parent.exists():
                break
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent


def check_context(profile: ContextProfile, *, seed_dirty: bool) -> int:
    baseline = measure_context(profile)
    markers: list[Path] = []
    size = baseline

    if seed_dirty:
        markers = seed_dirty_workspace(profile)
        try:
            matcher = DockerignoreMatcher.from_file(profile.dockerignore)
            leaked: list[str] = []
            for marker in markers:
                rel = marker.relative_to(profile.root).as_posix()
                if not matcher.excludes_path_or_ancestor(rel):
                    leaked.append(rel)
            dirty_size = measure_context(profile)
            delta = dirty_size - baseline
            if leaked:
                print(
                    f"ERROR: {profile.name} dirty markers not excluded by .dockerignore: "
                    f"{', '.join(leaked)}",
                    file=sys.stderr,
                )
                return 1
            if delta != 0:
                print(
                    f"ERROR: {profile.name} dirty seed changed measured context by "
                    f"{_human_size(delta)} (baseline {_human_size(baseline)} → "
                    f"{_human_size(dirty_size)}); markers must be fully ignored",
                    file=sys.stderr,
                )
                return 1
            print(
                f"[{profile.name}] dirty-seed OK: {len(markers)} markers excluded; "
                f"context unchanged at {_human_size(baseline)}"
            )
            size = baseline
        finally:
            cleanup_markers(markers)

    print(
        f"[{profile.name}] effective context size: {_human_size(size)} "
        f"(limit {_human_size(profile.max_bytes)})"
    )
    if size > profile.max_bytes:
        print(
            f"ERROR: {profile.name} context exceeds limit "
            f"({_human_size(size)} > {_human_size(profile.max_bytes)})",
            file=sys.stderr,
        )
        return 1
    return 0


def shutil_which(cmd: str) -> str | None:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(path) / cmd
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def canonical_compose_image_ref(project_name: str, service: str) -> str:
    """Default local tag Compose assigns after ``docker compose build``."""
    return f"{project_name}-{service}"


def _docker_cmd(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        check=check,
    )


def _compose_cmd(
    project_name: str,
    compose_file: Path | None,
    *args: str,
) -> subprocess.CompletedProcess[str]:
    cmd = ["docker", "compose", "--project-name", project_name]
    if compose_file is not None:
        cmd.extend(["-f", str(compose_file)])
    cmd.extend(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _image_id_from_ref(image_ref: str) -> str | None:
    proc = _docker_cmd("image", "inspect", "--format", "{{.Id}}", image_ref)
    if proc.returncode != 0:
        return None
    image_id = proc.stdout.strip()
    return image_id or None


def _resolve_by_compose_labels(project_name: str, service: str) -> str | None:
    proc = _docker_cmd(
        "image",
        "ls",
        "-q",
        "--filter",
        f"label=com.docker.compose.project={project_name}",
        "--filter",
        f"label=com.docker.compose.service={service}",
    )
    if proc.returncode != 0:
        return None
    candidates = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    # Prefer the newest image when multiple tags/refs match the same service.
    newest = candidates[0]
    newest_created = ""
    for ref in candidates:
        created_proc = _docker_cmd("image", "inspect", "--format", "{{.Created}}", ref)
        if created_proc.returncode != 0:
            continue
        created = created_proc.stdout.strip()
        if created >= newest_created:
            newest_created = created
            newest = ref
    return newest


def _resolve_by_compose_images(
    project_name: str,
    service: str,
    compose_file: Path | None,
) -> str | None:
    proc = _compose_cmd(project_name, compose_file, "images", "-q", service)
    if proc.returncode != 0:
        return None
    image_id = proc.stdout.strip()
    return image_id or None


def print_compose_image_diagnostics(
    *,
    project_name: str,
    service: str,
    compose_file: Path | None,
) -> None:
    compose_path = compose_file if compose_file is not None else REPO_ROOT / "infra" / "docker-compose.yml"
    print(f"--- compose {service} image diagnostics (ISSUE-294) ---", file=sys.stderr)
    print(f"project_name={project_name}", file=sys.stderr)
    print(f"service={service}", file=sys.stderr)
    print(f"compose_file={compose_path}", file=sys.stderr)
    print(f"canonical_ref={canonical_compose_image_ref(project_name, service)}", file=sys.stderr)

    for label, cmd in (
        ("compose images", _compose_cmd(project_name, compose_file, "images")),
        ("compose ps -a", _compose_cmd(project_name, compose_file, "ps", "-a")),
        ("docker images (head)", _docker_cmd("images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}")),
    ):
        print(f"[{label}]", file=sys.stderr)
        output = (cmd.stdout or cmd.stderr or "").strip()
        if not output:
            print("(empty)", file=sys.stderr)
            continue
        lines = output.splitlines()
        limit = 20 if label.startswith("docker images") else len(lines)
        for line in lines[:limit]:
            print(line, file=sys.stderr)
        if len(lines) > limit:
            print(f"... ({len(lines) - limit} more lines)", file=sys.stderr)


def resolve_compose_service_image(
    *,
    project_name: str,
    service: str,
    compose_file: Path | None = None,
) -> str:
    """Resolve a built Compose service image id (works after ``compose build`` only).

    ``docker compose images`` lists images attached to *created containers*; after
    ``compose build`` with no ``up`` it is often empty even though the image exists.
    """
    if not shutil_which("docker"):
        print("ERROR: docker not available — cannot resolve compose service image", file=sys.stderr)
        raise SystemExit(1)

    strategies: tuple[tuple[str, Callable[[], str | None]], ...] = (
        ("compose-labels", lambda: _resolve_by_compose_labels(project_name, service)),
        (
            "canonical-ref",
            lambda: _image_id_from_ref(canonical_compose_image_ref(project_name, service)),
        ),
        (
            "compose-images",
            lambda: _resolve_by_compose_images(project_name, service, compose_file),
        ),
    )
    for name, resolver in strategies:
        image_id = resolver()
        if image_id:
            print(
                f"[compose-image] resolved via {name}: {image_id}",
                file=sys.stderr,
            )
            return image_id

    print_compose_image_diagnostics(
        project_name=project_name,
        service=service,
        compose_file=compose_file,
    )
    print(
        f"ERROR: compose service image not found for project={project_name} service={service}",
        file=sys.stderr,
    )
    raise SystemExit(1)


def probe_socketio_schema_in_image(image_ref: str) -> int:
    """Assert runtime image ships readable Socket.IO schema for the non-root user."""
    readable = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            image_ref,
            "-c",
            (
                f'test -r "{SOCKETIO_SCHEMA_IMAGE_PATH}" '
                '&& test "$(id -un)" = shadowtrace'
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if readable.returncode != 0:
        detail = (readable.stderr or readable.stdout or "").strip()
        print(
            f"ERROR: Socket.IO schema missing or unreadable for shadowtrace user "
            f"at {SOCKETIO_SCHEMA_IMAGE_PATH}"
            + (f": {detail}" if detail else ""),
            file=sys.stderr,
        )
        return 1

    smoke = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            image_ref,
            "-c",
            _SOCKETIO_SCHEMA_SMOKE_PY,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if smoke.returncode != 0:
        detail = (smoke.stderr or smoke.stdout or "").strip()
        print(
            "ERROR: Socket.IO schema smoke failed inside backend image"
            + (f": {detail}" if detail else ""),
            file=sys.stderr,
        )
        return 1
    print("[backend-image] socketio schema probe: OK")
    return 0


def inspect_backend_image(image_ref: str, *, max_bytes: int) -> int:
    if not shutil_which("docker"):
        print("WARN: docker not available — skipping image inspection", file=sys.stderr)
        return 0

    size_proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Size}}", image_ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if size_proc.returncode != 0:
        print(f"ERROR: cannot inspect image {image_ref}: {size_proc.stderr.strip()}", file=sys.stderr)
        return 1
    image_size = int(size_proc.stdout.strip())
    print(f"[backend-image] size: {_human_size(image_size)} (limit {_human_size(max_bytes)})")
    if image_size > max_bytes:
        print(
            f"ERROR: backend image exceeds limit "
            f"({_human_size(image_size)} > {_human_size(max_bytes)})",
            file=sys.stderr,
        )
        return 1

    for forbidden in FORBIDDEN_BACKEND_IMAGE_PATHS:
        probe = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "sh", image_ref, "-c", f"test ! -e {forbidden}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode != 0:
            print(f"ERROR: forbidden path present in image: {forbidden}", file=sys.stderr)
            return 1
    print("[backend-image] forbidden path probe: OK")

    schema_exit = probe_socketio_schema_in_image(image_ref)
    if schema_exit != 0:
        return schema_exit
    return 0


def _required_dockerignore_patterns(path: Path, required: tuple[str, ...]) -> list[str]:
    if not path.is_file():
        return list(required)
    text = path.read_text(encoding="utf-8")
    return [pat for pat in required if pat not in text]


def validate_dockerignore_files() -> int:
    root_required = (
        "frontend/",
        "**/.venv",
        "**/.venv*",
        "**/node_modules",
        "backend/tests/",
        ".worktrees/",
        "artifacts/",
        ".env",
    )
    frontend_required = (
        "node_modules/",
        "dist/",
        "tests/",
        "e2e/",
        ".worktrees/",
        ".env",
    )
    checks = (
        (REPO_ROOT / ".dockerignore", root_required),
        (REPO_ROOT / "frontend" / ".dockerignore", frontend_required),
    )
    exit_code = 0
    for path, required in checks:
        missing = _required_dockerignore_patterns(path, required)
        if not path.is_file():
            print(f"ERROR: missing {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            exit_code = 1
            continue
        if missing:
            print(
                f"ERROR: {path.relative_to(REPO_ROOT)} missing patterns: {', '.join(missing)}",
                file=sys.stderr,
            )
            exit_code = 1
        else:
            print(f"[dockerignore] {path.relative_to(REPO_ROOT)}: required patterns OK")
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--context",
        choices=sorted(CONTEXT_PROFILES),
        help="Measure effective build context for a profile.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        help="Override context root (must match docker-compose build context).",
    )
    parser.add_argument(
        "--max-context-bytes",
        type=int,
        default=None,
        help="Override max context bytes for --context.",
    )
    parser.add_argument(
        "--seed-dirty",
        action="store_true",
        help="Create synthetic dirty-workspace blobs and assert they do not change context size.",
    )
    parser.add_argument(
        "--validate-dockerignore",
        action="store_true",
        help="Assert required exclusion patterns exist (no measurement).",
    )
    parser.add_argument(
        "--inspect-image",
        metavar="IMAGE",
        help="Validate a built backend image ref (forbidden paths + size).",
    )
    parser.add_argument(
        "--resolve-compose-image",
        metavar="SERVICE",
        help="Resolve a built Compose service image id (for CI after compose build).",
    )
    parser.add_argument(
        "--project-name",
        help="Compose project name for --resolve-compose-image.",
    )
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=REPO_ROOT / "infra" / "docker-compose.yml",
        help="Compose file path for --resolve-compose-image diagnostics/fallback.",
    )
    parser.add_argument(
        "--max-image-bytes",
        type=int,
        default=DEFAULT_MAX_BACKEND_IMAGE_BYTES,
        help="Max backend image size for --inspect-image.",
    )
    args = parser.parse_args(argv)

    if args.validate_dockerignore:
        return validate_dockerignore_files()

    if args.inspect_image:
        return inspect_backend_image(args.inspect_image, max_bytes=args.max_image_bytes)

    if args.resolve_compose_image:
        if not args.project_name:
            parser.error("--project-name is required with --resolve-compose-image")
        image_id = resolve_compose_service_image(
            project_name=args.project_name,
            service=args.resolve_compose_image,
            compose_file=args.compose_file,
        )
        print(image_id)
        return 0

    if not args.context:
        parser.error(
            "one of --context, --validate-dockerignore, --inspect-image, "
            "or --resolve-compose-image is required"
        )

    profile = CONTEXT_PROFILES[args.context]
    max_bytes = args.max_context_bytes if args.max_context_bytes is not None else profile.max_bytes
    root = args.root.resolve() if args.root is not None else profile.root
    profile = ContextProfile(
        name=profile.name,
        root=root,
        dockerignore=profile.dockerignore,
        max_bytes=max_bytes,
    )

    if not profile.dockerignore.is_file():
        print(f"ERROR: missing {profile.dockerignore}", file=sys.stderr)
        return 1

    return check_context(profile, seed_dirty=args.seed_dirty)


if __name__ == "__main__":
    raise SystemExit(main())
