#!/usr/bin/env python3
"""Docker build context / runtime image guards (ISSUE-278).

Measures effective build context size (honouring .dockerignore) and optionally
validates a built backend image does not ship host-only trees or secrets.

Usage (CI / local)::

    python scripts/check_docker_build_context.py --context backend-root
    python scripts/check_docker_build_context.py --context frontend --root frontend
    python scripts/check_docker_build_context.py --inspect-image shadowtrace-backend:ci

Exit 0 when within limits; non-zero on violation.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Conservative ceilings — dirty workspaces with installed deps must stay well
# below the ~929MB classic-builder context observed in ID-DEMO-001.
DEFAULT_MAX_CONTEXT_BYTES = 80 * 1024 * 1024  # 80 MiB
DEFAULT_MAX_BACKEND_IMAGE_BYTES = 900 * 1024 * 1024  # 900 MiB compressed export

# Runtime paths that must never appear in backend production images.
FORBIDDEN_BACKEND_IMAGE_PATHS = (
    "/app/backend/tests",
    "/app/backend/.venv",
    "/app/.venv/host-marker",
    "/app/.env",
    "/app/frontend",
    "/app/node_modules",
)


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
    """Minimal dockerignore matcher (same semantics as Docker for our patterns)."""

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

    @staticmethod
    def _match(pattern: str, rel_posix: str) -> bool:
        if pattern.endswith("/"):
            pattern = pattern.rstrip("/")
            if rel_posix == pattern or rel_posix.startswith(pattern + "/"):
                return True
        if "/" not in pattern:
            parts = rel_posix.split("/")
            return any(fnmatch.fnmatch(part, pattern) for part in parts) or fnmatch.fnmatch(
                rel_posix, pattern
            )
        return fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(
            Path(rel_posix).as_posix(), pattern
        )


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


def seed_dirty_workspace(root: Path) -> list[Path]:
    """Create obvious host-only trees to prove .dockerignore excludes them."""
    markers: list[Path] = []
    specs = (
        root / "backend" / ".venv" / "host-marker",
        root / "frontend" / "node_modules" / "host-marker",
        root / "backend" / "tests" / ".host-only",
    )
    for path in specs:
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
        for _ in range(4):
            if not parent.exists():
                break
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent


def check_context(profile: ContextProfile, *, seed_dirty: bool) -> int:
    markers: list[Path] = []
    if seed_dirty:
        markers = seed_dirty_workspace(profile.root)
    try:
        size = measure_context(profile)
    finally:
        if markers:
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
        "**/node_modules",
        "backend/tests/",
        ".env",
    )
    frontend_required = (
        "node_modules/",
        "dist/",
        "tests/",
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
        help="Create synthetic .venv/node_modules/tests blobs before measuring.",
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

    if not args.context:
        parser.error("one of --context, --validate-dockerignore, or --inspect-image is required")

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
