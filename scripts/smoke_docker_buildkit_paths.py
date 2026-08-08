#!/usr/bin/env python3
"""BuildKit workspace-path compatibility smoke (ISSUE-286).

Exercises docker build from ASCII and non-ASCII checkout paths with BuildKit
enabled (never disables BuildKit). Emits a JSON artifact for the platform
matrix and exits non-zero only when the ASCII control path fails.

Usage::

    python scripts/smoke_docker_buildkit_paths.py
    python scripts/smoke_docker_buildkit_paths.py --write-artifact reports/buildkit-smoke.json

Requires: docker CLI, readable repo checkout.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT = REPO_ROOT / "reports" / "platform-matrix" / "buildkit-path-smoke.json"
SMOKE_IMAGE = "shadowtrace-buildkit-smoke:issue-286"
NON_ASCII_SEGMENT = "副本"


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    cwd: str
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class BuildAttempt:
    label: str
    workspace_path: str
    path_is_ascii: bool
    result: CommandResult
    success: bool
    notes: str


def _run(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> CommandResult:
    started = time.monotonic()
    proc = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    return CommandResult(
        argv=argv,
        cwd=str(cwd),
        exit_code=proc.returncode,
        duration_ms=duration_ms,
        stdout=proc.stdout[-8000:],
        stderr=proc.stderr[-8000:],
    )


def _docker_version(component: str) -> str:
    proc = subprocess.run(
        ["docker", component, "version", "--format", "{{.Server.Version}}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return proc.stderr.strip() or "unknown"
    return proc.stdout.strip() or "unknown"


def _path_is_ascii(value: str) -> bool:
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return True


def _prepare_frontend_context(target: Path) -> None:
    src = REPO_ROOT / "frontend"
    ignore = shutil.ignore_patterns("node_modules", "dist", "e2e/test-results", "playwright-report")
    shutil.copytree(src, target / "frontend", ignore=ignore, dirs_exist_ok=True)


def _attempt_build(label: str, workspace: Path) -> BuildAttempt:
    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"
    env["COMPOSE_DOCKER_CLI_BUILD"] = "1"
    frontend_dir = workspace / "frontend"
    result = _run(
        [
            "docker",
            "build",
            "--progress=plain",
            "-t",
            SMOKE_IMAGE,
            "-f",
            "Dockerfile",
            ".",
        ],
        cwd=frontend_dir,
        env=env,
    )
    notes = ""
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if "non-printable ascii" in combined or "invalid header" in combined:
        notes = "buildkit_non_ascii_header"
    success = result.exit_code == 0
    return BuildAttempt(
        label=label,
        workspace_path=str(workspace),
        path_is_ascii=_path_is_ascii(str(workspace)),
        result=result,
        success=success,
        notes=notes,
    )


def run_smoke() -> dict:
    if shutil.which("docker") is None:
        raise RuntimeError("docker CLI not found; cannot run BuildKit path smoke")

    ascii_attempt = _attempt_build("ascii-control", REPO_ROOT)

    non_ascii_root = Path(tempfile.mkdtemp(prefix=f"shadowtrace-{NON_ASCII_SEGMENT}-"))
    _prepare_frontend_context(non_ascii_root)
    non_ascii_attempt = _attempt_build("non-ascii-checkout", non_ascii_root)

    return {
        "issue": "ISSUE-286",
        "collectedAt": datetime.now(tz=UTC).isoformat(),
        "repoRoot": str(REPO_ROOT),
        "repoRootIsAscii": _path_is_ascii(str(REPO_ROOT)),
        "docker": {
            "serverVersion": _docker_version(""),
            "buildxVersion": _docker_version("buildx"),
            "buildkitEnabled": True,
        },
        "attempts": [asdict(ascii_attempt) for ascii_attempt in (ascii_attempt, non_ascii_attempt)],
        "verdict": {
            "asciiControlPassed": ascii_attempt.success,
            "nonAsciiSupported": non_ascii_attempt.success,
            "nonAsciiFailureReason": non_ascii_attempt.notes or None,
            "status": (
                "supported"
                if non_ascii_attempt.success
                else ("suspected_upstream_limit" if ascii_attempt.success else "ascii_control_failed")
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-artifact",
        type=Path,
        default=DEFAULT_ARTIFACT,
        help=f"Write JSON report (default: {DEFAULT_ARTIFACT})",
    )
    args = parser.parse_args()

    report = run_smoke()
    args.write_artifact.parent.mkdir(parents=True, exist_ok=True)
    args.write_artifact.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"[buildkit-smoke] artifact: {args.write_artifact}", file=sys.stderr)

    if not report["verdict"]["asciiControlPassed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
