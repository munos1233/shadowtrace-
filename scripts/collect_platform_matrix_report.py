#!/usr/bin/env python3
"""Merge Playwright + BuildKit matrix artifacts into one report (ISSUE-286)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "reports" / "platform-matrix" / "platform-matrix-report.json"


def _load(path: Path | None) -> dict | None:
    if path is None or not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def merge_report(
    *,
    playwright_report: Path | None,
    buildkit_report: Path | None,
) -> dict:
    pw = _load(playwright_report)
    bk = _load(buildkit_report)
    return {
        "issue": "ISSUE-286",
        "collectedAt": datetime.now(tz=UTC).isoformat(),
        "playwright": pw,
        "buildkit": bk,
        "matrixStatus": {
            "playwrightReady": bool(pw and pw.get("chromium", {}).get("ok")),
            "buildkitAsciiControl": bool(
                bk and bk.get("verdict", {}).get("asciiControlPassed")
            ),
            "buildkitNonAsciiSupported": bool(
                bk and bk.get("verdict", {}).get("nonAsciiSupported")
            ),
            "overall": "partial" if pw or bk else "empty",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--playwright-report",
        type=Path,
        default=REPO_ROOT / "frontend" / "e2e" / "platform-artifacts" / "playwright-platform-report.json",
    )
    parser.add_argument(
        "--buildkit-report",
        type=Path,
        default=REPO_ROOT / "reports" / "platform-matrix" / "buildkit-path-smoke.json",
    )
    parser.add_argument("--write-artifact", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    report = merge_report(
        playwright_report=args.playwright_report,
        buildkit_report=args.buildkit_report,
    )
    args.write_artifact.parent.mkdir(parents=True, exist_ok=True)
    args.write_artifact.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"[platform-matrix] artifact: {args.write_artifact}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
