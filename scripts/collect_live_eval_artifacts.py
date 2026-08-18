#!/usr/bin/env python3
"""Collect live-reasoning artifacts from a gold-path eval JSON dump."""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from dynamic_eval_full_loop import extract_json_objects  # noqa: E402


def _fetch(base: str, token: str, path: str) -> Any:
    req = urllib.request.Request(
        f"{base}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    del argv
    root = Path("artifacts/live-reasoning")
    root.mkdir(parents=True, exist_ok=True)
    summary_path = root / "insider-eval.json"
    if not summary_path.is_file():
        return 0
    objects = extract_json_objects(summary_path.read_text(encoding="utf-8"))
    payload: dict[str, Any] | None = None
    for obj in reversed(objects):
        if obj.get("event_ids") or obj.get("require_llm_quality"):
            payload = obj
            break
    if payload is None:
        return 0
    event_ids = [str(item) for item in (payload.get("event_ids") or []) if item]
    token = os.environ.get("BOOTSTRAP_AUTH_TOKEN", "bootstrap-token")
    port = os.environ.get("BACKEND_PORT", "8000")
    base = f"http://127.0.0.1:{port}"
    for event_id in event_ids:
        try:
            (root / f"{event_id}-event.json").write_text(
                json.dumps(
                    _fetch(base, token, f"/api/v1/events/{event_id}"),
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            (root / f"{event_id}-report.json").write_text(
                json.dumps(
                    _fetch(base, token, f"/api/v1/events/{event_id}/report"),
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            (root / f"{event_id}-timeline.json").write_text(
                json.dumps(
                    _fetch(base, token, f"/api/v1/events/{event_id}/timeline"),
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            (root / f"{event_id}-decision-trace.json").write_text(
                json.dumps(
                    _fetch(
                        base,
                        token,
                        f"/api/v1/events/{event_id}/decision-trace?entry_type=llm_call&page=1&page_size=200",
                    ),
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001 — artifact collection is best-effort
            (root / f"{event_id}-collect-error.txt").write_text(str(exc), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
