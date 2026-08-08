#!/usr/bin/env python3
"""Compare llm_call_log invalid rates by prompt_key (ISSUE-251).

Reads either:
  * a JSON/JSONL dump of llm_call_log-like rows, or
  * stdin JSON array / JSONL

Exits 0 when every measured key with samples is within demo thresholds.
Does not call providers and never prints prompt/completion bodies.

Example:
  python scripts/llm_prompt_invalid_rate_report.py \\
    --input /tmp/round2_llm_call_log.jsonl \\
    --baseline-invalid-rate 0.37
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Allow running from repo root without installing the package editable.
_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.core.llm.prompt_quality import (  # noqa: E402
    PROMPT_INVALID_RATE_DEMO_THRESHOLDS,
    STRUCTURED_PROMPT_KEYS,
    compute_prompt_key_invalid_rates,
)


def _load_jsonl(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise SystemExit(f"JSONL line {line_no} must be an object")
        rows.append(payload)
    return rows


def _load_rows(path: Path | None) -> list[dict[str, Any]]:
    raw = sys.stdin.read() if path is None else path.read_text(encoding="utf-8")
    text = raw.strip()
    if not text:
        return []
    if path is not None and path.suffix.lower() == ".jsonl":
        return _load_jsonl(text)
    # Multi-line object stream → JSONL (stdin or extension-less dumps).
    if "\n" in text and text.lstrip().startswith("{"):
        return _load_jsonl(text)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # Last resort for extension-less JSONL files.
        return _load_jsonl(text)
    if isinstance(payload, list):
        rows = []
        for idx, item in enumerate(payload):
            if not isinstance(item, dict):
                raise SystemExit(f"input[{idx}] must be an object")
            rows.append(item)
        return rows
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        rows = []
        for idx, item in enumerate(payload["items"]):
            if not isinstance(item, dict):
                raise SystemExit(f"items[{idx}] must be an object")
            rows.append(item)
        return rows
    raise SystemExit("input must be a JSON array, {items:[...]}, or JSONL objects")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="JSON/JSONL path; omit to read stdin",
    )
    parser.add_argument(
        "--baseline-invalid-rate",
        type=float,
        default=None,
        help="Optional overall baseline invalid rate (e.g. 0.37 from round-2)",
    )
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Exit 0 when the input has no measurable structured calls",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON report",
    )
    args = parser.parse_args(argv)

    rows = _load_rows(args.input)
    report = compute_prompt_key_invalid_rates(
        rows,
        prompt_keys=sorted(STRUCTURED_PROMPT_KEYS),
        thresholds=PROMPT_INVALID_RATE_DEMO_THRESHOLDS,
    )

    measured = [item for item in report.keys if item.total_calls > 0]
    overall_total = sum(item.total_calls for item in measured)
    overall_invalid = sum(item.invalid_calls for item in measured)
    overall_rate = (overall_invalid / overall_total) if overall_total else 0.0

    payload = {
        "overall": {
            "total_calls": overall_total,
            "invalid_calls": overall_invalid,
            "invalid_rate": overall_rate,
            "baseline_invalid_rate": args.baseline_invalid_rate,
            "improved_vs_baseline": (
                None
                if args.baseline_invalid_rate is None or overall_total == 0
                else overall_rate <= float(args.baseline_invalid_rate)
            ),
        },
        "report": report.model_dump(mode="json"),
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("prompt_key invalid-rate report (ISSUE-251)")
        print(f"overall: invalid={overall_invalid}/{overall_total} rate={overall_rate:.3f}")
        if args.baseline_invalid_rate is not None:
            delta = overall_rate - float(args.baseline_invalid_rate)
            print(f"baseline: {float(args.baseline_invalid_rate):.3f} delta={delta:+.3f}")
        for item in report.keys:
            threshold = f"{item.demo_threshold:.2f}" if item.demo_threshold is not None else "-"
            gate = (
                "ok"
                if item.within_demo_threshold is True
                else ("FAIL" if item.within_demo_threshold is False else "n/a")
            )
            print(
                f"  {item.prompt_key}: {item.invalid_calls}/{item.total_calls} "
                f"rate={item.invalid_rate:.3f} threshold={threshold} gate={gate} "
                f"classes={item.by_error_class}"
            )

    if overall_total == 0:
        return 0 if args.allow_empty else 2
    if args.baseline_invalid_rate is not None and overall_rate > float(args.baseline_invalid_rate):
        return 2
    return 0 if report.all_within_demo_threshold else 1


if __name__ == "__main__":
    raise SystemExit(main())
