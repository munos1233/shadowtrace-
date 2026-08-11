#!/usr/bin/env python3
"""Poll demo events until terminal smoke acceptance (ISSUE-304 / #923).

Used by ``scripts/smoke_bootstrap.sh`` when ``SMOKE_TERMINAL_MODE`` is set.

Modes
-----
compat (default for ``make smoke-demo``):
  Each event is OK when status is not ``failed`` and either
  ``analysis_only_complete`` is true or status is ``closed`` / ``contained`` /
  ``reporting``.

strict:
  Each event must reach ``closed`` with a non-placeholder report (ISSUE-301 /
  ISSUE-256 strict profile). Use after ``make eval-full-loop`` or
  ``BOOTSTRAP_INCLUDE_RESPONSE=true`` + scripted approval — not after default
  ``make bootstrap`` (analysis-only short path).

off:
  No terminal polling (health + event count only).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from dynamic_eval_approve import (  # noqa: E402
    DynamicEvalApiError,
    DynamicEvalClient,
    unwrap_event_detail_payload,
)
from dynamic_eval_full_loop import assert_strict_closed_acceptance  # noqa: E402

_COMPAT_TERMINAL_STATUSES = frozenset({"closed", "contained", "reporting"})
_IN_FLIGHT = frozenset(
    {
        "new",
        "triaging",
        "collecting_evidence",
        "analyzing",
        "scoring",
        "planning_response",
        "executing_response",
        "verifying",
        "replanning",
        "waiting_approval",
    }
)
_DEFAULT_POLL_S = 5.0


@dataclass
class EventTrajectory:
    event_id: str
    statuses: list[str] = field(default_factory=list)

    def record(self, status: str) -> None:
        if not self.statuses or self.statuses[-1] != status:
            self.statuses.append(status)


def _analysis_only_complete(detail: dict[str, Any]) -> bool:
    if detail.get("analysis_only_complete") is True:
        return True
    event = unwrap_event_detail_payload(detail)
    snapshot = event.get("event_context_snapshot")
    if isinstance(snapshot, dict) and snapshot.get("analysis_only_complete") is True:
        return True
    return event.get("analysis_only_complete") is True


def compat_terminal_reached(detail: dict[str, Any]) -> tuple[bool, str]:
    """Return (reached, status) for compat smoke profile."""
    event = unwrap_event_detail_payload(detail)
    status = str(event.get("status") or "")
    if status == "failed":
        return False, status
    if status in _COMPAT_TERMINAL_STATUSES:
        return True, status
    if _analysis_only_complete(detail):
        return True, status
    return False, status


def list_demo_events(
    client: DynamicEvalClient,
    *,
    min_events: int,
    page_size: int = 50,
) -> list[dict[str, Any]]:
    payload = client.get_json(f"/api/v1/events?page_size={page_size}")
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise DynamicEvalApiError(f"unexpected events list payload: {payload!r}")
    events = [item for item in items if isinstance(item, dict) and item.get("event_id")]
    if len(events) < min_events:
        raise DynamicEvalApiError(
            f"expected at least {min_events} demo event(s), found {len(events)}"
        )
    return events


def wait_for_terminal_events(
    client: DynamicEvalClient,
    *,
    mode: str,
    timeout_s: float,
    min_events: int,
    poll_s: float = _DEFAULT_POLL_S,
) -> dict[str, Any]:
    """Poll until every listed event satisfies *mode* or timeout."""
    if mode == "off":
        return {"mode": "off", "events": []}

    events = list_demo_events(client, min_events=min_events)
    trajectories = {str(e["event_id"]): EventTrajectory(str(e["event_id"])) for e in events}
    deadline = time.monotonic() + timeout_s
    pending = set(trajectories.keys())
    results: dict[str, dict[str, Any]] = {}

    while pending and time.monotonic() < deadline:
        finished_this_round: list[str] = []
        for event_id in sorted(pending):
            detail = client.get_json(f"/api/v1/events/{event_id}")
            event = unwrap_event_detail_payload(detail, expected_event_id=event_id)
            status = str(event.get("status") or "")
            trajectories[event_id].record(status)

            if status == "failed":
                raise RuntimeError(
                    _format_terminal_failure(
                        mode=mode,
                        trajectories=trajectories,
                        reason=f"{event_id} reached status=failed",
                    )
                )

            if mode == "strict":
                if status == "closed":
                    assert_strict_closed_acceptance(client, event_id, max_wait_s=0.0)
                    results[event_id] = {"status": status, "profile": "strict_closed"}
                    finished_this_round.append(event_id)
                continue

            reached, observed = compat_terminal_reached(detail)
            if reached:
                results[event_id] = {
                    "status": observed,
                    "analysis_only_complete": _analysis_only_complete(detail),
                    "profile": "compat",
                }
                finished_this_round.append(event_id)

        for event_id in finished_this_round:
            pending.discard(event_id)

        if pending:
            in_flight = {
                eid: trajectories[eid].statuses[-1] if trajectories[eid].statuses else "?"
                for eid in sorted(pending)
            }
            print(
                f"[smoke-terminal] waiting ({len(pending)} pending): "
                f"{json.dumps(in_flight, ensure_ascii=False)}",
                flush=True,
            )
            time.sleep(poll_s)

    if pending:
        raise RuntimeError(
            _format_terminal_failure(
                mode=mode,
                trajectories=trajectories,
                reason=(
                    f"timeout after {timeout_s:.0f}s with {len(pending)} event(s) "
                    f"still in-flight: {', '.join(sorted(pending))}"
                ),
            )
        )

    return {
        "mode": mode,
        "events": results,
        "trajectories": {eid: t.statuses for eid, t in trajectories.items()},
    }


def _format_terminal_failure(
    *,
    mode: str,
    trajectories: dict[str, EventTrajectory],
    reason: str,
) -> str:
    lines = [
        f"smoke terminal check failed (mode={mode}): {reason}",
        "event status trajectories:",
    ]
    for event_id in sorted(trajectories):
        path = " -> ".join(trajectories[event_id].statuses) or "(no samples)"
        lines.append(f"  {event_id}: {path}")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default="bootstrap-token")
    parser.add_argument(
        "--mode",
        choices=("off", "compat", "strict"),
        default="compat",
        help="Terminal acceptance profile (default: compat)",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=600.0,
        help="Max seconds to wait for all events (default: 600)",
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=3,
        help="Minimum demo events to monitor (default: 3)",
    )
    parser.add_argument(
        "--poll-s",
        type=float,
        default=_DEFAULT_POLL_S,
        help=f"Poll interval seconds (default: {_DEFAULT_POLL_S})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.mode == "off":
        print("[smoke-terminal] mode=off — skipping terminal poll")
        return 0

    client = DynamicEvalClient(base_url=args.base_url.rstrip("/"), token=args.token)
    try:
        summary = wait_for_terminal_events(
            client,
            mode=args.mode,
            timeout_s=args.timeout_s,
            min_events=args.min_events,
            poll_s=args.poll_s,
        )
    except (RuntimeError, DynamicEvalApiError) as exc:
        print(f"[smoke-terminal] ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        "[smoke-terminal] ok: "
        f"mode={summary['mode']} events={json.dumps(summary['events'], ensure_ascii=False)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
