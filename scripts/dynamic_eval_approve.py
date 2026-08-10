#!/usr/bin/env python3
"""Scripted approve/reject for dynamic-eval / demo gold paths (ISSUE-256).

Human-gated actions must be decided by this script (or an operator UI).
**Never** end an evaluation by waiting for ``APPROVAL_TIMEOUT_MINUTES``
(production default 30) — that empty-waits and trips R2-012 / ISSUE-247 paths.

Usage (host, against a running stack)::

    python3 scripts/dynamic_eval_approve.py \\
        --base-url http://127.0.0.1:8000 \\
        --token bootstrap-token \\
        --event-id evt-... \\
        --decision approve
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

_SKIP_TOOL_NAMES = frozenset({"generate_report"})

TERMINAL_EVENT_STATUSES = frozenset(
    {
        "closed",
        "contained",
        "failed",
        "reporting",
    }
)
SUCCESSISH_EVENT_STATUSES = frozenset(
    {
        "closed",
        "contained",
        "reporting",
        "executing_response",
        "verifying",
        "replanning",
    }
)


@dataclass(frozen=True)
class ApiResponse:
    status: int
    data: Any


class DynamicEvalApiError(RuntimeError):
    """HTTP / contract failure during dynamic eval."""


def unwrap_event_detail_payload(
    payload: Any,
    *,
    expected_event_id: str | None = None,
) -> dict[str, Any]:
    """Normalize GET /api/v1/events/{event_id} JSON to a SecurityEvent dict.

    Production returns ``EventDetailResponse`` with the event nested under
    ``event``; older stacks may still return a flat SecurityEvent. After
    unwrap, ``event_id`` is validated when *expected_event_id* is provided.
    """
    if not isinstance(payload, dict):
        raise DynamicEvalApiError(f"unexpected event payload: {payload!r}")

    nested = payload.get("event")
    if isinstance(nested, dict):
        event = nested
    elif "event_id" in payload:
        event = payload
    else:
        raise DynamicEvalApiError(f"unexpected event payload: {payload!r}")

    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        raise DynamicEvalApiError(f"unexpected event payload: {payload!r}")

    if expected_event_id is not None and event_id != expected_event_id:
        raise DynamicEvalApiError(
            f"event_id mismatch for GET detail: expected {expected_event_id!r}, "
            f"got {event_id!r}"
        )
    return event


class DynamicEvalClient:
    """Minimal stdlib HTTP client for /api/v1 (no third-party deps on host)."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        timeout_s: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        max_retries: int = 3,
    ) -> ApiResponse:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        data: bytes | None = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        last_exc: Exception | None = None
        for attempt in range(1, max_retries + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    raw = resp.read()
                    payload: Any = {}
                    if raw:
                        payload = json.loads(raw.decode("utf-8"))
                    return ApiResponse(status=int(resp.status), data=payload)
            except urllib.error.HTTPError as exc:
                raw = exc.read() if exc.fp is not None else b""
                try:
                    payload = json.loads(raw.decode("utf-8")) if raw else {}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    payload = {"raw": raw.decode("utf-8", errors="replace")}
                if exc.code >= 500 and attempt < max_retries:
                    last_exc = DynamicEvalApiError(
                        f"HTTP {exc.code} {method} {path}: {payload}"
                    )
                    time.sleep(2**attempt)
                    continue
                raise DynamicEvalApiError(
                    f"HTTP {exc.code} {method} {path}: {payload}"
                ) from exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_exc = exc
                if attempt < max_retries:
                    time.sleep(2**attempt)
                    continue
                raise DynamicEvalApiError(f"{method} {path} failed: {exc}") from exc
        raise DynamicEvalApiError(f"{method} {path} failed: {last_exc}")

    def get_json(self, path: str) -> Any:
        return self.request("GET", path).data

    def post_json(self, path: str, body: dict[str, Any] | None = None) -> ApiResponse:
        return self.request("POST", path, body or {})


def is_human_gated_action(action: dict[str, Any]) -> bool:
    """True when *action* is waiting on a human decision (eval gold path).

    Selects any non-system ``waiting_approval`` row so the gold path cannot stall
    on unexpected levels; ``generate_report`` remains skipped.
    """
    if action.get("tool_name") in _SKIP_TOOL_NAMES:
        return False
    if action.get("action_category") == "system":
        return False
    return str(action.get("status") or "") == "waiting_approval"


def select_pending_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic pending human-gated actions (L2 preferred, then by id)."""
    pending = [a for a in actions if is_human_gated_action(a)]
    return sorted(
        pending,
        key=lambda a: (
            0 if str(a.get("action_level", "")).lower() == "l2" else 1,
            int(a.get("plan_revision") or 0),
            str(a.get("action_id") or ""),
        ),
    )


def list_event_actions(
    client: DynamicEvalClient,
    event_id: str,
    *,
    status: str | None = "waiting_approval",
    page_size: int = 50,
) -> list[dict[str, Any]]:
    params: dict[str, str] = {"page": "1", "page_size": str(page_size)}
    if status:
        params["status"] = status
    path = f"/api/v1/events/{event_id}/actions?{urlencode(params)}"
    payload = client.get_json(path)
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise DynamicEvalApiError(f"unexpected actions payload for {event_id}: {payload!r}")
    return [item for item in items if isinstance(item, dict)]


def decide_action(
    client: DynamicEvalClient,
    action_id: str,
    *,
    decision: str,
    comment: str,
    decision_id: str | None = None,
) -> dict[str, Any]:
    decision_norm = decision.strip().lower()
    if decision_norm not in {"approve", "reject"}:
        raise ValueError("decision must be 'approve' or 'reject'")
    body: dict[str, Any] = {"comment": comment}
    if decision_id:
        body["decision_id"] = decision_id
    resp = client.post_json(f"/api/v1/actions/{action_id}/{decision_norm}", body)
    if resp.status >= 400:
        raise DynamicEvalApiError(f"{decision_norm} {action_id} failed: {resp.data}")
    return resp.data if isinstance(resp.data, dict) else {"raw": resp.data}


def approve_or_reject_pending(
    client: DynamicEvalClient,
    event_id: str,
    *,
    decision: str = "approve",
    comment: str = "ISSUE-256 dynamic-eval scripted decision (not approval timeout)",
    decision_id_prefix: str = "dyn-eval",
) -> list[dict[str, Any]]:
    """Decide all currently waiting human-gated actions for *event_id*."""
    actions = list_event_actions(client, event_id, status="waiting_approval")
    pending = select_pending_actions(actions)
    outcomes: list[dict[str, Any]] = []
    for idx, action in enumerate(pending):
        action_id = str(action["action_id"])
        decision_id = f"{decision_id_prefix}-{event_id}-{idx}-{action_id[-8:]}"
        result = decide_action(
            client,
            action_id,
            decision=decision,
            comment=comment,
            decision_id=decision_id,
        )
        outcomes.append(
            {
                "action_id": action_id,
                "action_level": action.get("action_level"),
                "decision": decision,
                "api": result,
            }
        )
    return outcomes


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scripted approve/reject for waiting_approval actions (ISSUE-256)"
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Backend origin (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--token",
        default="bootstrap-token",
        help="Bearer token with approver role (compose default: bootstrap-token)",
    )
    parser.add_argument("--event-id", required=True, help="Target event_id")
    parser.add_argument(
        "--decision",
        choices=("approve", "reject"),
        default="approve",
        help="Decision for all currently waiting human-gated actions",
    )
    parser.add_argument(
        "--comment",
        default="ISSUE-256 dynamic-eval scripted decision (not approval timeout)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON outcome",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    client = DynamicEvalClient(base_url=args.base_url, token=args.token)
    outcomes = approve_or_reject_pending(
        client,
        args.event_id,
        decision=args.decision,
        comment=args.comment,
    )
    payload = {
        "event_id": args.event_id,
        "decision": args.decision,
        "decided_count": len(outcomes),
        "outcomes": outcomes,
        "note": "Eval must script approve/reject; do not wait for APPROVAL_TIMEOUT_MINUTES",
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if not outcomes:
            print(
                "[dynamic-eval-approve] no waiting_approval human-gated actions "
                f"on {args.event_id}"
            )
        for row in outcomes:
            print(
                f"[dynamic-eval-approve] {args.decision} {row['action_id']} "
                f"level={row.get('action_level')}"
            )
        print(f"[dynamic-eval-approve] decided_count={len(outcomes)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DynamicEvalApiError, ValueError) as exc:
        print(f"[dynamic-eval-approve] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
