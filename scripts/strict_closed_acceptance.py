"""ISSUE-301 / ISSUE-256 strict CLOSED acceptance helpers (shared eval + smoke)."""

from __future__ import annotations

import time
from typing import Any

from dynamic_eval_approve import DynamicEvalApiError, DynamicEvalClient, unwrap_event_detail_payload

_MAX_ACTION_PAGES = 50
STRICT_ASSERT_MIN_WAIT_S = 10.0
STRICT_ASSERT_MAX_CAP_S = 60.0
STRICT_ASSERT_POLL_S = 0.5
_GATE_APPLICABLE_CATEGORIES = frozenset({"response", "rollback"})


def get_event_detail(client: DynamicEvalClient, event_id: str) -> dict[str, Any]:
    """Return raw EventDetailResponse (writeback gate fields at envelope level)."""
    payload = client.get_json(f"/api/v1/events/{event_id}")
    if not isinstance(payload, dict):
        raise DynamicEvalApiError(f"unexpected event detail payload: {payload!r}")
    if "event" in payload and isinstance(payload.get("event"), dict):
        return payload
    if "event_id" in payload:
        return {"event": payload}
    raise DynamicEvalApiError(f"unexpected event detail payload: {payload!r}")


def list_all_event_actions(
    client: DynamicEvalClient,
    event_id: str,
    *,
    page_size: int = 100,
) -> list[dict[str, Any]]:
    page = 1
    collected: list[dict[str, Any]] = []
    total: int | None = None
    while page <= _MAX_ACTION_PAGES:
        payload = client.get_json(
            f"/api/v1/events/{event_id}/actions?page={page}&page_size={page_size}"
        )
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise DynamicEvalApiError(
                f"unexpected actions payload for {event_id}: {payload!r}"
            )
        page_items = [item for item in items if isinstance(item, dict)]
        collected.extend(page_items)
        if total is None and isinstance(payload, dict) and payload.get("total") is not None:
            try:
                total = int(payload["total"])
            except (TypeError, ValueError) as exc:
                raise DynamicEvalApiError(
                    f"invalid actions total for {event_id}: {payload.get('total')!r}"
                ) from exc
        if total is not None and len(collected) >= total:
            break
        if total is None and len(page_items) < page_size:
            break
        if not page_items:
            if total is not None and len(collected) < total:
                raise DynamicEvalApiError(
                    f"actions pagination truncated for {event_id}: "
                    f"collected={len(collected)} total={total} empty page={page}"
                )
            break
        page += 1
    else:
        raise DynamicEvalApiError(
            f"actions pagination exceeded {_MAX_ACTION_PAGES} pages for {event_id}"
        )
    return collected


def assert_strict_closed_acceptance_once(
    client: DynamicEvalClient,
    event_id: str,
) -> dict[str, Any]:
    """ISSUE-301 strict profile: CLOSED + report + terminal writeback convergence.

    Event-level ``writeback_readiness`` / ``writeback_overall_status`` /
    ``pending_writeback_count`` are ISSUE-312 **terminal** (applicable) fields.
    Entity ACCEPTED receipts belong in ``entity_writeback_accepted_count`` and
    must not fail this gate.
    """
    detail = get_event_detail(client, event_id)
    event = unwrap_event_detail_payload(detail, expected_event_id=event_id)
    status = str(event.get("status") or "")
    if status != "closed":
        raise RuntimeError(
            f"strict profile requires status=closed for {event_id}, got {status!r}"
        )

    report_resp = client.request("GET", f"/api/v1/events/{event_id}/report")
    if report_resp.status != 200:
        raise RuntimeError(
            f"strict profile: GET /report for {event_id} failed HTTP "
            f"{report_resp.status}: {report_resp.data!r}"
        )
    report_data = report_resp.data if isinstance(report_resp.data, dict) else {}
    report_obj = report_data.get("report")
    if not report_obj:
        raise RuntimeError(
            f"strict profile: GET /report for {event_id} returned no report body"
        )
    if isinstance(report_obj, dict):
        report_quality = str(report_obj.get("report_quality") or "")
        if not report_quality:
            raise RuntimeError(
                f"strict profile: report_quality missing for {event_id}"
            )
        if report_quality == "incomplete_placeholder":
            raise RuntimeError(
                f"strict profile: report_quality={report_quality!r} for {event_id}"
            )

    if detail.get("writeback_required"):
        readiness = str(detail.get("writeback_readiness") or "")
        if readiness != "ready":
            raise RuntimeError(
                f"strict profile: event-level writeback_readiness={readiness!r} "
                f"for {event_id} (expected ready)"
            )
        wb_status = detail.get("writeback_overall_status")
        if wb_status != "confirmed":
            raise RuntimeError(
                f"strict profile: writeback_overall_status={wb_status!r} "
                f"for {event_id} (expected confirmed)"
            )
        pending = int(detail.get("pending_writeback_count") or 0)
        if pending > 0:
            raise RuntimeError(
                f"strict profile: pending_writeback_count={pending} for {event_id}"
            )
        # Entity ACCEPTED is allowed; do not treat it as terminal pending.

    action_violations: list[str] = []
    for action in list_all_event_actions(client, event_id):
        if not action.get("writeback_required") or not action.get("writeback_applicable"):
            continue
        category = str(action.get("action_category") or "")
        if category not in _GATE_APPLICABLE_CATEGORIES:
            continue
        if action.get("superseded_by_revision") is not None:
            continue
        action_status = str(action.get("status") or "")
        if action_status == "rejected":
            continue
        action_id = str(action.get("action_id") or "")
        readiness = str(action.get("writeback_readiness") or "")
        if readiness != "ready":
            action_violations.append(
                f"{action_id}: writeback_readiness={readiness!r}"
            )
        wb = action.get("writeback_status")
        if wb != "confirmed":
            action_violations.append(
                f"{action_id}: writeback_status={wb!r}"
            )
    if action_violations:
        raise RuntimeError(
            f"strict profile: gate-applicable writeback actions not converged "
            f"for {event_id}: {action_violations}"
        )

    return {
        "event_id": event_id,
        "status": status,
        "writeback_required": bool(detail.get("writeback_required")),
        "writeback_readiness": detail.get("writeback_readiness"),
        "writeback_overall_status": detail.get("writeback_overall_status"),
        "report_quality": (
            (report_data.get("report") or {}).get("report_quality")
            if isinstance(report_data.get("report"), dict)
            else None
        ),
    }


def strict_assert_budget(*, max_wait_s: float, elapsed_s: float) -> float:
    """Remaining wall clock for post-close strict convergence checks."""
    remaining = max_wait_s - elapsed_s
    return max(STRICT_ASSERT_MIN_WAIT_S, min(remaining, STRICT_ASSERT_MAX_CAP_S))


# Backward-compatible alias for existing eval/smoke imports and tests.
_strict_assert_budget = strict_assert_budget
_assert_strict_closed_acceptance_once = assert_strict_closed_acceptance_once


def assert_strict_closed_acceptance(
    client: DynamicEvalClient,
    event_id: str,
    *,
    max_wait_s: float = STRICT_ASSERT_MIN_WAIT_S,
    poll_interval_s: float = STRICT_ASSERT_POLL_S,
) -> dict[str, Any]:
    """Strict CLOSED acceptance with bounded retry for post-close convergence lag."""
    deadline = time.monotonic() + max_wait_s
    last_error: RuntimeError | None = None
    while True:
        try:
            return assert_strict_closed_acceptance_once(client, event_id)
        except RuntimeError as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                raise last_error from None
            time.sleep(min(poll_interval_s, max(0.0, deadline - time.monotonic())))
