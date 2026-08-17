"""Live reasoning card — per-event LLM quality (ISSUE-350).

Independent of ``--require-closed`` (plumbing). Never consults GET /health
60-minute ``success_rate``; that window is ops telemetry, not this event.
"""

from __future__ import annotations

from typing import Any

from dynamic_eval_approve import DynamicEvalApiError, DynamicEvalClient, unwrap_event_detail_payload

CORE_PROMPT_KEYS = (
    "triage_extract",
    "plan_generate",
    "risk_score",
    "response_plan",
)

_EXFIL_EVENT_TYPES = frozenset({"data_exfiltration"})
_EXFIL_SCENARIOS = frozenset(
    {
        "insider_data_exfiltration",
        "adversarial_credential_db_staging_exfil",
    }
)
_TIMEOUT_STATUSES = frozenset({"llm_timeout", "timeout"})


def _llm_call_detail(entry: dict[str, Any]) -> dict[str, Any]:
    detail = entry.get("detail")
    return detail if isinstance(detail, dict) else {}


def collect_llm_calls_from_trace(entries: list[Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_type = str(entry.get("entry_type") or "")
        detail = _llm_call_detail(entry)
        prompt_key = detail.get("prompt_key")
        if entry_type != "llm_call" and not prompt_key:
            continue
        calls.append(
            {
                "prompt_key": prompt_key,
                "status": detail.get("status") or entry.get("status"),
                "error_class": detail.get("error_class"),
                "error_detail": detail.get("error_detail"),
                "agent_name": detail.get("agent_name") or entry.get("actor"),
            }
        )
    return calls


def _scenario_from_event(event: dict[str, Any]) -> str | None:
    snapshot = event.get("event_context_snapshot")
    blobs: list[Any] = [event.get("raw_alert_snapshot"), snapshot]
    if isinstance(snapshot, dict):
        blobs.extend((snapshot.get("source_snapshot"), snapshot.get("normalized")))
    normalized = event.get("normalized")
    if isinstance(normalized, dict):
        blobs.append(normalized)
    for blob in blobs:
        if not isinstance(blob, dict):
            continue
        for key in ("scenario",):
            value = blob.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        nested = blob.get("normalized")
        if isinstance(nested, dict):
            value = nested.get("scenario")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _generated_by_from_event(event: dict[str, Any]) -> str | None:
    snapshot = event.get("event_context_snapshot")
    if isinstance(snapshot, dict):
        direct = snapshot.get("response_plan_generated_by")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        plan = snapshot.get("response_plan")
        if isinstance(plan, dict):
            value = plan.get("generated_by")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def evaluate_llm_quality(
    *,
    event_id: str,
    event_type: str | None,
    final_verdict: str | None,
    scenario_id: str | None,
    response_plan_generated_by: str | None,
    llm_calls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return a quality summary or raise RuntimeError when the Live card fails."""
    by_prompt: dict[str, list[dict[str, Any]]] = {key: [] for key in CORE_PROMPT_KEYS}
    for call in llm_calls:
        key = str(call.get("prompt_key") or "")
        if key in by_prompt:
            by_prompt[key].append(call)

    missing = [key for key, rows in by_prompt.items() if not rows]
    successes = {
        key: [row for row in rows if str(row.get("status") or "") == "success"]
        for key, rows in by_prompt.items()
    }
    timeouts = {
        key: [
            row
            for row in rows
            if str(row.get("status") or "") in _TIMEOUT_STATUSES
            or str(row.get("error_class") or "") == "timeout"
        ]
        for key, rows in by_prompt.items()
    }
    core_attempted = [key for key, rows in by_prompt.items() if rows]
    all_timeout = bool(core_attempted) and all(
        rows and len(timeouts[key]) == len(rows) and not successes[key]
        for key, rows in by_prompt.items()
        if rows
    )
    failed_keys = [key for key in CORE_PROMPT_KEYS if not successes[key]]

    summary = {
        "event_id": event_id,
        "certification_card": "live_reasoning",
        "core_prompt_keys": list(CORE_PROMPT_KEYS),
        "missing_core_prompts": missing,
        "failed_core_prompts": failed_keys,
        "all_core_timeout": all_timeout,
        "event_type": event_type,
        "final_verdict": final_verdict,
        "scenario_id": scenario_id,
        "response_plan_generated_by": response_plan_generated_by,
        "health_window_consulted": False,
    }

    if missing or failed_keys or all_timeout:
        raise RuntimeError(
            "live reasoning card FAIL: core LLM prompts did not succeed for "
            f"{event_id} missing={missing} failed={failed_keys} "
            f"all_timeout={all_timeout} (do not use GET /health success_rate)"
        )

    exfil_like = (event_type or "") in _EXFIL_EVENT_TYPES or (scenario_id or "") in _EXFIL_SCENARIOS
    generated_by = (response_plan_generated_by or "").strip().lower()
    if (
        generated_by == "template"
        and (final_verdict or "") == "confirmed_threat"
        and exfil_like
    ):
        raise RuntimeError(
            "live reasoning card FAIL: response_plan.generated_by=template on "
            f"confirmed_threat exfil event {event_id} "
            f"(event_type={event_type!r} scenario={scenario_id!r}); "
            "rule fallback is not Agent reasoning success"
        )

    summary["ok"] = True
    return summary


def _paginate_decision_trace(
    client: DynamicEvalClient,
    event_id: str,
    *,
    page_size: int = 200,
) -> list[dict[str, Any]]:
    page = 1
    collected: list[dict[str, Any]] = []
    total: int | None = None
    while page <= 20:
        payload = client.get_json(
            f"/api/v1/events/{event_id}/decision-trace"
            f"?entry_type=llm_call&page={page}&page_size={page_size}"
        )
        if not isinstance(payload, dict):
            raise DynamicEvalApiError(f"unexpected decision-trace payload: {payload!r}")
        items = payload.get("entries")
        if not isinstance(items, list):
            raise DynamicEvalApiError(
                f"decision-trace entries missing for {event_id}: {payload!r}"
            )
        page_items = [item for item in items if isinstance(item, dict)]
        collected.extend(page_items)
        if total is None and payload.get("total") is not None:
            try:
                total = int(payload["total"])
            except (TypeError, ValueError) as exc:
                raise DynamicEvalApiError(
                    f"invalid decision-trace total for {event_id}: {payload.get('total')!r}"
                ) from exc
        if total is not None and len(collected) >= total:
            break
        if total is None and len(page_items) < page_size:
            break
        if not page_items:
            break
        page += 1
    return collected


def assert_llm_quality_acceptance(
    client: DynamicEvalClient,
    event_id: str,
) -> dict[str, Any]:
    """Live reasoning card: per-event llm_call_log + template/exfil FAIL."""
    payload = client.get_json(f"/api/v1/events/{event_id}")
    if not isinstance(payload, dict):
        raise DynamicEvalApiError(f"unexpected event detail payload: {payload!r}")
    event = unwrap_event_detail_payload(payload, expected_event_id=event_id)
    trace_entries = _paginate_decision_trace(client, event_id)
    llm_calls = collect_llm_calls_from_trace(trace_entries)
    return evaluate_llm_quality(
        event_id=event_id,
        event_type=str(event.get("event_type") or "") or None,
        final_verdict=str(event.get("final_verdict") or "") or None,
        scenario_id=_scenario_from_event(event),
        response_plan_generated_by=_generated_by_from_event(event),
        llm_calls=llm_calls,
    )
