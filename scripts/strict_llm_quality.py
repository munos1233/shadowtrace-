"""Live reasoning card — per-event LLM quality (ISSUE-350).

Independent of ``--require-closed`` (plumbing). Never consults GET /health
60-minute ``success_rate``; that window is ops telemetry, not this event.
"""

from __future__ import annotations

import re
from typing import Any

from dynamic_eval_approve import DynamicEvalApiError, DynamicEvalClient, unwrap_event_detail_payload

_GENERATED_BY_RE = re.compile(r"generated_by=([a-z_]+)", re.IGNORECASE)
_RESPONSE_AGENT_NAMES = frozenset({"response_agent", "ResponseAgent"})

CORE_PROMPT_KEYS = (
    "triage_extract",
    "plan_generate",
    "risk_score",
    "response_plan",
)

_EXFIL_EVENT_TYPES = frozenset({"data_exfiltration", "insider_threat"})
_EXFIL_SCENARIOS = frozenset(
    {
        "insider_data_exfiltration",
        "adversarial_credential_db_staging_exfil",
    }
)
_TIMEOUT_STATUSES = frozenset({"llm_timeout", "timeout"})
_MOCK_MODEL_NAMES = frozenset({"mock-model", "mock"})
# Keep in sync with app.services.agent_trace_service._RESPONSE_GATE_TRACE_MARKERS.
_GATE_INJECTION_MARKERS = (
    "entity_coverage_merge",
    "identity_containment_dedup",
    "rule fallback after ungrounded",
    "containment_quality_gate_unsatisfied",
    "domain_containment_missing",
)


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
                "model_name": detail.get("model_name") or detail.get("model"),
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
    """Best-effort snapshot lookup. API snapshots usually omit response_plan."""
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


def _generated_by_token(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip().lower()
    if trimmed in {"template", "llm"}:
        return trimmed
    return None


def _generated_by_from_trace(entries: list[Any]) -> str | None:
    """Read response_plan.generated_by from agent_execution titles/details.

    GET /events/{id} snapshots are ISSUE-254 whitelisted and do not include
    ``response_plan``. Decision-trace response_agent titles carry
    ``generated_by=template|llm``.
    """
    found: str | None = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        actor = str(entry.get("actor") or "")
        detail = _llm_call_detail(entry)
        agent_name = str(detail.get("agent_name") or actor)
        if agent_name not in _RESPONSE_AGENT_NAMES and actor not in _RESPONSE_AGENT_NAMES:
            continue
        for candidate in (
            detail.get("generated_by"),
            _GENERATED_BY_RE.search(str(entry.get("title") or "")),
            _GENERATED_BY_RE.search(str(detail.get("structured_conclusion") or "")),
            _GENERATED_BY_RE.search(str(detail.get("brief") or "")),
        ):
            token = (
                _generated_by_token(candidate.group(1))
                if isinstance(candidate, re.Match)
                else _generated_by_token(candidate)
            )
            if token:
                found = token
    return found


def _response_strategy_from_trace(entries: list[Any]) -> str:
    """Concatenate response_agent titles/details so gate-injection notes are visible."""
    blobs: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        actor = str(entry.get("actor") or "")
        detail = _llm_call_detail(entry)
        agent_name = str(detail.get("agent_name") or actor)
        if agent_name not in _RESPONSE_AGENT_NAMES and actor not in _RESPONSE_AGENT_NAMES:
            continue
        for value in (
            entry.get("title"),
            detail.get("strategy_summary"),
            detail.get("structured_conclusion"),
            detail.get("decision_summary"),
            detail.get("brief"),
        ):
            if isinstance(value, str) and value.strip():
                blobs.append(value.strip())
    return " ".join(blobs)


def _mock_model_successes(llm_calls: list[dict[str, Any]]) -> list[str]:
    watched = set(CORE_PROMPT_KEYS) | {"report_generate"}
    bad: list[str] = []
    for row in llm_calls:
        key = str(row.get("prompt_key") or "")
        if key not in watched:
            continue
        if str(row.get("status") or "") != "success":
            continue
        model = str(row.get("model_name") or "").strip().lower()
        if not model or model in _MOCK_MODEL_NAMES:
            bad.append(f"{key}:{model or 'missing'}")
    return bad


def evaluate_llm_quality(
    *,
    event_id: str,
    event_type: str | None,
    final_verdict: str | None,
    scenario_id: str | None,
    response_plan_generated_by: str | None,
    llm_calls: list[dict[str, Any]],
    storyline_generated_by: str | None = None,
    storyline_phase_count: int = 0,
    report_quality: str | None = None,
    response_plan_strategy: str | None = None,
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
        "storyline_generated_by": storyline_generated_by,
        "storyline_phase_count": int(storyline_phase_count or 0),
        "report_quality": report_quality,
        "response_plan_strategy": response_plan_strategy,
        "health_window_consulted": False,
    }

    mock_hits = _mock_model_successes(llm_calls)
    if mock_hits:
        raise RuntimeError(
            "live reasoning card FAIL: mock-model (or missing model_name) is not "
            f"live glm for {event_id}: {mock_hits}"
        )

    if missing or failed_keys or all_timeout:
        raise RuntimeError(
            "live reasoning card FAIL: core LLM prompts did not succeed for "
            f"{event_id} missing={missing} failed={failed_keys} "
            f"all_timeout={all_timeout} (do not use GET /health success_rate)"
        )

    exfil_like = (event_type or "") in _EXFIL_EVENT_TYPES or (scenario_id or "") in _EXFIL_SCENARIOS
    generated_by = (response_plan_generated_by or "").strip().lower()
    if exfil_like and (final_verdict or "") == "confirmed_threat":
        if not generated_by:
            raise RuntimeError(
                "live reasoning card FAIL: could not observe "
                "response_plan.generated_by on confirmed_threat exfil event "
                f"{event_id} (event_type={event_type!r} scenario={scenario_id!r}); "
                "GET /events snapshot does not carry the plan — use decision-trace"
            )
        if generated_by == "template":
            raise RuntimeError(
                "live reasoning card FAIL: response_plan.generated_by=template on "
                f"confirmed_threat exfil event {event_id} "
                f"(event_type={event_type!r} scenario={scenario_id!r}); "
                "rule fallback is not Agent reasoning success"
            )
        strategy_blob = (response_plan_strategy or "").lower()
        hit = next((marker for marker in _GATE_INJECTION_MARKERS if marker in strategy_blob), None)
        if hit:
            raise RuntimeError(
                "live reasoning card FAIL: response_plan was completed by quality-gate "
                f"injection ({hit}) on confirmed_threat exfil event {event_id}; "
                "entity_coverage_merge / identity_containment_dedup / "
                "domain_containment_missing is not Agent reasoning"
            )
        storyline_by = (storyline_generated_by or "").strip().lower()
        if storyline_by != "llm" or int(storyline_phase_count or 0) < 1:
            raise RuntimeError(
                "live reasoning card FAIL: storyline was not adopted from LLM on "
                f"confirmed_threat exfil event {event_id} "
                f"generated_by={storyline_generated_by!r} phases={storyline_phase_count}; "
                "llm_call_log success is not narrative adoption"
            )
        report_successes = [
            row
            for row in llm_calls
            if str(row.get("prompt_key") or "") == "report_generate"
            and str(row.get("status") or "") == "success"
        ]
        quality = (report_quality or "").strip().lower()
        if not report_successes:
            raise RuntimeError(
                "live reasoning card FAIL: report_generate did not succeed on "
                f"confirmed_threat exfil event {event_id}"
            )
        if quality in {"", "incomplete_placeholder", "degraded_template"}:
            raise RuntimeError(
                "live reasoning card FAIL: report_quality="
                f"{report_quality!r} on confirmed_threat exfil event {event_id}; "
                "incomplete_placeholder/degraded_template is not Live reasoning success"
            )

    summary["ok"] = True
    return summary


def _paginate_decision_trace(
    client: DynamicEvalClient,
    event_id: str,
    *,
    entry_types: tuple[str, ...] = ("llm_call",),
    page_size: int = 200,
) -> list[dict[str, Any]]:
    page = 1
    collected: list[dict[str, Any]] = []
    total: int | None = None
    type_qs = "&".join(f"entry_type={item}" for item in entry_types)
    while page <= 20:
        payload = client.get_json(
            f"/api/v1/events/{event_id}/decision-trace?{type_qs}&page={page}&page_size={page_size}"
        )
        if not isinstance(payload, dict):
            raise DynamicEvalApiError(f"unexpected decision-trace payload: {payload!r}")
        items = payload.get("entries")
        if not isinstance(items, list):
            raise DynamicEvalApiError(f"decision-trace entries missing for {event_id}: {payload!r}")
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


def _load_storyline_adoption(
    client: DynamicEvalClient,
    event_id: str,
) -> tuple[str | None, int]:
    try:
        payload = client.get_json(f"/api/v1/events/{event_id}/timeline")
    except DynamicEvalApiError:
        return None, 0
    if not isinstance(payload, dict):
        return None, 0
    generated_by = payload.get("generated_by")
    phases = payload.get("phases")
    phase_count = len(phases) if isinstance(phases, list) else 0
    token = generated_by.strip() if isinstance(generated_by, str) else None
    return token, phase_count


def _load_report_quality(client: DynamicEvalClient, event_id: str) -> str | None:
    try:
        payload = client.get_json(f"/api/v1/events/{event_id}/report")
    except DynamicEvalApiError:
        return None
    if not isinstance(payload, dict):
        return None
    report = payload.get("report")
    if not isinstance(report, dict):
        return None
    quality = report.get("report_quality")
    return quality.strip() if isinstance(quality, str) and quality.strip() else None


def assert_llm_quality_acceptance(
    client: DynamicEvalClient,
    event_id: str,
) -> dict[str, Any]:
    """Live reasoning card: per-event llm_call_log + template/exfil FAIL."""
    payload = client.get_json(f"/api/v1/events/{event_id}")
    if not isinstance(payload, dict):
        raise DynamicEvalApiError(f"unexpected event detail payload: {payload!r}")
    event = unwrap_event_detail_payload(payload, expected_event_id=event_id)
    trace_entries = _paginate_decision_trace(
        client,
        event_id,
        entry_types=("llm_call", "agent_execution"),
    )
    llm_calls = collect_llm_calls_from_trace(trace_entries)
    generated_by = _generated_by_from_event(event) or _generated_by_from_trace(trace_entries)
    strategy = _response_strategy_from_trace(trace_entries)
    storyline_generated_by, storyline_phase_count = _load_storyline_adoption(client, event_id)
    report_quality = _load_report_quality(client, event_id)
    return evaluate_llm_quality(
        event_id=event_id,
        event_type=str(event.get("event_type") or "") or None,
        final_verdict=str(event.get("final_verdict") or "") or None,
        scenario_id=_scenario_from_event(event),
        response_plan_generated_by=generated_by,
        llm_calls=llm_calls,
        storyline_generated_by=storyline_generated_by,
        storyline_phase_count=storyline_phase_count,
        report_quality=report_quality,
        response_plan_strategy=strategy,
    )
