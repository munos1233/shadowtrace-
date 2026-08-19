#!/usr/bin/env python3
"""Gold-path dynamic eval: mock-xdr seed → full_loop investigate → scripted approval.

ISSUE-256 / R2-010 / R2-011 / R2-017 / R2-018 / R2-019.

Industrial fixture contract
---------------------------
1. Events **must** come from ``scripts/seed_mock_xdr_and_ingest.py`` (mock-xdr
   control seed + SourceAdapter poll). Hand-crafted ``POST /api/v1/events`` is
   **not** the gold path — Mock has no entities → Evidence fails.
2. Investigate with ``include_response_execution=true`` (and usually
   ``generate_report=true``).
3. Human gates are closed by ``dynamic_eval_approve`` — **never** by waiting
   for production ``APPROVAL_TIMEOUT_MINUTES=30``.
4. Production defaults stay unchanged; use the eval env profile in docs /
   ``.env.example`` comments for short approval / LLM timeouts.

Usage (recommended)::

    # Stack with worker (demo or WORKER=1). Prefer 1 scenario for predictable latency.
    make up-demo   # or: make up WORKER=1
    python3 scripts/dynamic_eval_full_loop.py --seed-via-compose \\
        --scenario insider_data_exfiltration

    # Makefile one-liner:
    make eval-full-loop
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _SCRIPTS_DIR.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from dynamic_eval_approve import (  # noqa: E402
    SUCCESSISH_EVENT_STATUSES,
    DynamicEvalApiError,
    DynamicEvalClient,
    approve_or_reject_pending,
    list_event_actions,
    select_pending_actions,
    unwrap_event_detail_payload,
)
from strict_closed_acceptance import (  # noqa: E402
    STRICT_ASSERT_POLL_S as _STRICT_ASSERT_POLL_S,
    assert_strict_closed_acceptance,
    get_event_detail,
    list_all_event_actions,
    strict_assert_budget as _strict_assert_budget,
)
from strict_llm_quality import assert_llm_quality_acceptance  # noqa: E402
from dynamic_eval_diagnostics import (  # noqa: E402
    collect_event_diagnostics,
    format_eval_failure_message,
)
from dynamic_eval_profiles import (  # noqa: E402
    profile_for_scenario,
    scenario_requires_demo_baseline,
)

# Demo scenarios from bootstrap / ISSUE-088. Gold path uses one at a time by default.
GOLD_SCENARIOS = (
    "insider_data_exfiltration",
    "account_anomaly_fp",
    "suspicious_domain_access",
)

# Event statuses that mean the pipeline is still progressing (do not approve yet).
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
    }
)

# Past these statuses, evidence summary must be present and non-failed (ISSUE-256).
_EVIDENCE_REQUIRED_STATUSES = frozenset(
    {
        "scoring",
        "planning_response",
        "waiting_approval",
        "executing_response",
        "verifying",
        "replanning",
        "reporting",
        "contained",
        "closed",
    }
)
_EVIDENCE_OK_STATUSES = frozenset({"completed", "partial_done", "degraded"})
# waiting_approval with zero selectable actions for this many polls → fail fast.
_WAITING_STALL_POLLS = 5

# Semantic gates assert status==closed; do not treat reporting/contained as done
# (poll can observe REPORTING before close_node finishes — ISSUE-313).
_ANALYSIS_ONLY_TERMINAL = frozenset({"closed"})


class EvalFailure(RuntimeError):
    """Eval failure with structured diagnostics attached."""

    def __init__(
        self,
        message: str,
        *,
        event_id: str | None = None,
        diagnostics: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.event_id = event_id
        self.diagnostics = diagnostics or {}


def _raise_eval_failure(
    client: DynamicEvalClient,
    *,
    headline: str,
    event_id: str,
    status_trace: list[str] | None = None,
    elapsed_s: float | None = None,
) -> None:
    diagnostics = collect_event_diagnostics(
        client,
        event_id,
        status_trace=status_trace,
        elapsed_s=elapsed_s,
    )
    soft_limit_diag = format_soft_limit_failure_diagnostics(client, event_id)
    diagnostics["soft_limit_diagnostics"] = soft_limit_diag
    message = format_eval_failure_message(
        headline=headline,
        event_id=event_id,
        diagnostics=diagnostics,
    )
    if soft_limit_diag:
        message = f"{message}\nsoft_limit_diagnostics={soft_limit_diag}"
    raise EvalFailure(
        message,
        event_id=event_id,
        diagnostics=diagnostics,
    )


def _compose_cmd() -> list[str]:
    worktree_id = (
        subprocess.check_output(
            ["bash", "-c", f"printf '%s' '{_ROOT_DIR}' | cksum | cut -d ' ' -f 1"],
            text=True,
        ).strip()
    )
    project = os.environ.get("COMPOSE_PROJECT_NAME") or f"shadowtrace-{worktree_id}"
    compose_file = str(_ROOT_DIR / "infra" / "docker-compose.yml")
    return [
        "docker",
        "compose",
        "--project-name",
        project,
        "-f",
        compose_file,
    ]


def flush_mock_observation_via_compose() -> None:
    """Drop leftover mock observation projection keys before gold-path seed."""
    cmd = _compose_cmd() + [
        "exec",
        "-T",
        "redis",
        "redis-cli",
        "DEL",
        "shadowtrace:mock_observation_projection",
        "shadowtrace:mock_observation_idempotency",
    ]
    print("[dynamic-eval] flushing mock observation projection keys")
    proc = subprocess.run(cmd, cwd=_ROOT_DIR, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(
            "[dynamic-eval] WARN: observation key flush skipped "
            f"(exit={proc.returncode}): {proc.stderr.strip()}",
            file=sys.stderr,
        )


def seed_via_compose(
    *,
    scenario: str,
    mock_xdr_url: str,
    seed: int,
    instance: int = 0,
) -> dict[str, Any]:
    """Seed mock-xdr + SourceAdapter ingest inside the backend container."""
    cmd = _compose_cmd() + [
        "exec",
        "-T",
        "backend",
        "python3",
        "scripts/seed_mock_xdr_and_ingest.py",
        "--scenario",
        scenario,
        "--mock-xdr-url",
        mock_xdr_url,
        "--seed",
        str(seed),
        "--instance",
        str(instance),
    ]
    print(f"[dynamic-eval] seeding via compose: scenario={scenario}")
    proc = subprocess.run(cmd, cwd=_ROOT_DIR, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        combined = f"{proc.stdout}\n{proc.stderr}"
        if "dirty fixture" in combined:
            raise RuntimeError(
                "dirty fixture, run down-v or --fresh-volumes "
                f"(or retry with --instance N+1; exit={proc.returncode}):\n"
                f"{proc.stdout}\n{proc.stderr}"
            )
        raise RuntimeError(
            "seed_mock_xdr_and_ingest failed "
            f"(exit={proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
        )
    # Script may print pretty-printed (indent=2) JSON mixed with log lines.
    stdout = proc.stdout.strip()
    summary = parse_seed_stdout(stdout)
    accepted = summary.get("accepted")
    if not isinstance(accepted, int) or accepted < 1:
        raise RuntimeError(
            "seed_mock_xdr_and_ingest returned no accepted events "
            f"(summary={summary!r}). Refusing to continue gold path."
        )
    return summary


def extract_json_objects(text: str) -> list[dict[str, Any]]:
    """Extract top-level JSON objects from mixed / pretty-printed stdout."""
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    idx = 0
    while idx < len(text):
        start = text.find("{", idx)
        if start < 0:
            break
        try:
            obj, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            idx = start + 1
            continue
        if isinstance(obj, dict):
            objects.append(obj)
        idx = end
    return objects


def parse_seed_stdout(stdout: str) -> dict[str, Any]:
    """Prefer the last ingest-style summary (has ``accepted``); else last object."""
    objects = extract_json_objects(stdout)
    if not objects:
        return {"raw_stdout": stdout}
    for obj in reversed(objects):
        if "accepted" in obj:
            return obj
    return objects[-1]


def unwrap_event_detail(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize GET /events/{id} — flat SecurityEvent or EventDetailResponse envelope."""
    return unwrap_event_detail_payload(payload)


def get_event(client: DynamicEvalClient, event_id: str) -> dict[str, Any]:
    payload = client.get_json(f"/api/v1/events/{event_id}")
    return unwrap_event_detail_payload(payload, expected_event_id=event_id)


def list_events(client: DynamicEvalClient, *, page_size: int = 50) -> list[dict[str, Any]]:
    payload = client.get_json(f"/api/v1/events?page_size={page_size}")
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise DynamicEvalApiError(f"unexpected events payload: {payload!r}")
    return [item for item in items if isinstance(item, dict)]


def list_new_events(client: DynamicEvalClient, *, page_size: int = 50) -> list[dict[str, Any]]:
    return [
        item
        for item in list_events(client, page_size=page_size)
        if str(item.get("status") or "") == "new"
    ]


def select_gold_event_ids(
    events: list[dict[str, Any]],
    *,
    max_events: int,
    scenario: str,
    before_ids: set[str] | None = None,
) -> list[str]:
    """Pick NEW events for the gold path, preferring this seed's fresh IDs."""
    new_events = [item for item in events if str(item.get("status") or "") == "new"]
    if before_ids is not None:
        fresh = [
            item
            for item in new_events
            if str(item.get("event_id") or "") not in before_ids
        ]
        if fresh:
            new_events = fresh

    scenario_key = scenario.lower().replace("_", " ")

    def _matches_scenario(item: dict[str, Any]) -> bool:
        blob = " ".join(
            str(item.get(key) or "").lower()
            for key in ("title", "description", "event_type", "source_type")
        )
        return scenario.lower() in blob or scenario_key in blob

    matched = [item for item in new_events if _matches_scenario(item)]
    pool = matched if matched else new_events
    pool = sorted(
        pool,
        key=lambda item: str(item.get("created_at") or item.get("event_id") or ""),
        reverse=True,
    )
    if not pool:
        return []
    return [str(item["event_id"]) for item in pool[: max(1, max_events)]]


def collection_status_from_event(event: dict[str, Any]) -> str | None:
    snap = event.get("event_context_snapshot")
    if not isinstance(snap, dict):
        return None
    raw = snap.get("collection_status")
    if raw is None and isinstance(snap.get("evidence_summary"), dict):
        raw = snap["evidence_summary"].get("collection_status")
    if raw is None:
        return None
    return str(raw)


def assert_evidence_ok(event: dict[str, Any], *, event_id: str) -> str:
    """Require non-failed evidence observability (gold-path acceptance)."""
    status = collection_status_from_event(event)
    if status is None:
        raise RuntimeError(
            f"gold-path evidence missing for {event_id}: "
            "event_context_snapshot has no collection_status "
            "(use seed_mock_xdr_and_ingest, not hand-crafted POST /events)."
        )
    if status == "failed" or status not in _EVIDENCE_OK_STATUSES:
        raise RuntimeError(
            f"gold-path evidence not acceptable for {event_id}: "
            f"collection_status={status!r} (expected one of "
            f"{sorted(_EVIDENCE_OK_STATUSES)})."
        )
    return status


def format_soft_limit_failure_diagnostics(
    client: DynamicEvalClient,
    event_id: str,
) -> str:
    """Summarize audit + intent + checkpoint hints when eval hits FAILED (ISSUE-314)."""
    parts: list[str] = [f"event_id={event_id!r}"]
    try:
        audit = client.get_json(f"/api/v1/events/{event_id}/audit-logs?page=1&page_size=20")
        items = audit.get("items") if isinstance(audit, dict) else None
        if isinstance(items, list):
            for row in reversed(items):
                if not isinstance(row, dict):
                    continue
                reason = str(row.get("reason") or "")
                if "soft_time_limit" in reason or reason.endswith(":exception"):
                    parts.append(
                        "audit_reason="
                        f"{reason!r} operator={row.get('operator')!r} "
                        f"to={row.get('to_status')!r}"
                    )
                    break
    except Exception as exc:
        parts.append(f"audit_unavailable={exc!r}")
    try:
        event = get_event(client, event_id)
        snap = event.get("event_context_snapshot")
        node_hint = None
        checkpoint_hint = None
        if isinstance(snap, dict):
            trace = snap.get("node_trace")
            if isinstance(trace, list) and trace:
                node_hint = str(trace[-1])
            for key in (
                "last_checkpoint_node",
                "checkpoint_node",
                "graph_checkpoint_node",
            ):
                if snap.get(key) is not None:
                    checkpoint_hint = str(snap.get(key))
                    break
        parts.append(
            f"event_status={event.get('status')!r} last_node={node_hint!r} "
            f"checkpoint_node={checkpoint_hint!r}"
        )
        try:
            from dynamic_eval_diagnostics import _intent_summary

            intent, intent_error = _intent_summary(
                client,
                event_id,
                snapshot=snap if isinstance(snap, dict) else None,
                detail={"event": event},
            )
            if intent is not None:
                parts.append(
                    "intent_id="
                    f"{intent.get('intent_id')!r} intent_status={intent.get('status')!r}"
                )
            elif intent_error:
                parts.append(f"intent_unavailable={intent_error!r}")
            else:
                parts.append("intent_status=None")
        except Exception as exc:
            parts.append(f"intent_unavailable={exc!r}")
    except Exception as exc:
        parts.append(f"event_unavailable={exc!r}")
    return "; ".join(parts) if parts else "no_soft_limit_correlation_found"


def trigger_investigate(
    client: DynamicEvalClient,
    event_id: str,
    *,
    include_response_execution: bool,
    generate_report: bool = True,
) -> dict[str, Any]:
    """POST investigate with explicit response/report flags."""
    body = {
        "include_response_execution": include_response_execution,
        "generate_report": generate_report,
        "force_replan": False,
    }
    resp = client.post_json(f"/api/v1/events/{event_id}/investigate", body)
    if resp.status not in (200, 202):
        raise DynamicEvalApiError(
            f"investigate {event_id} failed HTTP {resp.status}: {resp.data}"
        )
    data = resp.data if isinstance(resp.data, dict) else {}
    if data.get("include_response_execution") is not include_response_execution:
        raise DynamicEvalApiError(
            "investigate response missing expected include_response_execution="
            f"{include_response_execution} — got {data!r}"
        )
    return data


def trigger_full_loop(
    client: DynamicEvalClient,
    event_id: str,
    *,
    generate_report: bool = True,
) -> dict[str, Any]:
    """POST investigate with include_response_execution=true (gold path)."""
    return trigger_investigate(
        client,
        event_id,
        include_response_execution=True,
        generate_report=generate_report,
    )


def trigger_analysis_only(
    client: DynamicEvalClient,
    event_id: str,
    *,
    generate_report: bool = True,
) -> dict[str, Any]:
    """POST investigate without response execution (semantic gate path)."""
    return trigger_investigate(
        client,
        event_id,
        include_response_execution=False,
        generate_report=generate_report,
    )


def event_outcome_ok(status: str, *, require_closed: bool = False) -> bool:
    """True when status is an acceptable non-FAILED gold-path outcome."""
    if status == "failed":
        return False
    if require_closed:
        return status == "closed"
    return status in SUCCESSISH_EVENT_STATUSES or status == "waiting_approval"


def _terminal_enough(status: str, *, require_closed: bool) -> bool:
    if require_closed:
        return status == "closed"
    return status in SUCCESSISH_EVENT_STATUSES


def assert_fp_semantic_gate(client: DynamicEvalClient, event_id: str) -> dict[str, Any]:
    """Analysis-only FP semantic gate: CLOSED + false_positive verdict."""
    event = get_event(client, event_id)
    status = str(event.get("status") or "")
    verdict = str(event.get("final_verdict") or "")
    if status != "closed":
        diagnostics = collect_event_diagnostics(client, event_id)
        raise EvalFailure(
            format_eval_failure_message(
                headline=(
                    f"FP semantic gate requires status=closed, got {status!r} "
                    f"(final_verdict={verdict!r})"
                ),
                event_id=event_id,
                diagnostics=diagnostics,
            ),
            event_id=event_id,
            diagnostics=diagnostics,
        )
    if verdict != "false_positive":
        diagnostics = collect_event_diagnostics(client, event_id)
        raise EvalFailure(
            format_eval_failure_message(
                headline=(
                    f"FP semantic gate requires final_verdict=false_positive, got {verdict!r}"
                ),
                event_id=event_id,
                diagnostics=diagnostics,
            ),
            event_id=event_id,
            diagnostics=diagnostics,
        )
    return {
        "status": status,
        "final_verdict": verdict,
        "disposition_policy": event.get("disposition_policy"),
    }


def assert_domain_semantic_gate(client: DynamicEvalClient, event_id: str) -> dict[str, Any]:
    """Analysis-only domain semantic gate: CLOSED without response pressure."""
    event = get_event(client, event_id)
    status = str(event.get("status") or "")
    verdict = str(event.get("final_verdict") or "")
    if status != "closed":
        diagnostics = collect_event_diagnostics(client, event_id)
        raise EvalFailure(
            format_eval_failure_message(
                headline=(
                    f"domain semantic gate requires status=closed, got {status!r} "
                    f"(final_verdict={verdict!r})"
                ),
                event_id=event_id,
                diagnostics=diagnostics,
            ),
            event_id=event_id,
            diagnostics=diagnostics,
        )
    return {
        "status": status,
        "final_verdict": verdict,
        "disposition_policy": event.get("disposition_policy"),
    }


def run_analysis_only_loop(
    client: DynamicEvalClient,
    *,
    event_ids: list[str],
    generate_report: bool,
    poll_interval_s: float,
    max_wait_s: float,
    semantic_profile: str,
) -> dict[str, Any]:
    """Drive analysis-only investigate until semantic terminal acceptance."""
    started = time.monotonic()
    triggered: list[dict[str, Any]] = []
    status_trace: dict[str, list[str]] = {eid: [] for eid in event_ids}
    last_seen: dict[str, str | None] = {eid: None for eid in event_ids}
    for event_id in event_ids:
        inv = trigger_analysis_only(
            client,
            event_id,
            generate_report=generate_report,
        )
        triggered.append({"event_id": event_id, "investigate": inv})
        print(
            f"[dynamic-eval] triggered analysis_only event_id={event_id} "
            f"generate_report={generate_report}"
        )

    finals: dict[str, str] = {}
    evidence_statuses: dict[str, str] = {}
    semantic_assertions: dict[str, Any] = {}

    while True:
        elapsed = time.monotonic() - started
        if elapsed > max_wait_s:
            sample_id = event_ids[0]
            _raise_eval_failure(
                client,
                headline=(
                    f"analysis-only semantic gate exceeded max_wait_s={max_wait_s} "
                    f"(elapsed={elapsed:.1f}s)"
                ),
                event_id=sample_id,
                status_trace=status_trace.get(sample_id),
                elapsed_s=elapsed,
            )

        all_done = True
        for event_id in event_ids:
            event = get_event(client, event_id)
            status = str(event.get("status") or "")
            finals[event_id] = status
            if status != last_seen[event_id]:
                status_trace[event_id].append(status)
                last_seen[event_id] = status

            if status == "failed":
                _raise_eval_failure(
                    client,
                    headline=f"analysis-only semantic gate FAILED for {event_id}",
                    event_id=event_id,
                    status_trace=status_trace[event_id],
                    elapsed_s=elapsed,
                )

            if status in _EVIDENCE_REQUIRED_STATUSES:
                evidence_statuses[event_id] = assert_evidence_ok(
                    event, event_id=event_id
                )

            if status not in _ANALYSIS_ONLY_TERMINAL:
                all_done = False

        if all_done:
            break
        time.sleep(poll_interval_s)

    for event_id in event_ids:
        if semantic_profile == "analysis_only_fp":
            semantic_assertions[event_id] = assert_fp_semantic_gate(client, event_id)
        elif semantic_profile == "analysis_only_domain":
            semantic_assertions[event_id] = assert_domain_semantic_gate(client, event_id)
        else:
            raise EvalFailure(
                f"unsupported analysis-only semantic profile: {semantic_profile!r}",
                event_id=event_id,
            )

    return {
        "triggered": triggered,
        "decisions": {},
        "final_statuses": finals,
        "evidence_statuses": evidence_statuses,
        "status_trace": status_trace,
        "semantic_assertions": semantic_assertions,
        "strict_assertions": None,
        "profile": semantic_profile,
        "elapsed_s": round(time.monotonic() - started, 2),
        "approval_timeout_used": False,
        "fixture": "seed_mock_xdr_and_ingest",
        "include_response_execution": False,
    }


def run_gold_loop(
    client: DynamicEvalClient,
    *,
    event_ids: list[str],
    decision: str,
    generate_report: bool,
    poll_interval_s: float,
    max_wait_s: float,
    require_closed: bool = False,
) -> dict[str, Any]:
    """Drive investigate → scripted approve/reject → non-FAILED assertion."""
    started = time.monotonic()
    triggered: list[dict[str, Any]] = []
    status_trace: dict[str, list[str]] = {eid: [] for eid in event_ids}
    last_seen: dict[str, str | None] = {eid: None for eid in event_ids}
    for event_id in event_ids:
        inv = trigger_full_loop(client, event_id, generate_report=generate_report)
        triggered.append({"event_id": event_id, "investigate": inv})
        print(
            f"[dynamic-eval] triggered full_loop event_id={event_id} "
            f"generate_report={generate_report}"
        )

    decisions: dict[str, list[dict[str, Any]]] = {eid: [] for eid in event_ids}
    decided_ids: set[str] = set()
    finals: dict[str, str] = {}
    evidence_statuses: dict[str, str] = {}
    waiting_stall: dict[str, int] = {eid: 0 for eid in event_ids}

    while True:
        elapsed = time.monotonic() - started
        if elapsed > max_wait_s:
            sample_id = next(iter(finals), event_ids[0])
            _raise_eval_failure(
                client,
                headline=(
                    f"gold-path exceeded max_wait_s={max_wait_s} "
                    f"(elapsed={elapsed:.1f}s). finals={finals!r}. "
                    "Do NOT raise APPROVAL_TIMEOUT to 'finish' the eval — "
                    "script approve/reject instead."
                ),
                event_id=sample_id,
                status_trace=status_trace.get(sample_id),
                elapsed_s=elapsed,
            )

        all_done = True
        for event_id in event_ids:
            event = get_event(client, event_id)
            status = str(event.get("status") or "")
            finals[event_id] = status
            if status != last_seen[event_id]:
                status_trace[event_id].append(status)
                last_seen[event_id] = status

            if status == "failed":
                _raise_eval_failure(
                    client,
                    headline=f"gold-path FAILED for {event_id}",
                    event_id=event_id,
                    status_trace=status_trace[event_id],
                    elapsed_s=elapsed,
                )

            if status in _EVIDENCE_REQUIRED_STATUSES:
                evidence_statuses[event_id] = assert_evidence_ok(
                    event, event_id=event_id
                )

            if status == "waiting_approval" or status in _IN_FLIGHT:
                all_done = False
            elif require_closed and status != "closed":
                all_done = False

            # Always drain waiting actions even if event status lags.
            waiting_actions = list_event_actions(
                client, event_id, status="waiting_approval"
            )
            pending = select_pending_actions(waiting_actions)
            if status == "waiting_approval" and not pending:
                waiting_stall[event_id] += 1
                if waiting_stall[event_id] >= _WAITING_STALL_POLLS:
                    raise RuntimeError(
                        f"{event_id} is waiting_approval but no selectable "
                        f"human-gated actions after {_WAITING_STALL_POLLS} polls "
                        f"(waiting rows={len(waiting_actions)}). "
                        "Cannot finish via APPROVAL_TIMEOUT."
                    )
            else:
                waiting_stall[event_id] = 0

            if pending:
                all_done = False
                # Avoid re-deciding the same action_id in a tight loop.
                fresh = [
                    a
                    for a in pending
                    if str(a.get("action_id")) not in decided_ids
                ]
                if fresh:
                    outcomes = approve_or_reject_pending(
                        client,
                        event_id,
                        decision=decision,
                    )
                    for row in outcomes:
                        decided_ids.add(str(row["action_id"]))
                    decisions[event_id].extend(outcomes)
                    print(
                        f"[dynamic-eval] scripted {decision} on {event_id}: "
                        f"{len(outcomes)} action(s)"
                    )

            if _terminal_enough(status, require_closed=require_closed) and not pending:
                continue

        if all_done:
            # Require every event non-failed and not stuck in early phases.
            for event_id, status in finals.items():
                if status in _IN_FLIGHT or status == "new":
                    all_done = False
                    break
                if status == "failed" or not event_outcome_ok(
                    status, require_closed=require_closed
                ):
                    raise RuntimeError(
                        f"unacceptable final status for {event_id}: {status}"
                    )
            if all_done:
                # Final evidence gate for every event.
                for event_id in event_ids:
                    event = get_event(client, event_id)
                    evidence_statuses[event_id] = assert_evidence_ok(
                        event, event_id=event_id
                    )
                break

        time.sleep(poll_interval_s)

    strict_assertions: dict[str, Any] = {}
    if require_closed:
        strict_budget = _strict_assert_budget(
            max_wait_s=max_wait_s,
            elapsed_s=time.monotonic() - started,
        )
        for event_id in event_ids:
            strict_assertions[event_id] = assert_strict_closed_acceptance(
                client,
                event_id,
                max_wait_s=strict_budget,
                poll_interval_s=min(poll_interval_s, _STRICT_ASSERT_POLL_S),
            )

    return {
        "triggered": triggered,
        "decisions": decisions,
        "final_statuses": finals,
        "evidence_statuses": evidence_statuses,
        "status_trace": status_trace,
        "strict_assertions": strict_assertions or None,
        "profile": "strict" if require_closed else "compat",
        "elapsed_s": round(time.monotonic() - started, 2),
        "approval_timeout_used": False,
        "fixture": "seed_mock_xdr_and_ingest",
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "ISSUE-256 gold-path: seed_mock_xdr_and_ingest + full_loop + "
            "scripted approve (never approval timeout)"
        )
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default="bootstrap-token")
    parser.add_argument(
        "--scenario",
        default="insider_data_exfiltration",
        choices=GOLD_SCENARIOS,
        help="Mock-xdr scenario to seed (default: insider_data_exfiltration)",
    )
    parser.add_argument(
        "--seed-via-compose",
        action="store_true",
        help="Run seed_mock_xdr_and_ingest inside the backend container before investigate",
    )
    parser.add_argument(
        "--mock-xdr-url",
        default=os.environ.get("MOCK_XDR_URL", "http://mock-xdr:8100"),
        help="Mock XDR URL as seen from the backend container",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--instance",
        type=int,
        default=0,
        help="Scenario instance suffix for distinct source object IDs (ISSUE-313)",
    )
    parser.add_argument(
        "--event-id",
        action="append",
        default=None,
        help="Existing event_id to drive (repeatable). Skips seed when set.",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=1,
        help="Max NEW events to trigger (default 1 — predictable; 3 with worker -c 2 queues)",
    )
    parser.add_argument(
        "--decision",
        choices=("approve", "reject"),
        default="approve",
    )
    parser.add_argument(
        "--generate-report",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Pass generate_report to investigate (default: true)",
    )
    parser.add_argument("--poll-interval-s", type=float, default=2.0)
    parser.add_argument(
        "--max-wait-s",
        type=float,
        default=float(os.environ.get("DYNAMIC_EVAL_MAX_WAIT_S", "240")),
        help="Hard wall clock (default 240s). Must stay << production approval timeout.",
    )
    parser.add_argument(
        "--require-closed",
        action="store_true",
        help=(
            "ISSUE-301 strict profile: final status must be closed, GET /report "
            "must succeed, and gate-applicable writeback actions must converge"
        ),
    )
    parser.add_argument(
        "--require-llm-quality",
        action="store_true",
        help=(
            "ISSUE-350 live reasoning card: per-event llm_call_log core-prompt "
            "success; template+exfil+confirmed_threat FAIL. Independent of "
            "--require-closed. Never uses GET /health success_rate."
        ),
    )
    parser.add_argument(
        "--analysis-only",
        action="store_true",
        help=(
            "ISSUE-313 semantic gate: investigate with include_response_execution=false "
            "(FP/domain analysis-only acceptance)"
        ),
    )
    parser.add_argument(
        "--semantic-profile",
        choices=("analysis_only_fp", "analysis_only_domain"),
        default=None,
        help="Semantic assertion profile when --analysis-only is set",
    )
    parser.add_argument(
        "--skip-baseline-preflight",
        action="store_true",
        help="Skip tenant-demo change-window baseline preflight (not recommended)",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def _preflight_change_window_baseline(client: DynamicEvalClient, *, scenario: str) -> None:
    if not scenario_requires_demo_baseline(scenario):
        return
    # Prefer in-process assert when the backend package is importable (compose exec).
    try:
        from app.services.change_window_baseline_loader import (
            assert_demo_eval_baseline_available,
        )

        assert_demo_eval_baseline_available()
        return
    except ImportError:
        pass
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    health = client.get_json("/api/v1/health")
    probe = (health or {}).get("change_window_baseline") or {}
    status = str(probe.get("status") or "")
    resolved_path = probe.get("resolved_path") or "(unknown)"
    tenant_ids = [str(item) for item in (probe.get("tenant_ids") or [])]
    reasons = [str(item) for item in (probe.get("reasons") or [])]
    # Demo eval only requires tenant-demo; other tenants may degrade global status.
    demo_empty = any(
        item.startswith("empty_change_windows:")
        and "tenant-demo" in [part.strip() for part in item.split(":", 1)[-1].split(",")]
        for item in reasons
    )
    demo_missing = "tenant-demo" not in tenant_ids or any(
        item.startswith("missing_required_tenants:") and "tenant-demo" in item
        for item in reasons
    )
    if not demo_missing and not demo_empty:
        return
    detail = ", ".join(reasons) if reasons else f"status={status!r}"
    raise SystemExit(
        "change-window baseline preflight failed for scenario="
        f"{scenario!r}: resolved_path={resolved_path!r} ({detail}). "
        "Set CHANGE_WINDOW_BASELINE_PATH or ensure data/organization/change_windows.json "
        "is readable in the backend container."
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.analysis_only and args.require_closed:
        raise SystemExit("--analysis-only cannot be combined with --require-closed")
    if args.require_closed and not args.generate_report:
        raise SystemExit(
            "--require-closed requires report generation; omit --no-generate-report"
        )
    if args.analysis_only and not args.generate_report:
        raise SystemExit(
            "--analysis-only requires report generation to reach CLOSED; "
            "omit --no-generate-report"
        )
    if args.event_id and args.seed_via_compose:
        raise SystemExit(
            "--event-id cannot be combined with --seed-via-compose; "
            "seed emits fresh event_ids (ISSUE-301)"
        )
    if args.max_wait_s >= 30 * 60:
        raise SystemExit(
            "Refusing max-wait-s >= 30 minutes — that recreates the "
            "APPROVAL_TIMEOUT_MINUTES empty-wait anti-pattern (ISSUE-256)."
        )

    client = DynamicEvalClient(base_url=args.base_url, token=args.token)

    if not args.skip_baseline_preflight:
        _preflight_change_window_baseline(client, scenario=str(args.scenario))

    semantic_profile = args.semantic_profile
    if args.analysis_only and semantic_profile is None:
        profile = profile_for_scenario(str(args.scenario))
        if profile.semantic.startswith("analysis_only_"):
            semantic_profile = profile.semantic
        else:
            raise SystemExit(
                f"--analysis-only requires a NOT_REQUIRED semantic profile; "
                f"scenario={args.scenario!r} uses {profile.semantic!r}"
            )

    # Health / playbook readiness (demo honesty).
    health = client.get_json("/api/v1/health")
    pb = (health or {}).get("playbook_resources") or {}
    if pb.get("status") and pb.get("status") != "ready":
        print(
            f"[dynamic-eval] WARN: playbook_resources.status={pb.get('status')!r} "
            "(Response/Playbook binding may fail-soft). Run make bootstrap.",
            file=sys.stderr,
        )

    event_ids = [str(item).strip() for item in (args.event_id or []) if str(item).strip()]
    seed_summary: dict[str, Any] | None = None
    if not event_ids:
        before_ids = {
            str(item["event_id"])
            for item in list_new_events(client)
            if item.get("event_id")
        }
        if args.seed_via_compose:
            flush_mock_observation_via_compose()
            seed_summary = seed_via_compose(
                scenario=args.scenario,
                mock_xdr_url=args.mock_xdr_url,
                seed=args.seed,
                instance=int(args.instance),
            )
            raw_ids = seed_summary.get("event_ids")
            if isinstance(raw_ids, list):
                event_ids = [str(item) for item in raw_ids if item][: int(args.max_events)]
        if not event_ids and args.require_closed:
            if args.seed_via_compose:
                raise SystemExit(
                    "strict profile (--require-closed): seed summary missing event_ids "
                    "(ISSUE-301)"
                )
            raise SystemExit(
                "strict profile (--require-closed) requires explicit event_ids from "
                "seed output or --event-id; heuristic DB selection is forbidden "
                "(ISSUE-301)"
            )
        # Short retry when seed did not emit explicit IDs (legacy compat path).
        if not event_ids:
            for attempt in range(1, 6):
                event_ids = select_gold_event_ids(
                    list_events(client),
                    max_events=int(args.max_events),
                    scenario=str(args.scenario),
                    before_ids=before_ids if args.seed_via_compose else None,
                )
                if event_ids:
                    break
                if attempt < 5:
                    time.sleep(min(2.0, float(args.poll_interval_s)))
        if not event_ids:
            raise SystemExit(
                "No status=new events found for gold path. Re-run with "
                "--seed-via-compose or FORCE_BOOTSTRAP / make down-v reset. "
                "Do not use hand-crafted POST /events as the gold fixture."
            )

    print(
        f"[dynamic-eval] gold path events={event_ids} "
        f"(fixture=seed_mock_xdr_and_ingest, "
        f"include_response_execution={not args.analysis_only})"
    )
    if len(event_ids) > 2 and not args.analysis_only:
        print(
            "[dynamic-eval] NOTE: compose worker uses celery -c 2; "
            f"{len(event_ids)} parallel investigations will queue (R2-017)."
        )

    if args.analysis_only:
        result = run_analysis_only_loop(
            client,
            event_ids=event_ids,
            generate_report=bool(args.generate_report),
            poll_interval_s=float(args.poll_interval_s),
            max_wait_s=float(args.max_wait_s),
            semantic_profile=str(semantic_profile),
        )
    else:
        result = run_gold_loop(
            client,
            event_ids=event_ids,
            decision=args.decision,
            generate_report=bool(args.generate_report),
            poll_interval_s=float(args.poll_interval_s),
            max_wait_s=float(args.max_wait_s),
            require_closed=bool(args.require_closed),
        )
    result["seed_summary"] = seed_summary
    result["scenario"] = args.scenario
    result["event_ids"] = event_ids
    result["require_closed"] = bool(args.require_closed)
    result["require_llm_quality"] = bool(args.require_llm_quality)
    result["analysis_only"] = bool(args.analysis_only)
    result["notes"] = [
        "Gold fixture is seed_mock_xdr_and_ingest — not POST /events.",
        "Approvals were scripted — APPROVAL_TIMEOUT_MINUTES was not used to finish.",
        "Production APPROVAL_TIMEOUT_MINUTES default remains 30.",
        "EMBEDDING_MODE defaults to mock even when LLM_MODE is real (R2-014).",
    ]
    if args.analysis_only:
        result["notes"].append(
            "ISSUE-313 analysis-only semantic gate — response chain is intentionally skipped."
        )
    if args.require_closed:
        result["notes"].append(
            "Strict profile (ISSUE-301): reporting/contained/verifying are not success."
        )
    if args.require_llm_quality:
        quality: dict[str, Any] = {}
        for event_id in event_ids:
            quality[event_id] = assert_llm_quality_acceptance(
                client, event_id, analysis_only=bool(args.analysis_only)
            )
        result["llm_quality"] = quality
        result["notes"].append(
            "Live reasoning card (ISSUE-350): per-event llm_call_log, not /health window."
        )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("[dynamic-eval] final_statuses=", json.dumps(result["final_statuses"]))
        print(
            f"[dynamic-eval] OK elapsed_s={result['elapsed_s']} "
            f"approval_timeout_used={result['approval_timeout_used']}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvalFailure as exc:
        print(f"[dynamic-eval] ERROR: {exc}", file=sys.stderr)
        if exc.diagnostics and "status_trace" not in str(exc):
            print(
                format_eval_failure_message(
                    headline="eval failure diagnostics",
                    event_id=exc.event_id or "(unknown)",
                    diagnostics=exc.diagnostics,
                ),
                file=sys.stderr,
            )
        raise SystemExit(1) from exc
    except (DynamicEvalApiError, RuntimeError, TimeoutError, ValueError) as exc:
        print(f"[dynamic-eval] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
