"""AgentTraceService with TraceProjection for decision_trace audit (ISSUE-028).

Stores redacted, bounded input/output projections so the audit trail reveals
*what* an Agent decided and *which* evidence it cited, without persisting raw
payloads, secrets, prompts, or hidden reasoning chains.

ISSUE-243 / ISSUE-255: every agent_execution must carry a non-empty structured
brief (``decision_summary`` / ``structured_conclusion``) or an explicit
``summary_unavailable`` reason. Coverage includes rag/graph/super/memory typed
projections. Raw CoT keys remain omitted / ``[NOT_RETAINED]``.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Any, Literal

import orjson
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.sanitization import REDACTED, is_sensitive_key, redact_sensitive_text
from app.db import models as orm

logger = logging.getLogger(__name__)

MAX_AUDIT_FIELD_BYTES = 1_048_576
_MAX_DECISION_TEXT_CHARS = 4_096
_MAX_DECISION_SUMMARY_CHARS = 512

# Allowlisted quality-gate tokens for response_agent traces. Keep in sync with
# scripts/strict_llm_quality.py ``_GATE_INJECTION_MARKERS``. Never copy free-text
# ``strategy_summary`` into decision briefs (ISSUE-255).
_RESPONSE_GATE_TRACE_MARKERS = (
    "entity_coverage_merge",
    "identity_containment_dedup",
    "rule fallback after ungrounded",
    "containment_quality_gate_unsatisfied",
    "domain_containment_missing",
)
_MAX_AUDIT_DEPTH = 32
_RAW_KEYS = frozenset({"raw_payload", "raw_data", "source_snapshot", "raw_result", "prompt"})
_COT_KEYS = frozenset(
    {
        "thought",
        "reflection",
        "rationale",
        "chain_of_thought",
        "chain-of-thought",
        "reasoning",
    }
)
_NOT_RETAINED = "[NOT_RETAINED]"
DecisionRationaleMode = Literal["off", "structured", "short_text"]
_VALID_RATIONALE_MODES = frozenset({"off", "structured", "short_text"})

# Fields that TraceProjection extracts for the structured decision_basis summary.
_DECISION_ID_FIELDS = frozenset(
    {
        "event_id",
        "evidence_id",
        "action_id",
        "plan_id",
        "storyline_id",
        "report_id",
        "case_id",
        "trace_id",
    }
)
_DECISION_CONCLUSION_FIELDS = frozenset(
    {
        "decision_summary",
        "structured_conclusion",
        "verdict",
        "final_verdict",
    }
)
_DECISION_EVIDENCE_FIELDS = frozenset(
    {
        "evidence_list",
        "evidence_refs",
        "evidence_output",
        "success_sources",
        "failed_sources",
    }
)
_DECISION_RULES_FIELDS = frozenset(
    {
        "rules_applied",
        "playbook_refs",
        "attack_techniques",
        "mitre_technique",
        "technique_id",
    }
)
_DECISION_MODEL_FIELDS = frozenset(
    {
        "model_name",
        "scoring_mode",
        "generated_by",
        "llm_model",
    }
)
_DECISION_CONFIDENCE_FIELDS = frozenset(
    {
        "confidence",
        "overall_confidence",
        "risk_score",
    }
)
_DECISION_WARNING_FIELDS = frozenset(
    {
        "warnings",
        "degraded",
        "degraded_flags",
        "error_detail",
        "possible_false_positive",
        # ISSUE-241: evidence_limited demotion must stay structured (not CoT).
        "evidence_limited",
        "verdict_reason_codes",
    }
)
_DECISION_ENTITY_FIELDS = frozenset(
    {
        "entity_provenance_summary",
        "entity_conflicts",
        "entity_rejection_summary",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def _hasher(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _normalize_scalar(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return redact_sensitive_text(value) if isinstance(value, str) else value
    if isinstance(value, bytes):
        return redact_sensitive_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return _normalize_scalar(value.value)
    return redact_sensitive_text(str(value))


def _audit_hash_reference(value: Any, *, reason: str) -> dict[str, Any]:
    projected = _project_tree(value, project_raw=False)
    encoded = _canonical_bytes(projected)
    return {
        "_redacted": True,
        "reason": reason,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "size_bytes": len(encoded),
    }


def _is_raw_key(key: str) -> bool:
    lowered = key.lower()
    return (
        lowered in _RAW_KEYS
        or "raw_payload" in lowered
        or "raw_data" in lowered
        or "prompt" in lowered
    )


def _project_tree(value: Any, *, project_raw: bool = True, depth: int = 0) -> Any:
    """Recursively sanitize a value: redact secrets, hash raw payloads, bound size."""
    if depth > _MAX_AUDIT_DEPTH:
        return {"_redacted": True, "reason": "max_depth_exceeded"}
    if isinstance(value, Mapping):
        projected: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if project_raw and _is_raw_key(key):
                projected[key] = _audit_hash_reference(item, reason="raw_block")
            elif depth == 0 and key.lower() in _COT_KEYS:
                continue
            elif is_sensitive_key(key):
                projected[key] = REDACTED
            else:
                projected[key] = _project_tree(item, project_raw=project_raw, depth=depth + 1)
        return projected
    if isinstance(value, list | tuple):
        return [_project_tree(item, project_raw=project_raw, depth=depth + 1) for item in value]
    if isinstance(value, set | frozenset):
        projected_items = [
            _project_tree(item, project_raw=project_raw, depth=depth + 1) for item in value
        ]
        return sorted(projected_items, key=_canonical_bytes)
    return _normalize_scalar(value)


def _truncate_text(value: str, max_chars: int = _MAX_DECISION_TEXT_CHARS) -> str:
    cleaned = redact_sensitive_text(value)
    if len(cleaned) <= max_chars:
        return cleaned
    return f"{cleaned[:max_chars]}[TRUNCATED sha256={_hasher(cleaned)}]"


def _extract_scalar(data: dict[str, Any], keys: frozenset[str]) -> Any:
    """Extract the first matching value from a dict by key name."""
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _collect_refs(data: dict[str, Any], keys: frozenset[str]) -> list[str]:
    """Collect reference IDs from named list/dict fields."""
    refs: list[str] = []
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    _ref_keys = (
                        "evidence_id",
                        "action_id",
                        "case_id",
                        "technique_id",
                        "citation_id",
                    )
                    for id_key in _ref_keys:
                        if id_key in item:
                            refs.append(str(item[id_key]))
        elif isinstance(value, Mapping):
            for id_key in ("evidence_id", "action_id", "case_id"):
                if id_key in value:
                    refs.append(str(value[id_key]))
    return refs[:100]


def _normalize_agent_name(agent_name: str | None) -> str:
    if not agent_name:
        return ""
    name = str(agent_name).strip()
    if not name:
        return ""
    if name.endswith("Agent") and "_" not in name and name != "Agent":
        return f"{name[: -len('Agent')].lower()}_agent"
    return name.lower()


def _as_mapping(value: Any) -> dict[str, Any] | None:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return dict(value)
    return None


def response_gate_trace_tokens(strategy: Any) -> list[str]:
    """Return quality-gate injection markers present in a response strategy."""
    text = strategy if isinstance(strategy, str) else ""
    return [marker for marker in _RESPONSE_GATE_TRACE_MARKERS if marker in text]


def _safe_scalar_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned or cleaned == _NOT_RETAINED:
            return None
        return _truncate_text(cleaned, _MAX_DECISION_SUMMARY_CHARS)
    if isinstance(value, Enum):
        return _safe_scalar_text(value.value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _existing_structured_conclusion(data: dict[str, Any]) -> str | None:
    """Return an already-safe conclusion field; never fall back to CoT/narrative."""
    for key in ("decision_summary", "structured_conclusion", "verdict", "final_verdict"):
        text = _safe_scalar_text(data.get(key))
        if text is not None:
            return text
    return None


def _join_kv(parts: list[str]) -> str:
    return " ".join(part for part in parts if part).strip()[:_MAX_DECISION_SUMMARY_CHARS]


def _synthesize_from_typed_fields(agent_name: str | None, data: dict[str, Any]) -> str:
    """Rule-based brief from typed agent fields (no CoT / free narrative keys)."""
    name = _normalize_agent_name(agent_name)

    if name == "triage_agent":
        notes = data.get("notes")
        note_bits: list[str] = []
        if isinstance(notes, list):
            note_bits = [
                str(item).strip()
                for item in notes[:5]
                if item is not None and str(item).strip() and str(item).strip() != _NOT_RETAINED
            ]
        base = _join_kv(
            [
                f"event_type={data.get('event_type')}"
                if data.get("event_type") is not None
                else "",
                f"severity={data.get('severity')}" if data.get("severity") is not None else "",
                f"need_investigation={data.get('need_investigation')}"
                if data.get("need_investigation") is not None
                else "",
            ]
        )
        if note_bits:
            joined = "; ".join(note_bits)
            return _truncate_text(
                f"{base}; {joined}" if base else joined, _MAX_DECISION_SUMMARY_CHARS
            )
        return base

    if name == "risk_agent":
        return _join_kv(
            [
                f"risk_score={data.get('risk_score')}"
                if data.get("risk_score") is not None
                else "",
                f"severity={data.get('severity')}" if data.get("severity") is not None else "",
                f"mode={data.get('scoring_mode')}" if data.get("scoring_mode") is not None else "",
            ]
        )

    if name == "evidence_agent":
        query_timings = data.get("query_timings") or []
        query_count = len(query_timings) if isinstance(query_timings, list) else 0
        empty_ok_count = 0
        if isinstance(query_timings, list):
            empty_ok_count = sum(
                1
                for row in query_timings
                if isinstance(row, Mapping)
                and (
                    row.get("tool_outcome") == "tool_ok_empty"
                    or row.get("gap_reason") == "no_records"
                    or row.get("status") == "tool_ok_empty"
                )
            )
        query_plan = data.get("query_plan") if isinstance(data.get("query_plan"), Mapping) else {}
        degraded = query_plan.get("degraded_reasons") if isinstance(query_plan, Mapping) else None
        if isinstance(degraded, list) and degraded:
            return _truncate_text(
                ",".join(str(item) for item in degraded if item is not None),
                _MAX_DECISION_SUMMARY_CHARS,
            )
        return _join_kv(
            [
                f"collection_status={data.get('collection_status')}"
                if data.get("collection_status") is not None
                else "",
                f"queries={query_count}",
                f"tool_ok_empty={empty_ok_count}" if empty_ok_count else "",
            ]
        )

    if name == "planner_agent":
        steps = data.get("steps") or []
        if isinstance(steps, list) and steps and isinstance(steps[0], Mapping):
            goal = _safe_scalar_text(steps[0].get("step_goal"))
            if goal:
                return goal
        plan_id = data.get("plan_id")
        revision = data.get("revision")
        return _join_kv(
            [
                f"plan_id={plan_id}" if plan_id is not None else "",
                f"revision={revision}" if revision is not None else "",
                f"steps={len(steps) if isinstance(steps, list) else 0}",
            ]
        )

    if name == "response_agent":
        actions = data.get("actions") or []
        action_count = len(actions) if isinstance(actions, list) else 0
        gate_hits = response_gate_trace_tokens(data.get("strategy_summary"))
        return _join_kv(
            [
                f"response_plan actions={action_count}",
                f"plan_id={data.get('plan_id') or 'none'}",
                f"generated_by={data.get('generated_by') or 'unknown'}",
                f"gates={','.join(gate_hits)}" if gate_hits else "",
            ]
        )

    if name == "verify_agent":
        results = data.get("results") or []
        failed_actions = data.get("failed_actions") or []
        return _join_kv(
            [
                f"overall_status={data.get('overall_status') or 'unknown'}",
                f"verification_phase={data.get('verification_phase') or 'unknown'}",
                f"results={len(results) if isinstance(results, list) else 0}",
                f"failed_actions={len(failed_actions) if isinstance(failed_actions, list) else 0}",
            ]
        )

    if name == "report_agent":
        return _join_kv(
            [
                f"report_id={data.get('report_id')}" if data.get("report_id") is not None else "",
                f"status={data.get('status')}" if data.get("status") is not None else "",
                f"quality={data.get('quality_status')}"
                if data.get("quality_status") is not None
                else "",
            ]
        )

    if name == "rag_agent":
        techniques = data.get("attack_techniques") or []
        similar = data.get("similar_cases") or []
        playbooks = data.get("playbook_refs") or []
        citations = data.get("citations") or []
        raw_fp = data.get("fp_similarity")
        fp: Mapping[Any, Any] = raw_fp if isinstance(raw_fp, Mapping) else {}
        technique_ids: list[str] = []
        if isinstance(techniques, list):
            for item in techniques[:3]:
                if isinstance(item, Mapping) and item.get("technique_id") is not None:
                    technique_ids.append(str(item["technique_id"]))
        return _join_kv(
            [
                f"techniques={len(techniques) if isinstance(techniques, list) else 0}",
                f"top={','.join(technique_ids)}" if technique_ids else "",
                f"fp_max={fp.get('max_score')}" if fp.get("max_score") is not None else "",
                f"similar_cases={len(similar) if isinstance(similar, list) else 0}",
                f"playbook_refs={len(playbooks) if isinstance(playbooks, list) else 0}",
                f"citations={len(citations) if isinstance(citations, list) else 0}",
                f"degraded={_safe_scalar_text(data.get('degraded'))}"
                if data.get("degraded") is not None
                else "",
            ]
        )

    if name == "graph_agent":
        nodes = data.get("nodes") or []
        edges = data.get("edges") or []
        central = data.get("central_entities") or []
        paths = data.get("attack_path_candidates") or []
        central_preview = ""
        if isinstance(central, list) and central:
            central_preview = ",".join(str(item) for item in central[:3] if item is not None)
        return _join_kv(
            [
                f"nodes={len(nodes) if isinstance(nodes, list) else 0}",
                f"edges={len(edges) if isinstance(edges, list) else 0}",
                f"central={central_preview}" if central_preview else "",
                f"attack_paths={len(paths) if isinstance(paths, list) else 0}",
                f"degraded={_safe_scalar_text(data.get('degraded'))}"
                if data.get("degraded") is not None
                else "",
                f"degraded_reason={_safe_scalar_text(data.get('degraded_reason'))}"
                if _safe_scalar_text(data.get("degraded_reason"))
                else "",
            ]
        )

    if name == "memory_agent":
        cases = data.get("case_records") or []
        fp_rules = data.get("fp_rules") or []
        profiles = data.get("profile_updates") or []
        sigma = data.get("sigma_drafts") or []
        return _join_kv(
            [
                f"case_records={len(cases) if isinstance(cases, list) else 0}",
                f"fp_rules={len(fp_rules) if isinstance(fp_rules, list) else 0}",
                f"profile_updates={len(profiles) if isinstance(profiles, list) else 0}",
                f"sigma_drafts={len(sigma) if isinstance(sigma, list) else 0}",
            ]
        )

    if name in {"react_engine", "super_agent"}:
        # SuperAgent wraps InvestigationResult in AgentOutput.data; ReAct may
        # put typed fields at the top level. Never promote nested narrative.
        nested = data.get("data") if isinstance(data.get("data"), Mapping) else {}

        def _pick(key: str) -> Any:
            if key != "data" and key in data and data[key] is not None:
                return data[key]
            if isinstance(nested, Mapping):
                return nested.get(key)
            return None

        parts: list[str] = []
        for key in (
            "final_status",
            "final_verdict",
            "reason_code",
            "selected_action",
            "report_id",
        ):
            text = _safe_scalar_text(_pick(key))
            if text:
                parts.append(f"{key}={text}")
        writeback_required = _pick("writeback_required")
        if writeback_required is not None:
            wb_text = _safe_scalar_text(writeback_required)
            if wb_text:
                parts.append(f"writeback_required={wb_text}")
        # Do not synthesize from AgentOutput.success alone — that masks missing
        # InvestigationResult projection and violates summary_unavailable semantics.
        if data.get("degraded") or (isinstance(nested, Mapping) and nested.get("degraded")):
            parts.append("degraded=true")
        return _join_kv(parts)

    # Generic typed fallback for unknown agents / ClassName variants.
    return _join_kv(
        [
            f"event_type={data.get('event_type')}" if data.get("event_type") is not None else "",
            f"severity={data.get('severity')}" if data.get("severity") is not None else "",
            f"risk_score={data.get('risk_score')}" if data.get("risk_score") is not None else "",
            f"collection_status={data.get('collection_status')}"
            if data.get("collection_status") is not None
            else "",
            f"overall_status={data.get('overall_status')}"
            if data.get("overall_status") is not None
            else "",
            f"reason_code={data.get('reason_code')}" if data.get("reason_code") is not None else "",
            f"selected_action={data.get('selected_action')}"
            if data.get("selected_action") is not None
            else "",
            f"final_status={data.get('final_status')}"
            if data.get("final_status") is not None
            else "",
            f"final_verdict={data.get('final_verdict')}"
            if data.get("final_verdict") is not None
            else "",
        ]
    )


def _short_text_fallback(data: dict[str, Any]) -> str:
    """Optional short_text mode: bounded non-CoT snippets only (never CoT key names)."""
    for key in ("short_rationale", "decision_notes"):
        text = _safe_scalar_text(data.get(key))
        if text is not None:
            return text
    notes = data.get("notes")
    if isinstance(notes, list):
        bits = [
            str(item).strip()
            for item in notes[:8]
            if item is not None and str(item).strip() and str(item).strip() != _NOT_RETAINED
        ]
        if bits:
            return _truncate_text("; ".join(bits), _MAX_DECISION_SUMMARY_CHARS)
    degradation = data.get("degradation_reasons")
    if isinstance(degradation, list) and degradation:
        return _truncate_text(
            ",".join(str(item) for item in degradation if item is not None),
            _MAX_DECISION_SUMMARY_CHARS,
        )
    # Never promote CoT keys or legacy free-text narrative fields.
    return ""


def resolve_decision_rationale_mode(mode: str | None = None) -> DecisionRationaleMode:
    """Resolve effective rationale mode; production never allows ``short_text``."""
    if mode is None:
        try:
            from app.core.config import get_settings

            mode = get_settings().decision_rationale_mode
        except Exception:  # noqa: BLE001 - tracing must not depend on settings wiring
            mode = "structured"
    normalized = str(mode or "structured").strip().lower()
    if normalized not in _VALID_RATIONALE_MODES:
        normalized = "structured"
    try:
        from app.core.config import get_settings

        if get_settings().is_production() and normalized == "short_text":
            return "structured"
    except Exception:  # noqa: BLE001
        pass
    return normalized  # type: ignore[return-value]


def synthesize_decision_summary(
    agent_name: str | None,
    value: Any,
    *,
    rationale_mode: str | None = None,
) -> tuple[str, str | None]:
    """Return ``(summary, summary_unavailable_reason)``.

    Prefer existing structured fields; otherwise synthesize from typed agent
    outputs. Never promote CoT keys or legacy free-text narrative fields.
    """
    data = _as_mapping(value)
    if data is None:
        return "", "empty_output"
    if not data:
        return "", "empty_output"

    existing = _existing_structured_conclusion(data)
    if existing is not None:
        return existing, None

    mode = resolve_decision_rationale_mode(rationale_mode)
    summary = _synthesize_from_typed_fields(agent_name, data)
    if summary:
        return summary, None

    if mode == "short_text":
        short = _short_text_fallback(data)
        if short:
            return short, None

    # Only legacy narrative / CoT / opaque blobs remain.
    return "", "no_typed_decision_fields"


def ensure_decision_summary(
    agent_name: str | None,
    value: Any,
    *,
    rationale_mode: str | None = None,
) -> tuple[dict[str, Any], str, str | None]:
    """Return enriched output dict plus synthesized summary / unavailable reason."""
    data = _as_mapping(value)
    if data is None:
        return {}, "", "empty_output"
    enriched = dict(data)
    summary, unavailable = synthesize_decision_summary(
        agent_name,
        enriched,
        rationale_mode=rationale_mode,
    )
    if summary and not _safe_scalar_text(enriched.get("decision_summary")):
        enriched["decision_summary"] = summary
    return enriched, summary, unavailable


class TraceProjection:
    """Safe projection of Agent I/O for the audit trail.

    Strips raw payloads, secrets, and prompts; produces a bounded ``decision_basis``
    summary suitable for the ``agent_trace`` input_data / output_data columns.
    """

    @staticmethod
    def project(value: Any) -> dict[str, Any]:
        """Return a sanitised, size-bounded dict suitable for JSONB persistence."""
        if isinstance(value, BaseModel):
            raw = value.model_dump(mode="json")
        elif isinstance(value, Mapping):
            raw = dict(value)
        else:
            raw = {"_value": _normalize_scalar(value)}

        projected = _project_tree(raw)
        assert isinstance(projected, dict)
        encoded = _canonical_bytes(projected)
        if len(encoded) <= MAX_AUDIT_FIELD_BYTES:
            return projected

        return {
            "_truncated": True,
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "original_size_bytes": len(encoded),
            "top_level_keys": sorted(projected)[:100],
        }

    @staticmethod
    def decision_basis(
        value: Any,
        *,
        agent_name: str | None = None,
        rationale_mode: str | None = None,
    ) -> dict[str, Any]:
        """Extract a compact structured summary from a projected model.

        Fields: input_summary, evidence_refs, rules_applied, model_name,
        structured_conclusion, selected_action, confidence, warnings,
        and ``summary_unavailable`` when no safe brief can be synthesized.
        """
        data = _as_mapping(value)
        if data is None:
            return {}

        id_scalar = _extract_scalar(data, _DECISION_ID_FIELDS)
        input_summary = str(id_scalar) if id_scalar is not None else f"keys={sorted(data)[:20]}"

        structured_conclusion, unavailable = synthesize_decision_summary(
            agent_name,
            data,
            rationale_mode=rationale_mode,
        )

        evidence_refs = _collect_refs(data, _DECISION_EVIDENCE_FIELDS)

        raw_rules = _extract_scalar(data, _DECISION_RULES_FIELDS)
        rules_applied = (
            [str(raw_rules)]
            if raw_rules is not None and not isinstance(raw_rules, (list, dict))
            else raw_rules
            if isinstance(raw_rules, list)
            else []
        )

        raw_model = _extract_scalar(data, _DECISION_MODEL_FIELDS)
        model_name = str(raw_model) if raw_model is not None else None

        raw_action = _extract_scalar(
            data,
            frozenset({"selected_action", "actions", "response_plan"}),
        )
        selected_action = str(raw_action)[:1000] if raw_action is not None else None

        confidence = None
        for key in _DECISION_CONFIDENCE_FIELDS:
            v = data.get(key)
            if isinstance(v, (int, float)):
                confidence = float(v)
                break

        explicit_warnings = data.get("warnings")
        warnings: list[str] = []
        if isinstance(explicit_warnings, list):
            warnings = [str(w)[:500] for w in explicit_warnings[:20] if w is not None]
        elif explicit_warnings is not None:
            warnings = [str(explicit_warnings)[:500]]
        else:
            raw_warnings = _extract_scalar(
                data,
                _DECISION_WARNING_FIELDS
                - frozenset(
                    {
                        "warnings",
                        "error_detail",
                        "evidence_limited",
                        "verdict_reason_codes",
                    }
                ),
            )
            if isinstance(raw_warnings, list):
                warnings = [str(w)[:500] for w in raw_warnings[:20]]
            elif raw_warnings is not None:
                warnings = [str(raw_warnings)[:500]]

        # ISSUE-241: surface structured risk demotion codes (never free-form CoT).
        if bool(data.get("evidence_limited")) and "evidence_limited" not in warnings:
            warnings.append("evidence_limited")
        reason_codes = data.get("verdict_reason_codes")
        if isinstance(reason_codes, list):
            for code in reason_codes[:10]:
                if code is None:
                    continue
                text = str(code).strip()
                if text and text not in warnings:
                    warnings.append(text[:500])
            if reason_codes:
                demotion_brief = (
                    f"evidence_limited=true "
                    f"verdict_reason_codes={','.join(str(c) for c in reason_codes[:5] if c)}"
                )
                if not structured_conclusion:
                    structured_conclusion = (
                        f"risk_score={data.get('risk_score')} {demotion_brief}"
                    )[:512]
                elif "verdict_reason_codes=" not in structured_conclusion:
                    # Keep synthesized severity/score brief and append demotion codes.
                    structured_conclusion = (f"{structured_conclusion} {demotion_brief}")[:512]

        entity_audit: dict[str, Any] = {}
        for key in _DECISION_ENTITY_FIELDS:
            field_value = data.get(key)
            if isinstance(field_value, list) and field_value:
                entity_audit[key] = field_value[:20]
            elif (
                key == "entity_rejection_summary" and isinstance(field_value, dict) and field_value
            ):
                entity_audit[key] = field_value
        degradation_reasons = data.get("degradation_reasons")
        if isinstance(degradation_reasons, list) and degradation_reasons:
            entity_audit["degradation_reasons"] = [
                str(item)[:200] for item in degradation_reasons[:20]
            ]

        basis = {
            "input_summary": input_summary,
            "evidence_refs": evidence_refs,
            "rules_applied": rules_applied,
            "model_name": model_name,
            "structured_conclusion": structured_conclusion,
            "brief": structured_conclusion,
            "selected_action": selected_action,
            "confidence": confidence,
            "warnings": warnings,
        }
        if unavailable:
            basis["summary_unavailable"] = unavailable
        basis.update(entity_audit)
        return basis

    @staticmethod
    def project_for_compat(value: Any) -> dict[str, Any]:
        """API/read-path projection: omit CoT from DB payloads but retain legacy keys."""
        projected = TraceProjection.project(value)
        if not isinstance(projected, dict):
            return {}
        for key in _COT_KEYS:
            if key not in projected:
                projected[key] = _NOT_RETAINED
        return projected


class AgentTraceService:
    """Writes and queries ``agent_trace`` rows with redacted I/O projections."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        decision_record_service: Any | None = None,
        degraded_flag_service: Any | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._decision_record_service = decision_record_service
        self._degraded_flag_service = degraded_flag_service

    @staticmethod
    def new_trace_id() -> str:
        return f"trc-{uuid.uuid4().hex[:8]}"

    async def log_trace(
        self,
        event_id: str,
        agent_name: str,
        input_data: Any,
        output_data: Any | None,
        status: str,
        started_at: datetime,
        completed_at: datetime | None,
        error_detail: str | None = None,
        llm_model: str | None = None,
        llm_tokens_used: int | None = None,
    ) -> str:
        trace_id = self.new_trace_id()
        input_projected = TraceProjection.project(input_data)
        rationale_mode = resolve_decision_rationale_mode()
        if output_data is not None:
            enriched_output, _summary, _unavailable = ensure_decision_summary(
                agent_name,
                output_data,
                rationale_mode=rationale_mode,
            )
            output_projected = TraceProjection.project(enriched_output)
            decision_basis = TraceProjection.decision_basis(
                enriched_output,
                agent_name=agent_name,
                rationale_mode=rationale_mode,
            )
        else:
            output_projected = {}
            decision_basis = {
                "structured_conclusion": "",
                "brief": "",
                "summary_unavailable": "empty_output",
                "evidence_refs": [],
                "rules_applied": [],
                "warnings": [],
            }
        output_projected["_decision_basis"] = decision_basis

        duration_ms: int | None = None
        if started_at is not None and completed_at is not None:
            duration_ms = max(0, int((completed_at - started_at).total_seconds() * 1_000))

        row = orm.AgentTrace(
            trace_id=trace_id,
            event_id=event_id,
            agent_name=agent_name,
            input_data=input_projected,
            output_data=output_projected,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            error_detail=(
                redact_sensitive_text(error_detail)[:MAX_AUDIT_FIELD_BYTES]
                if error_detail
                else None
            ),
            llm_model=llm_model,
            llm_tokens_used=llm_tokens_used,
        )

        decision_record_ref: str | None = None
        audit_degraded = False
        async with self._session_factory() as session:
            async with session.begin():
                if self._decision_record_service is not None and output_data is not None:
                    try:
                        decision_record_ref = (
                            await self._decision_record_service.persist_from_agent_trace(
                                event_id=event_id,
                                agent_name=agent_name,
                                trace_id=trace_id,
                                input_data=input_data,
                                output_data=output_projected,
                                llm_model=llm_model,
                                session=session,
                            )
                        )
                    except Exception:  # noqa: BLE001 - decision record must not break tracing
                        logger.exception(
                            "DecisionRecord persist failed event=%s trace=%s",
                            event_id,
                            trace_id,
                        )
                        audit_degraded = True
                if decision_record_ref is not None:
                    output_projected["decision_record_ref"] = decision_record_ref
                    row.output_data = output_projected
                session.add(row)
                await session.flush()
                if audit_degraded:
                    await self._mark_decision_audit_degraded(event_id)
        return trace_id

    async def _mark_decision_audit_degraded(self, event_id: str) -> None:
        if self._degraded_flag_service is None:
            return
        try:
            await self._degraded_flag_service.set_flag(
                event_id,
                "decision_audit_degraded",
                True,
                writer="AgentTraceService",
            )
        except Exception:  # noqa: BLE001 - degraded annotation must not break tracing
            logger.exception("Failed to set decision_audit_degraded event=%s", event_id)

    async def get_traces_by_event(self, event_id: str) -> list[orm.AgentTrace]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(orm.AgentTrace)
                .where(orm.AgentTrace.event_id == event_id)
                .order_by(
                    orm.AgentTrace.started_at.asc().nulls_last(),
                    orm.AgentTrace.trace_id.asc(),
                )
            )
            return list(rows)

    async def get_trace(self, trace_id: str) -> orm.AgentTrace | None:
        async with self._session_factory() as session:
            return await session.get(orm.AgentTrace, trace_id)


__all__ = [
    "AgentTraceService",
    "MAX_AUDIT_FIELD_BYTES",
    "TraceProjection",
    "ensure_decision_summary",
    "resolve_decision_rationale_mode",
    "response_gate_trace_tokens",
    "synthesize_decision_summary",
]
