"""Bounded ``event_context_snapshot`` observability projection (ISSUE-254).

API list/detail snapshots keep a **whitelist + size-capped** summary of evidence
and storyline so operators can triage without opening decision-trace. The full
EventContext remains in WorkingMemory / journal / decision-trace — this module
must never dump raw CoT, prompts, or the entire WM aggregate into the API-facing
snapshot returned by GET/list event.

CLOSED rows may still persist a full freeze in ORM for ``rebuild_context``;
``project_snapshot_for_api`` is the mandatory read-path filter for API responses.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

import orjson

from app.models.agent_io import AttackStoryline, EvidenceOutput
from app.models.evidence import EvidenceGap

# Keys allowed on API-facing snapshots (hard whitelist).
SNAPSHOT_SUMMARY_KEYS = frozenset(
    {
        "evidence_count",
        "collection_status",
        "evidence_gaps",
        "evidence_summary",
        "storyline",
        "report_generated",
        "report_quality",
        "analysis_only_complete",
        "risk_assessment",
        "classification_override",
        "execution_substate",
    }
)

# Nested keys forbidden anywhere in summary payloads (defence in depth).
_FORBIDDEN_KEYS = frozenset(
    {
        "thought",
        "chain_of_thought",
        "raw_prompt",
        "raw_response",
        "prompt",
        "messages",
        "decision_trace",
        "cot",
        "reasoning",
        "hidden_reasoning",
        "raw_data",
        "raw_payload",
        "raw_result",
    }
)

_MAX_TOP_GAPS = 5
_MAX_SOURCE_LIST = 16
_MAX_REASON_CHARS = 240
_MAX_NARRATIVE_CHARS = 480
_MAX_STORYLINE_SUMMARY_BYTES = 4_096
_MAX_EVIDENCE_SUMMARY_BYTES = 4_096
_MAX_RISK_ASSESSMENT_BYTES = 8_192
_MAX_SNAPSHOT_BYTES = 65_536


def _strip_forbidden(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in _FORBIDDEN_KEYS:
                continue
            out[str(key)[:128]] = _strip_forbidden(item)
        return out
    if isinstance(value, list):
        return [_strip_forbidden(item) for item in value[:64]]
    if isinstance(value, str):
        return value[:8192]
    return value


def _strip_forbidden_dict(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip forbidden keys and return a dict (empty when projection is not mapping-like)."""
    stripped = _strip_forbidden(payload)
    if not isinstance(stripped, dict):
        return {}
    return stripped


def _enum_or_str(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    return str(value or "")


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def _fit_bytes(payload: dict[str, Any], *, max_bytes: int) -> dict[str, Any]:
    """Return payload if within budget; otherwise drop optional stringy fields."""
    cleaned = _strip_forbidden_dict(payload)
    if len(_canonical_bytes(cleaned)) <= max_bytes:
        return cleaned
    # Progressive shrink: drop narrative / reasons first, keep status counters.
    shrunk = dict(cleaned)
    for key in ("narrative_summary", "reason", "detail"):
        shrunk.pop(key, None)
    if isinstance(shrunk.get("top_gaps"), list):
        shrunk["top_gaps"] = [
            {k: v for k, v in gap.items() if k != "reason"}
            for gap in shrunk["top_gaps"][:3]
            if isinstance(gap, dict)
        ]
    if isinstance(shrunk.get("evidence_gaps"), list):
        shrunk["evidence_gaps"] = [
            {k: v for k, v in gap.items() if k != "reason"}
            for gap in shrunk["evidence_gaps"][:3]
            if isinstance(gap, dict)
        ]
    if len(_canonical_bytes(shrunk)) <= max_bytes:
        return shrunk
    # Last resort: counters / enums only.
    minimal: dict[str, Any] = {
        k: shrunk[k]
        for k in (
            "evidence_count",
            "collection_status",
            "gap_count",
            "conflict_count",
            "overall_confidence",
            "grounding_status",
            "generated_by",
            "storyline_id",
            "phase_count",
            "claim_ref_count",
            "risk_score",
            "evidence_limited",
            "scoring_mode",
        )
        if k in shrunk
    }
    return minimal


def _gap_to_summary(gap: EvidenceGap | dict[str, Any]) -> dict[str, str]:
    if isinstance(gap, EvidenceGap):
        missing = gap.missing_source.value
        reason = gap.reason
    else:
        missing = str(gap.get("missing_source") or "")
        reason = str(gap.get("reason") or "")
    return {
        "missing_source": missing[:64],
        "reason": reason.strip()[:_MAX_REASON_CHARS],
    }


def build_evidence_snapshot_summary(
    evidence: EvidenceOutput | dict[str, Any],
) -> dict[str, Any]:
    """Project EvidenceOutput into bounded snapshot fields (empty-evidence safe)."""
    if isinstance(evidence, EvidenceOutput):
        evidence_list = evidence.evidence_list
        gaps = evidence.gaps
        conflicts = evidence.conflicts
        success_sources = [str(s) for s in evidence.success_sources]
        failed_sources = [str(s) for s in evidence.failed_sources]
        collection_status = evidence.collection_status.value
        overall_confidence = float(evidence.overall_confidence)
    else:
        evidence_list = evidence.get("evidence_list") or []
        gaps = evidence.get("gaps") or []
        conflicts = evidence.get("conflicts") or []
        success_sources = [str(s) for s in (evidence.get("success_sources") or [])]
        failed_sources = [str(s) for s in (evidence.get("failed_sources") or [])]
        raw_status = evidence.get("collection_status")
        collection_status = _enum_or_str(raw_status)
        try:
            overall_confidence = float(evidence.get("overall_confidence") or 0.0)
        except (TypeError, ValueError):
            overall_confidence = 0.0

    top_gaps = [_gap_to_summary(g) for g in list(gaps)[:_MAX_TOP_GAPS]]
    summary = {
        "evidence_count": len(evidence_list) if isinstance(evidence_list, list) else 0,
        "collection_status": collection_status[:64],
        "gap_count": len(gaps) if isinstance(gaps, list) else 0,
        "conflict_count": len(conflicts) if isinstance(conflicts, list) else 0,
        "overall_confidence": max(0.0, min(1.0, overall_confidence)),
        "success_sources": success_sources[:_MAX_SOURCE_LIST],
        "failed_sources": failed_sources[:_MAX_SOURCE_LIST],
        "top_gaps": top_gaps,
    }
    return _fit_bytes(summary, max_bytes=_MAX_EVIDENCE_SUMMARY_BYTES)


def build_storyline_snapshot_summary(
    storyline: AttackStoryline | dict[str, Any],
) -> dict[str, Any]:
    """Project AttackStoryline into a bounded ``storyline`` snapshot object."""
    if isinstance(storyline, AttackStoryline):
        payload = {
            "storyline_id": storyline.storyline_id,
            "grounding_status": storyline.grounding_status.value,
            "generated_by": storyline.generated_by.value,
            "phase_count": len(storyline.phases),
            "claim_ref_count": len(storyline.claim_refs),
            "narrative_summary": (storyline.narrative_summary or "")[:_MAX_NARRATIVE_CHARS],
            "schema_version": storyline.schema_version,
        }
    else:
        grounding = storyline.get("grounding_status")
        generated_by = storyline.get("generated_by")
        phases = storyline.get("phases") or []
        claim_refs = storyline.get("claim_refs") or []
        payload = {
            "storyline_id": str(storyline.get("storyline_id") or "")[:128],
            "grounding_status": _enum_or_str(grounding)[:64],
            "generated_by": _enum_or_str(generated_by)[:32],
            "phase_count": len(phases) if isinstance(phases, list) else 0,
            "claim_ref_count": len(claim_refs) if isinstance(claim_refs, list) else 0,
            "narrative_summary": str(storyline.get("narrative_summary") or "")[
                :_MAX_NARRATIVE_CHARS
            ],
            "schema_version": str(storyline.get("schema_version") or "1.0")[:16],
        }
    return _fit_bytes(payload, max_bytes=_MAX_STORYLINE_SUMMARY_BYTES)


def _bound_risk_assessment(risk: dict[str, Any]) -> dict[str, Any]:
    return _fit_bytes(_strip_forbidden_dict(risk), max_bytes=_MAX_RISK_ASSESSMENT_BYTES)


def _storyline_needs_reproject(storyline: dict[str, Any]) -> bool:
    heavy = ("phases", "entries", "claim_refs", "prompt", "messages")
    return any(key in storyline for key in heavy)


def merge_evidence_summary_into_snapshot(
    snapshot: dict[str, Any] | None,
    evidence: EvidenceOutput | dict[str, Any],
) -> dict[str, Any]:
    """Merge bounded evidence observability fields into the durable ORM snapshot.

    Preserves unrelated keys (including CLOSED full-freeze fields used by
    ``rebuild_context``). API responses must still pass ``project_snapshot_for_api``.
    """
    merged = dict(snapshot) if isinstance(snapshot, dict) else {}
    summary = build_evidence_snapshot_summary(evidence)
    merged["evidence_count"] = summary["evidence_count"]
    merged["collection_status"] = summary["collection_status"]
    merged["evidence_gaps"] = list(summary.get("top_gaps") or [])
    merged["evidence_summary"] = summary
    return _shrink_summary_sections(merged)


def merge_storyline_summary_into_snapshot(
    snapshot: dict[str, Any] | None,
    storyline: AttackStoryline | dict[str, Any],
) -> dict[str, Any]:
    """Merge bounded storyline summary (incl. grounding_status) into the snapshot.

    Replaces only the ``storyline`` key with a bounded object. Do not call this on
    a CLOSED freeze if full ``storyline.phases`` must remain for rebuild — use
    ``project_snapshot_for_api`` on the read path instead.
    """
    merged = dict(snapshot) if isinstance(snapshot, dict) else {}
    existing = merged.get("storyline")
    base = dict(existing) if isinstance(existing, dict) else {}
    # Never retain full phases/entries/claim payloads from a prior dump.
    for heavy in ("phases", "entries", "claim_refs", "prompt", "messages"):
        base.pop(heavy, None)
    base.update(build_storyline_snapshot_summary(storyline))
    merged["storyline"] = base
    return _shrink_summary_sections(merged)


def merge_report_generated_into_snapshot(
    snapshot: dict[str, Any] | None,
    generated: bool,
) -> dict[str, Any]:
    """Mirror ``report_generated`` onto the durable snapshot (ISSUE-254 / R2-013)."""
    merged = dict(snapshot) if isinstance(snapshot, dict) else {}
    merged["report_generated"] = bool(generated)
    return merged


def project_snapshot_for_api(snapshot: dict[str, Any] | None) -> dict[str, Any] | None:
    """Hard-project ORM snapshot (thin merge or CLOSED full freeze) for API responses.

    Derives evidence/storyline summaries from full ``evidence_output`` / ``storyline``
    when present (CLOSED freeze), otherwise keeps already-merged summary keys.
    Never returns full EventContext fields.
    """
    if snapshot is None:
        return None
    if not isinstance(snapshot, dict):
        return {}

    projected: dict[str, Any] = {}

    evidence_output = snapshot.get("evidence_output")
    if isinstance(evidence_output, dict):
        summary = build_evidence_snapshot_summary(evidence_output)
        projected["evidence_count"] = summary["evidence_count"]
        projected["collection_status"] = summary["collection_status"]
        projected["evidence_gaps"] = list(summary.get("top_gaps") or [])
        projected["evidence_summary"] = summary
    else:
        for key in ("evidence_count", "collection_status", "evidence_gaps", "evidence_summary"):
            if key in snapshot:
                projected[key] = snapshot[key]

    storyline = snapshot.get("storyline")
    if isinstance(storyline, dict):
        projected["storyline"] = build_storyline_snapshot_summary(storyline)

    risk = snapshot.get("risk_assessment")
    if isinstance(risk, dict):
        projected["risk_assessment"] = _bound_risk_assessment(risk)

    if "analysis_only_complete" in snapshot:
        projected["analysis_only_complete"] = bool(snapshot.get("analysis_only_complete"))
    if "report_generated" in snapshot:
        projected["report_generated"] = bool(snapshot.get("report_generated"))
    if snapshot.get("report_quality") is not None:
        projected["report_quality"] = str(snapshot.get("report_quality"))[:64]
    override = snapshot.get("classification_override")
    if isinstance(override, dict):
        projected["classification_override"] = _strip_forbidden(override)
    if snapshot.get("execution_substate") is not None:
        projected["execution_substate"] = _enum_or_str(snapshot.get("execution_substate"))[:64]

    return _hard_project_api_snapshot(projected)


def _shrink_summary_sections(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Soft size guard for durable merges: shrink summary blobs, keep other keys."""
    if len(_canonical_bytes(snapshot)) <= _MAX_SNAPSHOT_BYTES:
        return snapshot
    cleaned = dict(snapshot)
    if isinstance(cleaned.get("evidence_summary"), dict):
        cleaned["evidence_summary"] = _fit_bytes(
            cleaned["evidence_summary"],
            max_bytes=1024,
        )
    if isinstance(cleaned.get("storyline"), dict) and not _storyline_needs_reproject(
        cleaned["storyline"]
    ):
        cleaned["storyline"] = _fit_bytes(cleaned["storyline"], max_bytes=1024)
    if isinstance(cleaned.get("evidence_gaps"), list):
        cleaned["evidence_gaps"] = cleaned["evidence_gaps"][:3]
    return cleaned


def _hard_project_api_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Hard whitelist + size guard for API responses only."""
    cleaned = {k: snapshot[k] for k in SNAPSHOT_SUMMARY_KEYS if k in snapshot}
    if isinstance(cleaned.get("risk_assessment"), dict):
        cleaned["risk_assessment"] = _bound_risk_assessment(cleaned["risk_assessment"])
    if isinstance(cleaned.get("evidence_summary"), dict):
        cleaned["evidence_summary"] = _fit_bytes(
            cleaned["evidence_summary"],
            max_bytes=_MAX_EVIDENCE_SUMMARY_BYTES,
        )
    if isinstance(cleaned.get("storyline"), dict):
        cleaned["storyline"] = build_storyline_snapshot_summary(cleaned["storyline"])
    if isinstance(cleaned.get("evidence_gaps"), list):
        cleaned["evidence_gaps"] = [
            _strip_forbidden(g)
            for g in cleaned["evidence_gaps"][:_MAX_TOP_GAPS]
            if isinstance(g, dict)
        ]
    if isinstance(cleaned.get("classification_override"), dict):
        cleaned["classification_override"] = _strip_forbidden(cleaned["classification_override"])

    if len(_canonical_bytes(cleaned)) <= _MAX_SNAPSHOT_BYTES:
        return cleaned

    if isinstance(cleaned.get("evidence_summary"), dict):
        cleaned["evidence_summary"] = _fit_bytes(cleaned["evidence_summary"], max_bytes=1024)
    if isinstance(cleaned.get("storyline"), dict):
        cleaned["storyline"] = _fit_bytes(cleaned["storyline"], max_bytes=1024)
    if isinstance(cleaned.get("evidence_gaps"), list):
        cleaned["evidence_gaps"] = cleaned["evidence_gaps"][:3]
    if isinstance(cleaned.get("risk_assessment"), dict):
        cleaned["risk_assessment"] = _fit_bytes(cleaned["risk_assessment"], max_bytes=1024)
    if len(_canonical_bytes(cleaned)) <= _MAX_SNAPSHOT_BYTES:
        return cleaned

    floor_keys = (
        "evidence_count",
        "collection_status",
        "report_generated",
        "report_quality",
        "analysis_only_complete",
        "execution_substate",
    )
    floor = {k: cleaned[k] for k in floor_keys if k in cleaned}
    if isinstance(cleaned.get("storyline"), dict) and "grounding_status" in cleaned["storyline"]:
        floor["storyline"] = {
            "grounding_status": str(cleaned["storyline"]["grounding_status"])[:64]
        }
    if isinstance(cleaned.get("risk_assessment"), dict):
        risk_floor = {
            k: cleaned["risk_assessment"][k]
            for k in ("risk_score", "evidence_limited", "scoring_mode")
            if k in cleaned["risk_assessment"]
        }
        if risk_floor:
            floor["risk_assessment"] = risk_floor
    return floor


__all__ = [
    "SNAPSHOT_SUMMARY_KEYS",
    "build_evidence_snapshot_summary",
    "build_storyline_snapshot_summary",
    "merge_evidence_summary_into_snapshot",
    "merge_report_generated_into_snapshot",
    "merge_storyline_summary_into_snapshot",
    "project_snapshot_for_api",
]
