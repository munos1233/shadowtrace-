"""Bounded ``event_context_snapshot`` observability projection (ISSUE-254).

API list/detail snapshots keep a **whitelist + size-capped** summary of evidence
and storyline so operators can triage without opening decision-trace. The full
EventContext remains in WorkingMemory / journal / decision-trace — this module
must never dump raw CoT, prompts, or the entire WM aggregate into the ORM
snapshot used by GET event.
"""

from __future__ import annotations

from typing import Any

import orjson

from app.models.agent_io import AttackStoryline, EvidenceOutput
from app.models.evidence import EvidenceGap

# Top-level keys this module may introduce / refresh on the durable snapshot.
SNAPSHOT_SUMMARY_KEYS = frozenset(
    {
        "evidence_count",
        "collection_status",
        "evidence_gaps",
        "evidence_summary",
        "storyline",
        "report_generated",
        "analysis_only_complete",
        "risk_assessment",
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
_MAX_SNAPSHOT_BYTES = 64_096


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


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def _fit_bytes(payload: dict[str, Any], *, max_bytes: int) -> dict[str, Any]:
    """Return payload if within budget; otherwise drop optional stringy fields."""
    cleaned = _strip_forbidden(payload)
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
    minimal = {
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
        collection_status = (
            raw_status.value if hasattr(raw_status, "value") else str(raw_status or "")
        )
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
            "grounding_status": (
                grounding.value if hasattr(grounding, "value") else str(grounding or "")
            )[:64],
            "generated_by": (
                generated_by.value if hasattr(generated_by, "value") else str(generated_by or "")
            )[:32],
            "phase_count": len(phases) if isinstance(phases, list) else 0,
            "claim_ref_count": len(claim_refs) if isinstance(claim_refs, list) else 0,
            "narrative_summary": str(storyline.get("narrative_summary") or "")[
                :_MAX_NARRATIVE_CHARS
            ],
            "schema_version": str(storyline.get("schema_version") or "1.0")[:16],
        }
    return _fit_bytes(payload, max_bytes=_MAX_STORYLINE_SUMMARY_BYTES)


def merge_evidence_summary_into_snapshot(
    snapshot: dict[str, Any] | None,
    evidence: EvidenceOutput | dict[str, Any],
) -> dict[str, Any]:
    """Merge bounded evidence observability fields into the durable ORM snapshot."""
    merged = dict(snapshot) if isinstance(snapshot, dict) else {}
    summary = build_evidence_snapshot_summary(evidence)
    merged["evidence_count"] = summary["evidence_count"]
    merged["collection_status"] = summary["collection_status"]
    merged["evidence_gaps"] = list(summary.get("top_gaps") or [])
    merged["evidence_summary"] = summary
    return _cap_snapshot(merged)


def merge_storyline_summary_into_snapshot(
    snapshot: dict[str, Any] | None,
    storyline: AttackStoryline | dict[str, Any],
) -> dict[str, Any]:
    """Merge bounded storyline summary (incl. grounding_status) into the snapshot."""
    merged = dict(snapshot) if isinstance(snapshot, dict) else {}
    existing = merged.get("storyline")
    base = dict(existing) if isinstance(existing, dict) else {}
    # Never retain full phases/entries/claim payloads from a prior dump.
    for heavy in ("phases", "entries", "claim_refs", "prompt", "messages"):
        base.pop(heavy, None)
    base.update(build_storyline_snapshot_summary(storyline))
    merged["storyline"] = base
    return _cap_snapshot(merged)


def merge_report_generated_into_snapshot(
    snapshot: dict[str, Any] | None,
    generated: bool,
) -> dict[str, Any]:
    """Mirror ``report_generated`` onto the durable snapshot (ISSUE-254 / R2-013)."""
    merged = dict(snapshot) if isinstance(snapshot, dict) else {}
    merged["report_generated"] = bool(generated)
    return merged


def _cap_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Soft size guard: shrink summary sections if the snapshot ballooned.

    Does **not** rewrite unrelated existing keys (e.g. risk factor ``reasoning``);
    CoT/prompt stripping applies only to evidence/storyline summary payloads.
    """
    if len(_canonical_bytes(snapshot)) <= _MAX_SNAPSHOT_BYTES:
        return snapshot
    cleaned = dict(snapshot)
    # Prefer keeping counters; drop narrative / gap reasons.
    if isinstance(cleaned.get("evidence_summary"), dict):
        cleaned["evidence_summary"] = _fit_bytes(
            cleaned["evidence_summary"],
            max_bytes=1024,
        )
    if isinstance(cleaned.get("storyline"), dict):
        cleaned["storyline"] = _fit_bytes(cleaned["storyline"], max_bytes=1024)
    if isinstance(cleaned.get("evidence_gaps"), list):
        cleaned["evidence_gaps"] = cleaned["evidence_gaps"][:3]
    return cleaned


__all__ = [
    "SNAPSHOT_SUMMARY_KEYS",
    "build_evidence_snapshot_summary",
    "build_storyline_snapshot_summary",
    "merge_evidence_summary_into_snapshot",
    "merge_report_generated_into_snapshot",
    "merge_storyline_summary_into_snapshot",
]
