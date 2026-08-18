"""Risk / verdict observability projection for Event list/detail (ISSUE-241).

Keeps fail-soft ``evidence_limited`` demotion, but makes the reason visible so
callers are not left with contradictory ``risk_score >= 70`` + ``final_verdict=none``.
"""

from __future__ import annotations

from typing import Any

from app.models.agent_io import ScoringMode

# Stable machine-readable reason code (API / decision-trace / UI contract).
EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT = "evidence_limited_demoted_from_confirmed_threat"
UNRESOLVED_IDENTITY_ENDPOINT_CONFLICT = "unresolved_identity_endpoint_conflict"

RISK_ASSESSMENT_SNAPSHOT_KEY = "risk_assessment"


def normalize_verdict_reason_codes(raw: Any) -> list[str]:
    """Return a bounded list of non-empty reason-code strings."""
    if not isinstance(raw, list):
        return []
    codes: list[str] = []
    for item in raw:
        if item is None:
            continue
        text = str(item).strip()
        if text and text not in codes:
            codes.append(text)
        if len(codes) >= 20:
            break
    return codes


def parse_scoring_mode(raw: Any) -> ScoringMode | None:
    if raw is None:
        return None
    try:
        return ScoringMode(str(raw))
    except ValueError:
        return None


def risk_observability_from_mapping(
    risk: dict[str, Any] | None,
) -> tuple[bool, ScoringMode | None, list[str]]:
    """Extract list/detail risk observability fields from a risk_assessment mapping."""
    if not isinstance(risk, dict):
        return False, None, []
    evidence_limited = bool(risk.get("evidence_limited"))
    scoring_mode = parse_scoring_mode(risk.get("scoring_mode"))
    reason_codes = normalize_verdict_reason_codes(risk.get("verdict_reason_codes"))
    return evidence_limited, scoring_mode, reason_codes


def risk_observability_from_snapshot(
    snapshot: dict[str, Any] | None,
) -> tuple[bool, ScoringMode | None, list[str]]:
    """Project observability fields from ``security_event.event_context_snapshot``."""
    if not isinstance(snapshot, dict):
        return False, None, []
    raw = snapshot.get(RISK_ASSESSMENT_SNAPSHOT_KEY)
    return risk_observability_from_mapping(raw if isinstance(raw, dict) else None)


def merge_risk_assessment_into_snapshot(
    snapshot: dict[str, Any] | None,
    assessment: dict[str, Any],
) -> dict[str, Any]:
    """Merge RiskAgent output into the durable ORM snapshot for list projection."""
    merged = dict(snapshot) if isinstance(snapshot, dict) else {}
    existing = merged.get(RISK_ASSESSMENT_SNAPSHOT_KEY)
    base = dict(existing) if isinstance(existing, dict) else {}
    base.update(assessment)
    merged[RISK_ASSESSMENT_SNAPSHOT_KEY] = base
    return merged


__all__ = [
    "UNRESOLVED_IDENTITY_ENDPOINT_CONFLICT",
    "EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT",
    "RISK_ASSESSMENT_SNAPSHOT_KEY",
    "merge_risk_assessment_into_snapshot",
    "normalize_verdict_reason_codes",
    "parse_scoring_mode",
    "risk_observability_from_mapping",
    "risk_observability_from_snapshot",
]
