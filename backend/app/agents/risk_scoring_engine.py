"""Rule-based six-dimension risk scoring engine (ISSUE-035 / ISSUE-102)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RAGOutput,
    RiskFactor,
    TriageResult,
)
from app.models.enums import EvidenceSource, Severity
from app.models.evidence import Evidence

# ISSUE-102: evidence-sparse scoring guardrails (fixed, testable formulas).
EVIDENCE_LIMITED_CONFIDENCE_CAP = 0.35
SOURCE_BASELINE_FLOOR_RATIO = 0.85
_HIGH_SOURCE_MIN_SCORE = 70
_CRITICAL_SOURCE_MIN_SCORE = 90

# Fixed weights (sum = 1.0).
FACTOR_WEIGHTS: dict[str, float] = {
    "asset_impact": 0.25,
    "behavior_anomaly": 0.20,
    "evidence_confidence": 0.20,
    "attack_stage": 0.15,
    "data_sensitivity": 0.10,
    "threat_intel": 0.10,
}

ASSET_VALUE_SCORES: dict[str, float] = {
    "critical": 100.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
}

SENSITIVITY_SCORES: dict[str, float] = {
    "restricted": 100.0,
    "confidential": 75.0,
    "internal": 50.0,
    "public": 25.0,
}

# Rough ATT&CK stage position (0 early → 100 late).
_TECHNIQUE_STAGE: dict[str, float] = {
    "T1566": 20.0,  # phishing
    "T1078": 25.0,  # valid accounts
    "T1059": 45.0,  # command scripting
    "T1027": 50.0,
    "T1005": 60.0,  # data from local system
    "T1560": 70.0,  # archive collected data
    "T1041": 90.0,  # exfiltration over C2
    "T1567": 95.0,  # exfil to web service
    "T1486": 100.0,  # impact / ransomware
}

_ANOMALY_KEYWORDS: tuple[tuple[str, float], ...] = (
    ("powershell", 25.0),
    ("encoded", 15.0),
    ("archive", 20.0),
    ("upload", 30.0),
    ("exfil", 35.0),
    ("7z", 15.0),
    ("unknown", 10.0),
    ("process_create", 10.0),
)


def severity_from_score(score: int) -> Severity:
    """Map 0-100 risk_score to Severity (intro §4.6)."""
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


def _severity_rank(severity: Severity) -> int:
    order = {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }
    return order[severity]


def _parse_severity(raw: Any) -> Severity | None:
    if raw is None:
        return None
    try:
        return Severity(str(raw).lower())
    except ValueError:
        return None


def extract_source_baseline(
    source_snapshot: dict[str, Any] | None,
) -> tuple[int | None, Severity | None]:
    """Read ``source_risk_baseline`` and source severity from frozen snapshot."""
    if not isinstance(source_snapshot, dict):
        return None, None

    baseline: int | None = None
    normalized = source_snapshot.get("normalized")
    if isinstance(normalized, dict):
        raw_score = normalized.get("risk_score")
        if raw_score is not None:
            try:
                baseline = max(0, min(100, int(raw_score)))
            except (TypeError, ValueError):
                baseline = None

    source_severity = _parse_severity(source_snapshot.get("severity"))
    return baseline, source_severity


def is_evidence_limited(evidence_output: EvidenceOutput) -> bool:
    """True when collection failed/degraded and no evidence was collected."""
    if evidence_output.collection_status not in {
        CollectionStatus.FAILED,
        CollectionStatus.DEGRADED,
    }:
        return False
    return len(evidence_output.evidence_list) == 0


def _source_eligible_for_severity_floor(source_severity: Severity | None) -> bool:
    """Floor only applies when source severity is HIGH or CRITICAL (ISSUE-102 step 2)."""
    if source_severity is None:
        return False
    return _severity_rank(source_severity) >= _severity_rank(Severity.HIGH)


def _min_floored_severity(source_severity: Severity) -> Severity:
    """Minimum output severity under evidence-limited floor.

    HIGH keeps HIGH. CRITICAL floors one tier to HIGH so score/severity stay
    aligned with intro §4.6 bands (CRITICAL requires score >= 90 only with evidence).
    """
    if source_severity is Severity.CRITICAL:
        return Severity.HIGH
    return Severity.HIGH


def _min_score_for_severity(severity: Severity) -> int:
    if severity is Severity.CRITICAL:
        return _CRITICAL_SOURCE_MIN_SCORE
    if severity is Severity.HIGH:
        return _HIGH_SOURCE_MIN_SCORE
    if severity is Severity.MEDIUM:
        return 40
    return 0


def compute_score_floor(
    *,
    source_baseline: int | None,
    source_severity: Severity | None,
) -> int | None:
    """Minimum rule/merged score when evidence is limited (ISSUE-102).

    Gated on ``source_severity >= HIGH``. Low/medium source alerts never get a
    score floor from baseline (avoids FP mis-lift).
    """
    if not _source_eligible_for_severity_floor(source_severity):
        return None
    if source_baseline is not None:
        return max(0, min(100, int(round(source_baseline * SOURCE_BASELINE_FLOOR_RATIO))))
    return _HIGH_SOURCE_MIN_SCORE


def apply_severity_floor(
    *,
    risk_score: int,
    severity: Severity,
    source_severity: Severity | None,
    evidence_limited: bool,
) -> tuple[int, Severity, bool]:
    """Ensure high-severity source alerts are not silently downgraded.

    Score and severity stay band-aligned: floor severity maps through
    ``severity_from_score`` mins (HIGH → score >= 70).
    """
    if not evidence_limited or not _source_eligible_for_severity_floor(source_severity):
        return risk_score, severity, False
    assert source_severity is not None

    min_severity = _min_floored_severity(source_severity)
    min_score = _min_score_for_severity(min_severity)
    adjusted_score = risk_score
    adjusted_severity = severity
    floor_applied = False

    if adjusted_score < min_score:
        adjusted_score = min_score
        floor_applied = True
    adjusted_severity = severity_from_score(adjusted_score)
    if _severity_rank(adjusted_severity) < _severity_rank(min_severity):
        adjusted_severity = min_severity
        adjusted_score = max(adjusted_score, min_score)
        floor_applied = True

    return adjusted_score, adjusted_severity, floor_applied


@dataclass(frozen=True)
class EvidenceLimitedAdjustment:
    risk_score: int
    severity: Severity
    confidence: float
    evidence_limited: bool
    severity_floor_applied: bool
    source_risk_baseline: int | None


def apply_evidence_limited_adjustments(
    *,
    risk_score: int,
    confidence: float,
    evidence_output: EvidenceOutput,
    source_snapshot: dict[str, Any] | None,
) -> EvidenceLimitedAdjustment:
    """Apply ISSUE-102 floor/cap when threat signal is strong but evidence is missing."""
    source_baseline, source_severity = extract_source_baseline(source_snapshot)
    evidence_limited = is_evidence_limited(evidence_output)
    if not evidence_limited:
        return EvidenceLimitedAdjustment(
            risk_score=risk_score,
            severity=severity_from_score(risk_score),
            confidence=confidence,
            evidence_limited=False,
            severity_floor_applied=False,
            source_risk_baseline=source_baseline,
        )

    adjusted_score = risk_score
    floor_applied = False
    score_floor = compute_score_floor(
        source_baseline=source_baseline,
        source_severity=source_severity,
    )
    if score_floor is not None and adjusted_score < score_floor:
        adjusted_score = score_floor
        floor_applied = True

    adjusted_score, adjusted_severity, severity_floor_applied = apply_severity_floor(
        risk_score=adjusted_score,
        severity=severity_from_score(adjusted_score),
        source_severity=source_severity,
        evidence_limited=True,
    )
    floor_applied = floor_applied or severity_floor_applied

    capped_confidence = min(confidence, EVIDENCE_LIMITED_CONFIDENCE_CAP)

    return EvidenceLimitedAdjustment(
        risk_score=adjusted_score,
        severity=adjusted_severity,
        confidence=capped_confidence,
        evidence_limited=True,
        severity_floor_applied=floor_applied,
        source_risk_baseline=source_baseline,
    )


def augment_factors_for_evidence_limited(
    factors: list[RiskFactor],
    *,
    adjustment: EvidenceLimitedAdjustment,
) -> list[RiskFactor]:
    """Ensure decision trace cites evidence confidence and source baseline."""
    if not adjustment.evidence_limited:
        return factors

    baseline_text = (
        "null" if adjustment.source_risk_baseline is None else str(adjustment.source_risk_baseline)
    )
    floor_note = (
        f"; severity_floor_applied=true, score={adjustment.risk_score}"
        if adjustment.severity_floor_applied
        else ""
    )
    suffix = (
        "; evidence_limited=true: zero evidence under failed/degraded collection, "
        f"confidence capped at {EVIDENCE_LIMITED_CONFIDENCE_CAP:.2f}; "
        f"source_baseline={baseline_text}{floor_note}"
    )

    updated: list[RiskFactor] = []
    found = False
    for factor in factors:
        if factor.factor_name == "evidence_confidence":
            found = True
            updated.append(
                factor.model_copy(update={"reasoning": factor.reasoning + suffix}),
            )
        else:
            updated.append(factor)
    if not found:
        updated.append(
            RiskFactor(
                factor_name="evidence_confidence",
                weight=FACTOR_WEIGHTS["evidence_confidence"],
                raw_score=0.0,
                weighted_score=0.0,
                reasoning=suffix.lstrip("; "),
            )
        )
    return updated


class RiskScoringEngine:
    """Deterministic rule path for the six risk dimensions."""

    def score(
        self,
        *,
        triage_result: TriageResult,
        evidence_output: EvidenceOutput,
        rag_output: RAGOutput | None = None,
        storyline: dict[str, Any] | None = None,
    ) -> dict[str, tuple[float, str]]:
        """Return ``{factor_name: (raw_score_0_100, reasoning)}``."""
        evidence = list(evidence_output.evidence_list)
        return {
            "asset_impact": self._asset_impact(triage_result, evidence),
            "behavior_anomaly": self._behavior_anomaly(evidence),
            "evidence_confidence": self._evidence_confidence(evidence_output),
            "attack_stage": self._attack_stage(evidence, rag_output, storyline),
            "data_sensitivity": self._data_sensitivity(evidence),
            "threat_intel": self._threat_intel(evidence, rag_output),
        }

    def _asset_impact(
        self,
        triage: TriageResult,
        evidence: list[Evidence],
    ) -> tuple[float, str]:
        values: list[str] = []
        for item in evidence:
            if item.source is not EvidenceSource.ASSET:
                continue
            raw = item.raw_data or {}
            for key in ("asset_value", "business_criticality", "criticality"):
                if raw.get(key):
                    values.append(str(raw[key]).lower())
            hostname = str(raw.get("hostname") or "")
            if "fin" in hostname.lower() or "finance" in hostname.lower():
                values.append("high")
            owner = str(raw.get("owner") or "")
            if owner:
                values.append("medium")

        # Host entity hints from triage.
        for host in triage.entities.hosts:
            role = str((host.attributes or {}).get("asset_value") or "").lower()
            if role:
                values.append(role)
            if host.hostname and "fin" in host.hostname.lower():
                values.append("high")

        if not values:
            # Default: workstation-like medium impact when hosts present.
            score = 50.0 if triage.entities.hosts else 25.0
            return score, "未标注资产价值，按默认主机基线评分"
        best = max(ASSET_VALUE_SCORES.get(v, 50.0) for v in values)
        label = next(
            (v for v in values if ASSET_VALUE_SCORES.get(v) == best),
            "medium",
        )
        return best, f"资产价值映射为 {label} → {best:.0f}"

    def _behavior_anomaly(self, evidence: list[Evidence]) -> tuple[float, str]:
        score = 0.0
        hits: list[str] = []
        blob_parts: list[str] = []
        for item in evidence:
            raw = item.raw_data or {}
            blob_parts.append(item.description.lower())
            blob_parts.append(str(raw.get("process") or "").lower())
            blob_parts.append(str(raw.get("cmdline") or "").lower())
            blob_parts.append(str(raw.get("action") or "").lower())
            blob_parts.append(item.evidence_type.lower())
            if item.is_conflicting:
                score += 10.0
                hits.append("conflicting_evidence")
        blob = " ".join(blob_parts)
        for keyword, points in _ANOMALY_KEYWORDS:
            if keyword in blob:
                score += points
                hits.append(keyword)
        score = min(100.0, score)
        if not hits:
            return 15.0, "未见显著异常行为关键词，给基线分"
        return score, "异常行为信号: " + ", ".join(dict.fromkeys(hits))

    def _evidence_confidence(self, evidence_output: EvidenceOutput) -> tuple[float, str]:
        score = max(0.0, min(100.0, float(evidence_output.overall_confidence) * 100.0))
        return (
            score,
            f"EvidenceOutput.overall_confidence={evidence_output.overall_confidence:.3f}",
        )

    def _attack_stage(
        self,
        evidence: list[Evidence],
        rag_output: RAGOutput | None,
        storyline: dict[str, Any] | None,
    ) -> tuple[float, str]:
        stages: list[float] = []
        labels: list[str] = []

        for item in evidence:
            tech = (item.mitre_technique or "").upper()
            if tech:
                prefix = tech.split(".")[0]
                if prefix in _TECHNIQUE_STAGE:
                    stages.append(_TECHNIQUE_STAGE[prefix])
                    labels.append(prefix)
            raw = item.raw_data or {}
            action = str(raw.get("action") or item.evidence_type or "").lower()
            if action in {"upload", "exfil"}:
                stages.append(90.0)
                labels.append(action)
            if item.source is EvidenceSource.NETWORK_FLOW and raw.get("dst_ip"):
                stages.append(75.0)
                labels.append("external_flow")

        if rag_output is not None:
            for match in rag_output.attack_techniques:
                tid = (match.technique_id or "").upper().split(".")[0]
                if tid in _TECHNIQUE_STAGE:
                    stages.append(_TECHNIQUE_STAGE[tid])
                    labels.append(tid)
                for tactic in match.tactics or []:
                    t = tactic.lower()
                    if "exfiltration" in t or "impact" in t:
                        stages.append(95.0)
                        labels.append(tactic)

        if storyline:
            for phase in storyline.get("phases") or []:
                name = str(phase.get("phase_name") or "").lower()
                if name in {"exfiltration", "post_action"}:
                    stages.append(95.0)
                    labels.append(name)
                elif name in {"staging", "collection"}:
                    stages.append(70.0)
                    labels.append(name)
                elif name == "initial_access":
                    stages.append(25.0)
                    labels.append(name)

        if not stages:
            return 30.0, "缺少 ATT&CK/阶段线索，按早期阶段基线"
        best = max(stages)
        return best, "攻击阶段依据: " + ", ".join(dict.fromkeys(labels))[:120]

    def _data_sensitivity(self, evidence: list[Evidence]) -> tuple[float, str]:
        scores: list[float] = []
        labels: list[str] = []
        bulk_bonus = 0.0
        for item in evidence:
            raw = item.raw_data or {}
            for key in ("sensitivity", "data_sensitivity", "classification"):
                value = str(raw.get(key) or "").lower()
                if value in SENSITIVITY_SCORES:
                    scores.append(SENSITIVITY_SCORES[value])
                    labels.append(value)
            name = str(raw.get("file_name") or raw.get("name") or "").lower()
            if any(token in name for token in ("finance", "salary", "secret", "report")):
                scores.append(75.0)
                labels.append("confidential_filename")
            try:
                nbytes = int(raw.get("bytes") or raw.get("bytes_out") or 0)
            except (TypeError, ValueError):
                nbytes = 0
            if nbytes >= 10_000_000:
                bulk_bonus = max(bulk_bonus, 15.0)
                labels.append("bulk_transfer")
            if str(raw.get("action") or "").lower() == "upload":
                scores.append(70.0)
                labels.append("upload")

        base = max(scores) if scores else 40.0
        total = min(100.0, base + bulk_bonus)
        if not labels:
            return total, "无敏感标签，按内部数据基线"
        return total, "敏感度信号: " + ", ".join(dict.fromkeys(labels))

    def _threat_intel(
        self,
        evidence: list[Evidence],
        rag_output: RAGOutput | None,
    ) -> tuple[float, str]:
        scores: list[float] = []
        labels: list[str] = []
        for item in evidence:
            if item.source is not EvidenceSource.THREAT_INTEL:
                continue
            raw = item.raw_data or {}
            conf = raw.get("confidence", item.confidence)
            try:
                scores.append(float(conf) * 100.0 if float(conf) <= 1.0 else float(conf))
            except (TypeError, ValueError):
                scores.append(60.0)
            tags = raw.get("tags") or []
            if isinstance(tags, list):
                for tag in tags:
                    labels.append(str(tag))
                    if str(tag).lower() in {"exfil", "c2", "malware", "unknown_infra"}:
                        scores.append(85.0)
            reputation = str(raw.get("reputation") or "").lower()
            if reputation in {"malicious", "suspicious"}:
                scores.append(90.0 if reputation == "malicious" else 70.0)
                labels.append(reputation)

        if rag_output is not None and rag_output.attack_techniques:
            bonus = min(10.0, len(rag_output.attack_techniques) * 3.0)
            scores.append(60.0 + bonus)
            labels.append(f"rag_techniques+{bonus:.0f}")

        if not scores:
            return 20.0, "无威胁情报命中，基线低分"
        best = min(100.0, max(scores))
        return best, "情报信号: " + (", ".join(dict.fromkeys(labels))[:120] or "confidence")
