"""Output quality evaluator for agent outputs (ISSUE-065).

Rule-based four-metric scoring with optional LLM-judge calibration.
Evaluates triage_result, evidence_output, risk_assessment, and report;
writes results to EventContext.quality_scores via WorkingMemory.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from app.agents.prompts.quality_judge_prompt import build_quality_judge_messages
from app.models.enums import QualityVerdict

logger = logging.getLogger(__name__)

# Thresholds per ISSUE-065 §5
PASS_THRESHOLD = 0.75
WARN_THRESHOLD = 0.5

# Metric weights (sum to 1.0)
WEIGHT_COMPLETENESS = 0.30
WEIGHT_GROUNDING = 0.30
WEIGHT_CONSISTENCY = 0.25
WEIGHT_SPECIFICITY = 0.15

# Agents whose outputs are evaluated
EVALUATED_AGENTS = ["triage_agent", "evidence_agent", "risk_agent", "report_agent"]

# Agent name → EventContext key for output retrieval
AGENT_OUTPUT_KEYS: dict[str, str] = {
    "triage_agent": "triage_result",
    "evidence_agent": "evidence_output",
    "risk_agent": "risk_assessment",
    "report_agent": "report",
}


def _verdict_from_score(score: float) -> QualityVerdict:
    if score >= PASS_THRESHOLD:
        return QualityVerdict.PASS
    if score >= WARN_THRESHOLD:
        return QualityVerdict.WARN
    return QualityVerdict.FAIL


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_len(value: Any) -> int:
    try:
        return len(value)
    except TypeError:
        return 0


# --------------------------------------------------------------------------- #
# Rule-based metric functions
# --------------------------------------------------------------------------- #


def _completeness(output: dict[str, Any], agent_name: str) -> float:
    """Ratio of expected fields present in the output."""
    required: dict[str, set[str]] = {
        "triage_agent": {"event_type", "severity", "need_investigation"},
        "evidence_agent": {"evidence_list", "collection_status"},
        "risk_agent": {"risk_score", "severity", "risk_factors"},
        "report_agent": {"report_id", "title", "final_verdict", "risk_score"},
    }
    expected = required.get(agent_name, set())
    if not expected:
        return 1.0
    present = sum(1 for k in expected if output.get(k) is not None)
    return present / len(expected)


def _grounding_ratio(output: dict[str, Any], agent_name: str) -> float:
    """Proportion of claims that reference evidence or entities."""
    # evidence_agent: check evidence_list entries have non-empty description
    if agent_name == "evidence_agent":
        items = output.get("evidence_list", [])
        if not items:
            return 0.0
        grounded = sum(
            1
            for e in items
            if isinstance(e, dict) and (e.get("description") or e.get("evidence_id"))
        )
        return grounded / len(items)

    # risk_agent: check risk_factors have reasoning
    if agent_name == "risk_agent":
        factors = output.get("risk_factors", [])
        if not factors:
            return 0.0
        reasoned = sum(1 for f in factors if isinstance(f, dict) and f.get("reasoning", "").strip())
        return reasoned / len(factors)

    # report_agent: check executive_summary is non-empty with length tiers
    if agent_name == "report_agent":
        summary = output.get("executive_summary", "")
        if not isinstance(summary, str):
            return 0.0
        length = len(summary)
        if length > 100:
            return 1.0
        if length > 20:
            return 0.5
        return 0.0

    # triage_agent: check reasoning field
    if agent_name == "triage_agent":
        reasoning = output.get("reasoning", "")
        return 1.0 if (isinstance(reasoning, str) and len(reasoning) > 10) else 0.0

    return 0.5


def _consistency(output: dict[str, Any], agent_name: str) -> float:
    """Check internal field consistency (e.g. severity vs risk_score)."""
    if agent_name == "risk_agent":
        severity = output.get("severity", "")
        risk_score = _safe_float(output.get("risk_score"), -1)
        # severity ↔ risk_score range check
        ranges = {
            "low": (0, 24),
            "medium": (25, 54),
            "high": (55, 84),
            "critical": (85, 100),
        }
        expected = ranges.get(severity)
        if expected and risk_score >= 0:
            lo, hi = expected
            return 1.0 if lo <= risk_score <= hi else 0.5
        return 0.5  # unknown severity — neutral

    if agent_name == "report_agent":
        # report risk_score cross-check is deferred until evaluate() accepts
        # context with the upstream risk_assessment for comparison.
        return 1.0

    if agent_name == "triage_agent":
        # need_investigation=True should have entities or ioc_list
        need = output.get("need_investigation", False)
        if need:
            entities = output.get("entities", {})
            iocs = output.get("ioc_list", [])
            has_entity = any(
                len(v) > 0
                for v in (entities.values() if isinstance(entities, dict) else [])
            )
            has_ioc = _safe_len(iocs) > 0
            return 1.0 if (has_entity or has_ioc) else 0.3
        return 1.0

    return 1.0


def _specificity(output: dict[str, Any], agent_name: str) -> float:
    """Check for concrete entities rather than vague descriptions."""
    # Look for entity-like patterns in string fields
    text_fields: list[str] = []
    if agent_name == "triage_agent":
        text_fields.append(str(output.get("reasoning", "")))
    elif agent_name == "evidence_agent":
        evidence_list = output.get("evidence_list")
        if isinstance(evidence_list, list):
            for e in evidence_list:
                if isinstance(e, dict):
                    text_fields.append(str(e.get("description", "")))
    elif agent_name == "risk_agent":
        risk_factors = output.get("risk_factors")
        if isinstance(risk_factors, list):
            for f in risk_factors:
                if isinstance(f, dict):
                    text_fields.append(str(f.get("reasoning", "")))
    elif agent_name == "report_agent":
        text_fields.append(str(output.get("executive_summary", "")))

    if not text_fields:
        return 0.5

    combined = " ".join(text_fields)
    # Simple heuristics for specificity: IPs, hostnames, file paths, user names

    patterns = [
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IPv4
        r"[a-zA-Z]:?\\[a-zA-Z0-9_\\]+",  # Windows paths (e.g. C:\Windows\System32)
        r"/[a-zA-Z0-9/_.-]+",  # Unix paths
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]+",  # email
        r"PC-[A-Z]+-\d+",  # hostname pattern
        r"CVE-\d{4}-\d+",  # CVE
        r"[0-9a-f]{32,}",  # hash
    ]
    entities_found = sum(1 for p in patterns if re.search(p, combined))
    return min(1.0, entities_found / 3.0)


# --------------------------------------------------------------------------- #
# LLM judge response model
# --------------------------------------------------------------------------- #


class _JudgeResponse(BaseModel):
    calibrated_score: float = -1.0
    verdict: str = "pass"
    reasons: list[str] = []
    disagreement_note: str = ""


# --------------------------------------------------------------------------- #
# OutputQualityScore
# --------------------------------------------------------------------------- #


@dataclass
class OutputQualityScore:
    agent_name: str
    score: float
    verdict: QualityVerdict
    metrics: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    evaluated_by: str = "rule"

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "score": self.score,
            "verdict": self.verdict.value,
            "metrics": self.metrics,
            "reasons": self.reasons,
            "evaluated_by": self.evaluated_by,
        }


# --------------------------------------------------------------------------- #
# OutputQualityEvaluator
# --------------------------------------------------------------------------- #


class OutputQualityEvaluator:
    """Rule-based + optional LLM-judge output quality scoring."""

    def __init__(
        self,
        *,
        llm_client: Any = None,
        working_memory: Any = None,
        judge_enabled: bool | None = None,
    ) -> None:
        self._llm_client = llm_client
        self._bound_wm = (
            working_memory.for_writer("OutputQualityEvaluator")
            if working_memory is not None
            else None
        )
        if judge_enabled is None:
            judge_enabled = os.environ.get("QUALITY_JUDGE_ENABLED", "false").lower() == "true"
        self._judge_enabled = judge_enabled

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def evaluate(
        self,
        agent_name: str,
        output: dict[str, Any],
        context: dict[str, Any] | None = None,
        event_id: str = "",
    ) -> OutputQualityScore:
        """Evaluate one agent output and return a structured score."""
        del context  # reserved for future cross-agent checks

        # 1. Rule-based scoring
        metrics = {
            "completeness": _completeness(output, agent_name),
            "grounding_ratio": _grounding_ratio(output, agent_name),
            "consistency": _consistency(output, agent_name),
            "specificity": _specificity(output, agent_name),
        }
        rule_score = (
            WEIGHT_COMPLETENESS * metrics["completeness"]
            + WEIGHT_GROUNDING * metrics["grounding_ratio"]
            + WEIGHT_CONSISTENCY * metrics["consistency"]
            + WEIGHT_SPECIFICITY * metrics["specificity"]
        )
        rule_verdict = _verdict_from_score(rule_score)
        reasons = self._build_reasons(metrics, rule_score)

        score = OutputQualityScore(
            agent_name=agent_name,
            score=round(rule_score, 4),
            verdict=rule_verdict,
            metrics=metrics,
            reasons=reasons,
            evaluated_by="rule",
        )

        # 2. Optional LLM judge calibration
        if self._judge_enabled and self._llm_client is not None:
            try:
                calibrated = await self._llm_judge(
                    agent_name,
                    output,
                    rule_score,
                    rule_verdict,
                    reasons,
                    event_id=event_id,
                )
                if calibrated is not None:
                    score = calibrated
            except Exception:
                logger.warning(
                    "LLM quality judge failed for agent=%s, keeping rule score",
                    agent_name,
                    exc_info=True,
                )

        return score

    async def evaluate_all(
        self,
        event_id: str,
        outputs: dict[str, dict[str, Any]],
    ) -> list[OutputQualityScore]:
        """Evaluate all configured agent outputs and persist to EventContext."""
        scores: list[OutputQualityScore] = []
        for agent_name in EVALUATED_AGENTS:
            output_key = AGENT_OUTPUT_KEYS.get(agent_name)
            if output_key is None:
                logger.debug(
                    "No output key mapping for agent=%s, skipping", agent_name
                )
                continue
            output = outputs.get(output_key)
            if output is None:
                logger.debug(
                    "No output for agent=%s key=%s in event=%s, skipping",
                    agent_name,
                    output_key,
                    event_id,
                )
                continue
            score = await self.evaluate(agent_name, output, event_id=event_id)
            scores.append(score)

        if self._bound_wm is not None:
            try:
                await self._bound_wm.write(
                    event_id,
                    "quality_scores",
                    [s.to_dict() for s in scores],
                )
            except Exception:
                logger.warning(
                    "Failed to persist quality_scores for event=%s",
                    event_id,
                    exc_info=True,
                )

        return scores

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_reasons(
        metrics: dict[str, float],
        score: float,
    ) -> list[str]:
        reasons: list[str] = []
        if metrics["completeness"] < 1.0:
            reasons.append(f"completeness={metrics['completeness']:.2f} (missing required fields)")
        if metrics["grounding_ratio"] < 0.7:
            reasons.append(
                f"grounding_ratio={metrics['grounding_ratio']:.2f} (weak evidence backing)"
            )
        if metrics["consistency"] < 1.0:
            reasons.append(
                f"consistency={metrics['consistency']:.2f} (field inconsistency detected)"
            )
        if metrics["specificity"] < 0.5:
            reasons.append(
                f"specificity={metrics['specificity']:.2f} (vague, no concrete entities)"
            )
        if not reasons:
            reasons.append("all metrics within acceptable range")
        reasons.append(f"weighted_score={score:.3f}")
        return reasons

    async def _llm_judge(
        self,
        agent_name: str,
        output: dict[str, Any],
        rule_score: float,
        rule_verdict: QualityVerdict,
        rule_reasons: list[str],
        *,
        event_id: str = "",
    ) -> OutputQualityScore | None:
        messages = build_quality_judge_messages(
            agent_name=agent_name,
            output_summary=output,
            rule_score=rule_score,
            rule_verdict=rule_verdict.value,
            rule_reasons=rule_reasons,
        )

        response = await self._llm_client.chat(
            messages,
            event_id=event_id or "quality_judge",
            agent_name="OutputQualityEvaluator",
            prompt_key="quality_judge",
            json_mode=True,
            response_model=_JudgeResponse,
        )

        if response.parsed is not None and isinstance(response.parsed, _JudgeResponse):
            data = response.parsed
            if data.calibrated_score < 0:
                logger.warning(
                    "LLM judge returned no calibrated_score for agent=%s, using rule_score",
                    agent_name,
                )
                calibrated = rule_score
            else:
                calibrated = _safe_float(data.calibrated_score, rule_score)
            # Average rule and LLM scores
            final_score = round((rule_score + calibrated) / 2, 4)
            verdict = _verdict_from_score(final_score)
            return OutputQualityScore(
                agent_name=agent_name,
                score=final_score,
                verdict=verdict,
                metrics={
                    "rule_score": rule_score,
                    "llm_score": calibrated,
                },
                reasons=list(data.reasons) if data.reasons else rule_reasons,
                evaluated_by="llm",
            )

        return None


__all__ = [
    "OutputQualityEvaluator",
    "OutputQualityScore",
    "PASS_THRESHOLD",
    "WARN_THRESHOLD",
]
