"""P0 VerdictResolver — sole logical resolver for FinalVerdict (ISSUE-035 / ISSUE-114)."""

from __future__ import annotations

from typing import Any

from app.models.agent_io import RAGOutput, RiskAssessment
from app.models.enums import FinalVerdict
from app.models.workflow import FP_HIGH_THRESHOLD, FP_LOW_THRESHOLD

# Backward-compatible aliases for tests / imports.
FP_HIGH_SCORE = FP_HIGH_THRESHOLD
FP_MEDIUM_SCORE = FP_LOW_THRESHOLD

# Shared with ISSUE-200 triage/risk consistency checks and risk scoring paths.
CONFIRMED_THREAT_RISK_THRESHOLD = 70


class VerdictResolver:
    """Resolve ``FinalVerdict`` with fixed priority (must not be overridden).

    Priority (ISSUE-035 / ISSUE-047 / ISSUE-114 / #675 / ISSUE-241):
    1. ``fp_adjudication.recommendation == close_as_fp`` → false_positive
       (post-evidence typed decision; never overridden by risk_score >= 70),
       **except** high-source + evidence-limited events (``#675`` guard).
       RiskAgent additionally downgrades ``confirmed_threat`` → ``none`` when
       ``evidence_limited`` (see ``risk_agent.py`` post-resolve hook) and records
       ``verdict_reason_codes`` so callers do not treat risk≥70 as confirmed_threat.
    2. Pre-evidence vector / RAG FP signal → possible_false_positive (advisory only)
    3. risk_score >= 70 → confirmed_threat (**before** evidence_limited demotion)
    4. else → none

    Do **not** equate ``risk_score >= 70`` with a durable ``confirmed_threat``
    label: the evidence_limited fail-soft path may demote it to ``none``.

    Pre-evidence ``false_positive_match`` must never yield false_positive.
    Legacy ``false_positive_match`` journal entries are advisory only.
    """

    def resolve(
        self,
        risk_assessment: RiskAssessment,
        false_positive_match: dict[str, Any] | None = None,
        rag_output: RAGOutput | None = None,
        fp_adjudication: dict[str, Any] | None = None,
    ) -> FinalVerdict:
        adjudication = fp_adjudication or {}
        if str(adjudication.get("recommendation") or "").strip().lower() == "close_as_fp":
            if _blocks_auto_fp_close(risk_assessment):
                return FinalVerdict.NONE
            return FinalVerdict.FALSE_POSITIVE

        fp = false_positive_match or {}
        fp_score = self._fp_score(fp, rag_output)
        risk_score = int(risk_assessment.risk_score)

        if fp_score >= FP_LOW_THRESHOLD:
            return FinalVerdict.POSSIBLE_FALSE_POSITIVE
        if risk_score >= CONFIRMED_THREAT_RISK_THRESHOLD:
            return FinalVerdict.CONFIRMED_THREAT
        return FinalVerdict.NONE

    @staticmethod
    def _fp_score(
        fp_match: dict[str, Any],
        rag_output: RAGOutput | None,
    ) -> float:
        candidates: list[float] = []
        for key in ("max_score", "score", "confidence"):
            raw = fp_match.get(key)
            if raw is not None:
                try:
                    candidates.append(float(raw))
                except (TypeError, ValueError):
                    pass
        if rag_output is not None and rag_output.fp_similarity is not None:
            try:
                candidates.append(float(rag_output.fp_similarity.max_score))
            except (TypeError, ValueError, AttributeError):
                pass
        return max(candidates) if candidates else 0.0


def _blocks_auto_fp_close(risk_assessment: RiskAssessment) -> bool:
    """High-source + evidence-limited events must not auto close-as-FP (#675)."""
    return bool(risk_assessment.evidence_limited and risk_assessment.high_source_evidence_limited)


__all__ = [
    "CONFIRMED_THREAT_RISK_THRESHOLD",
    "FP_HIGH_SCORE",
    "FP_MEDIUM_SCORE",
    "VerdictResolver",
]
