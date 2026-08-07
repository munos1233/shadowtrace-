"""ISSUE-241: evidence_limited demotion observability projection."""

from __future__ import annotations

from app.models.agent_io import ScoringMode
from app.services.risk_verdict_projection import (
    EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
    merge_risk_assessment_into_snapshot,
    risk_observability_from_snapshot,
)


def test_risk_observability_from_snapshot_reads_reason_codes() -> None:
    evidence_limited, scoring_mode, codes = risk_observability_from_snapshot(
        {
            "risk_assessment": {
                "evidence_limited": True,
                "scoring_mode": "rule_only",
                "verdict_reason_codes": [
                    EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
                    EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
                ],
            }
        }
    )
    assert evidence_limited is True
    assert scoring_mode is ScoringMode.RULE_ONLY
    assert codes == [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT]


def test_merge_risk_assessment_into_snapshot_preserves_other_fields() -> None:
    snapshot = merge_risk_assessment_into_snapshot(
        {"triage_result": {"event_type": "malicious_process"}},
        {
            "risk_score": 70,
            "evidence_limited": True,
            "scoring_mode": "llm_and_rule",
            "verdict_reason_codes": [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT],
        },
    )
    assert snapshot["triage_result"]["event_type"] == "malicious_process"
    assert snapshot["risk_assessment"]["evidence_limited"] is True
    assert snapshot["risk_assessment"]["verdict_reason_codes"] == [
        EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT
    ]


def test_empty_snapshot_defaults() -> None:
    evidence_limited, scoring_mode, codes = risk_observability_from_snapshot(None)
    assert evidence_limited is False
    assert scoring_mode is None
    assert codes == []
