"""ISSUE-241: risk_agent DecisionRecord enrichment includes demotion codes."""

from __future__ import annotations

from app.services.decision_record_service import _enrich_agent_output
from app.services.risk_verdict_projection import (
    EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
)


def test_risk_agent_enrichment_surfaces_evidence_limited_demotion() -> None:
    enriched = _enrich_agent_output(
        "risk_agent",
        {"event_id": "evt-demo"},
        {
            "risk_score": 70,
            "severity": "high",
            "confidence": 0.08,
            "scoring_mode": "rule_only",
            "evidence_limited": True,
            "verdict_reason_codes": [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT],
        },
    )
    assert enriched["reason_code"] == EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT
    assert EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT in enriched["reason_codes"]
    assert "evidence_limited=True" in enriched["decision_summary"]
    assert (
        f"verdict_reason_codes={EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT}"
        in enriched["decision_summary"]
    )


def test_risk_agent_enrichment_falls_back_to_scoring_mode() -> None:
    enriched = _enrich_agent_output(
        "risk_agent",
        {"event_id": "evt-demo"},
        {
            "risk_score": 40,
            "severity": "medium",
            "confidence": 0.5,
            "scoring_mode": "llm_and_rule",
            "evidence_limited": False,
        },
    )
    assert enriched["reason_code"] == "llm_and_rule"
    assert "evidence_limited=False" in enriched["decision_summary"]
