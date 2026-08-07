"""ISSUE-241: TraceProjection surfaces evidence_limited demotion without CoT."""

from __future__ import annotations

from app.services.agent_trace_service import TraceProjection
from app.services.risk_verdict_projection import (
    EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
)


def test_decision_basis_includes_evidence_limited_demotion_codes() -> None:
    basis = TraceProjection.decision_basis(
        {
            "risk_score": 70,
            "severity": "high",
            "confidence": 0.08,
            "scoring_mode": "rule_only",
            "evidence_limited": True,
            "verdict_reason_codes": [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT],
        }
    )
    assert "evidence_limited" in basis["warnings"]
    assert EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT in basis["warnings"]
    assert "verdict_reason_codes=" in basis["structured_conclusion"]
    assert "evidence_limited=true" in basis["structured_conclusion"]
    # CoT keys must remain absent from structured decision basis.
    for banned in ("thought", "reflection", "rationale", "chain_of_thought"):
        assert banned not in basis


def test_project_for_compat_keeps_verdict_reason_codes() -> None:
    projected = TraceProjection.project_for_compat(
        {
            "risk_score": 70,
            "evidence_limited": True,
            "verdict_reason_codes": [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT],
            "thought": "secret-cot-must-not-leak",
        }
    )
    assert projected["verdict_reason_codes"] == [
        EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT
    ]
    assert projected["thought"] == "[NOT_RETAINED]"
