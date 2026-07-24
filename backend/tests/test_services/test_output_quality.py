"""OutputQualityEvaluator tests (ISSUE-065)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.llm.base import InMemoryLLMCallAuditRecorder
from app.core.llm.mock_client import MockLLMClient
from app.models.enums import QualityVerdict
from app.services.output_quality_evaluator import (
    PASS_THRESHOLD,
    OutputQualityEvaluator,
    _completeness,
    _consistency,
    _grounding_ratio,
    _specificity,
    _verdict_from_score,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_mock_llm(tmp_path: Path) -> MockLLMClient:
    return MockLLMClient(
        golden_root=tmp_path,
        audit_recorder=InMemoryLLMCallAuditRecorder(),
    )


def _make_golden_quality_judge(tmp_path: Path) -> None:
    """Write a quality_judge golden that returns a calibrated score of 0.92."""
    golden_dir = tmp_path / "quality_judge"
    golden_dir.mkdir(parents=True, exist_ok=True)
    (golden_dir / "default.json").write_text(
        json.dumps(
            {
                "content": {
                    "calibrated_score": 0.92,
                    "verdict": "pass",
                    "reasons": ["well structured", "good evidence grounding"],
                    "disagreement_note": "",
                },
                "model_name": "mock-model",
                "prompt_tokens": 50,
                "completion_tokens": 50,
                "total_tokens": 100,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _high_quality_triage() -> dict:
    return {
        "event_type": "data_exfiltration",
        "severity": "high",
        "need_investigation": True,
        "entities": {"ips": ["10.0.0.1"], "hosts": ["PC-FIN-023"]},
        "ioc_list": ["10.0.0.1"],
        "reasoning": "Suspicious data transfer from PC-FIN-023 to external IP 10.0.0.1",
        "degraded": False,
    }


def _high_quality_evidence() -> dict:
    return {
        "evidence_list": [
            {
                "evidence_id": "evd-001",
                "description": "Outbound 50MB transfer from PC-FIN-023 to 10.0.0.1",
                "confidence": 0.9,
            },
            {
                "evidence_id": "evd-002",
                "description": "PowerShell process chain on PC-FIN-023",
                "confidence": 0.85,
            },
        ],
        "collection_status": "completed",
    }


def _high_quality_risk() -> dict:
    return {
        "risk_score": 72,
        "severity": "high",
        "risk_factors": [
            {
                "factor_name": "data_volume",
                "reasoning": "50MB exfiltrated",
                "weight": 0.4,
                "raw_score": 80,
                "weighted_score": 32,
            },
            {
                "factor_name": "lateral_movement",
                "reasoning": "No lateral movement detected",
                "weight": 0.3,
                "raw_score": 20,
                "weighted_score": 6,
            },
            {
                "factor_name": "threat_intel",
                "reasoning": "IP matches known C2",
                "weight": 0.3,
                "raw_score": 70,
                "weighted_score": 21,
            },
        ],
    }


def _high_quality_report() -> dict:
    return {
        "report_id": "rpt-test001",
        "title": "Data Exfiltration Investigation Report",
        "final_verdict": "confirmed_threat",
        "risk_score": 72,
        "executive_summary": (
            "Investigation confirmed data exfiltration from PC-FIN-023 to external "
            "C2 server at 10.0.0.1. PowerShell-based exfiltration of 50MB detected."
        ),
    }


# --------------------------------------------------------------------------- #
# Verdict thresholds
# --------------------------------------------------------------------------- #


def test_verdict_pass() -> None:
    assert _verdict_from_score(0.9) == QualityVerdict.PASS
    assert _verdict_from_score(0.75) == QualityVerdict.PASS


def test_verdict_warn() -> None:
    assert _verdict_from_score(0.74) == QualityVerdict.WARN
    assert _verdict_from_score(0.5) == QualityVerdict.WARN


def test_verdict_fail() -> None:
    assert _verdict_from_score(0.49) == QualityVerdict.FAIL
    assert _verdict_from_score(0.0) == QualityVerdict.FAIL


# --------------------------------------------------------------------------- #
# Completeness
# --------------------------------------------------------------------------- #


def test_completeness_full() -> None:
    assert _completeness(_high_quality_triage(), "triage_agent") == 1.0


def test_completeness_missing_field() -> None:
    incomplete = {"severity": "high", "need_investigation": True}
    # event_type missing → 2/3
    assert _completeness(incomplete, "triage_agent") == pytest.approx(2 / 3)


def test_completeness_unknown_agent() -> None:
    assert _completeness({}, "unknown_agent") == 1.0


# --------------------------------------------------------------------------- #
# Grounding ratio
# --------------------------------------------------------------------------- #


def test_grounding_ratio_full() -> None:
    # 2 evidence items, both with description → 2/2
    assert _grounding_ratio(_high_quality_evidence(), "evidence_agent") == 1.0


def test_grounding_ratio_empty() -> None:
    assert _grounding_ratio({}, "evidence_agent") == 0.0


def test_grounding_ratio_triage_no_reasoning() -> None:
    output = {"reasoning": ""}
    assert _grounding_ratio(output, "triage_agent") == 0.0


def test_grounding_ratio_triage_with_reasoning() -> None:
    output = {"reasoning": "Detailed analysis of threat indicators"}
    assert _grounding_ratio(output, "triage_agent") == 1.0


# --------------------------------------------------------------------------- #
# Consistency
# --------------------------------------------------------------------------- #


def test_consistency_risk_severity_match() -> None:
    # risk_score 72 → "high" (55-85) → consistent
    assert _consistency(_high_quality_risk(), "risk_agent") == 1.0


def test_consistency_risk_severity_mismatch() -> None:
    output = {"severity": "low", "risk_score": 90}
    # risk_score 90 should be "critical", not "low"
    assert _consistency(output, "risk_agent") == 0.5


def test_consistency_triage_no_entities() -> None:
    output = {"need_investigation": True, "entities": {}, "ioc_list": []}
    assert _consistency(output, "triage_agent") == 0.3


def test_consistency_triage_with_entities() -> None:
    output = {"need_investigation": True, "entities": {"ips": ["10.0.0.1"]}, "ioc_list": []}
    assert _consistency(output, "triage_agent") == 1.0


# --------------------------------------------------------------------------- #
# Specificity
# --------------------------------------------------------------------------- #


def test_specificity_with_entities() -> None:
    output = {"reasoning": "PC-FIN-023 contacted 10.0.0.1 via CVE-2024-1234"}
    score = _specificity(output, "triage_agent")
    assert score >= 0.66  # at least 2 of 3 patterns matched


def test_specificity_vague() -> None:
    output = {"reasoning": "The system detected some anomalous activity"}
    assert _specificity(output, "triage_agent") == 0.0


# --------------------------------------------------------------------------- #
# evaluate — rule-only (QUALITY_JUDGE_ENABLED=false)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_evaluate_high_quality_pass() -> None:
    evaluator = OutputQualityEvaluator(judge_enabled=False)
    score = await evaluator.evaluate("triage_agent", _high_quality_triage())
    assert score.verdict == QualityVerdict.PASS
    assert score.score >= PASS_THRESHOLD
    assert score.evaluated_by == "rule"
    assert "completeness" in score.metrics
    assert len(score.reasons) >= 1


@pytest.mark.asyncio
async def test_evaluate_low_quality_fail() -> None:
    evaluator = OutputQualityEvaluator(judge_enabled=False)
    output = {
        "event_type": "other",
        "severity": "low",
        "need_investigation": False,
        "reasoning": "",
    }
    score = await evaluator.evaluate("triage_agent", output)
    # completeness=1.0 (all required fields present, but empty),
    # grounding=0.0, consistency=1.0, specificity=0.0
    # weighted ≈ 0.30*1 + 0.30*0 + 0.25*1 + 0.15*0 = 0.55
    assert score.score < PASS_THRESHOLD
    assert score.verdict in (QualityVerdict.WARN, QualityVerdict.FAIL)


@pytest.mark.asyncio
async def test_evaluate_risk_high_quality() -> None:
    evaluator = OutputQualityEvaluator(judge_enabled=False)
    score = await evaluator.evaluate("risk_agent", _high_quality_risk())
    assert score.verdict == QualityVerdict.PASS
    assert score.score >= PASS_THRESHOLD


@pytest.mark.asyncio
async def test_evaluate_report_high_quality() -> None:
    evaluator = OutputQualityEvaluator(judge_enabled=False)
    score = await evaluator.evaluate("report_agent", _high_quality_report())
    assert score.verdict == QualityVerdict.PASS


# --------------------------------------------------------------------------- #
# evaluate_all — aggregate + persist
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_evaluate_all_persists_scores() -> None:
    from app.services.working_memory import BoundWorkingMemory

    wm = MagicMock(spec=BoundWorkingMemory)
    wm.read = AsyncMock(return_value=None)
    wm.write = AsyncMock()

    evaluator = OutputQualityEvaluator(
        working_memory=MagicMock(for_writer=MagicMock(return_value=wm)),
        judge_enabled=False,
    )

    outputs = {
        "triage_result": _high_quality_triage(),
        "evidence_output": _high_quality_evidence(),
        "risk_assessment": _high_quality_risk(),
        "report": _high_quality_report(),
    }

    scores = await evaluator.evaluate_all("evt-test-all", outputs)
    assert len(scores) == 4
    for s in scores:
        assert s.agent_name in {"triage_agent", "evidence_agent", "risk_agent", "report_agent"}
        assert 0 <= s.score <= 1

    # Should have called write once with quality_scores
    wm.write.assert_called_once()
    args = wm.write.call_args
    assert args[0][1] == "quality_scores"


# --------------------------------------------------------------------------- #
# LLM judge (QUALITY_JUDGE_ENABLED=true)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_evaluate_with_llm_judge(tmp_path: Path) -> None:
    _make_golden_quality_judge(tmp_path)
    llm = _make_mock_llm(tmp_path)
    evaluator = OutputQualityEvaluator(llm_client=llm, judge_enabled=True)

    score = await evaluator.evaluate("triage_agent", _high_quality_triage())
    assert score.evaluated_by == "llm"
    assert score.verdict == QualityVerdict.PASS
    assert "llm_score" in score.metrics


@pytest.mark.asyncio
async def test_llm_judge_fallback_on_error(tmp_path: Path) -> None:
    """When LLM golden is missing, fall back to rule score."""
    llm = _make_mock_llm(tmp_path)
    evaluator = OutputQualityEvaluator(llm_client=llm, judge_enabled=True)

    score = await evaluator.evaluate("triage_agent", _high_quality_triage())
    # LLM fails (no golden), falls back to rule
    assert score.evaluated_by == "rule"
    assert score.score >= PASS_THRESHOLD


# --------------------------------------------------------------------------- #
# Determinism — judge_enabled=false
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_rule_only_deterministic() -> None:
    evaluator = OutputQualityEvaluator(judge_enabled=False)
    output = _high_quality_triage()
    s1 = await evaluator.evaluate("triage_agent", output)
    s2 = await evaluator.evaluate("triage_agent", output)
    assert s1.score == s2.score
    assert s1.verdict == s2.verdict
    assert s1.evaluated_by == "rule"
    assert s2.evaluated_by == "rule"
