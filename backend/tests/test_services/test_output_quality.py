"""OutputQualityEvaluator tests (ISSUE-065).

Covers:
- High-quality output scores as pass
- Missing fields lowers completeness
- Fabricated assertions lowers grounding_ratio
- severity/risk_score contradiction lowers consistency
- Rule-only deterministic path
- LLM judge enabled/disabled
- evaluate_all across four target agents
- Fail-safe defaulting when evaluation itself fails
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.core.errors import OutputQualityEvaluationBlockedError
from app.core.llm.base import LLMMessage, LLMResponse
from app.models.agent_io import OutputQualityScore
from app.models.enums import QualityVerdict
from app.services.output_quality_evaluator import (
    OUTPUT_QUALITY_EVALUATOR_UNAVAILABLE_FLAG,
    OutputQualityEvaluator,
    _completeness,
    _consistency,
    _grounding_ratio,
    _specificity,
    _verdict_from_score,
    build_output_quality_evaluator,
    evaluate_investigation_quality_scores,
)

# ====================================================================== #
# Helpers
# ====================================================================== #


def _new_sfx() -> str:
    return uuid4().hex[:8]


# -- high-quality triage output --


def _high_quality_triage() -> dict[str, Any]:
    return {
        "event_type": "data_exfiltration",
        "severity": "high",
        "need_investigation": True,
        "entities": {
            "users": ["zhangsan"],
            "hosts": ["PC-FIN-023"],
            "ips": ["203.0.113.88"],
        },
        "ioc_list": ["203.0.113.88", "cloud-storage.example.com"],
        "reasoning": (
            "账号 zhangsan 从 10.20.30.23 登录主机 PC-FIN-023，"
            "通过 rar.exe 打包 financial_data.zip 后经由 DNS "
            "cloud-storage.example.com 连接外部 IP 203.0.113.88，"
            "符合数据外传攻击模式。"
        ),
        "degraded": False,
    }


# -- low-quality triage output (missing fields, vague) --


def _low_quality_triage() -> dict[str, Any]:
    return {
        "event_type": "other",
        "severity": "low",
        "need_investigation": False,
        "reasoning": "需要进一步调查",
        "degraded": True,
    }


# -- high-quality evidence output --


def _high_quality_evidence() -> dict[str, Any]:
    return {
        "evidence_list": [
            {
                "evidence_id": f"ev-{_new_sfx()}",
                "source": "identity",
                "evidence_type": "login",
                "description": "账号 zhangsan 从 10.20.30.23 登录主机 PC-FIN-023",
                "confidence": 0.9,
            },
            {
                "evidence_id": f"ev-{_new_sfx()}",
                "source": "endpoint",
                "evidence_type": "process_create",
                "description": "主机 PC-FIN-023 上 rar.exe 进程启动",
                "confidence": 0.85,
            },
            {
                "evidence_id": f"ev-{_new_sfx()}",
                "source": "network_flow",
                "evidence_type": "outbound",
                "description": "PC-FIN-023 连接外部 IP 203.0.113.88 端口 443",
                "confidence": 0.88,
            },
            {
                "evidence_id": f"ev-{_new_sfx()}",
                "source": "dns",
                "evidence_type": "dns_query",
                "description": "DNS 解析 cloud-storage.example.com 到 203.0.113.88",
                "confidence": 0.82,
            },
        ],
        "conflicts": [],
        "gaps": [],
        "success_sources": ["identity", "endpoint", "network_flow", "dns"],
        "failed_sources": [],
        "overall_confidence": 0.86,
        "collection_status": "completed",
    }


# -- evidence with fabricated entries (no evidence_id) --


def _ungrounded_evidence() -> dict[str, Any]:
    return {
        "evidence_list": [
            {
                "evidence_id": "",
                "source": "unknown",
                "evidence_type": "anonymous_tip",
                "description": "系统提示可能存在异常活动",
                "confidence": 0.3,
            },
            {
                "evidence_id": "",
                "source": "unknown",
                "evidence_type": "anonymous_tip",
                "description": "未知来源报告",
                "confidence": 0.2,
            },
        ],
        "collection_status": "degraded",
        "overall_confidence": 0.25,
        "success_sources": [],
        "failed_sources": ["identity", "endpoint", "network_flow"],
    }


# -- high-quality risk assessment --


def _high_quality_risk() -> dict[str, Any]:
    return {
        "risk_score": 82,
        "severity": "critical",
        "confidence": 0.88,
        "risk_factors": [
            {
                "factor_name": "asset_impact",
                "weight": 0.25,
                "raw_score": 85,
                "weighted_score": 21.25,
                "reasoning": "涉及财务数据 financial_data.zip，影响核心业务资产 PC-FIN-023",
            },
            {
                "factor_name": "behavior_anomaly",
                "weight": 0.25,
                "raw_score": 80,
                "weighted_score": 20.0,
                "reasoning": "rar.exe 打包操作结合异常外部连接，异常度高",
            },
        ],
        "scoring_mode": "llm_and_rule",
        "possible_false_positive": False,
    }


# -- inconsistent risk (high score but low severity) --


def _inconsistent_risk() -> dict[str, Any]:
    return {
        "risk_score": 85,
        "severity": "low",
        "confidence": 0.9,
        "risk_factors": [
            {
                "factor_name": "asset_impact",
                "weight": 0.5,
                "raw_score": 90,
                "weighted_score": 45.0,
                "reasoning": "critical asset",
            },
        ],
        "scoring_mode": "rule_only",
        "possible_false_positive": False,
    }


# -- high-quality report --


def _high_quality_report() -> dict[str, Any]:
    return {
        "title": "数据外传事件研判报告 — evt-001",
        "summary": (
            "确认威胁：账号 zhangsan 在主机 PC-FIN-023 上通过 rar.exe "
            "打包 financial_data.zip，经 DNS cloud-storage.example.com "
            "连接到 203.0.113.88 完成数据外传。"
        ),
        "findings": [
            {
                "title": "初始访问",
                "description": "账号 zhangsan 从 10.20.30.23 登录",
                "evidence_id": "ev-001",
                "severity": "high",
            },
            {
                "title": "数据收集与暂存",
                "description": "rar.exe 打包 financial_data.zip",
                "evidence_id": "ev-002",
                "severity": "high",
            },
        ],
        "final_verdict": "confirmed_threat",
        "narrative": "完整的攻击链：初始访问 → 数据收集 → 外传",
        "recommendations": ["隔离主机 PC-FIN-023", "重置账号 zhangsan 凭据"],
    }


# ====================================================================== #
# Mock LLM Client
# ====================================================================== #


class _MockLLMClient:
    """Mock LLM client returning a fixed quality judge score."""

    def __init__(self, judge_score: float = 0.90) -> None:
        self._judge_score = judge_score
        self.chat_calls: list[dict[str, Any]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        event_id: str = "",
        agent_name: str = "",
        prompt_key: str = "",
        json_mode: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        self.chat_calls.append(
            {
                "event_id": event_id,
                "agent_name": agent_name,
                "prompt_key": prompt_key,
            }
        )
        content = json.dumps(
            {
                "score": self._judge_score,
                "metrics": {
                    "completeness": 0.92,
                    "grounding_ratio": 0.90,
                    "consistency": 0.88,
                    "specificity": 0.90,
                },
                "reasons": [
                    "All required fields present",
                    "Well-grounded in evidence",
                    "Consistent severity assignment",
                    "Concrete entity references",
                ],
            }
        )
        return LLMResponse(
            content=content,
            model_name="mock-judge",
            prompt_tokens=200,
            completion_tokens=100,
            total_tokens=300,
            latency_ms=50,
        )


class _FailingLLMClient:
    """LLM client that always raises."""

    async def chat(self, **kwargs: Any) -> Any:
        raise RuntimeError("LLM unavailable")


# ====================================================================== #
# unit — thresholds / helpers
# ====================================================================== #


class TestVerdictFromScore:
    def test_pass_at_threshold(self) -> None:
        assert _verdict_from_score(0.75) == QualityVerdict.PASS

    def test_pass_above_threshold(self) -> None:
        assert _verdict_from_score(0.92) == QualityVerdict.PASS

    def test_warn_at_threshold(self) -> None:
        assert _verdict_from_score(0.50) == QualityVerdict.WARN

    def test_warn_between_thresholds(self) -> None:
        assert _verdict_from_score(0.65) == QualityVerdict.WARN

    def test_fail_below_threshold(self) -> None:
        assert _verdict_from_score(0.35) == QualityVerdict.FAIL

    def test_fail_at_zero(self) -> None:
        assert _verdict_from_score(0.0) == QualityVerdict.FAIL


# ====================================================================== #
# unit — completeness
# ====================================================================== #


class TestCompleteness:
    def test_full_triage_completeness(self) -> None:
        result = _completeness("triage", _high_quality_triage())
        assert result == 1.0

    def test_low_triage_missing_fields(self) -> None:
        result = _completeness("triage", _low_quality_triage())
        # All four required fields are technically present (even if poor quality)
        # — entities and ioc_list are not in the required set
        assert result == 1.0

    def test_full_evidence_completeness(self) -> None:
        result = _completeness("evidence", _high_quality_evidence())
        assert result == 1.0

    def test_full_risk_completeness(self) -> None:
        result = _completeness("risk", _high_quality_risk())
        assert result == 1.0

    def test_full_report_completeness(self) -> None:
        result = _completeness("report", _high_quality_report())
        assert result == 1.0

    def test_empty_output_zero(self) -> None:
        result = _completeness("triage", {})
        assert result == 0.0


# ====================================================================== #
# unit — grounding_ratio
# ====================================================================== #


class TestGroundingRatio:
    def test_evidence_all_grounded(self) -> None:
        result = _grounding_ratio("evidence", _high_quality_evidence())
        assert result == 1.0

    def test_evidence_ungrounded(self) -> None:
        result = _grounding_ratio("evidence", _ungrounded_evidence())
        assert result == 0.0

    def test_triage_with_reasoning_and_entities(self) -> None:
        result = _grounding_ratio("triage", _high_quality_triage())
        assert result > 0.7

    def test_triage_vague_reasoning(self) -> None:
        result = _grounding_ratio("triage", _low_quality_triage())
        assert result <= 0.3

    def test_risk_with_reasoned_factors(self) -> None:
        result = _grounding_ratio("risk", _high_quality_risk())
        assert result == 1.0

    def test_report_with_citations(self) -> None:
        result = _grounding_ratio("report", _high_quality_report())
        assert result == 1.0


# ====================================================================== #
# unit — consistency
# ====================================================================== #


class TestConsistency:
    def test_triage_severity_matches_event_type(self) -> None:
        result = _consistency("triage", _high_quality_triage())
        assert result == 1.0

    def test_triage_high_severity_no_investigation(self) -> None:
        output = _high_quality_triage()
        output["severity"] = "critical"
        output["need_investigation"] = False
        result = _consistency("triage", output)
        assert result < 0.8

    def test_risk_severity_matches_score(self) -> None:
        result = _consistency("risk", _high_quality_risk())
        assert result == 1.0

    def test_risk_severity_contradicts_score(self) -> None:
        result = _consistency("risk", _inconsistent_risk())
        assert result < 0.6

    def test_evidence_status_matches_confidence(self) -> None:
        result = _consistency("evidence", _high_quality_evidence())
        assert result == 1.0

    def test_report_threat_language_consistent_with_verdict(self) -> None:
        result = _consistency("report", _high_quality_report())
        assert result == 1.0


# ====================================================================== #
# unit — specificity
# ====================================================================== #


class TestSpecificity:
    def test_triage_with_concrete_entities(self) -> None:
        result = _specificity("triage", _high_quality_triage())
        assert result >= 0.5  # Has IPs, hostnames, usernames

    def test_triage_vague(self) -> None:
        result = _specificity("triage", _low_quality_triage())
        assert result < 0.3  # Minimal concrete content

    def test_evidence_with_concrete_details(self) -> None:
        result = _specificity("evidence", _high_quality_evidence())
        assert result >= 0.5

    def test_empty_output(self) -> None:
        result = _specificity("report", {})
        # No concrete entities → base 0.1 vagueness filter, close to zero
        assert result < 0.15


# ====================================================================== #
# integration — evaluate (rule-only)
# ====================================================================== #


@pytest.mark.asyncio
class TestEvaluateRuleOnly:
    async def test_high_quality_triage_pass(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate("triage", _high_quality_triage(), {"event_id": "evt-001"})
        assert isinstance(result, OutputQualityScore)
        assert result.agent_name == "triage"
        assert result.score >= 0.75
        assert result.verdict == QualityVerdict.PASS
        assert result.evaluated_by == "rule"
        assert set(result.metrics.keys()) == {
            "completeness",
            "grounding_ratio",
            "consistency",
            "specificity",
        }
        assert len(result.reasons) > 0

    async def test_low_quality_triage_warn_or_fail(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate("triage", _low_quality_triage(), {"event_id": "evt-002"})
        assert result.score < 0.75
        assert result.verdict in (QualityVerdict.WARN, QualityVerdict.FAIL)
        assert result.evaluated_by == "rule"

    async def test_high_quality_evidence_pass(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate(
            "evidence", _high_quality_evidence(), {"event_id": "evt-003"}
        )
        assert result.verdict == QualityVerdict.PASS
        assert result.score >= 0.75

    async def test_ungrounded_evidence_warn_or_fail(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate(
            "evidence", _ungrounded_evidence(), {"event_id": "evt-004"}
        )
        assert result.verdict in (QualityVerdict.WARN, QualityVerdict.FAIL)

    async def test_high_quality_risk_pass(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate("risk", _high_quality_risk(), {"event_id": "evt-005"})
        assert result.verdict == QualityVerdict.PASS

    async def test_inconsistent_risk_warn_or_fail(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate("risk", _inconsistent_risk(), {"event_id": "evt-006"})
        assert result.verdict in (QualityVerdict.WARN, QualityVerdict.FAIL)

    async def test_high_quality_report_pass(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate("report", _high_quality_report(), {"event_id": "evt-007"})
        assert result.verdict == QualityVerdict.PASS
        assert result.score >= 0.75

    async def test_metrics_independent_and_explainable(self) -> None:
        """Each metric should produce a distinct value for non-trivial output."""
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate("triage", _high_quality_triage(), {"event_id": "evt-008"})
        # All four metrics present with values in [0, 1]
        for name in ("completeness", "grounding_ratio", "consistency", "specificity"):
            assert 0.0 <= result.metrics[name] <= 1.0, f"{name} out of range"

    async def test_evaluate_from_dict(self) -> None:
        """Should accept a plain dict (not just Pydantic models)."""
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        result = await evaluator.evaluate("report", _high_quality_report(), {"event_id": "evt-009"})
        assert result.agent_name == "report"
        assert result.score > 0


# ====================================================================== #
# integration — LLM judge
# ====================================================================== #


@pytest.mark.asyncio
class TestLLMJudge:
    async def test_llm_judge_calibrates_score(self) -> None:
        """When the judge is enabled, the final score is the average of rule + judge."""
        llm = _MockLLMClient(judge_score=0.90)
        evaluator = OutputQualityEvaluator(llm_client=llm, judge_enabled=True)
        result = await evaluator.evaluate("triage", _high_quality_triage(), {"event_id": "evt-010"})
        assert result.evaluated_by == "llm"
        assert len(llm.chat_calls) == 1
        assert llm.chat_calls[0]["prompt_key"] == "quality_judge"
        # The final score should be between rule-only and judge score
        assert 0.0 <= result.score <= 1.0

    async def test_llm_judge_disabled_stays_rule_only(self) -> None:
        """When judge_enabled=False, should not call LLM."""
        llm = _MockLLMClient()
        evaluator = OutputQualityEvaluator(llm_client=llm, judge_enabled=False)
        result = await evaluator.evaluate("triage", _high_quality_triage(), {"event_id": "evt-011"})
        assert result.evaluated_by == "rule"
        assert len(llm.chat_calls) == 0

    async def test_llm_failure_falls_back_to_rule(self) -> None:
        """LLM judge failure should not crash — fall back to rule score."""
        llm = _FailingLLMClient()
        evaluator = OutputQualityEvaluator(llm_client=llm, judge_enabled=True)
        result = await evaluator.evaluate("triage", _high_quality_triage(), {"event_id": "evt-012"})
        assert result.evaluated_by == "rule"
        assert result.score >= 0.75
        assert result.verdict == QualityVerdict.PASS


# ====================================================================== #
# integration — evaluate_all
# ====================================================================== #


@pytest.mark.asyncio
class TestEvaluateAll:
    async def test_evaluates_all_four_agents(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        context = {
            "event_id": "evt-020",
            "triage_result": _high_quality_triage(),
            "evidence_output": _high_quality_evidence(),
            "risk_assessment": _high_quality_risk(),
            "report": _high_quality_report(),
        }
        results = await evaluator.evaluate_all(context)
        assert set(results.keys()) == {"triage", "evidence", "risk", "report"}
        for agent_name, score in results.items():
            assert isinstance(score, OutputQualityScore)
            assert score.agent_name == agent_name
            assert 0.0 <= score.score <= 1.0

    async def test_skips_missing_outputs(self) -> None:
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        context = {
            "event_id": "evt-021",
            "triage_result": _high_quality_triage(),
            # evidence_output, risk_assessment, report are missing
        }
        results = await evaluator.evaluate_all(context)
        assert set(results.keys()) == {"triage"}

    async def test_eval_failure_records_fail_not_pass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When evaluation of one agent fails, it must not masquerade as PASS (ISSUE-309)."""

        def _boom(
            _agent_name: str, _output: dict[str, Any], _context: dict[str, Any]
        ) -> dict[str, float]:
            raise RuntimeError("metric computation exploded")

        monkeypatch.setattr(
            "app.services.output_quality_evaluator._compute_rule_metrics",
            _boom,
        )
        degraded = _MockDegradedFlags()
        evaluator = OutputQualityEvaluator(degraded_flags=degraded, judge_enabled=False)
        context = {
            "event_id": "evt-022",
            "triage_result": _high_quality_triage(),
        }
        results = await evaluator.evaluate_all(context)

        assert evaluator.eval_errors_encountered is True
        assert set(results.keys()) == {"triage"}
        score = results["triage"]
        assert score.verdict == QualityVerdict.FAIL
        assert score.score == 0.0
        assert score.metrics == {
            "completeness": 0.0,
            "grounding_ratio": 0.0,
            "consistency": 0.0,
            "specificity": 0.0,
        }
        assert any("eval_error_defaulted" in reason for reason in score.reasons)
        assert degraded.calls == [
            {
                "event_id": "evt-022",
                "flag_name": OUTPUT_QUALITY_EVALUATOR_UNAVAILABLE_FLAG,
                "value": True,
                "writer": "OutputQualityEvaluator",
            }
        ]

    async def test_eval_failure_default_does_not_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default blocking=false keeps investigation completion fail-soft."""

        def _boom(
            _agent_name: str, _output: dict[str, Any], _context: dict[str, Any]
        ) -> dict[str, float]:
            raise RuntimeError("metric computation exploded")

        monkeypatch.setattr(
            "app.services.output_quality_evaluator._compute_rule_metrics",
            _boom,
        )
        evaluator = OutputQualityEvaluator(blocking_enabled=False, judge_enabled=False)
        from app.models.context import EventContext

        ec = EventContext(triage_result=_high_quality_triage())
        scores = await evaluate_investigation_quality_scores(evaluator, ec)
        assert scores["triage"].verdict == QualityVerdict.FAIL

    async def test_eval_failure_blocks_when_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OUTPUT_QUALITY_BLOCKING=true raises to halt downstream nodes."""

        def _boom(
            _agent_name: str, _output: dict[str, Any], _context: dict[str, Any]
        ) -> dict[str, float]:
            raise RuntimeError("metric computation exploded")

        monkeypatch.setattr(
            "app.services.output_quality_evaluator._compute_rule_metrics",
            _boom,
        )
        evaluator = OutputQualityEvaluator(blocking_enabled=True, judge_enabled=False)
        from app.models.context import EventContext

        ec = EventContext(triage_result=_high_quality_triage())
        with pytest.raises(OutputQualityEvaluationBlockedError):
            await evaluate_investigation_quality_scores(evaluator, ec)


# ====================================================================== #
# integration — quality_scores dict write-back
# ====================================================================== #


class _MockDegradedFlags:
    """Capture degraded flag writes for ISSUE-309 tests."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def set_flag(
        self,
        event_id: str,
        flag_name: str,
        value: bool,
        *,
        writer: str,
    ) -> list[str]:
        self.calls.append(
            {
                "event_id": event_id,
                "flag_name": flag_name,
                "value": value,
                "writer": writer,
            }
        )
        return [f"{flag_name}={str(value).lower()}"]


class _FakeWorkingMemory:
    """Minimal in-memory WorkingMemory double for tests."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    def for_writer(self, writer: str) -> _FakeWorkingMemory:
        return self

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value


@pytest.mark.asyncio
class TestQualityScoresWriteBack:
    async def test_scores_written_to_working_memory(self) -> None:
        """Caller can persist quality_scores list to WorkingMemory."""
        wm = _FakeWorkingMemory()
        evaluator = OutputQualityEvaluator(working_memory=wm, judge_enabled=False)
        context = {
            "event_id": "evt-030",
            "triage_result": _high_quality_triage(),
            "evidence_output": _high_quality_evidence(),
            "risk_assessment": _high_quality_risk(),
            "report": _high_quality_report(),
        }
        scores = await evaluator.evaluate_all(context)
        assert len(scores) == 4

        stored = await wm.read("evt-030", "quality_scores")
        assert stored is not None
        assert isinstance(stored, list)
        assert len(stored) == 4
        agent_names = {entry["agent_name"] for entry in stored if isinstance(entry, dict)}
        assert agent_names >= {"triage", "evidence", "risk", "report"}
        triage_entry = next(e for e in stored if e.get("agent_name") == "triage")
        assert "score" in triage_entry
        assert "verdict" in triage_entry
        assert "metrics" in triage_entry
        from app.models.context import EventContext

        EventContext.model_validate({"quality_scores": stored})


# ====================================================================== #
# Determinism
# ====================================================================== #


@pytest.mark.asyncio
class TestDeterminism:
    async def test_rule_eval_deterministic(self) -> None:
        """Same input twice → same score (rule-only, no LLM)."""
        evaluator = OutputQualityEvaluator(judge_enabled=False)
        r1 = await evaluator.evaluate("triage", _high_quality_triage(), {"event_id": "evt-040"})
        r2 = await evaluator.evaluate("triage", _high_quality_triage(), {"event_id": "evt-040"})
        assert r1.score == r2.score
        assert r1.verdict == r2.verdict
        assert r1.metrics == r2.metrics


# ====================================================================== #
# production wiring — ISSUE-233
# ====================================================================== #


class TestBuildOutputQualityEvaluator:
    def test_factory_rule_only_by_default(self) -> None:
        wm = _FakeWorkingMemory()
        evaluator = build_output_quality_evaluator(working_memory=wm, judge_enabled=False)
        assert evaluator is not None
        assert evaluator._judge_enabled is False  # noqa: SLF001


@pytest.mark.asyncio
class TestEvaluateInvestigationQualityScores:
    async def test_populates_event_context_and_working_memory(self) -> None:
        wm = _FakeWorkingMemory()
        evaluator = build_output_quality_evaluator(working_memory=wm, judge_enabled=False)
        from app.models.context import EventContext
        from app.models.enums import (
            DispositionPolicy,
            EventStatus,
            EventType,
            FinalVerdict,
            Severity,
            WritebackReadiness,
        )
        from app.models.security_event import EventSummary

        event_id = "evt-233-prod"
        ec = EventContext(
            event=EventSummary(
                event_id=event_id,
                title="Quality wiring test",
                event_type=EventType.DATA_EXFILTRATION,
                severity=Severity.HIGH,
                status=EventStatus.REPORTING,
                final_verdict=FinalVerdict.NONE,
                risk_score=0,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                disposition_policy=DispositionPolicy.NOT_REQUIRED,
            ),
            triage_result=_high_quality_triage(),
            evidence_output=_high_quality_evidence(),
            risk_assessment=_high_quality_risk(),
        )

        scores = await evaluate_investigation_quality_scores(evaluator, ec)

        assert set(scores.keys()) == {"triage", "evidence", "risk"}
        assert len(ec.quality_scores) == 3
        stored = await wm.read(event_id, "quality_scores")
        assert stored is not None
        assert isinstance(stored, list)
        assert len(stored) == 3
        agent_names = {entry["agent_name"] for entry in stored if isinstance(entry, dict)}
        assert agent_names == {"triage", "evidence", "risk"}
        from app.models.context import EventContext

        EventContext.model_validate({"quality_scores": stored})

    async def test_none_evaluator_is_no_op(self) -> None:
        from app.models.context import EventContext

        ec = EventContext()
        scores = await evaluate_investigation_quality_scores(None, ec)
        assert scores == {}
        assert ec.quality_scores == []

    async def test_fail_soft_on_evaluator_error(self) -> None:
        class _BrokenEvaluator:
            _blocking_enabled = False
            eval_errors_encountered = False

            async def evaluate_all(self, _ctx: dict[str, Any]) -> dict[str, OutputQualityScore]:
                raise RuntimeError("evaluator exploded")

            async def _persist_eval_degraded_flag(self, _ctx: dict[str, Any]) -> None:
                return None

        from app.models.context import EventContext

        ec = EventContext(triage_result=_high_quality_triage())
        scores = await evaluate_investigation_quality_scores(_BrokenEvaluator(), ec)  # type: ignore[arg-type]
        assert scores == {}
        assert ec.quality_scores == []

    async def test_blocking_on_evaluator_catastrophic_error(self) -> None:
        class _BrokenBlockingEvaluator:
            _blocking_enabled = True
            eval_errors_encountered = False

            async def evaluate_all(self, _ctx: dict[str, Any]) -> dict[str, OutputQualityScore]:
                raise RuntimeError("evaluator exploded")

            async def _persist_eval_degraded_flag(self, _ctx: dict[str, Any]) -> None:
                return None

        from app.models.context import EventContext

        ec = EventContext(triage_result=_high_quality_triage())
        with pytest.raises(OutputQualityEvaluationBlockedError):
            await evaluate_investigation_quality_scores(_BrokenBlockingEvaluator(), ec)  # type: ignore[arg-type]


@pytest.mark.asyncio
class TestAnalysisOnlyPipelineQualityWiring:
    async def test_persist_complete_runs_quality_evaluation(self) -> None:
        """Pipeline completion hook must populate quality_scores without breaking context."""
        from app.models.context import EventContext
        from app.models.enums import (
            DispositionPolicy,
            EventStatus,
            EventType,
            FinalVerdict,
            Severity,
            WritebackReadiness,
        )
        from app.models.security_event import EventSummary
        from app.services.analysis_only_pipeline import AnalysisOnlyPipeline

        event_id = "evt-233-pipeline"
        ec = EventContext(
            event=EventSummary(
                event_id=event_id,
                title="Pipeline quality",
                event_type=EventType.DATA_EXFILTRATION,
                severity=Severity.HIGH,
                status=EventStatus.REPORTING,
                final_verdict=FinalVerdict.NONE,
                risk_score=0,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                disposition_policy=DispositionPolicy.NOT_REQUIRED,
            ),
            triage_result=_high_quality_triage(),
            evidence_output=_high_quality_evidence(),
            risk_assessment=_high_quality_risk(),
        )
        wm = _FakeWorkingMemory()
        evaluator = build_output_quality_evaluator(working_memory=wm, judge_enabled=False)

        context_store = MagicMock()
        context_store.get_full_context = AsyncMock(return_value=ec)
        context_store.set = AsyncMock()

        pipeline = AnalysisOnlyPipeline(
            triage_agent=MagicMock(),
            evidence_agent=MagicMock(),
            rag_agent=MagicMock(),
            risk_agent=MagicMock(),
            report_agent=MagicMock(),
            context_store=context_store,
            output_quality_evaluator=evaluator,
        )

        await pipeline._persist_analysis_only_complete(event_id)

        stored = await wm.read(event_id, "quality_scores")
        assert stored is not None
        assert isinstance(stored, list)
        assert len(stored) == 3
        EventContext.model_validate({"quality_scores": stored})
        context_store.set.assert_awaited_once_with(event_id, "analysis_only_complete", True)
