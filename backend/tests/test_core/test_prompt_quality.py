"""ISSUE-251: prompt_key invalid-rate metrics and wire-model hardening."""

from __future__ import annotations

from app.agents.prompts.planner_prompt import (
    PLAN_GENERATE_SYSTEM,
    PlanGenerateLLMResponse,
    build_plan_generate_messages,
)
from app.agents.prompts.response_prompt import (
    ResponsePlanLLMResponse,
    build_response_plan_messages,
)
from app.agents.prompts.risk_prompt import RiskScoreLLMResponse, build_risk_messages
from app.agents.prompts.storyline_prompt import (
    StorylineLLMResponse,
    build_storyline_messages,
)
from app.agents.prompts.triage_prompt import (
    TRIAGE_SYSTEM_PROMPT,
    TriageLLMResponse,
    build_triage_messages,
)
from app.core.llm.prompt_quality import (
    PROMPT_INVALID_RATE_DEMO_THRESHOLDS,
    STRUCTURED_PROMPT_TIMEOUT_SECONDS,
    compute_prompt_key_invalid_rates,
    is_invalid_json_failure,
)
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.enums import EventType, Severity


def test_structured_timeout_is_short_demo_profile() -> None:
    assert STRUCTURED_PROMPT_TIMEOUT_SECONDS == 15.0


def test_is_invalid_json_failure_prefers_error_class() -> None:
    assert is_invalid_json_failure(status="llm_invalid_json", error_class="empty_content")
    assert is_invalid_json_failure(status="llm_invalid_json", error_class="invalid_json")
    assert is_invalid_json_failure(status="llm_invalid_json", error_class="schema_validation")
    assert is_invalid_json_failure(status="llm_invalid_json", error_class=None)
    assert not is_invalid_json_failure(status="llm_timeout", error_class="timeout")
    assert not is_invalid_json_failure(status="success", error_class=None)


def test_compute_prompt_key_invalid_rates_demo_gate() -> None:
    rows = [
        {"prompt_key": "query_rewrite", "status": "success", "error_class": None},
        {"prompt_key": "query_rewrite", "status": "success", "error_class": None},
        {
            "prompt_key": "triage_extract",
            "status": "llm_invalid_json",
            "error_class": "invalid_json",
        },
        {"prompt_key": "triage_extract", "status": "success", "error_class": None},
        {"prompt_key": "triage_extract", "status": "success", "error_class": None},
        {"prompt_key": "triage_extract", "status": "success", "error_class": None},
        {
            "prompt_key": "plan_generate",
            "status": "llm_invalid_json",
            "error_class": "schema_validation",
        },
        {
            "prompt_key": "plan_generate",
            "status": "llm_invalid_json",
            "error_class": "empty_content",
        },
        {"prompt_key": "plan_generate", "status": "success", "error_class": None},
        {"prompt_key": "plan_generate", "status": "success", "error_class": None},
        {"prompt_key": "risk_score", "status": "success", "error_class": None},
        {"prompt_key": "storyline_generate", "status": "success", "error_class": None},
        {"prompt_key": "response_plan", "status": "success", "error_class": None},
    ]
    report = compute_prompt_key_invalid_rates(rows)
    by_key = {item.prompt_key: item for item in report.keys}
    assert by_key["query_rewrite"].invalid_rate == 0.0
    assert by_key["query_rewrite"].within_demo_threshold is True
    assert by_key["triage_extract"].invalid_calls == 1
    assert by_key["triage_extract"].by_error_class == {"invalid_json": 1}
    assert by_key["plan_generate"].invalid_rate == 0.5
    assert by_key["plan_generate"].within_demo_threshold is False
    assert report.all_within_demo_threshold is False
    assert PROMPT_INVALID_RATE_DEMO_THRESHOLDS["query_rewrite"] <= 0.10


def test_triage_wire_model_fills_missing_entity_id_and_ignores_extras() -> None:
    parsed = TriageLLMResponse.model_validate(
        {
            "event_type": "not_a_real_type",
            "confidence": 0.99,
            "entities": {
                "accounts": [{"username": "svc-backup", "extra_field": "drop-me"}],
                "hosts": [{"hostname": "PC-OPS-01"}],
                "ips": [],
                "domains": [],
                "processes": [],
                "files": [],
            },
            "decision_summary": "ok",
        }
    )
    assert parsed.event_type == EventType.OTHER
    assert parsed.entities.accounts[0].entity_id.startswith("acct-")
    assert parsed.entities.hosts[0].entity_id.startswith("host-")
    assert "JSON" in TRIAGE_SYSTEM_PROMPT.upper() or "json" in TRIAGE_SYSTEM_PROMPT
    messages = build_triage_messages("Account svc-backup failed login")
    assert "JSON only" in messages[1].content


def test_plan_wire_model_ignores_server_owned_fields() -> None:
    parsed = PlanGenerateLLMResponse.model_validate(
        {
            "plan_id": "pln-should-ignore",
            "event_id": "evt-should-ignore",
            "revision": 9,
            "steps": [
                {
                    "step_order": 1,
                    "step_goal": "collect",
                    "assigned_agent": "evidence_agent",
                    "required_tools": ["query_threat_intel"],
                },
                {
                    "step_order": 2,
                    "step_goal": "bad agent dropped at convert time",
                    "assigned_agent": "not_an_agent",
                },
                {
                    "step_order": 3,
                    "step_goal": "missing agent skipped in wire coerce",
                },
            ],
            "budget": {"max_tool_calls": 12},
        }
    )
    assert len(parsed.steps) == 2
    assert parsed.budget is not None
    assert parsed.budget.max_tool_calls == 12
    assert "Do NOT emit plan_id" in PLAN_GENERATE_SYSTEM
    msgs = build_plan_generate_messages("evt-1", None)
    assert "JSON only" in msgs[1]["content"]


def test_risk_storyline_response_wire_models_and_prompts() -> None:
    risk = RiskScoreLLMResponse.model_validate(
        {
            "factors": {
                "asset_impact": {"score": "80", "reasoning": "asset critical"},
                "behavior_anomaly": {"score": 70, "reason": "anomaly"},
                "evidence_confidence": {"score": 60},
                "attack_stage": {"score": 50},
                "data_sensitivity": {"bad": True},
                "threat_intel": {"score": 40, "reason": "ti"},
            },
            "raw_confidence": "0.7",
        }
    )
    assert "asset_impact" in risk.factors
    assert risk.factors["asset_impact"].reason == "asset critical"
    assert "data_sensitivity" not in risk.factors

    story = StorylineLLMResponse.model_validate(
        {
            "narrative_summary": "n",
            "phases": [
                {
                    "phase_name": "initial_access",
                    "entries": [{"description": "x", "timestamp": "2025-01-01T00:00:00Z"}],
                }
            ],
            "storyline_id": "ignored",
        }
    )
    assert story.phases[0].entries[0].evidence_id == ""

    response = ResponsePlanLLMResponse.model_validate(
        {
            "actions": [
                {"tool_name": "create_ticket", "parameters": {"title": "t"}},
                "bad",
            ],
            "strategy_summary": "s",
            "extra": 1,
        }
    )
    assert len(response.actions) == 1

    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=True,
        reasoning="r",
    )
    evidence = EvidenceOutput(
        evidence_list=[],
        overall_confidence=0.1,
        collection_status=CollectionStatus.PARTIAL_DONE,
        success_sources=[],
        failed_sources=[],
    )
    risk_msgs = build_risk_messages(triage_result=triage, evidence_output=evidence)
    assert "JSON only" in risk_msgs[1].content
    story_msgs = build_storyline_messages(
        evidence_entries=[],
        technique_matches=[],
        graph_paths=[],
        entity_names=[],
    )
    assert "JSON only" in story_msgs[1].content
    response_msgs = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=RiskAssessment(
            risk_score=10,
            severity=Severity.LOW,
            confidence=0.2,
            risk_factors=[],
            scoring_mode=ScoringMode.RULE_ONLY,
        ),
        evidence_output=evidence,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    assert "JSON only" in response_msgs[1].content
