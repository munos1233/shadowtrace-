"""OutputGuard / OutboundDispositionGuard tests (ISSUE-030)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.agents.base import BaseAgent
from app.core.errors import GuardrailViolationError
from app.core.guardrails import (
    GUARD_RULES,
    GuardrailMode,
    InMemoryGuardViolationWriter,
    OutboundDispositionGuard,
    OutputGuard,
)
from app.models.action import Action
from app.models.agent_io import (
    Citation,
    ResponseAgentInput,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    RiskFactor,
    ScoringMode,
)
from app.models.disposition import DispositionCommand, SourceObjectLocator
from app.models.entities import EntitySet, IPEntity
from app.models.enums import (
    ActionCategory,
    ActionLevel,
    DispositionIntentKind,
    ExecutionOwner,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.report import InvestigationReport, ReportSection


def _now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC)


def _locator(**overrides: Any) -> SourceObjectLocator:
    base = {
        "source_product": "mock_xdr",
        "source_tenant_id": "t1",
        "connector_id": "conn-1",
        "source_kind": SourceObjectKind.INCIDENT,
        "source_object_id": "INC-1",
    }
    base.update(overrides)
    return SourceObjectLocator(**base)


def _command(**overrides: Any) -> DispositionCommand:
    base: dict[str, Any] = {
        "disposition_id": "disp-1",
        "action_id": "act-1",
        "closure_cycle": 1,
        "intent_kind": DispositionIntentKind.EVENT_STATUS_UPDATE,
        "source_locator": _locator(),
        "operation_code": "set_event_disposition",
        "operation_params": {
            "operation_code": "set_event_disposition",
            "target_disposition": "contained",
        },
        "operator_id": "system",
        "idempotency_key": "idem-1",
        "execution_owner": ExecutionOwner.XDR_MANAGED,
    }
    base.update(overrides)
    return DispositionCommand(**base)


def _block_action(target: str) -> Action:
    return Action(
        action_id="act-block-1",
        event_id="evt-20260101-guardrails",
        plan_revision=1,
        action_fingerprint="fp-block",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L3,
        target_type="ip",
        target=target,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
        reason="containment",
    )


def test_guard_rules_cover_required_agents() -> None:
    for agent in (
        "evidence_agent",
        "risk_agent",
        "response_agent",
        "graph_agent",
        "report_agent",
    ):
        names = {rule.rule_name for rule in GUARD_RULES[agent]}
        assert "grounding" in names
        assert "entity_target_exists" in names
    assert "citation_present" in {rule.rule_name for rule in GUARD_RULES["rag_agent"]}
    assert "citation_present" in {rule.rule_name for rule in GUARD_RULES["report_agent"]}
    assert "no_pii_leak" in {rule.rule_name for rule in GUARD_RULES["report_agent"]}


@pytest.mark.asyncio
async def test_grounding_blocks_unknown_evidence_reference() -> None:
    writer = InMemoryGuardViolationWriter()
    guard = OutputGuard(mode=GuardrailMode.ENFORCE, violation_writer=writer)
    output = RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.7,
        risk_factors=[
            RiskFactor(
                factor_name="lateral_movement",
                weight=0.5,
                raw_score=80,
                weighted_score=40,
                reasoning="supported by evd-missing-001 and evd-known-001",
            )
        ],
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    with pytest.raises(GuardrailViolationError) as exc_info:
        await guard.validate(
            "risk_agent",
            output,
            {
                "event_id": "evt-grounding",
                "evidence_ids": {"evd-known-001"},
            },
        )
    assert exc_info.value.error_code == "guardrail_violation"
    violations = exc_info.value.details["violations"]
    assert any(item["rule_name"] == "grounding" for item in violations)
    assert any(item["severity"] == "block" for item in violations)
    assert writer.by_event["evt-grounding"]


@pytest.mark.asyncio
async def test_entity_target_missing_from_entity_set_is_blocked() -> None:
    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    plan = ResponsePlan(
        plan_id="plan-1",
        actions=[_block_action("198.51.100.20")],
        strategy_summary="block external ip",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    entities = EntitySet(ips=[IPEntity(entity_id="ip-1", address="203.0.113.9", scope="external")])
    with pytest.raises(GuardrailViolationError) as exc_info:
        await guard.validate(
            "response_agent",
            plan,
            {"event_id": "evt-target", "entities": entities},
        )
    assert any(
        item["rule_name"] == "entity_target_exists" for item in exc_info.value.details["violations"]
    )


@pytest.mark.asyncio
async def test_entity_target_present_passes() -> None:
    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    plan = ResponsePlan(
        plan_id="plan-1",
        actions=[_block_action("203.0.113.9")],
        strategy_summary="block external ip",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    entities = EntitySet(ips=[IPEntity(entity_id="ip-1", address="203.0.113.9", scope="external")])
    result = await guard.validate(
        "response_agent",
        plan,
        {"event_id": "evt-target-ok", "entities": entities, "evidence_ids": set()},
    )
    assert result.passed is True


@pytest.mark.asyncio
async def test_warn_only_demotes_quality_blocks_and_returns_sanitized_output() -> None:
    writer = InMemoryGuardViolationWriter()
    guard = OutputGuard(mode=GuardrailMode.WARN_ONLY, violation_writer=writer)
    output = RiskAssessment(
        risk_score=10,
        severity=Severity.LOW,
        confidence=0.4,
        risk_factors=[
            RiskFactor(
                factor_name="noise",
                weight=0.2,
                raw_score=10,
                weighted_score=2,
                reasoning="see evd-ghost-9",
            )
        ],
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    result = await guard.validate(
        "risk_agent",
        output,
        {"event_id": "evt-warn", "evidence_ids": set()},
    )
    assert result.passed is True
    assert result.violations
    assert all(item.severity == "warn" for item in result.violations)
    assert writer.by_event["evt-warn"]


@pytest.mark.asyncio
async def test_outbound_guard_blocks_analysis_and_secret_injection() -> None:
    outbound = OutboundDispositionGuard()
    poisoned = _command().model_dump(mode="python")
    poisoned["report"] = {"summary": "do not send"}
    poisoned["parameters"] = {
        "reason": "investigation report for analyst",
        "prompt": "system prompt leak",
        "api_key": "sk-leak-1234567890abcdef",
        "raw_result": {"trace": "decision_trace"},
        "evidence": ["evd-1"],
    }
    with pytest.raises(GuardrailViolationError) as exc_info:
        await outbound.validate(
            poisoned,
            {
                "event_id": "evt-out",
                "source_locator": _locator(),
                "approved_action_ids": {"act-1"},
            },
        )
    names = {item["rule_name"] for item in exc_info.value.details["violations"]}
    assert "disposition_field_allowlist" in names
    assert "no_analysis_content_outbound" in names


@pytest.mark.asyncio
async def test_outbound_guard_enforces_source_and_approval() -> None:
    outbound = OutboundDispositionGuard()
    with pytest.raises(GuardrailViolationError) as source_exc:
        await outbound.validate(
            _command(),
            {
                "source_locator": _locator(source_object_id="INC-OTHER"),
                "approved_action_ids": {"act-1"},
            },
        )
    assert any(
        item["rule_name"] == "disposition_source_match"
        for item in source_exc.value.details["violations"]
    )

    with pytest.raises(GuardrailViolationError) as approval_exc:
        await outbound.validate(
            _command(),
            {
                "source_locator": _locator(),
                "approved_action_ids": {"act-other"},
            },
        )
    assert any(
        item["rule_name"] == "disposition_approved_action"
        for item in approval_exc.value.details["violations"]
    )


@pytest.mark.asyncio
async def test_outbound_guard_ignores_warn_only_mode_knobs() -> None:
    # OutboundDispositionGuard has no mode switch; always fail-closed.
    outbound = OutboundDispositionGuard()
    poisoned = dict(_command().model_dump(mode="python"))
    poisoned["decision_trace"] = {"steps": []}
    with pytest.raises(GuardrailViolationError):
        await outbound.validate(poisoned, {"approved_action_ids": {"act-1"}})


@pytest.mark.asyncio
async def test_outbound_guard_accepts_clean_command() -> None:
    outbound = OutboundDispositionGuard()
    result = await outbound.validate(
        _command(),
        {
            "source_locator": _locator(),
            "approved_action_ids": {"act-1"},
        },
    )
    assert result.passed is True


@pytest.mark.asyncio
async def test_base_agent_block_marks_trace_failed_and_persists_violations() -> None:
    writer = InMemoryGuardViolationWriter()
    guard = OutputGuard(mode=GuardrailMode.ENFORCE, violation_writer=writer)
    traces: list[str] = []

    class StubResponseAgent(BaseAgent[ResponseAgentInput, ResponsePlan]):
        agent_name = "response_agent"

        async def _run(self, input: ResponseAgentInput) -> ResponsePlan:
            return ResponsePlan(
                plan_id="plan-1",
                actions=[_block_action("198.51.100.66")],
                strategy_summary="bad target",
                generated_by=ResponsePlanGeneratedBy.TEMPLATE,
            )

        async def _build_guard_context(self, input: ResponseAgentInput | None) -> dict[str, Any]:
            assert input is not None
            return {
                "event_id": input.event_id,
                "entities": EntitySet(
                    ips=[IPEntity(entity_id="ip-1", address="203.0.113.9", scope="external")]
                ),
                "evidence_ids": set(),
            }

        async def _record_trace(self, **kwargs: Any) -> None:  # type: ignore[override]
            traces.append(str(kwargs.get("status")))

    agent = StubResponseAgent(output_guard=guard)
    risk = RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.8,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    with pytest.raises(GuardrailViolationError):
        await agent.execute(ResponseAgentInput(event_id="evt-agent-block", risk_assessment=risk))
    assert traces == ["failed"]
    assert writer.by_event["evt-agent-block"]
    assert any(
        item["rule_name"] == "entity_target_exists" for item in writer.by_event["evt-agent-block"]
    )


@pytest.mark.asyncio
async def test_report_no_pii_leak_blocks_api_key() -> None:
    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    report = InvestigationReport(
        report_id="rpt-1",
        event_id="evt-20260101-guardrails",
        title="Investigation",
        summary="token=sk-abcdefghijklmnopqrstuvwxyz012345",
        sections=[
            ReportSection(
                key="secrets",
                title="Secrets",
                content="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb",
            )
        ],
    )
    with pytest.raises(GuardrailViolationError) as exc_info:
        await guard.validate("report_agent", report, {"event_id": "evt-pii"})
    assert any(item["rule_name"] == "no_pii_leak" for item in exc_info.value.details["violations"])


@pytest.mark.asyncio
async def test_citation_present_for_rag_output() -> None:
    from app.models.agent_io import AttackTechniqueMatch, RAGOutput

    guard = OutputGuard(mode=GuardrailMode.ENFORCE)
    output = RAGOutput(
        attack_techniques=[
            AttackTechniqueMatch(
                technique_id="T1110",
                technique_name="Brute Force",
                match_confidence=0.9,
                citation_id="cit-missing",
            )
        ],
        citations=[],
    )
    with pytest.raises(GuardrailViolationError) as exc_info:
        await guard.validate("rag_agent", output, {"event_id": "evt-cite"})
    names = {item["rule_name"] for item in exc_info.value.details["violations"]}
    assert "citation_present" in names

    ok = RAGOutput(
        attack_techniques=[
            AttackTechniqueMatch(
                technique_id="T1110",
                technique_name="Brute Force",
                match_confidence=0.9,
                citation_id="cit-1",
            )
        ],
        citations=[
            Citation(
                citation_id="cit-1",
                chunk_id="chk-1",
                kb_name="mitre",
                quoted_text="brute force",
                relevance_score=0.9,
            )
        ],
    )
    result = await guard.validate("rag_agent", ok, {"event_id": "evt-cite-ok"})
    assert result.passed is True
