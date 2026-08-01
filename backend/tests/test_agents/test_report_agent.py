"""ReportAgent 15-section report generation tests (ISSUE-036)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.agents.report_agent import (
    GENERATED_BY_LLM,
    GENERATED_BY_TEMPLATE,
    ReportAgent,
    generate_report_action_fingerprint,
)
from app.agents.report_llm_failure import llm_failure_metadata
from app.agents.report_section_builder import (
    PLACEHOLDER_LOW_RISK_NO_EVIDENCE,
    PLACEHOLDER_NO_ACTIONS,
    PLACEHOLDER_NO_VERIFICATION,
    SECTION_KEYS,
    ReportSectionBuilder,
)
from app.core.errors import LLMError
from app.core.llm.base import InMemoryLLMCallAuditRecorder, LLMResponse
from app.core.llm.mock_client import MockLLMClient
from app.models.action import Action
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ReportAgentInput,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    RiskFactor,
    ScoringMode,
    TriageResult,
)
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    HostEntity,
    IPEntity,
)
from app.models.enums import (
    ActionCategory,
    ActionLevel,
    ActionStatus,
    EventType,
    EvidenceSource,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.evidence import Evidence, EvidenceGap
from app.models.ids import new_evidence_id, report_id_for_event
from app.services.agent_trace_service import TraceProjection


class _FakeWorkingMemory:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        return None


class _FakeEventService:
    def __init__(self) -> None:
        self.reports: dict[str, Any] = {}
        self.reports_by_event: dict[str, Any] = {}
        self.actions: list[dict[str, Any]] = []
        self.final_verdicts: dict[str, FinalVerdict] = {}
        self._fingerprints: set[str] = set()

    async def get_event(self, event_id: str) -> Any:
        return SimpleNamespace(
            event_id=event_id,
            final_verdict=self.final_verdicts.get(event_id, FinalVerdict.NONE),
        )

    async def upsert_report(self, report: Any) -> Any:
        existing = self.reports.get(report.report_id)
        if existing is None:
            report.version = 1
        else:
            report.version = int(existing.version) + 1
        report.updated_at = datetime.now(UTC)
        self.reports[report.report_id] = report
        self.reports_by_event[report.event_id] = report
        return report

    async def get_report(
        self,
        *,
        report_id: str | None = None,
        event_id: str | None = None,
    ) -> Any:
        if report_id is not None:
            return self.reports.get(report_id)
        if event_id is not None:
            return self.reports_by_event.get(event_id)
        return None

    async def upsert_generate_report_action(self, event_id: str, *, plan_revision: int = 1) -> str:
        fp = generate_report_action_fingerprint(event_id, plan_revision)
        if fp in self._fingerprints:
            for action in self.actions:
                if action["action_fingerprint"] == fp:
                    return action["action_id"]
        action_id = f"act-{uuid4().hex[:8]}"
        self._fingerprints.add(fp)
        self.actions.append(
            {
                "action_id": action_id,
                "event_id": event_id,
                "plan_revision": plan_revision,
                "action_fingerprint": fp,
                "action_category": "system",
                "action_name": "generate_report",
                "tool_name": "generate_report",
                "action_level": "l0",
                "status": "success",
            }
        )
        return action_id


class _FakeEventBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    async def publish_event(
        self, event_id: str, message_type: str, payload: dict[str, Any] | None = None
    ) -> bool:
        self.events.append((event_id, message_type, dict(payload or {})))
        return True


class _FailingLLM:
    async def chat(self, *args: Any, **kwargs: Any) -> LLMResponse:
        raise RuntimeError("llm unavailable")


class _StructuredLLMErrorClient:
    async def chat(self, *args: Any, **kwargs: Any) -> LLMResponse:
        raise LLMError(
            "provider returned invalid json",
            error_code="llm_invalid_json",
            details={"http_status": 502},
        )


class _PartialLLM:
    async def chat(self, *args: Any, **kwargs: Any) -> LLMResponse:
        return LLMResponse(
            content='{"title":"partial","summary":"partial","sections":{"overview":"only one"}}',
            model_name="partial",
        )


def _evd(
    *,
    source: EvidenceSource,
    evidence_type: str,
    confidence: float,
    event_id: str,
    description: str,
    raw: dict[str, Any],
    mitre: str | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=new_evidence_id(),
        event_id=event_id,
        source=source,
        evidence_type=evidence_type,
        description=description,
        confidence=confidence,
        timestamp=datetime(2024, 6, 15, 9, 0, tzinfo=UTC),
        raw_data=raw,
        mitre_technique=mitre,
        related_entities=[],
    )


def _main_triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            accounts=[AccountEntity(entity_id="a1", username="zhangsan")],
            hosts=[
                HostEntity(
                    entity_id="h1",
                    hostname="PC-FIN-023",
                    ip="10.20.30.23",
                )
            ],
            ips=[
                IPEntity(entity_id="i1", address="10.20.30.23", scope="internal"),
                IPEntity(entity_id="i2", address="203.0.113.88", scope="external"),
            ],
            domains=[
                DomainEntity(entity_id="d1", fqdn="unknown-upload-example.com"),
            ],
        ),
        ioc_list=["203.0.113.88"],
        reasoning="insider exfiltration",
    )


def _main_evidence(event_id: str) -> EvidenceOutput:
    return EvidenceOutput(
        evidence_list=[
            _evd(
                source=EvidenceSource.IDENTITY,
                evidence_type="login_lookup",
                confidence=0.7,
                event_id=event_id,
                description="账号 zhangsan 无交互登录",
                raw={"account": "zhangsan", "result": "no_record"},
            ),
            _evd(
                source=EvidenceSource.ENDPOINT,
                evidence_type="process_create",
                confidence=0.9,
                event_id=event_id,
                description="powershell archive on PC-FIN-023",
                raw={
                    "hostname": "PC-FIN-023",
                    "account": "zhangsan",
                    "process": "powershell.exe",
                },
                mitre="T1059.001",
            ),
            _evd(
                source=EvidenceSource.NETWORK_FLOW,
                evidence_type="egress",
                confidence=0.91,
                event_id=event_id,
                description="egress to 203.0.113.88",
                raw={"dst_ip": "203.0.113.88", "hostname": "PC-FIN-023"},
                mitre="T1048",
            ),
            _evd(
                source=EvidenceSource.THREAT_INTEL,
                evidence_type="ip_reputation",
                confidence=0.8,
                event_id=event_id,
                description="threat intel hit 203.0.113.88",
                raw={"indicator": "203.0.113.88"},
            ),
        ],
        success_sources=["identity", "endpoint", "network_flow", "threat_intel"],
        failed_sources=[],
        overall_confidence=0.86,
        collection_status=CollectionStatus.COMPLETED,
    )


def _high_risk() -> RiskAssessment:
    factors = [
        RiskFactor(
            factor_name=name,
            weight=weight,
            raw_score=80.0,
            weighted_score=80.0 * weight,
            reasoning=f"rule:{name}",
        )
        for name, weight in (
            ("asset_impact", 0.20),
            ("behavior_anomaly", 0.20),
            ("evidence_confidence", 0.15),
            ("attack_stage", 0.20),
            ("data_sensitivity", 0.15),
            ("threat_intel", 0.10),
        )
    ]
    return RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.72,
        risk_factors=factors,
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _low_risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=15,
        severity=Severity.LOW,
        confidence=0.4,
        risk_factors=[],
        possible_false_positive=True,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


@pytest.fixture
def wm() -> _FakeWorkingMemory:
    return _FakeWorkingMemory()


@pytest.fixture
def event_service() -> _FakeEventService:
    return _FakeEventService()


@pytest.fixture
def event_bus() -> _FakeEventBus:
    return _FakeEventBus()


def test_section_keys_are_exactly_fifteen_fixed_order() -> None:
    assert len(SECTION_KEYS) == 15
    assert SECTION_KEYS[0] == "overview"
    assert SECTION_KEYS[-1] == "appendix_index"
    assert SECTION_KEYS[11] == "executed_actions"


@pytest.mark.asyncio
async def test_main_scenario_fifteen_sections_and_key_facts(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
    event_bus: _FakeEventBus,
) -> None:
    event_id = f"evt-report-main-{uuid4().hex[:8]}"
    triage = _main_triage()
    await wm.write(event_id, "triage_result", triage.model_dump(mode="json"))
    event_service.final_verdicts[event_id] = FinalVerdict.CONFIRMED_THREAT

    agent = ReportAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=event_service,
        event_bus=event_bus,
    )
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_main_evidence(event_id),
            risk_assessment=_high_risk(),
        )
    )

    assert report.report_id == report_id_for_event(event_id)
    assert report.generated_by == GENERATED_BY_LLM
    assert len(report.sections) == 15
    assert [s.key for s in report.sections] == list(SECTION_KEYS)
    assert all(s.content.strip() for s in report.sections)

    blob = "\n".join(s.content for s in report.sections) + report.summary + report.title
    assert "zhangsan" in blob
    assert "PC-FIN-023" in blob
    assert "203.0.113.88" in blob
    assert "80" in report.sections[2].content or report.risk_score == 80
    assert len(report.sections[2].data.get("factors", [])) == 6

    stored = await wm.read(event_id, "report")
    assert stored["report_id"] == report.report_id
    assert event_service.reports[report.report_id].report_id == report.report_id
    by_event = await event_service.get_report(event_id=event_id)
    assert by_event is not None
    assert by_event.report_id == report.report_id

    assert event_service.actions
    assert event_service.actions[0]["action_name"] == "generate_report"
    assert event_service.actions[0]["tool_name"] == "generate_report"

    published = [e for e in event_bus.events if e[1] == "report_generated"]
    assert published
    bus_payload = published[0][2]
    assert bus_payload == {
        "report_id": report.report_id,
        "sections": 15,
        "generated_at": report.generated_at.isoformat(),
    }
    appendix = next(s for s in report.sections if s.key == "appendix_index")
    assert appendix.data.get("content_sha256") == agent.last_content_sha256
    assert agent.last_content_sha256
    assert agent.last_report_markdown
    assert "zhangsan" in agent.last_report_markdown
    assert f"content_sha256={agent.last_content_sha256}" in agent.last_report_markdown


@pytest.mark.asyncio
async def test_llm_failure_falls_back_to_template(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
    event_bus: _FakeEventBus,
) -> None:
    event_id = f"evt-report-tpl-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    event_service.final_verdicts[event_id] = FinalVerdict.CONFIRMED_THREAT

    agent = ReportAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
        event_bus=event_bus,
    )
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_main_evidence(event_id),
            risk_assessment=_high_risk(),
        )
    )
    assert report.generated_by == GENERATED_BY_TEMPLATE
    assert len(report.sections) == 15
    blob = "\n".join(s.content for s in report.sections)
    assert "zhangsan" in blob
    assert "PC-FIN-023" in blob
    assert "203.0.113.88" in blob
    assert PLACEHOLDER_NO_ACTIONS in blob
    assert PLACEHOLDER_NO_VERIFICATION in blob


@pytest.mark.asyncio
async def test_missing_actions_and_verification_use_placeholders(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-report-ph-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    agent = ReportAgent(
        llm_client=None,
        working_memory=wm,
        event_service=event_service,
    )
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_main_evidence(event_id),
            risk_assessment=_high_risk(),
            response_plan=None,
            verification_result=None,
        )
    )
    by_key = {s.key: s.content for s in report.sections}
    assert by_key["executed_actions"] == PLACEHOLDER_NO_ACTIONS
    assert by_key["verification_results"] == PLACEHOLDER_NO_VERIFICATION


@pytest.mark.asyncio
async def test_low_risk_empty_evidence_placeholder(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-report-low-{uuid4().hex[:8]}"
    triage = TriageResult(
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="single failed login",
    )
    await wm.write(event_id, "triage_result", triage.model_dump(mode="json"))
    agent = ReportAgent(
        llm_client=None,
        working_memory=wm,
        event_service=event_service,
    )
    empty = EvidenceOutput(
        evidence_list=[],
        overall_confidence=0.0,
        collection_status=CollectionStatus.FAILED,
    )
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=empty,
            risk_assessment=_low_risk(),
        )
    )
    by_key = {s.key: s.content for s in report.sections}
    assert PLACEHOLDER_LOW_RISK_NO_EVIDENCE in by_key["evidence_chain"]
    assert PLACEHOLDER_NO_ACTIONS in by_key["executed_actions"]


@pytest.mark.asyncio
async def test_response_actions_counted_by_category_not_tool_name(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-report-act-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    response_plan = ResponsePlan(
        plan_id="plan-1",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        actions=[
            Action(
                action_id="act-sys",
                event_id=event_id,
                plan_revision=1,
                action_fingerprint="fp-sys",
                action_category=ActionCategory.SYSTEM,
                action_name="generate_report",
                tool_name="generate_report",
                action_level=ActionLevel.L0,
                status=ActionStatus.SUCCESS,
            ),
            Action(
                action_id="act-block",
                event_id=event_id,
                plan_revision=1,
                action_fingerprint="fp-block",
                action_category=ActionCategory.RESPONSE,
                action_name="Block IP",
                tool_name="block_ip",
                action_level=ActionLevel.L3,
                execution_owner=ExecutionOwner.DIRECT_TOOL,
                target="203.0.113.88",
                status=ActionStatus.SUCCESS,
                writeback_required=True,
                writeback_applicable=True,
                writeback_readiness=WritebackReadiness.READY,
                effect_verification_status="verified",
            ),
        ],
    )
    agent = ReportAgent(
        llm_client=None,
        working_memory=wm,
        event_service=event_service,
    )
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_main_evidence(event_id),
            risk_assessment=_high_risk(),
            response_plan=response_plan,
        )
    )
    executed = next(s for s in report.sections if s.key == "executed_actions")
    assert PLACEHOLDER_NO_ACTIONS not in executed.content
    assert "act-block" in executed.content
    assert "block_ip" in executed.content
    assert executed.data["response_action_count"] == 1
    assert "act-sys" not in executed.content


@pytest.mark.asyncio
async def test_report_upsert_is_idempotent_by_report_id(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-report-idem-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    agent = ReportAgent(
        llm_client=None,
        working_memory=wm,
        event_service=event_service,
    )
    first = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_main_evidence(event_id),
            risk_assessment=_high_risk(),
        )
    )
    second = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_main_evidence(event_id),
            risk_assessment=_high_risk(),
        )
    )
    assert first.report_id == second.report_id
    assert len(event_service.reports) == 1
    assert event_service.reports[first.report_id].version == 2
    # generate_report Action fingerprint also idempotent
    assert len(event_service.actions) == 1


class _FailingPersistEventService(_FakeEventService):
    async def upsert_report(self, report: Any) -> Any:
        raise RuntimeError("report db unavailable")


@pytest.mark.asyncio
async def test_report_persist_failure_propagates(wm: _FakeWorkingMemory) -> None:
    event_id = f"evt-report-persist-fail-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    agent = ReportAgent(
        llm_client=None,
        working_memory=wm,
        event_service=_FailingPersistEventService(),
    )
    with pytest.raises(RuntimeError, match="report db unavailable"):
        await agent.execute(
            ReportAgentInput(
                event_id=event_id,
                evidence_output=_main_evidence(event_id),
                risk_assessment=_high_risk(),
            )
        )


@pytest.mark.asyncio
async def test_llm_incomplete_sections_falls_back_to_template(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-report-partial-llm-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    agent = ReportAgent(
        llm_client=_PartialLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_main_evidence(event_id),
            risk_assessment=_high_risk(),
        )
    )
    assert report.generated_by == GENERATED_BY_TEMPLATE
    assert len(report.sections) == 15


def test_builder_preserves_section_order() -> None:
    builder = ReportSectionBuilder()
    event_id = "evt-builder"
    sections = builder.build(
        event_id=event_id,
        evidence_output=_main_evidence(event_id),
        risk_assessment=_high_risk(),
        triage_result=_main_triage(),
    )
    assert [s.key for s in sections] == list(SECTION_KEYS)


def test_builder_risk_section_excludes_factor_reasoning() -> None:
    """ISSUE-131: report section data must not persist risk factor CoT reasoning."""
    builder = ReportSectionBuilder()
    event_id = "evt-risk-no-reasoning"
    sections = builder.build(
        event_id=event_id,
        evidence_output=_main_evidence(event_id),
        risk_assessment=_high_risk(),
        triage_result=_main_triage(),
    )
    risk = next(section for section in sections if section.key == "risk_scoring")
    factors = risk.data.get("factors", [])
    assert factors
    assert all("reasoning" not in factor for factor in factors)


def test_report_includes_impact_assessment_hint() -> None:
    """ISSUE-079: recommendations reference high-impact assessments from context."""
    builder = ReportSectionBuilder()
    event_id = "evt-impact-hint"
    action = Action(
        action_id="act-isolate-dc",
        event_id=event_id,
        plan_revision=1,
        action_fingerprint="fp-isolate",
        action_category=ActionCategory.RESPONSE,
        action_name="Isolate Host",
        tool_name="isolate_host",
        action_level=ActionLevel.L4,
        target="10.0.0.10",
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )
    response_plan = ResponsePlan(
        plan_id="plan-impact",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        actions=[action],
    )
    sections = builder.build(
        event_id=event_id,
        evidence_output=_main_evidence(event_id),
        risk_assessment=_high_risk(),
        triage_result=_main_triage(),
        response_plan=response_plan,
        impact_assessments=[
            {
                "action_id": "act-isolate-dc",
                "impact_score": 90,
                "business_disruption": "high",
                "affected_scope": "tool=isolate_host",
                "reversible": True,
            }
        ],
    )
    recommendations = next(section for section in sections if section.key == "recommendations")
    assert "高影响处置复核" in recommendations.content
    assert "isolate_host" in recommendations.content


def test_builder_includes_evidence_limited_risk_semantics() -> None:
    builder = ReportSectionBuilder()
    event_id = "evt-report-evidence-limited"
    sections = builder.build(
        event_id=event_id,
        evidence_output=EvidenceOutput(
            evidence_list=[],
            overall_confidence=0.0,
            collection_status=CollectionStatus.FAILED,
        ),
        risk_assessment=RiskAssessment(
            risk_score=70,
            severity=Severity.HIGH,
            confidence=0.35,
            risk_factors=[],
            possible_false_positive=False,
            scoring_mode=ScoringMode.RULE_ONLY,
            evidence_limited=True,
            severity_floor_applied=True,
            source_risk_baseline=76,
        ),
        triage_result=_main_triage(),
    )
    risk_section = next(section for section in sections if section.key == "risk_scoring")
    severity_section = next(section for section in sections if section.key == "severity_level")
    assert "evidence_limited=True" in risk_section.content
    assert "source_risk_baseline=76" in risk_section.content
    assert "evidence_limited=True" in severity_section.content


def test_builder_includes_human_escalation_note() -> None:
    """ISSUE-062 acceptance: escalated events must carry human-escalation text."""
    builder = ReportSectionBuilder()
    event_id = "evt-escalated"
    sections = builder.build(
        event_id=event_id,
        evidence_output=_main_evidence(event_id),
        risk_assessment=_high_risk(),
        triage_result=_main_triage(),
        escalated=True,
        replan_count=3,
    )
    overview = next(section for section in sections if section.key == "overview")
    recommendations = next(section for section in sections if section.key == "recommendations")
    assert "human_escalation:" in overview.content
    assert "escalated=true" in overview.content
    assert "人工升级" in recommendations.content
    assert "replan_count=3" in recommendations.content


def test_llm_overview_preserves_post_evidence_fp_basis() -> None:
    builder = ReportSectionBuilder()
    event_id = "evt-report-fp-adj-post"
    sections = builder.build(
        event_id=event_id,
        evidence_output=_main_evidence(event_id),
        risk_assessment=_high_risk(),
        triage_result=_main_triage(),
        fp_adjudication={
            "recommendation": "close_as_fp",
            "matched_window_id": "cw-scheduled-ops-maintenance",
            "supporting_evidence_ids": ["evd-auth-001"],
            "matched_conditions": ["baseline_window_match", "asset_scope_match"],
            "max_score": 0.9,
        },
    )

    merged = ReportAgent(llm_client=None)._merge_sections(
        sections,
        {"overview": "LLM-generated analyst summary."},
    )
    overview = next(section for section in merged if section.key == "overview")

    assert overview.content.startswith("LLM-generated analyst summary.")
    assert "fp_decision: post_evidence_close_as_fp" in overview.content
    assert "fp_matched_window_id: cw-scheduled-ops-maintenance" in overview.content
    assert "evd-auth-001" in overview.content


def test_llm_overview_preserves_false_positive_basis() -> None:
    builder = ReportSectionBuilder()
    event_id = "evt-report-fp-basis"
    sections = builder.build(
        event_id=event_id,
        evidence_output=_main_evidence(event_id),
        risk_assessment=_high_risk(),
        triage_result=_main_triage(),
        false_positive_match={
            "matched_case_id": "case-known-fp",
            "matched_rule": "ops_change_window_bulk_login",
            "recommendation": "close_as_fp",
        },
    )

    merged = ReportAgent(llm_client=None)._merge_sections(
        sections,
        {"overview": "LLM-generated analyst summary."},
    )
    overview = next(section for section in merged if section.key == "overview")

    assert overview.content.startswith("LLM-generated analyst summary.")
    assert "fp_matched_case_id: case-known-fp" in overview.content
    assert "fp_matched_pattern: ops_change_window_bulk_login" in overview.content


def test_llm_overview_preserves_human_escalation_note() -> None:
    """ISSUE-062: LLM merge must keep mandatory human-escalation template lines."""
    builder = ReportSectionBuilder()
    event_id = "evt-report-escalation-merge"
    sections = builder.build(
        event_id=event_id,
        evidence_output=_main_evidence(event_id),
        risk_assessment=_high_risk(),
        triage_result=_main_triage(),
        escalated=True,
        replan_count=3,
    )

    merged = ReportAgent(llm_client=None)._merge_sections(
        sections,
        {
            "overview": "LLM-generated analyst summary.",
            "recommendations": "LLM-generated remediation tips.",
        },
    )
    overview = next(section for section in merged if section.key == "overview")
    recommendations = next(section for section in merged if section.key == "recommendations")

    assert overview.content.startswith("LLM-generated analyst summary.")
    assert "human_escalation:" in overview.content
    assert "escalated=true" in overview.content
    assert recommendations.content.startswith("LLM-generated remediation tips.")
    assert "人工升级" in recommendations.content
    assert "replan_count=3" in recommendations.content


def test_llm_failure_metadata_redacts_and_codes() -> None:
    meta = llm_failure_metadata(
        LLMError(
            "Authorization: Bearer secret-token-12345",
            error_code="llm_auth_error",
            details={"http_status": 401, "prompt": "do not leak"},
        )
    )
    assert meta["error_code"] == "llm_auth_error"
    assert meta["http_status"] == 401
    assert "secret-token-12345" not in meta["error_message"]
    assert "prompt" not in meta["details"]


def test_llm_failure_metadata_empty_message_uses_error_code() -> None:
    meta = llm_failure_metadata(LLMError("", error_code="llm_timeout"))
    assert meta["error_code"] == "llm_timeout"
    assert meta["error_message"] == "llm timeout"


def test_builder_zero_evidence_lists_gaps_and_limitations() -> None:
    builder = ReportSectionBuilder()
    event_id = "evt-report-zero-evidence"
    gaps = [
        EvidenceGap(
            event_id=event_id,
            missing_source=EvidenceSource.IDENTITY,
            reason="tool_timeout",
            detail={"tool": "lookup_user"},
        )
    ]
    sections = builder.build(
        event_id=event_id,
        evidence_output=EvidenceOutput(
            evidence_list=[],
            gaps=gaps,
            overall_confidence=0.0,
            collection_status=CollectionStatus.FAILED,
        ),
        risk_assessment=RiskAssessment(
            risk_score=70,
            severity=Severity.HIGH,
            confidence=0.35,
            risk_factors=[],
            possible_false_positive=False,
            scoring_mode=ScoringMode.RULE_ONLY,
            evidence_limited=True,
            severity_floor_applied=True,
            source_risk_baseline=76,
        ),
        triage_result=_main_triage(),
        source_snapshot={
            "title": "Suspicious outbound transfer",
            "alert_type": "data_exfiltration",
            "severity": "high",
        },
    )
    overview = next(section for section in sections if section.key == "overview")
    evidence_chain = next(section for section in sections if section.key == "evidence_chain")
    storyline = next(section for section in sections if section.key == "attack_storyline")
    risk_section = next(section for section in sections if section.key == "risk_scoring")

    assert "调查限制" in overview.content
    assert "gap: identity | reason=tool_timeout" in evidence_chain.content
    assert PLACEHOLDER_LOW_RISK_NO_EVIDENCE not in evidence_chain.content
    assert "attack_storyline_limitation" in storyline.content
    assert "title=Suspicious outbound transfer" in storyline.content
    assert "score_divergence" in risk_section.content
    assert "source_baseline=76" in risk_section.content


def test_builder_includes_degraded_triage_and_entity_rejection() -> None:
    builder = ReportSectionBuilder()
    event_id = "evt-report-degraded-triage"
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.MEDIUM,
        need_investigation=True,
        degraded=True,
        degradation_reasons=["llm_timeout"],
        entity_rejection_summary={
            "rejection_counts": {"phrase_without_host_context": 2},
            "total_rejected": 2,
        },
    )
    sections = builder.build(
        event_id=event_id,
        evidence_output=EvidenceOutput(
            evidence_list=[],
            overall_confidence=0.0,
            collection_status=CollectionStatus.FAILED,
        ),
        risk_assessment=RiskAssessment(
            risk_score=55,
            severity=Severity.MEDIUM,
            confidence=0.4,
            risk_factors=[],
            possible_false_positive=False,
            scoring_mode=ScoringMode.RULE_ONLY,
            evidence_limited=True,
        ),
        triage_result=triage,
    )
    overview = next(section for section in sections if section.key == "overview")
    assert "triage_degraded: true" in overview.content
    assert "triage_degradation_reason: llm_timeout" in overview.content
    assert "entity_rejection_total: 2" in overview.content
    assert "phrase_without_host_context=2" in overview.content


def test_builder_evidence_chain_includes_evidence_id() -> None:
    builder = ReportSectionBuilder()
    event_id = "evt-report-evidence-id"
    sections = builder.build(
        event_id=event_id,
        evidence_output=_main_evidence(event_id),
        risk_assessment=_high_risk(),
        triage_result=_main_triage(),
    )
    evidence_chain = next(section for section in sections if section.key == "evidence_chain")
    storyline = next(section for section in sections if section.key == "attack_storyline")
    assert "evidence_id=" in evidence_chain.content
    assert "evidence_id=" in storyline.content


@pytest.mark.asyncio
async def test_llm_failure_emits_structured_observability(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
    caplog: pytest.LogCaptureFixture,
) -> None:
    event_id = f"evt-report-llm-obs-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    agent = ReportAgent(
        llm_client=_StructuredLLMErrorClient(),
        working_memory=wm,
        event_service=event_service,
    )
    with caplog.at_level("WARNING"):
        report = await agent.execute(
            ReportAgentInput(
                event_id=event_id,
                evidence_output=_main_evidence(event_id),
                risk_assessment=_high_risk(),
            )
        )

    assert report.generated_by == GENERATED_BY_TEMPLATE
    assert report.error_detail
    assert report.warnings == ["report_llm_fallback:llm_invalid_json"]
    assert any("error_code=llm_invalid_json" in record.message for record in caplog.records)

    basis = TraceProjection.decision_basis(report.model_dump(mode="json"))
    assert basis["warnings"] == ["report_llm_fallback:llm_invalid_json"]
    assert "llm_invalid_json" in basis["warnings"][0]
    assert "invalid json" in (report.error_detail or "")


class _RecordingTraceService:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def log_trace(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


@pytest.mark.asyncio
async def test_llm_failure_records_trace_error_detail(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-report-trace-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    trace = _RecordingTraceService()
    agent = ReportAgent(
        llm_client=_StructuredLLMErrorClient(),
        working_memory=wm,
        event_service=event_service,
        trace_service=trace,
    )
    await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=_main_evidence(event_id),
            risk_assessment=_high_risk(),
        )
    )
    assert trace.calls
    assert trace.calls[0]["error_detail"] == "llm_invalid_json: provider returned invalid json"


@pytest.mark.asyncio
async def test_template_zero_evidence_via_agent_execute(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    """ISSUE-104: template path with zero evidence must surface gaps and limitations."""
    from app.agents.report_section_builder import INVESTIGATION_LIMITATION_HEADER

    event_id = f"evt-report-zero-agent-{uuid4().hex[:8]}"
    await wm.write(event_id, "triage_result", _main_triage().model_dump(mode="json"))
    await wm.write(
        event_id,
        "source_snapshot",
        {"title": "Suspicious outbound transfer", "alert_type": "data_exfiltration"},
    )
    gaps = [
        EvidenceGap(
            event_id=event_id,
            missing_source=EvidenceSource.IDENTITY,
            reason="tool_timeout",
        )
    ]
    agent = ReportAgent(
        llm_client=None,
        working_memory=wm,
        event_service=event_service,
    )
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=EvidenceOutput(
                evidence_list=[],
                gaps=gaps,
                overall_confidence=0.0,
                collection_status=CollectionStatus.FAILED,
            ),
            risk_assessment=RiskAssessment(
                risk_score=70,
                severity=Severity.HIGH,
                confidence=0.35,
                risk_factors=[],
                possible_false_positive=False,
                scoring_mode=ScoringMode.RULE_ONLY,
                evidence_limited=True,
            ),
        )
    )
    assert report.generated_by == GENERATED_BY_TEMPLATE
    assert len(report.sections) == 15
    overview = next(section for section in report.sections if section.key == "overview")
    evidence_chain = next(section for section in report.sections if section.key == "evidence_chain")
    assert INVESTIGATION_LIMITATION_HEADER.split("：")[0] in overview.content
    assert "gap: identity | reason=tool_timeout" in evidence_chain.content
    assert "Suspicious outbound transfer" in overview.content


def test_stamp_clears_stale_appendix_observability_when_warnings_empty() -> None:
    from app.models.report import (
        ReportSection,
        observability_from_sections,
        stamp_report_observability_in_sections,
    )

    sections = [
        ReportSection(
            key="appendix_index",
            title="附录索引",
            content="event_id=evt-stale-obs",
            data={
                "report_warnings": ["report_llm_fallback:llm_timeout"],
                "report_error_detail": "provider timed out",
            },
        )
    ]
    cleared = stamp_report_observability_in_sections(
        sections,
        warnings=[],
        error_detail=None,
    )
    warnings, detail = observability_from_sections(cleared)
    assert warnings == []
    assert detail is None


def test_llm_merge_preserves_investigation_limitation_lines() -> None:
    from app.agents.report_section_builder import INVESTIGATION_LIMITATION_HEADER

    builder = ReportSectionBuilder()
    event_id = "evt-merge-limit"
    gaps = [
        EvidenceGap(
            event_id=event_id,
            missing_source=EvidenceSource.IDENTITY,
            reason="tool_timeout",
        )
    ]
    sections = builder.build(
        event_id=event_id,
        evidence_output=EvidenceOutput(
            evidence_list=[],
            gaps=gaps,
            overall_confidence=0.0,
            collection_status=CollectionStatus.FAILED,
        ),
        risk_assessment=RiskAssessment(
            risk_score=70,
            severity=Severity.HIGH,
            confidence=0.35,
            risk_factors=[],
            possible_false_positive=False,
            scoring_mode=ScoringMode.RULE_ONLY,
            evidence_limited=True,
        ),
        triage_result=_main_triage(),
        source_snapshot={"title": "Suspicious outbound transfer"},
    )
    merged = ReportAgent(llm_client=None)._merge_sections(
        sections,
        {
            "overview": "LLM short summary only.",
            "evidence_chain": "LLM evidence narrative.",
            "attack_storyline": "LLM storyline only.",
        },
    )
    overview = next(section for section in merged if section.key == "overview")
    evidence_chain = next(section for section in merged if section.key == "evidence_chain")
    storyline = next(section for section in merged if section.key == "attack_storyline")
    assert INVESTIGATION_LIMITATION_HEADER.split("：")[0] in overview.content
    assert "gap: identity | reason=tool_timeout" in evidence_chain.content
    assert "Suspicious outbound transfer" in overview.content
    assert "attack_storyline_limitation" in storyline.content or "调查限制" in storyline.content


def test_llm_failure_metadata_timeout_code() -> None:

    meta = llm_failure_metadata(TimeoutError())
    assert meta["error_code"] == "llm_timeout"
