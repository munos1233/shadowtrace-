"""RiskAgent six-dimension scoring tests (ISSUE-035)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from app.agents.confidence_calibration import calibrate_confidence
from app.agents.prompts.risk_prompt import FACTOR_NAMES
from app.agents.risk_agent import RiskAgent
from app.agents.risk_llm_admissibility import classify_llm_risk_response
from app.agents.risk_scoring_engine import (
    CONFIDENCE_CAP_VERSION,
    EVIDENCE_LIMITED_CONFIDENCE_CAP,
    FACTOR_WEIGHTS,
    SOURCE_BASELINE_FLOOR_RATIO,
    RiskScoringEngine,
    apply_evidence_limited_adjustments,
    apply_versioned_confidence_cap,
    extract_source_baseline,
    is_evidence_limited,
    severity_from_score,
    source_scale_unnormalized,
)
from app.core.llm.base import InMemoryLLMCallAuditRecorder, LLMResponse
from app.core.llm.mock_client import MockLLMClient
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    GraphOutput,
    GraphSummary,
    GraphSummaryFeature,
    LlmAdmissibility,
    RiskAgentInput,
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
    EventType,
    EvidenceSource,
    FinalVerdict,
    Severity,
)
from app.models.evidence import Evidence
from app.models.ids import new_evidence_id

_DEMO_SCENARIO_ID = "insider_data_exfiltration"


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
        self.risk_updates: list[dict[str, Any]] = []
        self.verdicts: list[FinalVerdict] = []

    async def update_risk_fields(
        self,
        event_id: str,
        *,
        risk_score: int,
        severity: Severity,
        confidence: float,
        operator: str | None = None,
        factor_names: list[str] | None = None,
        risk_assessment: dict[str, Any] | None = None,
    ) -> None:
        self.risk_updates.append(
            {
                "event_id": event_id,
                "risk_score": risk_score,
                "severity": severity,
                "confidence": confidence,
                "operator": operator,
                "factor_names": factor_names,
                "risk_assessment": risk_assessment,
            }
        )

    async def set_final_verdict(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
        context: Any = None,
    ) -> None:
        self.verdicts.append(verdict)


class _MockDegradedFlags:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def set_flag(
        self,
        event_id: str,
        flag_name: str,
        value: Any,
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
        return [f"{flag_name}=true"]


class _FailingLLM:
    async def chat(self, *args: Any, **kwargs: Any) -> LLMResponse:
        raise RuntimeError("llm unavailable")


class _DegradedLLM:
    """Returns structurally valid but degraded LLM scores (must not merge)."""

    async def chat(self, *args: Any, **kwargs: Any) -> LLMResponse:
        factors = {
            name: {"score": 95, "reason": "degraded llm inflation attempt"} for name in FACTOR_NAMES
        }
        content = json.dumps({"factors": factors, "raw_confidence": 0.99})
        return LLMResponse(
            content=content,
            parsed=None,
            model_name="degraded-model",
            degraded_reason="fallback_model_used",
        )


class _MalformedLLM:
    """Returns structurally invalid risk JSON (missing required factors)."""

    async def chat(self, *args: Any, **kwargs: Any) -> LLMResponse:
        content = json.dumps({"factors": {"asset_impact": {"score": 95}}, "raw_confidence": 0.99})
        return LLMResponse(content=content, parsed=None, model_name="malformed-model")


class _InflatingValidLLM:
    """Returns admissible LLM scores high enough to exceed floor without applying it."""

    async def chat(self, *args: Any, **kwargs: Any) -> LLMResponse:
        factors = {name: {"score": 100, "reason": "valid llm inflation"} for name in FACTOR_NAMES}
        content = json.dumps({"factors": factors, "raw_confidence": 0.99})
        return LLMResponse(content=content, parsed=None, model_name="inflating-model")


def _risk_factor_signature(factors: list[RiskFactor]) -> list[tuple[str, float, float]]:
    return sorted((f.factor_name, f.raw_score, f.weighted_score) for f in factors)


def _evd(
    *,
    source: EvidenceSource,
    evidence_type: str,
    confidence: float,
    event_id: str,
    description: str,
    raw: dict[str, Any],
    mitre: str | None = None,
    conflicting: bool = False,
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
        is_conflicting=conflicting,
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
    items = [
        _evd(
            source=EvidenceSource.IDENTITY,
            evidence_type="login_lookup",
            confidence=0.7,
            event_id=event_id,
            description="账号 zhangsan 无交互登录",
            raw={"account": "zhangsan", "result": "no_record"},
            conflicting=True,
        ),
        _evd(
            source=EvidenceSource.ENDPOINT,
            evidence_type="process_create",
            confidence=0.9,
            event_id=event_id,
            description="powershell archive",
            raw={
                "hostname": "PC-FIN-023",
                "account": "zhangsan",
                "process": "powershell.exe",
                "action": "process_create",
                "cmdline": "powershell.exe -enc compressed",
            },
            mitre="T1059.001",
        ),
        _evd(
            source=EvidenceSource.DATA_SECURITY,
            evidence_type="upload",
            confidence=0.88,
            event_id=event_id,
            description="upload finance_report.zip",
            raw={
                "action": "upload",
                "file_name": "finance_report.zip",
                "bytes": 52428800,
                "account": "zhangsan",
            },
            mitre="T1567.002",
        ),
        _evd(
            source=EvidenceSource.NETWORK_FLOW,
            evidence_type="network_flow",
            confidence=0.85,
            event_id=event_id,
            description="external upload traffic",
            raw={
                "src_ip": "10.20.30.23",
                "dst_ip": "203.0.113.88",
                "bytes_out": 52000000,
                "domain": "unknown-upload-example.com",
            },
            mitre="T1041",
        ),
        _evd(
            source=EvidenceSource.ASSET,
            evidence_type="asset_info",
            confidence=0.8,
            event_id=event_id,
            description="finance asset",
            raw={
                "hostname": "PC-FIN-023",
                "ip": "10.20.30.23",
                "owner": "zhangsan",
                "asset_value": "high",
            },
        ),
        _evd(
            source=EvidenceSource.THREAT_INTEL,
            evidence_type="ip",
            confidence=0.91,
            event_id=event_id,
            description="ti hit",
            raw={
                "indicator": "203.0.113.88",
                "confidence": 0.91,
                "tags": ["exfil", "unknown_infra"],
            },
        ),
    ]
    return EvidenceOutput(
        evidence_list=items,
        success_sources=[
            "identity",
            "endpoint",
            "data_security",
            "network_flow",
            "asset",
            "threat_intel",
        ],
        failed_sources=[],
        overall_confidence=0.86,
        collection_status=CollectionStatus.COMPLETED,
    )


def _fp_evidence(event_id: str) -> EvidenceOutput:
    return EvidenceOutput(
        evidence_list=[
            _evd(
                source=EvidenceSource.DNS,
                evidence_type="dns_query",
                confidence=0.4,
                event_id=event_id,
                description="benign domain lookup",
                raw={"query": "update.example.com", "answer": "203.0.113.10"},
            )
        ],
        success_sources=["dns"],
        failed_sources=[],
        overall_confidence=0.35,
        collection_status=CollectionStatus.DEGRADED,
    )


@pytest.fixture
def wm() -> _FakeWorkingMemory:
    return _FakeWorkingMemory()


@pytest.fixture
def event_service() -> _FakeEventService:
    return _FakeEventService()


def test_factor_weights_sum_to_one() -> None:
    assert abs(sum(FACTOR_WEIGHTS.values()) - 1.0) < 1e-9


def test_severity_bands() -> None:
    assert severity_from_score(0) is Severity.LOW
    assert severity_from_score(39) is Severity.LOW
    assert severity_from_score(40) is Severity.MEDIUM
    assert severity_from_score(69) is Severity.MEDIUM
    assert severity_from_score(70) is Severity.HIGH
    assert severity_from_score(89) is Severity.HIGH
    assert severity_from_score(90) is Severity.CRITICAL
    assert severity_from_score(100) is Severity.CRITICAL


def test_calibrate_confidence_below_raw_when_temperature_gt_one() -> None:
    raw = 0.9
    calibrated = calibrate_confidence(raw, temperature=1.2)
    assert calibrated < raw
    assert calibrated <= 1.0
    assert abs(calibrated - raw / 1.2) < 1e-9


def test_rule_engine_all_zero_baseline() -> None:
    """Empty failed collection → each dimension stays at low baselines."""
    engine = RiskScoringEngine()
    empty = EvidenceOutput(
        evidence_list=[],
        overall_confidence=0.0,
        collection_status=CollectionStatus.FAILED,
    )
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
    )
    scores = engine.score(triage_result=triage, evidence_output=empty)
    assert scores["evidence_confidence"][0] == 0.0
    assert scores["asset_impact"][0] <= 25.0
    assert scores["behavior_anomaly"][0] <= 20.0
    assert scores["threat_intel"][0] <= 25.0
    merged = sum(scores[name][0] * FACTOR_WEIGHTS[name] for name in FACTOR_WEIGHTS)
    assert merged < 30.0


def test_rule_engine_saturated_scores_reach_high_risk() -> None:
    """Rich main-scenario evidence drives merged rule path toward high risk."""
    engine = RiskScoringEngine()
    event_id = f"evt-{uuid4().hex[:8]}"
    rich = _main_evidence(event_id)
    scores = engine.score(triage_result=_main_triage(), evidence_output=rich)
    assert all(0.0 <= score <= 100.0 for score, _ in scores.values())
    assert scores["attack_stage"][0] >= 70.0
    assert scores["threat_intel"][0] >= 70.0
    merged = sum(scores[name][0] * FACTOR_WEIGHTS[name] for name in FACTOR_WEIGHTS)
    assert merged >= 70.0


def test_rule_engine_uses_graph_summary_for_attack_stage() -> None:
    """ISSUE-116: attack_stage consumes evidence-bound graph summary features."""
    engine = RiskScoringEngine()
    empty = EvidenceOutput(
        evidence_list=[],
        overall_confidence=0.0,
        collection_status=CollectionStatus.COMPLETED,
    )
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
    )
    graph_output = GraphOutput(
        summary=GraphSummary(
            features=[
                GraphSummaryFeature(
                    feature_id="relation_connected_to",
                    feature_kind="attack_stage",
                    score_hint=70.0,
                    evidence_ids=["evd-graph-001"],
                    provenance="graph_edge",
                )
            ]
        )
    )
    scores = engine.score(
        triage_result=triage,
        evidence_output=empty,
        graph_output=graph_output,
    )
    assert scores["attack_stage"][0] == 70.0
    assert "relation_connected_to" in scores["attack_stage"][1]


def test_rule_engine_attack_stage_ignores_edges_when_summary_missing() -> None:
    """ISSUE-116: rule path must not score raw graph edges without GraphSummary."""
    from app.models.agent_io import GraphEdge, GraphNode, GraphRelationType

    engine = RiskScoringEngine()
    empty = EvidenceOutput(
        evidence_list=[],
        overall_confidence=0.0,
        collection_status=CollectionStatus.COMPLETED,
    )
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
    )
    graph_output = GraphOutput(
        nodes=[
            GraphNode(
                node_id="node-a",
                event_id="evt-001",
                entity_type="account",
                entity_value="svc",
            ),
            GraphNode(
                node_id="node-b",
                event_id="evt-001",
                entity_type="ip",
                entity_value="203.0.113.9",
            ),
        ],
        edges=[
            GraphEdge(
                edge_id="edge-1",
                event_id="evt-001",
                source_node_id="node-a",
                target_node_id="node-b",
                relation_type=GraphRelationType.CONNECTED_TO,
                evidence_id="evd-would-score-90",
                occurred_at=datetime.now(UTC),
            )
        ],
        summary=None,
    )
    scores = engine.score(
        triage_result=triage,
        evidence_output=empty,
        graph_output=graph_output,
    )
    assert scores["attack_stage"][0] == 30.0
    assert "summary missing" in scores["attack_stage"][1]
    assert "CONNECTED_TO" not in scores["attack_stage"][1]


def test_rule_engine_boundary_all_zero_and_all_hundred() -> None:
    engine = RiskScoringEngine()
    empty = EvidenceOutput(
        evidence_list=[],
        overall_confidence=0.0,
        collection_status=CollectionStatus.FAILED,
    )
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
    )
    low = engine.score(triage_result=triage, evidence_output=empty)
    assert all(0.0 <= score <= 100.0 for score, _ in low.values())

    event_id = f"evt-{uuid4().hex[:8]}"
    rich = _main_evidence(event_id)
    high = engine.score(triage_result=_main_triage(), evidence_output=rich)
    assert all(0.0 <= score <= 100.0 for score, _ in high.values())


@pytest.mark.asyncio
async def test_main_scenario_score_ge_70_confirmed_threat(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-main-{uuid4().hex[:8]}"
    agent = RiskAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=event_service,
        calibration_temperature=1.2,
        scenario_id=_DEMO_SCENARIO_ID,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_main_triage(),
            evidence_output=_main_evidence(event_id),
        )
    )
    assert output.risk_score >= 70
    assert output.severity in {Severity.HIGH, Severity.CRITICAL}
    assert output.scoring_mode is ScoringMode.LLM_AND_RULE
    assert len(output.risk_factors) == 6
    assert abs(sum(f.weight for f in output.risk_factors) - 1.0) < 1e-9
    assert all(f.reasoning for f in output.risk_factors)
    assert agent.last_raw_confidence is not None
    assert output.confidence <= 1.0
    assert output.confidence < agent.last_raw_confidence
    assert agent.last_verdict is FinalVerdict.CONFIRMED_THREAT
    assert event_service.verdicts[-1] is FinalVerdict.CONFIRMED_THREAT
    assert event_service.risk_updates[-1]["risk_score"] == output.risk_score
    stored = await wm.read(event_id, "risk_assessment")
    assert stored["risk_score"] == output.risk_score


@pytest.mark.asyncio
async def test_false_positive_scenario_score_below_40(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-fp-{uuid4().hex[:8]}"
    wm.values[(event_id, "false_positive_match")] = {
        "recommendation": "investigate_with_flag",
        "max_score": 0.96,
        "phase": "pre_evidence",
    }
    wm.values[(event_id, "fp_adjudication")] = {
        "recommendation": "close_as_fp",
        "matched_window_id": "cw-test",
        "max_score": 0.9,
    }
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    # Weak evidence → rule_only low score; post-evidence close_as_fp forces FP verdict.
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=TriageResult(
                event_type=EventType.OTHER,
                severity=Severity.LOW,
                need_investigation=False,
            ),
            evidence_output=_fp_evidence(event_id),
        )
    )
    assert output.risk_score < 40
    assert output.scoring_mode is ScoringMode.RULE_ONLY
    assert agent.last_verdict is FinalVerdict.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_llm_failure_falls_back_to_rule_only(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-fallback-{uuid4().hex[:8]}"
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_main_triage(),
            evidence_output=_main_evidence(event_id),
        )
    )
    assert output.scoring_mode is ScoringMode.RULE_ONLY
    assert output.risk_score >= 70
    assert agent.last_verdict is FinalVerdict.CONFIRMED_THREAT


@pytest.mark.asyncio
async def test_verdict_written_only_via_event_service(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-verdict-{uuid4().hex[:8]}"
    agent = RiskAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=event_service,
        scenario_id=_DEMO_SCENARIO_ID,
    )
    await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_main_triage(),
            evidence_output=_main_evidence(event_id),
        )
    )
    assert len(event_service.verdicts) == 1
    assert len(event_service.risk_updates) == 1


class _FailingRiskSyncEventService(_FakeEventService):
    async def update_risk_fields(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("risk db sync unavailable")


@pytest.mark.asyncio
async def test_risk_db_sync_failure_propagates(wm: _FakeWorkingMemory) -> None:
    """update_risk_fields failure must abort RiskAgent after WM write attempt."""
    event_id = f"evt-risk-sync-fail-{uuid4().hex[:8]}"
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=_FailingRiskSyncEventService(),
    )
    with pytest.raises(RuntimeError, match="risk db sync unavailable"):
        await agent.execute(
            RiskAgentInput(
                event_id=event_id,
                triage_result=_main_triage(),
                evidence_output=_main_evidence(event_id),
            )
        )
    stored = await wm.read(event_id, "risk_assessment")
    assert stored is not None
    assert stored["risk_score"] >= 70


def _zero_evidence_output(*, status: CollectionStatus = CollectionStatus.FAILED) -> EvidenceOutput:
    return EvidenceOutput(
        evidence_list=[],
        success_sources=[],
        failed_sources=["endpoint", "network_flow"],
        overall_confidence=0.0,
        collection_status=status,
    )


def _malicious_process_triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            hosts=[HostEntity(entity_id="h1", hostname="DEV-WKS-012", ip="10.0.0.12")],
        ),
        reasoning="malicious process spawned",
    )


def _malicious_process_source_snapshot() -> dict[str, Any]:
    return {
        "severity": "high",
        "alert_type": "malicious_process",
        "normalized": {"event_type": "malicious_process", "risk_score": 76},
    }


def test_extract_source_baseline_from_snapshot() -> None:
    baseline, severity = extract_source_baseline(_malicious_process_source_snapshot())
    assert baseline == 76
    assert severity is Severity.HIGH


def test_is_evidence_limited_requires_failed_or_degraded_and_empty() -> None:
    empty_failed = _zero_evidence_output(status=CollectionStatus.FAILED)
    assert is_evidence_limited(empty_failed) is True
    completed = EvidenceOutput(
        evidence_list=[],
        overall_confidence=0.0,
        collection_status=CollectionStatus.COMPLETED,
    )
    assert is_evidence_limited(completed) is False
    assert is_evidence_limited(_fp_evidence("evt-fp")) is False


def test_apply_evidence_limited_floor_formula() -> None:
    adjustment = apply_evidence_limited_adjustments(
        risk_score=45,
        confidence=0.55,
        evidence_output=_zero_evidence_output(),
        source_snapshot=_malicious_process_source_snapshot(),
    )
    expected_floor = int(round(76 * SOURCE_BASELINE_FLOOR_RATIO))
    assert adjustment.evidence_limited is True
    assert adjustment.source_risk_baseline == 76
    assert adjustment.high_source_evidence_limited is True
    assert adjustment.risk_score >= max(expected_floor, 70)
    assert adjustment.severity is Severity.HIGH
    assert adjustment.severity_floor_applied is True
    assert adjustment.confidence <= EVIDENCE_LIMITED_CONFIDENCE_CAP


def test_apply_evidence_limited_skips_fp_low_severity() -> None:
    adjustment = apply_evidence_limited_adjustments(
        risk_score=22,
        confidence=0.25,
        evidence_output=_zero_evidence_output(status=CollectionStatus.FAILED),
        source_snapshot={
            "severity": "low",
            "normalized": {"risk_score": 18, "scenario": "account_anomaly_fp"},
        },
    )
    assert adjustment.evidence_limited is True
    assert adjustment.high_source_evidence_limited is False
    assert adjustment.risk_score == 22
    assert adjustment.severity_floor_applied is False
    assert adjustment.confidence <= EVIDENCE_LIMITED_CONFIDENCE_CAP


def test_low_severity_zero_evidence_no_score_floor() -> None:
    """Score floor is gated on source severity >= HIGH; low FP must not lift."""
    adjustment = apply_evidence_limited_adjustments(
        risk_score=5,
        confidence=0.4,
        evidence_output=_zero_evidence_output(status=CollectionStatus.FAILED),
        source_snapshot={
            "severity": "low",
            "normalized": {"risk_score": 18, "scenario": "account_anomaly_fp"},
        },
    )
    assert adjustment.evidence_limited is True
    assert adjustment.risk_score == 5
    assert adjustment.severity is Severity.LOW
    assert adjustment.severity_floor_applied is False
    assert adjustment.confidence <= EVIDENCE_LIMITED_CONFIDENCE_CAP


def test_critical_source_floor_keeps_score_severity_aligned() -> None:
    """CRITICAL source floors one tier to HIGH; score stays in HIGH band (>=70)."""
    adjustment = apply_evidence_limited_adjustments(
        risk_score=45,
        confidence=0.5,
        evidence_output=_zero_evidence_output(),
        source_snapshot={
            "severity": "critical",
            "normalized": {"risk_score": 95, "event_type": "malicious_process"},
        },
    )
    assert adjustment.evidence_limited is True
    assert adjustment.severity_floor_applied is True
    assert adjustment.severity is Severity.HIGH
    assert 70 <= adjustment.risk_score < 90
    assert severity_from_score(adjustment.risk_score) is adjustment.severity


def test_source_baseline_from_frozen_ingest_snapshot() -> None:
    from app.db import models as orm
    from app.services.event_service import _source_snapshot_from_row

    row = orm.SecurityEvent(
        event_id="evt-ingest-baseline",
        event_type="malicious_process",
        title="Suspicious process",
        severity="high",
        creation_source_ref={
            "source_product": "mock_xdr",
            "source_tenant_id": "tenant-demo",
            "connector_id": "conn-1",
            "source_kind": "incident",
            "source_object_id": "inc-1",
        },
        source_reference_snapshots=[],
        raw_alert_snapshot={
            "normalized": {"risk_score": 76, "event_type": "malicious_process"},
        },
    )
    snapshot = _source_snapshot_from_row(row)
    baseline, severity = extract_source_baseline(snapshot)
    assert baseline == 76
    assert severity is Severity.HIGH
    adjustment = apply_evidence_limited_adjustments(
        risk_score=45,
        confidence=0.55,
        evidence_output=_zero_evidence_output(),
        source_snapshot=snapshot,
    )
    assert adjustment.source_risk_baseline == 76
    assert adjustment.risk_score >= int(round(76 * SOURCE_BASELINE_FLOOR_RATIO))


@pytest.mark.asyncio
async def test_malicious_process_zero_evidence_applies_severity_floor(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-mp-zero-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = _malicious_process_source_snapshot()
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_malicious_process_triage(),
            evidence_output=_zero_evidence_output(),
        )
    )
    assert output.evidence_limited is True
    assert output.high_source_evidence_limited is True
    assert output.source_risk_baseline == 76
    assert output.severity_floor_applied is True
    assert output.risk_score >= 70
    assert output.severity is Severity.HIGH
    assert output.confidence <= EVIDENCE_LIMITED_CONFIDENCE_CAP
    assert agent.last_verdict is FinalVerdict.NONE
    assert "evidence_limited_demoted_from_confirmed_threat" in output.verdict_reason_codes
    evidence_factor = next(f for f in output.risk_factors if f.factor_name == "evidence_confidence")
    assert "source_baseline=76" in evidence_factor.reasoning
    assert "evidence_limited=true" in evidence_factor.reasoning
    assert event_service.risk_updates
    synced = event_service.risk_updates[-1]["risk_assessment"]
    assert isinstance(synced, dict)
    assert synced.get("evidence_limited") is True
    assert "evidence_limited_demoted_from_confirmed_threat" in (
        synced.get("verdict_reason_codes") or []
    )


@pytest.mark.asyncio
async def test_account_anomaly_fp_zero_evidence_not_floored_to_high(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-fp-zero-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = {
        "severity": "low",
        "normalized": {"risk_score": 18, "scenario": "account_anomaly_fp"},
    }
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=TriageResult(
                event_type=EventType.ACCOUNT_ANOMALY,
                severity=Severity.LOW,
                need_investigation=False,
            ),
            evidence_output=_zero_evidence_output(),
        )
    )
    assert output.evidence_limited is True
    assert output.high_source_evidence_limited is False
    assert output.severity_floor_applied is False
    assert output.severity is not Severity.HIGH
    assert output.risk_score < 40
    assert output.confidence <= EVIDENCE_LIMITED_CONFIDENCE_CAP


@pytest.mark.asyncio
async def test_full_evidence_path_not_raised_by_floor(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-full-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = _malicious_process_source_snapshot()
    agent = RiskAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=event_service,
        scenario_id=_DEMO_SCENARIO_ID,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_main_triage(),
            evidence_output=_main_evidence(event_id),
        )
    )
    assert output.evidence_limited is False
    assert output.severity_floor_applied is False
    assert output.risk_score >= 70


@pytest.mark.asyncio
async def test_llm_failure_zero_evidence_still_applies_floor(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-llm-fail-floor-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = _malicious_process_source_snapshot()
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_malicious_process_triage(),
            evidence_output=_zero_evidence_output(status=CollectionStatus.DEGRADED),
        )
    )
    assert output.scoring_mode is ScoringMode.RULE_ONLY
    assert output.evidence_limited is True
    assert output.risk_score >= 70
    assert output.severity is Severity.HIGH


def test_classify_llm_risk_response_marks_degraded() -> None:
    response = LLMResponse(
        content="{}",
        model_name="m",
        degraded_reason="fallback_model_used",
    )
    assert classify_llm_risk_response(response) is LlmAdmissibility.DEGRADED


def test_classify_llm_risk_response_empty_degraded_reason_is_valid() -> None:
    response = LLMResponse(content="{}", model_name="m", degraded_reason="")
    assert classify_llm_risk_response(response) is LlmAdmissibility.VALID


def test_classify_llm_risk_response_whitespace_degraded_reason_is_valid() -> None:
    response = LLMResponse(content="{}", model_name="m", degraded_reason="   ")
    assert classify_llm_risk_response(response) is LlmAdmissibility.VALID


def test_apply_versioned_confidence_cap_only_lowers() -> None:
    capped, version = apply_versioned_confidence_cap(0.9, evidence_limited=True)
    assert capped == EVIDENCE_LIMITED_CONFIDENCE_CAP
    assert version == CONFIDENCE_CAP_VERSION
    unchanged, version2 = apply_versioned_confidence_cap(0.2, evidence_limited=True)
    assert unchanged == 0.2
    assert version2 == CONFIDENCE_CAP_VERSION
    no_cap, version3 = apply_versioned_confidence_cap(0.9, evidence_limited=False)
    assert no_cap == 0.9
    assert version3 is None


def test_extract_source_baseline_unknown_vendor_scale() -> None:
    snapshot = {
        "severity": "high",
        "normalized": {
            "vendor_risk_score": 76,
            "scale": "vendor_x_unnormalized",
        },
    }
    baseline, severity = extract_source_baseline(snapshot)
    assert baseline is None
    assert severity is Severity.HIGH
    assert source_scale_unnormalized(snapshot, source_baseline=baseline) is True


def test_source_scale_unnormalized_explicit_flag() -> None:
    snapshot = {"normalized": {"unnormalized": True, "vendor_risk_score": 50}}
    assert source_scale_unnormalized(snapshot, source_baseline=None) is True


def test_source_scale_unnormalized_false_when_baseline_present() -> None:
    snapshot = {"normalized": {"risk_score": 76, "scale": "vendor_x"}}
    baseline, _ = extract_source_baseline(snapshot)
    assert baseline == 76
    assert source_scale_unnormalized(snapshot, source_baseline=baseline) is False


@pytest.mark.asyncio
async def test_degraded_llm_matches_rule_only_contract(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-degraded-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = _malicious_process_source_snapshot()
    rule_only_agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    degraded_agent = RiskAgent(
        llm_client=_DegradedLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    agent_input = RiskAgentInput(
        event_id=event_id,
        triage_result=_malicious_process_triage(),
        evidence_output=_zero_evidence_output(),
    )
    rule_output = await rule_only_agent.execute(agent_input)
    degraded_output = await degraded_agent.execute(agent_input)

    assert degraded_output.scoring_mode is ScoringMode.RULE_ONLY
    assert degraded_output.llm_admissibility is LlmAdmissibility.DEGRADED
    assert rule_output.risk_score == degraded_output.risk_score
    assert rule_output.confidence == degraded_output.confidence
    assert rule_output.evidence_limited == degraded_output.evidence_limited
    assert _risk_factor_signature(rule_output.risk_factors) == _risk_factor_signature(
        degraded_output.risk_factors
    )
    assert degraded_output.confidence_cap_version == CONFIDENCE_CAP_VERSION


@pytest.mark.asyncio
async def test_valid_llm_zero_evidence_still_applies_floor_and_cap(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-valid-llm-zero-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = _malicious_process_source_snapshot()
    agent = RiskAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=event_service,
        scenario_id=_DEMO_SCENARIO_ID,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_malicious_process_triage(),
            evidence_output=_zero_evidence_output(),
        )
    )
    assert output.scoring_mode is ScoringMode.LLM_AND_RULE
    assert output.llm_admissibility is LlmAdmissibility.VALID
    assert output.evidence_limited is True
    assert output.high_source_evidence_limited is True
    assert output.risk_score >= 70
    assert output.severity is Severity.HIGH
    assert output.confidence <= EVIDENCE_LIMITED_CONFIDENCE_CAP
    assert output.confidence_cap_version == CONFIDENCE_CAP_VERSION


@pytest.mark.asyncio
async def test_valid_llm_high_source_blocks_auto_fp_without_floor(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-valid-fp-block-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = _malicious_process_source_snapshot()
    wm.values[(event_id, "fp_adjudication")] = {
        "recommendation": "close_as_fp",
        "matched_window_id": "cw-test",
        "max_score": 0.9,
    }
    agent = RiskAgent(
        llm_client=_InflatingValidLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_malicious_process_triage(),
            evidence_output=_zero_evidence_output(),
        )
    )
    assert output.scoring_mode is ScoringMode.LLM_AND_RULE
    assert output.llm_admissibility is LlmAdmissibility.VALID
    assert output.evidence_limited is True
    assert output.high_source_evidence_limited is True
    assert output.severity_floor_applied is False
    assert output.risk_score >= 70
    assert agent.last_verdict is FinalVerdict.NONE
    assert FinalVerdict.FALSE_POSITIVE not in event_service.verdicts


@pytest.mark.asyncio
async def test_invalid_llm_matches_rule_only_contract(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-invalid-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = _malicious_process_source_snapshot()
    rule_only_agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    invalid_agent = RiskAgent(
        llm_client=_MalformedLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    agent_input = RiskAgentInput(
        event_id=event_id,
        triage_result=_malicious_process_triage(),
        evidence_output=_zero_evidence_output(),
    )
    rule_output = await rule_only_agent.execute(agent_input)
    invalid_output = await invalid_agent.execute(agent_input)

    assert invalid_output.scoring_mode is ScoringMode.RULE_ONLY
    assert invalid_output.llm_admissibility is LlmAdmissibility.INVALID
    assert rule_output.risk_score == invalid_output.risk_score
    assert rule_output.confidence == invalid_output.confidence
    assert rule_output.evidence_limited == invalid_output.evidence_limited
    assert _risk_factor_signature(rule_output.risk_factors) == _risk_factor_signature(
        invalid_output.risk_factors
    )
    assert invalid_output.high_source_evidence_limited is True


@pytest.mark.asyncio
async def test_evidence_limited_high_source_blocks_auto_fp_close(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-fp-block-{uuid4().hex[:8]}"
    wm.values[(event_id, "source_snapshot")] = _malicious_process_source_snapshot()
    wm.values[(event_id, "fp_adjudication")] = {
        "recommendation": "close_as_fp",
        "matched_window_id": "cw-test",
        "max_score": 0.9,
    }
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_malicious_process_triage(),
            evidence_output=_zero_evidence_output(),
        )
    )
    assert output.evidence_limited is True
    assert output.high_source_evidence_limited is True
    assert output.severity_floor_applied is True
    assert agent.last_verdict is FinalVerdict.NONE
    assert FinalVerdict.FALSE_POSITIVE not in event_service.verdicts


def _weak_other_triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.MEDIUM,
        need_investigation=True,
        decision_summary="No clear threat pattern detected.",
    )


@pytest.mark.asyncio
async def test_risk_agent_flags_triage_risk_inconsistency(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-inconsistency-{uuid4().hex[:8]}"
    degraded_flags = _MockDegradedFlags()
    agent = RiskAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=event_service,
        degraded_flags=degraded_flags,
        scenario_id=_DEMO_SCENARIO_ID,
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_weak_other_triage(),
            evidence_output=_main_evidence(event_id),
        )
    )
    assert output.risk_score >= 70
    assert agent.last_verdict is FinalVerdict.CONFIRMED_THREAT
    assert degraded_flags.calls
    assert degraded_flags.calls[-1]["flag_name"] == "triage_risk_inconsistency"
    assert degraded_flags.calls[-1]["writer"] == "RiskAgent"


@pytest.mark.asyncio
async def test_risk_agent_skips_inconsistency_flag_for_aligned_triage(
    wm: _FakeWorkingMemory,
    event_service: _FakeEventService,
) -> None:
    event_id = f"evt-risk-aligned-{uuid4().hex[:8]}"
    degraded_flags = _MockDegradedFlags()
    agent = RiskAgent(
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
        working_memory=wm,
        event_service=event_service,
        degraded_flags=degraded_flags,
        scenario_id=_DEMO_SCENARIO_ID,
    )
    await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=_main_triage(),
            evidence_output=_main_evidence(event_id),
        )
    )
    assert degraded_flags.calls == []
