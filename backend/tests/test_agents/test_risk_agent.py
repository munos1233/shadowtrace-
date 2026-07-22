"""RiskAgent six-dimension scoring tests (ISSUE-035)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from app.agents.confidence_calibration import calibrate_confidence
from app.agents.risk_agent import RiskAgent
from app.agents.risk_scoring_engine import FACTOR_WEIGHTS, RiskScoringEngine, severity_from_score
from app.core.llm.base import InMemoryLLMCallAuditRecorder, LLMResponse
from app.core.llm.mock_client import MockLLMClient
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RiskAgentInput,
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
    ) -> None:
        self.risk_updates.append(
            {
                "event_id": event_id,
                "risk_score": risk_score,
                "severity": severity,
                "confidence": confidence,
                "operator": operator,
                "factor_names": factor_names,
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


class _FailingLLM:
    async def chat(self, *args: Any, **kwargs: Any) -> LLMResponse:
        raise RuntimeError("llm unavailable")


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
        "recommendation": "close_as_fp",
        "max_score": 0.96,
    }
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    # Weak evidence → rule_only low score; close_as_fp forces FP verdict.
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
