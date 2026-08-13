"""Tests for response plan quality gates (ISSUE-198 / ISSUE-248)."""

from __future__ import annotations

from dataclasses import dataclass

from app.agents.rules.response_plan_quality_gate import (
    CONTAINMENT_TOOLS,
    apply_containment_quality_gate,
    apply_evidence_sufficiency_gate,
    evidence_blocks_high_impact_actions,
    evidence_insufficiency_reason_code,
    has_actionable_containment_targets,
    required_containment_targets,
    requires_threat_aligned_containment,
)
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    ScoringMode,
)
from app.models.entities import AccountEntity, EntitySet, HostEntity, IPEntity
from app.models.enums import ActionLevel, EvidenceSource, FinalVerdict, Severity
from app.models.evidence import Evidence


@dataclass
class _Candidate:
    tool_name: str
    target: str = ""
    target_type: str | None = None


def _risk(
    *,
    score: int = 85,
    severity: Severity = Severity.HIGH,
    evidence_limited: bool = False,
) -> RiskAssessment:
    return RiskAssessment(
        risk_score=score,
        severity=severity,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
        evidence_limited=evidence_limited,
    )


def _tool_level(tool_name: str) -> ActionLevel:
    levels = {
        "create_ticket": ActionLevel.L1,
        "notify_security_team": ActionLevel.L1,
        "block_ip": ActionLevel.L2,
        "isolate_host": ActionLevel.L3,
        "disable_account": ActionLevel.L3,
    }
    return levels.get(tool_name, ActionLevel.L2)


def _entities_with_external_ip() -> EntitySet:
    return EntitySet(
        ips=[
            IPEntity(
                entity_id="ip-ext",
                address="198.51.100.44",
                scope="external",
            )
        ],
        hosts=[HostEntity(entity_id="host-1", hostname="victim-host-01")],
    )


def test_has_actionable_containment_targets_requires_known_entities() -> None:
    assert has_actionable_containment_targets(_entities_with_external_ip()) is True
    assert has_actionable_containment_targets(EntitySet()) is False


def test_requires_containment_for_confirmed_threat_with_entities() -> None:
    assert requires_threat_aligned_containment(
        severity=Severity.MEDIUM,
        risk_assessment=_risk(score=40, severity=Severity.MEDIUM),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )


def test_requires_containment_false_for_false_positive() -> None:
    assert not requires_threat_aligned_containment(
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )


def test_apply_gate_falls_back_when_llm_leaves_only_ticket() -> None:
    llm_filtered = [
        _Candidate("create_ticket"),
    ]
    rule_filtered = [
        _Candidate("block_ip", "198.51.100.44"),
        _Candidate("create_ticket"),
    ]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=rule_filtered,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM proposed candidate actions",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )
    tool_names = {item.tool_name for item in merged}
    assert "block_ip" in tool_names
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "containment_quality_gate" in strategy


def test_apply_gate_marks_unsatisfied_when_no_rule_containment() -> None:
    llm_filtered = [_Candidate("create_ticket")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[_Candidate("create_ticket")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM proposed candidate actions",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )
    assert merged == llm_filtered
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "containment_quality_gate_unsatisfied" in strategy


def test_apply_gate_merges_missing_host_when_llm_has_partial_containment() -> None:
    """ISSUE-328: block_ip alone must not skip isolate_host for uncovered EntitySet hosts."""
    llm_filtered = [_Candidate("block_ip", "198.51.100.44", "ip")]
    rule_filtered = [_Candidate("isolate_host", "victim-host-01", "host")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=rule_filtered,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_entities_with_external_ip(),
        disposition_only=False,
    )
    tool_targets = {(item.tool_name, item.target) for item in merged}
    assert ("block_ip", "198.51.100.44") in tool_targets
    assert ("isolate_host", "victim-host-01") in tool_targets
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "entity coverage merge" in strategy


def test_apply_gate_noop_when_entity_coverage_complete() -> None:
    """Full EntitySet containment coverage — no merge when every host/IP/account is covered."""
    llm_filtered = [
        _Candidate("block_ip", "198.51.100.44", "ip"),
        _Candidate("isolate_host", "victim-host-01", "host"),
        _Candidate("disable_account", "svc-backup", "account"),
    ]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=EntitySet(
            accounts=[AccountEntity(entity_id="acct-1", username="svc-backup")],
            hosts=[HostEntity(entity_id="host-1", hostname="victim-host-01")],
            ips=[
                IPEntity(
                    entity_id="ip-ext",
                    address="198.51.100.44",
                    scope="external",
                )
            ],
        ),
        disposition_only=False,
    )
    assert merged == llm_filtered
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert strategy == "LLM ok"


def test_required_containment_targets_scoped_to_entity_set_only() -> None:
    """ISSUE-328: only EntitySet members are required — no asset-inventory expansion."""
    targets = required_containment_targets(
        EntitySet(
            hosts=[HostEntity(entity_id="host-wks", hostname="WKS-DATA-031")],
            ips=[
                IPEntity(entity_id="ip-ext", address="198.51.100.44", scope="external"),
            ],
        )
    )
    assert ("isolate_host", "host", "WKS-DATA-031") in targets
    assert ("block_ip", "ip", "198.51.100.44") in targets
    assert not any(item[2] == "BACKUP-SRV-01" for item in targets)


def test_apply_gate_synthesizes_missing_db_host_from_entity_set() -> None:
    """ISSUE-328 probe: partial LLM containment must add isolate_host(SRV-DB-STG-02)."""
    llm_filtered = [
        _Candidate("block_ip", "198.51.100.44", "ip"),
        _Candidate("isolate_host", "WKS-DATA-031", "host"),
        _Candidate("disable_account", "svc-analytics-47", "account"),
    ]
    entities = EntitySet(
        accounts=[AccountEntity(entity_id="acct-1", username="svc-analytics-47")],
        hosts=[
            HostEntity(entity_id="host-wks", hostname="WKS-DATA-031"),
            HostEntity(entity_id="host-db", hostname="SRV-DB-STG-02"),
        ],
        ips=[IPEntity(entity_id="ip-ext", address="198.51.100.44", scope="external")],
    )
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[
            _Candidate("isolate_host", "WKS-DATA-031", "host"),
            _Candidate("block_ip", "198.51.100.44", "ip"),
            _Candidate("disable_account", "svc-analytics-47", "account"),
        ],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM partial",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=entities,
        disposition_only=False,
    )
    tool_targets = {(item.tool_name, item.target) for item in merged}
    assert ("isolate_host", "SRV-DB-STG-02") in tool_targets
    assert ("isolate_host", "WKS-DATA-031") in tool_targets
    assert all(
        target != "BACKUP-SRV-01"
        for tool_name, target in tool_targets
        if tool_name == "isolate_host"
    )
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "entity coverage merge" in strategy


def test_apply_gate_skips_synthesis_when_tool_not_in_rule_pool() -> None:
    """Synthesis respects policy-filtered rule pool — disabled tools are not invented."""
    llm_filtered = [_Candidate("create_ticket", "ticket")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[
            _Candidate("isolate_host", "WKS-DATA-031", "host"),
        ],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="ticket only",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=EntitySet(
            hosts=[HostEntity(entity_id="host-wks", hostname="WKS-DATA-031")],
            ips=[IPEntity(entity_id="ip-ext", address="198.51.100.44", scope="external")],
        ),
        disposition_only=False,
    )
    tool_names = {item.tool_name for item in merged}
    assert "isolate_host" in tool_names
    assert "block_ip" not in tool_names


def test_containment_tools_cover_issue_scope() -> None:
    for tool in ("block_ip", "block_domain", "isolate_host", "disable_account"):
        assert tool in CONTAINMENT_TOOLS


def test_evidence_blocks_on_collection_failed() -> None:
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.FAILED,
        overall_confidence=0.0,
    )
    assert evidence_blocks_high_impact_actions(
        evidence_output=evidence,
        risk_assessment=_risk(score=90, evidence_limited=True),
    )


def test_evidence_blocks_on_collection_failed_even_with_items() -> None:
    """ISSUE-248: failed collection blocks L2+ even when evidence_list is non-empty."""
    evidence = EvidenceOutput(
        evidence_list=[
            Evidence(
                evidence_id="ev-partial",
                event_id="evt-1",
                source=EvidenceSource.ENDPOINT,
                evidence_type="process",
                description="partial artifact before failure",
                confidence=0.4,
            )
        ],
        collection_status=CollectionStatus.FAILED,
        overall_confidence=0.4,
    )
    assert evidence_blocks_high_impact_actions(
        evidence_output=evidence,
        risk_assessment=_risk(score=90, evidence_limited=False),
    )
    assert evidence_insufficiency_reason_code(evidence_output=evidence) == "collection_failed"


def test_evidence_blocks_when_output_missing_and_limited() -> None:
    """ISSUE-248: missing evidence payload + evidence_limited fails closed."""
    assert evidence_blocks_high_impact_actions(
        evidence_output=None,
        risk_assessment=_risk(score=85, evidence_limited=True),
    )
    assert (
        evidence_insufficiency_reason_code(
            evidence_output=None,
            risk_assessment=_risk(score=85, evidence_limited=True),
        )
        == "zero_evidence_limited"
    )


def test_evidence_blocks_on_zero_evidence_limited() -> None:
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.DEGRADED,
        overall_confidence=0.1,
    )
    assert evidence_blocks_high_impact_actions(
        evidence_output=evidence,
        risk_assessment=_risk(score=88, evidence_limited=True),
    )


def test_evidence_does_not_block_when_usable_evidence_present() -> None:
    evidence = EvidenceOutput(
        evidence_list=[
            Evidence(
                evidence_id="ev-1",
                event_id="evt-1",
                source=EvidenceSource.ENDPOINT,
                evidence_type="process",
                description="malicious process",
                confidence=0.9,
            )
        ],
        collection_status=CollectionStatus.COMPLETED,
        overall_confidence=0.9,
    )
    assert not evidence_blocks_high_impact_actions(
        evidence_output=evidence,
        risk_assessment=_risk(score=90, evidence_limited=False),
    )


def test_verdict_none_alone_does_not_block_high_impact() -> None:
    """ISSUE-248: do not ban containment solely because verdict demoted to none."""
    evidence = EvidenceOutput(
        evidence_list=[
            Evidence(
                evidence_id="ev-2",
                event_id="evt-1",
                source=EvidenceSource.NETWORK_FLOW,
                evidence_type="flow",
                description="exfil flow",
                confidence=0.8,
            )
        ],
        collection_status=CollectionStatus.COMPLETED,
        overall_confidence=0.85,
    )
    assert not evidence_blocks_high_impact_actions(
        evidence_output=evidence,
        risk_assessment=_risk(score=75, evidence_limited=False),
    )
    assert requires_threat_aligned_containment(
        severity=Severity.HIGH,
        risk_assessment=_risk(score=75),
        final_verdict=FinalVerdict.NONE,
        entities=_entities_with_external_ip(),
        disposition_only=False,
        evidence_output=evidence,
    )


def test_requires_containment_false_when_evidence_insufficient() -> None:
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.FAILED,
        overall_confidence=0.0,
    )
    assert not requires_threat_aligned_containment(
        severity=Severity.HIGH,
        risk_assessment=_risk(score=92, evidence_limited=True),
        final_verdict=FinalVerdict.NONE,
        entities=_entities_with_external_ip(),
        disposition_only=False,
        evidence_output=evidence,
    )


def test_apply_evidence_gate_strips_l2_plus_keeps_l1() -> None:
    candidates = [
        _Candidate("block_ip", "198.51.100.44"),
        _Candidate("isolate_host", "victim-host-01"),
        _Candidate("create_ticket"),
        _Candidate("notify_security_team"),
    ]
    kept, generated_by, strategy = apply_evidence_sufficiency_gate(
        candidates=candidates,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM proposed candidate actions",
        evidence_output=EvidenceOutput(
            evidence_list=[],
            collection_status=CollectionStatus.FAILED,
            overall_confidence=0.0,
        ),
        risk_assessment=_risk(score=90, evidence_limited=True),
        disposition_only=False,
        resolve_tool_level=_tool_level,
    )
    assert {item.tool_name for item in kept} == {"create_ticket", "notify_security_team"}
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "evidence_sufficiency_gate" in strategy
    assert "collection_failed" in strategy


def test_apply_evidence_gate_noop_with_sufficient_evidence() -> None:
    candidates = [
        _Candidate("block_ip", "198.51.100.44"),
        _Candidate("create_ticket"),
    ]
    evidence = EvidenceOutput(
        evidence_list=[
            Evidence(
                evidence_id="ev-3",
                event_id="evt-1",
                source=EvidenceSource.THREAT_INTEL,
                evidence_type="ioc",
                description="known bad IP",
                confidence=0.95,
            )
        ],
        collection_status=CollectionStatus.COMPLETED,
        overall_confidence=0.95,
    )
    kept, generated_by, strategy = apply_evidence_sufficiency_gate(
        candidates=candidates,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        evidence_output=evidence,
        risk_assessment=_risk(score=90, evidence_limited=False),
        disposition_only=False,
        resolve_tool_level=_tool_level,
    )
    assert kept == candidates
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert strategy == "LLM ok"


def test_apply_evidence_gate_uses_safe_fallback_when_stripped_empty() -> None:
    kept, _, strategy = apply_evidence_sufficiency_gate(
        candidates=[_Candidate("block_ip", "198.51.100.44")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM proposed candidate actions",
        evidence_output=EvidenceOutput(
            evidence_list=[],
            collection_status=CollectionStatus.DEGRADED,
            overall_confidence=0.0,
        ),
        risk_assessment=_risk(score=88, evidence_limited=True),
        disposition_only=False,
        resolve_tool_level=_tool_level,
        fallback_safe_candidates=[
            _Candidate("create_ticket"),
            _Candidate("block_ip", "198.51.100.44"),
        ],
    )
    assert [item.tool_name for item in kept] == ["create_ticket"]
    assert "zero_evidence_limited" in strategy
