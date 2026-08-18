"""Tests for response plan quality gates (ISSUE-198 / ISSUE-248 / ISSUE-359)."""

from __future__ import annotations

from dataclasses import dataclass

from app.agents.rules.response_plan_quality_gate import (
    CONTAINMENT_TOOLS,
    IDENTITY_CONTAINMENT_TOOLS,
    apply_containment_quality_gate,
    apply_evidence_sufficiency_gate,
    apply_exfil_domain_containment_gate,
    apply_identity_containment_dedup_gate,
    deduplicate_identity_containment,
    entity_containment_coverage_needs,
    evidence_blocks_high_impact_actions,
    evidence_insufficiency_reason_code,
    exfil_domain_containment_needs,
    has_actionable_containment_targets,
    requires_threat_aligned_containment,
)
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    ScoringMode,
)
from app.models.entities import AccountEntity, DomainEntity, EntitySet, HostEntity, IPEntity
from app.models.enums import ActionLevel, EvidenceSource, FinalVerdict, Severity
from app.models.evidence import Evidence


@dataclass
class _Candidate:
    tool_name: str
    target: str = ""


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


def test_apply_gate_merges_uncovered_host_when_llm_already_has_containment() -> None:
    """ISSUE-328: block_ip alone does not cover an EntitySet host."""
    llm_filtered = [_Candidate("block_ip", "198.51.100.44")]
    rule_filtered = [_Candidate("isolate_host", "victim-host-01")]
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
    tool_names = {item.tool_name for item in merged}
    isolate_targets = {item.target for item in merged if item.tool_name == "isolate_host"}
    assert "block_ip" in tool_names
    assert isolate_targets == {"victim-host-01"}
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert "entity_coverage_merge" in strategy


def test_apply_gate_noop_when_entity_coverage_complete() -> None:
    """ISSUE-328: no host/account in EntitySet and dest IP already blocked → noop."""
    entities = EntitySet(
        ips=[
            IPEntity(
                entity_id="ip-dst",
                address="198.51.100.77",
                scope="external",
                attributes={"normalized_field": "dst_ip"},
            )
        ]
    )
    llm_filtered = [_Candidate("block_ip", "198.51.100.77")]
    rule_filtered = [_Candidate("isolate_host", "BACKUP-SRV-01")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=rule_filtered,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=entities,
        disposition_only=False,
    )
    assert merged == llm_filtered
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert strategy == "LLM ok"
    assert all(item.target != "BACKUP-SRV-01" for item in merged)


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


def _exfil_coverage_entities() -> EntitySet:
    return EntitySet(
        accounts=[AccountEntity(entity_id="acct-1", username="svc-analytics-47")],
        hosts=[
            HostEntity(entity_id="host-wks", hostname="WKS-DATA-031"),
            HostEntity(entity_id="host-db", hostname="SRV-DB-STG-02"),
        ],
        ips=[
            IPEntity(
                entity_id="ip-vpn",
                address="198.51.100.44",
                scope="external",
                attributes={"normalized_field": "src_ip"},
            ),
            IPEntity(
                entity_id="ip-upload",
                address="198.51.100.77",
                scope="external",
                attributes={"normalized_field": "dst_ip"},
            ),
        ],
    )


def test_entity_coverage_needs_skip_vpn_src_and_hosts_outside_entityset() -> None:
    needs = entity_containment_coverage_needs(_exfil_coverage_entities())
    pairs = {(item.tool_name, item.canonical_target) for item in needs}
    assert ("disable_account", "svc-analytics-47") in pairs
    assert ("isolate_host", "WKS-DATA-031") in pairs
    assert ("isolate_host", "SRV-DB-STG-02") in pairs
    assert ("block_ip", "198.51.100.77") in pairs
    assert ("block_ip", "198.51.100.44") not in pairs
    assert all(item.canonical_target != "BACKUP-SRV-01" for item in needs)


def test_apply_gate_merges_uncovered_db_host_without_isolating_bait() -> None:
    """ISSUE-328: WKS isolated + block_ip + disable_account still must isolate DB."""
    llm_filtered = [
        _Candidate("block_ip", "198.51.100.77"),
        _Candidate("isolate_host", "WKS-DATA-031"),
        _Candidate("disable_account", "svc-analytics-47"),
    ]
    rule_filtered = [
        _Candidate("isolate_host", "WKS-DATA-031"),
        _Candidate("isolate_host", "SRV-DB-STG-02"),
        _Candidate("isolate_host", "BACKUP-SRV-01"),
        _Candidate("disable_account", "svc-analytics-47"),
        _Candidate("block_ip", "198.51.100.77"),
    ]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=rule_filtered,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy=("Isolate workstation; SRV-DB-STG-02 remains online pending investigation"),
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
    )
    isolate_targets = {item.target for item in merged if item.tool_name == "isolate_host"}
    assert isolate_targets == {"WKS-DATA-031", "SRV-DB-STG-02"}
    assert "BACKUP-SRV-01" not in isolate_targets
    assert any(item.tool_name == "disable_account" for item in merged)
    assert any(item.target == "198.51.100.77" for item in merged if item.tool_name == "block_ip")
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert "entity_coverage_merge" in strategy
    assert "remains online" not in strategy.lower()
    assert "isolated hosts: WKS-DATA-031, SRV-DB-STG-02" in strategy


def test_apply_gate_reconciles_leave_host_online_clause() -> None:
    llm_filtered = [_Candidate("isolate_host", "WKS-DATA-031")]
    rule_filtered = [_Candidate("isolate_host", "SRV-DB-STG-02")]
    _, _, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=rule_filtered,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="Contain WKS; leave SRV-DB-STG-02 online for monitoring",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
    )
    assert "leave SRV-DB-STG-02 online" not in strategy.lower()
    assert "isolated hosts: WKS-DATA-031, SRV-DB-STG-02" in strategy


def test_apply_gate_reconciles_keep_and_stays_and_leave_the_db_clauses() -> None:
    llm_filtered = [_Candidate("isolate_host", "WKS-DATA-031")]
    rule_filtered = [_Candidate("isolate_host", "SRV-DB-STG-02")]
    variants = (
        "keep SRV-DB-STG-02 online",
        "SRV-DB-STG-02 stays online",
        "leave the DB SRV-DB-STG-02 online",
    )
    for original in variants:
        _, _, strategy = apply_containment_quality_gate(
            candidates=llm_filtered,
            rule_fallback_candidates=rule_filtered,
            generated_by=ResponsePlanGeneratedBy.LLM,
            strategy=original,
            severity=Severity.HIGH,
            risk_assessment=_risk(),
            final_verdict=FinalVerdict.CONFIRMED_THREAT,
            entities=_exfil_coverage_entities(),
            disposition_only=False,
        )
        lowered = strategy.lower()
        assert "keep srv-db-stg-02 online" not in lowered
        assert "stays online" not in lowered
        assert "leave the db srv-db-stg-02 online" not in lowered
        assert "isolated hosts: WKS-DATA-031, SRV-DB-STG-02" in strategy


def test_apply_gate_preserves_non_isolated_host_online_clause() -> None:
    llm_filtered = [_Candidate("isolate_host", "WKS-DATA-031")]
    rule_filtered = [_Candidate("isolate_host", "SRV-DB-STG-02")]
    _, _, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=rule_filtered,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy=(
            "BACKUP-SRV-01 remains online; SRV-DB-STG-02 remains online pending investigation"
        ),
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
    )
    assert "BACKUP-SRV-01 remains online" in strategy
    assert "SRV-DB-STG-02 remains online" not in strategy
    assert "isolated hosts: WKS-DATA-031, SRV-DB-STG-02" in strategy


def test_apply_gate_reconciles_when_coverage_already_complete() -> None:
    """ISSUE-357: contradictory strategy is fixed even when merge adds nothing."""
    both_hosts = [
        _Candidate("isolate_host", "WKS-DATA-031"),
        _Candidate("isolate_host", "SRV-DB-STG-02"),
        _Candidate("disable_account", "svc-analytics-47"),
        _Candidate("block_ip", "198.51.100.77"),
    ]
    merged, _, strategy = apply_containment_quality_gate(
        candidates=both_hosts,
        rule_fallback_candidates=both_hosts,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="Isolate workstation; SRV-DB-STG-02 remains online pending investigation",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
    )
    isolate_targets = {item.target for item in merged if item.tool_name == "isolate_host"}
    assert isolate_targets == {"WKS-DATA-031", "SRV-DB-STG-02"}
    assert "entity_coverage_merge" not in strategy
    assert "remains online" not in strategy.lower()
    assert "isolated hosts: WKS-DATA-031, SRV-DB-STG-02" in strategy


def test_apply_gate_strips_hostname_when_isolate_target_is_ip() -> None:
    entities = EntitySet(
        hosts=[
            HostEntity(entity_id="host-wks", hostname="WKS-DATA-031"),
            HostEntity(
                entity_id="host-db",
                hostname="SRV-DB-STG-02",
                ip="10.44.20.88",
            ),
        ]
    )
    merged, _, strategy = apply_containment_quality_gate(
        candidates=[
            _Candidate("isolate_host", "WKS-DATA-031"),
            _Candidate("isolate_host", "10.44.20.88"),
        ],
        rule_fallback_candidates=[_Candidate("isolate_host", "SRV-DB-STG-02")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="SRV-DB-STG-02 remains online pending investigation",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=entities,
        disposition_only=False,
    )
    isolate_targets = {item.target for item in merged if item.tool_name == "isolate_host"}
    assert isolate_targets == {"WKS-DATA-031", "10.44.20.88"}
    assert "remains online" not in strategy.lower()
    assert "isolated hosts: WKS-DATA-031, SRV-DB-STG-02" in strategy


def test_apply_gate_synthesizes_isolate_when_rules_omit_host() -> None:
    """ISSUE-328: once isolate_host is admitted, uncovered EntitySet hosts are synthesized."""
    llm_filtered = [
        _Candidate("block_ip", "198.51.100.77"),
        _Candidate("isolate_host", "WKS-DATA-031"),
    ]
    merged, _, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[_Candidate("block_ip", "198.51.100.77")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
    )
    isolate_targets = {item.target for item in merged if item.tool_name == "isolate_host"}
    assert isolate_targets == {"WKS-DATA-031", "SRV-DB-STG-02"}
    assert "BACKUP-SRV-01" not in isolate_targets
    assert "entity_coverage_merge" in strategy
    assert "isolated hosts: WKS-DATA-031, SRV-DB-STG-02" in strategy


def test_apply_gate_does_not_synthesize_tool_absent_from_plan_and_fallback() -> None:
    """Do not invent isolate/block when PolicyFilter never admitted those tools."""
    llm_filtered = [_Candidate("disable_account", "svc-analytics-47")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[_Candidate("disable_account", "svc-analytics-47")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
    )
    tool_names = {item.tool_name for item in merged}
    assert tool_names == {"disable_account"}
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert "entity_coverage_incomplete" in strategy
    assert "isolate_host" not in tool_names
    assert "block_ip" not in tool_names


def test_apply_gate_skips_coverage_when_evidence_insufficient() -> None:
    """ISSUE-248 still outranks containment encouragement, including coverage merge."""
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.FAILED,
        overall_confidence=0.0,
    )
    llm_filtered = [_Candidate("create_ticket")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[_Candidate("isolate_host", "SRV-DB-STG-02")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(score=92, evidence_limited=True),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
        evidence_output=evidence,
    )
    assert merged == llm_filtered
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert strategy == "LLM ok"


def test_coverage_needs_merges_host_alias_split_across_entity_rows() -> None:
    """Same host listed as hostname row + IP row must not emit two isolate needs."""
    entities = EntitySet(
        hosts=[
            HostEntity(entity_id="10.44.20.88", hostname="SRV-DB-STG-02"),
            HostEntity(entity_id="host-db-ip", hostname=None, ip="10.44.20.88"),
        ]
    )
    needs = entity_containment_coverage_needs(entities)
    isolate = [item for item in needs if item.tool_name == "isolate_host"]
    assert len(isolate) == 1
    assert "srv-db-stg-02" in isolate[0].aliases
    assert "10.44.20.88" in isolate[0].aliases

    merged, _, strategy = apply_containment_quality_gate(
        candidates=[_Candidate("isolate_host", "SRV-DB-STG-02")],
        rule_fallback_candidates=[_Candidate("isolate_host", "10.44.20.88")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=entities,
        disposition_only=False,
    )
    isolate_targets = [item.target for item in merged if item.tool_name == "isolate_host"]
    assert isolate_targets == ["SRV-DB-STG-02"]
    assert "entity_coverage_merge" not in strategy


def test_has_actionable_includes_domains_but_coverage_needs_ignore_them() -> None:
    """ISSUE-198 encouragement is broader than ISSUE-328 coverage merge."""
    entities = EntitySet(domains=[DomainEntity(entity_id="dom-1", fqdn="evil.example")])
    assert has_actionable_containment_targets(entities) is True
    assert entity_containment_coverage_needs(entities) == ()
    needs = exfil_domain_containment_needs(entities)
    assert len(needs) == 1
    assert needs[0].tool_name == "block_domain"
    assert needs[0].canonical_target == "evil.example"


def test_exfil_domain_gate_demotes_llm_without_injecting_block_domain() -> None:
    entities = EntitySet(domains=[DomainEntity(entity_id="dom-1", fqdn="evil.example")])
    kept, generated_by, strategy = apply_exfil_domain_containment_gate(
        candidates=[_Candidate("isolate_host", "PC-FIN-023")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=entities,
        disposition_only=False,
    )
    assert [item.tool_name for item in kept] == ["isolate_host"]
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "domain_containment_missing" in strategy


def test_exfil_domain_gate_keeps_llm_when_block_domain_covers_entityset() -> None:
    entities = EntitySet(domains=[DomainEntity(entity_id="dom-1", fqdn="evil.example")])
    kept, generated_by, strategy = apply_exfil_domain_containment_gate(
        candidates=[
            _Candidate("isolate_host", "PC-FIN-023"),
            _Candidate("block_domain", "evil.example"),
        ],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=entities,
        disposition_only=False,
    )
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert "domain_containment_missing" not in strategy
    assert any(item.tool_name == "block_domain" for item in kept)


def test_apply_gate_noop_on_empty_entityset() -> None:
    llm_filtered = [_Candidate("create_ticket")]
    merged, generated_by, strategy = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[_Candidate("isolate_host", "SRV-DB-STG-02")],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM ok",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=EntitySet(),
        disposition_only=False,
    )
    assert merged == llm_filtered
    assert generated_by is ResponsePlanGeneratedBy.LLM
    assert strategy == "LLM ok"


def test_identity_dedup_collapses_three_piece_set_on_same_account() -> None:
    """ISSUE-359: disable + force_logout + revoke_token on one account → keep disable only."""
    candidates = [
        _Candidate("disable_account", "svc-analytics-47"),
        _Candidate("force_logout", "svc-analytics-47"),
        _Candidate("revoke_token", "svc-analytics-47"),
    ]
    deduped, removed = deduplicate_identity_containment(candidates)
    assert removed is True
    assert [item.tool_name for item in deduped] == ["disable_account"]
    assert deduped[0].target == "svc-analytics-47"


def test_identity_dedup_keeps_force_logout_when_disable_absent() -> None:
    candidates = [
        _Candidate("force_logout", "svc-analytics-47"),
        _Candidate("revoke_token", "svc-analytics-47"),
    ]
    deduped, removed = deduplicate_identity_containment(candidates)
    assert removed is True
    assert [item.tool_name for item in deduped] == ["force_logout"]


def test_identity_dedup_does_not_merge_different_accounts() -> None:
    candidates = [
        _Candidate("disable_account", "account-a"),
        _Candidate("disable_account", "account-b"),
    ]
    deduped, removed = deduplicate_identity_containment(candidates)
    assert removed is False
    assert len(deduped) == 2


def test_identity_dedup_preserves_isolate_hosts_after_containment_merge() -> None:
    """ISSUE-359: identity dedup must not remove EntitySet isolate coverage."""
    llm_filtered = [
        _Candidate("disable_account", "svc-analytics-47"),
        _Candidate("force_logout", "svc-analytics-47"),
        _Candidate("revoke_token", "svc-analytics-47"),
        _Candidate("isolate_host", "WKS-DATA-031"),
        _Candidate("block_ip", "198.51.100.77"),
    ]
    merged, _, _ = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[
            _Candidate("isolate_host", "WKS-DATA-031"),
            _Candidate("isolate_host", "SRV-DB-STG-02"),
            _Candidate("disable_account", "svc-analytics-47"),
            _Candidate("block_ip", "198.51.100.77"),
        ],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM identity triple",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
    )
    deduped, generated_by, strategy = apply_identity_containment_dedup_gate(
        candidates=merged,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM identity triple",
        disposition_only=False,
    )
    identity_tools = [
        item.tool_name for item in deduped if item.tool_name in IDENTITY_CONTAINMENT_TOOLS
    ]
    isolate_targets = {item.target for item in deduped if item.tool_name == "isolate_host"}
    assert identity_tools == ["disable_account"]
    assert isolate_targets == {"WKS-DATA-031", "SRV-DB-STG-02"}
    assert "BACKUP-SRV-01" not in isolate_targets
    assert generated_by is ResponsePlanGeneratedBy.TEMPLATE
    assert "identity_containment_dedup" in strategy


def test_identity_dedup_after_coverage_injects_disable() -> None:
    """328 may add disable_account; 359 must then drop force_logout/revoke."""
    llm_filtered = [
        _Candidate("force_logout", "svc-analytics-47"),
        _Candidate("revoke_token", "svc-analytics-47"),
        _Candidate("isolate_host", "WKS-DATA-031"),
        _Candidate("block_ip", "198.51.100.77"),
    ]
    merged, _, _ = apply_containment_quality_gate(
        candidates=llm_filtered,
        rule_fallback_candidates=[
            _Candidate("isolate_host", "WKS-DATA-031"),
            _Candidate("isolate_host", "SRV-DB-STG-02"),
            _Candidate("disable_account", "svc-analytics-47"),
            _Candidate("block_ip", "198.51.100.77"),
        ],
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM force_logout plus revoke",
        severity=Severity.HIGH,
        risk_assessment=_risk(),
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        entities=_exfil_coverage_entities(),
        disposition_only=False,
    )
    assert any(item.tool_name == "disable_account" for item in merged)
    deduped, _, strategy = apply_identity_containment_dedup_gate(
        candidates=merged,
        generated_by=ResponsePlanGeneratedBy.LLM,
        strategy="LLM force_logout plus revoke",
        disposition_only=False,
    )
    identity_tools = [
        item.tool_name for item in deduped if item.tool_name in IDENTITY_CONTAINMENT_TOOLS
    ]
    isolate_targets = {item.target for item in deduped if item.tool_name == "isolate_host"}
    assert identity_tools == ["disable_account"]
    assert isolate_targets == {"WKS-DATA-031", "SRV-DB-STG-02"}
    assert "identity_containment_dedup" in strategy


def test_identity_dedup_collapses_duplicate_same_tool() -> None:
    candidates = [
        _Candidate("disable_account", "svc-analytics-47"),
        _Candidate("disable_account", "svc-analytics-47"),
    ]
    deduped, removed = deduplicate_identity_containment(candidates)
    assert removed is True
    assert [item.tool_name for item in deduped] == ["disable_account"]


def test_identity_dedup_collapses_disable_and_reset_password() -> None:
    candidates = [
        _Candidate("disable_account", "svc-analytics-47"),
        _Candidate("reset_password", "svc-analytics-47"),
    ]
    deduped, removed = deduplicate_identity_containment(candidates)
    assert removed is True
    assert [item.tool_name for item in deduped] == ["disable_account"]


def test_identity_containment_tools_cover_issue_scope() -> None:
    for tool in ("disable_account", "force_logout", "reset_password", "revoke_token"):
        assert tool in IDENTITY_CONTAINMENT_TOOLS
