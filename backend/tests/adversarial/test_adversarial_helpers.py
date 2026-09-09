"""Unit tests for adversarial helper contracts (ISSUE-203)."""

from __future__ import annotations

import pytest

from app.models.evidence import SKIP_GAP_REASONS, skipped_entity_description
from tests.adversarial.audit_report import (
    AdversarialAuditChecks,
    _writeback_certification_label,
    build_scorecard_header,
    build_writeback_certification,
    evaluate_evidence_collection_ok,
    evaluate_writeback_confirmed,
    resolve_scorecard_llm_mode,
    scorecard_contract_for_llm_mode,
    writeback_tier_ok,
)
from tests.adversarial.full_loop_runner import (
    resolve_disposition_is_mock,
    resolve_full_loop_timeout_s,
)
from tests.adversarial.helpers import (
    assert_opaque_alert_quality,
    audit_required_signals,
    block_ip_reason_destination_mislabels,
    build_alert_corpus,
    build_narrative_corpus,
    containment_tool_for_target,
    disposition_gap_target_label,
    format_disposition_gap,
    missing_response_targets,
    opaque_scorecard_tokens,
    response_plan_targets,
    response_plan_tool_targets,
    strict_disposition_targets_enabled,
)
from tests.adversarial.scenario_credential_db_staging_exfil import (
    ACCOUNT,
    GROUND_TRUTH,
    HOST_BACKUP_NOISE,
    HOST_DB,
    HOST_WORKSTATION,
    UPLOAD_DOMAIN,
    UPLOAD_IP,
    VPN_SRC_IP,
)

_CLOSED_SEQUENCE = [
    "new",
    "investigating",
    "planning_response",
    "waiting_approval",
    "executing_response",
    "verifying",
    "reporting",
    "closed",
]
_REPORTING_ONLY_SEQUENCE = [
    "new",
    "investigating",
    "verifying",
    "reporting",
]
_EMPTY_ENTITY_BUCKETS = {
    "hosts": [],
    "accounts": [],
    "ips": [],
    "domains": [],
    "processes": [],
    "files": [],
}


def _analysis_pass_checks(**overrides: object) -> AdversarialAuditChecks:
    defaults = {
        "ground_truth": GROUND_TRUTH,
        "event_type": "account_anomaly",
        "severity": "high",
        "risk_score": 80,
        "final_verdict": "confirmed_threat",
        "entities_found": list(GROUND_TRUTH["must_identify_entities"]),
        "indicators_found": list(GROUND_TRUTH["must_identify_indicators"]),
        "report_excerpt": "Confirmed threat summary",
        "triage_summary": "",
        "evidence_collection_status": "completed",
        "status_sequence": _REPORTING_ONLY_SEQUENCE,
    }
    defaults.update(overrides)
    return AdversarialAuditChecks(**defaults)  # type: ignore[arg-type]


def test_response_plan_targets_normalizes_case() -> None:
    actions = [{"target": "WKS-DATA-031"}, {"target": "198.51.100.44"}]
    assert response_plan_targets(actions) == {"wks-data-031", "198.51.100.44"}


def test_response_plan_tool_targets_requires_tool_name() -> None:
    actions = [{"target": "WKS-DATA-031"}, {"tool_name": "isolate_host", "target": "WKS-DATA-031"}]
    assert response_plan_tool_targets(actions) == {("isolate_host", "wks-data-031")}


def test_containment_tool_for_target_maps_ground_truth_entities() -> None:
    assert containment_tool_for_target(ACCOUNT, GROUND_TRUTH) == "disable_account"
    assert containment_tool_for_target("WKS-DATA-031", GROUND_TRUTH) == "isolate_host"
    assert containment_tool_for_target(HOST_DB, GROUND_TRUTH) == "isolate_host"
    assert containment_tool_for_target(UPLOAD_IP, GROUND_TRUTH) == "block_ip"
    assert containment_tool_for_target(UPLOAD_DOMAIN, GROUND_TRUTH) == "block_domain"


def test_vpn_src_is_identify_only_not_containment() -> None:
    """ISSUE-365: VPN source stays identifiable; it is not a block_ip requirement."""
    assert VPN_SRC_IP in GROUND_TRUTH["must_identify_indicators"]
    assert VPN_SRC_IP not in GROUND_TRUTH["must_response_targets"]
    assert VPN_SRC_IP not in GROUND_TRUTH["response_containment_tools"]
    assert containment_tool_for_target(VPN_SRC_IP, GROUND_TRUTH) is None
    complete = [
        {"tool_name": "disable_account", "target": ACCOUNT},
        {"tool_name": "isolate_host", "target": HOST_WORKSTATION},
        {"tool_name": "isolate_host", "target": HOST_DB},
        {"tool_name": "block_ip", "target": UPLOAD_IP},
        {"tool_name": "block_domain", "target": UPLOAD_DOMAIN},
    ]
    gaps = missing_response_targets(ground_truth=GROUND_TRUTH, actions=complete)
    assert gaps == []
    assert format_disposition_gap("block_ip", VPN_SRC_IP) not in gaps


def test_containment_tool_explicit_map_survives_entity_reorder() -> None:
    reordered = {
        **GROUND_TRUTH,
        "must_identify_entities": [HOST_WORKSTATION, ACCOUNT, HOST_DB],
    }
    assert containment_tool_for_target(HOST_WORKSTATION, reordered) == "isolate_host"
    assert containment_tool_for_target(ACCOUNT, reordered) == "disable_account"


def test_disposition_gap_target_label_roundtrip() -> None:
    gap = format_disposition_gap("isolate_host", "WKS-DATA-031")
    assert gap == "isolate_host×WKS-DATA-031"
    assert disposition_gap_target_label(gap) == "WKS-DATA-031"
    assert disposition_gap_target_label(HOST_DB) == HOST_DB
    assert "×" in gap
    assert "isolate_hostxWKS-DATA-031" != gap


def test_missing_response_targets_reports_gaps(monkeypatch) -> None:
    monkeypatch.delenv("ADVERSARIAL_STRICT_DISPOSITION_TARGETS", raising=False)
    actions = [{"tool_name": "disable_account", "target": "svc-analytics-47"}]
    gaps = missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)
    assert format_disposition_gap("isolate_host", "WKS-DATA-031") in gaps
    assert format_disposition_gap("block_ip", UPLOAD_IP) in gaps
    assert format_disposition_gap("block_domain", UPLOAD_DOMAIN) in gaps
    assert format_disposition_gap("isolate_host", HOST_DB) in gaps


def test_missing_response_targets_requires_tool_target_pair() -> None:
    actions = [
        {"tool_name": "disable_account", "target": "svc-analytics-47"},
        {"tool_name": "disable_account", "target": "WKS-DATA-031"},
        {"tool_name": "block_ip", "target": UPLOAD_IP},
        {"tool_name": "block_domain", "target": UPLOAD_DOMAIN},
    ]
    gaps = missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)
    assert gaps == [
        format_disposition_gap("isolate_host", "WKS-DATA-031"),
        format_disposition_gap("isolate_host", HOST_DB),
    ]


def test_target_only_action_does_not_clear_isolation_gap() -> None:
    actions = [{"target": "WKS-DATA-031"}]
    gaps = missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)
    assert format_disposition_gap("isolate_host", "WKS-DATA-031") in gaps


def test_missing_response_targets_default_enforces_db_isolation() -> None:
    """ISSUE-328: SRV-DB-STG-02 is no longer gated out of default CI."""
    actions = [
        {"tool_name": "disable_account", "target": "svc-analytics-47"},
        {"tool_name": "isolate_host", "target": "WKS-DATA-031"},
        {"tool_name": "block_ip", "target": UPLOAD_IP},
        {"tool_name": "block_domain", "target": UPLOAD_DOMAIN},
    ]
    enforced = missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)
    all_gaps = missing_response_targets(
        ground_truth=GROUND_TRUTH,
        actions=actions,
        enforce_gated=True,
    )
    db_gap = format_disposition_gap("isolate_host", HOST_DB)
    assert db_gap in enforced
    assert enforced == all_gaps
    assert format_disposition_gap("isolate_host", HOST_BACKUP_NOISE) not in enforced


def test_text_understanding_rejects_prompt_echo_only() -> None:
    triage_ctx = {
        "entities": {
            "accounts": [],
            "hosts": [],
            "ips": [],
            "domains": [],
            "processes": [],
            "files": [],
        },
        "decision_summary": "Pivot involved SRV-DB-STG-02 after VPN login",
    }
    audit = audit_required_signals(
        required=["SRV-DB-STG-02"],
        alert_corpus="Correlation: elevated session and volume signals",
        triage_ctx=triage_ctx,
        narrative_corpus=build_narrative_corpus(
            triage_ctx=triage_ctx,
            evidence_ctx={},
            report_ctx={},
        ),
    )
    assert audit.echo_only_hits == ("SRV-DB-STG-02",)
    assert audit.text_understanding_hits == ()
    assert audit.text_understanding_missing == ("SRV-DB-STG-02",)


def test_text_understanding_alert_only_without_source_refs() -> None:
    audit = audit_required_signals(
        required=["SRV-DB-STG-02"],
        alert_corpus="RDP pivot onto SRV-DB-STG-02 after VPN login",
        triage_ctx={
            "entities": {
                "hosts": [],
                "accounts": [],
                "ips": [],
                "domains": [],
                "processes": [],
                "files": [],
            }
        },
        narrative_corpus="",
    )
    assert audit.text_understanding_hits == ("SRV-DB-STG-02",)
    assert audit.source_projection_hits == ()
    assert audit.echo_only_hits == ()
    assert audit.text_understanding_missing == ()


def test_source_projection_is_not_text_understanding_credit() -> None:
    triage_ctx = {
        "entities": {
            "hosts": [
                {
                    "hostname": "SRV-DB-STG-02",
                    "source_refs": [{"source_kind": "incident", "source_object_id": "88190001"}],
                    "attributes": {"provenance": "source"},
                }
            ],
            "accounts": [],
            "ips": [],
            "domains": [],
            "processes": [],
            "files": [],
        }
    }
    audit = audit_required_signals(
        required=["SRV-DB-STG-02"],
        alert_corpus="Correlation: elevated session and volume signals",
        triage_ctx=triage_ctx,
        narrative_corpus="",
    )
    assert audit.source_projection_hits == ("SRV-DB-STG-02",)
    assert audit.text_understanding_hits == ()
    assert audit.text_understanding_missing == ("SRV-DB-STG-02",)
    assert audit.echo_only_hits == ()


def test_build_alert_corpus_excludes_normalized_hosts() -> None:
    corpus = build_alert_corpus(
        alert_text="Correlation incident",
        event_payload={
            "title": "Correlation incident",
            "description": "Elevated session volume",
            "normalized": {"secondary_host": "SRV-DB-STG-02", "hostname": "WKS-DATA-031"},
        },
    )
    assert "SRV-DB-STG-02" not in corpus
    assert "WKS-DATA-031" not in corpus
    assert "Correlation incident" in corpus
    assert "Elevated session volume" in corpus


def test_llm_copied_source_refs_are_not_source_projection() -> None:
    triage_ctx = {
        "entities": {
            "hosts": [
                {
                    "hostname": "SRV-DB-STG-02",
                    "source_refs": [{"source_kind": "incident", "source_object_id": "88190001"}],
                }
            ],
            "accounts": [],
            "ips": [],
            "domains": [],
            "processes": [],
            "files": [],
        },
        "decision_summary": "Host SRV-DB-STG-02 appeared in the prompt appendix",
    }
    audit = audit_required_signals(
        required=["SRV-DB-STG-02"],
        alert_corpus="Correlation: elevated session and volume signals",
        triage_ctx=triage_ctx,
        narrative_corpus=build_narrative_corpus(
            triage_ctx=triage_ctx,
            evidence_ctx={},
            report_ctx={},
        ),
    )
    assert audit.source_projection_hits == ()
    assert audit.text_understanding_hits == ()
    assert audit.echo_only_hits == ("SRV-DB-STG-02",)


def test_narrative_corpus_ignores_evidence_tool_hostnames() -> None:
    corpus = build_narrative_corpus(
        triage_ctx={"decision_summary": "Account abuse over VPN"},
        evidence_ctx={
            "entities": {"hosts": [{"hostname": "SRV-DB-STG-02"}]},
            "tool_results": [{"hostname": "SRV-DB-STG-02"}],
        },
        report_ctx={"sections": [{"content": "Executive summary without the staging host"}]},
    )
    assert "srv-db-stg-02" not in corpus
    assert "account abuse over vpn" in corpus


def test_missing_db_gap_cleared_when_plan_isolates_host() -> None:
    with_db = [
        {"tool_name": "disable_account", "target": "svc-analytics-47"},
        {"tool_name": "isolate_host", "target": "WKS-DATA-031"},
        {"tool_name": "block_ip", "target": UPLOAD_IP},
        {"tool_name": "block_domain", "target": UPLOAD_DOMAIN},
        {"tool_name": "isolate_host", "target": HOST_DB},
    ]
    without_db = with_db[:-1]
    assert missing_response_targets(ground_truth=GROUND_TRUTH, actions=with_db) == []
    assert format_disposition_gap("isolate_host", HOST_DB) not in missing_response_targets(
        ground_truth=GROUND_TRUTH, actions=with_db
    )
    assert format_disposition_gap("isolate_host", HOST_DB) in missing_response_targets(
        ground_truth=GROUND_TRUTH, actions=without_db
    )
    all_with = missing_response_targets(
        ground_truth=GROUND_TRUTH, actions=with_db, enforce_gated=True
    )
    all_without = missing_response_targets(
        ground_truth=GROUND_TRUTH, actions=without_db, enforce_gated=True
    )
    assert format_disposition_gap("isolate_host", HOST_DB) not in all_with
    assert format_disposition_gap("isolate_host", HOST_DB) in all_without


def test_opaque_alert_quality_rejects_source_projection_credit() -> None:
    triage_ctx = {
        "entities": {
            "hosts": [
                {
                    "hostname": "SRV-DB-STG-02",
                    "attributes": {"provenance": "source"},
                }
            ],
            "accounts": [],
            "ips": [],
            "domains": [],
            "processes": [],
            "files": [],
        }
    }
    entity_audit = audit_required_signals(
        required=["SRV-DB-STG-02"],
        alert_corpus="Correlation: elevated session and volume signals",
        triage_ctx=triage_ctx,
        narrative_corpus="",
    )
    indicator_audit = audit_required_signals(
        required=["198.51.100.44"],
        alert_corpus="Correlation: elevated session and volume signals",
        triage_ctx={"entities": {"ips": []}},
        narrative_corpus="",
    )
    assert_opaque_alert_quality(
        alert_corpus="Correlation: elevated session and volume signals",
        entity_audit=entity_audit,
        indicator_audit=indicator_audit,
        opaque_tokens=opaque_scorecard_tokens(GROUND_TRUTH),
    )


def test_opaque_alert_quality_fails_when_host_leaks_into_corpus() -> None:
    entity_audit = audit_required_signals(
        required=["SRV-DB-STG-02"],
        alert_corpus="RDP pivot onto SRV-DB-STG-02 after VPN login",
        triage_ctx={"entities": {"hosts": []}},
        narrative_corpus="",
    )
    indicator_audit = audit_required_signals(
        required=[],
        alert_corpus="RDP pivot onto SRV-DB-STG-02 after VPN login",
        triage_ctx={"entities": {"ips": []}},
        narrative_corpus="",
    )
    with pytest.raises(AssertionError, match="opaque alert corpus"):
        assert_opaque_alert_quality(
            alert_corpus="RDP pivot onto SRV-DB-STG-02 after VPN login",
            entity_audit=entity_audit,
            indicator_audit=indicator_audit,
            opaque_tokens=("SRV-DB-STG-02",),
        )


def test_collect_entity_tokens_removed_from_scorecard() -> None:
    import tests.adversarial.audit_report as audit_report

    assert not hasattr(audit_report, "collect_entity_tokens")


def test_block_ip_reason_destination_mislabel_detected() -> None:
    actions = [
        {
            "tool_name": "block_ip",
            "target": "198.51.100.44",
            "reason": "Block malicious destination address",
            "parameters": {"normalized_field": "src_ip"},
        }
    ]
    assert block_ip_reason_destination_mislabels(actions)


def test_block_ip_reason_destination_mislabel_allows_source_wording() -> None:
    actions = [
        {
            "tool_name": "block_ip",
            "target": "198.51.100.44",
            "reason": "Block unusual VPN source address",
            "parameters": {"normalized_field": "src_ip"},
        }
    ]
    assert block_ip_reason_destination_mislabels(actions) == []


def test_block_ip_destination_wording_on_dst_ip_is_not_a_gap() -> None:
    actions = [
        {
            "tool_name": "block_ip",
            "target": "198.51.100.77",
            "reason": "Block malicious destination address",
            "parameters": {"normalized_field": "dst_ip"},
        }
    ]
    assert block_ip_reason_destination_mislabels(actions) == []


def test_block_ip_reason_reads_action_entity_attributes() -> None:
    actions = [
        {
            "tool_name": "block_ip",
            "target": VPN_SRC_IP,
            "reason": "Block malicious destination address",
            "parameters": {},
            "attributes": {"normalized_field": "src_ip"},
        }
    ]
    gaps = block_ip_reason_destination_mislabels(actions)
    assert gaps and gaps[0]["normalized_field"] == "src_ip"


def test_block_ip_reason_reads_triage_ip_normalized_field() -> None:
    actions = [
        {
            "tool_name": "block_ip",
            "target": VPN_SRC_IP,
            "reason": "Block malicious destination address",
            "parameters": {},
        }
    ]
    triage_ctx = {
        "entities": {
            "ips": [
                {
                    "address": VPN_SRC_IP,
                    "attributes": {"normalized_field": "src_ip", "provenance": "source"},
                }
            ]
        }
    }
    gaps = block_ip_reason_destination_mislabels(actions, triage_ctx=triage_ctx)
    assert gaps and gaps[0]["normalized_field"] == "src_ip"


def test_strict_disposition_targets_env(monkeypatch) -> None:
    """Helper still skips names listed in must_response_targets_gated unless env is on."""
    gated_truth = {
        **GROUND_TRUTH,
        "must_response_targets_gated": [HOST_DB],
    }
    actions = [
        {"tool_name": "disable_account", "target": "svc-analytics-47"},
        {"tool_name": "isolate_host", "target": "WKS-DATA-031"},
        {"tool_name": "block_ip", "target": UPLOAD_IP},
        {"tool_name": "block_domain", "target": UPLOAD_DOMAIN},
    ]
    monkeypatch.delenv("ADVERSARIAL_STRICT_DISPOSITION_TARGETS", raising=False)
    assert strict_disposition_targets_enabled() is False
    assert format_disposition_gap("isolate_host", HOST_DB) not in missing_response_targets(
        ground_truth=gated_truth, actions=actions
    )
    monkeypatch.setenv("ADVERSARIAL_STRICT_DISPOSITION_TARGETS", "1")
    assert strict_disposition_targets_enabled() is True
    assert format_disposition_gap("isolate_host", HOST_DB) in missing_response_targets(
        ground_truth=gated_truth, actions=actions
    )


def test_human_verdict_requires_reporting_for_pass() -> None:
    checks = AdversarialAuditChecks(
        ground_truth=GROUND_TRUTH,
        event_type="account_anomaly",
        severity="high",
        risk_score=80,
        final_verdict="confirmed_threat",
        entities_found=list(GROUND_TRUTH["must_identify_entities"]),
        indicators_found=list(GROUND_TRUTH["must_identify_indicators"]),
        report_excerpt="",
        triage_summary="",
        evidence_collection_status="completed",
        status_sequence=["verifying"],
    )
    report = checks.to_dict()
    assert report["verdict_for_human"].startswith("FAIL")


def test_analysis_only_pass_does_not_require_closed() -> None:
    report = _analysis_pass_checks().to_dict()
    assert report["audit_mode"] == "analysis_only"
    assert report["checks"]["reached_reporting"] is True
    assert "closed_reached" not in report["checks"]
    assert report["score"]["total_dimensions"] == 5
    assert report["verdict_for_human"].startswith("PASS")


def test_full_loop_pass_annotates_coverage_and_understanding_gaps() -> None:
    entity_audit = audit_required_signals(
        required=list(GROUND_TRUTH["must_identify_entities"]),
        alert_corpus="Correlation: elevated session and volume signals",
        triage_ctx={"entities": _EMPTY_ENTITY_BUCKETS},
        narrative_corpus="",
    )
    indicator_audit = audit_required_signals(
        required=list(GROUND_TRUTH["must_identify_indicators"]),
        alert_corpus="Correlation: elevated session and volume signals",
        triage_ctx={"entities": _EMPTY_ENTITY_BUCKETS},
        narrative_corpus="",
    )
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_CLOSED_SEQUENCE,
        entities_found=list(entity_audit.text_understanding_hits),
        indicators_found=list(indicator_audit.text_understanding_hits),
        disposition_gaps=(format_disposition_gap("isolate_host", "WKS-DATA-031"),),
        entity_signal_audit=entity_audit,
        indicator_signal_audit=indicator_audit,
    ).to_dict()
    assert report["verdict_for_human"].startswith("PASS")
    assert "coverage GAP: WKS-DATA-031" in report["verdict_for_human"]
    assert "understanding entities 0/3" in report["verdict_for_human"]
    assert report["score"]["passed"] == 7
    assert report["score"]["total_dimensions"] == 7
    assert "disposition_targets_aligned" not in report["checks"]
    assert "text_understanding" not in report["checks"]
    assert report["unscored"]["disposition_coverage_gaps"] == [
        format_disposition_gap("isolate_host", "WKS-DATA-031")
    ]
    assert report["unscored"]["text_understanding"]["entities"]["hits"] == 0
    assert report["unscored"]["output_quality"]["present"] is False
    assert "quality_unscored" not in report


def test_analysis_only_pass_annotates_understanding_without_closed_gate() -> None:
    entity_audit = audit_required_signals(
        required=list(GROUND_TRUTH["must_identify_entities"]),
        alert_corpus="Correlation: elevated session and volume signals",
        triage_ctx={"entities": _EMPTY_ENTITY_BUCKETS},
        narrative_corpus="",
    )
    report = _analysis_pass_checks(
        entities_found=list(entity_audit.text_understanding_hits),
        entity_signal_audit=entity_audit,
    ).to_dict()
    assert report["verdict_for_human"].startswith("PASS")
    assert "understanding entities 0/3" in report["verdict_for_human"]
    assert "closed_reached" not in report["checks"]
    assert report["score"]["total_dimensions"] == 5


def test_analysis_only_missing_plan_discloses_enforced_coverage_gaps() -> None:
    gaps = missing_response_targets(ground_truth=GROUND_TRUTH, actions=[])
    assert format_disposition_gap("isolate_host", "WKS-DATA-031") in gaps
    report = _analysis_pass_checks(disposition_gaps=tuple(gaps)).to_dict()
    assert report["verdict_for_human"].startswith("PASS")
    assert "coverage GAP:" in report["verdict_for_human"]
    assert "WKS-DATA-031" in report["verdict_for_human"]
    assert report["score"]["total_dimensions"] == 5


def test_full_loop_pass_requires_closed() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_REPORTING_ONLY_SEQUENCE,
    ).to_dict()
    assert report["checks"]["closed_reached"] is False
    assert report["checks"]["evidence_collection_ok"] is True
    assert report["score"]["total_dimensions"] == 7
    assert report["score"]["passed"] == 6
    assert report["verdict_for_human"].startswith("FAIL")
    assert "not release-grade" in report["verdict_for_human"]
    assert "PASS" not in report["verdict_for_human"]


def test_full_loop_pass_when_closed_and_analysis_met() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_CLOSED_SEQUENCE,
    ).to_dict()
    assert report["checks"]["closed_reached"] is True
    assert report["checks"]["evidence_collection_ok"] is True
    assert report["score"]["passed"] == report["score"]["total_dimensions"] == 7
    assert report["verdict_for_human"].startswith("PASS")
    assert "CLOSED" in report["verdict_for_human"]


def test_full_loop_fail_when_closed_missing_and_analysis_weak() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        risk_score=1,
        final_verdict="false_positive",
        status_sequence=["new", "investigating", "verifying"],
    ).to_dict()
    assert report["checks"]["closed_reached"] is False
    assert report["checks"]["reached_reporting"] is False
    assert report["verdict_for_human"] == "FAIL — full loop did not reach CLOSED"
    assert "PASS" not in report["verdict_for_human"]


def test_full_loop_fail_verdict_has_no_pass_token() -> None:
    """FAIL strings must not contain PASS (grep / substring false-green)."""
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_REPORTING_ONLY_SEQUENCE,
    ).to_dict()
    verdict = report["verdict_for_human"]
    assert verdict.startswith("FAIL")
    assert "PASS" not in verdict


def test_full_loop_writeback_ok_does_not_override_closed_gate() -> None:
    """Scorecard ignores disposition_writeback_ok; only status_sequence drives CLOSED."""
    # Mimic artifact shape: writeback confirmed while loop never reached CLOSED.
    production_checks = {
        "disposition_writeback_ok": True,
        "terminal_status": "failed",
        "status_sequence_includes_closed": False,
    }
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_REPORTING_ONLY_SEQUENCE,
    ).to_dict()
    assert production_checks["disposition_writeback_ok"] is True
    assert report["checks"]["closed_reached"] is False
    assert report["checks"]["evidence_collection_ok"] is True
    assert report["score"]["passed"] == 6
    assert report["score"]["total_dimensions"] == 7
    assert report["verdict_for_human"].startswith("FAIL")
    assert "PASS" not in report["verdict_for_human"]


def test_full_loop_closed_without_reporting_is_not_pass() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=["new", "investigating", "verifying", "closed"],
    ).to_dict()
    assert report["checks"]["closed_reached"] is True
    assert report["checks"]["reached_reporting"] is False
    assert not report["verdict_for_human"].startswith("PASS")


def test_audit_mode_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="audit_mode"):
        _analysis_pass_checks(audit_mode="release")  # type: ignore[arg-type]


def test_resolve_full_loop_timeout_defaults(monkeypatch) -> None:
    monkeypatch.delenv("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", raising=False)
    monkeypatch.setenv("LLM_MODE", "mock")
    assert resolve_full_loop_timeout_s() == 120.0


def test_resolve_full_loop_timeout_live_default(monkeypatch) -> None:
    monkeypatch.delenv("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", raising=False)
    monkeypatch.setenv("LLM_MODE", "openai_compatible")
    assert resolve_full_loop_timeout_s() == 600.0


def test_resolve_full_loop_timeout_env_override(monkeypatch) -> None:
    monkeypatch.setenv("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", "90")
    assert resolve_full_loop_timeout_s() == 90.0
    monkeypatch.setenv("ADVERSARIAL_FULL_LOOP_TIMEOUT_S", "10")
    assert resolve_full_loop_timeout_s() == 30.0


def test_resolve_scorecard_llm_mode_defaults_to_settings_when_env_unset(
    monkeypatch,
) -> None:
    monkeypatch.delenv("LLM_MODE", raising=False)
    from app.core.config import get_settings

    get_settings.cache_clear()
    expected = str(get_settings().llm_mode or "mock").strip().lower() or "mock"
    assert resolve_scorecard_llm_mode() == expected


def test_resolve_scorecard_llm_mode_explicit_override(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "openai_compatible")
    assert resolve_scorecard_llm_mode(llm_mode="mock") == "mock"


def test_resolve_scorecard_llm_mode_normalizes_case(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "MOCK")
    assert resolve_scorecard_llm_mode() == "mock"
    monkeypatch.setenv("LLM_MODE", "OpenAI_Compatible")
    assert resolve_scorecard_llm_mode() == "openai_compatible"
    assert scorecard_contract_for_llm_mode("OpenAI_Compatible")["kind"] == "live_reasoning"


def test_resolve_scorecard_llm_mode_blank_env_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "  ")
    from app.core.config import get_settings

    get_settings.cache_clear()
    expected = str(get_settings().llm_mode or "mock").strip().lower() or "mock"
    assert resolve_scorecard_llm_mode() == expected


def test_scorecard_header_marks_mock_plumbing_card(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "mock")
    header = build_scorecard_header()
    assert header["llm_mode"] == "mock"
    assert header["certification_card"] == "mock_plumbing"
    assert "not Live reasoning" in header["summary"]
    assert "containment-coverage" in header["summary"]
    report = _analysis_pass_checks().to_dict()
    assert report["scorecard_header"] == header
    assert report["verdict_for_human"].startswith("PASS")


def test_scorecard_header_marks_live_reasoning_card(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "openai_compatible")
    header = build_scorecard_header()
    assert header["llm_mode"] == "openai_compatible"
    assert header["certification_card"] == "live_reasoning"
    assert "golden isolate is not glm capability" in header["summary"]
    report = _analysis_pass_checks().to_dict()
    assert report["scorecard_header"] == header
    assert report["verdict_for_human"].startswith("PASS")


def test_scorecard_header_marks_custom_provider_card() -> None:
    contract = scorecard_contract_for_llm_mode("anthropic")
    assert contract["kind"] == "custom"
    header = build_scorecard_header(llm_mode="anthropic")
    assert header["certification_card"] == "custom"
    assert "anthropic" in header["summary"]


def test_resolve_observed_severity_prefers_risk_over_triage() -> None:
    from tests.adversarial.audit_report import resolve_observed_severity

    outward, triage = resolve_observed_severity(
        risk_ctx={"severity": "high"},
        event_severity="high",
        triage_ctx={"severity": "medium"},
    )
    assert outward == "high"
    assert triage == "medium"


def test_resolve_observed_severity_ignores_higher_triage_when_risk_missing() -> None:
    from tests.adversarial.audit_report import resolve_observed_severity

    outward, triage = resolve_observed_severity(
        risk_ctx=None,
        event_severity="medium",
        triage_ctx={"severity": "high"},
    )
    assert outward == "medium"
    assert triage == "high"


def test_evidence_collection_ok_true_for_completed_without_gaps() -> None:
    ok, detail = evaluate_evidence_collection_ok(collection_status="completed", gaps=[])
    assert ok is True
    assert detail["failure_reasons"] == []


def test_evidence_collection_ok_fails_on_collection_failed() -> None:
    ok, detail = evaluate_evidence_collection_ok(collection_status="failed", gaps=[])
    assert ok is False
    assert detail["failure_reasons"] == ["collection_status_failed"]


def test_evidence_collection_ok_fails_on_mandatory_dns_invalid_entity() -> None:
    gaps = [
        {
            "missing_source": "dns",
            "reason": "invalid_entity",
            "detail": {
                "tool_name": "query_dns",
                "description": "domain rejected by validator",
            },
        }
    ]
    ok, detail = evaluate_evidence_collection_ok(collection_status="degraded", gaps=gaps)
    assert ok is False
    assert detail["failure_reasons"] == ["mandatory_query_dns_skipped"]
    assert detail["mandatory_query_dns_skips"]


def test_evidence_collection_ok_exempts_ip_only_dns_skip() -> None:
    gaps = [
        {
            "missing_source": "dns",
            "reason": "source_skipped",
            "detail": {
                "tool_name": "query_dns",
                "description": skipped_entity_description("query_dns"),
            },
        }
    ]
    ok, detail = evaluate_evidence_collection_ok(collection_status="degraded", gaps=gaps)
    assert ok is True
    assert detail["expected_query_dns_skips"]
    assert detail["mandatory_query_dns_skips"] == []


def test_full_loop_closed_with_failed_collection_is_not_pass() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_CLOSED_SEQUENCE,
        evidence_collection_status="failed",
    ).to_dict()
    assert report["checks"]["closed_reached"] is True
    assert report["checks"]["evidence_collection_ok"] is False
    assert report["score"]["passed"] == 6
    assert report["score"]["total_dimensions"] == 7
    assert report["verdict_for_human"].startswith("FAIL")
    assert "evidence collection incomplete" in report["verdict_for_human"]
    assert "PASS" not in report["verdict_for_human"]


def test_analysis_only_annotates_incomplete_collection() -> None:
    report = _analysis_pass_checks(
        evidence_collection_status="failed",
    ).to_dict()
    assert report["checks"]["evidence_collection_ok"] is False
    assert report["score"]["total_dimensions"] == 5
    assert report["verdict_for_human"].startswith("PARTIAL")
    assert "evidence_collection_ok" in report["verdict_for_human"]
    assert not report["verdict_for_human"].startswith("PASS")


def test_evidence_collection_ok_fails_on_triage_degraded_dns_skip() -> None:
    gaps = [
        {
            "missing_source": "dns",
            "reason": "triage_degraded",
            "detail": {
                "tool_name": "query_dns",
                "description": "triage degraded; skipped query_dns",
            },
        }
    ]
    assert "triage_degraded" in SKIP_GAP_REASONS
    ok, detail = evaluate_evidence_collection_ok(collection_status="degraded", gaps=gaps)
    assert ok is False
    assert detail["failure_reasons"] == ["mandatory_query_dns_skipped"]
    assert detail["mandatory_query_dns_skips"]


def test_full_loop_closed_with_mandatory_dns_skip_is_not_pass() -> None:
    """FQDN was present but query_dns source_skipped with a non-generic description."""
    gaps = [
        {
            "missing_source": "dns",
            "reason": "source_skipped",
            "detail": {
                "tool_name": "query_dns",
                "description": "query_dns skipped after valid FQDN was present",
            },
        }
    ]
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_CLOSED_SEQUENCE,
        evidence_collection_status="degraded",
        evidence_gaps=gaps,
    ).to_dict()
    assert report["checks"]["closed_reached"] is True
    assert report["checks"]["evidence_collection_ok"] is False
    assert report["score"]["passed"] == 6
    assert report["score"]["total_dimensions"] == 7
    assert report["verdict_for_human"].startswith("FAIL")
    assert "evidence collection incomplete" in report["verdict_for_human"]
    assert "PASS" not in report["verdict_for_human"]


def test_output_quality_unscored_bucket_is_informative_only() -> None:
    report = _analysis_pass_checks().to_dict()
    assert "unscored" in report
    assert report["unscored"]["output_quality"]["present"] is False
    assert report["unscored"]["output_quality"]["blocking_profile"] is False
    assert report["score"]["total_dimensions"] == 5


def test_output_quality_unscored_surfaces_agent_scores_without_scoring() -> None:
    from tests.adversarial.audit_report import OUTPUT_QUALITY_PASS_THRESHOLD

    quality_scores = [
        {
            "agent_name": "triage",
            "score": 0.82,
            "verdict": "pass",
            "metrics": {"completeness": 0.9},
            "reasons": ["completeness: 0.90 — good"],
            "evaluated_by": "rule",
        },
        {
            "agent_name": "report",
            "score": 0.0,
            "verdict": "fail",
            "metrics": {"completeness": 0.0},
            "reasons": ["eval_error_defaulted: boom"],
            "evaluated_by": "rule",
        },
    ]
    report = _analysis_pass_checks(quality_scores=quality_scores).to_dict()
    bucket = report["unscored"]["output_quality"]
    assert bucket["present"] is True
    assert bucket["pass_threshold"] == OUTPUT_QUALITY_PASS_THRESHOLD
    assert bucket["agents"]["triage"]["score"] == 0.82
    assert bucket["summary"]["agents_passing"] == 1
    assert bucket["summary"]["eval_error_agents"] == ["report"]
    assert bucket["agents"]["report"]["eval_error"] is True
    assert bucket["summary"]["agents_at_or_above_threshold"] == 1
    assert report["score"]["total_dimensions"] == 5


def test_build_output_quality_unscored_eval_error_not_passing() -> None:
    from tests.adversarial.audit_report import build_output_quality_unscored

    bucket = build_output_quality_unscored(
        [
            {
                "agent_name": "triage",
                "score": 0.9,
                "verdict": "pass",
                "reasons": ["eval_error_defaulted: boom"],
                "evaluated_by": "rule",
            }
        ]
    )
    assert bucket["agents"]["triage"]["eval_error"] is True
    assert bucket["summary"]["agents_passing"] == 0
    assert bucket["summary"]["agents_at_or_above_threshold"] == 0
    assert bucket["summary"]["eval_error_agents"] == ["triage"]


def test_full_loop_quality_does_not_change_scored_dims() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_CLOSED_SEQUENCE,
        quality_scores=[
            {
                "agent_name": "triage",
                "score": 0.1,
                "verdict": "fail",
                "reasons": ["specificity: 0.00 — low"],
                "evaluated_by": "rule",
            }
        ],
    ).to_dict()
    assert report["unscored"]["output_quality"]["present"] is True
    assert report["score"]["total_dimensions"] == 7
    assert report["score"]["passed"] == 7
    assert report["verdict_for_human"].startswith("PASS")
    assert "output_quality" not in report["checks"]


def test_build_output_quality_unscored_blocking_profile_flag() -> None:
    from tests.adversarial.audit_report import build_output_quality_unscored

    bucket = build_output_quality_unscored([], output_quality_blocking=True)
    assert bucket["blocking_profile"] is True
    assert bucket["present"] is False


def test_scorecard_annotates_non_complete_report_quality() -> None:
    report = _analysis_pass_checks(report_quality="degraded_template").to_dict()
    assert report["observed"]["report_quality"] == "degraded_template"
    assert report["score"]["report_quality_complete"] is False
    assert report["score"]["report_quality_note"] is not None
    assert "does not block CLOSED" in report["score"]["report_quality_note"]
    assert report["verdict_for_human"].startswith("PASS")


def test_scorecard_complete_report_quality_has_no_note() -> None:
    report = _analysis_pass_checks(report_quality="complete").to_dict()
    assert report["score"]["report_quality_complete"] is True
    assert report["score"]["report_quality_note"] is None


def test_writeback_certification_label_mock_simulated_not_readback_verified() -> None:
    label = _writeback_certification_label(
        confirmation_evidence="readback_verified",
        simulated=True,
        disposition_is_mock=True,
    )
    assert label == "mock_simulated"


def test_writeback_certification_label_mock_adapter_acknowledged() -> None:
    label = _writeback_certification_label(
        confirmation_evidence="adapter_acknowledged",
        simulated=True,
        disposition_is_mock=True,
    )
    assert label == "adapter_acknowledged"


def test_writeback_certification_label_live_readback_verified() -> None:
    label = _writeback_certification_label(
        confirmation_evidence="readback_verified",
        simulated=False,
        disposition_is_mock=False,
    )
    assert label == "readback_verified"


def test_full_loop_human_verdict_annotates_mock_writeback() -> None:
    cert = build_writeback_certification(
        confirmation_evidence="readback_verified",
        simulated=True,
        disposition_is_mock=True,
        receipt_status="confirmed",
    )
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_CLOSED_SEQUENCE,
        writeback_certification=cert,
    ).to_dict()
    verdict = report["verdict_for_human"]
    assert verdict.startswith("PASS")
    assert "writeback=simulated" in verdict
    assert "certification=mock_simulated" in verdict
    assert "readback_verified" not in verdict


def test_build_writeback_certification_exports_raw_receipt_fields() -> None:
    cert = build_writeback_certification(
        confirmation_evidence="adapter_acknowledged",
        simulated=True,
        disposition_is_mock=True,
        receipt_status="confirmed",
        mock_cert_strict=False,
    )
    assert cert["confirmation_evidence"] == "adapter_acknowledged"
    assert cert["simulated"] is True
    assert cert["certification_label"] == "adapter_acknowledged"
    assert cert["tier_ok"] is True


def test_build_writeback_certification_mock_cert_strict_requires_tier() -> None:
    weak = build_writeback_certification(
        confirmation_evidence="adapter_acknowledged",
        simulated=True,
        disposition_is_mock=True,
        receipt_status="confirmed",
        mock_cert_strict=True,
    )
    assert weak["tier_ok"] is False
    strong = build_writeback_certification(
        confirmation_evidence="readback_verified",
        simulated=True,
        disposition_is_mock=True,
        receipt_status="confirmed",
        mock_cert_strict=True,
    )
    assert strong["tier_ok"] is True


def test_writeback_tier_ok_live_rejects_simulated_none_or_true() -> None:
    assert (
        writeback_tier_ok(
            confirmation_evidence="readback_verified",
            simulated=True,
            disposition_is_mock=False,
            mock_cert_strict=False,
        )
        is False
    )
    assert (
        writeback_tier_ok(
            confirmation_evidence="readback_verified",
            simulated=None,
            disposition_is_mock=False,
            mock_cert_strict=False,
        )
        is False
    )
    assert (
        writeback_tier_ok(
            confirmation_evidence="readback_verified",
            simulated=False,
            disposition_is_mock=False,
            mock_cert_strict=False,
        )
        is True
    )


def test_evaluate_writeback_confirmed_mock_default_accepts_weak_receipt() -> None:
    assert (
        evaluate_writeback_confirmed(
            terminal_delivered=True,
            confirmed_receipt=True,
            confirmation_evidence="adapter_acknowledged",
            simulated=True,
            disposition_is_mock=True,
            mock_cert_strict=False,
        )
        is True
    )


def test_evaluate_writeback_confirmed_live_rejects_simulated_and_weak_ack() -> None:
    assert (
        evaluate_writeback_confirmed(
            terminal_delivered=True,
            confirmed_receipt=True,
            confirmation_evidence="readback_verified",
            simulated=True,
            disposition_is_mock=False,
            mock_cert_strict=False,
        )
        is False
    )
    assert (
        evaluate_writeback_confirmed(
            terminal_delivered=True,
            confirmed_receipt=True,
            confirmation_evidence="adapter_acknowledged",
            simulated=False,
            disposition_is_mock=False,
            mock_cert_strict=False,
        )
        is False
    )
    assert (
        evaluate_writeback_confirmed(
            terminal_delivered=True,
            confirmed_receipt=True,
            confirmation_evidence="readback_verified",
            simulated=False,
            disposition_is_mock=False,
            mock_cert_strict=False,
        )
        is True
    )


def test_evaluate_writeback_confirmed_requires_delivered_confirmed() -> None:
    assert (
        evaluate_writeback_confirmed(
            terminal_delivered=False,
            confirmed_receipt=True,
            confirmation_evidence="readback_verified",
            simulated=False,
            disposition_is_mock=False,
            mock_cert_strict=False,
        )
        is False
    )


def test_resolve_disposition_is_mock_344_allowlist(monkeypatch) -> None:
    from app.core.config import get_settings

    def _set(*, mode: str, adapter: str = "mock") -> None:
        monkeypatch.setenv("DISPOSITION_MODE", mode)
        monkeypatch.setenv("DISPOSITION_ADAPTER_KIND", adapter)
        get_settings.cache_clear()

    try:
        _set(mode="mock_xdr")
        assert resolve_disposition_is_mock() is True
        _set(mode=" MOCK_XDR ")
        assert resolve_disposition_is_mock() is True
        _set(mode="not_mock")
        assert resolve_disposition_is_mock() is False
        _set(mode="mockish")
        assert resolve_disposition_is_mock() is False
        # ``live`` is intentionally rejected during Settings construction;
        # exercise the registered non-Mock mode instead of bypassing that gate.
        _set(mode="live_xdr", adapter="sangfor_xdr")
        assert resolve_disposition_is_mock() is False
    finally:
        get_settings.cache_clear()
