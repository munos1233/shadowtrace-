"""Unit tests for adversarial helper contracts (ISSUE-203)."""

from __future__ import annotations

import pytest

from tests.adversarial.audit_report import (
    AdversarialAuditChecks,
    resolve_scorecard_llm_mode,
    scorecard_contract_for_llm_mode,
)
from tests.adversarial.full_loop_runner import resolve_full_loop_timeout_s
from tests.adversarial.helpers import (
    assert_opaque_alert_quality,
    audit_required_signals,
    block_ip_reason_destination_mislabels,
    build_alert_corpus,
    build_narrative_corpus,
    missing_response_targets,
    opaque_scorecard_tokens,
    response_plan_targets,
    strict_disposition_targets_enabled,
)
from tests.adversarial.scenario_credential_db_staging_exfil import GROUND_TRUTH, HOST_DB, VPN_SRC_IP

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


def test_missing_response_targets_reports_gaps(monkeypatch) -> None:
    monkeypatch.delenv("ADVERSARIAL_STRICT_DISPOSITION_TARGETS", raising=False)
    actions = [{"tool_name": "disable_account", "target": "svc-analytics-47"}]
    gaps = missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)
    assert "WKS-DATA-031" in gaps
    assert "198.51.100.44" in gaps
    assert HOST_DB not in gaps


def test_missing_response_targets_all_includes_gated_db() -> None:
    actions = [
        {"tool_name": "disable_account", "target": "svc-analytics-47"},
        {"tool_name": "isolate_host", "target": "WKS-DATA-031"},
        {"tool_name": "block_ip", "target": "198.51.100.44"},
    ]
    enforced = missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)
    all_gaps = missing_response_targets(
        ground_truth=GROUND_TRUTH,
        actions=actions,
        enforce_gated=True,
    )
    assert enforced == []
    assert HOST_DB in all_gaps


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


def test_missing_db_gap_recorded_but_not_required_when_plan_includes_host() -> None:
    with_db = [
        {"tool_name": "disable_account", "target": "svc-analytics-47"},
        {"tool_name": "isolate_host", "target": "WKS-DATA-031"},
        {"tool_name": "block_ip", "target": "198.51.100.44"},
        {"tool_name": "isolate_host", "target": HOST_DB},
    ]
    without_db = with_db[:-1]
    assert missing_response_targets(ground_truth=GROUND_TRUTH, actions=with_db) == []
    assert HOST_DB not in missing_response_targets(ground_truth=GROUND_TRUTH, actions=with_db)
    all_with = missing_response_targets(
        ground_truth=GROUND_TRUTH, actions=with_db, enforce_gated=True
    )
    all_without = missing_response_targets(
        ground_truth=GROUND_TRUTH, actions=without_db, enforce_gated=True
    )
    assert HOST_DB not in all_with
    assert HOST_DB in all_without


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
    actions = [
        {"tool_name": "disable_account", "target": "svc-analytics-47"},
        {"tool_name": "isolate_host", "target": "WKS-DATA-031"},
        {"tool_name": "block_ip", "target": "198.51.100.44"},
    ]
    monkeypatch.delenv("ADVERSARIAL_STRICT_DISPOSITION_TARGETS", raising=False)
    assert strict_disposition_targets_enabled() is False
    assert HOST_DB not in missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)
    monkeypatch.setenv("ADVERSARIAL_STRICT_DISPOSITION_TARGETS", "1")
    assert strict_disposition_targets_enabled() is True
    assert HOST_DB in missing_response_targets(ground_truth=GROUND_TRUTH, actions=actions)


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


def test_full_loop_pass_requires_closed() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_REPORTING_ONLY_SEQUENCE,
    ).to_dict()
    assert report["checks"]["closed_reached"] is False
    assert report["score"]["total_dimensions"] == 6
    assert report["score"]["passed"] == 5
    assert report["verdict_for_human"].startswith("FAIL")
    assert "not release-grade" in report["verdict_for_human"]
    assert "PASS" not in report["verdict_for_human"]


def test_full_loop_pass_when_closed_and_analysis_met() -> None:
    report = _analysis_pass_checks(
        audit_mode="full_loop",
        status_sequence=_CLOSED_SEQUENCE,
    ).to_dict()
    assert report["checks"]["closed_reached"] is True
    assert report["score"]["passed"] == report["score"]["total_dimensions"] == 6
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
    assert report["score"]["passed"] == 5
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


def test_resolve_scorecard_llm_mode_defaults_to_mock(monkeypatch) -> None:
    monkeypatch.delenv("LLM_MODE", raising=False)
    assert resolve_scorecard_llm_mode() == "mock"


def test_resolve_scorecard_llm_mode_explicit_override(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "openai_compatible")
    assert resolve_scorecard_llm_mode(llm_mode="mock") == "mock"


def test_scorecard_contract_mock_plumbing() -> None:
    contract = scorecard_contract_for_llm_mode("mock")
    assert contract["kind"] == "mock_plumbing"
    assert "scripted golden" in contract["interpretation"]


def test_scorecard_contract_live_reasoning() -> None:
    contract = scorecard_contract_for_llm_mode("openai_compatible")
    assert contract["kind"] == "live_reasoning"
    assert "Non-deterministic" in contract["interpretation"]


def test_audit_scorecard_header_includes_llm_mode(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "mock")
    report = _analysis_pass_checks().to_dict()
    assert report["llm_mode"] == "mock"
    assert report["scorecard_contract"]["kind"] == "mock_plumbing"


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
