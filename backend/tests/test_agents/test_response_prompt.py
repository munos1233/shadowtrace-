"""Response prompt packing tests (ISSUE-326 / #957)."""

from __future__ import annotations

import json

from app.agents.prompts.response_prompt import build_response_plan_messages
from app.agents.triage_risk_consistency import TRIAGE_RISK_INCONSISTENCY_FLAG
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.enums import EventType, EvidenceSource, FinalVerdict, Severity
from app.models.evidence import Evidence


def _risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=72,
        severity=Severity.HIGH,
        confidence=0.8,
        risk_factors=[],
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def test_response_user_payload_includes_decision_summary_when_reasoning_empty() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="",
        decision_summary="Coordinated data exfiltration to external staging host.",
    )
    evidence = EvidenceOutput(
        evidence_list=[
            Evidence(
                evidence_id="ev-1",
                event_id="evt-test",
                source=EvidenceSource.NETWORK_FLOW,
                evidence_type="flow",
                description="Large HTTPS upload to 203.0.113.88",
                confidence=0.92,
            )
        ],
        collection_status=CollectionStatus.COMPLETED,
        overall_confidence=0.9,
        success_sources=["network_flow"],
        failed_sources=["endpoint_telemetry"],
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=evidence,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload["decision_summary"] == "Coordinated data exfiltration to external staging host."
    assert payload["triage_reasoning"] == ""
    assert payload["evidence"]["success_sources"] == ["network_flow"]
    assert payload["evidence"]["failed_sources"] == ["endpoint_telemetry"]
    sample = payload["evidence"]["sample"][0]
    assert sample["description"] == "Large HTTPS upload to 203.0.113.88"
    assert sample["source"] == EvidenceSource.NETWORK_FLOW.value
    assert sample["evidence_type"] == "flow"
    assert sample["confidence"] == 0.92


def test_response_decision_summary_truncated_to_512_chars() -> None:
    long_summary = "x" * 600
    triage = TriageResult.model_construct(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="",
        decision_summary=long_summary,
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=None,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert len(payload["decision_summary"]) == 512
    assert payload["decision_summary"] == long_summary[:512]
    assert payload["evidence"] == {}


def test_response_empty_decision_summary_and_reasoning() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="",
        decision_summary="",
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=None,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload["decision_summary"] == ""
    assert payload["triage_reasoning"] == ""
    assert payload["evidence"] == {}


def test_response_empty_evidence_output_still_has_source_keys() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="",
        decision_summary="kept",
    )
    evidence = EvidenceOutput(
        evidence_list=[],
        collection_status=CollectionStatus.PARTIAL_DONE,
        overall_confidence=0.1,
        success_sources=[],
        failed_sources=["endpoint_telemetry"],
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=evidence,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload["evidence"] != {}
    assert payload["evidence"]["success_sources"] == []
    assert payload["evidence"]["failed_sources"] == ["endpoint_telemetry"]
    assert payload["evidence"]["sample"] == []


def test_response_triage_reasoning_truncated_to_500_chars() -> None:
    long_reasoning = "z" * 600
    triage = TriageResult.model_construct(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning=long_reasoning,
        decision_summary="brief",
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=None,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload["decision_summary"] == "brief"
    assert len(payload["triage_reasoning"]) == 500
    assert payload["triage_reasoning"] == long_reasoning[:500]


def test_response_reasoning_none_coerced_to_empty_string() -> None:
    triage = TriageResult.model_construct(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning=None,
        decision_summary="kept",
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=None,
        available_tools=["create_ticket"],
        entities_summary={},
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload["decision_summary"] == "kept"
    assert payload["triage_reasoning"] == ""


def test_response_system_prompt_block_ip_dest_only_policy() -> None:
    messages = build_response_plan_messages(
        triage_result=TriageResult(
            event_type=EventType.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            need_investigation=True,
            reasoning="",
            decision_summary="exfil",
        ),
        risk_assessment=_risk(),
        evidence_output=None,
        available_tools=["block_ip", "disable_account"],
        entities_summary={},
    )
    system = messages[0].content.lower()
    assert "block_ip" in system
    assert "dst_ip" in system
    assert "src_ip" in system
    assert "explicit_source_block" in system
    assert "disable_account" in system
    assert "analyst/playbook only" in system
    assert "**destination**" not in messages[0].content


def test_response_and_risk_share_prompt_blocks() -> None:
    from pathlib import Path

    from app.agents.prompts import response_prompt, risk_prompt

    shared = "from app.agents.prompts.prompt_blocks import"
    response_source = Path(response_prompt.__file__).read_text(encoding="utf-8")
    risk_source = Path(risk_prompt.__file__).read_text(encoding="utf-8")
    assert shared in response_source
    assert shared in risk_source
    assert "from app.agents.prompts.risk_prompt" not in response_source


def test_response_prompt_confirmed_threat_requires_entityset_host_isolation() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="",
        decision_summary="Confirmed staging DB exfiltration.",
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=None,
        available_tools=["isolate_host", "create_ticket"],
        entities_summary={"hosts": [{"hostname": "SRV-DB-STG-02"}]},
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )
    system = messages[0].content
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert "entities.hosts" in system
    assert "isolate_host" in system
    assert "must not claim a host remains online" in system
    assert "not asset inventory or decoys" in system
    assert payload["final_verdict"] == FinalVerdict.CONFIRMED_THREAT.value


def test_response_prompt_non_confirmed_threat_omits_entityset_isolation_mandate() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="",
        decision_summary="Needs more evidence.",
    )
    for verdict in (None, FinalVerdict.NONE, FinalVerdict.FALSE_POSITIVE):
        messages = build_response_plan_messages(
            triage_result=triage,
            risk_assessment=_risk(),
            evidence_output=None,
            available_tools=["isolate_host", "create_ticket"],
            entities_summary={"hosts": [{"hostname": "SRV-DB-STG-02"}]},
            final_verdict=verdict,
        )
        system = messages[0].content
        payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
        assert "plan isolate_host for every host listed in entities.hosts" not in system
        expected = None if verdict is None else verdict.value
        assert payload["final_verdict"] == expected


def test_response_system_prompt_follows_risk_severity_for_containment() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        need_investigation=True,
        reasoning="",
        decision_summary="Data exfiltration pattern; alert title lacks external IP.",
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=RiskAssessment(
            risk_score=75,
            severity=Severity.HIGH,
            confidence=0.8,
            risk_factors=[],
            scoring_mode=ScoringMode.RULE_ONLY,
        ),
        evidence_output=None,
        available_tools=["isolate_host", "block_ip"],
        entities_summary={"hosts": [{"hostname": "wks-01"}]},
    )
    system = messages[0].content
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert "When risk_severity is high or risk_score >= 65" in system
    assert (
        "plan containment for EntitySet hosts/accounts even if triage severity is medium" in system
    )
    assert payload["severity"] == Severity.MEDIUM.value
    assert payload["risk_severity"] == Severity.HIGH.value
    assert payload["risk_score"] == 75


def test_response_prompt_issue360_live_path_stacks_with_357_and_omits_inconsistency_flag() -> None:
    """DATA_EXFIL MEDIUM + risk 75 + confirmed_threat: 360+357 stack, no 330 weak-triage flag."""
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        need_investigation=True,
        reasoning="",
        decision_summary="Data exfiltration pattern; alert title lacks external IP.",
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=RiskAssessment(
            risk_score=75,
            severity=Severity.HIGH,
            confidence=0.8,
            risk_factors=[],
            scoring_mode=ScoringMode.RULE_ONLY,
        ),
        evidence_output=None,
        available_tools=["isolate_host", "block_ip"],
        entities_summary={"hosts": [{"hostname": "SRV-DB-STG-02"}]},
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )
    system = messages[0].content
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert "When risk_severity is high or risk_score >= 65" in system
    assert (
        "plan containment for EntitySet hosts/accounts even if triage severity is medium" in system
    )
    assert "plan isolate_host for every host listed in entities.hosts" in system
    assert "Coverage contract (ISSUE-328, not domain)" in system
    assert "for each EntitySet account propose disable_account" in system
    assert "Domain containment (not ISSUE-328)" in system
    assert (
        "for each EntitySet domain used as an exfil or C2 destination propose block_domain"
        in system
    )
    assert "block_ip policy (ISSUE-361)" in system
    assert "dst_ip" in system
    assert "explicit_source_block" in system
    assert "do not stack disable_account with force_logout" in system
    assert "reset_password" in system
    assert "unless L4 revoke is explicitly required" not in system
    assert payload["severity"] == Severity.MEDIUM.value
    assert payload["risk_severity"] == Severity.HIGH.value
    assert payload["risk_score"] == 75
    assert payload["final_verdict"] == FinalVerdict.CONFIRMED_THREAT.value
    assert TRIAGE_RISK_INCONSISTENCY_FLAG not in payload


def test_response_user_payload_includes_triage_risk_inconsistency_flag() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.MEDIUM,
        need_investigation=True,
        decision_summary="No clear threat pattern detected.",
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=RiskAssessment(
            risk_score=80,
            severity=Severity.HIGH,
            confidence=0.8,
            risk_factors=[],
            scoring_mode=ScoringMode.RULE_ONLY,
        ),
        evidence_output=None,
        available_tools=["create_ticket"],
        entities_summary={},
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert payload[TRIAGE_RISK_INCONSISTENCY_FLAG] is True


def test_response_user_payload_omits_triage_risk_inconsistency_when_consistent() -> None:
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        decision_summary="Confirmed data exfiltration to external staging host.",
    )
    messages = build_response_plan_messages(
        triage_result=triage,
        risk_assessment=_risk(),
        evidence_output=None,
        available_tools=["create_ticket"],
        entities_summary={},
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
    )
    payload = json.loads(messages[1].content.split("Context:\n", 1)[1])
    assert TRIAGE_RISK_INCONSISTENCY_FLAG not in payload
