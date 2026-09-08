"""ISSUE-254: bounded event_context_snapshot evidence/storyline projection."""

from __future__ import annotations

import orjson
import pytest

from app.models.agent_io import (
    AttackStoryline,
    CollectionStatus,
    EvidenceOutput,
    StorylineGeneratedBy,
    StorylineGroundingStatus,
)
from app.models.enums import EvidenceSource, ExecutionSubstate
from app.models.evidence import EvidenceGap
from app.services.event_context_snapshot_projection import (
    SNAPSHOT_SUMMARY_KEYS,
    build_evidence_snapshot_summary,
    build_storyline_snapshot_summary,
    merge_evidence_summary_into_snapshot,
    merge_report_generated_into_snapshot,
    merge_report_quality_into_snapshot,
    merge_storyline_summary_into_snapshot,
    project_snapshot_for_api,
)


def test_empty_evidence_summary_exposes_collection_status_and_gaps() -> None:
    output = EvidenceOutput(
        evidence_list=[],
        gaps=[
            EvidenceGap(
                event_id="evt-254",
                missing_source=EvidenceSource.ENDPOINT,
                reason="timeout",
            ),
            EvidenceGap(
                event_id="evt-254",
                missing_source=EvidenceSource.NETWORK_FLOW,
                reason="connector_unavailable",
            ),
        ],
        failed_sources=["endpoint", "network_flow"],
        overall_confidence=0.0,
        collection_status=CollectionStatus.FAILED,
    )
    summary = build_evidence_snapshot_summary(output)
    assert summary["evidence_count"] == 0
    assert summary["collection_status"] == CollectionStatus.FAILED.value
    assert summary["gap_count"] == 2
    assert summary["top_gaps"][0]["missing_source"] == EvidenceSource.ENDPOINT.value
    assert "timeout" in summary["top_gaps"][0]["reason"]


def test_merge_evidence_summary_preserves_risk_and_strips_cot() -> None:
    snapshot = merge_evidence_summary_into_snapshot(
        {
            "risk_assessment": {"risk_score": 72, "evidence_limited": True},
            "analysis_only_complete": True,
        },
        {
            "evidence_list": [],
            "gaps": [
                {
                    "event_id": "evt-254",
                    "missing_source": "endpoint",
                    "reason": "empty",
                    "raw_prompt": "LEAK",
                    "thought": "should-not-appear",
                }
            ],
            "conflicts": [],
            "success_sources": [],
            "failed_sources": ["endpoint"],
            "overall_confidence": 0.0,
            "collection_status": "failed",
            "chain_of_thought": "SECRET",
            "raw_prompt": "PROMPT-LEAK",
        },
    )
    assert snapshot["risk_assessment"]["risk_score"] == 72
    assert snapshot["risk_assessment"]["evidence_limited"] is True
    assert snapshot["collection_status"] == "failed"
    assert snapshot["evidence_count"] == 0
    assert snapshot["evidence_gaps"]
    assert "chain_of_thought" not in snapshot
    assert "raw_prompt" not in snapshot
    assert "thought" not in snapshot.get("evidence_summary", {})
    blob = orjson.dumps(snapshot).decode()
    assert "LEAK" not in blob
    assert "should-not-appear" not in blob
    assert "SECRET" not in blob
    assert "PROMPT-LEAK" not in blob


def test_merge_storyline_summary_keeps_grounding_status_bounded() -> None:
    storyline = AttackStoryline(
        storyline_id="stl-254",
        event_id="evt-254",
        narrative_summary="x" * 2000,
        phases=[],
        generated_by=StorylineGeneratedBy.RULE,
        grounding_status=StorylineGroundingStatus.UNGROUNDED,
    )
    snapshot = merge_storyline_summary_into_snapshot(
        {"evidence_count": 0, "collection_status": "failed"},
        storyline,
    )
    assert snapshot["storyline"]["grounding_status"] == "ungrounded"
    assert snapshot["storyline"]["phase_count"] == 0
    assert "phases" not in snapshot["storyline"]
    assert len(snapshot["storyline"]["narrative_summary"]) <= 480


def test_storyline_summary_from_dict_drops_heavy_fields() -> None:
    summary = build_storyline_snapshot_summary(
        {
            "storyline_id": "stl-1",
            "grounding_status": "evidence_grounded",
            "generated_by": "llm",
            "phases": [{"phase_order": 1, "entries": [{"description": "big"}]}],
            "claim_refs": [{"claim_id": "c1"}],
            "narrative_summary": "ok",
            "prompt": "SYSTEM: leak",
        }
    )
    assert summary["grounding_status"] == "evidence_grounded"
    assert summary["phase_count"] == 1
    assert summary["claim_ref_count"] == 1
    assert "phases" not in summary
    assert "prompt" not in summary


def test_dict_projection_preserves_enum_values_at_type_boundaries() -> None:
    evidence = build_evidence_snapshot_summary({"collection_status": CollectionStatus.COMPLETED})
    storyline = build_storyline_snapshot_summary(
        {
            "grounding_status": StorylineGroundingStatus.EVIDENCE_GROUNDED,
            "generated_by": StorylineGeneratedBy.RULE,
        }
    )
    projected = project_snapshot_for_api(
        {"execution_substate": ExecutionSubstate.WAITING_WRITEBACK}
    )

    assert evidence["collection_status"] == CollectionStatus.COMPLETED.value
    assert storyline["grounding_status"] == StorylineGroundingStatus.EVIDENCE_GROUNDED.value
    assert storyline["generated_by"] == StorylineGeneratedBy.RULE.value
    assert projected == {
        "execution_substate": ExecutionSubstate.WAITING_WRITEBACK.value,
    }


def test_merge_report_generated_into_snapshot() -> None:
    snapshot = merge_report_generated_into_snapshot({"risk_assessment": {}}, True)
    assert snapshot["report_generated"] is True
    assert "risk_assessment" in snapshot


def test_merge_report_quality_into_snapshot() -> None:
    snapshot = merge_report_quality_into_snapshot({"report_generated": True}, "degraded_template")
    assert snapshot["report_quality"] == "degraded_template"
    assert snapshot["report_generated"] is True


def test_merge_report_quality_into_snapshot_rejects_invalid() -> None:
    with pytest.raises(ValueError):
        merge_report_quality_into_snapshot({}, "not_a_grade")


def test_merge_analysis_only_complete_into_snapshot() -> None:
    from app.services.event_context_snapshot_projection import (
        merge_analysis_only_complete_into_snapshot,
    )

    snapshot = merge_analysis_only_complete_into_snapshot({"risk_assessment": {}}, True)
    assert snapshot["analysis_only_complete"] is True
    downgraded = merge_analysis_only_complete_into_snapshot(snapshot, False)
    assert downgraded["analysis_only_complete"] is True


def test_project_closed_freeze_extracts_bounded_summary_without_dump() -> None:
    """CLOSED full EventContext freeze must project to whitelist summaries only."""
    projected = project_snapshot_for_api(
        {
            "evidence_output": {
                "evidence_list": [{"evidence_id": "e1", "raw_prompt": "LEAK"}],
                "gaps": [
                    {
                        "missing_source": "endpoint",
                        "reason": "all_sources_failed",
                        "thought": "nope",
                    }
                ],
                "conflicts": [],
                "success_sources": [],
                "failed_sources": ["endpoint"],
                "overall_confidence": 0.0,
                "collection_status": "failed",
                "chain_of_thought": "SECRET",
            },
            "storyline": {
                "storyline_id": "stl-1",
                "grounding_status": "ungrounded",
                "generated_by": "rule",
                "phases": [{"phase_order": 1, "entries": [{"description": "big"}]}],
                "claim_refs": [{"claim_id": "c1"}],
                "narrative_summary": "empty",
                "prompt": "SYSTEM",
            },
            "report": {"sections": ["huge"]},
            "rag_output": {
                "chunks": ["x" * 1000],
                "org_context_matches": [
                    {
                        "kind": "allowed_destination",
                        "matched_value": "files.corp.internal",
                        "explanation": "should-not-appear",
                        "citation_id": "cit-deadbeef",
                        "chunk_id": "chk-deadbeef",
                    }
                ],
            },
            "fp_adjudication": {
                "recommendation": "close_as_fp",
                "matched_window_id": "cw-test",
                "reasoning": "hidden-fp-cot",
                "supporting_evidence_ids": ["e1"],
            },
            "risk_assessment": {
                "risk_score": 40,
                "evidence_limited": True,
                "risk_factors": [{"name": "f1", "reasoning": "hidden"}],
            },
            "analysis_only_complete": True,
            "report_generated": True,
        }
    )
    assert projected is not None
    assert projected["collection_status"] == "failed"
    assert projected["evidence_count"] == 1
    assert projected["evidence_gaps"][0]["missing_source"] == "endpoint"
    assert projected["storyline"]["grounding_status"] == "ungrounded"
    assert "phases" not in projected["storyline"]
    assert "evidence_output" not in projected
    assert "report" not in projected
    assert "rag_output" not in projected
    assert projected["rag_citations"] == {"retrieved": True, "degraded": False}
    assert projected["org_context_matches"] == [
        {"kind": "allowed_destination", "matched_value": "files.corp.internal"}
    ]
    assert projected["fp_adjudication"] == {
        "recommendation": "close_as_fp",
        "matched_window_id": "cw-test",
    }
    assert set(projected) <= SNAPSHOT_SUMMARY_KEYS
    blob = orjson.dumps(projected).decode()
    assert "LEAK" not in blob
    assert "SECRET" not in blob
    assert "hidden" not in blob
    assert "SYSTEM" not in blob
    assert "should-not-appear" not in blob
    assert "hidden-fp-cot" not in blob
    assert "cit-deadbeef" not in blob


def test_project_snapshot_exposes_bounded_triage_severity_not_payload() -> None:
    projected = project_snapshot_for_api(
        {
            "risk_assessment": {"risk_score": 77, "severity": "high"},
            "triage_result": {
                "severity": "medium",
                "decision_summary": "event_type=data_exfiltration, severity=medium",
                "reasoning": "CoT must not leak",
            },
        }
    )
    assert projected is not None
    assert projected["triage_severity"] == "medium"
    assert "triage_result" not in projected
    blob = orjson.dumps(projected).decode()
    assert "CoT must not leak" not in blob
    assert "severity=medium" not in blob


def test_project_hard_whitelist_drops_unknown_heavy_keys() -> None:
    projected = project_snapshot_for_api(
        {
            "collection_status": "partial",
            "evidence_count": 0,
            "scratchpad": [{"note": "x" * 5000}],
            "execution_plan": {"steps": list(range(200))},
        }
    )
    assert projected is not None
    assert projected["collection_status"] == "partial"
    assert "scratchpad" not in projected
    assert "execution_plan" not in projected
    assert len(orjson.dumps(projected)) <= 65_536


def test_project_snapshot_exposes_fp_qualification_and_arbitration() -> None:
    projected = project_snapshot_for_api(
        {
            "fp_adjudication": {
                "recommendation": "investigate",
                "matched_window_id": "cw-test",
                "qualification_level": 3,
                "arbitration": "malicious_overrides_allowance",
                "reasoning": "hidden-fp-cot",
            }
        }
    )
    assert projected is not None
    assert projected["fp_adjudication"] == {
        "recommendation": "investigate",
        "matched_window_id": "cw-test",
        "qualification_level": "3",
        "arbitration": "malicious_overrides_allowance",
    }
    blob = orjson.dumps(projected).decode()
    assert "hidden-fp-cot" not in blob


def test_project_snapshot_omits_rag_citations_when_rag_output_missing() -> None:
    projected = project_snapshot_for_api(
        {
            "analysis_only_complete": False,
            "fp_adjudication": {"recommendation": "investigate"},
        }
    )
    assert projected is not None
    assert "rag_citations" not in projected
    assert "rag_output" not in projected


def test_project_snapshot_exposes_bounded_rag_citations_without_payload() -> None:
    projected = project_snapshot_for_api(
        {
            "rag_output": {
                "degraded": True,
                "degraded_steps": ["attack_kb"],
                "fp_similarity": {
                    "max_score": 0.91,
                    "matched_case_id": "case-00000001",
                    "matched_pattern": "change-window-password-reset",
                },
                "playbook_refs": [
                    {
                        "playbook_id": "pb-c8d9e0f1",
                        "release_id": "rel-1",
                        "release_version": "1.0",
                        "content_hash": "a" * 64,
                    },
                    {"playbook_id": "pb-aabbccdd"},
                    {"playbook_id": "pb-11223344"},
                ],
                "attack_techniques": [
                    {
                        "technique_id": "T1021",
                        "technique_name": "Remote Services",
                        "tactics": ["lateral-movement"],
                        "match_confidence": 0.8,
                        "citation_id": "cit-attack-secret",
                    },
                    {
                        "technique_id": "T1078",
                        "technique_name": "Valid Accounts",
                        "citation_id": "cit-t1078",
                    },
                    {"technique_id": "T1110", "technique_name": "Brute Force"},
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                    },
                ],
                "citations": [
                    {
                        "citation_id": "cit-quoted",
                        "quoted_text": "JUMP-HOST-001 must not leak",
                        "kb_name": "attack_kb",
                    }
                ],
                "similar_cases": [{"case_id": "case-secret", "summary": "hidden-case-summary"}],
                "knowledge_query_plan": {"attack_kb": {"query": "SECRET-PLAN"}},
                "org_context_matches": [
                    {
                        "kind": "time_window",
                        "matched_value": "08:00-12:00",
                        "explanation": "should-not-appear",
                        "citation_id": "cit-org",
                        "chunk_id": "chk-org",
                    }
                ],
            }
        }
    )
    assert projected is not None
    assert "rag_output" not in projected
    assert projected["rag_citations"] == {
        "retrieved": True,
        "degraded": True,
        "fp_case_id": "case-00000001",
        "playbook_ids": ["pb-c8d9e0f1", "pb-aabbccdd"],
        "attack_techniques": [
            {"technique_id": "T1021", "technique_name": "Remote Services"},
            {"technique_id": "T1078", "technique_name": "Valid Accounts"},
            {"technique_id": "T1110", "technique_name": "Brute Force"},
        ],
    }
    assert projected["org_context_matches"] == [
        {"kind": "time_window", "matched_value": "08:00-12:00"}
    ]
    blob = orjson.dumps(projected).decode()
    assert "cit-attack-secret" not in blob
    assert "cit-quoted" not in blob
    assert "JUMP-HOST-001" not in blob
    assert "hidden-case-summary" not in blob
    assert "SECRET-PLAN" not in blob
    assert "should-not-appear" not in blob
    assert "change-window-password-reset" not in blob


def test_project_snapshot_empty_rag_output_marks_retrieved() -> None:
    projected = project_snapshot_for_api({"rag_output": {}})
    assert projected is not None
    assert projected["rag_citations"] == {"retrieved": True, "degraded": False}
    assert "fp_case_id" not in projected["rag_citations"]
    assert "playbook_ids" not in projected["rag_citations"]
    assert "attack_techniques" not in projected["rag_citations"]
