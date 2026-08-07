"""ISSUE-254: bounded event_context_snapshot evidence/storyline projection."""

from __future__ import annotations

import orjson

from app.models.agent_io import (
    AttackStoryline,
    CollectionStatus,
    EvidenceOutput,
    StorylineGeneratedBy,
    StorylineGroundingStatus,
)
from app.models.enums import EvidenceSource
from app.models.evidence import EvidenceGap
from app.services.event_context_snapshot_projection import (
    build_evidence_snapshot_summary,
    build_storyline_snapshot_summary,
    merge_evidence_summary_into_snapshot,
    merge_report_generated_into_snapshot,
    merge_storyline_summary_into_snapshot,
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


def test_merge_report_generated_into_snapshot() -> None:
    snapshot = merge_report_generated_into_snapshot({"risk_assessment": {}}, True)
    assert snapshot["report_generated"] is True
    assert "risk_assessment" in snapshot
