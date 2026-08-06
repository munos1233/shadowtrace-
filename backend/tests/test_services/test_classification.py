"""Unit tests for classification helpers (ISSUE-209) — no DB required."""

from __future__ import annotations

from app.services.classification import (
    apply_event_type_to_triage_payload,
    derive_classification_source,
)


def test_derive_classification_source_priority() -> None:
    assert (
        derive_classification_source(
            classification_override={"source": "human"},
            degraded_flags=["event_type_from_llm_fallback=true"],
        ).value
        == "human"
    )
    assert (
        derive_classification_source(
            degraded_flags=["event_type_from_llm_fallback=true"]
        ).value
        == "llm_fallback"
    )
    assert (
        derive_classification_source(
            degraded_flags=["event_type_from_heuristic=true"]
        ).value
        == "heuristic"
    )
    assert derive_classification_source(degraded_flags=[]).value == "source"
    assert (
        derive_classification_source(
            event_context_snapshot={
                "classification_override": {"source": "human", "event_type": "other"}
            },
            degraded_flags=["event_type_from_heuristic=true"],
        ).value
        == "human"
    )


def test_apply_event_type_to_triage_payload_syncs_dict() -> None:
    updated, changed = apply_event_type_to_triage_payload(
        {"event_type": "other", "confidence": 0.4},
        "data_exfiltration",
    )
    assert changed is True
    assert isinstance(updated, dict)
    assert updated["event_type"] == "data_exfiltration"
    assert updated["confidence"] == 0.4
    same, unchanged = apply_event_type_to_triage_payload(updated, "data_exfiltration")
    assert unchanged is False
    assert same is updated
