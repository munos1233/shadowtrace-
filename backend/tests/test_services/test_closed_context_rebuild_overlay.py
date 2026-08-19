"""CLOSED rebuild must overlay journal AttackStoryline over ISSUE-254 summaries."""

from __future__ import annotations

from app.models.context import EventContext
from app.services.context_service import overlay_closed_snapshot_with_journal
from app.services.event_context_snapshot_projection import parse_attack_storyline


def _summary_blob() -> dict[str, object]:
    return {
        "storyline_id": "sty-overlay",
        "grounding_status": "evidence_grounded",
        "generated_by": "llm",
        "phase_count": 2,
        "claim_ref_count": 1,
        "narrative_summary": "bounded snapshot",
        "schema_version": "1.0",
    }


def _full_storyline() -> dict[str, object]:
    return {
        "storyline_id": "sty-overlay",
        "event_id": "evt-overlay",
        "narrative_summary": "full journal storyline",
        "generated_by": "llm",
        "schema_version": "1.0",
        "grounding_status": "evidence_grounded",
        "phases": [
            {
                "phase_order": 1,
                "phase_name": "initial_access",
                "tactic": "Initial Access",
                "narrative": "account used",
                "entries": [
                    {
                        "timestamp": "2026-07-27T08:00:00Z",
                        "description": "login",
                        "evidence_id": "ev-overlay",
                        "technique_id": "T1078",
                        "severity_hint": "high",
                    }
                ],
            }
        ],
        "claim_refs": [],
    }


def test_overlay_replaces_snapshot_summary_with_journal_storyline() -> None:
    snapshot = EventContext(storyline=_summary_blob())
    journal = EventContext(storyline=_full_storyline(), analysis_only_complete=True)

    out = overlay_closed_snapshot_with_journal(snapshot, journal)

    parsed = parse_attack_storyline(out.storyline)
    assert parsed is not None
    assert parsed.event_id == "evt-overlay"
    assert parsed.phases[0].entries[0].evidence_id == "ev-overlay"
    assert out.analysis_only_complete is True


def test_overlay_keeps_snapshot_when_journal_has_no_full_storyline() -> None:
    snapshot = EventContext(storyline=_summary_blob())
    journal = EventContext(storyline=_summary_blob())

    out = overlay_closed_snapshot_with_journal(snapshot, journal)

    assert parse_attack_storyline(out.storyline) is None
    assert out.storyline is not None
    assert out.storyline["phase_count"] == 2


def test_overlay_does_not_replace_a_full_snapshot_storyline() -> None:
    snapshot = EventContext(storyline=_full_storyline())
    other = dict(_full_storyline())
    other["narrative_summary"] = "journal should not win"
    journal = EventContext(storyline=other)

    out = overlay_closed_snapshot_with_journal(snapshot, journal)

    parsed = parse_attack_storyline(out.storyline)
    assert parsed is not None
    assert parsed.narrative_summary == "full journal storyline"
