"""EventContext field-set double-sided assertion (ISSUE-002 统一命名 13)."""

from __future__ import annotations

from app.models.context import EventContext

# Canonical field set fixed by the ISSUE-002 spec (statement 13).
EXPECTED_CONTEXT_FIELDS = {
    "event",
    "source_snapshot",
    "source_sync_state",
    "triage_result",
    "false_positive_match",
    "evidence_output",
    "storyline",
    "graph_output",
    "rag_output",
    "risk_assessment",
    "execution_plan",
    "response_plan",
    "approval_records",
    "disposition_only_intent",
    "execution_substate",
    "execution_summary",
    "execution_jobs",
    "verification_result",
    "rollback_results",
    "impact_assessments",
    "report",
    "memory_output",
    "disposition_commands",
    "disposition_receipts",
    "writeback_summary",
    "state_history",
    "replan_count",
    "budget_usage",
    "guard_violations",
    "convergence_state",
    "quality_scores",
    "scratchpad",
    "degraded_flags",
}


def test_event_context_field_set_matches_spec_both_directions() -> None:
    actual = set(EventContext.model_fields.keys())
    assert actual == EXPECTED_CONTEXT_FIELDS, {
        "missing": EXPECTED_CONTEXT_FIELDS - actual,
        "unexpected": actual - EXPECTED_CONTEXT_FIELDS,
    }
