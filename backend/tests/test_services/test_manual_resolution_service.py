"""ManualResolutionService unit tests (ISSUE-277 / #873)."""

from __future__ import annotations

from app.models.enums import InvestigationIntentStatus
from app.models.graph_resume_intent import validate_intent_transition
from app.services.manual_resolution_service import (
    deterministic_graph_resume_task_id,
    stable_operation_id,
)


def test_graph_resume_intent_transitions_match_investigation_ledger() -> None:
    validate_intent_transition(
        InvestigationIntentStatus.PENDING,
        InvestigationIntentStatus.CLAIMED,
    )
    validate_intent_transition(
        InvestigationIntentStatus.STARTED,
        InvestigationIntentStatus.TERMINAL,
    )


def test_stable_operation_id_deterministic() -> None:
    first = stable_operation_id(
        resolution_kind="action",
        subject_id="act-1",
        resolution="mark_success",
        principal="admin-1",
        comment="ok",
    )
    second = stable_operation_id(
        resolution_kind="action",
        subject_id="act-1",
        resolution="mark_success",
        principal="admin-1",
        comment="ok",
    )
    third = stable_operation_id(
        resolution_kind="action",
        subject_id="act-1",
        resolution="mark_failed",
        principal="admin-1",
        comment="ok",
    )
    assert first == second
    assert first != third


def test_deterministic_graph_resume_task_id() -> None:
    a = deterministic_graph_resume_task_id("gri-abc", 1)
    b = deterministic_graph_resume_task_id("gri-abc", 1)
    c = deterministic_graph_resume_task_id("gri-abc", 2)
    assert a == b
    assert a != c
