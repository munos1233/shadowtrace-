"""Enum snapshot + drift tests (ISSUE-002 acceptance 4)."""

from __future__ import annotations

from enum import Enum

from app.models.enums import (
    DECLARED_ENUMS,
    TERMINAL_SOURCE_DISPOSITIONS,
    ActionStatus,
    CaseLabel,
    EventStatus,
    EventType,
    FinalVerdict,
    SourceDisposition,
)

# Canonical enum names from intro §4.6 (statement 1 of ISSUE-002 统一命名).
EXPECTED_ENUM_NAMES = {
    "EventStatus",
    "FinalVerdict",
    "CaseLabel",
    "AgentStatus",
    "SuperAgentStatus",
    "ActionStatus",
    "ActionCategory",
    "ActionExecutionPhase",
    "Severity",
    "ActionLevel",
    "EvidenceSource",
    "ToolCategory",
    "EventType",
    "SourceObjectKind",
    "SourceDisposition",
    "DispositionPolicy",
    "ExecutionJobStatus",
    "WritebackReadiness",
    "OutboxDeliveryStatus",
    "WritebackStatus",
    "ConfirmationEvidence",
    "TargetExecutionStatus",
    "TargetWritebackStatus",
    "ExecutionOwner",
    "ExecutionSubstate",
    "DispositionIntentKind",
    "ConnectorStatus",
    "CapabilityState",
    "ConnectorCapability",
    "ErrorCategory",
    "GuardRailDimension",
    "BudgetScope",
    "QualityVerdict",
}


def test_declared_enums_match_spec_no_drift() -> None:
    """Declared set must equal the spec set exactly (both directions)."""
    declared = set(DECLARED_ENUMS.keys())
    assert declared == EXPECTED_ENUM_NAMES, {
        "missing": EXPECTED_ENUM_NAMES - declared,
        "unexpected": declared - EXPECTED_ENUM_NAMES,
    }


def test_declared_enums_are_enum_classes() -> None:
    for name, cls in DECLARED_ENUMS.items():
        assert isinstance(cls, type) and issubclass(cls, Enum), name


def test_event_status_has_14_values() -> None:
    assert len(EventStatus) == 14
    assert EventStatus.NEW.value == "new"
    assert EventStatus.CLOSED.value == "closed"


def test_final_verdict_has_4_values() -> None:
    assert {v.value for v in FinalVerdict} == {
        "none",
        "possible_false_positive",
        "false_positive",
        "confirmed_threat",
    }


def test_case_label_has_3_values() -> None:
    assert {v.value for v in CaseLabel} == {"true_positive", "false_positive", "uncertain"}


def test_action_status_has_11_values() -> None:
    assert len(ActionStatus) == 11


def test_event_type_covers_eight_types() -> None:
    assert len(EventType) == 8
    assert EventType.INSIDER_THREAT.value == "insider_threat"


def test_terminal_source_dispositions_set() -> None:
    assert TERMINAL_SOURCE_DISPOSITIONS == frozenset(
        {
            SourceDisposition.CONTAINED,
            SourceDisposition.COMPLETED,
            SourceDisposition.SUSPENDED,
            SourceDisposition.IGNORED,
        }
    )
    # pending / processing / unknown must never be terminal.
    for non_terminal in (
        SourceDisposition.PENDING,
        SourceDisposition.PROCESSING,
        SourceDisposition.UNKNOWN,
    ):
        assert non_terminal not in TERMINAL_SOURCE_DISPOSITIONS
