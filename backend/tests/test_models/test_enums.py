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


# Golden value snapshot for EVERY declared enum. Protects the *values* (not just
# the class names) so a later Issue cannot silently rename/drop a member value.
EXPECTED_ENUM_VALUES: dict[str, set[str]] = {
    "EventStatus": {
        "new", "triaging", "collecting_evidence", "analyzing", "scoring",
        "planning_response", "waiting_approval", "executing_response", "verifying",
        "replanning", "contained", "failed", "reporting", "closed",
    },
    "FinalVerdict": {"none", "possible_false_positive", "false_positive", "confirmed_threat"},
    "CaseLabel": {"true_positive", "false_positive", "uncertain"},
    "AgentStatus": {"idle", "processing", "completed", "failed", "degraded"},
    "SuperAgentStatus": {
        "idle", "planning", "executing", "reflecting", "replanning", "finished", "failed",
    },
    "ActionStatus": {
        "pending", "waiting_approval", "approved", "rejected", "superseded", "executing",
        "partial_success", "success", "failed", "unknown", "rolled_back",
    },
    "ActionCategory": {"system", "response", "verification", "rollback"},
    "ActionExecutionPhase": {"immediate", "post_verify"},
    "Severity": {"low", "medium", "high", "critical"},
    "ActionLevel": {"l0", "l1", "l2", "l3", "l4", "l5"},
    "EvidenceSource": {
        "identity", "endpoint", "data_security", "network_flow", "dns", "asset",
        "threat_intel", "false_positive_match",
    },
    "ToolCategory": {"query", "response", "verification", "rollback"},
    "EventType": {
        "account_anomaly", "host_compromise", "data_exfiltration", "insider_threat",
        "malicious_process", "suspicious_domain", "lateral_movement", "other",
    },
    "SourceObjectKind": {"incident", "alert", "asset", "log", "connector"},
    "SourceDisposition": {
        "pending", "processing", "contained", "completed", "suspended", "ignored", "unknown",
    },
    "DispositionPolicy": {"required", "not_required"},
    "ExecutionJobStatus": {
        "queued", "running", "partial_success", "success", "failed", "timed_out",
        "cancelled", "unknown",
    },
    "WritebackReadiness": {
        "not_required", "ready", "source_unresolved", "not_configured", "capability_unknown",
        "capability_unsupported", "permission_denied", "connector_unavailable",
    },
    "OutboxDeliveryStatus": {
        "ready", "leased", "waiting_retry", "delivered", "paused", "dead_letter",
    },
    "WritebackStatus": {
        "pending", "sending", "accepted", "confirmed", "partial", "failed", "conflict",
        "unknown",
    },
    "ConfirmationEvidence": {
        "adapter_acknowledged", "status_queried", "readback_verified", "manual_confirmed",
    },
    "TargetExecutionStatus": {"success", "failed", "unknown", "skipped"},
    "TargetWritebackStatus": {"pending", "accepted", "confirmed", "failed", "conflict", "unknown"},
    "ExecutionOwner": {"xdr_managed", "direct_tool"},
    "ExecutionSubstate": {
        "none", "waiting_approval", "waiting_execution", "waiting_writeback", "manual_resolution",
    },
    "DispositionIntentKind": {
        "entity_action_submit", "execution_result_record", "compensation_record",
        "event_status_update",
    },
    "ConnectorStatus": {"online", "degraded", "offline", "unknown"},
    "CapabilityState": {"unknown", "supported", "unsupported"},
    "ConnectorCapability": {"log_ingestion", "query", "event_disposition", "entity_response"},
    "ErrorCategory": {
        "transient", "permanent", "user_input", "system", "llm", "tool", "budget", "guardrail",
    },
    "GuardRailDimension": {"schema", "grounding", "policy", "sanitization"},
    "BudgetScope": {"system", "event", "agent"},
    "QualityVerdict": {"pass", "warn", "fail"},
}


def test_every_enum_value_set_matches_snapshot() -> None:
    """Each declared enum's value set must match the golden snapshot exactly."""
    # Guard: the golden map must cover every declared enum (no silent omission).
    assert set(EXPECTED_ENUM_VALUES.keys()) == set(DECLARED_ENUMS.keys())
    for name, cls in DECLARED_ENUMS.items():
        actual = {member.value for member in cls}
        assert actual == EXPECTED_ENUM_VALUES[name], {
            "enum": name,
            "missing": EXPECTED_ENUM_VALUES[name] - actual,
            "unexpected": actual - EXPECTED_ENUM_VALUES[name],
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
