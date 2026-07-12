"""Core enumerations (intro §4.6).

Values are lowercase snake_case strings. Enum member names use uppercase
constants even when the value is lowercase (e.g. ``NEW = "new"``). All enums the
system relies on are declared here and registered in ``DECLARED_ENUMS`` so the
drift test can prove the exported set matches this canonical list.
"""

from __future__ import annotations

from enum import Enum, StrEnum


class EventStatus(StrEnum):
    """ShadowTrace internal investigation orchestration state (14 states)."""

    NEW = "new"
    TRIAGING = "triaging"
    COLLECTING_EVIDENCE = "collecting_evidence"
    ANALYZING = "analyzing"
    SCORING = "scoring"
    PLANNING_RESPONSE = "planning_response"
    WAITING_APPROVAL = "waiting_approval"
    EXECUTING_RESPONSE = "executing_response"
    VERIFYING = "verifying"
    REPLANNING = "replanning"
    CONTAINED = "contained"
    FAILED = "failed"
    REPORTING = "reporting"
    CLOSED = "closed"


class FinalVerdict(StrEnum):
    """Verdict label, independent from EventStatus."""

    NONE = "none"
    POSSIBLE_FALSE_POSITIVE = "possible_false_positive"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED_THREAT = "confirmed_threat"


class CaseLabel(StrEnum):
    """Case-KB compatible label derived from FinalVerdict."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class AgentStatus(StrEnum):
    IDLE = "idle"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEGRADED = "degraded"


class SuperAgentStatus(StrEnum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    REFLECTING = "reflecting"
    REPLANNING = "replanning"
    FINISHED = "finished"
    FAILED = "failed"


class ActionStatus(StrEnum):
    """Action lifecycle state (11 states)."""

    PENDING = "pending"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    EXECUTING = "executing"
    PARTIAL_SUCCESS = "partial_success"
    SUCCESS = "success"
    FAILED = "failed"
    UNKNOWN = "unknown"
    ROLLED_BACK = "rolled_back"


class ActionCategory(StrEnum):
    SYSTEM = "system"
    RESPONSE = "response"
    VERIFICATION = "verification"
    ROLLBACK = "rollback"


class ActionExecutionPhase(StrEnum):
    IMMEDIATE = "immediate"
    POST_VERIFY = "post_verify"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionLevel(StrEnum):
    L0 = "l0"
    L1 = "l1"
    L2 = "l2"
    L3 = "l3"
    L4 = "l4"
    L5 = "l5"


class EvidenceSource(StrEnum):
    """Eight evidence sources."""

    IDENTITY = "identity"
    ENDPOINT = "endpoint"
    DATA_SECURITY = "data_security"
    NETWORK_FLOW = "network_flow"
    DNS = "dns"
    ASSET = "asset"
    THREAT_INTEL = "threat_intel"
    FALSE_POSITIVE_MATCH = "false_positive_match"


class ToolCategory(StrEnum):
    QUERY = "query"
    RESPONSE = "response"
    VERIFICATION = "verification"
    ROLLBACK = "rollback"


class EventType(StrEnum):
    """Supported security event types (intro §1); extensible via scenario packs."""

    ACCOUNT_ANOMALY = "account_anomaly"
    HOST_COMPROMISE = "host_compromise"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    MALICIOUS_PROCESS = "malicious_process"
    SUSPICIOUS_DOMAIN = "suspicious_domain"
    LATERAL_MOVEMENT = "lateral_movement"
    OTHER = "other"


class SourceObjectKind(StrEnum):
    """Canonical source object kind used for the internal discriminated union."""

    INCIDENT = "incident"
    ALERT = "alert"
    ASSET = "asset"
    LOG = "log"
    CONNECTOR = "connector"


class SourceDisposition(StrEnum):
    """Normalized external disposition label; source_status_raw keeps the original."""

    PENDING = "pending"
    PROCESSING = "processing"
    CONTAINED = "contained"
    COMPLETED = "completed"
    SUSPENDED = "suspended"
    IGNORED = "ignored"
    UNKNOWN = "unknown"


class DispositionPolicy(StrEnum):
    REQUIRED = "required"
    NOT_REQUIRED = "not_required"


class ExecutionJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PARTIAL_SUCCESS = "partial_success"
    SUCCESS = "success"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class WritebackReadiness(StrEnum):
    """Pre-submission condition; not an external receipt."""

    NOT_REQUIRED = "not_required"
    READY = "ready"
    SOURCE_UNRESOLVED = "source_unresolved"
    NOT_CONFIGURED = "not_configured"
    CAPABILITY_UNKNOWN = "capability_unknown"
    CAPABILITY_UNSUPPORTED = "capability_unsupported"
    PERMISSION_DENIED = "permission_denied"
    CONNECTOR_UNAVAILABLE = "connector_unavailable"


class OutboxDeliveryStatus(StrEnum):
    """Local delivery queue state; never impersonates external fact."""

    READY = "ready"
    LEASED = "leased"
    WAITING_RETRY = "waiting_retry"
    DELIVERED = "delivered"
    PAUSED = "paused"
    DEAD_LETTER = "dead_letter"


class WritebackStatus(StrEnum):
    """Only valid once a writeback command exists; null otherwise."""

    PENDING = "pending"
    SENDING = "sending"
    ACCEPTED = "accepted"
    CONFIRMED = "confirmed"
    PARTIAL = "partial"
    FAILED = "failed"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class ConfirmationEvidence(StrEnum):
    ADAPTER_ACKNOWLEDGED = "adapter_acknowledged"
    STATUS_QUERIED = "status_queried"
    READBACK_VERIFIED = "readback_verified"
    MANUAL_CONFIRMED = "manual_confirmed"


class TargetExecutionStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


class TargetWritebackStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class ExecutionOwner(StrEnum):
    XDR_MANAGED = "xdr_managed"
    DIRECT_TOOL = "direct_tool"


class ExecutionSubstate(StrEnum):
    """Resumable checkpoint substate; never replaces EventStatus."""

    NONE = "none"
    WAITING_APPROVAL = "waiting_approval"
    WAITING_EXECUTION = "waiting_execution"
    WAITING_WRITEBACK = "waiting_writeback"
    MANUAL_RESOLUTION = "manual_resolution"


class DispositionIntentKind(StrEnum):
    """Internal envelope classification; not a vendor enum."""

    ENTITY_ACTION_SUBMIT = "entity_action_submit"
    EXECUTION_RESULT_RECORD = "execution_result_record"
    COMPENSATION_RECORD = "compensation_record"
    EVENT_STATUS_UPDATE = "event_status_update"


class ConnectorStatus(StrEnum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class CapabilityState(StrEnum):
    UNKNOWN = "unknown"
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"


class ConnectorCapability(StrEnum):
    LOG_INGESTION = "log_ingestion"
    QUERY = "query"
    EVENT_DISPOSITION = "event_disposition"
    ENTITY_RESPONSE = "entity_response"


class ErrorCategory(StrEnum):
    """Structured error classification (8 values)."""

    TRANSIENT = "transient"
    PERMANENT = "permanent"
    USER_INPUT = "user_input"
    SYSTEM = "system"
    LLM = "llm"
    TOOL = "tool"
    BUDGET = "budget"
    GUARDRAIL = "guardrail"


class GuardRailDimension(StrEnum):
    SCHEMA = "schema"
    GROUNDING = "grounding"
    POLICY = "policy"
    SANITIZATION = "sanitization"


class BudgetScope(StrEnum):
    SYSTEM = "system"
    EVENT = "event"
    AGENT = "agent"


class QualityVerdict(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


# Terminal external dispositions that may satisfy the event-disposition gate.
# pending / processing / unknown can NEVER satisfy it (intro §4.6.18).
TERMINAL_SOURCE_DISPOSITIONS: frozenset[SourceDisposition] = frozenset(
    {
        SourceDisposition.CONTAINED,
        SourceDisposition.COMPLETED,
        SourceDisposition.SUSPENDED,
        SourceDisposition.IGNORED,
    }
)


# Canonical registry of every enum the system declares. The drift test compares
# this mapping against the intro §4.6 spec list so a newly added enum cannot
# silently drift out of the contract.
DECLARED_ENUMS: dict[str, type[Enum]] = {
    "EventStatus": EventStatus,
    "FinalVerdict": FinalVerdict,
    "CaseLabel": CaseLabel,
    "AgentStatus": AgentStatus,
    "SuperAgentStatus": SuperAgentStatus,
    "ActionStatus": ActionStatus,
    "ActionCategory": ActionCategory,
    "ActionExecutionPhase": ActionExecutionPhase,
    "Severity": Severity,
    "ActionLevel": ActionLevel,
    "EvidenceSource": EvidenceSource,
    "ToolCategory": ToolCategory,
    "EventType": EventType,
    "SourceObjectKind": SourceObjectKind,
    "SourceDisposition": SourceDisposition,
    "DispositionPolicy": DispositionPolicy,
    "ExecutionJobStatus": ExecutionJobStatus,
    "WritebackReadiness": WritebackReadiness,
    "OutboxDeliveryStatus": OutboxDeliveryStatus,
    "WritebackStatus": WritebackStatus,
    "ConfirmationEvidence": ConfirmationEvidence,
    "TargetExecutionStatus": TargetExecutionStatus,
    "TargetWritebackStatus": TargetWritebackStatus,
    "ExecutionOwner": ExecutionOwner,
    "ExecutionSubstate": ExecutionSubstate,
    "DispositionIntentKind": DispositionIntentKind,
    "ConnectorStatus": ConnectorStatus,
    "CapabilityState": CapabilityState,
    "ConnectorCapability": ConnectorCapability,
    "ErrorCategory": ErrorCategory,
    "GuardRailDimension": GuardRailDimension,
    "BudgetScope": BudgetScope,
    "QualityVerdict": QualityVerdict,
}
