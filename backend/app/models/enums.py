"""Core enumerations (intro §4.6).

Values are lowercase snake_case strings. Enum member names use uppercase
constants even when the value is lowercase (e.g. ``NEW = "new"``). All enums the
system relies on are declared here and registered in ``DECLARED_ENUMS`` so the
drift test can prove the exported set matches this canonical list.
"""

from __future__ import annotations

from enum import Enum, StrEnum


class EventStatus(StrEnum):
    """ShadowTrace internal investigation orchestration state (14 states).

    ``REPORTING`` means the report phase is reachable (ISSUE-204 / ISSUE-036).
    It does **not** imply report bytes already exist; when investigation skips
    ReportAgent, callers must persist ``report_generated=false`` and guide
    operators to ``POST /events/{id}/report`` before CLOSED.
    """

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


class TaskMode(StrEnum):
    """Investigation task dispatch mode (ISSUE-276 / #872).

    ``celery`` is the production-durable path (PostgreSQL intent + broker worker).
    ``background`` is an explicit dev/test volatile FastAPI BackgroundTasks path.
    """

    CELERY = "celery"
    BACKGROUND = "background"


class InvestigationIntentStatus(StrEnum):
    """Durable auto-investigate intent ledger (#612)."""

    PENDING = "pending"
    CLAIMED = "claimed"
    ENQUEUED = "enqueued"
    STARTED = "started"
    TERMINAL = "terminal"
    SKIPPED = "skipped"
    RETRY = "retry"
    DEAD = "dead"


class BusinessDisruption(StrEnum):
    """Business impact disruption level (ISSUE-079)."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


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


class ClassificationSource(StrEnum):
    """Read-only provenance of ``SecurityEvent.event_type`` (ISSUE-209 / #754).

    Derived on GET; never a parallel machine-write store. Machine signals stay
    in ``event_type_from_*`` degraded_flags (ISSUE-197); human PATCH persists a
    separate ``classification_override`` marker.
    """

    SOURCE = "source"
    HEURISTIC = "heuristic"
    LLM_FALLBACK = "llm_fallback"
    HUMAN = "human"


class ReportQuality(StrEnum):
    """Persisted report quality grade (ISSUE-212 / #750).

    Distinguishes a complete formal report from template / quick-close /
    incomplete-placeholder escapes. Never inferred only on the frontend.
    """

    COMPLETE = "complete"
    DEGRADED_TEMPLATE = "degraded_template"
    QUICK_CLOSE = "quick_close"
    INCOMPLETE_PLACEHOLDER = "incomplete_placeholder"


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


class ResponsePhaseState(StrEnum):
    """Derived UX phase for analysis vs response (ISSUE-103)."""

    NOT_STARTED = "not_started"
    ANALYSIS_IN_PROGRESS = "analysis_in_progress"
    ANALYSIS_COMPLETE_DEFERRED = "analysis_complete_deferred"
    RESPONSE_PLANNING = "response_planning"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    COMPLETE = "complete"


class NextRecommendedAction(StrEnum):
    """Operator next step hint; never implies hidden auto-execution (ISSUE-103)."""

    NONE = "none"
    APPROVE_ACTIONS = "approve_actions"
    CLOSE = "close"


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


class DecisionTraceEntryType(StrEnum):
    AGENT_EXECUTION = "agent_execution"
    TOOL_CALL = "tool_call"
    LLM_CALL = "llm_call"
    STATE_TRANSITION = "state_transition"
    APPROVAL = "approval"
    ACTION_EXECUTION = "action_execution"
    DISPOSITION = "disposition"
    WRITEBACK = "writeback"


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
    "TaskMode": TaskMode,
    "BusinessDisruption": BusinessDisruption,
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
    "ResponsePhaseState": ResponsePhaseState,
    "NextRecommendedAction": NextRecommendedAction,
    "DispositionIntentKind": DispositionIntentKind,
    "ConnectorStatus": ConnectorStatus,
    "CapabilityState": CapabilityState,
    "ConnectorCapability": ConnectorCapability,
    "ErrorCategory": ErrorCategory,
    "GuardRailDimension": GuardRailDimension,
    "BudgetScope": BudgetScope,
    "QualityVerdict": QualityVerdict,
    "DecisionTraceEntryType": DecisionTraceEntryType,
}


class TrajectoryMetric(StrEnum):
    """ISSUE-066 structured trajectory quality indicators."""

    REDUNDANT_TOOL_CALLS = "redundant_tool_calls"
    LOOP_SUSPECTED = "loop_suspected"
    REPLAN_EFFECTIVENESS = "replan_effectiveness"
    AVG_AGENT_LATENCY_MS = "avg_agent_latency_ms"
    EVIDENCE_YIELD = "evidence_yield"
    STEPS_TO_VERDICT = "steps_to_verdict"
