"""Structured error taxonomy: ShadowTraceError, registry, and helpers (ISSUE-008).

All Agent / tool / service / API failures should surface as ``ShadowTraceError``
(or a registered ``error_code``) so callers can classify and decide retry safely.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import ErrorCategory, EventStatus

# --------------------------------------------------------------------------- #
# Category → default retryability (简介 §4.9)
# transient and *partial* llm/tool are retryable; permanent / user_input /
# guardrail / budget / system are not.
# --------------------------------------------------------------------------- #

_CATEGORY_RETRYABLE_DEFAULT: dict[ErrorCategory, bool] = {
    ErrorCategory.TRANSIENT: True,
    ErrorCategory.PERMANENT: False,
    ErrorCategory.USER_INPUT: False,
    ErrorCategory.SYSTEM: False,
    ErrorCategory.LLM: True,
    ErrorCategory.TOOL: True,
    ErrorCategory.BUDGET: False,
    ErrorCategory.GUARDRAIL: False,
}

# Codes that must never be auto-retried even when their category default is True
# (writeback step 8: permission_denied / invalid_operation / version_conflict;
# unknown_delivery = verify-first; writeback_pending = state conflict).
_NON_AUTO_RETRY_CODES: frozenset[str] = frozenset(
    {
        "permission_denied",
        "invalid_operation",
        "version_conflict",
        "unknown_delivery",
        "delivery_outcome_unknown",
        "submission_unknown",
        "writeback_pending",
        "closed_side_effects_pending",
        "writeback_failed",  # only Adapter-gated safe retry may re-enqueue
        "auth_error",
        "validation_error",
        "tool_validation_error",
        "unsupported",
        "capacity_limit_exceeded",
        "wrong_execution_channel",
        "llm_invalid_json",  # repair path is explicit, not blind retry
        "llm_auth_error",  # credentials are invalid; must not be retried
        "llm_audit_error",  # audit persistence failure is fail-closed
    }
)


def _category_retryable_default(category: ErrorCategory) -> bool:
    return _CATEGORY_RETRYABLE_DEFAULT[category]


def _retryable_for_code(error_code: str, category_default: bool) -> bool:
    if error_code in _NON_AUTO_RETRY_CODES:
        return False
    return category_default


# --------------------------------------------------------------------------- #
# Registry — every documented / in-tree error_code (snake_case noun phrases)
# --------------------------------------------------------------------------- #

ERROR_CODE_REGISTRY: dict[str, ErrorCategory] = {
    # API / auth / validation
    "event_not_found": ErrorCategory.USER_INPUT,
    "not_found": ErrorCategory.USER_INPUT,
    "approval_required": ErrorCategory.PERMANENT,
    "approval_decision_conflict": ErrorCategory.PERMANENT,
    "validation_error": ErrorCategory.USER_INPUT,
    "unauthorized": ErrorCategory.USER_INPUT,
    "forbidden": ErrorCategory.USER_INPUT,
    "internal_error": ErrorCategory.SYSTEM,
    # State machine
    "invalid_state_transition": ErrorCategory.PERMANENT,
    "closed_simulated_receipt_rejected": ErrorCategory.PERMANENT,
    "closed_requires_report": ErrorCategory.PERMANENT,
    "invalid_verdict_status_combination": ErrorCategory.PERMANENT,
    # Tools / LLM / budget / guardrail
    "tool_timeout": ErrorCategory.TOOL,
    "timeout": ErrorCategory.TRANSIENT,
    "llm_timeout": ErrorCategory.LLM,
    "llm_auth_error": ErrorCategory.LLM,
    "llm_rate_limited": ErrorCategory.LLM,
    "llm_invalid_json": ErrorCategory.LLM,
    "llm_provider_error": ErrorCategory.LLM,
    "llm_audit_error": ErrorCategory.LLM,
    "llm_config_error": ErrorCategory.SYSTEM,
    "llm_custom_not_probed": ErrorCategory.SYSTEM,
    "budget_exceeded": ErrorCategory.BUDGET,
    "guardrail_failed": ErrorCategory.GUARDRAIL,
    "guardrail_blocked": ErrorCategory.GUARDRAIL,
    "guardrail_violation": ErrorCategory.GUARDRAIL,
    "working_memory_unauthorized_write": ErrorCategory.GUARDRAIL,
    "tool_not_found": ErrorCategory.USER_INPUT,
    "tool_already_registered": ErrorCategory.USER_INPUT,
    "tool_validation_error": ErrorCategory.USER_INPUT,
    "tool_call_grant_denied": ErrorCategory.GUARDRAIL,
    "tool_call_grant_unavailable": ErrorCategory.TRANSIENT,
    "wrong_execution_channel": ErrorCategory.PERMANENT,
    "auth_error": ErrorCategory.TOOL,
    "rate_limited": ErrorCategory.TRANSIENT,
    "remote_error": ErrorCategory.TRANSIENT,
    "http_5xx": ErrorCategory.TRANSIENT,
    "circuit_open": ErrorCategory.TRANSIENT,
    "unsupported": ErrorCategory.PERMANENT,
    "capacity_limit_exceeded": ErrorCategory.TOOL,
    "react_action_denied": ErrorCategory.GUARDRAIL,
    # Writeback / disposition (step 8)
    "permission_denied": ErrorCategory.PERMANENT,
    "invalid_operation": ErrorCategory.PERMANENT,
    "version_conflict": ErrorCategory.PERMANENT,
    "unknown_delivery": ErrorCategory.TRANSIENT,  # verify-first; not auto-retry
    "delivery_outcome_unknown": ErrorCategory.TRANSIENT,
    "submission_unknown": ErrorCategory.TRANSIENT,
    "lookup_apply_failed": ErrorCategory.SYSTEM,
    "lookup_claim_invalid": ErrorCategory.PERMANENT,
    "lookup_degraded": ErrorCategory.TRANSIENT,
    "lookup_inconclusive": ErrorCategory.TRANSIENT,
    "lookup_never_accepted": ErrorCategory.TRANSIENT,
    "lookup_not_found": ErrorCategory.PERMANENT,
    "lookup_unknown": ErrorCategory.TRANSIENT,
    "lookup_unsupported": ErrorCategory.PERMANENT,
    "writeback_pending": ErrorCategory.PERMANENT,  # state conflict, not system fault
    "closed_side_effects_pending": ErrorCategory.PERMANENT,
    "writeback_failed": ErrorCategory.TOOL,
    "writeback_conflict": ErrorCategory.PERMANENT,
    "writeback_unsupported": ErrorCategory.PERMANENT,
    "disposition_permission_denied": ErrorCategory.USER_INPUT,
    # Product / API surface codes referenced in the plan
    "investigation_in_progress": ErrorCategory.PERMANENT,
    "investigation_lease_lost": ErrorCategory.PERMANENT,
    "lease_expired": ErrorCategory.TRANSIENT,
    "storyline_not_ready": ErrorCategory.USER_INPUT,
    "context_not_ready": ErrorCategory.USER_INPUT,
    "evidence_not_ready": ErrorCategory.USER_INPUT,
    "feature_disabled": ErrorCategory.USER_INPUT,
    "full_loop_unavailable": ErrorCategory.USER_INPUT,
    "qa_unavailable": ErrorCategory.TRANSIENT,
    "memory_review_not_found": ErrorCategory.USER_INPUT,
    "memory_review_conflict": ErrorCategory.PERMANENT,
    "memory_governance_bypass_blocked": ErrorCategory.USER_INPUT,
    # ISSUE-209 — classification override conflicts with active response/verify
    "classification_conflict_active_investigation": ErrorCategory.PERMANENT,
    # ISSUE-212 — report quality gate
    "report_quality_incomplete": ErrorCategory.USER_INPUT,
    "report_quality_conflict": ErrorCategory.PERMANENT,
    "output_quality_evaluation_blocked": ErrorCategory.PERMANENT,
    "report_prerequisites_missing": ErrorCategory.USER_INPUT,
    "report_prerequisites_invalid": ErrorCategory.USER_INPUT,
    "report_generation_failed": ErrorCategory.LLM,
    # Generic dependency / domain defaults used by subclasses
    "dependency_unavailable": ErrorCategory.TRANSIENT,
    "task_unavailable": ErrorCategory.TRANSIENT,
    "tool_execution_error": ErrorCategory.TOOL,
    "llm_error": ErrorCategory.LLM,
    # Mock XDR (ISSUE-010) — fixture-only codes, not vendor facts
    "invalid_cursor": ErrorCategory.USER_INPUT,
    "unauthorized_field": ErrorCategory.USER_INPUT,
    "mock_validation_error": ErrorCategory.USER_INPUT,
    "idempotency_key_reuse": ErrorCategory.USER_INPUT,
    "disposition_id_reuse": ErrorCategory.USER_INPUT,
    # Adapters (ISSUE-012)
    "adapter_not_found": ErrorCategory.USER_INPUT,
    "adapter_validation_error": ErrorCategory.USER_INPUT,
    # Startup / runtime configuration (ISSUE-093 §5)
    "configuration_error": ErrorCategory.SYSTEM,
    # Embedding / vector contract (ISSUE-140)
    "embedding_provider_error": ErrorCategory.SYSTEM,
    "embedding_compatibility_error": ErrorCategory.PERMANENT,
    "embedding_provider_unavailable": ErrorCategory.TRANSIENT,
    "embedding_prefilter_required": ErrorCategory.PERMANENT,
    "embedding_dimension_mismatch": ErrorCategory.PERMANENT,
    "embedding_release_mismatch": ErrorCategory.PERMANENT,
    "embedding_metric_mismatch": ErrorCategory.PERMANENT,
    "embedding_mode_conflict": ErrorCategory.SYSTEM,
    "embedding_schema_drift": ErrorCategory.PERMANENT,
    # Replan / writeback recovery (ISSUE-062)
    "replan_count_exceeded": ErrorCategory.PERMANENT,
    "writeback_recovery_exhausted": ErrorCategory.PERMANENT,
    "writeback_manual_resolution_required": ErrorCategory.PERMANENT,
    # Agent task ledger (ISSUE-133)
    "agent_task_denied": ErrorCategory.GUARDRAIL,
    "agent_task_unavailable": ErrorCategory.TRANSIENT,
    # Writeback readback (ISSUE-064)
    "readback_failed": ErrorCategory.TOOL,
}


def register_error_code(code: str, category: ErrorCategory) -> None:
    """Register or update an ``error_code`` → ``ErrorCategory`` mapping."""
    if not code or not code.replace("_", "").isalnum() or code != code.lower():
        raise ValueError(f"error_code must be snake_case: {code!r}")
    ERROR_CODE_REGISTRY[code] = category


# --------------------------------------------------------------------------- #
# Base exception
# --------------------------------------------------------------------------- #


class ShadowTraceError(Exception):
    """Unified structured exception for ShadowTrace."""

    status_code: int = 500
    default_error_code: str = "internal_error"
    default_category: ErrorCategory = ErrorCategory.SYSTEM
    default_retryable: bool | None = None

    def __init__(
        self,
        message: str = "",
        *,
        error_code: str | None = None,
        category: ErrorCategory | None = None,
        retryable: bool | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.error_code = error_code or self.default_error_code
        # Prefer explicit category; otherwise align with the registry when the
        # code is known so ToolExecutionError(..., error_code="rate_limited")
        # classifies as transient, not the subclass default (tool).
        if category is not None:
            self.category = category
        elif self.error_code in ERROR_CODE_REGISTRY:
            self.category = ERROR_CODE_REGISTRY[self.error_code]
        else:
            self.category = self.default_category
        self.message = message or self.error_code.replace("_", " ")
        # API / workflow handlers historically read ``error_message``.
        self.error_message = self.message
        self.details = dict(details or {})

        if retryable is not None:
            self.retryable = retryable
        elif self.default_retryable is not None and error_code is None:
            # Subclass default applies only when the caller did not override the
            # code; overridden codes follow registry category + overlays.
            self.retryable = _retryable_for_code(self.error_code, self.default_retryable)
        else:
            cat_default = _category_retryable_default(self.category)
            self.retryable = _retryable_for_code(self.error_code, cat_default)

        super().__init__(self.message)

    def to_response(self) -> dict[str, Any]:
        """Serialize to the unified API error body (简介 §4.2)."""
        return {
            "error_code": self.error_code,
            "error_message": self.message,
            "details": self.details,
        }


# --------------------------------------------------------------------------- #
# Fixed subclasses (9) + ISSUE-004 API domain errors
# --------------------------------------------------------------------------- #


class ValidationError(ShadowTraceError):
    """Malformed / rejected user or request input."""

    status_code = 422
    default_error_code = "validation_error"
    default_category = ErrorCategory.USER_INPUT
    default_retryable = False


class InvalidStateTransitionError(ShadowTraceError):
    """Illegal EventStatus / sub-state / job / outbox / writeback edge."""

    status_code = 400
    default_error_code = "invalid_state_transition"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False

    def __init__(
        self,
        message: str,
        *,
        current: Any | None = None,
        target: Any | None = None,
        details: dict[str, Any] | None = None,
        error_code: str | None = None,
        category: ErrorCategory | None = None,
        retryable: bool | None = None,
    ) -> None:
        merged = {
            **(details or {}),
            **({"current": getattr(current, "value", current)} if current is not None else {}),
            **({"target": getattr(target, "value", target)} if target is not None else {}),
        }
        self.current = current
        self.target = target
        super().__init__(
            message,
            error_code=error_code,
            category=category,
            retryable=retryable,
            details=merged,
        )
        if self.error_code == "closed_side_effects_pending":
            self.status_code = 409


class InvalidVerdictStatusCombinationError(ShadowTraceError):
    """``FinalVerdict`` incompatible with the current EventStatus / plan shape."""

    status_code = 400
    default_error_code = "invalid_verdict_status_combination"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class ToolExecutionError(ShadowTraceError):
    """ToolProvider / ToolExecutor failure."""

    status_code = 502
    default_error_code = "tool_execution_error"
    default_category = ErrorCategory.TOOL
    default_retryable = True


class LLMError(ShadowTraceError):
    """LLMProvider failure (ISSUE-027 subclasses this further)."""

    status_code = 502
    default_error_code = "llm_error"
    default_category = ErrorCategory.LLM
    default_retryable = True


class BudgetExceededError(ShadowTraceError):
    """Token / cost budget exhausted."""

    status_code = 429
    default_error_code = "budget_exceeded"
    default_category = ErrorCategory.BUDGET
    default_retryable = False


class GuardrailViolationError(ShadowTraceError):
    """Policy / schema / ownership / sanitization guardrail blocked the op."""

    status_code = 403
    default_error_code = "guardrail_failed"
    default_category = ErrorCategory.GUARDRAIL
    default_retryable = False


class ToolCallGrantDeniedError(ShadowTraceError):
    """Dynamic tool call rejected by grant mediation (ISSUE-134)."""

    status_code = 403
    default_error_code = "tool_call_grant_denied"
    default_category = ErrorCategory.GUARDRAIL
    default_retryable = False


class ToolCallGrantUnavailableError(ShadowTraceError):
    """Grant service unavailable — dynamic calls fail closed (ISSUE-134)."""

    status_code = 503
    default_error_code = "tool_call_grant_unavailable"
    default_category = ErrorCategory.TRANSIENT
    default_retryable = True


class AgentTaskDeniedError(ShadowTraceError):
    """AgentTask fencing, scope, or transition denied (ISSUE-133)."""

    status_code = 403
    default_error_code = "agent_task_denied"
    default_category = ErrorCategory.GUARDRAIL
    default_retryable = False


class AgentTaskUnavailableError(ShadowTraceError):
    """AgentTask ledger persistence unavailable (ISSUE-133)."""

    status_code = 503
    default_error_code = "agent_task_unavailable"
    default_category = ErrorCategory.TRANSIENT
    default_retryable = True


class DependencyUnavailableError(ShadowTraceError):
    """Downstream dependency temporarily unavailable."""

    status_code = 503
    default_error_code = "dependency_unavailable"
    default_category = ErrorCategory.TRANSIENT
    default_retryable = True


class InternalError(ShadowTraceError):
    """Unexpected internal failure."""

    status_code = 500
    default_error_code = "internal_error"
    default_category = ErrorCategory.SYSTEM
    default_retryable = False


class EventNotFoundError(ShadowTraceError):
    """Security event id not found (ISSUE-004)."""

    status_code = 404
    default_error_code = "event_not_found"
    default_category = ErrorCategory.USER_INPUT
    default_retryable = False


class ApprovalRequiredError(ShadowTraceError):
    """Action requires human approval before execution (ISSUE-004)."""

    status_code = 409
    default_error_code = "approval_required"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class ApprovalDecisionConflictError(ShadowTraceError):
    """Another approver already decided or decision_id reused (ISSUE-058)."""

    status_code = 409
    default_error_code = "approval_decision_conflict"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


# Writeback / disposition HTTP domain errors (ISSUE-004 codes; registered above).


class WritebackPendingError(ShadowTraceError):
    status_code = 409
    default_error_code = "writeback_pending"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class SideEffectsPendingError(ShadowTraceError):
    """Gate-applicable side effects have not converged before CLOSED (ISSUE-302)."""

    status_code = 409
    default_error_code = "closed_side_effects_pending"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class WritebackFailedError(ShadowTraceError):
    status_code = 409
    default_error_code = "writeback_failed"
    default_category = ErrorCategory.TOOL
    # Blind auto-retry is forbidden; OUTBOX/Worker may re-enqueue only when the
    # Adapter explicitly allows a safe retry (see WRITEBACK_STATUS_TRANSITIONS).
    default_retryable = False


class WritebackConflictError(ShadowTraceError):
    status_code = 409
    default_error_code = "writeback_conflict"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class WritebackUnsupportedError(ShadowTraceError):
    status_code = 422
    default_error_code = "writeback_unsupported"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class DispositionPermissionDenied(ShadowTraceError):
    status_code = 403
    default_error_code = "disposition_permission_denied"
    default_category = ErrorCategory.USER_INPUT
    default_retryable = False


class ResourceNotFoundError(ShadowTraceError):
    """Generic 404 for non-event resources (jobs, dispositions, etc.)."""

    status_code = 404
    default_error_code = "not_found"
    default_category = ErrorCategory.USER_INPUT
    default_retryable = False


class MemoryReviewNotFoundError(ShadowTraceError):
    """A memory governance review ID does not exist."""

    status_code = 404
    default_error_code = "memory_review_not_found"
    default_category = ErrorCategory.USER_INPUT
    default_retryable = False


class MemoryReviewConflictError(ShadowTraceError):
    """A decided memory review cannot transition to another terminal state."""

    status_code = 409
    default_error_code = "memory_review_conflict"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class AdapterNotFoundError(ShadowTraceError):
    """No adapter registered under the requested name (ISSUE-012)."""

    status_code = 404
    default_error_code = "adapter_not_found"
    default_category = ErrorCategory.USER_INPUT
    default_retryable = False


class InvestigationInProgressError(ShadowTraceError):
    """Another orchestration is already running for this event (ISSUE-054)."""

    status_code = 409
    default_error_code = "investigation_in_progress"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class IdempotencyKeyReuseError(ShadowTraceError):
    """An idempotency key was replayed with a different request payload."""

    status_code = 409
    default_error_code = "idempotency_key_reuse"
    default_category = ErrorCategory.USER_INPUT
    default_retryable = False


class ClassificationConflictError(ShadowTraceError):
    """Classification PATCH blocked during active response/verify (ISSUE-209)."""

    status_code = 409
    default_error_code = "classification_conflict_active_investigation"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class ReportQualityConflictError(ShadowTraceError):
    """Refusing to overwrite a complete report with a degraded quality grade (ISSUE-212)."""

    status_code = 409
    default_error_code = "report_quality_conflict"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class OutputQualityEvaluationBlockedError(ShadowTraceError):
    """Output quality evaluation failed while OUTPUT_QUALITY_BLOCKING is enabled (ISSUE-309)."""

    status_code = 422
    default_error_code = "output_quality_evaluation_blocked"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class InvestigationLeaseLostError(ShadowTraceError):
    """Distributed lease renewal failed — another worker owns the event (ISSUE-182)."""

    status_code = 409
    default_error_code = "investigation_lease_lost"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False


class ConfigurationError(ShadowTraceError):
    """Illegal runtime configuration (ISSUE-093 §5).

    Raised from ``Settings`` validation / application lifespan startup to
    fail-closed BEFORE serving traffic — e.g. ``app_env=production`` combined
    with any mock/simulation mode. Never retryable; the process must not start.
    """

    status_code = 500
    default_error_code = "configuration_error"
    default_category = ErrorCategory.SYSTEM
    default_retryable = False


# Replan / writeback recovery escalation errors (ISSUE-062)
# These are raised AFTER the state-machine transition (dual-write: state +
# exception) so the event is already in CONTAINED/FAILED/VERIFYING with the
# appropriate substate when the exception propagates.  Callers catch them to
# extract the escalation outcome for graph routing.


class ReplanCountExceededError(ShadowTraceError):
    """Replan count exhausted — event escalated to CONTAINED or FAILED.

    Raised by ``ReplanHandler.escalate()`` after the state machine has already
    persisted the escalated transition.  The caller is expected to catch this
    and route to report generation with the ``target_status`` attached.
    """

    status_code = 422
    default_error_code = "replan_count_exceeded"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        target_status: EventStatus,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.target_status: EventStatus = target_status
        super().__init__(message, details=details)


class WritebackRecoveryExhaustedError(ShadowTraceError):
    """Automated writeback recovery exhausted (retry/lookup limit reached).

    Raised by ``WritebackRecoveryHandler._escalate()`` when retry or lookup
    counters hit their configured maximums.  The event is already in VERIFYING
    with MANUAL_RESOLUTION substate before this exception propagates.
    """

    status_code = 422
    default_error_code = "writeback_recovery_exhausted"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        writeback_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.writeback_id = writeback_id
        super().__init__(message, details=details)


class WritebackManualResolutionRequiredError(ShadowTraceError):
    """Writeback requires manual resolution (conflict / direct MANUAL action).

    Raised by ``WritebackRecoveryHandler._escalate()`` when the writeback
    status is CONFLICT or the recovery evaluation returns MANUAL.  The event
    is already in VERIFYING with MANUAL_RESOLUTION substate.
    """

    status_code = 409
    default_error_code = "writeback_manual_resolution_required"
    default_category = ErrorCategory.PERMANENT
    default_retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        writeback_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.writeback_id = writeback_id
        super().__init__(message, details=details)


# Backward-compat alias used by API modules that still say ``APIError``.
APIError = ShadowTraceError


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def classify_exception(exc: BaseException) -> ErrorCategory:
    """Map an exception to an ``ErrorCategory``.

    Known ``ShadowTraceError`` → its ``category``.
    Registered ``error_code`` attribute → registry lookup.
    ``TimeoutError`` / ``ConnectionError`` → transient.
    Everything else → system.
    """
    if isinstance(exc, ShadowTraceError):
        return exc.category

    code = getattr(exc, "error_code", None)
    if isinstance(code, str) and code in ERROR_CODE_REGISTRY:
        return ERROR_CODE_REGISTRY[code]

    if isinstance(exc, (TimeoutError, ConnectionError)):
        return ErrorCategory.TRANSIENT

    return ErrorCategory.SYSTEM


def is_retryable(exc: BaseException) -> bool:
    """Whether automatic retry is allowed for this exception."""
    if isinstance(exc, ShadowTraceError):
        return exc.retryable

    code = getattr(exc, "error_code", None)
    if isinstance(code, str):
        category = ERROR_CODE_REGISTRY.get(code, classify_exception(exc))
        return _retryable_for_code(code, _category_retryable_default(category))

    return _category_retryable_default(classify_exception(exc))
