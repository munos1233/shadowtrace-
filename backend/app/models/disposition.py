"""Disposition / writeback envelope models (ISSUE-002 field spec).

Outbound envelopes are strictly field-allowlisted with ``extra="forbid"``. The
Factory (later issue) must rebuild commands from canonical entities and controlled
execution results only; it must NEVER copy ``Action.parameters`` / reason, report,
prompt, evidence text or Provider ``raw_result`` into an outbound command.
``raw_result`` on receipts is sanitized and length-limited and must never store
auth headers, tokens, cookies or passwords.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import (
    ConfirmationEvidence,
    DispositionIntentKind,
    DispositionPolicy,
    ExecutionOwner,
    OutboxDeliveryStatus,
    SourceDisposition,
    SourceObjectKind,
    TargetExecutionStatus,
    TargetWritebackStatus,
    WritebackReadiness,
    WritebackStatus,
)


class SourceObjectLocator(BaseModel):
    """Minimal writeback locator (intro §4.3.5 / ISSUE-002)."""

    model_config = ConfigDict(extra="forbid")

    source_product: str
    source_tenant_id: str
    connector_id: str
    source_kind: SourceObjectKind
    source_object_type: str | None = None
    source_object_id: str


# --- Strongly-typed operation params (discriminated by operation_code) ---------
# We do NOT know real vendor operation codes (no live XDR). These are ShadowTrace
# internal / Mock operations; live adapters may only map codes confirmed by an
# official spec. Each variant forbids extra fields.


class SetEventDispositionParams(BaseModel):
    """Params for EVENT_STATUS_UPDATE (the deferred terminal disposition)."""

    model_config = ConfigDict(extra="forbid")

    operation_code: Literal["set_event_disposition"] = "set_event_disposition"
    target_disposition: SourceDisposition
    comment_code: str | None = None


class SubmitEntityActionParams(BaseModel):
    """Params for ENTITY_ACTION_SUBMIT (XDR_MANAGED entity action)."""

    model_config = ConfigDict(extra="forbid")

    operation_code: Literal["submit_entity_action"] = "submit_entity_action"
    entity_action_code: str
    canonical_target: str


class RecordExecutionResultParams(BaseModel):
    """Params for EXECUTION_RESULT_RECORD (DIRECT_TOOL result sync)."""

    model_config = ConfigDict(extra="forbid")

    operation_code: Literal["record_execution_result"] = "record_execution_result"
    summary_code: str | None = None


class RecordCompensationParams(BaseModel):
    """Params for COMPENSATION_RECORD (rollback compensation sync)."""

    model_config = ConfigDict(extra="forbid")

    operation_code: Literal["record_compensation"] = "record_compensation"
    summary_code: str | None = None


OperationParams = Annotated[
    SetEventDispositionParams
    | SubmitEntityActionParams
    | RecordExecutionResultParams
    | RecordCompensationParams,
    Field(discriminator="operation_code"),
]

# Each intent envelope carries exactly one params variant (intro §4.6.18/19).
_INTENT_PARAMS: dict[DispositionIntentKind, type[BaseModel]] = {
    DispositionIntentKind.EVENT_STATUS_UPDATE: SetEventDispositionParams,
    DispositionIntentKind.ENTITY_ACTION_SUBMIT: SubmitEntityActionParams,
    DispositionIntentKind.EXECUTION_RESULT_RECORD: RecordExecutionResultParams,
    DispositionIntentKind.COMPENSATION_RECORD: RecordCompensationParams,
}


class TargetDispositionResult(BaseModel):
    """Outbound per-target result: allowlisted, no free message / raw_result."""

    model_config = ConfigDict(extra="forbid")

    canonical_target: str
    status: TargetExecutionStatus
    provider_code: str | None = None
    message_code: str | None = None
    artifact_ref: str | None = None


class DispositionCommand(BaseModel):
    """Minimal outbound disposition envelope (strict allowlist)."""

    model_config = ConfigDict(extra="forbid")

    disposition_id: str
    action_id: str
    closure_cycle: int
    intent_kind: DispositionIntentKind
    source_locator: SourceObjectLocator
    operation_code: str
    operation_params: OperationParams
    target_results: list[TargetDispositionResult] = Field(default_factory=list)
    operator_id: str
    idempotency_key: str
    source_concurrency_token: str | None = None
    execution_owner: ExecutionOwner
    parent_disposition_id: str | None = None
    supersedes_disposition_id: str | None = None

    @model_validator(mode="after")
    def _direct_tool_cannot_submit_entity_action(self) -> DispositionCommand:
        # DIRECT_TOOL may only record execution results, never submit entity
        # actions; EVENT_STATUS_UPDATE is XDR_MANAGED only (intro §4.6.18/19).
        if (
            self.execution_owner is ExecutionOwner.DIRECT_TOOL
            and self.intent_kind is DispositionIntentKind.ENTITY_ACTION_SUBMIT
        ):
            raise ValueError("DIRECT_TOOL cannot use ENTITY_ACTION_SUBMIT")
        if (
            self.intent_kind is DispositionIntentKind.EVENT_STATUS_UPDATE
            and self.execution_owner is not ExecutionOwner.XDR_MANAGED
        ):
            raise ValueError("EVENT_STATUS_UPDATE must be XDR_MANAGED")
        return self

    @model_validator(mode="after")
    def _operation_code_and_intent_are_consistent(self) -> DispositionCommand:
        # The top-level operation_code must not disagree with the discriminated
        # params, and each intent_kind carries exactly one params variant — an
        # outbound envelope must never claim one operation while carrying another.
        if self.operation_code != self.operation_params.operation_code:
            raise ValueError(
                "operation_code must equal operation_params.operation_code "
                f"({self.operation_code!r} != {self.operation_params.operation_code!r})"
            )
        expected = _INTENT_PARAMS.get(self.intent_kind)
        if expected is not None and not isinstance(self.operation_params, expected):
            raise ValueError(
                f"intent_kind {self.intent_kind.value} requires "
                f"{expected.__name__} operation_params"
            )
        return self


class TargetWritebackResult(BaseModel):
    """Per-target writeback result (kept separate from outbound disposition result)."""

    model_config = ConfigDict(extra="forbid")

    canonical_target: str
    status: TargetWritebackStatus
    provider_code: str | None = None
    message_code: str | None = None
    artifact_ref: str | None = None


class DispositionReceipt(BaseModel):
    """Append-only receipt keyed by ``(writeback_id, sequence)``; latest = max seq."""

    model_config = ConfigDict(extra="forbid")

    writeback_id: str
    sequence: int
    disposition_id: str
    action_id: str
    source_record_id: str
    status: WritebackStatus
    confirmation_evidence: ConfirmationEvidence | None = None
    provider_record_id: str | None = None
    provider_job_id: str | None = None
    provider_code: str | None = None
    provider_message: str | None = None
    observed_at: datetime | None = None
    submitted_at: datetime | None = None
    confirmed_at: datetime | None = None
    target_results: list[TargetWritebackResult] = Field(default_factory=list)
    raw_result: dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False
    simulated: bool = False

    @model_validator(mode="after")
    def _confirmed_requires_evidence(self) -> DispositionReceipt:
        # Only CONFIRMED requires confirmation_evidence; UNKNOWN with no confirmed
        # fact may be null. Mock CONFIRMED must be readback_verified (enforced by
        # the Mock adapter at runtime, ISSUE-012).
        if self.status is WritebackStatus.CONFIRMED and self.confirmation_evidence is None:
            raise ValueError("CONFIRMED receipt requires confirmation_evidence")
        return self


class DispositionOutboxRecord(BaseModel):
    """PostgreSQL outbox record: the source of truth for writeback delivery.

    ``command_payload`` is immutable after creation; superseding only updates
    lineage metadata, never the old payload/receipt.
    """

    model_config = ConfigDict(extra="forbid")

    outbox_id: str
    writeback_id: str
    disposition_id: str
    action_id: str
    event_id: str
    closure_cycle: int
    source_record_id: str
    source_locator_hash: str
    source_sequence: int
    intent_kind: DispositionIntentKind
    logical_slot: str
    supersedes_disposition_id: str | None = None
    superseded_by_disposition_id: str | None = None
    idempotency_key: str
    command_payload: dict[str, Any] = Field(default_factory=dict)
    command_payload_sha256: str
    delivery_status: OutboxDeliveryStatus = OutboxDeliveryStatus.READY
    latest_writeback_status: WritebackStatus | None = None
    attempt: int = 0
    next_retry_at: datetime | None = None
    locked_by: str | None = None
    locked_at: datetime | None = None
    lease_expires_at: datetime | None = None
    last_error_code: str | None = None
    last_error_detail: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    delivered_at: datetime | None = None


class WritebackSummary(BaseModel):
    """Aggregate writeback view (single source of truth for the CLOSED gate)."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    closure_cycle: int
    disposition_policy: DispositionPolicy
    required_action_count: int = 0
    applicable_action_count: int = 0
    blocked_action_ids: list[str] = Field(default_factory=list)
    readiness_counts: dict[WritebackReadiness, int] = Field(default_factory=dict)
    aggregate_readiness: WritebackReadiness = WritebackReadiness.NOT_REQUIRED
    writeback_counts: dict[WritebackStatus, int] = Field(default_factory=dict)
    aggregate_status: WritebackStatus | None = None
    terminal_event_action_id: str | None = None
    terminal_event_writeback_id: str | None = None
    terminal_event_disposition: SourceDisposition | None = None
    terminal_event_confirmed: bool = False
    external_unsynced: bool = False
    updated_at: datetime | None = None
