"""ORM models for the 18 core tables (ISSUE-003).

Column names and semantics mirror the ISSUE-002 Pydantic models one-to-one. JSON
container fields use JSONB. Internal investigation, action execution and external
disposition writeback are audited in separate tables so the three concerns never
share a status column.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# timezone-aware timestamp used across every table.
_TS = DateTime(timezone=True)


class SecurityEvent(Base):
    __tablename__ = "security_event"

    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String, default="new", nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String, default="low", nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    final_verdict: Mapped[str] = mapped_column(String, default="none", nullable=False)

    entities: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    creation_source_ref: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_reference_snapshots: Mapped[list[Any]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    current_primary_source_record_id: Mapped[str | None] = mapped_column(String, nullable=True)
    disposition_source_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    disposition_policy: Mapped[str] = mapped_column(String, default="not_required", nullable=False)

    raw_alert_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    raw_alert_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    source_type: Mapped[str | None] = mapped_column(String, nullable=True)

    occurred_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)

    replan_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    degraded_flags: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    external_unsynced: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    event_context_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # optimistic lock; atomically incremented on every controlled mutable update.
    row_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class SourceObject(Base):
    """Stores the SourceReference full field set plus mutable current_* state.

    Writeback delivery is serialized per source object via ``next_outbox_sequence``,
    allocated under a row lock with ``UPDATE ... RETURNING``.
    """

    __tablename__ = "source_object"
    __table_args__ = (
        UniqueConstraint(
            "source_product",
            "source_tenant_id",
            "connector_id",
            "source_kind",
            "source_object_id",
            name="uq_source_object_identity",
        ),
    )

    source_record_id: Mapped[str] = mapped_column(String, primary_key=True)

    # identity five-tuple + adapter-native type (not part of identity)
    source_product: Mapped[str] = mapped_column(String, nullable=False)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    connector_id: Mapped[str] = mapped_column(
        String, ForeignKey("source_connector.connector_id"), nullable=False, index=True
    )
    source_kind: Mapped[str] = mapped_column(String, nullable=False)
    source_object_id: Mapped[str] = mapped_column(String, nullable=False)
    source_object_type: Mapped[str | None] = mapped_column(String, nullable=True)
    parent_source_object_id: Mapped[str | None] = mapped_column(String, nullable=True)

    # immutable investigation snapshot fields
    source_status_raw: Mapped[str | None] = mapped_column(String, nullable=True)
    source_disposition: Mapped[str] = mapped_column(String, default="unknown", nullable=False)
    source_concurrency_token: Mapped[str | None] = mapped_column(String, nullable=True)
    source_updated_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    schema_version: Mapped[str] = mapped_column(String, default="1", nullable=False)
    ingested_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    raw_payload_hash: Mapped[str | None] = mapped_column(String, nullable=True)

    normalized: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # mutable current state (never overwrites the snapshot)
    current_source_status_raw: Mapped[str | None] = mapped_column(String, nullable=True)
    current_source_disposition: Mapped[str] = mapped_column(
        String, default="unknown", nullable=False
    )
    current_concurrency_token: Mapped[str | None] = mapped_column(String, nullable=True)
    current_source_updated_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    current_state_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    source_sync_state: Mapped[str | None] = mapped_column(String, nullable=True)

    next_outbox_sequence: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class SourceConnector(Base):
    __tablename__ = "source_connector"

    connector_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_product: Mapped[str] = mapped_column(String, nullable=False)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    device_type: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="unknown", nullable=False)
    read_endpoint: Mapped[str | None] = mapped_column(String, nullable=True)
    disposition_endpoint: Mapped[str | None] = mapped_column(String, nullable=True)
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    # NULL = not explicitly provisioned (live must fail closed; mock/file set a value).
    disposition_policy_default: Mapped[str | None] = mapped_column(String, nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    watermark: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    schema_version: Mapped[str] = mapped_column(String, default="1", nullable=False)
    # only credential references are stored; the secret material never lands here.
    read_credential_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    disposition_credential_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    connector_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class SourceCheckpoint(Base):
    """Durable ingestion progress isolated by connector and source object kind."""

    __tablename__ = "source_checkpoint"

    connector_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("source_connector.connector_id", ondelete="CASCADE"),
        primary_key=True,
    )
    object_kind: Mapped[str] = mapped_column(String, primary_key=True)
    stream_scope: Mapped[str] = mapped_column(String, primary_key=True, default="")
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    cursor: Mapped[str | None] = mapped_column(String, nullable=True)
    watermark: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(String, default="unknown", nullable=False)
    degraded_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    row_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class SourceEventLink(Base):
    """Links a source object to an internal event with a role + promotion status."""

    __tablename__ = "source_event_link"
    __table_args__ = (
        UniqueConstraint("source_record_id", "event_id", name="uq_source_event_link_pair"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source_record_id: Mapped[str] = mapped_column(
        String, ForeignKey("source_object.source_record_id"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String, default="primary", nullable=False)
    promotion_status: Mapped[str] = mapped_column(String, default="none", nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Evidence(Base):
    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    source: Mapped[str] = mapped_column(String, nullable=False)
    evidence_type: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    timestamp: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    related_entities: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    source_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    mitre_technique: Mapped[str | None] = mapped_column(String, nullable=True)
    is_conflicting: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class Action(Base):
    __tablename__ = "action"
    __table_args__ = (
        UniqueConstraint("action_fingerprint", name="uq_action_action_fingerprint"),
        Index("ix_action_idempotency_key", "idempotency_key"),
    )

    action_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    plan_revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    action_fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    action_category: Mapped[str] = mapped_column(String, nullable=False)
    action_name: Mapped[str] = mapped_column(String, nullable=False)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    action_level: Mapped[str] = mapped_column(String, nullable=False)
    execution_phase: Mapped[str] = mapped_column(String, default="immediate", nullable=False)
    activation_condition: Mapped[str | None] = mapped_column(String, nullable=True)
    approved_operation_template_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    approved_terminal_dispositions: Mapped[list[Any]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    target_type: Mapped[str | None] = mapped_column(String, nullable=True)
    target: Mapped[str | None] = mapped_column(String, nullable=True)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending", nullable=False)
    auto_execute: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact_assessment: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    playbook_id: Mapped[str | None] = mapped_column(String, nullable=True)
    playbook_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    action_template_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    provider_name: Mapped[str | None] = mapped_column(String, nullable=True)
    execution_owner: Mapped[str | None] = mapped_column(String, nullable=True)
    execution_job_id: Mapped[str | None] = mapped_column(String, nullable=True)
    tool_call_id: Mapped[str | None] = mapped_column(String, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    writeback_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    writeback_applicable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    writeback_readiness: Mapped[str] = mapped_column(String, default="not_required", nullable=False)
    writeback_block_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    writeback_status: Mapped[str | None] = mapped_column(String, nullable=True)
    disposition_source_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    superseded_by_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    effect_verification_status: Mapped[str | None] = mapped_column(String, nullable=True)
    rollback_status: Mapped[str | None] = mapped_column(String, nullable=True)
    source_action_id: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class ActionExecutionJob(Base):
    __tablename__ = "action_execution_job"
    __table_args__ = (
        Index("ix_action_execution_job_status", "status"),
        # ISSUE-220: one authoritative job per idempotency_key — lease reclaim
        # must never re-insert a duplicate job for the same key (duplicate
        # side-effects).  Migration 0034 deduplicates legacy rows before
        # creating this constraint.
        UniqueConstraint("idempotency_key", name="uq_action_execution_job_idempotency_key"),
        Index("ix_action_execution_job_lease_expires_at", "lease_expires_at"),
    )

    job_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    action_id: Mapped[str] = mapped_column(
        String, ForeignKey("action.action_id"), nullable=False, index=True
    )
    provider_name: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    provider_job_id: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="queued", nullable=False)
    claimed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    poll_after_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    provider_code: Mapped[str | None] = mapped_column(String, nullable=True)
    provider_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Provider raw result retained here (internal only).
    raw_result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)


class ActionTargetResult(Base):
    __tablename__ = "action_target_result"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(
        String, ForeignKey("action_execution_job.job_id"), nullable=False, index=True
    )
    canonical_target: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    code: Mapped[str | None] = mapped_column(String, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # Provider raw result retained here (internal only).
    raw_result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class DispositionOutbox(Base):
    """Reliable writeback outbox; the source of truth for writeback delivery.

    ``command_payload`` is immutable after creation. Only one active (non
    -superseded) EVENT_STATUS_UPDATE head is allowed per
    ``(event_id, closure_cycle, intent_kind, logical_slot)`` via a partial
    unique index over rows where ``superseded_by_disposition_id IS NULL``.
    This is deliberately event-scoped, NOT action-scoped: two different
    Actions racing to submit the terminal disposition for the same event/
    cycle/slot must collide on this index rather than silently coexist as
    two "active" heads (ISSUE-093 §4).
    """

    __tablename__ = "disposition_outbox"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_disposition_outbox_idempotency_key"),
        UniqueConstraint(
            "source_record_id", "source_sequence", name="uq_disposition_outbox_source_sequence"
        ),
        Index(
            "uq_disposition_outbox_event_status_active_head",
            "event_id",
            "closure_cycle",
            "intent_kind",
            "logical_slot",
            unique=True,
            postgresql_where=text(
                "superseded_by_disposition_id IS NULL AND intent_kind = 'event_status_update'"
            ),
        ),
        Index("ix_disposition_outbox_delivery_status", "delivery_status"),
        Index("ix_disposition_outbox_latest_writeback_status", "latest_writeback_status"),
        Index("ix_disposition_outbox_next_retry_at", "next_retry_at"),
        Index("ix_disposition_outbox_lease_expires_at", "lease_expires_at"),
        Index("ix_disposition_outbox_disposition_id", "disposition_id"),
    )

    outbox_id: Mapped[str] = mapped_column(String, primary_key=True)
    writeback_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    disposition_id: Mapped[str] = mapped_column(String, nullable=False)
    action_id: Mapped[str] = mapped_column(
        String, ForeignKey("action.action_id"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    closure_cycle: Mapped[int] = mapped_column(Integer, nullable=False)
    source_record_id: Mapped[str] = mapped_column(
        String, ForeignKey("source_object.source_record_id"), nullable=False, index=True
    )
    source_locator_hash: Mapped[str] = mapped_column(String, nullable=False)
    source_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    intent_kind: Mapped[str] = mapped_column(String, nullable=False)
    logical_slot: Mapped[str] = mapped_column(String, nullable=False)
    supersedes_disposition_id: Mapped[str | None] = mapped_column(String, nullable=True)
    superseded_by_disposition_id: Mapped[str | None] = mapped_column(String, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    # immutable after creation
    command_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    command_payload_sha256: Mapped[str] = mapped_column(String, nullable=False)
    delivery_status: Mapped[str] = mapped_column(String, default="ready", nullable=False)
    latest_writeback_status: Mapped[str | None] = mapped_column(String, nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    next_retry_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    locked_by: Mapped[str | None] = mapped_column(String, nullable=True)
    locked_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String, nullable=True)
    last_error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)


class DispositionReceipt(Base):
    """XDR writeback receipt; append-only keyed by (writeback_id, sequence)."""

    __tablename__ = "disposition_receipt"

    writeback_id: Mapped[str] = mapped_column(String, primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    disposition_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(
        String, ForeignKey("action.action_id"), nullable=False, index=True
    )
    source_record_id: Mapped[str] = mapped_column(
        String, ForeignKey("source_object.source_record_id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String, nullable=False)
    confirmation_evidence: Mapped[str | None] = mapped_column(String, nullable=True)
    provider_record_id: Mapped[str | None] = mapped_column(String, nullable=True)
    provider_job_id: Mapped[str | None] = mapped_column(String, nullable=True)
    provider_code: Mapped[str | None] = mapped_column(String, nullable=True)
    provider_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    target_results: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    raw_result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Report(Base):
    __tablename__ = "report"

    report_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    sections: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    final_verdict: Mapped[str] = mapped_column(String, default="none", nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    severity: Mapped[str] = mapped_column(String, default="low", nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    generated_by: Mapped[str | None] = mapped_column(String, nullable=True)
    # ISSUE-212: complete | degraded_template | quick_close | incomplete_placeholder
    report_quality: Mapped[str] = mapped_column(
        String, default="complete", server_default="complete", nullable=False
    )
    generated_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class AgentTrace(Base):
    __tablename__ = "agent_trace"

    trace_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    agent_name: Mapped[str] = mapped_column(String, nullable=False)
    input_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    output_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String, nullable=True)
    llm_tokens_used: Mapped[int | None] = mapped_column(Integer, nullable=True)


class DecisionRecord(Base):
    """Durable sanitized decision artifact (ISSUE-131 Phase B)."""

    __tablename__ = "decision_record"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_decision_record_idempotency_key"),
        Index("ix_decision_record_event_id", "event_id"),
        Index("ix_decision_record_trace_ref", "trace_ref"),
    )

    record_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False)
    stage: Mapped[str] = mapped_column(String, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    input_refs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    candidates: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    selected: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    decision_summary: Mapped[str] = mapped_column(String, default="", nullable=False)
    rule_version: Mapped[str | None] = mapped_column(String, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String, nullable=True)
    prompt_policy_version: Mapped[str | None] = mapped_column(String, nullable=True)
    kb_version: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    uncertainty_codes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    guardrail_flags: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    degraded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trace_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    record_hash: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    parent_record_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("decision_record.record_id"), nullable=True
    )
    supersedes_record_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("decision_record.record_id"), nullable=True
    )
    retention_policy: Mapped[str] = mapped_column(String, default="standard", nullable=False)
    unresolved_refs: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    owner: Mapped[str] = mapped_column(String, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class EvaluationCaseTruth(Base):
    """Canonical adjudicated evaluation truth (ISSUE-113 Phase A)."""

    __tablename__ = "evaluation_case_truth"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_evaluation_case_truth_idempotency_key"),
        Index("ix_evaluation_case_truth_tenant_dataset", "tenant_id", "dataset_id"),
        Index(
            "ix_evaluation_case_truth_tenant_dataset_case_rev",
            "tenant_id",
            "dataset_id",
            "case_id",
            "revision",
        ),
    )

    truth_id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    source_tenant_id: Mapped[str | None] = mapped_column(String, nullable=True)
    source_product: Mapped[str | None] = mapped_column(String, nullable=True)
    connector_id: Mapped[str | None] = mapped_column(String, nullable=True)
    dataset_id: Mapped[str] = mapped_column(String, nullable=False)
    dataset_version: Mapped[str] = mapped_column(String, nullable=False)
    case_id: Mapped[str] = mapped_column(String, nullable=False)
    case_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    observation_refs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    slice_expectation: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    label_provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    operational_mapping: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    supersedes_truth_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("evaluation_case_truth.truth_id"), nullable=True
    )
    correction_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    retention_policy: Mapped[str] = mapped_column(
        String, default="evaluation_standard", nullable=False
    )
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    truth_hash: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class DetectionScopeRevision(Base):
    """Canonical detection scope revision (ISSUE-120 Phase 0)."""

    __tablename__ = "detection_scope_revision"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_detection_scope_revision_idempotency_key"),
        Index(
            "ix_detection_scope_revision_tenant_product_instance",
            "source_tenant_id",
            "source_product",
            "integration_instance_id",
        ),
        Index(
            "ix_detection_scope_revision_scope_id_rev",
            "detection_scope_id",
            "revision",
        ),
        Index(
            "ix_detection_scope_revision_scope_lifecycle",
            "detection_scope_id",
            "lifecycle_state",
        ),
        Index(
            "uq_detection_scope_revision_one_active_per_scope",
            "detection_scope_id",
            unique=True,
            postgresql_where=text("lifecycle_state = 'active'"),
        ),
        Index(
            "uq_detection_scope_revision_one_active_per_instance",
            "source_tenant_id",
            "source_product",
            "integration_instance_id",
            unique=True,
            postgresql_where=text("lifecycle_state = 'active'"),
        ),
    )

    scope_revision_id: Mapped[str] = mapped_column(String, primary_key=True)
    detection_scope_id: Mapped[str] = mapped_column(String, nullable=False)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    source_product: Mapped[str] = mapped_column(String, nullable=False)
    integration_instance_id: Mapped[str] = mapped_column(String, nullable=False)
    environment: Mapped[str | None] = mapped_column(String, nullable=True)
    region: Mapped[str | None] = mapped_column(String, nullable=True)
    connector_set: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    connector_set_version: Mapped[int] = mapped_column(Integer, nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    supersedes_scope_revision_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("detection_scope_revision.scope_revision_id"),
        nullable=True,
    )
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    identity_hash: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class EventAuditLog(Base):
    __tablename__ = "event_audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String, nullable=True)
    to_status: Mapped[str | None] = mapped_column(String, nullable=True)
    operator: Mapped[str | None] = mapped_column(String, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class ToolCallLog(Base):
    __tablename__ = "tool_call_log"

    call_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    action_id: Mapped[str | None] = mapped_column(String, nullable=True)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    tool_category: Mapped[str] = mapped_column(String, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class LLMCallLog(Base):
    __tablename__ = "llm_call_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    agent_name: Mapped[str] = mapped_column(String, nullable=False)
    prompt_key: Mapped[str] = mapped_column(String, nullable=False)
    model_name: Mapped[str] = mapped_column(String, nullable=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fallback_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    # ISSUE-240: bounded failure taxonomy for durable audit (null on success).
    error_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class BehaviorObservation(Base):
    """Durable semantic projection of one source object revision (ISSUE-119 / #624)."""

    __tablename__ = "behavior_observation"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_behavior_observation_idempotency_key"),
        Index(
            "ix_behavior_observation_tenant_scope_observed",
            "source_tenant_id",
            "detection_scope_id",
            "observed_at",
        ),
        Index(
            "ix_behavior_observation_source_identity",
            "source_tenant_id",
            "detection_scope_id",
            "source_kind",
            "source_object_id",
            "source_revision",
        ),
    )

    observation_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    detection_scope_id: Mapped[str] = mapped_column(String, nullable=False)
    source_product: Mapped[str] = mapped_column(String, nullable=False)
    connector_id: Mapped[str] = mapped_column(String, nullable=False)
    source_kind: Mapped[str] = mapped_column(String, nullable=False)
    source_object_id: Mapped[str] = mapped_column(String, nullable=False)
    source_object_type: Mapped[str | None] = mapped_column(String, nullable=True)
    source_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    source_ref: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    entity_refs: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    action: Mapped[str | None] = mapped_column(String, nullable=True)
    category: Mapped[str | None] = mapped_column(String, nullable=True)
    normalized_attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    detection_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    projection_schema_version: Mapped[str] = mapped_column(String, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    observation_hash: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    supersedes_observation_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("behavior_observation.observation_id"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class BehaviorObservationProjectionFailure(Base):
    """Durable retry/dead-letter queue for semantic projection failures."""

    __tablename__ = "behavior_observation_projection_failure"
    __table_args__ = (
        Index(
            "ix_behavior_obs_projection_failure_retry",
            "status",
            "next_retry_at",
        ),
        Index(
            "ix_behavior_obs_projection_failure_source",
            "source_record_id",
            "status",
        ),
    )

    failure_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_record_id: Mapped[str] = mapped_column(String, nullable=False)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    error_category: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    next_retry_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class FeatureSnapshot(Base):
    """Event-time feature materialization over behavior observations (ISSUE-120 Phase A/B)."""

    __tablename__ = "feature_snapshot"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_feature_snapshot_idempotency_key"),
        Index(
            "ix_feature_snapshot_tenant_scope_entity_cutoff",
            "source_tenant_id",
            "detection_scope_id",
            "entity_type",
            "entity_id",
            "window_kind",
            "cutoff_at",
        ),
        Index(
            "ix_feature_snapshot_cache_key",
            "source_tenant_id",
            "cache_key",
        ),
    )

    snapshot_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    detection_scope_id: Mapped[str] = mapped_column(String, nullable=False)
    entity_type: Mapped[str] = mapped_column(String, nullable=False)
    entity_id: Mapped[str] = mapped_column(String, nullable=False)
    feature_contract_version: Mapped[str] = mapped_column(String, nullable=False)
    window_kind: Mapped[str] = mapped_column(String, nullable=False)
    window_start: Mapped[datetime] = mapped_column(_TS, nullable=False)
    window_end: Mapped[datetime] = mapped_column(_TS, nullable=False)
    cutoff_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    allowed_lateness_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    source_watermark: Mapped[datetime] = mapped_column(_TS, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    supersedes_snapshot_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("feature_snapshot.snapshot_id"),
        nullable=True,
    )
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    cache_key: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class DetectionFeatureBaseline(Base):
    """Rolling baseline stats from snapshots at or before cutoff (ISSUE-120 Phase B)."""

    __tablename__ = "detection_feature_baseline"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_detection_feature_baseline_idempotency_key"),
        Index(
            "ix_detection_baseline_tenant_scope_entity_cutoff",
            "source_tenant_id",
            "detection_scope_id",
            "entity_type",
            "entity_id",
            "window_kind",
            "cutoff_at",
        ),
        Index(
            "ix_detection_baseline_peer_group",
            "source_tenant_id",
            "peer_group_id",
        ),
    )

    baseline_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    detection_scope_id: Mapped[str] = mapped_column(String, nullable=False)
    entity_type: Mapped[str] = mapped_column(String, nullable=False)
    entity_id: Mapped[str] = mapped_column(String, nullable=False)
    peer_group_id: Mapped[str | None] = mapped_column(String, nullable=True)
    feature_contract_version: Mapped[str] = mapped_column(String, nullable=False)
    window_kind: Mapped[str] = mapped_column(String, nullable=False)
    cutoff_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    seasonality_profile: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    snapshot_revision_refs: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    supersedes_baseline_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("detection_feature_baseline.baseline_id"),
        nullable=True,
    )
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    cache_key: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class DetectionRulePackage(Base):
    """Versioned detection-as-code rule package (ISSUE-121 / #626)."""

    __tablename__ = "detection_rule_package"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_detection_rule_package_idempotency_key"),
        Index(
            "ix_detection_rule_package_tenant_state",
            "source_tenant_id",
            "runtime_state",
        ),
    )

    package_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    package_version: Mapped[int] = mapped_column(Integer, nullable=False)
    runtime_state: Mapped[str] = mapped_column(String, nullable=False)
    rules: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    supersedes_package_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("detection_rule_package.package_id"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class CandidateDetection(Base):
    """Shadow-only candidate detection output (ISSUE-121 / #626)."""

    __tablename__ = "candidate_detection"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_candidate_detection_idempotency_key"),
        Index(
            "ix_candidate_detection_tenant_scope_cutoff",
            "source_tenant_id",
            "detection_scope_id",
            "cutoff_at",
        ),
        Index(
            "ix_candidate_detection_package_rule",
            "source_tenant_id",
            "package_id",
            "rule_id",
        ),
    )

    candidate_detection_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    detection_scope_id: Mapped[str] = mapped_column(String, nullable=False)
    package_id: Mapped[str] = mapped_column(String, nullable=False)
    package_version: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_id: Mapped[str] = mapped_column(String, nullable=False)
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    operator: Mapped[str] = mapped_column(String, nullable=False)
    group_key: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    cutoff_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    window_kind: Mapped[str] = mapped_column(String, nullable=False)
    matched_value: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    shadow_only: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class DetectionRuleRuntimeError(Base):
    """Typed runtime execution failure (ISSUE-121 / #626)."""

    __tablename__ = "detection_rule_runtime_error"
    __table_args__ = (
        Index(
            "ix_detection_rule_runtime_error_tenant_package",
            "source_tenant_id",
            "package_id",
        ),
    )

    error_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    package_id: Mapped[str] = mapped_column(String, nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    error_category: Mapped[str] = mapped_column(String, nullable=False)
    error_message: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class DataQualityError(Base):
    """Ingestion/normalization quality issues; event_id nullable (pre-event errors)."""

    __tablename__ = "data_quality_error"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    stage: Mapped[str] = mapped_column(String, nullable=False)
    error_category: Mapped[str] = mapped_column(String, nullable=False)
    field_name: Mapped[str | None] = mapped_column(String, nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class EventContextJournal(Base):
    """Append-only versioned journal of EventContext field values."""

    __tablename__ = "event_context_journal"
    __table_args__ = (
        UniqueConstraint(
            "event_id", "field_name", "version", name="uq_event_context_journal_field_version"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    field_name: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class EventContextFieldVersion(Base):
    """Sole allocation source for context field versions; PK (event_id, field_name)."""

    __tablename__ = "event_context_field_version"

    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    field_name: Mapped[str] = mapped_column(String, primary_key=True)
    current_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class InvestigationIntent(Base):
    """PostgreSQL durable auto-investigate intent/outbox (ISSUE-108 / #612)."""

    __tablename__ = "investigation_intent"
    __table_args__ = (
        UniqueConstraint(
            "event_id",
            "intent_kind",
            "intent_version",
            name="uq_investigation_intent_event_kind_version",
        ),
        Index("ix_investigation_intent_status_updated", "status", "updated_at"),
        Index("ix_investigation_intent_claim_expires", "claim_expires_at"),
    )

    intent_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("security_event.event_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    intent_kind: Mapped[str] = mapped_column(String, nullable=False)
    intent_version: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    claim_owner: Mapped[str | None] = mapped_column(String, nullable=True)
    claim_expires_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    broker_task_id: Mapped[str | None] = mapped_column(String, nullable=True)
    skip_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    include_response_execution: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # ISSUE-204: API default True for backward compat; auto/Celery intents set False.
    generate_report: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class KnowledgeReleaseORM(Base):
    """ATT&CK STIX knowledge release registry (ISSUE-128 / #634)."""

    __tablename__ = "knowledge_release"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_knowledge_release_idempotency_key"),
        Index("ix_knowledge_release_corpus_lifecycle", "corpus_id", "lifecycle_state"),
        Index(
            "uq_knowledge_release_one_active_per_corpus",
            "corpus_id",
            unique=True,
            postgresql_where=text("lifecycle_state = 'active'"),
        ),
    )

    release_id: Mapped[str] = mapped_column(String, primary_key=True)
    corpus_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String, nullable=False)
    release_version: Mapped[str] = mapped_column(String, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    import_status: Mapped[str] = mapped_column(String, nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    supersedes_release_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("knowledge_release.release_id"),
        nullable=True,
    )
    object_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    relationship_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    vector_ready: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    embedding_release_id: Mapped[str | None] = mapped_column(String, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class KnowledgeStixObjectORM(Base):
    """Immutable STIX object rows bound to one knowledge release."""

    __tablename__ = "knowledge_stix_object"
    __table_args__ = (
        UniqueConstraint(
            "release_id",
            "stix_id",
            name="uq_knowledge_stix_object_release_stix_id",
        ),
        Index(
            "uq_knowledge_stix_object_release_external_id",
            "release_id",
            "external_id",
            unique=True,
            postgresql_where=text("external_id IS NOT NULL"),
        ),
    )

    object_row_id: Mapped[str] = mapped_column(String, primary_key=True)
    release_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("knowledge_release.release_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    stix_id: Mapped[str] = mapped_column(String, nullable=False)
    stix_type: Mapped[str] = mapped_column(String, nullable=False)
    external_id: Mapped[str | None] = mapped_column(String, nullable=True)
    object_hash: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class PlaybookReleaseObjectORM(Base):
    """Immutable playbook object rows bound to one playbook release (ISSUE-139 / #645)."""

    __tablename__ = "playbook_release_object"
    __table_args__ = (
        UniqueConstraint(
            "release_id",
            "playbook_id",
            name="uq_playbook_release_object_release_playbook_id",
        ),
    )

    object_row_id: Mapped[str] = mapped_column(String, primary_key=True)
    release_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("knowledge_release.release_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    playbook_id: Mapped[str] = mapped_column(String, nullable=False)
    object_hash: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class OrganizationPolicyProfileORM(Base):
    """Server-owned tenant policy applicability profile (ISSUE-129 / #635)."""

    __tablename__ = "organization_policy_profile"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "profile_id",
            "revision",
            name="uq_organization_policy_profile_tenant_profile_revision",
        ),
        UniqueConstraint(
            "tenant_id",
            "revision",
            name="uq_organization_policy_profile_tenant_revision",
        ),
        Index("ix_organization_policy_profile_tenant_revision", "tenant_id", "revision"),
    )

    profile_row_id: Mapped[str] = mapped_column(String, primary_key=True)
    profile_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_principal: Mapped[str] = mapped_column(String, nullable=False)
    framework_allowlist: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    jurisdiction_codes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    industry_codes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    effective_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String, nullable=True)
    audit_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class PolicyReleaseObjectORM(Base):
    """Immutable policy control rows bound to one policy release (ISSUE-129 / #635)."""

    __tablename__ = "policy_release_object"
    __table_args__ = (
        UniqueConstraint(
            "release_id",
            "control_id",
            name="uq_policy_release_object_release_control_id",
        ),
    )

    object_row_id: Mapped[str] = mapped_column(String, primary_key=True)
    release_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("knowledge_release.release_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    control_id: Mapped[str] = mapped_column(String, nullable=False)
    framework_id: Mapped[str] = mapped_column(String, nullable=False)
    object_hash: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class AttackControlMappingORM(Base):
    """Curated ATT&CK↔control mappings bound to one policy release."""

    __tablename__ = "attack_control_mapping"
    __table_args__ = (
        UniqueConstraint(
            "release_id",
            "mapping_id",
            name="uq_attack_control_mapping_release_mapping_id",
        ),
        Index(
            "ix_attack_control_mapping_release_technique",
            "release_id",
            "technique_id",
        ),
    )

    mapping_row_id: Mapped[str] = mapped_column(String, primary_key=True)
    release_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("knowledge_release.release_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    mapping_id: Mapped[str] = mapped_column(String, nullable=False)
    technique_id: Mapped[str] = mapped_column(String, nullable=False)
    control_id: Mapped[str] = mapped_column(String, nullable=False)
    framework_id: Mapped[str] = mapped_column(String, nullable=False)
    approval_state: Mapped[str] = mapped_column(String, nullable=False)
    mapping_version: Mapped[str] = mapped_column(String, nullable=False)
    provenance: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class ToolCallGrantORM(Base):
    """Authoritative ToolCallGrant ledger (ISSUE-134 / #640)."""

    __tablename__ = "tool_call_grant"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_tool_call_grant_idempotency_key"),
        Index("ix_tool_call_grant_event_id", "event_id"),
        Index("ix_tool_call_grant_namespace_key", "namespace_key"),
        Index("ix_tool_call_grant_mode_namespace", "mode", "namespace_key"),
    )

    grant_id: Mapped[str] = mapped_column(String, primary_key=True)
    mode: Mapped[str] = mapped_column(String, nullable=False)
    namespace_key: Mapped[str] = mapped_column(String, nullable=False)
    shadow_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False)
    plan_step_id: Mapped[str | None] = mapped_column(String, nullable=True)
    task_id: Mapped[str | None] = mapped_column(String, nullable=True)
    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    execution_principal: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    max_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(_TS, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(_TS, nullable=False)
    policy_version: Mapped[str] = mapped_column(String, nullable=False)
    schema_version: Mapped[str] = mapped_column(String, nullable=False)
    grant_token_hash: Mapped[str] = mapped_column(String, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class ToolCallAttemptORM(Base):
    """Grant-bound attempt / audit ledger with shadow namespace isolation."""

    __tablename__ = "tool_call_attempt"
    __table_args__ = (
        UniqueConstraint("grant_id", "attempt_seq", name="uq_tool_call_attempt_grant_seq"),
        Index("ix_tool_call_attempt_grant_id", "grant_id"),
        Index("ix_tool_call_attempt_namespace_key", "namespace_key"),
        Index("ix_tool_call_attempt_event_id", "event_id"),
    )

    attempt_id: Mapped[str] = mapped_column(String, primary_key=True)
    grant_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("tool_call_grant.grant_id", ondelete="CASCADE"),
        nullable=False,
    )
    mode: Mapped[str] = mapped_column(String, nullable=False)
    namespace_key: Mapped[str] = mapped_column(String, nullable=False)
    shadow_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    attempt_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    denial_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    params_hash: Mapped[str] = mapped_column(String, nullable=False)
    result_status: Mapped[str | None] = mapped_column(String, nullable=True)
    projection_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


from app.db.orm.agent_task import (  # noqa: E402,F401
    AgentArtifactORM,
    AgentTaskAttemptORM,
    AgentTaskORM,
)
from app.db.orm.approval import ApprovalRecordORM  # noqa: E402,F401
from app.db.orm.detection_context_snapshot import DetectionContextSnapshotORM  # noqa: E402,F401
from app.db.orm.detection_governance import DetectionGovernanceDecisionORM  # noqa: E402,F401
from app.db.orm.memory_review import MemoryReviewORM  # noqa: E402,F401
from app.db.orm.profile import EntityProfileORM  # noqa: E402,F401
from app.db.orm.shadow_run import (  # noqa: E402,F401
    ShadowDecisionRecordORM,
    ShadowQueryArtifactORM,
    ShadowRunORM,
)

# Explicit exports for ORM classes re-imported from app.db.orm.* (mypy attr-defined).
__all__ = [
    "AgentArtifactORM",
    "AgentTaskAttemptORM",
    "AgentTaskORM",
    "ApprovalRecordORM",
    "DetectionContextSnapshotORM",
    "DetectionGovernanceDecisionORM",
    "EntityProfileORM",
    "MemoryReviewORM",
    "ShadowDecisionRecordORM",
    "ShadowQueryArtifactORM",
    "ShadowRunORM",
]
