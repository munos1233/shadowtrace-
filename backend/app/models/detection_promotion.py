"""Detection production promotion contracts (ISSUE-124 / #629).

Durable saga from governance-approved shadow candidates to SourceAlert/Event via
the canonical SourceIngester → EventService ingest path. EventService remains
the sole producer of correlation outcomes and typed ``IngestResult``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

DETECTION_PROMOTION_SCHEMA_VERSION = "1.0"
DERIVED_DETECTION_ADAPTER_KIND = "derived_detection"
DERIVED_DETECTION_ADAPTER_VERSION = "1.0"


class SourceIngestCorrelationOutcome(StrEnum):
    """Canonical correlation outcome produced exclusively by EventService."""

    CREATED = "created"
    MERGED = "merged"
    DUPLICATE = "duplicate"
    IDEMPOTENT = "idempotent"
    PROMOTED = "promoted"
    RELATED_ONLY = "related_only"


class SourceIngestLinkDisposition(StrEnum):
    """Link role disposition surfaced on typed ingest results."""

    PRIMARY = "primary"
    PROVISIONAL = "provisional"
    RELATED = "related"


class DetectionPromotionStatus(StrEnum):
    """Durable promotion saga states."""

    PENDING = "pending"
    SOURCE_PERSISTED = "source_persisted"
    EVENT_LINKED = "event_linked"
    COMPLETED = "completed"
    RETRY = "retry"
    DEAD = "dead"
    MANUAL = "manual"


class DetectionPromotionReasonCode(StrEnum):
    """Machine-readable promotion failure / gate reason codes."""

    NO_ACTIVE_APPROVAL = "no_active_approval"
    ARTIFACT_HASH_MISMATCH = "artifact_hash_mismatch"
    CANDIDATE_BINDING_MISMATCH = "candidate_binding_mismatch"
    PACKAGE_HASH_MISMATCH = "package_hash_mismatch"
    PACKAGE_NOT_SHADOW_ACTIVE = "package_not_shadow_active"
    CANDIDATE_NOT_FOUND = "candidate_not_found"
    CANDIDATE_NOT_SHADOW = "candidate_not_shadow"
    CANDIDATE_HASH_MISMATCH = "candidate_hash_mismatch"
    SCOPE_MISMATCH = "scope_mismatch"
    DERIVED_CONNECTOR_RECURSION = "derived_connector_recursion"
    INGEST_FAILED = "ingest_failed"
    PACKAGE_TRANSITION_BLOCKED = "package_transition_blocked"
    PROMOTION_SUPERSEDED = "promotion_superseded"
    CONTEXT_PROJECTION_FAILED = "context_projection_failed"


class TypedIngestResult(BaseModel):
    """EventService-owned ingest result contract extended for #629."""

    model_config = ConfigDict(extra="forbid")

    source_record_id: str = Field(..., min_length=1, max_length=128)
    event_id: str | None = Field(default=None, max_length=128)
    accepted: bool = True
    created: bool = False
    promoted: bool = False
    related_only: bool = False
    idempotent: bool = False
    duplicate: bool = False
    source_object_id: str | None = Field(default=None, max_length=256)
    source_revision: int | None = Field(default=None, ge=1)
    correlation_outcome: SourceIngestCorrelationOutcome | None = None
    event_revision: int | None = Field(default=None, ge=1)
    link_disposition: SourceIngestLinkDisposition | None = None
    error_code: str | None = Field(default=None, max_length=64)
    error_message: str | None = Field(default=None, max_length=512)


class DetectionPromotionRequest(BaseModel):
    """Input to promote one immutable shadow candidate after governance approval."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(..., min_length=1, max_length=128)
    candidate_detection_id: str = Field(..., min_length=1, max_length=128)
    decision_id: str | None = Field(
        default=None,
        max_length=128,
        description="Optional explicit governance decision; resolved from gate when omitted.",
    )


class DetectionContextProjectionError(BaseModel):
    """Structured detection context projection failure surfaced on promotion results."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=128)
    message: str = Field(default="", max_length=512)
    recorded_at: datetime | None = None


class DetectionPromotionRecord(BaseModel):
    """Immutable promotion ledger row (append-only status transitions)."""

    model_config = ConfigDict(extra="forbid")

    promotion_id: str = Field(..., min_length=1, max_length=128)
    schema_version: str = Field(default=DETECTION_PROMOTION_SCHEMA_VERSION, min_length=1)
    tenant_id: str = Field(..., min_length=1, max_length=128)
    promotion_key: str = Field(..., min_length=1, max_length=512)
    status: DetectionPromotionStatus
    decision_id: str = Field(..., min_length=1, max_length=128)
    candidate_detection_id: str = Field(..., min_length=1, max_length=128)
    candidate_content_hash: str = Field(..., min_length=64, max_length=64)
    package_id: str = Field(..., min_length=1, max_length=128)
    package_version: int = Field(..., ge=1)
    package_content_hash: str = Field(..., min_length=64, max_length=64)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    scope_revision_id: str | None = Field(default=None, max_length=128)
    derived_connector_id: str | None = Field(default=None, max_length=128)
    source_record_id: str | None = Field(default=None, max_length=128)
    event_id: str | None = Field(default=None, max_length=128)
    link_revision: int = Field(default=1, ge=1)
    ingest_result: TypedIngestResult | None = None
    context_projection_error: DetectionContextProjectionError | None = None
    reason_codes: list[DetectionPromotionReasonCode] = Field(default_factory=list)
    reason_message: str = Field(default="", max_length=1024)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class DetectionPromotionResult(BaseModel):
    """Service output for one promotion attempt (terminal or resumable)."""

    model_config = ConfigDict(extra="forbid")

    promotion_id: str
    status: DetectionPromotionStatus
    record: DetectionPromotionRecord
    ingest_result: TypedIngestResult | None = None
    resumed: bool = False
    context_projection_error: DetectionContextProjectionError | None = None


class DerivedDetectionConnectorRecord(BaseModel):
    """Persisted derived connector identity bound to one detection scope."""

    model_config = ConfigDict(extra="forbid")

    connector_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    scope_revision_id: str | None = Field(default=None, max_length=128)
    adapter_kind: str = Field(default=DERIVED_DETECTION_ADAPTER_KIND, min_length=1)
    adapter_version: str = Field(default=DERIVED_DETECTION_ADAPTER_VERSION, min_length=1)
    disposition_policy: str = Field(
        default="not_required",
        description="Derived connectors must not pollute production checkpoint/writeback.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "DERIVED_DETECTION_ADAPTER_KIND",
    "DERIVED_DETECTION_ADAPTER_VERSION",
    "DETECTION_PROMOTION_SCHEMA_VERSION",
    "DerivedDetectionConnectorRecord",
    "DetectionContextProjectionError",
    "DetectionPromotionReasonCode",
    "DetectionPromotionRecord",
    "DetectionPromotionRequest",
    "DetectionPromotionResult",
    "DetectionPromotionStatus",
    "SourceIngestCorrelationOutcome",
    "SourceIngestLinkDisposition",
    "TypedIngestResult",
]
