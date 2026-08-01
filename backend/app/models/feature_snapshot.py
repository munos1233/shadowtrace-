"""FeatureSnapshot and DetectionFeatureBaseline — ISSUE-120 Phase A/B (#625).

Event-time feature materialization over ``BehaviorObservation`` rows scoped by
``detection_scope_id``. Cutoff/watermark semantics prevent training leakage;
cold-start states are explicit (no zero-fill masquerading as signal).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

FEATURE_SNAPSHOT_SCHEMA_VERSION = "1.0"
FEATURE_CONTRACT_VERSION = "1.0"
BASELINE_SCHEMA_VERSION = "1.0"

# Phase A minimum observations before READY (window-specific thresholds in resolver).
MIN_OBSERVATIONS_1H = 3
MIN_OBSERVATIONS_24H = 5
MIN_OBSERVATIONS_7D = 10
MIN_OBSERVATIONS_30D = 20

DEFAULT_ALLOWED_LATENESS = timedelta(minutes=15)


class FeatureWindowKind(StrEnum):
    """Supported event-time aggregation windows."""

    ONE_HOUR = "1h"
    TWENTY_FOUR_HOURS = "24h"
    SEVEN_DAYS = "7d"
    THIRTY_DAYS = "30d"


PHASE_A_WINDOW_KINDS = frozenset({FeatureWindowKind.ONE_HOUR, FeatureWindowKind.TWENTY_FOUR_HOURS})
PHASE_B_WINDOW_KINDS = frozenset({FeatureWindowKind.SEVEN_DAYS, FeatureWindowKind.THIRTY_DAYS})


class FeatureSnapshotStatus(StrEnum):
    """Materialization outcome — never infer readiness from zero-filled features."""

    READY = "ready"
    INSUFFICIENT_HISTORY = "insufficient_history"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"


class DetectionBaselineStatus(StrEnum):
    """Baseline readiness over historical snapshots (as-of cutoff)."""

    READY = "ready"
    INSUFFICIENT_HISTORY = "insufficient_history"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"


class FeatureSnapshotProvenance(BaseModel):
    """Observation anchors included in the snapshot body."""

    model_config = ConfigDict(extra="forbid")

    observation_ids: list[str] = Field(default_factory=list, max_length=256)
    observation_count: int = Field(..., ge=0)
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None


class FeatureSnapshot(BaseModel):
    """Immutable event-time feature vector for one entity/window/cutoff revision."""

    model_config = ConfigDict(extra="forbid")

    snapshot_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    entity_type: str = Field(..., min_length=1, max_length=64)
    entity_id: str = Field(..., min_length=1, max_length=256)
    feature_contract_version: str = Field(default=FEATURE_CONTRACT_VERSION, min_length=1)
    window_kind: FeatureWindowKind
    window_start: datetime
    window_end: datetime
    cutoff_at: datetime = Field(
        ...,
        description=(
            "As-of event-time watermark — observations with observed_at > cutoff are excluded."
        ),
    )
    allowed_lateness_seconds: int = Field(default=900, ge=0)
    source_watermark: datetime = Field(
        ...,
        description="Effective processed event-time high-water mark for this materialization.",
    )
    status: FeatureSnapshotStatus
    features: dict[str, Any] = Field(default_factory=dict)
    provenance: FeatureSnapshotProvenance
    revision: int = Field(default=1, ge=1)
    supersedes_snapshot_id: str | None = Field(default=None, max_length=128)
    content_hash: str = Field(..., min_length=64, max_length=64)
    cache_key: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="Durable cache key — identical to content_hash.",
    )
    idempotency_key: str = Field(..., min_length=1, max_length=512)
    schema_version: str = Field(default=FEATURE_SNAPSHOT_SCHEMA_VERSION, min_length=1)
    created_at: datetime | None = None

    @field_validator("cache_key")
    @classmethod
    def _cache_key_matches_content_hash(cls, value: str, info: Any) -> str:
        content_hash = info.data.get("content_hash")
        if content_hash is not None and value != content_hash:
            raise ValueError("cache_key must equal content_hash")
        return value


class SeasonalityProfile(BaseModel):
    """Phase B hour-of-week activity shape derived from historical snapshots."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="1.0", min_length=1)
    hour_of_week: dict[str, int] = Field(default_factory=dict)
    sample_snapshot_count: int = Field(default=0, ge=0)


class DetectionFeatureBaseline(BaseModel):
    """Rolling baseline stats from snapshots at or before cutoff (no post-cutoff leakage)."""

    model_config = ConfigDict(extra="forbid")

    baseline_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    entity_type: str = Field(..., min_length=1, max_length=64)
    entity_id: str = Field(..., min_length=1, max_length=256)
    peer_group_id: str | None = Field(default=None, max_length=128)
    feature_contract_version: str = Field(default=FEATURE_CONTRACT_VERSION, min_length=1)
    window_kind: FeatureWindowKind
    cutoff_at: datetime
    status: DetectionBaselineStatus
    stats: dict[str, Any] = Field(default_factory=dict)
    seasonality_profile: SeasonalityProfile | None = None
    snapshot_revision_refs: list[str] = Field(default_factory=list, max_length=64)
    revision: int = Field(default=1, ge=1)
    supersedes_baseline_id: str | None = Field(default=None, max_length=128)
    content_hash: str = Field(..., min_length=64, max_length=64)
    cache_key: str = Field(..., min_length=64, max_length=64)
    idempotency_key: str = Field(..., min_length=1, max_length=512)
    schema_version: str = Field(default=BASELINE_SCHEMA_VERSION, min_length=1)
    created_at: datetime | None = None

    @field_validator("cache_key")
    @classmethod
    def _baseline_cache_key_matches(cls, value: str, info: Any) -> str:
        content_hash = info.data.get("content_hash")
        if content_hash is not None and value != content_hash:
            raise ValueError("cache_key must equal content_hash")
        return value


class FeatureSnapshotQuery(BaseModel):
    """Tenant-scoped snapshot reads."""

    model_config = ConfigDict(extra="forbid")

    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str | None = Field(default=None, max_length=128)
    entity_type: str | None = Field(default=None, max_length=64)
    entity_id: str | None = Field(default=None, max_length=256)
    window_kind: FeatureWindowKind | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class FeatureSnapshotListResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    items: list[FeatureSnapshot] = Field(default_factory=list)


class DetectionFeatureBaselineQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    detection_scope_id: str | None = Field(default=None, max_length=128)
    entity_type: str | None = Field(default=None, max_length=64)
    entity_id: str | None = Field(default=None, max_length=256)
    peer_group_id: str | None = Field(default=None, max_length=128)
    window_kind: FeatureWindowKind | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class DetectionFeatureBaselineListResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    items: list[DetectionFeatureBaseline] = Field(default_factory=list)
