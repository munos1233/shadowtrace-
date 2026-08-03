"""Detection offline/shadow evaluation artifact contract (ISSUE-126 / #631 Phase A).

Pre-promotion evaluation consumes canonical ``EvaluationCaseTruth`` (#618),
shadow runtime outputs (#626–#628), and pinned candidate package/model hashes.
This artifact is immutable input for #630 governance — **not** an approval.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.detection_rule import CandidateDetection, DetectionRuleRuntimeError
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationGateResult,
    EvaluationRunStatus,
    EvaluationScorerResult,
)
from app.models.evaluation_truth import SliceType

if TYPE_CHECKING:
    from app.models.evaluation_quality import EvaluationQualityReport

DETECTION_EVALUATION_SCHEMA_VERSION = "1.0"


class DetectionCandidateRefs(BaseModel):
    """Pinned candidate package/model/rule identity bound into the artifact."""

    model_config = ConfigDict(extra="forbid")

    package_id: str = Field(..., min_length=1, max_length=128)
    package_version: int = Field(..., ge=1)
    package_content_hash: str = Field(..., min_length=64, max_length=64)
    rule_ids: list[str] = Field(default_factory=list, max_length=64)
    feature_contract_version: str = Field(..., min_length=1, max_length=32)
    detection_scope_id: str = Field(..., min_length=1, max_length=128)
    scope_revision_id: str | None = Field(default=None, max_length=128)
    model_release_id: str | None = Field(default=None, max_length=128)
    model_release_hash: str | None = Field(default=None, max_length=64)


class DetectionResourceMetrics(BaseModel):
    """Per-case shadow runtime resource accounting."""

    model_config = ConfigDict(extra="forbid")

    rules_evaluated: int = Field(default=0, ge=0)
    observations_scanned: int = Field(default=0, ge=0)
    runtime_error_count: int = Field(default=0, ge=0)
    candidate_count: int = Field(default=0, ge=0)
    replay_duration_ms: int = Field(default=0, ge=0)


class DetectionCaseObservation(BaseModel):
    """Shadow replay observation for one detection evaluation case."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., min_length=1)
    slice_type: SliceType
    candidates: list[CandidateDetection] = Field(default_factory=list)
    runtime_errors: list[DetectionRuleRuntimeError] = Field(default_factory=list)
    resource_metrics: DetectionResourceMetrics = Field(default_factory=DetectionResourceMetrics)
    observation_available: bool = True
    replay_cutoff_at: datetime | None = None
    replay_notes: str = Field(default="", max_length=512)


class DetectionCaseResult(BaseModel):
    """Aggregated per-case detection evaluation output."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., min_length=1)
    truth_id: str = Field(..., min_length=1)
    truth_revision: int = Field(..., ge=1)
    truth_content_hash: str = Field(..., min_length=64, max_length=64)
    slice_type: SliceType
    observation: DetectionCaseObservation
    scorer_results: list[EvaluationScorerResult] = Field(default_factory=list)
    case_status: EvaluationRunStatus
    unevaluable_reason: str | None = None
    candidate_refs: DetectionCandidateRefs | None = None


class DetectionResourceSummary(BaseModel):
    """Dataset-level resource rollups for shadow evaluation runs."""

    model_config = ConfigDict(extra="forbid")

    total_rules_evaluated: int = Field(default=0, ge=0)
    total_observations_scanned: int = Field(default=0, ge=0)
    total_runtime_errors: int = Field(default=0, ge=0)
    total_candidates: int = Field(default=0, ge=0)
    max_observations_scanned_per_case: int = Field(default=0, ge=0)
    total_replay_duration_ms: int = Field(default=0, ge=0)
    max_replay_duration_ms_per_case: int = Field(default=0, ge=0)


class DetectionTenantSafetyProbe(BaseModel):
    """Result of one cross-tenant isolation probe."""

    model_config = ConfigDict(extra="forbid")

    probe_id: str = Field(..., min_length=1, max_length=128)
    source_tenant_id: str = Field(..., min_length=1, max_length=128)
    probe_tenant_id: str = Field(..., min_length=1, max_length=128)
    passed: bool
    reason_code: str = Field(default="", max_length=64)
    message: str = Field(default="", max_length=512)


class DetectionTenantSafetySummary(BaseModel):
    """Rollup of tenant isolation probes executed during evaluation."""

    model_config = ConfigDict(extra="forbid")

    probe_count: int = Field(default=0, ge=0)
    pass_count: int = Field(default=0, ge=0)
    fail_count: int = Field(default=0, ge=0)
    probes: list[DetectionTenantSafetyProbe] = Field(default_factory=list)


class DetectionEvaluationConfig(BaseModel):
    """Frozen detection evaluation configuration bound into the artifact."""

    model_config = ConfigDict(extra="forbid")

    seed: int = Field(..., ge=0)
    cutoff_at: datetime
    effective_cutoff_at: datetime | None = Field(
        default=None,
        description="Max per-case replay cutoff bound into the artifact (>= manifest default).",
    )
    replay_mode: str = Field(default="detection_shadow", min_length=1)
    replay_fidelity: str = Field(
        default="shadow_runtime_v1",
        min_length=1,
        description=(
            "Shadow runtime replay against #624–#628 outputs. "
            "Does not use post-promotion Event severity or agent conclusions."
        ),
    )
    candidate_refs: DetectionCandidateRefs = Field(
        ...,
        description=(
            "Primary (first) candidate package refs for backward compatibility. "
            "Prefer candidate_refs_entries for full multi-package provenance."
        ),
    )
    candidate_refs_entries: list[DetectionCandidateRefs] = Field(
        default_factory=list,
        description="Complete pinned candidate package/model refs across all replay fixtures.",
    )
    candidate_set_hash: str = Field(
        default="",
        min_length=0,
        max_length=64,
        description="Deterministic hash over sorted candidate_refs_entries.",
    )
    scorer_ids: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class DetectionEvaluationArtifact(BaseModel):
    """Complete pre-promotion detection evaluation artifact (JSON, not a fact DB)."""

    model_config = ConfigDict(extra="forbid")

    evaluation_id: str = Field(..., min_length=1)
    schema_version: str = Field(default=DETECTION_EVALUATION_SCHEMA_VERSION, min_length=1)
    tenant_id: str = Field(..., min_length=1)
    dataset_id: str = Field(..., min_length=1)
    dataset_version: str = Field(..., min_length=1)
    dataset_content_hash: str = Field(..., min_length=64, max_length=64)
    code_sha: str = Field(..., min_length=7, max_length=64)
    config: DetectionEvaluationConfig
    started_at: datetime
    completed_at: datetime
    status: EvaluationRunStatus
    case_results: list[DetectionCaseResult] = Field(default_factory=list)
    aggregates: EvaluationAggregateMetrics
    gate: EvaluationGateResult | None = None
    quality_report: EvaluationQualityReport | None = None
    resource_summary: DetectionResourceSummary = Field(default_factory=DetectionResourceSummary)
    tenant_safety: DetectionTenantSafetySummary = Field(
        default_factory=DetectionTenantSafetySummary
    )
    errors: list[str] = Field(default_factory=list)
    artifact_hash: str = Field(default="", min_length=0, max_length=64)
    approval_note: str = Field(
        default="Not a governance approval; consume via #630 only.",
        max_length=256,
    )


__all__ = [
    "DETECTION_EVALUATION_SCHEMA_VERSION",
    "DetectionCandidateRefs",
    "DetectionCaseObservation",
    "DetectionCaseResult",
    "DetectionEvaluationArtifact",
    "DetectionEvaluationConfig",
    "DetectionResourceMetrics",
    "DetectionResourceSummary",
    "DetectionTenantSafetyProbe",
    "DetectionTenantSafetySummary",
]


def _rebuild_with_quality_report() -> None:
    from app.models.evaluation_quality import EvaluationQualityReport

    DetectionEvaluationArtifact.model_rebuild(
        _types_namespace={"EvaluationQualityReport": EvaluationQualityReport}
    )


_rebuild_with_quality_report()
