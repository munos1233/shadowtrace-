"""Versioned detection governance policy (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.evaluation.detection.artifact import compute_detection_artifact_hash
from app.evaluation.detection.metrics import quality_report_has_blocking_metrics
from app.evaluation.paths import REPO_ROOT
from app.evaluation.threshold import load_threshold_manifest, validate_threshold_manifest_for_run
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_governance import (
    DetectionGovernanceEligibilityAssessment,
    DetectionGovernanceReasonCode,
)
from app.models.evaluation_quality import EvaluationQualityReport
from app.models.evaluation_run import EvaluationRunStatus, GateVerdict

logger = logging.getLogger(__name__)

DETECTION_GOVERNANCE_POLICY_VERSION = "issue125_v1"
DETECTION_GOVERNANCE_POLICY_SOURCE = "detection_governance_policy_v1"
DEFAULT_POLICY_PATH = REPO_ROOT / "data" / "governance" / "detection_governance_policy_v1.json"
REQUIRED_GOVERNANCE_METRIC_IDS = frozenset({"threat_recall", "benign_specificity"})


@dataclass(frozen=True, slots=True)
class DetectionGovernancePolicyConfig:
    policy_version: str
    max_runtime_errors: int
    max_unevaluable_count: int
    require_gate_pass: bool
    require_human_reviewer_for_approve: bool
    default_approval_ttl_hours: int


def load_detection_governance_policy(
    path: Path | None = None,
) -> DetectionGovernancePolicyConfig:
    """Load versioned governance thresholds from the repo policy manifest."""
    policy_path = path or DEFAULT_POLICY_PATH
    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    version = str(raw.get("policy_version", "")).strip()
    if version != DETECTION_GOVERNANCE_POLICY_VERSION:
        raise ValueError(
            f"policy_version mismatch: file={version!r} "
            f"expected={DETECTION_GOVERNANCE_POLICY_VERSION!r}"
        )
    return DetectionGovernancePolicyConfig(
        policy_version=version,
        max_runtime_errors=int(raw.get("max_runtime_errors", 0)),
        max_unevaluable_count=int(raw.get("max_unevaluable_count", 0)),
        require_gate_pass=bool(raw.get("require_gate_pass", True)),
        require_human_reviewer_for_approve=bool(
            raw.get("require_human_reviewer_for_approve", True)
        ),
        default_approval_ttl_hours=int(raw.get("default_approval_ttl_hours", 168)),
    )


@lru_cache(maxsize=1)
def get_detection_governance_policy() -> DetectionGovernancePolicyConfig:
    return load_detection_governance_policy()


def _quality_report_meets_requirements(
    quality_report: EvaluationQualityReport | None,
) -> tuple[bool, DetectionGovernanceReasonCode | None, str | None]:
    if quality_report is None:
        return (
            False,
            DetectionGovernanceReasonCode.ARTIFACT_INCOMPLETE,
            "quality report missing",
        )
    present = {metric.metric_id for metric in quality_report.metrics}
    missing = REQUIRED_GOVERNANCE_METRIC_IDS - present
    if missing:
        return (
            False,
            DetectionGovernanceReasonCode.QUALITY_METRIC_FAIL_CLOSED,
            f"missing required metrics: {sorted(missing)}",
        )
    if quality_report_has_blocking_metrics(quality_report):
        return (
            False,
            DetectionGovernanceReasonCode.QUALITY_METRIC_FAIL_CLOSED,
            "quality report contains fail-closed or insufficient-sample metrics",
        )
    return True, None, None


def assess_governance_eligibility(
    artifact: DetectionEvaluationArtifact,
    *,
    threshold_manifest_path: Path | None = None,
    policy: DetectionGovernancePolicyConfig | None = None,
) -> DetectionGovernanceEligibilityAssessment:
    """Fail-closed eligibility for human/system approve decisions."""
    cfg = policy or get_detection_governance_policy()
    reason_codes: list[DetectionGovernanceReasonCode] = []
    messages: list[str] = []

    if not artifact.config.candidate_set_hash.strip():
        reason_codes.append(DetectionGovernanceReasonCode.ARTIFACT_INCOMPLETE)
        messages.append("evaluation artifact missing candidate_set_hash")

    if not artifact.artifact_hash:
        reason_codes.append(DetectionGovernanceReasonCode.ARTIFACT_INCOMPLETE)
        messages.append("evaluation artifact missing artifact_hash")
    else:
        computed = compute_detection_artifact_hash(artifact)
        if computed != artifact.artifact_hash:
            reason_codes.append(DetectionGovernanceReasonCode.ARTIFACT_HASH_MISMATCH)
            messages.append("evaluation artifact hash mismatch; artifact is stale or tampered")

    if artifact.status != EvaluationRunStatus.COMPLETED:
        reason_codes.append(DetectionGovernanceReasonCode.ARTIFACT_STATUS_FAILED)
        messages.append(f"evaluation run status is {artifact.status.value}")

    gate = artifact.gate
    if gate is None:
        reason_codes.append(DetectionGovernanceReasonCode.GATE_FAIL_CLOSED)
        messages.append("evaluation gate missing")
    elif gate.verdict == GateVerdict.FAIL_CLOSED:
        reason_codes.append(DetectionGovernanceReasonCode.GATE_FAIL_CLOSED)
        messages.append("evaluation gate fail-closed")
    elif cfg.require_gate_pass and gate.verdict != GateVerdict.PASS:
        reason_codes.append(DetectionGovernanceReasonCode.GATE_NOT_PASS)
        messages.append(f"evaluation gate verdict is {gate.verdict.value}")

    ok, metric_reason, metric_message = _quality_report_meets_requirements(artifact.quality_report)
    if not ok and metric_reason is not None:
        reason_codes.append(metric_reason)
        if metric_message:
            messages.append(metric_message)

    if artifact.tenant_safety.probe_count <= 0:
        reason_codes.append(DetectionGovernanceReasonCode.TENANT_ISOLATION_FAILED)
        messages.append("tenant isolation probes were not executed")
    elif artifact.tenant_safety.fail_count > 0:
        reason_codes.append(DetectionGovernanceReasonCode.TENANT_ISOLATION_FAILED)
        messages.append("tenant isolation probes failed")

    if artifact.aggregates.required_scorer_error_count > 0:
        reason_codes.append(DetectionGovernanceReasonCode.REQUIRED_SCORER_ERRORS)
        messages.append("required scorer errors present")

    if artifact.resource_summary.total_runtime_errors > cfg.max_runtime_errors:
        reason_codes.append(DetectionGovernanceReasonCode.RUNTIME_ERROR_BUDGET_EXCEEDED)
        messages.append("shadow runtime error budget exceeded")

    if artifact.aggregates.unevaluable_count > cfg.max_unevaluable_count:
        reason_codes.append(DetectionGovernanceReasonCode.QUALITY_METRIC_INSUFFICIENT_SAMPLE)
        messages.append("unevaluable case count exceeds policy limit")

    threshold_manifest_validated = False
    if threshold_manifest_path is None:
        reason_codes.append(DetectionGovernanceReasonCode.THRESHOLD_MANIFEST_MISSING)
        messages.append("threshold_manifest_path required for governance eligibility")
    else:
        try:
            manifest = load_threshold_manifest(threshold_manifest_path)
            validate_threshold_manifest_for_run(
                manifest,
                dataset_id=artifact.dataset_id,
                dataset_version=artifact.dataset_version,
            )
            gate_version = gate.manifest_version if gate is not None else None
            if gate_version and gate_version != manifest.manifest_version:
                reason_codes.append(DetectionGovernanceReasonCode.THRESHOLD_MANIFEST_MISMATCH)
                messages.append(
                    "artifact gate manifest_version does not match supplied threshold manifest"
                )
            else:
                threshold_manifest_validated = True
        except Exception:  # noqa: BLE001 — surface as fail-closed eligibility
            reason_codes.append(DetectionGovernanceReasonCode.THRESHOLD_MANIFEST_MISMATCH)
            messages.append("threshold manifest validation failed")

    eligible = not reason_codes
    return DetectionGovernanceEligibilityAssessment(
        eligible=eligible,
        threshold_manifest_validated=threshold_manifest_validated,
        reason_codes=reason_codes,
        messages=messages,
    )


__all__ = [
    "DEFAULT_POLICY_PATH",
    "DetectionGovernancePolicyConfig",
    "REQUIRED_GOVERNANCE_METRIC_IDS",
    "DETECTION_GOVERNANCE_POLICY_SOURCE",
    "DETECTION_GOVERNANCE_POLICY_VERSION",
    "assess_governance_eligibility",
    "get_detection_governance_policy",
    "load_detection_governance_policy",
]
