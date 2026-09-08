"""Detection governance decision API (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.v1 import schemas as s
from app.api.v1.deps import DetectionGovernanceDep, DetectionRuleRuntimeDep
from app.core.auth import ROLE_ANALYST, ROLE_APPROVER, Principal, require_roles
from app.evaluation.detection.artifact_io import (
    list_evaluation_artifact_summaries,
    load_evaluation_artifact,
)
from app.evaluation.threshold import confine_threshold_manifest_path
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_governance import (
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
    DetectionGovernanceRevokeRequest,
)
from app.models.detection_rule import CandidateDetectionQuery

router = APIRouter(tags=["detection-governance"])


def _confined_manifest_path(raw: str | None) -> Path | None:
    stripped = (raw or "").strip()
    if not stripped:
        return None
    return confine_threshold_manifest_path(Path(stripped))


@router.post(
    "/detection/governance/eligibility",
    response_model=s.DetectionGovernanceEligibilityResponse,
)
async def assess_detection_governance_eligibility(
    body: s.DetectionGovernanceEligibilityRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceEligibilityResponse:
    artifact = DetectionEvaluationArtifact.model_validate(body.artifact)
    assessment = await governance.assess_eligibility(
        artifact,
        threshold_manifest_path=_confined_manifest_path(body.threshold_manifest_path),
        principal=principal,
    )
    return s.DetectionGovernanceEligibilityResponse.model_validate(assessment.model_dump())


@router.post(
    "/detection/governance/decisions",
    response_model=s.DetectionGovernanceDecisionResponse,
)
async def record_detection_governance_decision(
    body: s.DetectionGovernanceDecisionCreateRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceDecisionResponse:
    artifact = DetectionEvaluationArtifact.model_validate(body.artifact)
    request = DetectionGovernanceDecisionRequest(
        decision=DetectionGovernanceDecisionKind(body.decision),
        reason_note=body.reason_note,
        expires_at=body.expires_at,
    )
    decision = await governance.record_decision(
        principal,
        artifact,
        request,
        threshold_manifest_path=_confined_manifest_path(body.threshold_manifest_path),
    )
    return s.DetectionGovernanceDecisionResponse.model_validate(decision.model_dump())


@router.get(
    "/detection/governance/decisions/{decision_id}",
    response_model=s.DetectionGovernanceDecisionResponse,
)
async def get_detection_governance_decision(
    decision_id: str,
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceDecisionResponse:
    decision = await governance.get_decision(decision_id, tenant_id=tenant_id, principal=principal)
    return s.DetectionGovernanceDecisionResponse.model_validate(decision.model_dump())


@router.get(
    "/detection/governance/decisions",
    response_model=s.DetectionGovernanceDecisionListResponse,
)
async def list_detection_governance_decisions(
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
    binding_hash: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
) -> s.DetectionGovernanceDecisionListResponse:
    offset = (page - 1) * page_size
    items, total = await governance.list_decisions(
        tenant_id=tenant_id,
        binding_hash=binding_hash,
        limit=page_size,
        offset=offset,
        principal=principal,
    )
    return s.DetectionGovernanceDecisionListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[
            s.DetectionGovernanceDecisionResponse.model_validate(item.model_dump())
            for item in items
        ],
    )


@router.post(
    "/detection/governance/decisions/{decision_id}/revoke",
    response_model=s.DetectionGovernanceDecisionResponse,
)
async def revoke_detection_governance_decision(
    decision_id: str,
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    body: DetectionGovernanceRevokeRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceDecisionResponse:
    decision = await governance.revoke_decision(
        principal,
        decision_id,
        reason_note=body.reason_note,
        tenant_id=tenant_id,
    )
    return s.DetectionGovernanceDecisionResponse.model_validate(decision.model_dump())


@router.post(
    "/detection/governance/promotion-gate",
    response_model=s.DetectionGovernancePromotionGateResponse,
)
async def evaluate_detection_promotion_gate(
    body: s.DetectionGovernancePromotionGateRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernancePromotionGateResponse:
    artifact = DetectionEvaluationArtifact.model_validate(body.artifact)
    result = await governance.evaluate_promotion_gate(
        artifact,
        binding_hash=body.binding_hash,
        principal=principal,
    )
    return s.DetectionGovernancePromotionGateResponse.model_validate(result.model_dump())


@router.get(
    "/detection/evaluation/artifacts",
    response_model=s.DetectionEvaluationArtifactListResponse,
)
async def list_detection_evaluation_artifacts(
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    root: str = Query(default="detection_shadow_v1", min_length=1, max_length=256),
) -> s.DetectionEvaluationArtifactListResponse:
    del principal
    items = list_evaluation_artifact_summaries(root)
    return s.DetectionEvaluationArtifactListResponse(
        items=[s.DetectionEvaluationArtifactSummary.model_validate(item) for item in items]
    )


@router.get(
    "/detection/evaluation/artifacts/by-path",
    response_model=s.DetectionEvaluationArtifactResponse,
)
async def get_detection_evaluation_artifact_by_path(
    path: Annotated[str, Query(min_length=1, max_length=512)],
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
) -> s.DetectionEvaluationArtifactResponse:
    del principal
    artifact, relative = load_evaluation_artifact(path)
    return s.DetectionEvaluationArtifactResponse(
        path=relative,
        artifact=artifact.model_dump(mode="json"),
    )


@router.get(
    "/detection/candidates",
    response_model=s.DetectionCandidateListResponse,
)
async def list_detection_candidates(
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    runtime: DetectionRuleRuntimeDep,
    package_id: str | None = Query(default=None, max_length=128),
    detection_scope_id: str | None = Query(default=None, max_length=128),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> s.DetectionCandidateListResponse:
    del principal
    result = await runtime.query_candidates(
        CandidateDetectionQuery(
            source_tenant_id=tenant_id,
            package_id=package_id,
            detection_scope_id=detection_scope_id,
            page=page,
            page_size=page_size,
        )
    )
    return s.DetectionCandidateListResponse(
        total=result.total,
        page=result.page,
        page_size=result.page_size,
        items=[item.model_dump(mode="json") for item in result.items],
    )


@router.post(
    "/detection/governance/decisions/from-path",
    response_model=s.DetectionGovernanceDecisionResponse,
)
async def record_detection_governance_decision_from_path(
    body: s.DetectionGovernanceDecisionFromPathRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
    governance: DetectionGovernanceDep,
) -> s.DetectionGovernanceDecisionResponse:
    artifact, _relative = load_evaluation_artifact(body.artifact_path)
    request = DetectionGovernanceDecisionRequest(
        decision=DetectionGovernanceDecisionKind(body.decision),
        reason_note=body.reason_note,
        expires_at=body.expires_at,
    )
    decision = await governance.record_decision(
        principal,
        artifact,
        request,
        threshold_manifest_path=_confined_manifest_path(body.threshold_manifest_path),
    )
    return s.DetectionGovernanceDecisionResponse.model_validate(decision.model_dump())
