"""Detection promotion saga API (ISSUE-124 / #629)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.v1 import schemas as s
from app.api.v1.deps import DetectionPromotionDep
from app.core.auth import ROLE_ANALYST, ROLE_APPROVER, Principal, require_roles
from app.core.errors import ValidationError
from app.evaluation.detection.artifact_io import load_evaluation_artifact
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_promotion import (
    DetectionPromotionRequest,
    DetectionPromotionStatus,
)
from app.services.detection_governance_service import assert_governance_tenant_access

router = APIRouter(tags=["detection-promotion"])


def _record_response(record: object) -> s.DetectionPromotionRecordResponse:
    dumped = record.model_dump(mode="json") if hasattr(record, "model_dump") else record
    return s.DetectionPromotionRecordResponse.model_validate(dumped)


def _result_response(result: object) -> s.DetectionPromotionResultResponse:
    dumped = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
    return s.DetectionPromotionResultResponse.model_validate(dumped)


def _parse_status(raw: str | None) -> DetectionPromotionStatus | None:
    if raw is None or not raw.strip():
        return None
    try:
        return DetectionPromotionStatus(raw.strip())
    except ValueError as exc:
        raise ValidationError(
            "invalid detection promotion status",
            details={"status": raw},
        ) from exc


@router.post(
    "/detection/promotions",
    response_model=s.DetectionPromotionResultResponse,
)
async def create_detection_promotion(
    body: s.DetectionPromotionCreateRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
    promotion: DetectionPromotionDep,
) -> s.DetectionPromotionResultResponse:
    assert_governance_tenant_access(principal, body.tenant_id)
    if body.artifact is not None:
        artifact = DetectionEvaluationArtifact.model_validate(body.artifact)
    else:
        artifact, _relative = load_evaluation_artifact(body.artifact_path or "")
    assert_governance_tenant_access(principal, artifact.tenant_id)
    request = DetectionPromotionRequest(
        tenant_id=body.tenant_id,
        candidate_detection_id=body.candidate_detection_id,
        decision_id=body.decision_id,
    )
    result = await promotion.promote_candidate(artifact, request)
    return _result_response(result)


@router.get(
    "/detection/promotions",
    response_model=s.DetectionPromotionListResponse,
)
async def list_detection_promotions(
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    promotion: DetectionPromotionDep,
    candidate_detection_id: str | None = Query(default=None, max_length=128),
    status: str | None = Query(default=None, max_length=32),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
) -> s.DetectionPromotionListResponse:
    assert_governance_tenant_access(principal, tenant_id)
    offset = (page - 1) * page_size
    items, total = await promotion.list_promotions(
        tenant_id=tenant_id,
        candidate_detection_id=candidate_detection_id,
        status=_parse_status(status),
        limit=page_size,
        offset=offset,
    )
    return s.DetectionPromotionListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[_record_response(item) for item in items],
    )


@router.get(
    "/detection/promotions/{promotion_id}",
    response_model=s.DetectionPromotionRecordResponse,
)
async def get_detection_promotion(
    promotion_id: str,
    tenant_id: Annotated[str, Query(min_length=1, max_length=128)],
    principal: Annotated[Principal, require_roles(ROLE_ANALYST, ROLE_APPROVER)],
    promotion: DetectionPromotionDep,
) -> s.DetectionPromotionRecordResponse:
    assert_governance_tenant_access(principal, tenant_id)
    record = await promotion.get_promotion(promotion_id, tenant_id=tenant_id)
    return _record_response(record)
