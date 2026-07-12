"""Action approval / adjudication endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.core.auth import ROLE_ADMIN, ROLE_APPROVER, Principal, require_roles

router = APIRouter(tags=["actions"])


@router.post("/actions/{action_id}/approve", response_model=s.ActionOperationResponse)
async def approve_action(
    action_id: str,
    body: s.ActionApproveRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
) -> s.ActionOperationResponse:
    # operator is the authenticated subject; the body can never specify it.
    return s.ActionOperationResponse(
        action_id=action_id, status="approved", decision_id=body.decision_id, message="approved"
    )


@router.post("/actions/{action_id}/reject", response_model=s.ActionOperationResponse)
async def reject_action(
    action_id: str,
    body: s.ActionRejectRequest,
    principal: Annotated[Principal, require_roles(ROLE_APPROVER)],
) -> s.ActionOperationResponse:
    return s.ActionOperationResponse(
        action_id=action_id, status="rejected", decision_id=body.decision_id, message="rejected"
    )


@router.post("/actions/{action_id}/resolve-unknown", response_model=s.ActionOperationResponse)
async def resolve_unknown_action(
    action_id: str,
    body: s.ResolveUnknownRequest,
    principal: Annotated[Principal, require_roles(ROLE_ADMIN)],
) -> s.ActionOperationResponse:
    # Admin-only adjudication of an UNKNOWN action; never triggers an entity action.
    return s.ActionOperationResponse(
        action_id=action_id, status=body.resolution, message="resolved"
    )
