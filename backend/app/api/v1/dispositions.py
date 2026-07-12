"""Disposition / writeback read + controlled-retry endpoints.

These endpoints only read or controllably re-enqueue the outbox; they never
construct disposition commands or bypass the ApprovalEngine.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.api.v1.errors import ResourceNotFoundError, WritebackConflictError
from app.core.auth import (
    ROLE_ADMIN,
    ROLE_DISPOSITION_OPERATOR,
    CurrentPrincipal,
    Principal,
    require_roles,
)
from app.models.enums import ConfirmationEvidence, WritebackStatus

router = APIRouter(tags=["dispositions"])

_KNOWN_DISPOSITIONS = {"disp-0a1b2c3d"}
# writeback_id -> current status (for placeholder retry/verify semantics)
_KNOWN_WRITEBACKS = {
    "wbk-0a1b2c3d": WritebackStatus.CONFIRMED,
    "wbk-unknown": WritebackStatus.UNKNOWN,
}


@router.get("/events/{event_id}/dispositions", response_model=s.DispositionListResponse)
async def list_event_dispositions(
    event_id: str, principal: CurrentPrincipal
) -> s.DispositionListResponse:
    return s.DispositionListResponse(
        event_id=event_id,
        items=[
            s.DispositionResponse(
                disposition=s.example_disposition_command(),
                writeback_status=WritebackStatus.CONFIRMED,
            )
        ],
    )


@router.get("/dispositions/{disposition_id}", response_model=s.DispositionResponse)
async def get_disposition(
    disposition_id: str, principal: CurrentPrincipal
) -> s.DispositionResponse:
    if disposition_id not in _KNOWN_DISPOSITIONS:
        raise ResourceNotFoundError(
            f"disposition {disposition_id} not found",
            details={"disposition_id": disposition_id},
        )
    return s.DispositionResponse(
        disposition=s.example_disposition_command(), writeback_status=WritebackStatus.CONFIRMED
    )


@router.get("/writebacks/{writeback_id}", response_model=s.WritebackResponse)
async def get_writeback(writeback_id: str, principal: CurrentPrincipal) -> s.WritebackResponse:
    status_value = _KNOWN_WRITEBACKS.get(writeback_id)
    if status_value is None:
        raise ResourceNotFoundError(
            f"writeback {writeback_id} not found", details={"writeback_id": writeback_id}
        )
    return s.WritebackResponse(
        writeback_id=writeback_id,
        disposition_id="disp-0a1b2c3d",
        action_id="act-0a1b2c3d",
        status=status_value,
        confirmation_evidence=(
            ConfirmationEvidence.READBACK_VERIFIED
            if status_value is WritebackStatus.CONFIRMED
            else None
        ),
        evidence_tier="strong" if status_value is WritebackStatus.CONFIRMED else None,
    )


@router.post("/writebacks/{writeback_id}/retry", response_model=s.WritebackOperationResponse)
async def retry_writeback(
    writeback_id: str,
    principal: Annotated[Principal, require_roles(ROLE_DISPOSITION_OPERATOR)],
) -> s.WritebackOperationResponse:
    status_value = _KNOWN_WRITEBACKS.get(writeback_id)
    if status_value is None:
        raise ResourceNotFoundError(
            f"writeback {writeback_id} not found", details={"writeback_id": writeback_id}
        )
    # An UNKNOWN writeback must be verified (queried) before any retry; retrying
    # blindly could double-apply an external side effect.
    if status_value is WritebackStatus.UNKNOWN:
        raise WritebackConflictError(
            "writeback is UNKNOWN and must be verified before retry",
            details={"writeback_id": writeback_id, "status": status_value.value},
        )
    # retry only re-enqueues the same outbox row (idempotent).
    return s.WritebackOperationResponse(
        writeback_id=writeback_id, status=WritebackStatus.PENDING, message="re-enqueued"
    )


@router.post("/writebacks/{writeback_id}/resolve", response_model=s.WritebackOperationResponse)
async def resolve_writeback(
    writeback_id: str,
    body: s.ResolveWritebackRequest,
    principal: Annotated[Principal, require_roles(ROLE_ADMIN)],
) -> s.WritebackOperationResponse:
    status_value = _KNOWN_WRITEBACKS.get(writeback_id)
    if status_value is None:
        raise ResourceNotFoundError(
            f"writeback {writeback_id} not found", details={"writeback_id": writeback_id}
        )
    # Admin-only manual resolution with CAS + evidence; never triggers entity actions.
    new_status = (
        WritebackStatus.CONFIRMED
        if body.resolution == "manual_confirmed"
        else WritebackStatus.FAILED
    )
    return s.WritebackOperationResponse(
        writeback_id=writeback_id, status=new_status, message="resolved"
    )
