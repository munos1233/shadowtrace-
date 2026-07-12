"""Platform statistics endpoint (placeholder)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.core.auth import CurrentPrincipal

router = APIRouter(tags=["stats"])


@router.get("/stats", response_model=s.StatsResponse)
async def get_stats(principal: CurrentPrincipal) -> s.StatsResponse:
    return s.StatsResponse(
        total_events=1,
        open_events=1,
        closed_events=0,
        pending_approvals=0,
        pending_writebacks=0,
        external_unsynced_events=0,
    )
