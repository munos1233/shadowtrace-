"""Knowledge base listing endpoint (placeholder)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.core.auth import CurrentPrincipal

router = APIRouter(tags=["knowledge"])


@router.get("/knowledge", response_model=s.KnowledgeResponse)
async def list_knowledge(
    principal: CurrentPrincipal, page: int = 1, page_size: int = 20
) -> s.KnowledgeResponse:
    return s.KnowledgeResponse(total=0, page=page, page_size=page_size, items=[])
