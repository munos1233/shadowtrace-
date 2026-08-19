"""Sync auto-investigate intent dispatch API (ISSUE-108 / #612)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status

from app.api.v1 import schemas as s
from app.api.v1.deps import get_investigation_intent_service
from app.core.auth import ROLE_ANALYST, Principal, require_roles
from app.core.config import get_settings
from app.core.errors import ValidationError

router = APIRouter(tags=["investigation-intents"])


@router.post(
    "/investigation-intents/dispatch",
    response_model=s.InvestigationIntentDispatchResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def dispatch_investigation_intents_sync(
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    intent_service: Annotated[Any, Depends(get_investigation_intent_service)],
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> s.InvestigationIntentDispatchResponse:
    """Explicitly claim pending intents and publish to the Celery broker."""
    settings = get_settings()
    if not settings.auto_investigate_enabled:
        raise ValidationError(
            "auto investigate is disabled; this path is not the CLOSED gold path",
            error_code="feature_disabled",
            details={"feature": "auto_investigate"},
        )
    result = await intent_service.dispatch_sync_batch(limit=limit)
    return s.InvestigationIntentDispatchResponse(**result)
