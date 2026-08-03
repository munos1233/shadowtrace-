"""Celery tasks for detection governance maintenance (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

import asyncio
import logging

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.services.detection_governance_service import DetectionGovernanceService

logger = logging.getLogger(__name__)


@celery_app.task(  # type: ignore[untyped-decorator]
    name="shadowtrace.detection_governance.expire_active_approvals"
)
def expire_detection_governance_approvals() -> dict[str, object]:
    """Append EXPIRE records for approvals past ``expires_at``."""
    settings = get_settings()
    if not settings.detection_governance_expire_enabled:
        return {"expired_count": 0, "skipped": True}

    async def _run() -> list[str]:
        from app.db.session_provider import get_session_provider

        provider = get_session_provider()
        service = DetectionGovernanceService(provider.session_factory())
        return await service.expire_active_approvals()

    expired_ids = asyncio.run(_run())
    logger.info(
        "detection governance expire sweep completed count=%d",
        len(expired_ids),
    )
    return {"expired_count": len(expired_ids), "decision_ids": expired_ids}
