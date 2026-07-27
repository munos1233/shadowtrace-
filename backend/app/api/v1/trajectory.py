"""Trajectory analysis API (ISSUE-066)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import get_event_service
from app.api.v1.errors import EventNotFoundError
from app.core.auth import CurrentPrincipal
from app.models.trajectory import TrajectoryReport
from app.services.event_service import EventService
from app.services.trajectory_analyzer import TrajectoryAnalyzer

logger = logging.getLogger(__name__)

router = APIRouter(tags=["trajectory"])


def _try_get_session_factory() -> async_sessionmaker[AsyncSession] | None:
    """Return the session factory, or None if DB is unavailable."""
    try:
        from app.api.v1.deps import _get_session_factory

        return _get_session_factory()
    except (ImportError, ModuleNotFoundError):
        logger.warning("Database session factory unavailable — returning empty trajectory")
        return None
    except (ValueError, TypeError):
        raise
    except (ConnectionRefusedError, TimeoutError, OSError):
        logger.warning("Database session factory unavailable (transient)", exc_info=True)
        return None


@router.get(
    "/events/{event_id}/trajectory",
    response_model=TrajectoryReport,
)
async def get_trajectory(
    event_id: str,
    principal: CurrentPrincipal,
    event_service: EventService = Depends(get_event_service),
) -> TrajectoryReport:
    """Return structured trajectory quality metrics for *event_id*."""
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    sf = _try_get_session_factory()
    if sf is None:
        return TrajectoryReport(event_id=event_id, insufficient_trace=True)

    analyzer = TrajectoryAnalyzer(sf)
    return await analyzer.analyze(event_id)
