"""API v1 router package."""

from fastapi import APIRouter

from app.api.v1 import (
    actions,
    connectors,
    dispositions,
    events,
    execution_jobs,
    health,
    knowledge,
    source_records,
    stats,
    tools,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(events.router)
api_router.include_router(actions.router)
api_router.include_router(source_records.router)
api_router.include_router(connectors.router)
api_router.include_router(dispositions.router)
api_router.include_router(execution_jobs.router)
api_router.include_router(tools.router)
api_router.include_router(knowledge.router)
api_router.include_router(stats.router)
