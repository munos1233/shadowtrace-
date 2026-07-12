"""Execution job + async task status endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.api.v1.errors import ResourceNotFoundError
from app.core.auth import CurrentPrincipal

router = APIRouter(tags=["platform"])

_KNOWN_JOBS = {"job-0a1b2c3d"}


@router.get("/execution-jobs/{job_id}", response_model=s.ExecutionJobResponse)
async def get_execution_job(job_id: str, principal: CurrentPrincipal) -> s.ExecutionJobResponse:
    if job_id not in _KNOWN_JOBS:
        raise ResourceNotFoundError(
            f"execution job {job_id} not found", details={"job_id": job_id}
        )
    return s.ExecutionJobResponse(
        job_id=job_id,
        event_id=s.EXAMPLE_EVENT_ID,
        action_id="act-0a1b2c3d",
        status="partial_success",
        attempt=1,
        target_results=[
            {"canonical_target": "ip:203.0.113.9", "status": "success"},
            {"canonical_target": "ip:203.0.113.10", "status": "failed"},
        ],
    )


@router.get("/tasks/{task_id}", response_model=s.TaskResponse)
async def get_task(task_id: str, principal: CurrentPrincipal) -> s.TaskResponse:
    return s.TaskResponse(task_id=task_id, status="running", event_id=s.EXAMPLE_EVENT_ID)
