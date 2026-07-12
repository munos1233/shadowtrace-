"""Source ingestion + source-record lookup endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, status

from app.api.v1 import schemas as s
from app.api.v1.errors import ResourceNotFoundError
from app.core.auth import ROLE_ANALYST, CurrentPrincipal, Principal, require_roles

router = APIRouter(tags=["source"])

_KNOWN_SOURCE_RECORDS = {"src-associated-1"}


@router.post(
    "/ingestion/source-records",
    response_model=s.IngestSourceRecordResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_source_record(
    body: s.IngestSourceRecordRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
) -> s.IngestSourceRecordResponse:
    return s.IngestSourceRecordResponse(
        source_record_id="src-associated-1", event_id=s.EXAMPLE_EVENT_ID, accepted=True
    )


@router.get("/source-records/{source_record_id}", response_model=s.SourceRecordResponse)
async def get_source_record(
    source_record_id: str, principal: CurrentPrincipal
) -> s.SourceRecordResponse:
    # located by internal primary key only.
    if source_record_id not in _KNOWN_SOURCE_RECORDS:
        raise ResourceNotFoundError(
            f"source record {source_record_id} not found",
            details={"source_record_id": source_record_id},
        )
    return s.SourceRecordResponse(
        source_record_id=source_record_id,
        reference=s.example_source_reference(),
        normalized={},
    )
