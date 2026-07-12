"""Connector listing endpoint (exposes capability/health, never credentials)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.core.auth import CurrentPrincipal

router = APIRouter(tags=["connectors"])


@router.get("/connectors", response_model=s.ConnectorsResponse)
async def list_connectors(principal: CurrentPrincipal) -> s.ConnectorsResponse:
    return s.ConnectorsResponse(
        items=[
            s.ConnectorPublic(
                connector_id="conn-mock-1",
                source_product="mock_xdr",
                display_name="Mock XDR",
                device_type="xdr",
                status="online",
                capabilities={
                    "LOG_INGESTION": "SUPPORTED",
                    "QUERY": "SUPPORTED",
                    "EVENT_DISPOSITION": "SUPPORTED",
                    "ENTITY_RESPONSE": "SUPPORTED",
                },
            )
        ]
    )
