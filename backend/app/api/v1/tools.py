"""Tool catalog + platform-wide tool-call listing endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import schemas as s
from app.core.auth import CurrentPrincipal

router = APIRouter(tags=["tools"])


@router.get("/tools", response_model=s.ToolsResponse)
async def list_tools(principal: CurrentPrincipal) -> s.ToolsResponse:
    return s.ToolsResponse(
        items=[
            s.ToolMetaItem(
                tool_name="block_ip",
                tool_category="response",
                side_effect_level="high",
                idempotency=True,
                async_mode=True,
                rollback_supported=True,
            ),
            s.ToolMetaItem(
                tool_name="query_asset_info",
                tool_category="query",
                side_effect_level="none",
                idempotency=True,
                async_mode=False,
                rollback_supported=False,
            ),
        ]
    )


@router.get("/tool-calls", response_model=s.ToolCallsResponse)
async def list_tool_calls(
    principal: CurrentPrincipal,
    page: int = 1,
    page_size: int = 20,
    tool_name: str | None = None,
    status: str | None = None,
) -> s.ToolCallsResponse:
    # Placeholder ignores the filters but declares the documented tool_name/status
    # query contract so later real implementations stay contract-stable.
    return s.ToolCallsResponse(
        total=1,
        page=page,
        page_size=page_size,
        items=[
            s.ToolCallItem(
                call_id="call-0a1b2c3d",
                event_id=s.EXAMPLE_EVENT_ID,
                action_id="act-0a1b2c3d",
                tool_name="block_ip",
                tool_category="response",
                status="success",
            )
        ],
    )
