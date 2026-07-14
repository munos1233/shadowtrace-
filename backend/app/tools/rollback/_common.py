from __future__ import annotations

from typing import Any

from app.models.tool_meta import ToolMeta
from app.providers.tools.mock_provider import execute_mock_rollback_tool
from app.tools.specs import baseline_tool_index


def rollback_tool_meta(tool_name: str) -> ToolMeta:
    return baseline_tool_index()[tool_name]


async def execute_rollback_tool(tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
    return await execute_mock_rollback_tool(tool_name, params)
