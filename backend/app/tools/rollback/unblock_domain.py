from typing import Any

from app.tools.rollback._common import execute_rollback_tool, rollback_tool_meta

TOOL_META = rollback_tool_meta("unblock_domain")


async def execute(params: dict[str, Any]) -> dict[str, Any]:
    return await execute_rollback_tool(TOOL_META.tool_name, params)
