"""Evidence collection observability helpers (ISSUE-101).

Shared utilities for query timing summaries used by the evidence API and
decision trace aggregation — avoids coupling HTTP handlers to private trace code.
"""

from __future__ import annotations

from typing import Any

from app.db import models as orm


def evidence_query_timing_by_tool(
    agent_rows: list[orm.AgentTrace],
) -> dict[str, dict[str, Any]]:
    """Build tool_name -> query timing map from the latest evidence_agent trace."""
    timing_by_tool: dict[str, dict[str, Any]] = {}
    for row in reversed(agent_rows):
        if row.agent_name != "evidence_agent":
            continue
        output_data = row.output_data if isinstance(row.output_data, dict) else {}
        timings = output_data.get("query_timings")
        if not isinstance(timings, list):
            continue
        for item in timings:
            if not isinstance(item, dict):
                continue
            tool_name = item.get("tool_name")
            if isinstance(tool_name, str) and tool_name:
                timing_by_tool.setdefault(tool_name, item)
        if timing_by_tool:
            break
    return timing_by_tool


def build_query_summary_items(
    agent_rows: list[orm.AgentTrace],
) -> list[dict[str, Any]]:
    """Serialize per-tool query timings for API responses."""
    timing_by_tool = evidence_query_timing_by_tool(agent_rows)
    summary: list[dict[str, Any]] = []
    for tool_name in sorted(timing_by_tool):
        item = timing_by_tool[tool_name]
        if not isinstance(item, dict):
            continue
        tool_outcome = item.get("tool_outcome")
        provider_status = item.get("provider_status")
        summary.append(
            {
                "tool_name": str(item.get("tool_name") or tool_name),
                "source": str(item.get("source") or ""),
                "status": str(item.get("status") or ""),
                "execution_time_ms": int(item.get("execution_time_ms") or 0),
                "records_count": int(item.get("records_count") or 0),
                "gap_reason": (
                    str(item["gap_reason"]) if item.get("gap_reason") is not None else None
                ),
                "tool_outcome": str(tool_outcome) if tool_outcome is not None else None,
                "provider_status": (str(provider_status) if provider_status is not None else None),
            }
        )
    return summary
