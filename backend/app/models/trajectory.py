"""Trajectory analysis models (ISSUE-066)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TrajectoryReport(BaseModel):
    """Structured quality analysis of one investigation trajectory."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    total_steps: int = 0
    agent_invocations: int = 0
    tool_calls: int = 0
    llm_calls: int = 0
    metrics: dict[str, float] = Field(default_factory=dict)
    findings: list[str] = Field(default_factory=list)
    insufficient_trace: bool = False


__all__ = ["TrajectoryReport"]
