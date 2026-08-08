"""DecisionTrace domain models (ISSUE-063).

Unified decision-trace timeline aggregating eight entry types across agent
executions, tool calls, LLM calls, state transitions, approvals, action
executions, dispositions, and writeback receipts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import DecisionTraceEntryType


class DecisionTraceEntry(BaseModel):
    """A single step in the decision trace timeline.

    ``detail`` is a sanitised structured projection (never raw payload).
    """

    model_config = ConfigDict(extra="forbid")

    entry_id: str
    entry_type: DecisionTraceEntryType
    timestamp: datetime
    actor: str
    title: str
    detail: dict[str, Any] = Field(default_factory=dict)
    ref_id: str | None = None
    decision_record_ref: str | None = None


class DecisionTraceSummary(BaseModel):
    """Aggregated counts computed from the full (unfiltered) trace."""

    model_config = ConfigDict(extra="forbid")

    agent_count: int = 0
    tool_call_count: int = 0
    llm_call_count: int = 0
    total_tokens: int = 0
    state_transition_count: int = 0
    approval_count: int = 0
    action_execution_count: int = 0
    disposition_count: int = 0
    writeback_count: int = 0
    total_duration_ms: int | None = Field(
        default=None,
        description=(
            "Wall-clock span from the first to last timeline entry (ms). "
            "Includes WAITING_* idle such as approval waits. "
            "Preserved for backward-compatible dashboards; prefer "
            "active_duration_ms for investigation effort."
        ),
    )
    active_duration_ms: int | None = Field(
        default=None,
        description=(
            "Effective investigation duration (ms): wall-clock span minus "
            "halt gaps inferred from EventStatus-level STATE_TRANSITION "
            "to_status values (primarily waiting_approval). "
            "ExecutionSubstate waiting_writeback is not an EventStatus and is "
            "not deducted unless recorded on the audit timeline. "
            "Use this for ops/eval '调查耗时' displays."
        ),
    )


class DecisionTrace(BaseModel):
    """Full decision trace for one event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    entries: list[DecisionTraceEntry] = Field(default_factory=list)
    summary: DecisionTraceSummary = Field(default_factory=DecisionTraceSummary)
    missing_sources: list[str] = Field(default_factory=list)
