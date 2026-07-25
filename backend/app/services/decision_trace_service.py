"""Decision trace aggregation service (ISSUE-063).

Merges eight data sources into a single chronological timeline for
explainability and reviewer interrogation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Domain models
# --------------------------------------------------------------------------- #

_ENTRY_TYPE_ORDER: dict[str, int] = {
    "state_transition": 0,
    "agent_execution": 1,
    "llm_call": 2,
    "tool_call": 3,
    "approval": 4,
    "action_execution": 5,
    "disposition": 6,
    "writeback": 7,
}


@dataclass
class DecisionTraceEntry:
    entry_id: str
    entry_type: str  # one of the eight values above
    timestamp: datetime
    actor: str
    title: str
    detail: dict[str, Any] = field(default_factory=dict)
    ref_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "entry_type": self.entry_type,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "title": self.title,
            "detail": self.detail,
            "ref_id": self.ref_id,
        }


@dataclass
class DecisionTraceSummary:
    agent_count: int = 0
    tool_call_count: int = 0
    llm_call_count: int = 0
    total_tokens: int = 0
    state_transition_count: int = 0
    approval_count: int = 0
    action_execution_count: int = 0
    disposition_count: int = 0
    writeback_count: int = 0
    total_duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_count": self.agent_count,
            "tool_call_count": self.tool_call_count,
            "llm_call_count": self.llm_call_count,
            "total_tokens": self.total_tokens,
            "state_transition_count": self.state_transition_count,
            "approval_count": self.approval_count,
            "action_execution_count": self.action_execution_count,
            "disposition_count": self.disposition_count,
            "writeback_count": self.writeback_count,
            "total_duration_ms": self.total_duration_ms,
        }


@dataclass
class DecisionTrace:
    event_id: str
    entries: list[DecisionTraceEntry] = field(default_factory=list)
    summary: DecisionTraceSummary = field(default_factory=DecisionTraceSummary)
    missing_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "entries": [e.to_dict() for e in self.entries],
            "summary": self.summary.to_dict(),
            "missing_sources": self.missing_sources,
        }


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


class DecisionTraceService:
    """Aggregate eight event-scoped data tables into a unified timeline."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def get_decision_trace(self, event_id: str) -> DecisionTrace:
        """Return the full decision trace for *event_id*.

        Each data source is queried independently.  A source that raises an
        exception is recorded in ``missing_sources`` and skipped so the
        rest of the trace is still returned (降级策略).
        """
        missing: list[str] = []
        entries: list[DecisionTraceEntry] = []

        async with self._sf() as session:
            # 1. State transitions (event_audit_log)
            entries += await _query_state_transitions(session, event_id, missing)

            # 2. Agent executions (agent_trace)
            entries += await _query_agent_traces(session, event_id, missing)

            # 3. LLM calls (llm_call_log)
            entries += await _query_llm_calls(session, event_id, missing)

            # 4. Tool calls (tool_call_log)
            entries += await _query_tool_calls(session, event_id, missing)

            # 5. Approvals (approval_record)
            entries += await _query_approvals(session, event_id, missing)

            # 6. Action executions (action_execution_job)
            entries += await _query_action_jobs(session, event_id, missing)

            # 7. Dispositions (disposition_outbox)
            entries += await _query_dispositions(session, event_id, missing)

            # 8. Writebacks (disposition_receipt)
            entries += await _query_writebacks(session, event_id, missing)

        entries.sort(key=_sort_key)

        summary = _compute_summary(entries)
        return DecisionTrace(
            event_id=event_id,
            entries=entries,
            summary=summary,
            missing_sources=missing,
        )


# --------------------------------------------------------------------------- #
# Per-source query helpers
# --------------------------------------------------------------------------- #


def _sort_key(entry: DecisionTraceEntry) -> tuple[Any, ...]:
    """Sort by timestamp ascending; same timestamp → fixed entry_type order."""
    return (entry.timestamp, _ENTRY_TYPE_ORDER.get(entry.entry_type, 99))


async def _query_state_transitions(
    session: AsyncSession, event_id: str, missing: list[str]
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    try:
        rows = list(
            (
                await session.execute(
                    select(orm.EventAuditLog)
                    .where(orm.EventAuditLog.event_id == event_id)
                    .order_by(orm.EventAuditLog.created_at)
                )
            ).scalars()
        )
        for r in rows:
            entries.append(
                DecisionTraceEntry(
                    entry_id=f"st-{r.id}",
                    entry_type="state_transition",
                    timestamp=r.created_at or _epoch(),
                    actor=r.operator or "system",
                    title=f"{r.from_status or '?'} → {r.to_status or '?'}",
                    detail={
                        "from_status": r.from_status,
                        "to_status": r.to_status,
                        "reason": r.reason,
                    },
                    ref_id="",
                )
            )
    except Exception:
        logger.warning("Failed to query state transitions for event=%s", event_id, exc_info=True)
        missing.append("state_transition")
    return entries


async def _query_agent_traces(
    session: AsyncSession, event_id: str, missing: list[str]
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    try:
        rows = list(
            (
                await session.execute(
                    select(orm.AgentTrace)
                    .where(orm.AgentTrace.event_id == event_id)
                    .order_by(orm.AgentTrace.started_at)
                )
            ).scalars()
        )
        for r in rows:
            # Build a human-readable title from known agent outputs.
            title = f"{r.agent_name}"
            if r.status == "success":
                title += " succeeded"
            elif r.status == "failed":
                title += " failed"
            elif r.status == "degraded":
                title += " completed (degraded)"

            entries.append(
                DecisionTraceEntry(
                    entry_id=r.trace_id,
                    entry_type="agent_execution",
                    timestamp=r.started_at or _epoch(),
                    actor=r.agent_name,
                    title=title,
                    detail={
                        "status": r.status,
                        "duration_ms": r.duration_ms,
                        "llm_model": r.llm_model,
                        "llm_tokens_used": r.llm_tokens_used,
                    },
                    ref_id=r.trace_id,
                )
            )
    except Exception:
        logger.warning("Failed to query agent traces for event=%s", event_id, exc_info=True)
        missing.append("agent_execution")
    return entries


async def _query_llm_calls(
    session: AsyncSession, event_id: str, missing: list[str]
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    try:
        rows = list(
            (
                await session.execute(
                    select(orm.LLMCallLog)
                    .where(orm.LLMCallLog.event_id == event_id)
                    .order_by(orm.LLMCallLog.created_at)
                )
            ).scalars()
        )
        for r in rows:
            entries.append(
                DecisionTraceEntry(
                    entry_id=f"llm-{r.id}",
                    entry_type="llm_call",
                    timestamp=r.created_at or _epoch(),
                    actor=r.agent_name,
                    title=f"LLM call: {r.prompt_key} ({r.model_name})",
                    detail={
                        "prompt_key": r.prompt_key,
                        "model_name": r.model_name,
                        "prompt_tokens": r.prompt_tokens,
                        "completion_tokens": r.completion_tokens,
                        "total_tokens": r.total_tokens,
                        "latency_ms": r.latency_ms,
                        "status": r.status,
                        "fallback_level": r.fallback_level,
                    },
                    ref_id="",
                )
            )
    except Exception:
        logger.warning("Failed to query LLM calls for event=%s", event_id, exc_info=True)
        missing.append("llm_call")
    return entries


async def _query_tool_calls(
    session: AsyncSession, event_id: str, missing: list[str]
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    try:
        rows = list(
            (
                await session.execute(
                    select(orm.ToolCallLog)
                    .where(orm.ToolCallLog.event_id == event_id)
                    .order_by(orm.ToolCallLog.started_at)
                )
            ).scalars()
        )
        for r in rows:
            entries.append(
                DecisionTraceEntry(
                    entry_id=r.call_id,
                    entry_type="tool_call",
                    timestamp=r.started_at or _epoch(),
                    actor=r.tool_name,
                    title=f"Tool: {r.tool_name} ({r.status})",
                    detail={
                        "tool_category": r.tool_category,
                        "status": r.status,
                        "duration_ms": r.duration_ms,
                        "retry_count": r.retry_count,
                        "action_id": r.action_id,
                    },
                    ref_id=r.call_id,
                )
            )
    except Exception:
        logger.warning("Failed to query tool calls for event=%s", event_id, exc_info=True)
        missing.append("tool_call")
    return entries


async def _query_approvals(
    session: AsyncSession, event_id: str, missing: list[str]
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    try:
        rows = list(
            (
                await session.execute(
                    select(ApprovalRecordORM)
                    .where(ApprovalRecordORM.event_id == event_id)
                    .order_by(ApprovalRecordORM.requested_at)
                )
            ).scalars()
        )
        for r in rows:
            title_parts = [f"Approval {r.approval_id}"]
            if r.decision:
                title_parts.append(f"→ {r.decision}")
            if r.operator:
                title_parts.append(f"by {r.operator}")

            entries.append(
                DecisionTraceEntry(
                    entry_id=r.approval_id,
                    entry_type="approval",
                    timestamp=r.requested_at or _epoch(),
                    actor=r.operator or "system",
                    title=" ".join(title_parts),
                    detail={
                        "action_id": r.action_id,
                        "decision": r.decision,
                        "required_level": r.required_level,
                        "plan_revision": r.plan_revision,
                        "approval_cycle": r.approval_cycle,
                        "decided_at": r.decided_at.isoformat() if r.decided_at else None,
                        "timeout_at": r.timeout_at.isoformat() if r.timeout_at else None,
                        "comment": r.comment,
                    },
                    ref_id=r.action_id,
                )
            )
    except Exception:
        logger.warning("Failed to query approvals for event=%s", event_id, exc_info=True)
        missing.append("approval")
    return entries


async def _query_action_jobs(
    session: AsyncSession, event_id: str, missing: list[str]
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    try:
        rows = list(
            (
                await session.execute(
                    select(orm.ActionExecutionJob)
                    .where(orm.ActionExecutionJob.event_id == event_id)
                    .order_by(orm.ActionExecutionJob.created_at)
                )
            ).scalars()
        )
        for r in rows:
            entries.append(
                DecisionTraceEntry(
                    entry_id=r.job_id,
                    entry_type="action_execution",
                    timestamp=r.created_at or _epoch(),
                    actor=r.provider_name,
                    title=f"Action job: {r.provider_name} ({r.status})",
                    detail={
                        "action_id": r.action_id,
                        "status": r.status,
                        "attempt": r.attempt,
                        "provider_code": r.provider_code,
                    },
                    ref_id=r.action_id,
                )
            )
    except Exception:
        logger.warning("Failed to query action jobs for event=%s", event_id, exc_info=True)
        missing.append("action_execution")
    return entries


async def _query_dispositions(
    session: AsyncSession, event_id: str, missing: list[str]
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    try:
        rows = list(
            (
                await session.execute(
                    select(orm.DispositionOutbox)
                    .where(orm.DispositionOutbox.event_id == event_id)
                    .order_by(orm.DispositionOutbox.created_at)
                )
            ).scalars()
        )
        for r in rows:
            entries.append(
                DecisionTraceEntry(
                    entry_id=r.outbox_id,
                    entry_type="disposition",
                    timestamp=r.created_at or _epoch(),
                    actor=r.intent_kind,
                    title=f"Disposition: {r.intent_kind} ({r.delivery_status})",
                    detail={
                        "writeback_id": r.writeback_id,
                        "action_id": r.action_id,
                        "delivery_status": r.delivery_status,
                        "attempt": r.attempt,
                        "closure_cycle": r.closure_cycle,
                        "logical_slot": r.logical_slot,
                    },
                    ref_id=r.action_id,
                )
            )
    except Exception:
        logger.warning("Failed to query dispositions for event=%s", event_id, exc_info=True)
        missing.append("disposition")
    return entries


async def _query_writebacks(
    session: AsyncSession, event_id: str, missing: list[str]
) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    try:
        rows = list(
            (
                await session.execute(
                    select(orm.DispositionReceipt)
                    .join(
                        orm.DispositionOutbox,
                        orm.DispositionReceipt.writeback_id == orm.DispositionOutbox.writeback_id,
                    )
                    .where(orm.DispositionOutbox.event_id == event_id)
                    .order_by(orm.DispositionReceipt.observed_at)
                )
            ).scalars()
        )
        for r in rows:
            entries.append(
                DecisionTraceEntry(
                    entry_id=f"wbk-{r.writeback_id}-{r.sequence}",
                    entry_type="writeback",
                    timestamp=r.observed_at or r.submitted_at or _epoch(),
                    actor="disposition_adapter",
                    title=f"Writeback: {r.status}",
                    detail={
                        "writeback_id": r.writeback_id,
                        "status": r.status,
                        "provider_code": r.provider_code,
                        "provider_message": r.provider_message,
                        "simulated": r.simulated,
                    },
                    ref_id=r.action_id,
                )
            )
    except Exception:
        logger.warning("Failed to query writebacks for event=%s", event_id, exc_info=True)
        missing.append("writeback")
    return entries


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #


def _compute_summary(entries: list[DecisionTraceEntry]) -> DecisionTraceSummary:
    s = DecisionTraceSummary()
    timestamps: list[datetime] = []

    for e in entries:
        timestamps.append(e.timestamp)
        if e.entry_type == "agent_execution":
            s.agent_count += 1
        elif e.entry_type == "tool_call":
            s.tool_call_count += 1
        elif e.entry_type == "llm_call":
            s.llm_call_count += 1
            s.total_tokens += int(e.detail.get("total_tokens", 0) or 0)
        elif e.entry_type == "state_transition":
            s.state_transition_count += 1
        elif e.entry_type == "approval":
            s.approval_count += 1
        elif e.entry_type == "action_execution":
            s.action_execution_count += 1
        elif e.entry_type == "disposition":
            s.disposition_count += 1
        elif e.entry_type == "writeback":
            s.writeback_count += 1

    if len(timestamps) >= 2:
        delta = timestamps[-1] - timestamps[0]
        s.total_duration_ms = int(delta.total_seconds() * 1000)

    return s


def _epoch() -> datetime:
    return datetime(1970, 1, 1, tzinfo=UTC)


__all__ = [
    "DecisionTrace",
    "DecisionTraceEntry",
    "DecisionTraceService",
    "DecisionTraceSummary",
]
