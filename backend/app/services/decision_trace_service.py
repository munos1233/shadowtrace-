"""DecisionTraceService: unified decision trace from 8 data sources (ISSUE-063).

Aggregates agent executions, tool calls, LLM calls, state transitions,
approvals, action executions, dispositions, and writeback receipts into a
single timestamp-ordered timeline for explainability and auditing.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.models.decision_trace import DecisionTrace, DecisionTraceEntry, DecisionTraceSummary
from app.models.enums import DecisionTraceEntryType
from app.services.agent_trace_service import TraceProjection

logger = logging.getLogger(__name__)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# Fixed ordering for entries sharing the same timestamp.
_ENTRY_TYPE_ORDER: dict[DecisionTraceEntryType, int] = {
    DecisionTraceEntryType.AGENT_EXECUTION: 0,
    DecisionTraceEntryType.TOOL_CALL: 1,
    DecisionTraceEntryType.LLM_CALL: 2,
    DecisionTraceEntryType.STATE_TRANSITION: 3,
    DecisionTraceEntryType.APPROVAL: 4,
    DecisionTraceEntryType.ACTION_EXECUTION: 5,
    DecisionTraceEntryType.DISPOSITION: 6,
    DecisionTraceEntryType.WRITEBACK: 7,
}


def _new_entry_id() -> str:
    return f"dte-{secrets.token_hex(4)}"


def _ts(obj: Any, *attrs: str) -> datetime | None:
    """Extract the first non-None timestamp from the given attribute names."""
    for attr in attrs:
        val = getattr(obj, attr, None)
        if isinstance(val, datetime):
            return val
    return None


def _require_ts(obj: Any, *attrs: str) -> tuple[datetime, bool]:
    """Return a timestamp, falling back to epoch when none is present."""
    found = _ts(obj, *attrs)
    if found is not None:
        return found, False
    return _EPOCH, True


def _maybe_inferred_detail(base: dict[str, Any], inferred: bool) -> dict[str, Any]:
    if not inferred:
        return base
    return {**base, "timestamp_inferred": True}


def _agent_status_verb(status: str) -> str:
    normalized = status.lower()
    if normalized in {"running", "in_progress", "started", "pending"}:
        return "执行中"
    if normalized in {"failed", "error"}:
        return "执行失败"
    return "完成"


def _agent_decision_basis(output_data: Any) -> dict[str, Any]:
    """Return sanitized decision basis; never trust legacy stored CoT (ISSUE-131)."""
    if not isinstance(output_data, dict):
        return {}
    basis = TraceProjection.decision_basis(output_data)
    stored = output_data.get("_decision_basis")
    if not isinstance(stored, dict) or not stored:
        return basis
    # Preserve non-conclusion metadata from stored basis, but structured_conclusion
    # always comes from TraceProjection (decision_summary-first, CoT keys redacted).
    for key in (
        "input_summary",
        "confidence",
        "evidence_refs",
        "selected_action",
        "warnings",
        "model_name",
        "model_version",
        "rule_version",
        "rules_applied",
    ):
        value = stored.get(key)
        if value in (None, "", [], {}):
            continue
        existing = basis.get(key)
        if existing in (None, "", [], {}) or (
            key == "input_summary" and isinstance(existing, str) and existing.startswith("keys=")
        ):
            basis[key] = value
    return basis


def _agent_title(agent_name: str, status: str, output_data: Any) -> str:
    verb = _agent_status_verb(status)
    action_labels = {
        "triage_agent": "分诊",
        "TriageAgent": "分诊",
        "risk_agent": "风险评估",
        "RiskAgent": "风险评估",
        "evidence_agent": "证据收集",
        "EvidenceAgent": "证据收集",
        "planner_agent": "计划生成",
        "PlannerAgent": "计划生成",
        "response_agent": "响应方案",
        "ResponseAgent": "响应方案",
        "verify_agent": "效果验证",
        "VerifyAgent": "效果验证",
        "report_agent": "报告生成",
        "ReportAgent": "报告生成",
    }
    label = action_labels.get(agent_name, "执行")
    title = f"{agent_name} {verb}{label}"

    basis = _agent_decision_basis(output_data)
    if agent_name in {"TriageAgent", "triage_agent"} and isinstance(output_data, dict):
        severity = output_data.get("severity")
        if severity is not None:
            return f"{title}：severity={severity}"
    conclusion = basis.get("structured_conclusion")
    if isinstance(conclusion, str) and conclusion.strip():
        return f"{title}：{conclusion[:120]}"
    return f"{title}：status={status}"


def _agent_detail(row: orm.AgentTrace, inferred: bool) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "agent_name": row.agent_name,
        "status": row.status,
        "duration_ms": row.duration_ms,
        "tokens_used": row.llm_tokens_used,
        "model": row.llm_model,
    }
    output_data = row.output_data if isinstance(row.output_data, dict) else {}
    basis = _agent_decision_basis(output_data)
    compat = TraceProjection.project_for_compat(output_data)
    for legacy_key in (
        "thought",
        "reflection",
        "rationale",
        "reasoning",
        "chain_of_thought",
        "chain-of-thought",
    ):
        if legacy_key in compat:
            detail[legacy_key] = compat[legacy_key]
    for key in (
        "input_summary",
        "structured_conclusion",
        "confidence",
        "evidence_refs",
        "selected_action",
        "rules_applied",
        "model_name",
        "model_version",
        "rule_version",
        "warnings",
        "decision_record_ref",
    ):
        value = basis.get(key)
        if value not in (None, "", [], {}):
            detail[key] = value
    for key in (
        "severity",
        "event_type",
        "need_investigation",
        # ISSUE-066: verification / evidence fields for TrajectoryAnalyzer.
        "overall_status",
        "need_action_replan",
        "need_writeback_recovery",
        "collection_status",
        "evidence_list",
        "warnings",
        # ISSUE-101: evidence gap observability in agent execution detail.
        "gaps",
        "query_timings",
        "success_sources",
        "failed_sources",
    ):
        if key in output_data and output_data[key] is not None:
            detail[key] = output_data[key]
    record_ref = output_data.get("decision_record_ref")
    if isinstance(record_ref, str) and record_ref.strip():
        detail["decision_record_ref"] = record_ref.strip()
    return _maybe_inferred_detail(detail, inferred)


# --------------------------------------------------------------------------- #
# Per-source normalizers
# --------------------------------------------------------------------------- #


def _normalize_agent_traces(rows: list[orm.AgentTrace]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts, inferred = _require_ts(row, "started_at", "completed_at")
        output_data = row.output_data if isinstance(row.output_data, dict) else {}
        record_ref = output_data.get("decision_record_ref")
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.AGENT_EXECUTION,
                timestamp=ts,
                actor=row.agent_name,
                title=_agent_title(row.agent_name, row.status, row.output_data),
                detail=_agent_detail(row, inferred),
                ref_id=row.trace_id,
                decision_record_ref=(
                    record_ref.strip()
                    if isinstance(record_ref, str) and record_ref.strip()
                    else None
                ),
            )
        )
    return entries


def _evidence_query_timing_by_tool(
    agent_rows: list[orm.AgentTrace],
) -> dict[str, dict[str, Any]]:
    """Backward-compatible alias.

    Prefer ``evidence_observability.evidence_query_timing_by_tool``.
    """
    from app.services.evidence_observability import evidence_query_timing_by_tool

    return evidence_query_timing_by_tool(agent_rows)


def _normalize_tool_calls(
    rows: list[orm.ToolCallLog],
    *,
    timing_by_tool: dict[str, dict[str, Any]] | None = None,
) -> list[DecisionTraceEntry]:
    enrich = timing_by_tool or {}
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts, inferred = _require_ts(row, "started_at", "completed_at")
        detail: dict[str, Any] = {
            "tool_name": row.tool_name,
            "tool_category": row.tool_category,
            "status": row.status,
            "duration_ms": row.duration_ms,
            "retry_count": row.retry_count,
        }
        timing = enrich.get(row.tool_name)
        if isinstance(timing, dict):
            if "records_count" in timing:
                detail["records_count"] = timing["records_count"]
            gap_reason = timing.get("gap_reason")
            if gap_reason is not None:
                detail["gap_reason"] = gap_reason
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.TOOL_CALL,
                timestamp=ts,
                actor=row.tool_name,
                title=f"{row.tool_name} 工具调用完成：status={row.status}",
                detail=_maybe_inferred_detail(detail, inferred),
                ref_id=row.call_id,
            )
        )
    return entries


def _normalize_llm_calls(rows: list[orm.LLMCallLog]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.LLM_CALL,
                timestamp=row.created_at,
                actor=row.agent_name,
                title=f"{row.agent_name} LLM 调用（{row.model_name}）：{row.total_tokens} tokens",
                detail={
                    "agent_name": row.agent_name,
                    "model_name": row.model_name,
                    "prompt_key": row.prompt_key,
                    "prompt_tokens": row.prompt_tokens,
                    "completion_tokens": row.completion_tokens,
                    "total_tokens": row.total_tokens,
                    "latency_ms": row.latency_ms,
                    "status": row.status,
                    "error_class": row.error_class,
                    "error_detail": row.error_detail,
                },
                ref_id=str(row.id),
            )
        )
    return entries


def _normalize_state_transitions(rows: list[orm.EventAuditLog]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        from_s = row.from_status or "?"
        to_s = row.to_status or "?"
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.STATE_TRANSITION,
                timestamp=row.created_at,
                actor=row.operator or "system",
                title=f"状态转换：{from_s} → {to_s}",
                detail={
                    "from_status": row.from_status,
                    "to_status": row.to_status,
                    "operator": row.operator,
                    "reason": row.reason,
                },
                ref_id=str(row.id),
            )
        )
    return entries


def _normalize_approval_rows(rows: list[ApprovalRecordORM]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts, inferred = _require_ts(row, "decided_at", "requested_at")
        operator = row.operator or "system"
        reason = row.comment
        if reason is None and isinstance(row.detail, dict):
            reason = row.detail.get("reason")
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.APPROVAL,
                timestamp=ts,
                actor=operator,
                title=f"审批 {operator}：{row.decision}",
                detail=_maybe_inferred_detail(
                    {
                        "decision": row.decision,
                        "operator": operator,
                        "reason": reason,
                        "action_id": row.action_id,
                        "plan_revision": row.plan_revision,
                        "approval_cycle": row.approval_cycle,
                    },
                    inferred,
                ),
                ref_id=row.decision_id or row.approval_id,
            )
        )
    return entries


def _normalize_action_executions(rows: list[orm.ActionExecutionJob]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts, inferred = _require_ts(row, "started_at", "created_at", "updated_at")
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.ACTION_EXECUTION,
                timestamp=ts,
                actor=row.provider_name,
                title=f"动作执行 {row.action_id}：{row.status}",
                detail=_maybe_inferred_detail(
                    {
                        "job_id": row.job_id,
                        "action_id": row.action_id,
                        "provider_name": row.provider_name,
                        "status": row.status,
                        "attempt": row.attempt,
                        "provider_code": row.provider_code,
                    },
                    inferred,
                ),
                ref_id=row.job_id,
            )
        )
    return entries


def _normalize_dispositions(rows: list[orm.DispositionOutbox]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts, inferred = _require_ts(row, "created_at", "delivered_at")
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.DISPOSITION,
                timestamp=ts,
                actor="system",
                title=f"处置命令 {row.disposition_id}：{row.intent_kind}",
                detail=_maybe_inferred_detail(
                    {
                        "disposition_id": row.disposition_id,
                        "action_id": row.action_id,
                        "intent_kind": row.intent_kind,
                        "delivery_status": row.delivery_status,
                        "writeback_status": row.latest_writeback_status,
                        "closure_cycle": row.closure_cycle,
                        "attempt": row.attempt,
                    },
                    inferred,
                ),
                ref_id=row.outbox_id,
            )
        )
    return entries


def _normalize_writebacks(rows: list[orm.DispositionReceipt]) -> list[DecisionTraceEntry]:
    entries: list[DecisionTraceEntry] = []
    for row in rows:
        ts, inferred = _require_ts(row, "confirmed_at", "submitted_at", "observed_at")
        entries.append(
            DecisionTraceEntry(
                entry_id=_new_entry_id(),
                entry_type=DecisionTraceEntryType.WRITEBACK,
                timestamp=ts,
                actor="system",
                title=f"写回回执 {row.writeback_id}：{row.status}",
                detail=_maybe_inferred_detail(
                    {
                        "writeback_id": row.writeback_id,
                        "disposition_id": row.disposition_id,
                        "action_id": row.action_id,
                        "status": row.status,
                        "confirmation_evidence": row.confirmation_evidence,
                        "simulated": row.simulated,
                        "sequence": row.sequence,
                    },
                    inferred,
                ),
                ref_id=row.writeback_id,
            )
        )
    return entries


# --------------------------------------------------------------------------- #
# Sorting key
# --------------------------------------------------------------------------- #


def _sort_key(entry: DecisionTraceEntry) -> tuple[datetime, int, str]:
    return (
        entry.timestamp,
        _ENTRY_TYPE_ORDER.get(entry.entry_type, 99),
        entry.entry_id,
    )


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


class DecisionTraceService:
    """Aggregate 8 data sources into a unified decision trace timeline."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_decision_trace(self, event_id: str) -> DecisionTrace:
        """Build the full decision trace for *event_id*.

        Sources that fail are skipped and recorded in ``missing_sources``;
        the remaining entries are still returned.
        """
        all_entries: list[DecisionTraceEntry] = []
        missing: list[str] = []

        async with self._session_factory() as session:
            # 1. Agent traces
            agent_rows: list[orm.AgentTrace] = []
            try:
                agent_rows = await self._fetch_agent_traces(session, event_id)
                all_entries.extend(_normalize_agent_traces(agent_rows))
            except Exception as exc:
                logger.warning("Failed to fetch agent traces for %s: %s", event_id, exc)
                missing.append("agent_trace")

            # 2. Tool calls
            try:
                tool_rows = await self._fetch_tool_calls(session, event_id)
                timing_by_tool = _evidence_query_timing_by_tool(agent_rows)
                all_entries.extend(_normalize_tool_calls(tool_rows, timing_by_tool=timing_by_tool))
            except Exception as exc:
                logger.warning("Failed to fetch tool calls for %s: %s", event_id, exc)
                missing.append("tool_call_log")

            # 3. LLM calls
            try:
                llm_rows = await self._fetch_llm_calls(session, event_id)
                all_entries.extend(_normalize_llm_calls(llm_rows))
            except Exception as exc:
                logger.warning("Failed to fetch LLM calls for %s: %s", event_id, exc)
                missing.append("llm_call_log")

            # 4. State transitions (event_audit_log)
            try:
                audit_rows = await self._fetch_audit_logs(session, event_id)
                all_entries.extend(_normalize_state_transitions(audit_rows))
            except Exception as exc:
                logger.warning("Failed to fetch audit logs for %s: %s", event_id, exc)
                missing.append("event_audit_log")

            # 5. Approvals (approval_record table — ISSUE-058)
            try:
                approval_rows = await self._fetch_approval_records(session, event_id)
                all_entries.extend(_normalize_approval_rows(approval_rows))
            except Exception as exc:
                logger.warning("Failed to fetch approvals for %s: %s", event_id, exc)
                missing.append("approval_record")

            # 6. Action execution jobs
            try:
                job_rows = await self._fetch_action_jobs(session, event_id)
                all_entries.extend(_normalize_action_executions(job_rows))
            except Exception as exc:
                logger.warning("Failed to fetch action jobs for %s: %s", event_id, exc)
                missing.append("action_execution_job")

            # 7. Dispositions (outbox)
            try:
                disp_rows = await self._fetch_dispositions(session, event_id)
                all_entries.extend(_normalize_dispositions(disp_rows))
            except Exception as exc:
                logger.warning("Failed to fetch dispositions for %s: %s", event_id, exc)
                missing.append("disposition_outbox")

            # 8. Writeback receipts
            try:
                wb_rows = await self._fetch_writebacks(session, event_id)
                all_entries.extend(_normalize_writebacks(wb_rows))
            except Exception as exc:
                logger.warning("Failed to fetch writebacks for %s: %s", event_id, exc)
                missing.append("disposition_receipt")

        # Sort: timestamp ascending, then entry_type order, then entry_id.
        all_entries.sort(key=_sort_key)

        summary = self._compute_summary(all_entries)

        if all_entries:
            first_ts = all_entries[0].timestamp
            last_ts = all_entries[-1].timestamp
            summary.total_duration_ms = max(0, int((last_ts - first_ts).total_seconds() * 1000))

        return DecisionTrace(
            event_id=event_id,
            entries=all_entries,
            summary=summary,
            missing_sources=missing,
        )

    # ------------------------------------------------------------------ #
    # Internal fetchers
    # ------------------------------------------------------------------ #

    async def _fetch_agent_traces(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.AgentTrace]:
        rows = await session.scalars(
            select(orm.AgentTrace)
            .where(orm.AgentTrace.event_id == event_id)
            .order_by(orm.AgentTrace.started_at.asc().nulls_last())
        )
        return list(rows)

    async def _fetch_tool_calls(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.ToolCallLog]:
        rows = await session.scalars(
            select(orm.ToolCallLog)
            .where(orm.ToolCallLog.event_id == event_id)
            .order_by(orm.ToolCallLog.started_at.asc().nulls_last())
        )
        return list(rows)

    async def _fetch_llm_calls(self, session: AsyncSession, event_id: str) -> list[orm.LLMCallLog]:
        rows = await session.scalars(
            select(orm.LLMCallLog)
            .where(orm.LLMCallLog.event_id == event_id)
            .order_by(orm.LLMCallLog.created_at.asc())
        )
        return list(rows)

    async def _fetch_audit_logs(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.EventAuditLog]:
        rows = await session.scalars(
            select(orm.EventAuditLog)
            .where(orm.EventAuditLog.event_id == event_id)
            .order_by(orm.EventAuditLog.created_at.asc())
        )
        return list(rows)

    async def _fetch_approval_records(
        self, session: AsyncSession, event_id: str
    ) -> list[ApprovalRecordORM]:
        rows = await session.scalars(
            select(ApprovalRecordORM)
            .where(ApprovalRecordORM.event_id == event_id)
            .order_by(ApprovalRecordORM.requested_at.asc())
        )
        return list(rows)

    async def _fetch_action_jobs(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.ActionExecutionJob]:
        rows = await session.scalars(
            select(orm.ActionExecutionJob)
            .where(orm.ActionExecutionJob.event_id == event_id)
            .order_by(orm.ActionExecutionJob.created_at.asc())
        )
        return list(rows)

    async def _fetch_dispositions(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.DispositionOutbox]:
        rows = await session.scalars(
            select(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
            .order_by(orm.DispositionOutbox.created_at.asc())
        )
        return list(rows)

    async def _fetch_writebacks(
        self, session: AsyncSession, event_id: str
    ) -> list[orm.DispositionReceipt]:
        rows = await session.scalars(
            select(orm.DispositionReceipt)
            .where(
                orm.DispositionReceipt.action_id.in_(
                    select(orm.Action.action_id).where(orm.Action.event_id == event_id)
                )
            )
            .order_by(orm.DispositionReceipt.confirmed_at.asc().nulls_last())
        )
        return list(rows)

    # ------------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------------ #

    @staticmethod
    def _compute_summary(entries: list[DecisionTraceEntry]) -> DecisionTraceSummary:
        summary = DecisionTraceSummary()
        for entry in entries:
            if entry.entry_type == DecisionTraceEntryType.AGENT_EXECUTION:
                summary.agent_count += 1
            elif entry.entry_type == DecisionTraceEntryType.TOOL_CALL:
                summary.tool_call_count += 1
            elif entry.entry_type == DecisionTraceEntryType.LLM_CALL:
                summary.llm_call_count += 1
                tokens = entry.detail.get("total_tokens", 0)
                if isinstance(tokens, int):
                    summary.total_tokens += tokens
            elif entry.entry_type == DecisionTraceEntryType.STATE_TRANSITION:
                summary.state_transition_count += 1
            elif entry.entry_type == DecisionTraceEntryType.APPROVAL:
                summary.approval_count += 1
            elif entry.entry_type == DecisionTraceEntryType.ACTION_EXECUTION:
                summary.action_execution_count += 1
            elif entry.entry_type == DecisionTraceEntryType.DISPOSITION:
                summary.disposition_count += 1
            elif entry.entry_type == DecisionTraceEntryType.WRITEBACK:
                summary.writeback_count += 1
        return summary


__all__ = ["DecisionTraceService"]
