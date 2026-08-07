"""Investigation phase guidance for analysis-only vs full-loop UX (ISSUE-103)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    NextRecommendedAction,
    ReportQuality,
    ResponsePhaseState,
)
from app.services.agent_trace_service import AgentTraceService

WorkflowPath = Literal["analysis_only", "full_loop"]

_ANALYSIS_STATUSES = frozenset(
    {
        EventStatus.TRIAGING,
        EventStatus.COLLECTING_EVIDENCE,
        EventStatus.ANALYZING,
        EventStatus.SCORING,
    }
)

_AUTO_RESPONSE_FULL_LOOP_AUDIT = "auto_response:policy_match"
_ANALYSIS_ONLY_DEFERRED_SUFFIX = (
    "本事件已完成仅分析，无法从 REPORTING 补发处置方案。"
    "对新事件请在发起调查前选择「分析并生成处置方案」。"
)
_ANALYSIS_ONLY_MODE_HINT = (
    "（当前部署 ORCHESTRATION_MODE=analysis_only，完整处置链路不可用。）"
)


@dataclass(frozen=True)
class InvestigationGuidance:
    analysis_only_complete: bool
    execution_substate: ExecutionSubstate
    response_phase_state: ResponsePhaseState
    next_recommended_action: NextRecommendedAction
    full_loop_available: bool
    phase_message: str | None = None


def full_loop_available(orchestration_mode: str | None) -> bool:
    return (orchestration_mode or "graph").strip().lower() != "analysis_only"


def workflow_path_from_request(*, include_response_execution: bool) -> WorkflowPath:
    return "full_loop" if include_response_execution else "analysis_only"


def _execution_substate_from_snapshot(snapshot: dict[str, Any] | None) -> ExecutionSubstate:
    if not isinstance(snapshot, dict):
        return ExecutionSubstate.NONE
    raw = snapshot.get("execution_substate")
    if raw is None:
        return ExecutionSubstate.NONE
    try:
        return ExecutionSubstate(str(raw).lower())
    except ValueError:
        return ExecutionSubstate.NONE


def _analysis_only_complete_from_snapshot(snapshot: dict[str, Any] | None) -> bool:
    if not isinstance(snapshot, dict):
        return False
    return bool(snapshot.get("analysis_only_complete"))


def _report_generated_from_snapshot(snapshot: dict[str, Any] | None) -> bool:
    if not isinstance(snapshot, dict):
        return False
    if snapshot.get("report") is not None:
        return True
    return bool(snapshot.get("report_generated"))


def _report_quality_from_snapshot(snapshot: dict[str, Any] | None) -> ReportQuality | None:
    """Best-effort quality for REPORTING UX copy (ISSUE-250)."""
    if not isinstance(snapshot, dict):
        return None
    raw: Any = None
    report = snapshot.get("report")
    if isinstance(report, dict):
        raw = report.get("report_quality")
    elif report is not None and hasattr(report, "report_quality"):
        raw = getattr(report, "report_quality", None)
    if raw is None:
        raw = snapshot.get("report_quality")
    if raw is None:
        return None
    if isinstance(raw, ReportQuality):
        return raw
    try:
        return ReportQuality(str(raw).lower())
    except ValueError:
        return None


def _reporting_ready_phase_message(
    *,
    analysis_only_complete: bool,
    loop_available: bool,
    report_quality: ReportQuality | None,
) -> str:
    """Operator copy when a readable report already exists (GET /report 200)."""
    if report_quality is ReportQuality.DEGRADED_TEMPLATE:
        message = "分析完成（模板报告）"
    else:
        message = "可查看报告"
    if analysis_only_complete:
        message = f"{message}。{_ANALYSIS_ONLY_DEFERRED_SUFFIX}"
        if not loop_available:
            message += _ANALYSIS_ONLY_MODE_HINT
    return message


def derive_investigation_guidance(
    *,
    status: EventStatus,
    disposition_policy: DispositionPolicy,
    context_snapshot: dict[str, Any] | None,
    orchestration_mode: str | None,
) -> InvestigationGuidance:
    """Derive operator-facing phase hints from authoritative event + context."""
    analysis_only_complete = _analysis_only_complete_from_snapshot(context_snapshot)
    report_generated = _report_generated_from_snapshot(context_snapshot)
    report_quality = _report_quality_from_snapshot(context_snapshot)
    execution_substate = _execution_substate_from_snapshot(context_snapshot)
    loop_available = full_loop_available(orchestration_mode)

    if status is EventStatus.NEW:
        return InvestigationGuidance(
            analysis_only_complete=False,
            execution_substate=ExecutionSubstate.NONE,
            response_phase_state=ResponsePhaseState.NOT_STARTED,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status in _ANALYSIS_STATUSES:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.ANALYSIS_IN_PROGRESS,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status is EventStatus.REPORTING and not report_generated:
        # ISSUE-204: no report bytes yet — guide POST /report, never suggest CLOSE.
        if analysis_only_complete:
            message = f"分析完成·报告未生成。{_ANALYSIS_ONLY_DEFERRED_SUFFIX}"
            if not loop_available:
                message += _ANALYSIS_ONLY_MODE_HINT
        else:
            message = "分析完成·报告未生成"
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.ANALYSIS_COMPLETE_DEFERRED,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
            phase_message=message,
        )

    if status is EventStatus.REPORTING:
        # ISSUE-250: readable report present — never claim「报告未生成」.
        message = _reporting_ready_phase_message(
            analysis_only_complete=analysis_only_complete,
            loop_available=loop_available,
            report_quality=report_quality,
        )
        if analysis_only_complete:
            next_action = (
                NextRecommendedAction.CLOSE
                if disposition_policy is DispositionPolicy.NOT_REQUIRED
                else NextRecommendedAction.NONE
            )
            return InvestigationGuidance(
                analysis_only_complete=True,
                execution_substate=execution_substate,
                response_phase_state=ResponsePhaseState.ANALYSIS_COMPLETE_DEFERRED,
                next_recommended_action=next_action,
                full_loop_available=loop_available,
                phase_message=message,
            )
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.NOT_STARTED,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
            phase_message=message,
        )

    if status is EventStatus.PLANNING_RESPONSE:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.RESPONSE_PLANNING,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status is EventStatus.WAITING_APPROVAL:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.AWAITING_APPROVAL,
            next_recommended_action=NextRecommendedAction.APPROVE_ACTIONS,
            full_loop_available=loop_available,
        )

    if status in {
        EventStatus.EXECUTING_RESPONSE,
        EventStatus.VERIFYING,
        EventStatus.REPLANNING,
    }:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.EXECUTING,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    if status in {EventStatus.CLOSED, EventStatus.CONTAINED}:
        return InvestigationGuidance(
            analysis_only_complete=analysis_only_complete,
            execution_substate=execution_substate,
            response_phase_state=ResponsePhaseState.COMPLETE,
            next_recommended_action=NextRecommendedAction.NONE,
            full_loop_available=loop_available,
        )

    return InvestigationGuidance(
        analysis_only_complete=analysis_only_complete,
        execution_substate=execution_substate,
        response_phase_state=ResponsePhaseState.NOT_STARTED,
        next_recommended_action=NextRecommendedAction.NONE,
        full_loop_available=loop_available,
    )


async def record_investigation_workflow_path(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    workflow_path: WorkflowPath,
    include_response_execution: bool,
) -> None:
    """Persist workflow_path for decision trace aggregation (ISSUE-103)."""
    now = datetime.now(UTC)
    trace_service = AgentTraceService(session_factory)
    await trace_service.log_trace(
        event_id,
        "super_agent",
        {
            "workflow_path": workflow_path,
            "include_response_execution": include_response_execution,
        },
        {"workflow_path": workflow_path},
        "completed",
        now,
        now,
    )


async def _has_full_loop_trace_evidence(session: AsyncSession, event_id: str) -> bool:
    """True when durable super_agent trace shows an explicit full-loop path."""
    traces = (
        await session.scalars(
            select(orm.AgentTrace)
            .where(
                orm.AgentTrace.event_id == event_id,
                orm.AgentTrace.agent_name == "super_agent",
            )
            .order_by(orm.AgentTrace.started_at.desc())
            .limit(5)
        )
    ).all()
    for trace in traces:
        output = trace.output_data if isinstance(trace.output_data, dict) else {}
        if output.get("workflow_path") == "full_loop":
            return True
        input_data = trace.input_data if isinstance(trace.input_data, dict) else {}
        if input_data.get("include_response_execution") is True:
            return True
    return False


async def resolve_include_response_execution_for_resume(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> bool:
    """Infer full-loop resume semantics for approval/writeback hooks (#613).

    Fail-closed: only explicit intent flags, super_agent workflow traces, or
    auto-response audit markers may re-enter the response execution path.
    """
    async with session_factory() as session:
        intent_flag = await session.scalar(
            select(orm.InvestigationIntent.include_response_execution)
            .where(
                orm.InvestigationIntent.event_id == event_id,
                orm.InvestigationIntent.include_response_execution.is_(True),
            )
            .order_by(orm.InvestigationIntent.created_at.desc())
            .limit(1)
        )
        if intent_flag is True:
            return True
        if await _has_full_loop_trace_evidence(session, event_id):
            return True
        audit_match = await session.scalar(
            select(orm.EventAuditLog.reason)
            .where(
                orm.EventAuditLog.event_id == event_id,
                orm.EventAuditLog.reason == _AUTO_RESPONSE_FULL_LOOP_AUDIT,
            )
            .limit(1)
        )
        return audit_match is not None


__all__ = [
    "InvestigationGuidance",
    "WorkflowPath",
    "derive_investigation_guidance",
    "full_loop_available",
    "record_investigation_workflow_path",
    "resolve_include_response_execution_for_resume",
    "workflow_path_from_request",
]
