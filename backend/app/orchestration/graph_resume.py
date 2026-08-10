"""Checkpoint resume helpers for LangGraph investigation (ISSUE-059 / ISSUE-192 / ISSUE-247).

Production ``resume_investigation`` hooks must continue from the saved
checkpoint after ``approval_wait_node`` or writeback halt — not restart via
``SuperAgent.investigate()`` with fresh initial state.

ISSUE-247: once DB status is already ``REPORTING`` / ``CLOSED`` / ``FAILED``,
resume must never fall back to a full-graph ``execute_investigation()`` restart
(that produces illegal ``reporting → triaging`` and marks FAILED).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.runnables import RunnableConfig
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.agent_io import EvidenceOutput, RiskAssessment
from app.models.enums import (
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    WritebackStatus,
)
from app.orchestration.workflow_graph import (
    NODE_APPROVAL,
    NODE_EXECUTE,
    NODE_VERIFY,
    invoke_investigation_graph,
)
from app.services.analysis_only_complete_persistence import (
    persist_analysis_only_complete_authoritative,
)
from app.services.evidence_projection import EvidenceProjection, bind_evidence_projection

logger = logging.getLogger(__name__)

GetSuperAgent = Callable[[], Awaitable[Any]]
GetWorkflowRuntime = Callable[[], Awaitable[Any]]

# Resume may delegate to Celery only when the event never entered the graph.
_GRAPH_NEVER_STARTED_STATUSES = frozenset(
    {
        EventStatus.NEW.value,
        EventStatus.TRIAGING.value,
    }
)

# Post-analysis / terminal statuses: never restart from triage (ISSUE-247).
_NO_FULL_GRAPH_RESTART_STATUSES = frozenset(
    {
        EventStatus.REPORTING.value,
        EventStatus.CLOSED.value,
        EventStatus.FAILED.value,
    }
)

# Manual holds that must survive VERIFYING resume even when writebacks confirm.
_LEGITIMATE_MANUAL_DEGRADED_PREFIXES = frozenset(
    {
        "missing_response_plan_for_required_policy",
        "disposition_activation_failed",
        "disposition_writeback_blocked",
        "execution_failed_unverified",
    }
)


def _degraded_flag_name(raw: Any) -> str:
    return str(raw).split("=", 1)[0]


def _has_legitimate_manual_hold(degraded_flags: list[Any]) -> bool:
    return any(
        _degraded_flag_name(flag) in _LEGITIMATE_MANUAL_DEGRADED_PREFIXES for flag in degraded_flags
    )


def _strip_stale_verify_degraded(degraded_flags: list[Any]) -> list[Any]:
    return [flag for flag in degraded_flags if _degraded_flag_name(flag) != "verify_degraded"]


def _only_stale_verify_degraded(degraded_flags: list[Any]) -> bool:
    return bool(degraded_flags) and all(
        _degraded_flag_name(flag) == "verify_degraded" for flag in degraded_flags
    )


async def _active_outbox_writeback_rows(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> list[tuple[str, str | None]]:
    async with session_factory() as session:
        result = await session.execute(
            select(
                orm.DispositionOutbox.intent_kind,
                orm.DispositionOutbox.latest_writeback_status,
            ).where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
            )
        )
        return [(str(intent), status) for intent, status in result.all()]


# Non-failed outbox statuses that allow VERIFYING resume to route toward REPORTING.
# CLOSED gate still requires CONFIRMED separately (workflow.validate_closed_gate).
_RESUME_ROUTING_TERMINAL_STATUSES = frozenset(
    {
        WritebackStatus.CONFIRMED.value,
        WritebackStatus.ACCEPTED.value,
    }
)


def _all_writebacks_resolved(statuses: list[str | None]) -> bool:
    """Return True when every active outbox reached a non-failed terminal status."""
    if not statuses:
        return False
    return all(status in _RESUME_ROUTING_TERMINAL_STATUSES for status in statuses)


def _terminal_writeback_resolved(rows: list[tuple[str, str | None]]) -> bool:
    """True when every active EVENT_STATUS_UPDATE outbox is CONFIRMED/ACCEPTED."""
    terminal_statuses = [
        status
        for intent, status in rows
        if intent == DispositionIntentKind.EVENT_STATUS_UPDATE.value
    ]
    if not terminal_statuses:
        return False
    return all(status in _RESUME_ROUTING_TERMINAL_STATUSES for status in terminal_statuses)


def _has_active_terminal_outbox(rows: list[tuple[str, str | None]]) -> bool:
    return any(
        intent == DispositionIntentKind.EVENT_STATUS_UPDATE.value for intent, _status in rows
    )


def _can_clear_manual_resolution(
    *,
    degraded_flags: list[Any],
    rows: list[tuple[str, str | None]],
    failed_writebacks: list[str],
    disposition_policy: str | None,
) -> bool:
    """ISSUE-205: entity-only writebacks must not clear legitimate manual holds."""
    if failed_writebacks:
        return False
    if _has_legitimate_manual_hold(degraded_flags):
        return False

    statuses = [status for _intent, status in rows]
    if not _all_writebacks_resolved(statuses):
        return False

    if _terminal_writeback_resolved(rows):
        return True

    # Optional-disposition stale path: no terminal outbox expected; verify_degraded-only.
    if (
        _only_stale_verify_degraded(degraded_flags)
        and not _has_active_terminal_outbox(rows)
        and disposition_policy == DispositionPolicy.NOT_REQUIRED.value
    ):
        return True

    return False


async def _reconcile_verify_resume_patch(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    values: dict[str, Any],
) -> dict[str, Any]:
    """Re-evaluate verify routing flags after external writeback/resume (ISSUE-196).

    Production resume previously cleared only ``halted``, leaving stale
    ``verify_need_manual_resolution`` / ``verify_need_writeback_recovery`` that
    routed back to ``manual_hold`` despite confirmed writebacks.
    """
    patch: dict[str, Any] = {}
    if values.get("halted"):
        patch["halted"] = False

    need_writeback = bool(values.get("verify_need_writeback_recovery"))
    need_manual = bool(values.get("verify_need_manual_resolution"))
    failed_writebacks = list(values.get("verify_failed_writebacks") or [])
    recoverable_writebacks = list(
        values.get("verify_recoverable_writeback_ids") or failed_writebacks
    )
    pending_actions = list(values.get("verify_pending_writeback_action_ids") or [])
    if not (need_writeback or need_manual or values.get("halted")):
        return patch

    degraded_flags = list(values.get("degraded_flags") or [])
    legitimate_manual = _has_legitimate_manual_hold(degraded_flags)
    outbox_rows = await _active_outbox_writeback_rows(session_factory, event_id)
    wb_statuses = [status for _intent, status in outbox_rows]
    writebacks_resolved = (
        not recoverable_writebacks and not pending_actions and _all_writebacks_resolved(wb_statuses)
    )
    disposition_policy = values.get("disposition_policy")

    if need_writeback and writebacks_resolved:
        patch["verify_need_writeback_recovery"] = False
        patch["verify_failed_writebacks"] = []
        patch["verify_recoverable_writeback_ids"] = []
        patch["verify_pending_writeback_action_ids"] = []
        patch["execution_substate"] = ExecutionSubstate.NONE.value

    if (
        need_manual
        and not legitimate_manual
        and _can_clear_manual_resolution(
            degraded_flags=degraded_flags,
            rows=outbox_rows,
            failed_writebacks=recoverable_writebacks,
            disposition_policy=disposition_policy,
        )
    ):
        patch["verify_need_manual_resolution"] = False
        patch.setdefault("execution_substate", ExecutionSubstate.NONE.value)
        stripped = _strip_stale_verify_degraded(degraded_flags)
        if stripped != degraded_flags:
            patch["degraded_flags"] = stripped

    return patch


async def _read_event_status(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> str:
    async with session_factory() as session:
        event_status = await session.scalar(
            select(orm.SecurityEvent.status).where(orm.SecurityEvent.event_id == event_id)
        )
    return str(event_status or "")


async def _read_event_status_enum(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> EventStatus | None:
    raw = await _read_event_status(session_factory, event_id)
    if not raw:
        return None
    try:
        return EventStatus(raw)
    except ValueError:
        return None


async def _sync_execution_substate(
    runtime: Any,
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    substate: ExecutionSubstate,
    *,
    event_status: EventStatus,
) -> EventStatus:
    """Persist substate; on caller/DB mismatch re-read authoritative status."""
    from app.orchestration.graph_resume_observability import GraphResumeFailedError

    try:
        await runtime.set_execution_substate(
            event_id,
            substate,
            event_status=event_status,
        )
        return event_status
    except ValidationError as exc:
        if "caller EventStatus does not match authoritative state" not in str(exc):
            raise
        authoritative = await _read_event_status_enum(session_factory, event_id)
        if authoritative is None:
            raise GraphResumeFailedError(
                "state mismatch with missing authoritative status",
                event_id=event_id,
                error_type="state_mismatch",
            ) from exc
        logger.warning(
            "graph resume state mismatch event=%s caller=%s authoritative=%s",
            event_id,
            event_status.value,
            authoritative.value,
        )
        if authoritative in {
            EventStatus.FAILED,
            EventStatus.CLOSED,
            EventStatus.REPORTING,
        }:
            return authoritative
        raise GraphResumeFailedError(
            f"state mismatch caller={event_status.value} authoritative={authoritative.value}",
            event_id=event_id,
            error_type="state_mismatch",
            execution_substate=substate.value,
        ) from exc


async def prepare_graph_resume_state(
    session_factory: async_sessionmaker[AsyncSession],
    graph: Any,
    event_id: str,
    runtime: Any,
) -> bool:
    """Clear halt flags on the checkpoint so ``ainvoke(None)`` can continue.

    Re-reads DB event status before patching (idempotent). Returns ``True`` when
    a checkpoint exists (even if no patch was required).
    """
    config = {"configurable": {"thread_id": event_id}}
    snapshot = await graph.aget_state(config)
    if snapshot is None or not snapshot.values:
        return False

    status_value = await _read_event_status(session_factory, event_id)
    if status_value in {
        EventStatus.FAILED.value,
        EventStatus.CLOSED.value,
    }:
        logger.info(
            "prepare_graph_resume: terminal DB status=%s event=%s; skip checkpoint patch",
            status_value,
            event_id,
        )
        return snapshot is not None and bool(snapshot.values)

    values = snapshot.values

    if status_value == EventStatus.VERIFYING.value:
        prior_need_writeback = bool(values.get("verify_need_writeback_recovery"))
        prior_need_manual = bool(values.get("verify_need_manual_resolution"))
        resume_patch = await _reconcile_verify_resume_patch(
            session_factory,
            event_id,
            values,
        )
        if resume_patch:
            recovery_resolved = (
                prior_need_writeback and resume_patch.get("verify_need_writeback_recovery") is False
            ) or (prior_need_manual and resume_patch.get("verify_need_manual_resolution") is False)
            await graph.aupdate_state(
                config,
                resume_patch,
                # Mark the patch as the execute tail when recovery has resolved,
                # so the graph schedules a fresh Verify pass.  Using NODE_VERIFY
                # here would route directly from stale WAITING state to report.
                as_node=NODE_EXECUTE if recovery_resolved else NODE_VERIFY,
            )
            values = {**values, **resume_patch}
        if values.get("execution_substate") == ExecutionSubstate.WAITING_WRITEBACK.value:
            authoritative = await _sync_execution_substate(
                runtime,
                session_factory,
                event_id,
                ExecutionSubstate.WAITING_WRITEBACK,
                event_status=EventStatus.VERIFYING,
            )
            if authoritative is not EventStatus.VERIFYING:
                return True
        return True

    if status_value == EventStatus.REPORTING.value:
        authoritative = await _sync_execution_substate(
            runtime,
            session_factory,
            event_id,
            ExecutionSubstate.NONE,
            event_status=EventStatus.REPORTING,
        )
        needs_patch = bool(
            values.get("halted")
            or values.get("needs_approval_wait")
            or values.get("execution_substate") == ExecutionSubstate.WAITING_APPROVAL.value
        )
        if needs_patch:
            await graph.aupdate_state(
                config,
                {
                    "halted": False,
                    "needs_approval_wait": False,
                    "execution_substate": ExecutionSubstate.NONE.value,
                    "event_status": EventStatus.REPORTING.value,
                },
                as_node=NODE_APPROVAL,
            )
        return True

    if status_value != EventStatus.EXECUTING_RESPONSE.value:
        logger.warning(
            "prepare_graph_resume: unexpected DB status=%s event=%s; skipping checkpoint patch",
            status_value,
            event_id,
        )
        return True

    await _sync_execution_substate(
        runtime,
        session_factory,
        event_id,
        ExecutionSubstate.NONE,
        event_status=EventStatus.EXECUTING_RESPONSE,
    )

    needs_patch = bool(
        values.get("halted")
        or values.get("needs_approval_wait")
        or values.get("execution_substate") == ExecutionSubstate.WAITING_APPROVAL.value
    )
    if not needs_patch:
        return True

    await graph.aupdate_state(
        config,
        {
            "halted": False,
            "needs_approval_wait": False,
            "execution_substate": ExecutionSubstate.NONE.value,
            "event_status": EventStatus.EXECUTING_RESPONSE.value,
        },
        as_node=NODE_APPROVAL,
    )
    return True


async def _persist_context_flag(store: Any, event_id: str, field: str, value: Any) -> None:
    if store is None:
        return
    try:
        await store.set(event_id, field, value)
    except Exception:
        logger.warning(
            "failed to persist %s=%s event=%s",
            field,
            value,
            event_id,
            exc_info=True,
        )


async def _resume_report_only_from_analysis(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    agent: Any,
) -> None:
    """Generate/persist report for an event already at REPORTING (no graph).

    Used when approval fully rejects / times out and the SuperAgent has no
    wired investigation graph. Must not restart triage (ISSUE-247).
    """
    from app.orchestration.graph_resume_observability import GraphResumeFailedError
    from app.services.report_input_builder import build_report_agent_input

    report_agent = getattr(agent, "report_agent", None)
    context_store = getattr(agent, "context_store", None)
    if report_agent is None:
        raise GraphResumeFailedError(
            "report-only resume requires ReportAgent on SuperAgent",
            event_id=event_id,
            error_type="report_agent_missing",
        )
    if context_store is None:
        raise GraphResumeFailedError(
            "report-only resume requires context_store for analysis artifacts",
            event_id=event_id,
            error_type="report_prerequisites_missing",
        )

    async def _persist_analysis_completion() -> None:
        await persist_analysis_only_complete_authoritative(
            event_id,
            context_store=context_store,
            event_service=event_service,
            degraded_flags=getattr(agent, "_degraded_flags", None),
            writer="GraphResume",
            refresh_closed_snapshot=False,
        )

    evidence_raw = await context_store.get(event_id, "evidence_output")
    risk_raw = await context_store.get(event_id, "risk_assessment")
    if evidence_raw is None or risk_raw is None:
        raise GraphResumeFailedError(
            "report-only resume missing evidence_output/risk_assessment in context",
            event_id=event_id,
            error_type="report_prerequisites_missing",
        )

    try:
        evidence_output = (
            evidence_raw
            if isinstance(evidence_raw, EvidenceOutput)
            else EvidenceOutput.model_validate(evidence_raw)
        )
        risk_assessment = (
            risk_raw
            if isinstance(risk_raw, RiskAssessment)
            else RiskAssessment.model_validate(risk_raw)
        )
    except Exception as exc:
        raise GraphResumeFailedError(
            "report-only resume: stored evidence/risk payloads are invalid",
            event_id=event_id,
            error_type="report_prerequisites_invalid",
        ) from exc

    # Idempotent: if a report row already exists, keep REPORTING and skip work.
    event_service = getattr(agent, "event_service", None)
    get_report = getattr(event_service, "get_report", None) if event_service is not None else None
    if get_report is not None:
        try:
            existing = await get_report(event_id=event_id)
        except TypeError:
            existing = await get_report(event_id)
        if existing is not None:
            await _persist_context_flag(context_store, event_id, "report_generated", True)
            await _persist_analysis_completion()
            logger.info(
                "report-only resume: report already present event=%s; keeping REPORTING",
                event_id,
            )
            return

    report_input = await build_report_agent_input(
        event_id,
        evidence_output=evidence_output,
        risk_assessment=risk_assessment,
        context_store=context_store,
        session_factory=session_factory,
    )
    try:
        report = await report_agent.execute(report_input)
    except Exception as exc:
        await _persist_context_flag(context_store, event_id, "report_generated", False)
        raise GraphResumeFailedError(
            f"report-only resume failed: {type(exc).__name__}: {exc}",
            event_id=event_id,
            error_type="report_generation_failed",
        ) from exc

    if report is None:
        await _persist_context_flag(context_store, event_id, "report_generated", False)
        raise GraphResumeFailedError(
            "report-only resume: ReportAgent returned no report",
            event_id=event_id,
            error_type="report_generation_failed",
        )

    await _persist_context_flag(context_store, event_id, "report_generated", True)
    await _persist_analysis_completion()
    logger.info("report-only resume completed event=%s (status remains REPORTING)", event_id)


async def _delegate_execute_investigation(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> None:
    from app.services.investigation_guidance import (
        resolve_include_response_execution_for_resume,
    )
    from app.tasks.investigation_tasks import execute_investigation

    include_response = await resolve_include_response_execution_for_resume(
        session_factory,
        event_id,
    )
    await execute_investigation(
        event_id,
        include_response_execution=include_response,
    )


async def resume_investigation_from_checkpoint(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    get_super_agent: GetSuperAgent,
    get_workflow_runtime: GetWorkflowRuntime,
) -> None:
    """Resume LangGraph from checkpoint after approval or writeback.

    ISSUE-247: ``REPORTING`` / ``CLOSED`` / ``FAILED`` never fall back to a
    full-graph ``execute_investigation()`` restart. ``REPORTING`` continues via
    checkpoint → ``report_node``, or a report-only narrow path when no graph is
    wired. Missing checkpoint on ``REPORTING`` raises ``checkpoint_missing``
    while leaving the event at ``REPORTING`` (caller records degraded flags).
    """
    from app.orchestration.graph_resume_observability import GraphResumeFailedError

    agent = await get_super_agent()
    graph = getattr(agent, "_investigation_graph", None)
    status_value = await _read_event_status(session_factory, event_id)
    if status_value in _NO_FULL_GRAPH_RESTART_STATUSES:
        if status_value in {EventStatus.CLOSED.value, EventStatus.FAILED.value}:
            logger.info(
                "resume skipped for terminal status=%s event=%s",
                status_value,
                event_id,
            )
            return

        # REPORTING: continue report phase only — never restart triage.
        if graph is None:
            await _resume_report_only_from_analysis(session_factory, event_id, agent)
            return

        reporting_config: RunnableConfig = {"configurable": {"thread_id": event_id}}
        runtime = await get_workflow_runtime()
        has_checkpoint = await prepare_graph_resume_state(
            session_factory,
            graph,
            event_id,
            runtime,
        )
        if not has_checkpoint:
            raise GraphResumeFailedError(
                f"no checkpoint for event in status {status_value}",
                event_id=event_id,
                error_type="checkpoint_missing",
            )

        projection = EvidenceProjection(session_factory)
        with bind_evidence_projection(projection):
            await invoke_investigation_graph(graph, None, reporting_config)
        return

    if graph is None:
        # Only safe for pre-graph statuses; post-analysis handled above.
        await _delegate_execute_investigation(session_factory, event_id)
        return

    config: RunnableConfig = {"configurable": {"thread_id": event_id}}
    runtime = await get_workflow_runtime()
    has_checkpoint = await prepare_graph_resume_state(
        session_factory,
        graph,
        event_id,
        runtime,
    )
    if not has_checkpoint:
        if status_value in _GRAPH_NEVER_STARTED_STATUSES:
            await _delegate_execute_investigation(session_factory, event_id)
            return
        raise GraphResumeFailedError(
            f"no checkpoint for event in status {status_value}",
            event_id=event_id,
            error_type="checkpoint_missing",
        )

    projection = EvidenceProjection(session_factory)
    with bind_evidence_projection(projection):
        await invoke_investigation_graph(graph, None, config)


__all__ = [
    "prepare_graph_resume_state",
    "resume_investigation_from_checkpoint",
]
