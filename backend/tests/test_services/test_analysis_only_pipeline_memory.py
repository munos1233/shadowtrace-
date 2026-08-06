"""AnalysisOnlyPipeline ISSUE-208 early memory enqueue tests.

The pipeline schedules profile-only memory candidates after analysis-only
completion (REPORTING); MemoryAgent itself gates candidate types, so these
tests only verify the scheduling contract (when / whether MemoryAgent.execute
is invoked), not the candidate gates (covered in test_memory_agent.py).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.agent_io import InvestigationResult, MemoryAgentInput
from app.models.context import EventContext
from app.models.enums import EventStatus, EventType, FinalVerdict, Severity
from app.models.report import InvestigationReport
from app.models.security_event import EventSummary
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline

EVENT_ID = "evt-mem-pipeline-0001"


def _reporting_context() -> EventContext:
    return EventContext(
        event=EventSummary(
            event_id=EVENT_ID,
            event_type=EventType.DATA_EXFILTRATION,
            title="Suspicious upload",
            status=EventStatus.REPORTING,
            severity=Severity.HIGH,
            risk_score=88,
            final_verdict=FinalVerdict.CONFIRMED_THREAT,
            writeback_required=False,
            writeback_readiness="not_required",
            disposition_policy="not_required",
            external_unsynced=False,
        ),
        report=InvestigationReport(
            report_id="rpt-pipeline-1",
            event_id=EVENT_ID,
            title="Analysis report",
            summary="Analysis complete.",
            final_verdict=FinalVerdict.CONFIRMED_THREAT,
            risk_score=88,
            severity=Severity.HIGH,
        ),
        analysis_only_complete=True,
    )


class _ContextStore:
    def __init__(self, context: EventContext) -> None:
        self.context = context

    async def get_full_context(self, event_id: str) -> EventContext:
        return self.context


class _MemoryAgent:
    def __init__(self) -> None:
        self.inputs: list[MemoryAgentInput] = []
        self.early_enqueue_enabled = True

    async def execute(self, input: MemoryAgentInput) -> None:
        self.inputs.append(input)


def _pipeline(
    *,
    memory_agent: Any | None = None,
    context_store: Any | None = None,
    settings: Any | None = None,
) -> AnalysisOnlyPipeline:
    return AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=MagicMock(),
        context_store=context_store,
        settings=settings,
        memory_agent=memory_agent,
    )


def _settings(*, memory_enqueue_after_analysis: bool = True) -> MagicMock:
    settings = MagicMock()
    settings.memory_enqueue_after_analysis = memory_enqueue_after_analysis
    return settings


@pytest.mark.asyncio
async def test_schedule_fires_memory_execute_with_reporting_result() -> None:
    memory_agent = _MemoryAgent()
    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(_reporting_context()),
        settings=_settings(),
    )

    task = pipeline._schedule_memory_after_analysis(EVENT_ID)
    assert task is not None
    await task

    assert len(memory_agent.inputs) == 1
    result: InvestigationResult = memory_agent.inputs[0].investigation_result
    assert result.final_status is EventStatus.REPORTING
    assert result.event_id == EVENT_ID


@pytest.mark.asyncio
async def test_schedule_skipped_when_flag_off() -> None:
    memory_agent = _MemoryAgent()
    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(_reporting_context()),
        settings=_settings(memory_enqueue_after_analysis=False),
    )

    task = pipeline._schedule_memory_after_analysis(EVENT_ID)

    assert task is None
    assert memory_agent.inputs == []


@pytest.mark.asyncio
async def test_schedule_skipped_without_memory_agent() -> None:
    pipeline = _pipeline(
        memory_agent=None,
        context_store=_ContextStore(_reporting_context()),
        settings=_settings(),
    )

    assert pipeline._schedule_memory_after_analysis(EVENT_ID) is None


@pytest.mark.asyncio
async def test_run_memory_after_analysis_failure_records_degraded_flag() -> None:
    memory_agent = MagicMock()
    memory_agent.execute = AsyncMock(side_effect=RuntimeError("enqueue failed"))
    memory_agent.early_enqueue_enabled = True
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=[])
    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(_reporting_context()),
        settings=_settings(),
    )
    pipeline._degraded_flags = degraded

    await pipeline._run_memory_consolidation(EVENT_ID, EventStatus.REPORTING)

    degraded.set_flag.assert_awaited_once()
    args = degraded.set_flag.await_args.args
    assert args[0] == EVENT_ID
    assert args[1] == "memory_after_analysis_failed"


@pytest.mark.asyncio
async def test_schedule_memory_after_close_fires_full_consolidation() -> None:
    """CLOSED events (analysis-only auto/short-circuit close) schedule the full
    MemoryAgent pass — ISSUE-208 blocker: these paths must not be missed."""
    context = _reporting_context()
    context.event.status = EventStatus.CLOSED  # type: ignore[union-attr]
    memory_agent = _MemoryAgent()
    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(context),
        settings=_settings(),
    )

    task = pipeline._schedule_memory_after_close(EVENT_ID)
    assert task is not None
    await task

    assert len(memory_agent.inputs) == 1
    assert memory_agent.inputs[0].investigation_result.final_status is EventStatus.CLOSED


@pytest.mark.asyncio
async def test_run_memory_consolidation_skips_on_status_mismatch() -> None:
    """A scheduled REPORTING pass must not run once the snapshot moved to CLOSED
    (the CLOSED path owns consolidation then)."""
    context = _reporting_context()
    context.event.status = EventStatus.CLOSED  # type: ignore[union-attr]
    memory_agent = _MemoryAgent()
    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(context),
        settings=_settings(),
    )

    await pipeline._run_memory_consolidation(EVENT_ID, EventStatus.REPORTING)

    assert memory_agent.inputs == []


@pytest.mark.asyncio
async def test_flag_off_keeps_closed_consolidation() -> None:
    """MEMORY_ENQUEUE_AFTER_ANALYSIS=false rolls back only the early (REPORTING)
    enqueue — CLOSED consolidation must stay on (matches SuperAgent)."""
    context = _reporting_context()
    context.event.status = EventStatus.CLOSED  # type: ignore[union-attr]
    memory_agent = _MemoryAgent()
    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(context),
        settings=_settings(memory_enqueue_after_analysis=False),
    )

    task = pipeline._schedule_memory_after_close(EVENT_ID)
    assert task is not None
    await task
    assert len(memory_agent.inputs) == 1
    assert memory_agent.inputs[0].investigation_result.final_status is EventStatus.CLOSED
