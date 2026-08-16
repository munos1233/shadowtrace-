"""AnalysisOnlyPipeline ISSUE-208 early memory enqueue tests.

The pipeline schedules profile-only memory candidates after analysis-only
completion (REPORTING); MemoryAgent itself gates candidate types, so these
tests only verify the scheduling contract (when / whether MemoryAgent.execute
is invoked), not the candidate gates (covered in test_memory_agent.py).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    InvestigationResult,
    MemoryAgentInput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.context import EventContext
from app.models.enums import (
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
)
from app.models.report import InvestigationReport
from app.models.security_event import EventSummary
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
from app.services.context_service import SetResult

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

    async def get(self, event_id: str, key: str) -> Any:
        return getattr(self.context, key, None)

    async def set(
        self,
        event_id: str,
        key: str,
        value: Any,
        version: int | None = None,
    ) -> SetResult:
        del event_id, version
        setattr(self.context, key, value)
        return SetResult(redis_ok=True, version=1)


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
    settings.allow_live_side_effects = False
    settings.allow_xdr_writeback = False
    settings.source_mode = "mock_xdr"
    settings.disposition_mode = "mock_xdr"
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


def test_memory_failure_degraded_flags_are_allowlisted() -> None:
    """ISSUE-208: pipeline/SuperAgent failure flags must persist via DegradedFlagService."""
    from app.services.degraded_flag_service import (
        DEGRADED_FLAG_ALLOWLIST,
        DEGRADED_FLAG_TRUSTED_CALLERS,
    )

    assert "memory_after_analysis_failed" in DEGRADED_FLAG_ALLOWLIST
    assert "memory_after_close_failed" in DEGRADED_FLAG_ALLOWLIST
    assert "SuperAgent" in DEGRADED_FLAG_TRUSTED_CALLERS
    assert "AnalysisOnlyPipeline" in DEGRADED_FLAG_TRUSTED_CALLERS


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


@pytest.mark.asyncio
async def test_short_circuit_no_report_schedules_memory_after_analysis() -> None:
    """ISSUE-208 / ISSUE-204: short-circuit + generate_report=false must still
    enqueue profile candidates at REPORTING."""
    from types import SimpleNamespace

    memory_agent = _MemoryAgent()
    context = _reporting_context()
    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(context),
        settings=_settings(),
    )
    pipeline._transition = AsyncMock()
    pipeline._persist_report_skipped = AsyncMock()
    pipeline._persist_analysis_only_complete = AsyncMock()
    pipeline._read_false_positive_match = AsyncMock(return_value=None)

    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        decision_summary="low risk",
    )
    event = SimpleNamespace(title="t", disposition_policy="not_required")

    result = await pipeline._short_circuit_close(
        EVENT_ID,
        event,
        triage,
        generate_report=False,
    )

    assert result.status is EventStatus.REPORTING
    assert result.analysis_only_complete is True
    pipeline._persist_analysis_only_complete.assert_awaited_once_with(EVENT_ID)
    context.analysis_only_complete = True
    if pipeline._memory_tasks:
        await asyncio.gather(*pipeline._memory_tasks)
    assert len(memory_agent.inputs) == 1
    assert memory_agent.inputs[0].investigation_result.final_status is EventStatus.REPORTING


@pytest.mark.asyncio
async def test_generate_report_false_schedules_memory_after_analysis() -> None:
    """ISSUE-208 / ISSUE-204: full pipeline exit with generate_report=false."""
    memory_agent = _MemoryAgent()
    context = EventContext(
        event=EventSummary(
            event_id=EVENT_ID,
            event_type=EventType.DATA_EXFILTRATION,
            title="Suspicious upload",
            status=EventStatus.NEW,
            severity=Severity.HIGH,
            risk_score=88,
            final_verdict=FinalVerdict.CONFIRMED_THREAT,
            writeback_required=False,
            writeback_readiness="not_required",
            disposition_policy="not_required",
            external_unsynced=False,
        ),
    )
    triage_result = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        decision_summary="investigate",
    )
    evidence_output = EvidenceOutput(
        evidence_list=[],
        conflicts=[],
        gaps=[],
        success_sources=[],
        failed_sources=[],
        overall_confidence=0.8,
        collection_status=CollectionStatus.COMPLETED,
    )
    risk_assessment = RiskAssessment(
        risk_score=88,
        severity=Severity.HIGH,
        confidence=0.9,
        risk_factors=[],
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
    )

    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(context),
        settings=_settings(),
    )
    pipeline._triage.execute = AsyncMock(return_value=triage_result)
    pipeline._evidence.execute = AsyncMock(return_value=evidence_output)
    pipeline._rag.execute = AsyncMock(return_value=None)
    pipeline._run_fp_adjudication = AsyncMock(return_value=None)
    pipeline._run_graph = AsyncMock(return_value=None)
    pipeline._run_risk = AsyncMock(return_value=risk_assessment)
    pipeline._transition = AsyncMock()

    result = await pipeline._run(EVENT_ID, generate_report=False)

    assert result.status is EventStatus.REPORTING
    assert result.analysis_only_complete is True
    assert result.report is None
    context.event.status = EventStatus.REPORTING  # type: ignore[union-attr]
    context.analysis_only_complete = True
    if pipeline._memory_tasks:
        await asyncio.gather(*pipeline._memory_tasks)
    assert len(memory_agent.inputs) == 1
    assert memory_agent.inputs[0].investigation_result.final_status is EventStatus.REPORTING


@pytest.mark.asyncio
async def test_generate_report_false_skips_memory_when_flag_off() -> None:
    """Flag rollback: generate_report=false still must not early-enqueue."""
    memory_agent = _MemoryAgent()
    context = EventContext(
        event=EventSummary(
            event_id=EVENT_ID,
            event_type=EventType.DATA_EXFILTRATION,
            title="Suspicious upload",
            status=EventStatus.NEW,
            severity=Severity.HIGH,
            risk_score=88,
            final_verdict=FinalVerdict.CONFIRMED_THREAT,
            writeback_required=False,
            writeback_readiness="not_required",
            disposition_policy="not_required",
            external_unsynced=False,
        ),
    )
    triage_result = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        decision_summary="investigate",
    )
    evidence_output = EvidenceOutput(
        evidence_list=[],
        conflicts=[],
        gaps=[],
        success_sources=[],
        failed_sources=[],
        overall_confidence=0.8,
        collection_status=CollectionStatus.COMPLETED,
    )
    risk_assessment = RiskAssessment(
        risk_score=88,
        severity=Severity.HIGH,
        confidence=0.9,
        risk_factors=[],
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
    )

    pipeline = _pipeline(
        memory_agent=memory_agent,
        context_store=_ContextStore(context),
        settings=_settings(memory_enqueue_after_analysis=False),
    )
    pipeline._triage.execute = AsyncMock(return_value=triage_result)
    pipeline._evidence.execute = AsyncMock(return_value=evidence_output)
    pipeline._rag.execute = AsyncMock(return_value=None)
    pipeline._run_fp_adjudication = AsyncMock(return_value=None)
    pipeline._run_graph = AsyncMock(return_value=None)
    pipeline._run_risk = AsyncMock(return_value=risk_assessment)
    pipeline._transition = AsyncMock()

    result = await pipeline._run(EVENT_ID, generate_report=False)

    assert result.status is EventStatus.REPORTING
    assert memory_agent.inputs == []
