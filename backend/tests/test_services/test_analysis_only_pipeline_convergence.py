"""AnalysisOnlyPipeline ConvergenceGuard lifecycle (ISSUE-168).

The pipeline runs the same production LLM client / ToolExecutor as the
investigation stack, so it must release the shared guard's counters when a
run finishes — otherwise a re-investigation of the same event starts from
stale counters and the in-process ``_states`` dict grows unboundedly.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import ShadowTraceError
from app.orchestration.convergence_guard import ConvergenceGuard
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline


@pytest.mark.asyncio
async def test_run_releases_guard_counters_on_failure() -> None:
    """run() must reset the shared guard even when the run fails early."""
    guard = ConvergenceGuard()
    event_id = "evt-iss168-pipeline-fail"
    # Counters accumulated by the shared LLM client / ToolExecutor before or
    # during the run — exactly what must not survive past the run.
    await guard.record_step(event_id, "llm_call", signature="TriageAgent:triage_extract:m")
    await guard.record_step(event_id, tool_name="block_ip")

    event_service = MagicMock()
    event_service.get_event = AsyncMock(return_value=None)
    pipeline = AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=MagicMock(),
        event_service=event_service,
        state_machine=MagicMock(),
        convergence_guard=guard,
    )

    with pytest.raises(ShadowTraceError, match="not found"):
        await pipeline.run(event_id)

    state = guard.get_state(event_id)
    assert state.total_steps == 0
    assert state.llm_calls == 0


@pytest.mark.asyncio
async def test_run_is_noop_without_guard() -> None:
    """run() without a guard stays a no-op (back-compat for old fixtures)."""
    guard = ConvergenceGuard()
    event_id = "evt-iss168-noguard"
    await guard.record_step(event_id, "llm_call", signature="a:b:c")
    # A guard configured elsewhere but not on the pipeline must not be
    # touched — the pipeline only resets what it was explicitly given.
    event_service = MagicMock()
    event_service.get_event = AsyncMock(return_value=None)
    pipeline = AnalysisOnlyPipeline(
        triage_agent=MagicMock(),
        evidence_agent=MagicMock(),
        rag_agent=MagicMock(),
        risk_agent=MagicMock(),
        report_agent=MagicMock(),
        event_service=event_service,
        state_machine=MagicMock(),
    )
    with pytest.raises(ShadowTraceError, match="not found"):
        await pipeline.run(event_id)

    assert guard.get_state(event_id).llm_calls == 1
