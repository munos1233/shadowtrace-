"""ISSUE-055 multi-agent orchestration integration tests."""

from __future__ import annotations

import time
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.agents.report_section_builder import SECTION_KEYS
from app.core.errors import DependencyUnavailableError
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.security_event import EventSummary
from app.models.workflow import MAX_AGENT_RETRIES
from app.orchestration.workflow_graph import NODE_CLOSE, NODE_RISK
from app.services.agent_trace_service import AgentTraceService
from app.services.context_service import EventContextStore
from app.services.event_service import EventService
from app.services.evidence_projection import bind_evidence_projection
from app.services.state_machine_service import StateMachineService
from tests.test_orchestration.orchestration_fixtures import (
    GOLDEN_ORCHESTRATION_MAX_SECONDS,
    GOLDEN_ORCHESTRATION_STATUSES,
    ORCHESTRATION_AGENT_ORDER,
    assert_agent_trace_order,
    assert_ordered_subsequence,
    assert_valid_audit_transitions,
    exercise_concurrent_context_writes,
    exercise_version_conflict_retry,
    ingest_main_scenario_event,
    seed_graph_event,
)

pytestmark = pytest.mark.orchestration


def _graph_base_state(event_id: str) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_status": EventStatus.TRIAGING.value,
        "disposition_policy": DispositionPolicy.NOT_REQUIRED.value,
        "severity": Severity.HIGH.value,
        "final_verdict": None,
        "confidence": 0.0,
        "need_investigation": True,
        "execution_substate": "none",
        "event_status_update_readiness": "not_required",
        "degraded_flags": [],
        "node_trace": [],
        "halted": False,
        "disposition_only_intent": False,
        "report_generated": False,
        "needs_approval_wait": False,
    }


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_golden_path_super_agent_orchestration(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    agent_trace_service: AgentTraceService,
    build_super_agent,
) -> None:
    """Scenario 1: SuperAgent + PlannerAgent drive the main scenario to REPORTING."""
    event_id = await ingest_main_scenario_event(source_adapter, source_ingester, event_service)
    agent, projection = build_super_agent()

    started = time.perf_counter()
    with bind_evidence_projection(projection):
        await agent.investigate(event_id)
    elapsed = time.perf_counter() - started
    assert elapsed < GOLDEN_ORCHESTRATION_MAX_SECONDS

    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status is EventStatus.REPORTING
    assert event.final_verdict is FinalVerdict.CONFIRMED_THREAT
    assert event.risk_score >= 70

    plan = await context_store.get(event_id, "execution_plan")
    assert plan is not None
    steps = sorted(plan.get("steps") or [], key=lambda row: row["step_order"])
    assigned = [row["assigned_agent"] for row in steps]
    assert "evidence_agent" in assigned
    assert "risk_agent" in assigned
    assert assigned.index("evidence_agent") < assigned.index("risk_agent")

    triage_ctx = await context_store.get(event_id, "triage_result")
    evidence_ctx = await context_store.get(event_id, "evidence_output")
    risk_ctx = await context_store.get(event_id, "risk_assessment")
    report_ctx = await context_store.get(event_id, "report")
    assert triage_ctx and evidence_ctx and risk_ctx and report_ctx

    observed = await assert_valid_audit_transitions(session_factory, event_id)
    expected_statuses = tuple(status.value for status in GOLDEN_ORCHESTRATION_STATUSES)
    assert_ordered_subsequence(observed, expected_statuses)
    assert EventStatus.CLOSED.value not in observed

    traces = await agent_trace_service.get_traces_by_event(event_id)
    assert_agent_trace_order(traces, ORCHESTRATION_AGENT_ORDER)

    async with session_factory() as session:
        report_row = await session.scalar(select(orm.Report).where(orm.Report.event_id == event_id))
    assert report_row is not None
    assert len(report_row.sections) == len(SECTION_KEYS)


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_evidence_agent_failure_retries_once_and_records_traces(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    agent_trace_service: AgentTraceService,
    build_super_agent,
) -> None:
    """Scenario 2: first EvidenceAgent failure retries once and leaves fail+success traces."""
    event_id = await ingest_main_scenario_event(source_adapter, source_ingester, event_service)
    agent, projection = build_super_agent()
    evidence_agent = agent.evidence_agent
    original_run = evidence_agent._run
    attempts = {"n": 0}

    async def flaky_run(input: Any) -> Any:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise DependencyUnavailableError("forced evidence agent failure for retry test")
        return await original_run(input)

    evidence_agent._run = flaky_run  # type: ignore[method-assign]

    with bind_evidence_projection(projection):
        await agent.investigate(event_id)

    assert attempts["n"] == 2
    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status is EventStatus.REPORTING

    traces = await agent_trace_service.get_traces_by_event(event_id)
    evidence_traces = [row for row in traces if row.agent_name == "evidence_agent"]
    assert len(evidence_traces) == 2
    assert evidence_traces[0].status == "failed"
    assert evidence_traces[1].status == "completed"

    await assert_valid_audit_transitions(session_factory, event_id)


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_checkpoint_resume_skips_completed_nodes(
    event_service: EventService,
    context_store: EventContextStore,
    state_machine_service: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    workflow_graph_factory,
    redis_checkpointer,
) -> None:
    """Scenario 3: interrupt before risk_node, resume without re-running completed nodes."""
    event_id = await seed_graph_event(
        event_service,
        context_store,
        state_machine_service,
    )
    config = {"configurable": {"thread_id": event_id}}

    first_graph = workflow_graph_factory(
        checkpointer=redis_checkpointer,
        interrupt_before=[NODE_RISK],
    )
    paused = await first_graph.ainvoke(_graph_base_state(event_id), config)
    assert NODE_RISK not in paused["node_trace"]

    second_graph = workflow_graph_factory(checkpointer=redis_checkpointer)
    final = await second_graph.ainvoke(None, config)

    assert NODE_CLOSE in final["node_trace"]
    assert final["node_trace"].count(NODE_RISK) == 1
    assert final["node_trace"].count("triage_node") == 1
    assert final["node_trace"].count("evidence_node") == 1

    await assert_valid_audit_transitions(session_factory, event_id)


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_concurrent_context_writes_remain_consistent(
    event_service: EventService,
    context_store: EventContextStore,
    working_memory,
) -> None:
    """Scenario 4: concurrent writers on different fields do not lose updates."""
    event = await event_service.create_event(
        {"title": "context consistency", "description": "orchestration"},
        source_type="manual",
        title="context consistency",
        severity=Severity.MEDIUM,
    )
    assert event.event_id
    await context_store.init_context(
        event.event_id,
        EventSummary(
            event_id=event.event_id,
            event_type=EventType.OTHER,
            title=event.title,
            status=EventStatus.NEW,
            severity=Severity.MEDIUM,
            risk_score=0,
            final_verdict=event.final_verdict,
            writeback_required=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            disposition_policy=event.disposition_policy,
        ),
    )

    triage_payload, risk_payload = await exercise_concurrent_context_writes(
        working_memory,
        context_store,
        event.event_id,
    )
    assert await context_store.get(event.event_id, "triage_result") == triage_payload
    assert await context_store.get(event.event_id, "risk_assessment") == risk_payload

    await exercise_version_conflict_retry(working_memory, context_store, event.event_id)


@pytest.mark.asyncio
async def test_max_agent_retries_constant_matches_issue_spec() -> None:
    assert MAX_AGENT_RETRIES == 2
