"""ISSUE-055 orchestration integration fixtures and helpers.

Registered once via ``tests/conftest.py`` ``pytest_plugins`` so
``tests/integration/test_orchestration.py`` can reuse fixtures without
double-loading this module as a plugin.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.agents.planner_agent import PlannerAgent
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ReportAgentInput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.ids import report_id_for_event
from app.models.report import InvestigationReport
from app.models.security_event import EventSummary
from app.models.workflow import TransitionContext, validate_transition
from app.orchestration.checkpointer import RedisCheckpointer
from app.orchestration.workflow_graph import build_investigation_graph
from app.orchestration.workflow_runtime import WorkflowRuntimeService
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService

ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]

GOLDEN_ORCHESTRATION_STATUSES = (
    EventStatus.TRIAGING,
    EventStatus.COLLECTING_EVIDENCE,
    EventStatus.ANALYZING,
    EventStatus.SCORING,
    EventStatus.REPORTING,
)

ORCHESTRATION_AGENT_ORDER = (
    "triage_agent",
    "evidence_agent",
    "risk_agent",
    "report_agent",
)

GOLDEN_ORCHESTRATION_MAX_SECONDS = 90.0


class StubWorkflowAgent:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[Any] = []

    async def execute(self, input: Any) -> Any:
        self.calls.append(input)
        return self.result


class PersistingStubReportAgent:
    """Persist a minimal report so real StateMachineService can reach CLOSED."""

    def __init__(self, event_service: EventService) -> None:
        self.event_service = event_service
        self.calls: list[ReportAgentInput] = []

    async def execute(self, input: ReportAgentInput) -> InvestigationReport:
        self.calls.append(input)
        report = InvestigationReport(
            report_id=report_id_for_event(input.event_id),
            event_id=input.event_id,
            title="orchestration stub report",
            sections=[],
        )
        return await self.event_service.upsert_report(report)


async def ingest_main_scenario_event(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: SourceIngester,
    event_service: EventService,
) -> str:
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.rejected == 0, summary.errors
    listed = await event_service.list_events(status=EventStatus.NEW)
    assert listed.total == 1
    event = listed.items[0]
    assert event.disposition_policy is DispositionPolicy.REQUIRED
    return event.event_id


def assert_ordered_subsequence(items: list[str], expected: tuple[str, ...]) -> None:
    index = 0
    for value in expected:
        while index < len(items) and items[index] != value:
            index += 1
        assert index < len(items), f"missing ordered item: {value}"
        index += 1


async def assert_valid_audit_transitions(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> list[str]:
    """Validate every persisted status change against ``validate_transition``."""
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.EventAuditLog)
                .where(orm.EventAuditLog.event_id == event_id)
                .order_by(orm.EventAuditLog.id)
            )
        ).all()
        event_row = await session.get(orm.SecurityEvent, event_id)
        report_exists = (
            await session.scalar(
                select(orm.Report.report_id).where(orm.Report.event_id == event_id).limit(1)
            )
            is not None
        )
    assert rows, "event_audit_log must record lifecycle transitions"
    assert event_row is not None

    disposition_policy = DispositionPolicy(event_row.disposition_policy)
    severity = Severity(event_row.severity)
    transition_context = TransitionContext(
        disposition_policy=disposition_policy,
        severity=severity,
        report_exists=report_exists,
    )

    current: EventStatus | None = None
    observed: list[str] = []
    for row in rows:
        if row.to_status is None:
            continue
        target = EventStatus(row.to_status)
        if row.from_status is not None:
            source = EventStatus(row.from_status)
            if source == target:
                continue
            validate_transition(source, target, transition_context)
            observed.append(target.value)
            current = target
            continue
        if current is None:
            current = target
            observed.append(target.value)
        elif current != target:
            validate_transition(current, target, transition_context)
            observed.append(target.value)
            current = target
    assert observed, "event_audit_log must include status transitions"
    return observed


def assert_agent_trace_order(
    traces: list[Any],
    expected: tuple[str, ...],
) -> None:
    ordered = sorted(
        traces,
        key=lambda row: (row.started_at or datetime.min.replace(tzinfo=UTC), row.trace_id),
    )
    names = [row.agent_name for row in ordered]
    assert_ordered_subsequence(names, expected)


def build_stub_workflow_agents(
    *,
    triage: TriageResult | None = None,
    event_service: EventService | None = None,
) -> dict[str, Any]:
    triage_result = triage or TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="orchestration integration",
    )
    report_agent: Any
    if event_service is not None:
        report_agent = PersistingStubReportAgent(event_service)
    else:
        report_agent = StubWorkflowAgent(SimpleNamespace(report_id="rpt-stub"))
    return {
        "triage_agent": StubWorkflowAgent(triage_result),
        "planner_agent": PlannerAgent(llm_client=None),
        "evidence_agent": StubWorkflowAgent(
            EvidenceOutput(
                evidence_list=[],
                conflicts=[],
                gaps=[],
                success_sources=["endpoint"],
                failed_sources=[],
                overall_confidence=0.8,
                collection_status=CollectionStatus.COMPLETED,
            )
        ),
        "risk_agent": StubWorkflowAgent(
            RiskAssessment(
                risk_score=82,
                severity=Severity.HIGH,
                confidence=0.9,
                scoring_mode=ScoringMode.RULE_ONLY,
            )
        ),
        "report_agent": report_agent,
    }


def build_workflow_services(
    *,
    state_machine_service: StateMachineService,
    event_service: EventService,
    context_store: EventContextStore,
    degraded_flags: DegradedFlagService,
    session_factory: async_sessionmaker[AsyncSession],
) -> dict[str, Any]:
    runtime = WorkflowRuntimeService(session_factory, event_service=event_service)

    async def readiness(_event_id: str) -> WritebackReadiness:
        return WritebackReadiness.NOT_REQUIRED

    runtime._readiness_resolver = readiness  # type: ignore[attr-defined]
    return {
        "state_machine": state_machine_service,
        "event_service": event_service,
        "workflow_runtime": runtime,
        "degraded_flags": degraded_flags,
        "context_store": context_store,
    }


@pytest.fixture
def workflow_graph_factory(
    session_factory: async_sessionmaker[AsyncSession],
    state_machine_service: StateMachineService,
    event_service: EventService,
    context_store: EventContextStore,
    degraded_flags: DegradedFlagService,
) -> Callable[..., Any]:
    """Build a LangGraph investigation graph wired to real PG services."""

    def _build(
        *,
        checkpointer: RedisCheckpointer | None = None,
        interrupt_before: list[str] | None = None,
        triage: TriageResult | None = None,
    ) -> Any:
        agents = build_stub_workflow_agents(triage=triage, event_service=event_service)
        services = build_workflow_services(
            state_machine_service=state_machine_service,
            event_service=event_service,
            context_store=context_store,
            degraded_flags=degraded_flags,
            session_factory=session_factory,
        )
        return build_investigation_graph(
            agents,
            services,
            checkpointer=checkpointer,
            interrupt_before=interrupt_before,
        )

    return _build


@pytest.fixture
async def redis_checkpointer(redis_client: Any) -> RedisCheckpointer:
    saver = await RedisCheckpointer.create(redis_client)
    assert saver.recoverable is True
    return saver


async def seed_graph_event(
    event_service: EventService,
    context_store: EventContextStore,
    state_machine_service: StateMachineService,
    *,
    disposition_policy: DispositionPolicy = DispositionPolicy.NOT_REQUIRED,
) -> str:
    event = await event_service.create_event(
        {"title": "orchestration checkpoint", "description": "graph resume test"},
        source_type="manual",
        title="orchestration checkpoint",
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
    )
    assert event.event_id
    await context_store.init_context(
        event.event_id,
        EventSummary(
            event_id=event.event_id,
            event_type=EventType.DATA_EXFILTRATION,
            title=event.title,
            status=EventStatus.NEW,
            severity=Severity.HIGH,
            risk_score=0,
            final_verdict=event.final_verdict,
            writeback_required=disposition_policy is DispositionPolicy.REQUIRED,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            disposition_policy=disposition_policy,
        ),
    )
    await state_machine_service.transition(
        event.event_id,
        EventStatus.TRIAGING,
        context=TransitionContext(),
        reason="orchestration:graph_seed",
    )
    return event.event_id


async def exercise_concurrent_context_writes(
    working_memory: Any,
    context_store: EventContextStore,
    event_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    triage_writer = working_memory.for_writer("TriageAgent")
    risk_writer = working_memory.for_writer("RiskAgent")
    triage_payload = {
        "event_type": EventType.DATA_EXFILTRATION.value,
        "severity": Severity.HIGH.value,
        "need_investigation": True,
        "reasoning": "concurrent triage write",
    }
    risk_payload = {
        "risk_score": 55,
        "severity": Severity.MEDIUM.value,
        "confidence": 0.7,
        "risk_factors": [],
        "possible_false_positive": False,
        "scoring_mode": ScoringMode.RULE_ONLY.value,
    }
    await asyncio.gather(
        triage_writer.write(event_id, "triage_result", triage_payload),
        risk_writer.write(event_id, "risk_assessment", risk_payload),
    )
    return triage_payload, risk_payload


async def exercise_version_conflict_retry(
    working_memory: Any,
    context_store: EventContextStore,
    event_id: str,
) -> None:
    graph_writer = working_memory.for_writer("GraphAgent")
    await graph_writer.write(event_id, "graph_output", {"nodes": 1})

    calls = {"n": 0}
    real_cas = context_store.compare_and_set

    async def flaky_cas(*args: Any, **kwargs: Any) -> bool:
        calls["n"] += 1
        if calls["n"] == 1:
            return False
        return await real_cas(*args, **kwargs)

    with patch.object(context_store, "compare_and_set", side_effect=flaky_cas):
        await graph_writer.write(event_id, "graph_output", {"nodes": 2})

    assert calls["n"] >= 2
    stored = await context_store.get(event_id, "graph_output")
    assert stored == {"nodes": 2}
