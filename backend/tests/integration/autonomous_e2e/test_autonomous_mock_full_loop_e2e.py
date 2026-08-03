"""Autonomous Mock XDR full-loop E2E (ISSUE-110 / #614).

Scenarios A–E validate production ingest→intent→worker→approval paths with
mandatory ledger observability. Integration tests use production entry points
without ``task_always_eager``. Worker-gated tests require ``make up WORKER=1``.

OpenTelemetry correlation IDs are out of scope for this issue; defer to a
follow-up observability issue.
"""

from __future__ import annotations

import os
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import get_approval_engine, reset_deps
from app.core.auth import Principal
from app.core.celery_app import celery_app
from app.core.celery_delivery import (
    celery_task_owner_id,
    normalize_public_task_state,
)
from app.core.celery_health import build_celery_health
from app.core.config import Settings, get_settings
from app.core.errors import (
    ApprovalDecisionConflictError,
    ConfigurationError,
    InvalidStateTransitionError,
    InvestigationInProgressError,
    ValidationError,
)
from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.main import app
from app.models.action import Action
from app.models.agent_io import RiskAssessment, ScoringMode
from app.models.approval import ApprovalDecisionKind
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    EventStatus,
    EventType,
    ExecutionOwner,
    InvestigationIntentStatus,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.investigation_intent import IntentDeliveryAdmission
from app.models.source import SourceReference
from app.orchestration.lease import EventLease
from app.services.approval_engine import evaluate_level_rules
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.event_service import IngestableSource
from app.services.investigation_intent_service import InvestigationIntentService
from app.tasks import investigation_tasks as tasks
from tests.integration.autonomous_e2e.helpers import (
    DEV_AUTH_TOKENS_JSON,
    ISOLATED_E2E_QUEUE,
    TERMINAL_INTENT_STATUSES,
    auth_headers,
    backdate_intent_for_claim,
    build_approval_engine,
    build_autonomous_stack,
    build_mock_execution_stack,
    collect_observability,
    count_execution_jobs,
    incident_source,
    mock_autonomous_settings,
    patch_production_session_factory,
    poll_until,
    principal_lacks_approver_role,
    require_celery_worker,
    run_investigation_with_request,
    seed_primary_source_link,
    select_human_gated_action,
    unique_id,
)


def _response_action(
    *,
    event_id: str,
    level: ActionLevel,
    action_id: str,
    writeback_required: bool = False,
    writeback_applicable: bool = False,
) -> Action:
    payload: dict[str, Any] = {
        "action_id": action_id,
        "event_id": event_id,
        "plan_revision": 1,
        "action_fingerprint": f"fp-{action_id}",
        "action_category": ActionCategory.RESPONSE,
        "action_name": "isolate_host",
        "tool_name": "isolate_host",
        "action_level": level,
        "execution_owner": ExecutionOwner.DIRECT_TOOL,
        "execution_phase": ActionExecutionPhase.IMMEDIATE,
        "status": ActionStatus.PENDING,
        "target_type": "host",
        "target": "host-iss110",
        "parameters": {"target_type": "host", "target": "host-iss110"},
        "writeback_required": writeback_required,
        "writeback_applicable": writeback_applicable,
        "reason": "iss110-scenario-b",
    }
    if writeback_required and writeback_applicable:
        payload["writeback_readiness"] = WritebackReadiness.READY
        payload["disposition_source_ref"] = {
            "source_product": "mock_xdr",
            "source_tenant_id": "tenant-demo",
            "connector_id": "conn-mock",
            "source_kind": "incident",
            "source_object_id": f"INC-{action_id}",
        }
    return Action.model_validate(payload)


def _risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=82,
        confidence=0.91,
        severity=Severity.HIGH,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _event_seed_ref(*, object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=object_id,
        source_updated_at=datetime.now(UTC),
    )


async def _seed_security_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    status: EventStatus,
    object_id: str,
    title: str = "ISSUE-110 E2E",
) -> None:
    ref = _event_seed_ref(object_id=object_id)
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.MALICIOUS_PROCESS.value,
                    title=title,
                    description="",
                    status=status.value,
                    severity=Severity.HIGH.value,
                    risk_score=82,
                    confidence=0.91,
                    final_verdict="none",
                    creation_source_ref=ref.model_dump(mode="json"),
                    source_reference_snapshots=[ref.model_dump(mode="json")],
                    disposition_policy="required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                    occurred_at=now,
                )
            )


async def _seed_event_and_intent(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    intent_id: str,
    intent_status: InvestigationIntentStatus = InvestigationIntentStatus.ENQUEUED,
    broker_task_id: str = "task-current",
) -> None:
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.NEW,
        object_id=f"inc-{event_id}",
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=intent_status.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=broker_task_id,
                )
            )


def _wire_super_agent_mock(monkeypatch: pytest.MonkeyPatch, *, calls: dict[str, int]) -> None:
    async def _investigate(_event_id: str, **_kwargs: Any) -> None:
        calls["n"] = calls.get("n", 0) + 1

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: nullcontext(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        AsyncMock(),
    )


# --------------------------------------------------------------------------- #
# Scenario A — L0 auto loop, dual delivery → single investigation
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_a_stale_broker_task_skips_second_investigation(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = mock_autonomous_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = unique_id("evt-a")
    intent_id = unique_id("iin-a")
    await _seed_event_and_intent(
        session_factory,
        event_id=event_id,
        intent_id=intent_id,
        broker_task_id="task-current",
    )

    stale = await service.mark_started(intent_id, broker_task_id="task-stale")
    assert stale is IntentDeliveryAdmission.STALE_SUPERSEDED

    accepted = await service.mark_started(intent_id, broker_task_id="task-current")
    assert accepted is IntentDeliveryAdmission.ACCEPTED

    calls = {"n": 0}
    _wire_super_agent_mock(monkeypatch, calls=calls)
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: session_factory)

    result = await tasks.execute_investigation(event_id)
    assert result["status"] == "completed"
    assert calls["n"] == 1

    await service.mark_terminal(intent_id)

    stale_again = await service.mark_started(intent_id, broker_task_id="task-redelivery")
    assert stale_again is IntentDeliveryAdmission.ALREADY_TERMINAL

    snap = await collect_observability(session_factory, event_id)
    assert snap.intent_statuses == [InvestigationIntentStatus.TERMINAL.value]
    assert snap.intent_broker_task_ids == ["task-current"]
    assert snap.event_status is not None


@pytest.mark.integration
def test_scenario_a_dual_delivery_one_terminal_stale_skipped(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production run_investigation: current task completes once; stale task is skipped."""
    import asyncio

    event_id = unique_id("evt-a-dual")
    intent_id = unique_id("iin-a-dual")
    current_task = "task-current-dual"
    stale_task = "task-stale-dual"

    async def _seed() -> None:
        await _seed_event_and_intent(
            session_factory,
            event_id=event_id,
            intent_id=intent_id,
            intent_status=InvestigationIntentStatus.ENQUEUED,
            broker_task_id=current_task,
        )

    asyncio.run(_seed())

    calls = {"n": 0}

    async def _execute(investigated_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": investigated_id}

    monkeypatch.setattr(tasks, "execute_investigation", _execute)
    patch_production_session_factory(monkeypatch, session_factory)

    first = run_investigation_with_request(
        task_id=current_task,
        event_id=event_id,
        intent_id=intent_id,
    )
    assert first["status"] == "completed"
    assert calls["n"] == 1

    second = run_investigation_with_request(
        task_id=stale_task,
        event_id=event_id,
        intent_id=intent_id,
    )
    assert second["status"] == "skipped"
    assert second["reason"] in {"intent_already_terminal", "stale_broker_task"}
    assert calls["n"] == 1

    snap = asyncio.run(collect_observability(session_factory, event_id))
    assert snap.intent_statuses == [InvestigationIntentStatus.TERMINAL.value]
    assert snap.intent_broker_task_ids == [current_task]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_a_publish_skips_intent_when_event_not_new(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public claim_and_publish_batch marks intent SKIPPED when event left NEW."""
    events, intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    ingest = await events.ingest_source_object(incident_source(object_id=unique_id("inc-a-skip")))
    async with session_factory() as session:
        intent_row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
    assert intent_row is not None
    intent_id = intent_row.intent_id
    await backdate_intent_for_claim(session_factory, intent_id)

    async with session_factory() as session:
        async with session.begin():
            event = await session.get(orm.SecurityEvent, ingest.event_id)
            assert event is not None
            event.status = EventStatus.TRIAGING.value

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        AsyncMock(),
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        lambda **_kwargs: None,
    )
    await intent_service.claim_and_publish_batch(limit=50)

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
    assert row is not None
    assert row.status == InvestigationIntentStatus.SKIPPED.value
    assert row.broker_task_id is None

    snap = await collect_observability(session_factory, ingest.event_id)
    assert snap.intent_statuses == [InvestigationIntentStatus.SKIPPED.value]
    assert snap.intent_broker_task_ids == [None]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_a_l0_auto_loop_executes_once_without_human(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    mock_execution_stack: Any,
) -> None:
    """L0 policy auto-approves and executes exactly once without human operator."""
    engine = await build_approval_engine(session_factory, redis_client)
    stack = mock_execution_stack
    event_id = unique_id("evt-a-l0")
    action_id = unique_id("act-l0")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.EXECUTING_RESPONSE,
        object_id=f"inc-{event_id}",
        title="L0 auto loop",
    )
    async with session_factory() as session:
        async with session.begin():
            await seed_primary_source_link(session, event_id=event_id)
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await stack.store.init_context(event_id, event_summary_from_security_event(row))

    action = _response_action(event_id=event_id, level=ActionLevel.L0, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    decision = await engine.evaluate(action, _risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.AUTO_APPROVE

    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.status == ActionStatus.APPROVED.value

    await stack.service.execute_action(action_id)
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)

    assert len(stack.recorder.calls) == 1
    assert await count_execution_jobs(session_factory, event_id) == 1

    snap = await collect_observability(session_factory, event_id)
    assert snap.approval_record_count >= 1
    assert not any(op.startswith("iss110") for op in snap.approval_operators)
    assert snap.pending_action_count == 0
    assert snap.action_count == 1
    assert snap.execution_job_count == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_a_l0_policy_auto_approve_l0_l1_not_l2() -> None:
    l0 = _response_action(event_id="evt-gate", level=ActionLevel.L0, action_id="act-l0")
    l1 = _response_action(event_id="evt-gate", level=ActionLevel.L1, action_id="act-l1")
    l2 = _response_action(event_id="evt-gate", level=ActionLevel.L2, action_id="act-l2")
    l0_decision = evaluate_level_rules(l0, confidence=0.99, severity=Severity.CRITICAL)
    l1_decision = evaluate_level_rules(l1, confidence=0.99, severity=Severity.CRITICAL)
    l2_decision = evaluate_level_rules(l2, confidence=0.99, severity=Severity.CRITICAL)
    assert l0_decision.decision is ApprovalDecisionKind.AUTO_APPROVE
    assert l1_decision.decision is ApprovalDecisionKind.AUTO_APPROVE
    assert l2_decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL


@pytest.mark.autonomous_mock_e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_a_worker_completes_enqueued_intent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    require_celery_worker()
    events, intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    ingest = await events.ingest_source_object(incident_source(object_id=unique_id("inc-worker-a")))
    async with session_factory() as session:
        intent_row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
    assert intent_row is not None
    intent_id = intent_row.intent_id
    await backdate_intent_for_claim(session_factory, intent_id)

    await intent_service.claim_and_publish_batch(limit=10)

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
    assert row is not None
    assert row.status == InvestigationIntentStatus.ENQUEUED.value
    assert row.broker_task_id is not None

    async def _intent_terminal() -> str | None:
        async with session_factory() as session:
            intent_row = await session.get(orm.InvestigationIntent, intent_id)
            if intent_row is not None and intent_row.status in TERMINAL_INTENT_STATUSES:
                return intent_row.status
        return None

    terminal_status = await poll_until(
        _intent_terminal,
        timeout_s=120.0,
        description="intent terminal after worker delivery",
    )
    assert terminal_status in TERMINAL_INTENT_STATUSES
    snap = await collect_observability(session_factory, ingest.event_id)
    assert snap.intent_statuses.count(terminal_status) >= 1
    assert snap.intent_broker_task_ids
    assert snap.intent_broker_task_ids[0] is not None
    assert snap.event_status is not None
    assert snap.audit_log_count >= 1
    assert snap.agent_trace_count >= 1
    assert len(snap.agent_trace_ids) >= 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_full_loop_ingest_execute_investigation_produces_agent_trace(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ingest → production execute_investigation (real SuperAgent + mock LLM) → AgentTrace."""
    events, _intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    ingest = await events.ingest_source_object(
        incident_source(object_id=unique_id("inc-full-loop"))
    )
    async with session_factory() as session:
        before = await session.get(orm.SecurityEvent, ingest.event_id)
    assert before is not None
    initial_status = before.status

    patch_production_session_factory(monkeypatch, session_factory)

    result = await tasks.execute_investigation(ingest.event_id)
    assert result["status"] == "completed"

    snap = await collect_observability(session_factory, ingest.event_id)
    assert snap.agent_trace_count >= 1
    assert len(snap.agent_trace_ids) >= 1
    assert snap.event_status is not None
    assert snap.event_status != initial_status
    assert snap.audit_log_count >= 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_investigation_produces_l2_pending_then_human_executes_once(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production slice: real execute_investigation → L2 pending → API approve → execute once."""
    reset_deps()
    get_settings.cache_clear()
    settings = mock_autonomous_settings(AUTO_RESPONSE_ENABLED=True)
    events, _intent_service, _store = build_autonomous_stack(
        session_factory,
        redis_client,
        settings=settings,
    )
    ingest = await events.ingest_source_object(
        incident_source(object_id=unique_id("inc-b-prod-chain"))
    )
    patch_production_session_factory(monkeypatch, session_factory)

    result = await tasks.execute_investigation(
        ingest.event_id,
        include_response_execution=True,
    )
    assert result["status"] == "completed"

    async with session_factory() as session:
        pending_rows = (
            await session.scalars(
                select(orm.Action).where(
                    orm.Action.event_id == ingest.event_id,
                    orm.Action.status == ActionStatus.WAITING_APPROVAL.value,
                )
            )
        ).all()
    target = select_human_gated_action(pending_rows, prefer_level=ActionLevel.L2)
    assert target.action_level == ActionLevel.L2.value
    action_id = target.action_id

    stack = await build_mock_execution_stack(session_factory, redis_client)
    try:
        decision_id = f"dec-prod-{uuid4().hex[:10]}"
        monkeypatch.setenv("DEV_AUTH_TOKENS", DEV_AUTH_TOKENS_JSON)
        get_settings.cache_clear()
        engine_holder: dict[str, Any] = {}

        async def _engine() -> Any:
            if "engine" not in engine_holder:
                engine_holder["engine"] = await build_approval_engine(session_factory, redis_client)
            return engine_holder["engine"]

        app.dependency_overrides[get_approval_engine] = _engine
        try:
            with TestClient(app) as client:
                resp = client.post(
                    f"/api/v1/actions/{action_id}/approve",
                    headers=auth_headers("approver"),
                    json={
                        "comment": "human gate after investigation",
                        "decision_id": decision_id,
                    },
                )
        finally:
            app.dependency_overrides.pop(get_approval_engine, None)
            get_settings.cache_clear()
        assert resp.status_code == 200

        async with session_factory() as session:
            row = await session.get(orm.SecurityEvent, ingest.event_id)
            assert row is not None
            from app.services.context_service import event_summary_from_security_event

            await stack.store.init_context(ingest.event_id, event_summary_from_security_event(row))

        if target.execution_phase == ActionExecutionPhase.IMMEDIATE.value:
            await stack.service.execute_action(action_id)
            with pytest.raises(InvalidStateTransitionError):
                await stack.service.execute_action(action_id)
            assert len(stack.recorder.calls) == 1
        else:
            async with session_factory() as session:
                approved_row = await session.get(orm.Action, action_id)
                assert approved_row is not None
                assert approved_row.status == ActionStatus.APPROVED.value

        snap = await collect_observability(session_factory, ingest.event_id)
        assert snap.agent_trace_count >= 1
        assert len(snap.agent_trace_ids) >= 1
        assert snap.pending_action_count == 0
        assert "iss110-approver" in snap.approval_operators
        assert 1 in snap.approval_plan_revisions
        assert 0 in snap.approval_cycles
        if target.execution_phase == ActionExecutionPhase.IMMEDIATE.value:
            assert snap.execution_job_count == 1
    finally:
        await stack.aclose()
    reset_deps()
    get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# Scenario B — L2 mandatory human approval
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_l2_human_approval_persists_operator(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b")
    action_id = unique_id("act-l2")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
        title="L2 gate",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    row_action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    decision = await engine.evaluate(row_action, _risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    test_approver = Principal(subject="iss110-test-approver", roles=["approver"])
    decision_id = f"dec-human-{uuid4().hex[:10]}"

    await engine.approve(action_id, test_approver, "approved once", decision_id)

    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.status == ActionStatus.APPROVED.value
        record = await session.scalar(
            select(ApprovalRecordORM).where(
                ApprovalRecordORM.action_id == action_id,
                ApprovalRecordORM.decision_id == decision_id,
            )
        )
        assert record is not None
        assert record.operator == "iss110-test-approver"
        assert record.operator != "system"

    with pytest.raises(ApprovalDecisionConflictError):
        await engine.reject(
            action_id,
            Principal(subject="iss110-other-approver", roles=["approver"]),
            "stale cross decision",
            f"dec-human-{uuid4().hex[:10]}",
        )

    snap = await collect_observability(session_factory, event_id)
    assert snap.pending_action_count == 0
    assert snap.approval_record_count >= 1
    assert snap.approval_operators == ["iss110-test-approver"]
    assert snap.approval_plan_revisions == [1]
    assert snap.approval_cycles == [0]
    assert snap.action_count == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_ingest_creates_intent_then_l2_pending_human_approve_executes_once(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    approve_api_client: Any,
    mock_execution_stack: Any,
) -> None:
    """Contract slice: ingest + seeded L2 → API approve → single execute (no SuperAgent)."""
    engine = await build_approval_engine(session_factory, redis_client)
    stack = mock_execution_stack
    events, _intent_service, _store = build_autonomous_stack(session_factory, redis_client)

    ingest = await events.ingest_source_object(incident_source(object_id=unique_id("inc-b-ingest")))
    async with session_factory() as session:
        intent_row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
        assert intent_row is not None

    action_id = unique_id("act-ingest-l2")
    action = _response_action(event_id=ingest.event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))
            event_row = await session.get(orm.SecurityEvent, ingest.event_id)
            assert event_row is not None
            event_row.status = EventStatus.WAITING_APPROVAL.value
    await engine.evaluate(action, _risk(), approval_cycle=0)

    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.status == ActionStatus.WAITING_APPROVAL.value

    decision_id = f"dec-ingest-{uuid4().hex[:10]}"
    resp = approve_api_client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers=auth_headers("approver"),
        json={"comment": "human gate", "decision_id": decision_id},
    )
    assert resp.status_code == 200

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, ingest.event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await stack.store.init_context(ingest.event_id, event_summary_from_security_event(row))

    await stack.service.execute_action(action_id)
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)

    assert len(stack.recorder.calls) == 1
    snap = await collect_observability(session_factory, ingest.event_id)
    assert snap.pending_action_count == 0
    assert snap.approval_operators == ["iss110-approver"]
    assert snap.approval_plan_revisions == [1]
    assert snap.approval_cycles == [0]
    assert snap.execution_job_count == 1
    assert await count_execution_jobs(session_factory, ingest.event_id) == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_system_or_agent_cannot_approve_l2(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    mock_execution_stack: Any,
) -> None:
    """Policy and RBAC must block system/agent from L2 approval execution paths."""
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b-guard")
    action_id = unique_id("act-l2-guard")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    policy_decision = evaluate_level_rules(action, confidence=0.99, severity=Severity.CRITICAL)
    assert policy_decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    system_principal = Principal(subject="system", roles=[])
    agent_principal = Principal(subject="agent:response-agent", roles=["analyst"])
    assert principal_lacks_approver_role(system_principal)
    assert principal_lacks_approver_role(agent_principal)

    await engine.evaluate(action, _risk(), approval_cycle=0)
    stack = mock_execution_stack
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)


@pytest.mark.integration
def test_scenario_b_system_principal_api_approve_forbidden_403(
    approve_api_client: Any,
) -> None:
    """Production approve API rejects principals without ROLE_APPROVER."""
    for role in ("analyst", "system", "agent"):
        resp = approve_api_client.post(
            "/api/v1/actions/act-missing/approve",
            headers=auth_headers(role),
            json={"comment": "forbidden", "decision_id": f"dec-{role}"},
        )
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "forbidden"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_system_agent_api_approve_forbidden_on_waiting_action(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    approve_api_client: Any,
) -> None:
    """RBAC blocks system/agent/analyst from approving a real waiting_approval L2 action."""
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b-api-rbac")
    action_id = unique_id("act-l2-api-rbac")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))
    await engine.evaluate(action, _risk(), approval_cycle=0)

    for role in ("system", "agent", "analyst"):
        resp = approve_api_client.post(
            f"/api/v1/actions/{action_id}/approve",
            headers=auth_headers(role),
            json={"comment": "forbidden", "decision_id": f"dec-rbac-{role}-{uuid4().hex[:6]}"},
        )
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "forbidden"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_l2_execute_records_disposition_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    mock_execution_stack: Any,
) -> None:
    """Approved L2 execution with writeback enqueues disposition outbox rows."""
    engine = await build_approval_engine(session_factory, redis_client)
    stack = mock_execution_stack
    event_id = unique_id("evt-b-wb")
    action_id = unique_id("act-l2-wb")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.EXECUTING_RESPONSE,
        object_id=f"inc-{event_id}",
        title="L2 writeback",
    )
    async with session_factory() as session:
        async with session.begin():
            source_record_id = await seed_primary_source_link(session, event_id=event_id)
        source_row = await session.get(orm.SourceObject, source_record_id)
        assert source_row is not None
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await stack.store.init_context(event_id, event_summary_from_security_event(row))

    action = _response_action(
        event_id=event_id,
        level=ActionLevel.L2,
        action_id=action_id,
        writeback_required=True,
        writeback_applicable=True,
    )
    action_payload = action.model_dump()
    action_payload["disposition_source_ref"] = {
        "source_product": source_row.source_product,
        "source_tenant_id": source_row.source_tenant_id,
        "connector_id": source_row.connector_id,
        "source_kind": source_row.source_kind,
        "source_object_id": source_row.source_object_id,
    }
    action = Action.model_validate(action_payload)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    await engine.approve(
        action_id,
        Principal(subject="iss110-wb-approver", roles=["approver"]),
        "writeback execute",
        f"dec-wb-{uuid4().hex[:10]}",
    )

    await stack.service.execute_action(action_id)

    snap = await collect_observability(session_factory, event_id)
    assert snap.disposition_outbox_count >= 1
    assert snap.approval_operators == ["iss110-wb-approver"]
    assert len(stack.recorder.calls) == 1
    assert await count_execution_jobs(session_factory, event_id) == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_stale_decision_id_replay_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b-replay")
    action_id = unique_id("act-l2-replay")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="iss110-replay-approver", roles=["approver"])
    decision_id = f"dec-replay-{uuid4().hex[:10]}"
    await engine.approve(action_id, principal, "first", decision_id)
    await engine.approve(action_id, principal, "replay", decision_id)

    async with session_factory() as session:
        records = (
            await session.scalars(
                select(ApprovalRecordORM).where(ApprovalRecordORM.action_id == action_id)
            )
        ).all()
    assert len(records) == 1
    assert records[0].decision_id == decision_id


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_cross_revision_superseded_cannot_execute(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    mock_execution_stack: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    event_id = unique_id("evt-b-rev")
    action_id = unique_id("act-l2-rev")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.WAITING_APPROVAL,
        object_id=f"inc-{event_id}",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    await engine.approve(
        action_id,
        Principal(subject="iss110-rev-approver", roles=["approver"]),
        "approved stale revision",
        f"dec-rev-{uuid4().hex[:10]}",
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id)
            assert row is not None
            row.superseded_by_revision = 2

    stack = mock_execution_stack
    with pytest.raises(ValidationError, match="superseded action cannot be claimed"):
        await stack.service.execute_action(action_id)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_b_human_approval_single_execution(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    mock_execution_stack: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    stack = mock_execution_stack
    event_id = unique_id("evt-b-exec")
    action_id = unique_id("act-l2-exec")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.EXECUTING_RESPONSE,
        object_id=f"inc-{event_id}",
        title="L2 execute once",
    )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await stack.store.init_context(event_id, event_summary_from_security_event(row))

    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    await engine.approve(
        action_id,
        Principal(subject="iss110-exec-approver", roles=["approver"]),
        "execute once",
        f"dec-exec-{uuid4().hex[:10]}",
    )

    await stack.service.execute_action(action_id)
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)

    assert len(stack.recorder.calls) == 1
    assert stack.recorder.calls[0][0] == "isolate_host"
    assert await count_execution_jobs(session_factory, event_id) == 1

    snap = await collect_observability(session_factory, event_id)
    assert snap.approval_record_count == 1
    assert snap.approval_operators == ["iss110-exec-approver"]
    assert snap.pending_action_count == 0


# --------------------------------------------------------------------------- #
# Scenario C — crash / redelivery fencing
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_c_redelivery_after_terminal_event_skips_body(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events, _intent_service, store = build_autonomous_stack(session_factory, redis_client)
    event_id = unique_id("evt-c-closed")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.CLOSED,
        object_id=f"inc-{event_id}",
        title="closed for redelivery",
    )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await store.init_context(event_id, event_summary_from_security_event(row))

    class _EventBridge:
        def __init__(self, svc: Any) -> None:
            self._svc = svc

        async def get_event(self, lookup_id: str) -> Any:
            return await self._svc.get_event(lookup_id)

    async def _event_service() -> _EventBridge:
        return _EventBridge(events)

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _event_service)

    calls = {"n": 0}

    async def _fake_execute(investigated_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": investigated_id}

    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    result = await tasks._run_investigation_body(
        event_id,
        include_response_execution=False,
        owner_id=celery_task_owner_id("task-c-redelivery"),
        redelivered=True,
    )
    assert result["status"] == "skipped"
    assert result.get("reason") == "terminal_event"
    assert calls["n"] == 0
    snap = await collect_observability(session_factory, event_id)
    assert snap.event_status == EventStatus.CLOSED.value
    assert snap.intent_statuses == []


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_c_stale_reconcile_marks_retry_without_duplicate_execute(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = mock_autonomous_settings(AUTO_INVESTIGATE_CLAIM_LEASE_S=5)
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = unique_id("evt-c-reconcile")
    intent_id = unique_id("iin-c-reconcile")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.NEW,
        object_id=f"inc-{event_id}",
        title="stale",
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-stale-window",
                    updated_at=datetime.now(UTC) - timedelta(minutes=20),
                )
            )

    await service.reconcile_stale(limit=50)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_c_action_redelivery_no_duplicate_side_effect(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    mock_execution_stack: Any,
) -> None:
    engine = await build_approval_engine(session_factory, redis_client)
    stack = mock_execution_stack
    event_id = unique_id("evt-c-sidefx")
    action_id = unique_id("act-c-sidefx")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.EXECUTING_RESPONSE,
        object_id=f"inc-{event_id}",
        title="side effect fencing",
    )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        from app.services.context_service import event_summary_from_security_event

        await stack.store.init_context(event_id, event_summary_from_security_event(row))

    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))

    await engine.evaluate(action, _risk(), approval_cycle=0)
    await engine.approve(
        action_id,
        Principal(subject="iss110-sidefx-approver", roles=["approver"]),
        "once",
        f"dec-sidefx-{uuid4().hex[:10]}",
    )

    await stack.service.execute_action(action_id)
    assert len(stack.recorder.calls) == 1
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)
    assert len(stack.recorder.calls) == 1
    assert await count_execution_jobs(session_factory, event_id) == 1

    snap = await collect_observability(session_factory, event_id)
    assert snap.approval_operators == ["iss110-sidefx-approver"]
    assert snap.approval_plan_revisions == [1]
    assert snap.action_count == 1


@pytest.mark.integration
def test_scenario_c_investigation_crash_marks_intent_dead_no_duplicate_work(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Worker crash during investigate marks intent DEAD; redelivery does not re-run body."""
    import asyncio

    event_id = unique_id("evt-c-crash")
    intent_id = unique_id("iin-c-crash")
    current_task = "task-current-crash"
    stale_task = "task-stale-crash"

    async def _seed() -> None:
        await _seed_event_and_intent(
            session_factory,
            event_id=event_id,
            intent_id=intent_id,
            intent_status=InvestigationIntentStatus.ENQUEUED,
            broker_task_id=current_task,
        )

    asyncio.run(_seed())

    calls = {"n": 0}

    async def _crash(_event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        raise RuntimeError("simulated worker crash")

    monkeypatch.setattr(tasks, "execute_investigation", _crash)
    patch_production_session_factory(monkeypatch, session_factory)

    with pytest.raises(RuntimeError, match="simulated worker crash"):
        run_investigation_with_request(
            task_id=current_task,
            event_id=event_id,
            intent_id=intent_id,
        )
    assert calls["n"] == 1

    async def _verify_dead() -> None:
        async with session_factory() as session:
            row = await session.get(orm.InvestigationIntent, intent_id)
            assert row is not None
            assert row.status == InvestigationIntentStatus.DEAD.value

    asyncio.run(_verify_dead())

    redelivery = run_investigation_with_request(
        task_id=stale_task,
        event_id=event_id,
        intent_id=intent_id,
    )
    assert redelivery["status"] == "skipped"
    assert redelivery["reason"] == "intent_already_terminal"
    assert calls["n"] == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_c_lease_fencing_blocks_concurrent_investigate(
    redis_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redelivery while lease is held skips investigate body (no duplicate work)."""
    lease = EventLease(redis_client)
    event_id = unique_id("evt-c-lease")
    task_id = "task-c-lease-fence"
    owner_id = celery_task_owner_id(task_id)
    assert await lease.acquire(event_id, owner_id, ttl_s=600)

    calls = {"n": 0}

    async def _investigate(
        _event_id: str,
        *,
        owner_id: str | None = None,
        **_kwargs: Any,
    ) -> None:
        from app.orchestration.lease import generate_owner_id

        resolved_owner = owner_id or generate_owner_id()
        if not await lease.acquire(_event_id, resolved_owner):
            raise InvestigationInProgressError(
                message="investigation already in progress for this event",
                error_code="investigation_in_progress",
                details={"event_id": _event_id},
            )
        calls["n"] += 1

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: nullcontext(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        AsyncMock(),
    )

    result = await tasks.execute_investigation(event_id, owner_id=owner_id)
    assert result == {
        "status": "skipped",
        "event_id": event_id,
        "reason": "investigation_in_progress",
    }
    assert calls["n"] == 0
    await lease.release(event_id, owner_id)


@pytest.mark.integration
def test_scenario_c_public_task_state_marks_retry_revoked_unknown() -> None:
    """Broker RETRY/REVOKED map to public UNKNOWN — callers must inspect ledger."""
    assert normalize_public_task_state("RETRY") == "UNKNOWN"
    assert normalize_public_task_state("REVOKED") == "UNKNOWN"
    assert normalize_public_task_state("SUCCESS") == "SUCCESS"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_c_unknown_action_requires_manual_resolve(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    mock_execution_stack: Any,
) -> None:
    """UNKNOWN actions cannot be blindly re-executed; manual resolve is required."""
    stack = mock_execution_stack
    event_id = unique_id("evt-c-unknown")
    action_id = unique_id("act-c-unknown")
    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.EXECUTING_RESPONSE,
        object_id=f"inc-{event_id}",
        title="unknown manual",
    )
    action = _response_action(event_id=event_id, level=ActionLevel.L2, action_id=action_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(orm.Action(**action.model_dump()))
        async with session.begin():
            row = await session.get(orm.Action, action_id)
            assert row is not None
            row.status = ActionStatus.UNKNOWN.value

    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)

    resolved = await stack.service.resolve_unknown(
        action_id,
        "manual_confirmed",
        principal="iss110-admin",
        comment="operator verified outcome",
    )
    assert resolved.status is ActionStatus.SUCCESS


# --------------------------------------------------------------------------- #
# Scenario D — deny / degraded / broker vs worker semantics
# --------------------------------------------------------------------------- #


def test_scenario_d_auto_response_rejects_live_disposition_at_startup() -> None:
    """AUTO_RESPONSE with live disposition adapter must fail closed at startup."""
    with pytest.raises(ConfigurationError):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="live_crowdstrike",
        )


def test_scenario_d_auto_response_rejects_live_source_at_startup() -> None:
    """AUTO_RESPONSE with live source must fail closed at Settings construction."""
    with pytest.raises(ConfigurationError):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="live_crowdstrike",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
        )


def test_scenario_d_production_rejects_mock_runtime_at_startup() -> None:
    with pytest.raises(ConfigurationError):
        Settings(
            APP_ENV="production",
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
            SIMULATION_ENABLED=False,
        )


def test_scenario_d_unknown_capability_blocks_auto_response_at_startup() -> None:
    """AUTO_RESPONSE with non-mock disposition adapter kind must fail closed at startup."""
    with pytest.raises(ConfigurationError):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mock_xdr",
            DISPOSITION_ADAPTER_KIND="crowdstrike",
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_celery_health_broker_up_worker_down_is_degraded_not_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _broker_ok(_url: str) -> str:
        return "ok"

    def _no_workers(**_kwargs: Any) -> dict[str, Any]:
        return {
            "status": "degraded",
            "workers": 0,
            "worker_ids": [],
            "reason": "no_workers_responding",
        }

    monkeypatch.setattr("app.core.celery_health.check_celery_broker", _broker_ok)
    monkeypatch.setattr("app.core.celery_health.probe_celery_workers", _no_workers)

    health = await build_celery_health(
        task_mode="celery",
        broker_url="redis://127.0.0.1:6379/0",
    )
    assert health["broker"] == "ok"
    assert health["worker"]["status"] == "degraded"
    assert health["worker"]["workers"] == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_celery_health_broker_down_reports_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _broker_down(_url: str) -> str:
        return "error"

    async def _no_workers(**_kwargs: Any) -> dict[str, Any]:
        return {
            "status": "degraded",
            "workers": 0,
            "worker_ids": [],
            "reason": "no_workers_responding",
        }

    monkeypatch.setattr("app.core.celery_health.check_celery_broker", _broker_down)
    monkeypatch.setattr("app.core.celery_health.check_celery_workers", _no_workers)

    health = await build_celery_health(
        task_mode="celery",
        broker_url="redis://127.0.0.1:6379/0",
    )
    assert health["broker"] == "error"
    assert health["worker"]["status"] == "degraded"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_broker_down_publish_marks_retry_and_degraded(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Broker failure via claim_and_publish_batch reverts intent to RETRY + degraded (#622)."""
    from kombu.exceptions import OperationalError

    settings = mock_autonomous_settings(AUTO_INVESTIGATE_CLAIM_LEASE_S=30)
    events, intent_service, _store = build_autonomous_stack(
        session_factory,
        redis_client,
        settings=settings,
    )
    ingest = await events.ingest_source_object(
        incident_source(object_id=unique_id("inc-d-broker-down"))
    )
    async with session_factory() as session:
        intent_row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
    assert intent_row is not None
    intent_id = intent_row.intent_id
    event_id = ingest.event_id
    await backdate_intent_for_claim(session_factory, intent_id)

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _broker_down(**_kwargs: object) -> None:
        raise OperationalError("broker unavailable")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _broker_down,
    )

    await intent_service.claim_and_publish_batch(limit=50)

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        event = await session.get(orm.SecurityEvent, event_id)
    assert row is not None
    assert event is not None
    assert row.status == InvestigationIntentStatus.RETRY.value
    assert row.last_error is not None
    assert any(
        flag.startswith("auto_investigate_dispatch_unavailable=") for flag in event.degraded_flags
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_task_stays_pending_when_broker_up_worker_absent(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 1 of worker recovery: broker accepts task; isolated queue keeps PENDING."""
    event_id = unique_id("evt-d-queue")
    await _seed_event_and_intent(session_factory, event_id=event_id, intent_id=unique_id("iin-d"))

    broker_url = os.environ.get(
        "CELERY_BROKER_URL",
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    )
    previous = {
        "task_always_eager": celery_app.conf.task_always_eager,
        "broker_url": celery_app.conf.broker_url,
        "result_backend": celery_app.conf.result_backend,
    }
    celery_app.conf.task_always_eager = False
    celery_app.conf.task_eager_propagates = False
    celery_app.conf.broker_url = broker_url
    celery_app.conf.result_backend = broker_url

    monkeypatch.setattr(tasks, "register_task_metadata", AsyncMock())

    try:
        async_result = tasks.run_investigation.apply_async(
            args=[event_id],
            queue=ISOLATED_E2E_QUEUE,
        )
        assert async_result.state == "PENDING"

        async def _still_pending() -> bool | None:
            if async_result.state == "PENDING":
                return True
            if async_result.state == "SUCCESS":
                pytest.fail(
                    f"isolated queue task was consumed unexpectedly: state={async_result.state}"
                )
            return None

        stayed_pending = await poll_until(
            _still_pending,
            timeout_s=3.0,
            interval_s=0.25,
            description="task remains PENDING on isolated queue",
        )
        assert stayed_pending is True
    finally:
        celery_app.conf.task_always_eager = previous["task_always_eager"]
        celery_app.conf.broker_url = previous["broker_url"]
        celery_app.conf.result_backend = previous["result_backend"]


@pytest.mark.autonomous_mock_e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_worker_recovery_completes_queued_task(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    """Phase 2 of worker recovery: published intent reaches terminal via live worker.

    Complements ``test_scenario_d_task_stays_pending_when_broker_up_worker_absent``
    (isolated queue PENDING semantics when no consumer is attached).
    """
    require_celery_worker()
    events, intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    ingest = await events.ingest_source_object(incident_source(object_id=unique_id("inc-worker-d")))
    async with session_factory() as session:
        intent_row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
    assert intent_row is not None
    intent_id = intent_row.intent_id
    await backdate_intent_for_claim(session_factory, intent_id)

    await intent_service.claim_and_publish_batch(limit=10)

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
    assert row is not None
    assert row.status == InvestigationIntentStatus.ENQUEUED.value
    assert row.broker_task_id is not None

    async def _intent_terminal() -> str | None:
        async with session_factory() as session:
            row = await session.get(orm.InvestigationIntent, intent_id)
            if row is not None and row.status in TERMINAL_INTENT_STATUSES:
                return row.status
        return None

    terminal_status = await poll_until(
        _intent_terminal,
        timeout_s=120.0,
        description="worker completes queued investigation intent",
    )
    assert terminal_status in TERMINAL_INTENT_STATUSES
    snap = await collect_observability(session_factory, ingest.event_id)
    assert snap.intent_statuses
    assert snap.intent_broker_task_ids
    assert snap.intent_broker_task_ids[0] is not None
    assert snap.event_status is not None
    assert snap.audit_log_count >= 1
    assert snap.agent_trace_count >= 1
    assert len(snap.agent_trace_ids) >= 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_d_auto_response_disabled_intent_flag_false(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    settings = mock_autonomous_settings(AUTO_RESPONSE_ENABLED=False)
    assert settings.auto_response_enabled is False
    events, _intent_service, _store = build_autonomous_stack(
        session_factory,
        redis_client,
        settings=settings,
    )
    ingest = await events.ingest_source_object(incident_source(object_id=unique_id("inc-d-off")))
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == ingest.event_id
            )
        )
    assert row is not None
    assert row.include_response_execution is False


# --------------------------------------------------------------------------- #
# Scenario E — provisional promotion
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_e_provisional_alert_no_intent_until_promoted(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    settings = mock_autonomous_settings(AUTO_INVESTIGATE_PROVISIONAL_WINDOW_S=300)
    events, _intent_service, _store = build_autonomous_stack(
        session_factory,
        redis_client,
        settings=settings,
    )
    sfx = uuid4().hex[:8]
    alert_ref = SourceReference(
        source_kind=SourceObjectKind.ALERT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=f"AL-prov-e-{sfx}",
        source_updated_at=datetime.now(UTC),
    )
    incident_ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=f"INC-prov-e-{sfx}",
        source_updated_at=datetime.now(UTC),
    )
    alert = await events.ingest_source_object(
        IngestableSource(
            reference=alert_ref,
            title="provisional alert",
            event_type=EventType.MALICIOUS_PROCESS,
            severity=Severity.HIGH,
            normalized={"risk_score": 76, "event_type": "malicious_process"},
        )
    )
    async with session_factory() as session:
        before = await session.scalar(
            select(orm.InvestigationIntent).where(
                orm.InvestigationIntent.event_id == alert.event_id
            )
        )
        assert before is None

    promoted = await events.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            title="parent incident",
            event_type=EventType.MALICIOUS_PROCESS,
            severity=Severity.HIGH,
            normalized={"risk_score": 76, "event_type": "malicious_process"},
            related_alert_refs=[alert_ref],
        )
    )
    assert promoted.promoted is True
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.InvestigationIntent).where(
                    orm.InvestigationIntent.event_id == promoted.event_id
                )
            )
        ).all()
    assert len(rows) == 1
    assert rows[0].status == InvestigationIntentStatus.PENDING.value
    snap = await collect_observability(session_factory, promoted.event_id)
    assert len(snap.intent_statuses) == 1
    assert snap.intent_broker_task_ids == [None]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scenario_e_primary_incident_single_durable_intent(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    events, _intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    source = incident_source(object_id=unique_id("inc-e-dup"))
    first = await events.ingest_source_object(source)
    second = await events.ingest_source_object(source)
    assert second.idempotent is True
    assert first.event_id == second.event_id
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.InvestigationIntent)
            .where(orm.InvestigationIntent.event_id == first.event_id)
        )
    assert int(count or 0) == 1
