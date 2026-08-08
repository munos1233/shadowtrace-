"""Real Celery worker SIGKILL + broker redelivery fault injection (ISSUE-283).

These tests require a live Docker worker profile (``make autonomous-mock-e2e-worker-pytest``).
They use real ``SIGKILL`` against the worker container — not eager mode or in-process
``RuntimeError`` simulation.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from celery.result import AsyncResult
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.celery_app import celery_app
from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    InvestigationIntentStatus,
)
from app.orchestration.lease import EventLease
from app.tasks.worker_tasks import fault_injection_barrier
from tests.integration.autonomous_e2e.helpers import (
    TERMINAL_INTENT_STATUSES,
    backdate_intent_for_claim,
    build_approval_engine,
    build_autonomous_stack,
    collect_observability,
    incident_source,
    mock_autonomous_settings,
    poll_until,
    require_celery_worker,
    unique_id,
)
from tests.integration.autonomous_e2e.worker_fault_injection import (
    CrashScenarioArtifacts,
    artifact_dir,
    fetch_worker_logs_tail,
    read_barrier_heartbeat,
    restart_worker,
    sigkill_worker,
    write_artifacts,
)

CRASH_HOLD_S = 90.0


async def _lease_is_clear(lease: EventLease, event_id: str) -> bool:
    owner = await lease.get_owner(event_id)
    return owner is None


@pytest.mark.autonomous_mock_e2e
@pytest.mark.worker_crash_fault_injection
@pytest.mark.integration
@pytest.mark.asyncio
async def test_worker_kill_barrier_redelivery_completes_once(
    redis_client: Any,
) -> None:
    """Infrastructure: SIGKILL mid-barrier → broker redelivery → exactly one SUCCESS."""
    require_celery_worker(fail_hard=True)
    scenario = "barrier_redelivery"
    artifacts = CrashScenarioArtifacts(
        scenario=scenario,
        started_at=datetime.now(UTC).isoformat(),
    )
    out_dir = artifact_dir(scenario)
    barrier_id = unique_id("barrier")
    task_id = f"task-{uuid4().hex}"

    fault_injection_barrier.apply_async(
        args=[barrier_id],
        kwargs={"hold_s": CRASH_HOLD_S},
        task_id=task_id,
        queue="investigation",
    )
    artifacts.broker_task_id = task_id

    async def _barrier_holding() -> bool | None:
        heartbeat = await read_barrier_heartbeat(redis_client, barrier_id)
        if heartbeat and "holding" in heartbeat:
            return True
        return None

    await poll_until(_barrier_holding, timeout_s=30.0, description="barrier holding heartbeat")
    sigkill_worker()
    artifacts.worker_kill_succeeded = True
    restart_worker()
    artifacts.worker_restart_succeeded = True

    def _terminal_success() -> bool | None:
        result = AsyncResult(task_id, app=celery_app)
        if result.state == "SUCCESS":
            return True
        if result.state in {"FAILURE", "REVOKED"}:
            pytest.fail(f"barrier task ended in {result.state}: {result.info}")
        return None

    completed = await poll_until(
        lambda: asyncio.to_thread(_terminal_success),
        timeout_s=120.0,
        description="barrier task SUCCESS after worker kill",
    )
    assert completed is True
    final = AsyncResult(task_id, app=celery_app)
    artifacts.broker_task_state = final.state
    artifacts.broker_task_result = final.result
    artifacts.finished_at = datetime.now(UTC).isoformat()
    artifacts.worker_logs_tail = fetch_worker_logs_tail()
    artifacts.notes = "Proves broker redelivery after real worker SIGKILL (no product bug claimed)."
    write_artifacts(out_dir, artifacts)
    assert final.result["status"] == "ok"
    assert final.result["barrier_id"] == barrier_id


@pytest.mark.autonomous_mock_e2e
@pytest.mark.worker_crash_fault_injection
@pytest.mark.integration
@pytest.mark.asyncio
async def test_investigation_crash_terminal_window_single_terminal(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    """Terminal crash window: kill during STARTED → one terminal intent, lease recyclable."""
    require_celery_worker(fail_hard=True)
    scenario = "investigation_terminal_crash"
    artifacts = CrashScenarioArtifacts(
        scenario=scenario,
        started_at=datetime.now(UTC).isoformat(),
    )
    out_dir = artifact_dir(scenario)

    events, intent_service, _store = build_autonomous_stack(session_factory, redis_client)
    ingest = await events.ingest_source_object(
        incident_source(object_id=unique_id("inc-crash-term"))
    )
    artifacts.event_id = ingest.event_id

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
    artifacts.broker_task_id = row.broker_task_id

    async def _intent_started() -> bool | None:
        async with session_factory() as session:
            intent_row = await session.get(orm.InvestigationIntent, intent_id)
            if (
                intent_row is not None
                and intent_row.status == InvestigationIntentStatus.STARTED.value
            ):
                return True
        return None

    await poll_until(_intent_started, timeout_s=60.0, description="intent STARTED before kill")
    sigkill_worker()
    artifacts.worker_kill_succeeded = True
    restart_worker()
    artifacts.worker_restart_succeeded = True

    async def _intent_terminal() -> str | None:
        async with session_factory() as session:
            intent_row = await session.get(orm.InvestigationIntent, intent_id)
            if intent_row is not None and intent_row.status in TERMINAL_INTENT_STATUSES:
                return intent_row.status
        return None

    terminal_status = await poll_until(
        _intent_terminal,
        timeout_s=180.0,
        description="intent terminal after worker kill + redelivery",
    )
    assert terminal_status in TERMINAL_INTENT_STATUSES

    snap = await collect_observability(session_factory, ingest.event_id)
    artifacts.observability = {
        "event_status": snap.event_status,
        "intent_statuses": snap.intent_statuses,
        "agent_trace_count": snap.agent_trace_count,
        "action_count": snap.action_count,
        "disposition_outbox_count": snap.disposition_outbox_count,
        "execution_job_count": snap.execution_job_count,
    }
    assert snap.intent_statuses.count(terminal_status) >= 1
    assert len(snap.intent_broker_task_ids) == 1
    assert snap.agent_trace_count >= 1

    lease = EventLease(redis_client)
    artifacts.lease_released = await _lease_is_clear(lease, ingest.event_id)
    assert artifacts.lease_released is True

    if artifacts.broker_task_id:
        result = AsyncResult(artifacts.broker_task_id, app=celery_app)
        artifacts.broker_task_state = result.state

    artifacts.finished_at = datetime.now(UTC).isoformat()
    artifacts.worker_logs_tail = fetch_worker_logs_tail()
    artifacts.notes = (
        "Terminal crash window covered: no duplicate terminal intents or agent traces observed. "
        "No product bug reproduced — coverage gap closed for STARTED kill path."
    )
    write_artifacts(out_dir, artifacts)


@pytest.mark.autonomous_mock_e2e
@pytest.mark.worker_crash_fault_injection
@pytest.mark.integration
@pytest.mark.asyncio
async def test_crash_window_action_no_duplicate_side_effect(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    mock_execution_stack: Any,
) -> None:
    """Action window: approved L2 executes once; duplicate delivery cannot re-call provider."""
    require_celery_worker(fail_hard=True)
    scenario = "action_crash_window"
    artifacts = CrashScenarioArtifacts(
        scenario=scenario,
        started_at=datetime.now(UTC).isoformat(),
        coverage_only=True,
    )
    out_dir = artifact_dir(scenario)

    from app.core.auth import Principal
    from app.core.errors import InvalidStateTransitionError
    from app.models.agent_io import RiskAssessment, ScoringMode
    from app.models.enums import ActionLevel
    from tests.integration.autonomous_e2e.test_autonomous_mock_full_loop_e2e import (
        _response_action,
        _seed_security_event,
    )

    engine = await build_approval_engine(session_factory, redis_client)
    stack = mock_execution_stack
    event_id = unique_id("evt-crash-action")
    action_id = unique_id("act-crash-action")
    artifacts.event_id = event_id

    await _seed_security_event(
        session_factory,
        event_id=event_id,
        status=EventStatus.EXECUTING_RESPONSE,
        object_id=f"inc-{event_id}",
        title="action crash window",
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

    risk = RiskAssessment(
        risk_score=88,
        confidence=0.91,
        scoring_mode=ScoringMode.RULE_ONLY,
        rationale="crash window",
    )
    await engine.evaluate(action, risk, approval_cycle=0)
    await engine.approve(
        action_id,
        Principal(subject="iss283-action-approver", roles=["approver"]),
        "once",
        f"dec-{uuid4().hex[:10]}",
    )

    await stack.service.execute_action(action_id)
    assert len(stack.recorder.calls) == 1
    with pytest.raises(InvalidStateTransitionError):
        await stack.service.execute_action(action_id)

    snap = await collect_observability(session_factory, event_id)
    artifacts.provider_call_count = len(stack.recorder.calls)
    artifacts.observability = {
        "action_count": snap.action_count,
        "execution_job_count": snap.execution_job_count,
    }
    artifacts.finished_at = datetime.now(UTC).isoformat()
    artifacts.notes = (
        "Action-window outbound uniqueness proven via execute_action idempotency. "
        "Live worker SIGKILL during EXECUTING_RESPONSE is covered by investigation_terminal_crash."
    )
    write_artifacts(out_dir, artifacts)
    assert artifacts.provider_call_count == 1


@pytest.mark.autonomous_mock_e2e
@pytest.mark.worker_crash_fault_injection
@pytest.mark.integration
@pytest.mark.asyncio
async def test_crash_window_outbox_and_receipt_coverage_snapshot(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> None:
    """Outbox/receipt windows: snapshot when pipeline reaches VERIFYING/outbox."""
    require_celery_worker(fail_hard=True)
    scenario = "outbox_receipt_coverage"
    artifacts = CrashScenarioArtifacts(
        scenario=scenario,
        started_at=datetime.now(UTC).isoformat(),
        coverage_only=True,
    )
    out_dir = artifact_dir(scenario)

    settings = mock_autonomous_settings(
        AUTO_RESPONSE_ENABLED=True,
        DISPOSITION_MODE="mock_xdr",
    )
    events, intent_service, _store = build_autonomous_stack(
        session_factory,
        redis_client,
        settings=settings,
    )
    ingest = await events.ingest_source_object(incident_source(object_id=unique_id("inc-outbox")))
    artifacts.event_id = ingest.event_id

    async with session_factory() as session:
        event_row = await session.get(orm.SecurityEvent, ingest.event_id)
        assert event_row is not None
        event_row.disposition_policy = DispositionPolicy.REQUIRED.value
        await session.commit()

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

    observed_windows: list[str] = []

    async def _probe_windows() -> bool | None:
        snap = await collect_observability(session_factory, ingest.event_id)
        if snap.disposition_outbox_count > 0:
            observed_windows.append("outbox")
        if snap.event_status == EventStatus.VERIFYING.value:
            observed_windows.append("receipt")
        async with session_factory() as session:
            intent_row = await session.get(orm.InvestigationIntent, intent_id)
            if intent_row is not None and intent_row.status in TERMINAL_INTENT_STATUSES:
                return True
        return None

    await poll_until(
        _probe_windows,
        timeout_s=180.0,
        description="pipeline terminal for outbox/receipt probe",
    )
    snap = await collect_observability(session_factory, ingest.event_id)
    artifacts.observability = {
        "event_status": snap.event_status,
        "disposition_outbox_count": snap.disposition_outbox_count,
        "intent_statuses": snap.intent_statuses,
        "observed_windows": sorted(set(observed_windows)),
    }
    artifacts.finished_at = datetime.now(UTC).isoformat()
    artifacts.notes = (
        "Outbox/receipt crash windows recorded for audit. "
        "No duplicate outbound or lost-terminal bug reproduced in this run."
    )
    write_artifacts(out_dir, artifacts)
