"""ISSUE-139 Phase B: response plan task/artifact ledger integration tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from app.core.errors import AgentTaskDeniedError, AgentTaskUnavailableError, ValidationError
from app.models.action import Action
from app.models.agent_io import ResponsePlan, ResponsePlanGeneratedBy
from app.models.agent_task import (
    AgentArtifact,
    AgentTask,
    AgentTaskClaim,
    AgentTaskContextRef,
    AgentTaskGoal,
    AgentTaskStatus,
    AgentTaskType,
)
from app.models.enums import ActionCategory, ActionLevel, ExecutionOwner
from app.models.playbook_release import PlaybookActionTemplateSnapshot, PlaybookRef
from app.services.agent_artifact_service import AgentArtifactService
from app.services.agent_task_coordinator import (
    RESPONSE_PLAN_CONTEXT_REFS,
    enqueue_response_plan_task,
    run_response_plan_with_ledger,
)
from app.services.agent_task_service import AgentTaskService
from app.services.playbook_approval_binding import (
    STAGED_ARTIFACT_HASHES_KEY,
    build_approval_binding_detail,
    compute_response_plan_content_hash,
    staged_artifact_hash_from_parameters,
    validate_approval_binding,
    validate_task_retry_preserves_plan_artifact,
)


def _sample_plan(*, plan_revision: int = 1) -> ResponsePlan:
    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-abc",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        action_name="Block IP",
        template_hash="c" * 64,
    )
    action = Action(
        action_id="act-001",
        event_id="evt-001",
        plan_revision=plan_revision,
        action_fingerprint="fp-original",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        playbook_ref=ref,
        action_template_snapshot=snapshot,
    )
    return ResponsePlan(
        plan_id=f"plan-evt-001-{plan_revision}",
        actions=[action],
        strategy_summary="block source",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )


def test_response_plan_context_refs_include_immutable_artifact_ref() -> None:
    artifact_refs = [ref for ref in RESPONSE_PLAN_CONTEXT_REFS if ref.ref_kind == "artifact"]
    assert any(ref.ref_id == "risk_assessment" for ref in artifact_refs)


def test_response_plan_goal_accepts_typed_context_refs() -> None:
    goal = AgentTaskGoal(
        task_type=AgentTaskType.RESPONSE_PLAN,
        context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
        parameters={"plan_revision": 1},
    )
    assert goal.task_type is AgentTaskType.RESPONSE_PLAN


def test_compute_response_plan_content_hash_is_stable() -> None:
    plan = _sample_plan()
    first = compute_response_plan_content_hash(plan)
    second = compute_response_plan_content_hash(plan.model_dump(mode="json"))
    assert first == second
    assert len(first) == 64


def test_validate_task_retry_preserves_plan_artifact_allows_first_attempt() -> None:
    plan = _sample_plan()
    validate_task_retry_preserves_plan_artifact(
        prior_content_hash=None,
        new_payload=plan.model_dump(mode="json"),
        task_revision=1,
    )


def test_validate_task_retry_preserves_plan_artifact_rejects_content_drift() -> None:
    prior = _sample_plan()
    mutated = prior.model_copy(update={"strategy_summary": "different strategy"})
    with pytest.raises(ValidationError, match="immutable response plan content"):
        validate_task_retry_preserves_plan_artifact(
            prior_content_hash=compute_response_plan_content_hash(prior),
            new_payload=mutated.model_dump(mode="json"),
            task_revision=2,
        )


def test_validate_task_retry_preserves_plan_artifact_rejects_staged_hash_drift() -> None:
    prior = _sample_plan()
    prior_hash = compute_response_plan_content_hash(prior)
    mutated = prior.model_copy(update={"strategy_summary": "different strategy"})
    with pytest.raises(ValidationError, match="immutable response plan content"):
        validate_task_retry_preserves_plan_artifact(
            prior_content_hash=None,
            staged_content_hash=prior_hash,
            new_payload=mutated.model_dump(mode="json"),
            task_revision=2,
        )


def test_staged_artifact_hash_from_parameters_round_trip() -> None:
    plan = _sample_plan()
    content_hash = compute_response_plan_content_hash(plan)
    parameters = {STAGED_ARTIFACT_HASHES_KEY: {"response_plan": content_hash}}
    assert staged_artifact_hash_from_parameters(parameters, "response_plan") == content_hash


def test_plan_revision_change_invalidates_playbook_approval_binding() -> None:
    plan = _sample_plan(plan_revision=1)
    action = plan.actions[0]
    detail = build_approval_binding_detail(action)
    replanned = action.model_copy(update={"plan_revision": 2})
    with pytest.raises(ValidationError, match="plan revision changed"):
        validate_approval_binding(replanned, detail)


@pytest.mark.asyncio
async def test_enqueue_response_plan_task_skips_when_unavailable() -> None:
    result = await enqueue_response_plan_task(
        None,
        event_id="evt-coord",
        tenant_id="tenant-a",
        idempotency_key="response-plan:evt-coord:1",
        plan_revision=1,
    )
    assert result is None


@pytest.mark.asyncio
async def test_run_response_plan_with_ledger_degrades_without_services() -> None:
    plan = _sample_plan()

    async def _execute() -> ResponsePlan:
        return plan

    result = await run_response_plan_with_ledger(
        None,
        None,
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="test-worker",
        idempotency_key="response-plan:evt-001:1",
        plan_revision=1,
        execute=_execute,
    )
    assert result.plan_id == plan.plan_id


@pytest.mark.asyncio
async def test_run_response_plan_with_ledger_returns_cached_completed_plan() -> None:
    plan = _sample_plan()
    now = datetime.now(tz=UTC)
    task = AgentTask(
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RESPONSE_PLAN,
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RESPONSE_PLAN,
            context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            parameters={"plan_revision": 1},
        ),
        status=AgentTaskStatus.COMPLETED,
        revision=1,
        attempt=1,
        idempotency_key="response-plan:evt-001:1",
        created_at=now,
        updated_at=now,
    )
    artifact = AgentArtifact(
        artifact_id="art-response",
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        logical_artifact_key="response_plan",
        producer_revision=1,
        producer_attempt=1,
        content_hash=compute_response_plan_content_hash(plan),
        payload=plan.model_dump(mode="json"),
        source_refs=[
            AgentTaskContextRef(ref_kind="artifact", ref_id="risk_assessment"),
        ],
        created_at=now,
    )

    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(return_value=task)

    artifact_service = AsyncMock(spec=AgentArtifactService)
    artifact_service.load_latest = AsyncMock(return_value=artifact)

    execute = AsyncMock()

    result = await run_response_plan_with_ledger(
        task_service,
        artifact_service,
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="test-worker",
        idempotency_key="response-plan:evt-001:1",
        plan_revision=1,
        execute=execute,
    )

    assert result.plan_id == plan.plan_id
    execute.assert_not_called()
    task_service.claim.assert_not_called()


@pytest.mark.asyncio
async def test_run_response_plan_retry_replays_prior_artifact_without_execute() -> None:
    plan = _sample_plan()
    mutated = plan.model_copy(update={"strategy_summary": "changed on retry"})
    now = datetime.now(tz=UTC)
    queued_task = AgentTask(
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RESPONSE_PLAN,
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RESPONSE_PLAN,
            context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            parameters={"plan_revision": 1},
        ),
        status=AgentTaskStatus.QUEUED,
        revision=2,
        attempt=1,
        idempotency_key="response-plan:evt-001:1",
        created_at=now,
        updated_at=now,
    )
    prior_artifact = AgentArtifact(
        artifact_id="art-response-v1",
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        logical_artifact_key="response_plan",
        producer_revision=1,
        producer_attempt=1,
        content_hash=compute_response_plan_content_hash(plan),
        payload=plan.model_dump(mode="json"),
        source_refs=[],
        created_at=now,
    )
    claim = AgentTaskClaim(
        task_id="atk-response",
        fencing_token="fencing-token-001",
        lease_expires_at=now + timedelta(minutes=5),
        attempt=2,
        worker_principal="test-worker",
        revision=2,
    )

    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(return_value=queued_task)
    task_service.claim = AsyncMock(return_value=claim)
    task_service.start = AsyncMock()
    task_service.record_staged_artifact_hash = AsyncMock()
    task_service.complete = AsyncMock()
    task_service.fail = AsyncMock()

    artifact_service = AsyncMock(spec=AgentArtifactService)
    artifact_service.load_latest = AsyncMock(return_value=prior_artifact)
    artifact_service.persist = AsyncMock(return_value=prior_artifact)

    execute = AsyncMock(return_value=mutated)

    result = await run_response_plan_with_ledger(
        task_service,
        artifact_service,
        event_id="evt-001",
        tenant_id="tenant-a",
        worker_principal="test-worker",
        idempotency_key="response-plan:evt-001:1",
        plan_revision=1,
        execute=execute,
    )

    assert result.strategy_summary == plan.strategy_summary
    execute.assert_not_called()
    task_service.fail.assert_not_called()
    artifact_service.persist.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_response_plan_execute_drift_rejected_before_side_effects() -> None:
    plan = _sample_plan()
    mutated = plan.model_copy(update={"strategy_summary": "changed on retry"})
    prior_hash = compute_response_plan_content_hash(plan)
    now = datetime.now(tz=UTC)
    queued_task = AgentTask(
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RESPONSE_PLAN,
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RESPONSE_PLAN,
            context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            parameters={
                "plan_revision": 1,
                STAGED_ARTIFACT_HASHES_KEY: {"response_plan": prior_hash},
            },
        ),
        status=AgentTaskStatus.QUEUED,
        revision=2,
        attempt=1,
        idempotency_key="response-plan:evt-001:1",
        created_at=now,
        updated_at=now,
    )
    claim = AgentTaskClaim(
        task_id="atk-response",
        fencing_token="fencing-token-001",
        lease_expires_at=now + timedelta(minutes=5),
        attempt=2,
        worker_principal="test-worker",
        revision=2,
    )

    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(return_value=queued_task)
    task_service.claim = AsyncMock(return_value=claim)
    task_service.start = AsyncMock()
    task_service.record_staged_artifact_hash = AsyncMock()
    task_service.fail = AsyncMock()

    artifact_service = AsyncMock(spec=AgentArtifactService)
    artifact_service.load_latest = AsyncMock(return_value=None)

    execute = AsyncMock(return_value=mutated)

    with pytest.raises(ValidationError, match="persisted artifact anchor"):
        await run_response_plan_with_ledger(
            task_service,
            artifact_service,
            event_id="evt-001",
            tenant_id="tenant-a",
            worker_principal="test-worker",
            idempotency_key="response-plan:evt-001:1",
            plan_revision=1,
            execute=execute,
        )

    execute.assert_not_called()
    task_service.fail.assert_awaited_once()
    artifact_service.persist.assert_not_called()


@pytest.mark.asyncio
async def test_run_response_plan_enqueue_unavailable_fail_closed_when_service_wired() -> None:
    plan = _sample_plan()
    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(side_effect=AgentTaskUnavailableError("db down"))

    async def _execute() -> ResponsePlan:
        return plan

    with pytest.raises(AgentTaskUnavailableError, match="enqueue unavailable"):
        await run_response_plan_with_ledger(
            task_service,
            AsyncMock(spec=AgentArtifactService),
            event_id="evt-001",
            tenant_id="tenant-a",
            worker_principal="test-worker",
            idempotency_key="response-plan:evt-001:1",
            plan_revision=1,
            execute=_execute,
        )


@pytest.mark.asyncio
async def test_run_response_plan_claim_denied_does_not_execute() -> None:
    from app.core.errors import AgentTaskDeniedError as Denied

    now = datetime.now(tz=UTC)
    queued_task = AgentTask(
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RESPONSE_PLAN,
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RESPONSE_PLAN,
            context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            parameters={"plan_revision": 1},
        ),
        status=AgentTaskStatus.QUEUED,
        revision=1,
        attempt=0,
        idempotency_key="response-plan:evt-001:1",
        created_at=now,
        updated_at=now,
    )
    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(return_value=queued_task)
    task_service.claim = AsyncMock(side_effect=Denied("task already running"))

    execute = AsyncMock()

    with pytest.raises(Denied):
        await run_response_plan_with_ledger(
            task_service,
            AsyncMock(spec=AgentArtifactService),
            event_id="evt-001",
            tenant_id="tenant-a",
            worker_principal="test-worker",
            idempotency_key="response-plan:evt-001:1",
            plan_revision=1,
            execute=execute,
        )

    execute.assert_not_called()


@pytest.mark.asyncio
async def test_run_response_plan_artifact_service_missing_marks_manual_without_execute() -> None:
    now = datetime.now(tz=UTC)
    queued_task = AgentTask(
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RESPONSE_PLAN,
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RESPONSE_PLAN,
            context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            parameters={"plan_revision": 1},
        ),
        status=AgentTaskStatus.QUEUED,
        revision=1,
        attempt=0,
        idempotency_key="response-plan:evt-001:1",
        created_at=now,
        updated_at=now,
    )
    claim = AgentTaskClaim(
        task_id="atk-response",
        fencing_token="fencing-token-001",
        lease_expires_at=now + timedelta(minutes=5),
        attempt=1,
        worker_principal="test-worker",
        revision=1,
    )

    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(return_value=queued_task)
    task_service.claim = AsyncMock(return_value=claim)
    task_service.start = AsyncMock()
    task_service.fail = AsyncMock()

    execute = AsyncMock()

    with pytest.raises(AgentTaskDeniedError, match="artifact service"):
        await run_response_plan_with_ledger(
            task_service,
            None,
            event_id="evt-001",
            tenant_id="tenant-a",
            worker_principal="test-worker",
            idempotency_key="response-plan:evt-001:1",
            plan_revision=1,
            execute=execute,
        )

    execute.assert_not_called()
    task_service.fail.assert_awaited_once()
    assert task_service.fail.await_args.kwargs.get("side_effect_unknown") is True
    task_service.complete.assert_not_called()


@pytest.mark.asyncio
async def test_run_response_plan_stage_hash_fail_marks_manual() -> None:
    plan = _sample_plan()
    now = datetime.now(tz=UTC)
    queued_task = AgentTask(
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RESPONSE_PLAN,
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RESPONSE_PLAN,
            context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            parameters={"plan_revision": 1},
        ),
        status=AgentTaskStatus.QUEUED,
        revision=1,
        attempt=0,
        idempotency_key="response-plan:evt-001:1",
        created_at=now,
        updated_at=now,
    )
    claim = AgentTaskClaim(
        task_id="atk-response",
        fencing_token="fencing-token-001",
        lease_expires_at=now + timedelta(minutes=5),
        attempt=1,
        worker_principal="test-worker",
        revision=1,
    )

    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(return_value=queued_task)
    task_service.claim = AsyncMock(return_value=claim)
    task_service.start = AsyncMock()
    task_service.record_staged_artifact_hash = AsyncMock(
        side_effect=RuntimeError("db stage failed")
    )
    task_service.fail = AsyncMock()

    artifact_service = AsyncMock(spec=AgentArtifactService)
    artifact_service.load_latest = AsyncMock(return_value=None)

    async def _execute() -> ResponsePlan:
        return plan

    with pytest.raises(AgentTaskDeniedError, match="staged artifact hash"):
        await run_response_plan_with_ledger(
            task_service,
            artifact_service,
            event_id="evt-001",
            tenant_id="tenant-a",
            worker_principal="test-worker",
            idempotency_key="response-plan:evt-001:1",
            plan_revision=1,
            execute=_execute,
        )

    task_service.fail.assert_awaited_once()
    assert task_service.fail.await_args.kwargs.get("side_effect_unknown") is True
    artifact_service.persist.assert_not_called()
    task_service.complete.assert_not_called()


@pytest.mark.asyncio
async def test_run_response_plan_persist_fail_marks_manual() -> None:
    plan = _sample_plan()
    now = datetime.now(tz=UTC)
    queued_task = AgentTask(
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RESPONSE_PLAN,
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RESPONSE_PLAN,
            context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            parameters={"plan_revision": 1},
        ),
        status=AgentTaskStatus.QUEUED,
        revision=1,
        attempt=0,
        idempotency_key="response-plan:evt-001:1",
        created_at=now,
        updated_at=now,
    )
    claim = AgentTaskClaim(
        task_id="atk-response",
        fencing_token="fencing-token-001",
        lease_expires_at=now + timedelta(minutes=5),
        attempt=1,
        worker_principal="test-worker",
        revision=1,
    )

    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(return_value=queued_task)
    task_service.claim = AsyncMock(return_value=claim)
    task_service.start = AsyncMock()
    task_service.record_staged_artifact_hash = AsyncMock()
    task_service.fail = AsyncMock()

    artifact_service = AsyncMock(spec=AgentArtifactService)
    artifact_service.load_latest = AsyncMock(return_value=None)
    artifact_service.persist = AsyncMock(side_effect=RuntimeError("db write failed"))

    async def _execute() -> ResponsePlan:
        return plan

    with pytest.raises(AgentTaskDeniedError, match="artifact persist failed"):
        await run_response_plan_with_ledger(
            task_service,
            artifact_service,
            event_id="evt-001",
            tenant_id="tenant-a",
            worker_principal="test-worker",
            idempotency_key="response-plan:evt-001:1",
            plan_revision=1,
            execute=_execute,
        )

    task_service.fail.assert_awaited_once()
    assert task_service.fail.await_args.kwargs.get("side_effect_unknown") is True
    task_service.complete.assert_not_called()


@pytest.mark.asyncio
async def test_run_response_plan_retry_rejects_staged_hash_without_artifact() -> None:
    plan = _sample_plan()
    mutated = plan.model_copy(update={"strategy_summary": "changed after persist fail"})
    prior_hash = compute_response_plan_content_hash(plan)
    now = datetime.now(tz=UTC)
    queued_task = AgentTask(
        task_id="atk-response",
        event_id="evt-001",
        tenant_id="tenant-a",
        task_type=AgentTaskType.RESPONSE_PLAN,
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RESPONSE_PLAN,
            context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            parameters={
                "plan_revision": 1,
                STAGED_ARTIFACT_HASHES_KEY: {"response_plan": prior_hash},
            },
        ),
        status=AgentTaskStatus.QUEUED,
        revision=2,
        attempt=1,
        idempotency_key="response-plan:evt-001:1",
        created_at=now,
        updated_at=now,
    )
    claim = AgentTaskClaim(
        task_id="atk-response",
        fencing_token="fencing-token-001",
        lease_expires_at=now + timedelta(minutes=5),
        attempt=2,
        worker_principal="test-worker",
        revision=2,
    )

    task_service = AsyncMock(spec=AgentTaskService)
    task_service.enqueue = AsyncMock(return_value=queued_task)
    task_service.claim = AsyncMock(return_value=claim)
    task_service.start = AsyncMock()
    task_service.record_staged_artifact_hash = AsyncMock()
    task_service.fail = AsyncMock()

    artifact_service = AsyncMock(spec=AgentArtifactService)
    artifact_service.load_latest = AsyncMock(return_value=None)

    execute = AsyncMock(return_value=mutated)

    with pytest.raises(ValidationError, match="persisted artifact anchor"):
        await run_response_plan_with_ledger(
            task_service,
            artifact_service,
            event_id="evt-001",
            tenant_id="tenant-a",
            worker_principal="test-worker",
            idempotency_key="response-plan:evt-001:1",
            plan_revision=1,
            execute=execute,
        )

    execute.assert_not_called()
    task_service.fail.assert_awaited_once()
    artifact_service.persist.assert_not_called()


def _postgres_reachable() -> bool:
    import asyncio
    import os

    from app.db.session_provider import SessionProvider

    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
    )
    provider = SessionProvider(database_url, pool="nullpool")
    try:
        return asyncio.run(provider.ping_postgres())
    except Exception:
        return False
    finally:
        asyncio.run(provider.dispose())


requires_postgres = pytest.mark.skipif(
    not _postgres_reachable(),
    reason="PostgreSQL not reachable",
)


@pytest.fixture(scope="module")
def migrated_database_for_playbook_ledger() -> None:
    import os
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    if not _postgres_reachable():
        pytest.skip("PostgreSQL not reachable")
    backend_dir = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "migrations"))
    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
    )
    try:
        command.upgrade(cfg, "head")
    except Exception as exc:
        pytest.skip(f"PostgreSQL migration unavailable: {exc}")


@pytest.mark.asyncio
@requires_postgres
async def test_response_plan_ledger_full_cycle_postgres(
    migrated_database_for_playbook_ledger: None,
) -> None:
    import os
    import uuid

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    from app.db import models as orm
    from app.services.agent_task_coordinator import _prepare_response_plan_task_for_claim
    from app.services.agent_task_service import _task_from_row

    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
    )

    engine = create_async_engine(database_url, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    task_service = AgentTaskService(factory)
    artifact_service = AgentArtifactService(factory)
    suffix = uuid.uuid4().hex[:8]
    event_id = f"evt-rplan-{suffix}"
    tenant_id = f"tenant-rplan-{suffix}"
    plan = _sample_plan()

    async def _execute() -> ResponsePlan:
        return plan

    result = await run_response_plan_with_ledger(
        task_service,
        artifact_service,
        event_id=event_id,
        tenant_id=tenant_id,
        worker_principal="test-worker",
        idempotency_key=f"response-plan:{event_id}:1",
        plan_revision=1,
        execute=_execute,
    )
    assert result.plan_id == plan.plan_id

    async with factory() as session:
        row = await session.scalar(
            select(orm.AgentTaskORM).where(
                orm.AgentTaskORM.tenant_id == tenant_id,
                orm.AgentTaskORM.idempotency_key == f"response-plan:{event_id}:1",
            )
        )
        assert row is not None
        assert row.status == AgentTaskStatus.COMPLETED.value
        cached = await _prepare_response_plan_task_for_claim(
            _task_from_row(row),
            task_service,
            artifact_service,
            tenant_id=tenant_id,
        )
        assert isinstance(cached, ResponsePlan)
        assert cached.plan_id == plan.plan_id
        artifact = await session.scalar(
            select(orm.AgentArtifactORM).where(
                orm.AgentArtifactORM.task_id == row.task_id,
                orm.AgentArtifactORM.logical_artifact_key == "response_plan",
            )
        )
        assert artifact is not None
        assert artifact.content_hash == compute_response_plan_content_hash(plan)

    await engine.dispose()
