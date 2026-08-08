"""AgentTask / AgentArtifact integration tests (ISSUE-133 / #639)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import AgentTaskDeniedError, ValidationError
from app.db import models as orm
from app.models.agent_task import (
    AgentArtifactPersistRequest,
    AgentTaskClaimRequest,
    AgentTaskContextRef,
    AgentTaskEnqueueRequest,
    AgentTaskGoal,
    AgentTaskStatus,
    AgentTaskType,
    SideEffectStatus,
)
from app.services.agent_artifact_service import AgentArtifactService
from app.services.agent_task_service import AgentTaskService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def migrated_database() -> None:
    import asyncio

    async def _ping() -> None:
        engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                await conn.execute(select(1))
        finally:
            await engine.dispose()

    try:
        asyncio.run(_ping())
    except Exception:
        pytest.skip("PostgreSQL not reachable; start Compose postgres first")
    try:
        command.upgrade(_alembic_config(), "head")
    except Exception as exc:
        pytest.skip(f"PostgreSQL migration unavailable: {exc}")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(select(1))
    except Exception:
        await engine.dispose()
        pytest.skip("PostgreSQL not reachable; start Compose postgres first")
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_task_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.AgentArtifactORM))
            await session.execute(delete(orm.AgentTaskAttemptORM))
            await session.execute(delete(orm.AgentTaskORM))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.AgentArtifactORM))
            await session.execute(delete(orm.AgentTaskAttemptORM))
            await session.execute(delete(orm.AgentTaskORM))


@pytest_asyncio.fixture
def task_service(session_factory: async_sessionmaker[AsyncSession]) -> AgentTaskService:
    return AgentTaskService(session_factory)


@pytest_asyncio.fixture
def artifact_service(session_factory: async_sessionmaker[AsyncSession]) -> AgentArtifactService:
    return AgentArtifactService(session_factory)


def _enqueue_request(*, event_id: str, idempotency_key: str) -> AgentTaskEnqueueRequest:
    return AgentTaskEnqueueRequest(
        event_id=event_id,
        tenant_id="tenant-a",
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RISK_SCORE,
            context_refs=[
                AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
            ],
            parameters={"mode": "rule_only"},
        ),
        idempotency_key=idempotency_key,
    )


@pytest.mark.asyncio
async def test_enqueue_idempotent(task_service: AgentTaskService) -> None:
    event_id = f"evt-at-{_sfx()}"
    key = f"idem-{_sfx()}"
    first = await task_service.enqueue(_enqueue_request(event_id=event_id, idempotency_key=key))
    second = await task_service.enqueue(_enqueue_request(event_id=event_id, idempotency_key=key))
    assert first.task_id == second.task_id
    assert first.status is AgentTaskStatus.QUEUED


@pytest.mark.asyncio
async def test_enqueue_idempotency_rejects_goal_mismatch(task_service: AgentTaskService) -> None:
    event_id = f"evt-at-{_sfx()}"
    key = f"idem-{_sfx()}"
    await task_service.enqueue(_enqueue_request(event_id=event_id, idempotency_key=key))
    mismatched = AgentTaskEnqueueRequest(
        event_id=event_id,
        tenant_id="tenant-a",
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RISK_SCORE,
            context_refs=[
                AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
            ],
            parameters={"mode": "llm_assisted"},
        ),
        idempotency_key=key,
    )
    with pytest.raises(AgentTaskDeniedError, match="goal mismatch"):
        await task_service.enqueue(mismatched)


@pytest.mark.asyncio
async def test_claim_start_complete_happy_path(task_service: AgentTaskService) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    running = await task_service.start(claim, tenant_id="tenant-a")
    assert running.status is AgentTaskStatus.RUNNING
    done = await task_service.complete(claim)
    assert done.status is AgentTaskStatus.COMPLETED


@pytest.mark.asyncio
async def test_stale_fencing_token_denied(task_service: AgentTaskService) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    stale = claim.model_copy(update={"fencing_token": "stale-token-not-valid"})
    with pytest.raises(AgentTaskDeniedError, match="fencing"):
        await task_service.complete(stale)


@pytest.mark.asyncio
async def test_cross_tenant_claim_denied(task_service: AgentTaskService) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    with pytest.raises(AgentTaskDeniedError, match="cross-tenant"):
        await task_service.claim(
            AgentTaskClaimRequest(
                task_id=task.task_id,
                worker_principal="worker-a",
                tenant_id="tenant-b",
            )
        )


@pytest.mark.asyncio
async def test_side_effect_unknown_enters_manual_not_blind_retry(
    task_service: AgentTaskService,
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    manual = await task_service.fail(
        claim, error_summary="tool outcome unknown", side_effect_unknown=True
    )
    assert manual.status is AgentTaskStatus.MANUAL
    assert manual.side_effect_status is SideEffectStatus.UNKNOWN
    with pytest.raises(AgentTaskDeniedError, match="manual resolution"):
        await task_service.retry_to_queue(task.task_id, tenant_id="tenant-a")


@pytest.mark.asyncio
async def test_artifact_idempotent_logical_key(
    task_service: AgentTaskService,
    artifact_service: AgentArtifactService,
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    request = AgentArtifactPersistRequest(
        logical_artifact_key="risk_assessment",
        payload={"risk_score": 82, "severity": "high"},
        source_refs=[
            AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
        ],
        decision_record_refs=["dec-abc12345"],
    )
    first = await artifact_service.persist(
        claim,
        request,
        tenant_id="tenant-a",
        event_id=event_id,
    )
    second = await artifact_service.persist(
        claim,
        request,
        tenant_id="tenant-a",
        event_id=event_id,
    )
    assert first.artifact_id == second.artifact_id


@pytest.mark.asyncio
async def test_artifact_idempotent_replay_rejects_content_hash_mismatch(
    task_service: AgentTaskService,
    artifact_service: AgentArtifactService,
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    request = AgentArtifactPersistRequest(
        logical_artifact_key="risk_assessment",
        payload={"risk_score": 82, "severity": "high"},
        source_refs=[
            AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
        ],
    )
    await artifact_service.persist(
        claim,
        request,
        tenant_id="tenant-a",
        event_id=event_id,
    )
    mismatched = AgentArtifactPersistRequest(
        logical_artifact_key="risk_assessment",
        payload={"risk_score": 99, "severity": "critical"},
        source_refs=[
            AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
        ],
    )
    with pytest.raises(ValidationError, match="content_hash mismatch"):
        await artifact_service.persist(
            claim,
            mismatched,
            tenant_id="tenant-a",
            event_id=event_id,
        )


@pytest.mark.asyncio
async def test_claim_reclaims_after_lease_expiry(
    task_service: AgentTaskService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    first_claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
            lease_seconds=60,
        )
    )
    assert first_claim.worker_principal == "worker-a"
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.AgentTaskORM, task.task_id)
            assert row is not None
            row.lease_expires_at = datetime.now(tz=UTC) - timedelta(seconds=30)
    second_claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-b",
            tenant_id="tenant-a",
        )
    )
    assert second_claim.worker_principal == "worker-b"
    assert second_claim.attempt == first_claim.attempt + 1


@pytest.mark.asyncio
async def test_terminal_complete_idempotent(
    task_service: AgentTaskService,
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    first = await task_service.complete(claim)
    second = await task_service.complete(claim)
    assert first.status is AgentTaskStatus.COMPLETED
    assert second.status is AgentTaskStatus.COMPLETED


@pytest.mark.asyncio
async def test_attempt_history_recorded(
    task_service: AgentTaskService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    await task_service.complete(claim)
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.AgentTaskAttemptORM)
            .where(orm.AgentTaskAttemptORM.task_id == task.task_id)
        )
    assert count == 1


@pytest.mark.asyncio
async def test_cross_tenant_idempotency_key_isolated_per_tenant(
    task_service: AgentTaskService,
) -> None:
    event_id = f"evt-at-{_sfx()}"
    key = f"idem-{_sfx()}"
    first = await task_service.enqueue(_enqueue_request(event_id=event_id, idempotency_key=key))
    other = AgentTaskEnqueueRequest(
        event_id=event_id,
        tenant_id="tenant-b",
        goal=AgentTaskGoal(
            task_type=AgentTaskType.RISK_SCORE,
            context_refs=[
                AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
            ],
        ),
        idempotency_key=key,
    )
    second = await task_service.enqueue(other)
    assert first.task_id != second.task_id
    assert first.tenant_id == "tenant-a"
    assert second.tenant_id == "tenant-b"


@pytest.mark.asyncio
async def test_failed_task_retry_claim_complete_cycle(task_service: AgentTaskService) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    failed = await task_service.fail(claim, error_summary="transient error")
    assert failed.status is AgentTaskStatus.FAILED
    retried = await task_service.retry_to_queue(task.task_id, tenant_id="tenant-a")
    assert retried.status is AgentTaskStatus.QUEUED
    claim2 = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim2, tenant_id="tenant-a")
    done = await task_service.complete(claim2)
    assert done.status is AgentTaskStatus.COMPLETED


@pytest.mark.asyncio
async def test_expired_task_requeue_claim_complete_cycle(
    task_service: AgentTaskService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
            lease_seconds=60,
        )
    )
    async with session_factory() as session:
        row = await session.get(orm.AgentTaskORM, task.task_id)
        assert row is not None
        assert AgentTaskStatus(row.status) is AgentTaskStatus.CLAIMED
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.AgentTaskORM, task.task_id)
            assert row is not None
            row.lease_expires_at = datetime.now(tz=UTC) - timedelta(seconds=30)
    expired = await task_service.expire_stale_claim(task.task_id, tenant_id="tenant-a")
    assert expired.status is AgentTaskStatus.EXPIRED
    retried = await task_service.retry_to_queue(task.task_id, tenant_id="tenant-a")
    assert retried.status is AgentTaskStatus.QUEUED
    claim2 = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-b",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim2, tenant_id="tenant-a")
    done = await task_service.complete(claim2)
    assert done.status is AgentTaskStatus.COMPLETED


@pytest.mark.asyncio
async def test_artifact_denied_when_task_not_running(
    task_service: AgentTaskService,
    artifact_service: AgentArtifactService,
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    await task_service.complete(claim)
    with pytest.raises(AgentTaskDeniedError, match="running task"):
        await artifact_service.persist(
            claim,
            AgentArtifactPersistRequest(
                logical_artifact_key="risk_assessment",
                payload={"risk_score": 1},
            ),
            tenant_id="tenant-a",
            event_id=event_id,
        )


@pytest.mark.asyncio
async def test_reconcile_completed_without_artifact_allows_retry(
    task_service: AgentTaskService,
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    await task_service.complete(claim)
    reconciled = await task_service.reconcile_completed_without_artifact(
        task.task_id,
        tenant_id="tenant-a",
    )
    assert reconciled.status is AgentTaskStatus.FAILED
    retried = await task_service.retry_to_queue(task.task_id, tenant_id="tenant-a")
    assert retried.status is AgentTaskStatus.QUEUED


@pytest.mark.asyncio
async def test_reconcile_stale_running_marks_failed(
    task_service: AgentTaskService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = f"evt-at-{_sfx()}"
    task = await task_service.enqueue(
        _enqueue_request(event_id=event_id, idempotency_key=f"idem-{_sfx()}")
    )
    claim = await task_service.claim(
        AgentTaskClaimRequest(
            task_id=task.task_id,
            worker_principal="worker-a",
            tenant_id="tenant-a",
        )
    )
    await task_service.start(claim, tenant_id="tenant-a")
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.AgentTaskORM, task.task_id)
            assert row is not None
            row.updated_at = datetime.now(tz=UTC) - timedelta(hours=1)
    reconciled = await task_service.reconcile_stale_running(task.task_id, tenant_id="tenant-a")
    assert reconciled.status is AgentTaskStatus.FAILED
    assert reconciled.last_error == "stale_running_sweeper"
    retried = await task_service.retry_to_queue(task.task_id, tenant_id="tenant-a")
    assert retried.status is AgentTaskStatus.QUEUED
