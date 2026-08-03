"""Shadow run service tests (ISSUE-135 / #641 Phase A)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.db.orm.shadow_run import (
    ShadowDecisionRecordORM,
    ShadowQueryArtifactORM,
    ShadowRunORM,
)
from app.models.decision_record import DecisionRecord, DecisionStage
from app.models.shadow_run import ShadowQueryArtifactKind, ShadowRunStatus
from app.services.shadow_run_service import ShadowRunService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _postgres_reachable() -> bool:
    import asyncio

    from app.db.session_provider import SessionProvider

    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    try:
        return asyncio.run(provider.ping_postgres())
    except Exception:
        return False
    finally:
        asyncio.run(provider.dispose())


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated_database() -> None:
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_shadow_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(ShadowQueryArtifactORM))
            await session.execute(delete(ShadowDecisionRecordORM))
            await session.execute(delete(ShadowRunORM))
    yield


requires_postgres = pytest.mark.skipif(
    not _postgres_reachable(),
    reason="PostgreSQL not reachable",
)


@pytest.mark.asyncio
@requires_postgres
async def test_create_and_finalize_shadow_run(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    service = ShadowRunService(session_factory, retention_hours=24)
    sfx = uuid.uuid4().hex[:8]
    run = await service.create_run(
        event_id=f"evt-shadow-run-{sfx}",
        tenant_id="tenant-a",
        principal="investigation:test",
        trigger="unit_test",
        max_steps=3,
        max_tool_calls=2,
    )
    assert run.status is ShadowRunStatus.RUNNING
    assert run.namespace_key.startswith("shadow:")

    finalized = await service.finalize_run(
        run.shadow_run_id,
        status=ShadowRunStatus.COMPLETED,
        step_count=2,
        tool_call_count=1,
        result_summary={"stop_reason": "confidence_met"},
    )
    assert finalized is not None
    assert finalized.status is ShadowRunStatus.COMPLETED
    assert finalized.step_count == 2


@pytest.mark.asyncio
@requires_postgres
async def test_shadow_decision_record_does_not_increment_production_count(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    service = ShadowRunService(session_factory)
    sfx = uuid.uuid4().hex[:8]
    event_id = f"evt-shadow-decision-{sfx}"
    before = await service.count_production_decision_records_for_event(event_id)

    run = await service.create_run(
        event_id=event_id,
        tenant_id="tenant-a",
        principal="investigation:test",
        trigger="unit_test",
        max_steps=1,
        max_tool_calls=1,
    )
    record = DecisionRecord(
        record_id=f"sdr-{sfx}",
        event_id=event_id,
        stage=DecisionStage.REACT_REFLECT,
        actor="shadow_query_pivot",
        decision_summary="shadow pivot round complete",
        idempotency_key=f"shadow:{run.shadow_run_id}:reflect:round1",
        retention_policy="shadow_pivot_v1",
        owner=run.namespace_key,
        record_hash="abc123",
    )
    await service.persist_decision_record(run, record)
    await service.persist_artifact(
        run,
        kind=ShadowQueryArtifactKind.RETRIEVAL_HIT,
        payload={"chunk_count": 1},
    )

    after = await service.count_production_decision_records_for_event(event_id)
    assert after == before == 0

    loaded = await service.get_run(run.shadow_run_id)
    assert loaded is not None
    assert loaded.event_id == event_id


@pytest.mark.asyncio
@requires_postgres
async def test_shadow_decision_record_idempotent_replay(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    service = ShadowRunService(session_factory)
    sfx = uuid.uuid4().hex[:8]
    run = await service.create_run(
        event_id=f"evt-shadow-replay-{sfx}",
        tenant_id="tenant-a",
        principal="investigation:test",
        trigger="unit_test",
        max_steps=1,
        max_tool_calls=1,
    )
    idempotency_key = f"shadow:{run.shadow_run_id}:reflect:round1"
    record = DecisionRecord(
        record_id=f"sdr-{sfx}-a",
        event_id=run.event_id,
        stage=DecisionStage.REACT_REFLECT,
        actor="shadow_query_pivot",
        decision_summary="first write",
        idempotency_key=idempotency_key,
        retention_policy="shadow_pivot_v1",
        owner=run.namespace_key,
        record_hash="hash-a",
    )
    first_id = await service.persist_decision_record(run, record)
    replay = record.model_copy(update={"record_id": f"sdr-{sfx}-b", "record_hash": "hash-a"})
    second_id = await service.persist_decision_record(run, replay)
    assert second_id == first_id

    mismatch = record.model_copy(update={"record_id": f"sdr-{sfx}-c", "record_hash": "hash-b"})
    third_id = await service.persist_decision_record(run, mismatch)
    assert third_id == first_id
