"""Persistence and projection tests for BehaviorObservation (ISSUE-119 / #624)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.behavior_observation import (
    BehaviorObservationProjectionStatus,
    BehaviorObservationQuery,
)
from app.models.detection_scope import (
    DetectionScopeIdentity,
    DetectionScopeLifecycleState,
    UpstreamConnectorMember,
)
from app.models.enums import SourceDisposition, SourceObjectKind
from app.services.behavior_observation_service import BehaviorObservationService
from app.services.detection_scope_service import DetectionScopeService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="module")
def migrated_database() -> None:
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
async def clean_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.BehaviorObservationProjectionFailure))
            await session.execute(delete(orm.BehaviorObservation))
            await session.execute(delete(orm.DetectionScopeRevision))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.SourceConnector))
            await session.execute(delete(orm.DataQualityError))
            await session.execute(delete(orm.SecurityEvent))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.BehaviorObservationProjectionFailure))
            await session.execute(delete(orm.BehaviorObservation))
            await session.execute(delete(orm.DetectionScopeRevision))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.SourceConnector))
            await session.execute(delete(orm.DataQualityError))
            await session.execute(delete(orm.SecurityEvent))


def _observation_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> BehaviorObservationService:
    return BehaviorObservationService(session_factory)


def _scope_service(session_factory: async_sessionmaker[AsyncSession]) -> DetectionScopeService:
    return DetectionScopeService(session_factory)


async def _seed_connector(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    connector_id: str,
    tenant_id: str,
    integration_instance_id: str = "inst-primary",
) -> None:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name=f"Test {connector_id}",
                    status="online",
                    schema_version="1",
                    connector_metadata={
                        "source_tenant_id": tenant_id,
                        "integration_instance_id": integration_instance_id,
                        "connector_set_version": 1,
                    },
                )
            )


async def _seed_source_log(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
    connector_id: str,
    source_revision: int = 1,
) -> str:
    record_id = f"src-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceObject(
                    source_record_id=record_id,
                    source_product="mock_xdr",
                    source_tenant_id=tenant_id,
                    connector_id=connector_id,
                    source_kind=SourceObjectKind.LOG.value,
                    source_object_id=f"log-{suffix}",
                    source_object_type="edr",
                    source_status_raw="indexed",
                    source_disposition=SourceDisposition.UNKNOWN.value,
                    schema_version="1",
                    ingested_at=datetime(2026, 8, 1, tzinfo=UTC),
                    raw_payload_hash=f"hash-{suffix}",
                    normalized={
                        "channel": "endpoint",
                        "category": "process_create",
                        "action": "create_process",
                        "src_ip": "10.0.0.10",
                        "detection_score": 55,
                        "logged_at": "2026-08-01T00:00:00+00:00",
                    },
                    raw_payload={"cmdline": "sensitive"},
                    current_source_status_raw="indexed",
                    current_source_disposition=SourceDisposition.UNKNOWN.value,
                    current_state_version=source_revision,
                    source_updated_at=datetime(2026, 8, 1, tzinfo=UTC),
                    source_sync_state="synced",
                )
            )
    return record_id


@pytest.mark.asyncio
async def test_project_source_object_persists_observation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    await _seed_connector(session_factory, connector_id=connector_id, tenant_id=tenant_id)
    record_id = await _seed_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    service = _observation_service(session_factory)
    observation = await service.project_source_object(record_id)
    assert observation is not None
    assert observation.source_tenant_id == tenant_id
    assert observation.detection_score == 55.0
    assert observation.provenance.source_record_id == record_id
    assert "cmdline" not in observation.normalized_attributes

    loaded = await service.get_observation(observation.observation_id)
    assert loaded is not None
    assert loaded.content_hash == observation.content_hash


@pytest.mark.asyncio
async def test_project_is_idempotent_for_same_source_revision(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    await _seed_connector(session_factory, connector_id=connector_id, tenant_id=tenant_id)
    record_id = await _seed_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    service = _observation_service(session_factory)
    first = await service.project_source_object(record_id)
    second = await service.project_source_object(record_id)
    assert first is not None and second is not None
    assert first.observation_id == second.observation_id


@pytest.mark.asyncio
async def test_source_revision_bump_creates_new_observation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    await _seed_connector(session_factory, connector_id=connector_id, tenant_id=tenant_id)
    record_id = await _seed_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
        source_revision=1,
    )
    service = _observation_service(session_factory)
    first = await service.project_source_object(record_id)
    assert first is not None

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SourceObject, record_id)
            assert row is not None
            row.current_state_version = 2
            row.normalized = {
                **dict(row.normalized or {}),
                "detection_score": 80,
            }

    second = await service.project_source_object(record_id)
    assert second is not None
    assert second.observation_id != first.observation_id
    assert second.supersedes_observation_id == first.observation_id
    assert second.detection_score == 80.0


@pytest.mark.asyncio
async def test_tenant_isolation_for_same_source_object_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    connector_a = f"conn-a-{suffix}"
    connector_b = f"conn-b-{suffix}"
    await _seed_connector(session_factory, connector_id=connector_a, tenant_id=tenant_a)
    await _seed_connector(session_factory, connector_id=connector_b, tenant_id=tenant_b)
    record_a = await _seed_source_log(
        session_factory,
        suffix=f"a-{suffix}",
        tenant_id=tenant_a,
        connector_id=connector_a,
    )
    record_b = await _seed_source_log(
        session_factory,
        suffix=f"b-{suffix}",
        tenant_id=tenant_b,
        connector_id=connector_b,
    )
    service = _observation_service(session_factory)
    obs_a = await service.project_source_object(record_a)
    obs_b = await service.project_source_object(record_b)
    assert obs_a is not None and obs_b is not None
    assert obs_a.observation_id != obs_b.observation_id

    result = await service.query_observations(BehaviorObservationQuery(source_tenant_id=tenant_a))
    assert all(item.source_tenant_id == tenant_a for item in result.items)


@pytest.mark.asyncio
async def test_uses_registered_detection_scope_when_available(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    await _seed_connector(
        session_factory,
        connector_id=connector_id,
        tenant_id=tenant_id,
        integration_instance_id=f"inst-{suffix}",
    )
    scope_service = _scope_service(session_factory)
    identity = DetectionScopeIdentity(
        source_tenant_id=tenant_id,
        source_product="mock_xdr",
        integration_instance_id=f"inst-{suffix}",
    )
    revision = await scope_service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id=connector_id, source_product="mock_xdr"),
        ],
    )
    activated = await scope_service.activate_revision(revision.scope_revision_id)
    assert activated.lifecycle_state is DetectionScopeLifecycleState.ACTIVE

    record_id = await _seed_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    observation = await _observation_service(session_factory).project_source_object(record_id)
    assert observation is not None
    assert observation.detection_scope_id == activated.detection_scope_id


@pytest.mark.asyncio
async def test_projection_failure_is_durable_and_retryable(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    await _seed_connector(session_factory, connector_id=connector_id, tenant_id=tenant_id)
    record_id = await _seed_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    service = _observation_service(session_factory)
    with patch.object(
        service,
        "persist_in_session",
        side_effect=RuntimeError("projection boom"),
    ):
        with pytest.raises(RuntimeError, match="projection boom"):
            await service.project_source_object(record_id)

    await service.record_projection_failure(
        source_record_id=record_id,
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "projection boom"},
    )
    async with session_factory() as session:
        failure = await session.scalar(
            select(orm.BehaviorObservationProjectionFailure).where(
                orm.BehaviorObservationProjectionFailure.source_record_id == record_id
            )
        )
        assert failure is not None
        assert failure.status == BehaviorObservationProjectionStatus.PENDING_RETRY.value
        quality = await session.scalar(
            select(orm.DataQualityError).where(
                orm.DataQualityError.stage == "behavior_observation_projection"
            )
        )
        assert quality is not None

    observation = await service.project_source_object(record_id)
    assert observation is not None
    retried = await service.retry_pending(limit=10)
    assert retried >= 0


@pytest.mark.asyncio
async def test_idempotency_hash_mismatch_rejected(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    await _seed_connector(session_factory, connector_id=connector_id, tenant_id=tenant_id)
    record_id = await _seed_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    service = _observation_service(session_factory)
    first = await service.project_source_object(record_id)
    assert first is not None
    tampered = first.model_copy(
        update={
            "detection_score": 11.0,
            "observation_hash": "deadbeef" * 8,
        }
    )
    async with session_factory() as session:
        async with session.begin():
            with pytest.raises(ValidationError, match="different content hash"):
                await service.persist_in_session(session, tampered)


@pytest.mark.asyncio
async def test_resolve_scope_fallback_when_other_instance_has_active_scope(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scoped_connector = f"conn-a-{suffix}"
    fallback_connector = f"conn-b-{suffix}"
    instance_a = f"inst-a-{suffix}"
    instance_b = f"inst-b-{suffix}"
    await _seed_connector(
        session_factory,
        connector_id=scoped_connector,
        tenant_id=tenant_id,
        integration_instance_id=instance_a,
    )
    await _seed_connector(
        session_factory,
        connector_id=fallback_connector,
        tenant_id=tenant_id,
        integration_instance_id=instance_b,
    )
    scope_service = _scope_service(session_factory)
    identity = DetectionScopeIdentity(
        source_tenant_id=tenant_id,
        source_product="mock_xdr",
        integration_instance_id=instance_a,
    )
    revision = await scope_service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id=scoped_connector, source_product="mock_xdr"),
        ],
    )
    await scope_service.activate_revision(revision.scope_revision_id)

    record_id = await _seed_source_log(
        session_factory,
        suffix=f"b-{suffix}",
        tenant_id=tenant_id,
        connector_id=fallback_connector,
    )
    observation = await _observation_service(session_factory).project_source_object(record_id)
    assert observation is not None
    assert observation.detection_scope_id.startswith("dscope-")


@pytest.mark.asyncio
async def test_resolve_scope_fails_when_active_scope_missing_connector(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scoped_connector = f"conn-scoped-{suffix}"
    missing_connector = f"conn-missing-{suffix}"
    instance_id = f"inst-{suffix}"
    await _seed_connector(
        session_factory,
        connector_id=scoped_connector,
        tenant_id=tenant_id,
        integration_instance_id=instance_id,
    )
    await _seed_connector(
        session_factory,
        connector_id=missing_connector,
        tenant_id=tenant_id,
        integration_instance_id=instance_id,
    )
    scope_service = _scope_service(session_factory)
    identity = DetectionScopeIdentity(
        source_tenant_id=tenant_id,
        source_product="mock_xdr",
        integration_instance_id=instance_id,
    )
    revision = await scope_service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id=scoped_connector, source_product="mock_xdr"),
        ],
    )
    await scope_service.activate_revision(revision.scope_revision_id)

    record_id = await _seed_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=missing_connector,
    )
    service = _observation_service(session_factory)
    with pytest.raises(ValidationError, match="not in active detection scope"):
        await service.project_source_object(record_id)


@pytest.mark.asyncio
async def test_projection_failure_updates_single_row_on_repeat(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    record_id = f"src-{suffix}"
    service = _observation_service(session_factory)
    await service.record_projection_failure(
        source_record_id=record_id,
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "first"},
    )
    await service.record_projection_failure(
        source_record_id=record_id,
        source_tenant_id=tenant_id,
        error_category="projection_failed",
        detail={"message": "second"},
    )
    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.BehaviorObservationProjectionFailure).where(
                    orm.BehaviorObservationProjectionFailure.source_record_id == record_id,
                    orm.BehaviorObservationProjectionFailure.status
                    == BehaviorObservationProjectionStatus.PENDING_RETRY.value,
                )
            )
        )
        total = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.BehaviorObservationProjectionFailure)
                .where(orm.BehaviorObservationProjectionFailure.source_record_id == record_id)
            )
            or 0
        )
        dqe_total = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.DataQualityError)
                .where(
                    orm.DataQualityError.stage == "behavior_observation_projection",
                    orm.DataQualityError.detail["source_record_id"].as_string() == record_id,
                )
            )
            or 0
        )
    assert total == 1
    assert rows[0].attempt == 2
    assert rows[0].detail["message"] == "second"
    assert dqe_total == 1


@pytest.mark.asyncio
async def test_projection_dead_letter_after_max_attempts(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    record_id = f"src-dead-{suffix}"
    service = _observation_service(session_factory)
    for attempt in range(5):
        await service.record_projection_failure(
            source_record_id=record_id,
            source_tenant_id=tenant_id,
            error_category="projection_failed",
            detail={"message": f"attempt-{attempt + 1}"},
        )
    async with session_factory() as session:
        failure = await session.scalar(
            select(orm.BehaviorObservationProjectionFailure).where(
                orm.BehaviorObservationProjectionFailure.source_record_id == record_id
            )
        )
    assert failure is not None
    assert failure.status == BehaviorObservationProjectionStatus.DEAD_LETTER.value
    assert failure.attempt == 5
    assert failure.next_retry_at is None
