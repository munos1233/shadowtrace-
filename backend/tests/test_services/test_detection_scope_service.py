"""Persistence tests for DetectionScopeRevision (ISSUE-120 Phase 0)."""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.detection_scope import (
    DetectionScopeIdentity,
    DetectionScopeLifecycleState,
    DetectionScopeQuery,
    UpstreamConnectorMember,
)
from app.services.detection_scope_resolver import compute_scope_content_hash
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


def _service(session_factory: async_sessionmaker[AsyncSession]) -> DetectionScopeService:
    return DetectionScopeService(session_factory)


def _identity(suffix: str) -> DetectionScopeIdentity:
    return DetectionScopeIdentity(
        source_tenant_id=f"tenant-{suffix}",
        source_product="mock_xdr",
        integration_instance_id=f"inst-{suffix}",
        environment="prod",
        region="cn-east",
    )


@pytest.mark.asyncio
async def test_register_rejects_connector_membership_drift_at_same_version(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
        ],
    )
    with pytest.raises(ValidationError, match="connector membership drift"):
        await service.register_revision(
            identity=identity,
            connector_set_version=1,
            upstream_connectors=[
                UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
                UpstreamConnectorMember(connector_id="conn-edr", source_product="mock_xdr"),
            ],
            revision=2,
        )


@pytest.mark.asyncio
async def test_content_hash_matches_lifecycle_after_activate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    revision = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
        ],
    )
    activated = await service.activate_revision(revision.scope_revision_id)
    assert activated.lifecycle_state is DetectionScopeLifecycleState.ACTIVE
    expected_hash = compute_scope_content_hash(
        {
            "detection_scope_id": activated.detection_scope_id,
            "identity": identity.model_dump(mode="json"),
            "connector_set": activated.connector_set.model_dump(mode="json"),
            "lifecycle_state": DetectionScopeLifecycleState.ACTIVE.value,
            "revision": activated.revision,
            "schema_version": activated.schema_version,
        }
    )
    assert activated.content_hash == expected_hash


@pytest.mark.asyncio
async def test_concurrent_activate_only_one_active_per_instance(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    first = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
        ],
    )
    second = await service.register_revision(
        identity=identity,
        connector_set_version=2,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
            UpstreamConnectorMember(connector_id="conn-edr", source_product="mock_xdr"),
        ],
        revision=2,
        supersedes_scope_revision_id=first.scope_revision_id,
    )
    results = await asyncio.gather(
        service.activate_revision(first.scope_revision_id),
        service.activate_revision(second.scope_revision_id),
        return_exceptions=True,
    )
    assert any(not isinstance(item, Exception) for item in results)
    assert all(
        isinstance(item, IntegrityError)
        or "uq_detection_scope_revision_one_active_per_instance" in str(item)
        or not isinstance(item, Exception)
        for item in results
    )
    active_for_instance = await service.get_active_revision_for_instance(
        source_tenant_id=identity.source_tenant_id,
        source_product=identity.source_product,
        integration_instance_id=identity.integration_instance_id,
    )
    assert active_for_instance is not None
    async with session_factory() as session:
        active_rows = await session.scalars(
            select(orm.DetectionScopeRevision).where(
                orm.DetectionScopeRevision.source_tenant_id == identity.source_tenant_id,
                orm.DetectionScopeRevision.source_product == identity.source_product,
                orm.DetectionScopeRevision.integration_instance_id
                == identity.integration_instance_id,
                orm.DetectionScopeRevision.lifecycle_state
                == DetectionScopeLifecycleState.ACTIVE.value,
            )
        )
        assert len(list(active_rows)) == 1

    async with session_factory() as session:
        async with session.begin():
            extras = await session.scalars(
                select(orm.DetectionScopeRevision).where(
                    orm.DetectionScopeRevision.source_tenant_id == identity.source_tenant_id,
                    orm.DetectionScopeRevision.source_product == identity.source_product,
                    orm.DetectionScopeRevision.integration_instance_id
                    == identity.integration_instance_id,
                    orm.DetectionScopeRevision.lifecycle_state
                    == DetectionScopeLifecycleState.ACTIVE.value,
                )
            )
            now = datetime.now(UTC)
            for row in list(extras)[1:]:
                row.lifecycle_state = DetectionScopeLifecycleState.RETIRED.value
                row.retired_at = now


@pytest.mark.asyncio
async def test_source_product_isolation_in_query(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    tenant_id = f"tenant-prod-{suffix}"
    instance_id = f"inst-{suffix}"
    mock_scope = await service.register_revision(
        identity=DetectionScopeIdentity(
            source_tenant_id=tenant_id,
            source_product="mock_xdr",
            integration_instance_id=instance_id,
        ),
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-a", source_product="mock_xdr"),
        ],
    )
    await service.register_revision(
        identity=DetectionScopeIdentity(
            source_tenant_id=tenant_id,
            source_product="other_product",
            integration_instance_id=instance_id,
        ),
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-b", source_product="other_product"),
        ],
    )
    result = await service.query_revisions(
        DetectionScopeQuery(
            source_tenant_id=tenant_id,
            source_product="mock_xdr",
        )
    )
    assert all(item.identity.source_product == "mock_xdr" for item in result.items)
    assert any(item.scope_revision_id == mock_scope.scope_revision_id for item in result.items)


@pytest.mark.asyncio
async def test_get_active_revision_for_instance_empty_after_retire_all(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    revision = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
        ],
    )
    activated = await service.activate_revision(revision.scope_revision_id)
    await service.retire_revision(activated.scope_revision_id)
    active = await service.get_active_revision_for_instance(
        source_tenant_id=identity.source_tenant_id,
        source_product=identity.source_product,
        integration_instance_id=identity.integration_instance_id,
    )
    assert active is None


@pytest.mark.asyncio
async def test_register_and_query_scope_revision(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    revision = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
            UpstreamConnectorMember(connector_id="conn-edr", source_product="mock_xdr"),
        ],
    )
    assert revision.lifecycle_state is DetectionScopeLifecycleState.DRAFT
    loaded = await service.get_revision(revision.scope_revision_id)
    assert loaded is not None
    assert loaded.detection_scope_id == revision.detection_scope_id
    assert len(loaded.connector_set.upstream_connectors) == 2

    result = await service.query_revisions(
        DetectionScopeQuery(source_tenant_id=identity.source_tenant_id)
    )
    assert result.total >= 1
    assert any(item.scope_revision_id == revision.scope_revision_id for item in result.items)


@pytest.mark.asyncio
async def test_activate_retires_previous_active_revision(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    first = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
        ],
    )
    activated_first = await service.activate_revision(first.scope_revision_id)
    assert activated_first.lifecycle_state is DetectionScopeLifecycleState.ACTIVE
    assert activated_first.activated_at is not None

    second = await service.register_revision(
        identity=identity,
        connector_set_version=2,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
            UpstreamConnectorMember(connector_id="conn-edr", source_product="mock_xdr"),
        ],
        revision=2,
        supersedes_scope_revision_id=first.scope_revision_id,
    )
    activated_second = await service.activate_revision(second.scope_revision_id)
    reloaded_first = await service.get_revision(first.scope_revision_id)
    assert reloaded_first is not None
    assert reloaded_first.lifecycle_state is DetectionScopeLifecycleState.RETIRED
    assert reloaded_first.retired_at is not None
    assert activated_second.lifecycle_state is DetectionScopeLifecycleState.ACTIVE

    active = await service.get_active_revision(detection_scope_id=second.detection_scope_id)
    assert active is not None
    assert active.scope_revision_id == second.scope_revision_id

    active_for_instance = await service.get_active_revision_for_instance(
        source_tenant_id=identity.source_tenant_id,
        source_product=identity.source_product,
        integration_instance_id=identity.integration_instance_id,
    )
    assert active_for_instance is not None
    assert active_for_instance.scope_revision_id == second.scope_revision_id


@pytest.mark.asyncio
async def test_register_revision_is_idempotent_by_key(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    kwargs = {
        "identity": identity,
        "connector_set_version": 1,
        "upstream_connectors": [
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
        ],
    }
    await service.register_revision(**kwargs)
    with pytest.raises(ValidationError, match="detection scope revision already exists"):
        await service.register_revision(**kwargs)


@pytest.mark.asyncio
async def test_tenant_isolation_in_query(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    tenant_a = _identity(f"a-{suffix}")
    tenant_b = _identity(f"b-{suffix}")
    scope_a = await service.register_revision(
        identity=tenant_a,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-a", source_product="mock_xdr"),
        ],
    )
    await service.register_revision(
        identity=tenant_b,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-b", source_product="mock_xdr"),
        ],
    )
    result = await service.query_revisions(
        DetectionScopeQuery(source_tenant_id=tenant_a.source_tenant_id)
    )
    assert all(item.identity.source_tenant_id == tenant_a.source_tenant_id for item in result.items)
    assert any(item.scope_revision_id == scope_a.scope_revision_id for item in result.items)

    async with session_factory() as session:
        rows = await session.scalars(select(orm.DetectionScopeRevision))
        assert len(list(rows)) >= 2


@pytest.mark.asyncio
async def test_register_rejects_invalid_supersedes(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    other = _identity(f"other-{suffix}")

    with pytest.raises(ValidationError, match="supersedes_scope_revision_id not found"):
        await service.register_revision(
            identity=identity,
            connector_set_version=1,
            upstream_connectors=[
                UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
            ],
            supersedes_scope_revision_id="dscope-rev-missing",
        )

    first = await service.register_revision(
        identity=other,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-other", source_product="mock_xdr"),
        ],
    )
    with pytest.raises(ValidationError, match="supersedes revision tenant mismatch"):
        await service.register_revision(
            identity=identity,
            connector_set_version=1,
            upstream_connectors=[
                UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
            ],
            supersedes_scope_revision_id=first.scope_revision_id,
        )


@pytest.mark.asyncio
async def test_activate_same_scope_id_requires_version_bump_for_membership_change(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    first = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
        ],
        revision=1,
    )
    await service.activate_revision(first.scope_revision_id)

    second = await service.register_revision(
        identity=identity,
        connector_set_version=2,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
            UpstreamConnectorMember(connector_id="conn-edr", source_product="mock_xdr"),
        ],
        revision=2,
        supersedes_scope_revision_id=first.scope_revision_id,
    )
    await service.activate_revision(second.scope_revision_id)

    reloaded_first = await service.get_revision(first.scope_revision_id)
    assert reloaded_first is not None
    assert reloaded_first.lifecycle_state is DetectionScopeLifecycleState.RETIRED


@pytest.mark.asyncio
async def test_activate_already_active_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    identity = _identity(suffix)
    revision = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id="conn-log", source_product="mock_xdr"),
        ],
    )
    activated = await service.activate_revision(revision.scope_revision_id)
    again = await service.activate_revision(revision.scope_revision_id)
    assert again.lifecycle_state is DetectionScopeLifecycleState.ACTIVE
    assert again.activated_at == activated.activated_at


@pytest.mark.asyncio
async def test_query_latest_revision_only_across_pages(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    service = _service(session_factory)
    tenant_id = f"tenant-page-{suffix}"

    scope_ids: list[str] = []
    for index in range(3):
        identity = DetectionScopeIdentity(
            source_tenant_id=tenant_id,
            source_product="mock_xdr",
            integration_instance_id=f"inst-{suffix}-{index}",
            environment="prod",
            region="cn-east",
        )
        first = await service.register_revision(
            identity=identity,
            connector_set_version=1,
            upstream_connectors=[
                UpstreamConnectorMember(
                    connector_id=f"conn-{index}-a",
                    source_product="mock_xdr",
                ),
            ],
            revision=1,
        )
        await service.register_revision(
            identity=identity,
            connector_set_version=1,
            upstream_connectors=[
                UpstreamConnectorMember(
                    connector_id=f"conn-{index}-a",
                    source_product="mock_xdr",
                ),
            ],
            revision=2,
            supersedes_scope_revision_id=first.scope_revision_id,
        )
        scope_ids.append(first.detection_scope_id)

    page_one = await service.query_revisions(
        DetectionScopeQuery(
            source_tenant_id=tenant_id,
            latest_revision_only=True,
            page=1,
            page_size=2,
        )
    )
    page_two = await service.query_revisions(
        DetectionScopeQuery(
            source_tenant_id=tenant_id,
            latest_revision_only=True,
            page=2,
            page_size=2,
        )
    )
    assert page_one.total == 3
    assert len(page_one.items) == 2
    assert page_two.total == 3
    assert len(page_two.items) == 1
    returned_scope_ids = {item.detection_scope_id for item in page_one.items + page_two.items}
    assert returned_scope_ids == set(scope_ids)
    assert all(item.revision == 2 for item in page_one.items + page_two.items)
