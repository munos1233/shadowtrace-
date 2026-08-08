"""Unit and integration tests for BehaviorObservation resolver (ISSUE-119 / #624)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.detection_scope import (
    DetectionScopeIdentity,
    DetectionScopeLifecycleState,
    UpstreamConnectorMember,
)
from app.models.enums import SourceObjectKind
from app.services.behavior_observation_resolver import (
    build_behavior_observation,
    build_observation_id,
    build_observation_idempotency_key,
    compute_observation_content_hash,
    resolve_detection_scope_id,
)
from app.services.detection_scope_service import DetectionScopeService
from tests.test_services.behavior_observation_fixtures import (
    build_ambiguous_active_scope_rows,
    patch_session_scalars_with_ambiguous_scopes,
    seed_behavior_observation_connector as seed_connector,
)
from tests.test_services.behavior_observation_fixtures import (
    truncate_behavior_observation_tables,
)

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


@pytest_asyncio.fixture
async def clean_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    await truncate_behavior_observation_tables(session_factory)
    yield
    await truncate_behavior_observation_tables(session_factory)


def _scope_service(session_factory: async_sessionmaker[AsyncSession]) -> DetectionScopeService:
    return DetectionScopeService(session_factory)


def _source_row(**overrides: object) -> orm.SourceObject:
    base = {
        "source_record_id": "src-test123456",
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-a",
        "connector_id": "conn-log",
        "source_kind": SourceObjectKind.LOG.value,
        "source_object_id": "log-001",
        "source_object_type": "edr",
        "source_status_raw": "indexed",
        "source_disposition": "unknown",
        "schema_version": "1",
        "ingested_at": datetime(2026, 8, 1, tzinfo=UTC),
        "raw_payload_hash": "abc123",
        "normalized": {
            "channel": "endpoint",
            "category": "process_create",
            "action": "create_process",
            "src_ip": "10.0.0.5",
            "detection_score": 72,
            "risk_score": 99,
            "logged_at": "2026-08-01T00:00:00+00:00",
        },
        "raw_payload": {"secret": "must-not-copy"},
        "current_source_status_raw": "indexed",
        "current_source_disposition": "unknown",
        "current_state_version": 1,
        "source_updated_at": datetime(2026, 8, 1, tzinfo=UTC),
    }
    base.update(overrides)
    return orm.SourceObject(**base)


def test_observation_id_is_deterministic() -> None:
    key = build_observation_idempotency_key(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-abc",
        source_kind="log",
        source_object_id="log-001",
        source_revision=1,
    )
    first = build_observation_id(idempotency_key=key)
    second = build_observation_id(idempotency_key=key)
    assert first == second
    assert first.startswith("bobs-")


def test_build_behavior_observation_ignores_risk_score() -> None:
    observation = build_behavior_observation(
        row=_source_row(),
        detection_scope_id="dscope-test",
    )
    assert observation.detection_score == 72.0
    assert observation.provenance.scope_binding_unverified is False
    assert "risk_score" not in observation.normalized_attributes
    assert "secret" not in observation.normalized_attributes
    assert any(ref.entity_id == "10.0.0.5" for ref in observation.entity_refs)
    assert observation.provenance.source_record_id == "src-test123456"
    assert observation.provenance.raw_payload_hash == "abc123"


def test_content_hash_stable_for_same_inputs() -> None:
    first = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    second = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    assert first.content_hash == second.content_hash
    assert first.observation_id == second.observation_id


def test_content_hash_changes_with_source_revision() -> None:
    first = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    second = build_behavior_observation(
        row=_source_row(current_state_version=2),
        detection_scope_id="dscope-test",
    )
    assert first.content_hash != second.content_hash
    assert first.observation_id != second.observation_id


def test_build_behavior_observation_marks_unverified_scope_binding() -> None:
    observation = build_behavior_observation(
        row=_source_row(),
        detection_scope_id="dscope-fallback",
        scope_binding_unverified=True,
    )
    assert observation.provenance.scope_binding_unverified is True
    assert observation.detection_scope_id == "dscope-fallback"


def test_content_hash_sensitive_to_scope_binding_unverified() -> None:
    verified = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    unverified = build_behavior_observation(
        row=_source_row(),
        detection_scope_id="dscope-test",
        scope_binding_unverified=True,
    )
    assert verified.content_hash != unverified.content_hash


def test_connector_kind_rejected() -> None:
    with pytest.raises(ValidationError, match="connector source objects"):
        build_behavior_observation(
            row=_source_row(source_kind=SourceObjectKind.CONNECTOR.value),
            detection_scope_id="dscope-test",
        )


def test_compute_observation_content_hash_ignores_runtime_metadata() -> None:
    observation = build_behavior_observation(row=_source_row(), detection_scope_id="dscope-test")
    payload = {
        "observation_id": observation.observation_id,
        "source_tenant_id": observation.source_tenant_id,
        "detection_scope_id": observation.detection_scope_id,
        "source_ref": observation.source_ref.model_dump(mode="json"),
        "observed_at": observation.observed_at.isoformat(),
        "ingested_at": observation.ingested_at.isoformat(),
        "entity_refs": [item.model_dump(mode="json") for item in observation.entity_refs],
        "action": observation.action,
        "category": observation.category,
        "normalized_attributes": observation.normalized_attributes,
        "detection_score": observation.detection_score,
        "schema_version": observation.schema_version,
        "projection_schema_version": observation.projection_schema_version,
        "provenance": observation.provenance.model_dump(mode="json"),
        "supersedes_observation_id": observation.supersedes_observation_id,
        "created_at": "2026-08-01T01:00:00+00:00",
        "observation_hash": "different",
    }
    assert compute_observation_content_hash(payload) == observation.content_hash


@pytest.mark.asyncio
async def test_resolve_scope_unbound_connector_uses_metadata_fallback(
    session_factory: async_sessionmaker[AsyncSession],
    clean_tables: None,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scoped_connector = f"conn-scoped-{suffix}"
    missing_connector = f"conn-missing-{suffix}"
    instance_id = f"inst-{suffix}"
    await seed_connector(
        session_factory,
        connector_id=scoped_connector,
        tenant_id=tenant_id,
        integration_instance_id=instance_id,
    )
    await seed_connector(
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
    activated = await scope_service.activate_revision(revision.scope_revision_id)

    async with session_factory() as session:
        binding = await resolve_detection_scope_id(
            session,
            source_tenant_id=tenant_id,
            source_product="mock_xdr",
            connector_id=missing_connector,
        )

    assert binding.scope_binding_unverified is True
    assert binding.detection_scope_id.startswith("dscope-")
    assert binding.detection_scope_id == activated.detection_scope_id
    assert binding.detection_scope_id in binding.active_scope_ids
    assert binding.integration_instance_id == instance_id


@pytest.mark.asyncio
async def test_resolve_scope_verified_connector_in_active_set(
    session_factory: async_sessionmaker[AsyncSession],
    clean_tables: None,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-verified-{suffix}"
    instance_id = f"inst-{suffix}"
    await seed_connector(
        session_factory,
        connector_id=connector_id,
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
            UpstreamConnectorMember(connector_id=connector_id, source_product="mock_xdr"),
        ],
    )
    activated = await scope_service.activate_revision(revision.scope_revision_id)

    async with session_factory() as session:
        binding = await resolve_detection_scope_id(
            session,
            source_tenant_id=tenant_id,
            source_product="mock_xdr",
            connector_id=connector_id,
        )

    assert binding.scope_binding_unverified is False
    assert binding.detection_scope_id == activated.detection_scope_id


@pytest.mark.asyncio
async def test_resolve_scope_ambiguous_binding_raises(
    session_factory: async_sessionmaker[AsyncSession],
    clean_tables: None,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-ambiguous-{suffix}"
    instance_id = f"inst-{suffix}"
    await seed_connector(
        session_factory,
        connector_id=connector_id,
        tenant_id=tenant_id,
        integration_instance_id=instance_id,
    )
    ambiguous_rows = build_ambiguous_active_scope_rows(
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
        instance_id=instance_id,
    )

    async with session_factory() as session:
        patch_session_scalars_with_ambiguous_scopes(session, ambiguous_rows)
        with pytest.raises(ValidationError, match="ambiguous detection scope binding"):
            await resolve_detection_scope_id(
                session,
                source_tenant_id=tenant_id,
                source_product="mock_xdr",
                connector_id=connector_id,
            )
