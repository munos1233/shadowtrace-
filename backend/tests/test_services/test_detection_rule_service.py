"""Persistence and lifecycle tests for DetectionRuleService (ISSUE-121 / #626)."""

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

from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.models.detection_rule import (
    DetectionRuleDefinition,
    DetectionRulePackageQuery,
    DetectionRuleRuntimeState,
    MissingDataPolicy,
    RuleOperatorKind,
)
from app.models.detection_scope import DetectionScopeIdentity, UpstreamConnectorMember
from app.models.feature_snapshot import FEATURE_CONTRACT_VERSION, FeatureWindowKind
from app.services.detection_rule_service import DetectionRuleService
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


def _rule_service(session_factory: async_sessionmaker[AsyncSession]) -> DetectionRuleService:
    return DetectionRuleService(session_factory)


def _rule_definition(*, scope_id: str) -> DetectionRuleDefinition:
    return DetectionRuleDefinition(
        rule_id="rule-event-match",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        required_fields=["action"],
        missing_data_policy=MissingDataPolicy.SKIP,
        match_criteria={"action": "create_process"},
    )


async def _seed_scope(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
) -> str:
    service = DetectionScopeService(session_factory)
    identity = DetectionScopeIdentity(
        source_tenant_id=tenant_id,
        source_product="mock_xdr",
        integration_instance_id=f"inst-{suffix}",
    )
    revision = await service.register_revision(
        identity=identity,
        connector_set_version=1,
        upstream_connectors=[
            UpstreamConnectorMember(connector_id=f"conn-{suffix}", source_product="mock_xdr"),
        ],
    )
    activated = await service.activate_revision(revision.scope_revision_id)
    return activated.detection_scope_id


@pytest_asyncio.fixture(autouse=True)
async def clean_detection_rule_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.DetectionRuleRuntimeError))
            await session.execute(delete(orm.CandidateDetection))
            await session.execute(delete(orm.DetectionRulePackage))
            await session.execute(delete(orm.DetectionScopeRevision))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.DetectionRuleRuntimeError))
            await session.execute(delete(orm.CandidateDetection))
            await session.execute(delete(orm.DetectionRulePackage))
            await session.execute(delete(orm.DetectionScopeRevision))


@pytest.mark.asyncio
async def test_register_package_starts_in_draft(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = f"dscope-{suffix}"
    service = _rule_service(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
        review_artifact_ref="review-001",
        test_artifact_ref="test-001",
    )
    assert package.runtime_state is DetectionRuleRuntimeState.DRAFT
    assert package.provenance.author == "tester"
    assert package.provenance.review_artifact_ref == "review-001"
    assert len(package.content_hash) == 64


@pytest.mark.asyncio
async def test_register_package_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = f"dscope-{suffix}"
    service = _rule_service(session_factory)
    first = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    second = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    assert first.package_id == second.package_id
    assert first.content_hash == second.content_hash


@pytest.mark.asyncio
async def test_register_package_idempotent_despite_different_compiled_at(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = f"dscope-{suffix}"
    service = _rule_service(session_factory)
    first = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    second = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    assert first.package_id == second.package_id


@pytest.mark.asyncio
async def test_lifecycle_transition_preserves_content_hash(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    service = _rule_service(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    original_hash = package.content_hash
    validated = await service.validate_package(
        source_tenant_id=tenant_id,
        package_id=package.package_id,
    )
    shadow = await service.activate_shadow(
        source_tenant_id=tenant_id,
        package_id=package.package_id,
    )
    assert validated.content_hash == original_hash
    assert shadow.content_hash == original_hash


@pytest.mark.asyncio
async def test_lifecycle_transitions(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    service = _rule_service(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    validated = await service.validate_package(
        source_tenant_id=tenant_id,
        package_id=package.package_id,
    )
    assert validated.runtime_state is DetectionRuleRuntimeState.VALIDATED

    shadow = await service.activate_shadow(
        source_tenant_id=tenant_id,
        package_id=package.package_id,
    )
    assert shadow.runtime_state is DetectionRuleRuntimeState.SHADOW_ACTIVE

    disabled = await service.disable_package(
        source_tenant_id=tenant_id,
        package_id=package.package_id,
    )
    assert disabled.runtime_state is DetectionRuleRuntimeState.DISABLED


@pytest.mark.asyncio
async def test_invalid_lifecycle_transition_rejected(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = f"dscope-{suffix}"
    service = _rule_service(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    with pytest.raises(ValidationError, match="invalid detection rule runtime transition"):
        await service.activate_shadow(
            source_tenant_id=tenant_id,
            package_id=package.package_id,
        )


@pytest.mark.asyncio
async def test_tenant_isolation_for_get_package(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    scope_id = f"dscope-{suffix}"
    service = _rule_service(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_a,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    assert await service.get_package(source_tenant_id=tenant_a, package_id=package.package_id)
    assert (
        await service.get_package(source_tenant_id=tenant_b, package_id=package.package_id) is None
    )


@pytest.mark.asyncio
async def test_query_packages_filters_by_runtime_state(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    service = _rule_service(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=scope_id)],
        author="tester",
    )
    await service.validate_package(source_tenant_id=tenant_id, package_id=package.package_id)
    await service.activate_shadow(source_tenant_id=tenant_id, package_id=package.package_id)

    result = await service.query_packages(
        DetectionRulePackageQuery(
            source_tenant_id=tenant_id,
            runtime_state=DetectionRuleRuntimeState.SHADOW_ACTIVE,
        )
    )
    assert result.total == 1
    assert result.items[0].package_id == package.package_id


@pytest.mark.asyncio
async def test_validate_package_rejects_unknown_scope(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    service = _rule_service(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[_rule_definition(scope_id=f"dscope-missing-{suffix}")],
        author="tester",
    )
    with pytest.raises(ValidationError, match="detection scope not active"):
        await service.validate_package(
            source_tenant_id=tenant_id,
            package_id=package.package_id,
        )


@pytest.mark.asyncio
async def test_get_package_not_found_raises_on_transition(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    service = _rule_service(session_factory)
    with pytest.raises(ResourceNotFoundError):
        await service.validate_package(
            source_tenant_id="missing-tenant",
            package_id="drpkg-missing",
        )
