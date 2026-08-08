"""Shadow runtime integration tests for DetectionRuleRuntimeService (ISSUE-121 / #626)."""

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
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ValidationError
from app.db import models as orm
from app.detection.scoring.release import MOCK_ACCOUNT_MAD_RELEASE
from app.detection.sequences.releases import (
    GEO_SENSITIVE_SEQUENCE_V1,
    IDENTITY_EXFIL_SEQUENCE_V1,
    sequence_match_threshold,
)
from app.models.behavior_observation import (
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationProvenance,
    BehaviorObservationSourceRef,
)
from app.models.detection_rule import (
    CandidateDetectionQuery,
    DetectionRuleDefinition,
    MissingDataPolicy,
    RuleOperatorKind,
)
from app.models.detection_scope import DetectionScopeIdentity, UpstreamConnectorMember
from app.models.feature_snapshot import (
    FEATURE_CONTRACT_VERSION,
    DetectionBaselineStatus,
    FeatureSnapshotStatus,
    FeatureWindowKind,
)
from app.services.detection_baseline_service import DetectionBaselineService
from app.services.detection_rule_runtime import DetectionRuleRuntimeService
from app.services.detection_rule_service import DetectionRuleService
from app.services.detection_scope_service import DetectionScopeService
from app.services.feature_snapshot_service import FeatureSnapshotService

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
            await session.execute(delete(orm.DetectionRuleRuntimeError))
            await session.execute(delete(orm.CandidateDetection))
            await session.execute(delete(orm.DetectionRulePackage))
            await session.execute(delete(orm.DetectionFeatureBaseline))
            await session.execute(delete(orm.FeatureSnapshot))
            await session.execute(delete(orm.BehaviorObservation))
            await session.execute(delete(orm.DetectionScopeRevision))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.DetectionRuleRuntimeError))
            await session.execute(delete(orm.CandidateDetection))
            await session.execute(delete(orm.DetectionRulePackage))
            await session.execute(delete(orm.DetectionFeatureBaseline))
            await session.execute(delete(orm.FeatureSnapshot))
            await session.execute(delete(orm.BehaviorObservation))
            await session.execute(delete(orm.DetectionScopeRevision))


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


async def _insert_observation(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
    scope_id: str,
    observed_at: datetime,
    action: str = "create_process",
    category: str = "process_create",
    entity_type: str = "ip",
    entity_id: str = "10.0.0.10",
) -> BehaviorObservation:
    observation = BehaviorObservation(
        observation_id=f"obs-{suffix}",
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        source_ref=BehaviorObservationSourceRef(
            source_product="mock_xdr",
            connector_id=f"conn-{suffix[:6]}",
            source_kind="log",
            source_object_id=f"log-{suffix}",
            source_object_type="edr",
            source_revision=1,
        ),
        observed_at=observed_at,
        ingested_at=observed_at,
        entity_refs=[BehaviorEntityRef(entity_type=entity_type, entity_id=entity_id, role="src")],
        action=action,
        category=category,
        detection_score=55.0,
        content_hash="c" * 64,
        observation_hash="d" * 64,
        idempotency_key=f"idem-{suffix}",
        provenance=BehaviorObservationProvenance(source_record_id=f"src-{suffix}"),
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.BehaviorObservation(
                    observation_id=observation.observation_id,
                    source_tenant_id=observation.source_tenant_id,
                    detection_scope_id=observation.detection_scope_id,
                    source_product=observation.source_ref.source_product,
                    connector_id=observation.source_ref.connector_id,
                    source_kind=observation.source_ref.source_kind,
                    source_object_id=observation.source_ref.source_object_id,
                    source_object_type=observation.source_ref.source_object_type,
                    source_revision=observation.source_ref.source_revision,
                    source_ref=observation.source_ref.model_dump(mode="json"),
                    observed_at=observation.observed_at,
                    ingested_at=observation.ingested_at,
                    entity_refs=[item.model_dump(mode="json") for item in observation.entity_refs],
                    action=observation.action,
                    category=observation.category,
                    normalized_attributes=observation.normalized_attributes,
                    detection_score=observation.detection_score,
                    schema_version=observation.schema_version,
                    projection_schema_version=observation.projection_schema_version,
                    content_hash=observation.content_hash,
                    observation_hash=observation.observation_hash,
                    idempotency_key=observation.idempotency_key,
                    provenance=observation.provenance.model_dump(mode="json"),
                )
            )
    return observation


async def _register_shadow_package(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: str,
    scope_id: str,
    rule: DetectionRuleDefinition,
) -> str:
    service = DetectionRuleService(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[rule],
        author="tester",
    )
    await service.validate_package(source_tenant_id=tenant_id, package_id=package.package_id)
    activated = await service.activate_shadow(
        source_tenant_id=tenant_id, package_id=package.package_id
    )
    return activated.package_id


@pytest.mark.asyncio
async def test_shadow_execute_event_match_produces_candidate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-0",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=30),
    )
    rule = DetectionRuleDefinition(
        rule_id="rule-match",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.rules_evaluated == 1
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.shadow_only is True
    assert candidate.package_id == package_id
    assert candidate.group_key == {"entity_type": "ip", "entity_id": "10.0.0.10"}


@pytest.mark.asyncio
async def test_shadow_execute_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-0",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=30),
    )
    rule = DetectionRuleDefinition(
        rule_id="rule-match",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    first = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    second = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert first.candidates[0].candidate_detection_id == second.candidates[0].candidate_detection_id


@pytest.mark.asyncio
async def test_shadow_execute_tenant_isolation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    scope_a = await _seed_scope(session_factory, suffix=f"a-{suffix}", tenant_id=tenant_a)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-0",
        tenant_id=tenant_a,
        scope_id=scope_a,
        observed_at=cutoff - timedelta(minutes=30),
    )
    rule = DetectionRuleDefinition(
        rule_id="rule-match",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_a,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_a,
        scope_id=scope_a,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    with pytest.raises(ValidationError, match="not found for tenant"):
        await runtime.execute_shadow(
            source_tenant_id=tenant_b,
            cutoff_at=cutoff,
            package_id=package_id,
        )


@pytest.mark.asyncio
async def test_shadow_execute_records_runtime_error_on_cost_limit(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index in range(5):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=60 - index * 5),
        )
    rule = DetectionRuleDefinition(
        rule_id="rule-count",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_COUNT,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={},
        max_observation_scan=3,
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.candidates == []
    assert len(result.errors) == 1
    assert result.errors[0].error_category == "validation_error"

    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.DetectionRuleRuntimeError).where(
                    orm.DetectionRuleRuntimeError.package_id == package_id
                )
            )
        )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_value_count_operator_uses_ready_snapshot(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    snapshot_service = FeatureSnapshotService(session_factory)
    snapshot = await snapshot_service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert snapshot.status is FeatureSnapshotStatus.READY

    rule = DetectionRuleDefinition(
        rule_id="rule-value",
        rule_version=1,
        operator=RuleOperatorKind.VALUE_COUNT,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=3.0,
        severity="high",
        match_criteria={"entity_type": "ip", "entity_id": "10.0.0.10"},
        value_field="observation_count",
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(result.candidates) == 1
    assert result.candidates[0].matched_value == 3.0
    assert result.candidates[0].operator is RuleOperatorKind.VALUE_COUNT


@pytest.mark.asyncio
async def test_query_candidates_tenant_scoped(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-0",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=30),
    )
    rule = DetectionRuleDefinition(
        rule_id="rule-match",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    result = await runtime.query_candidates(
        CandidateDetectionQuery(source_tenant_id=tenant_id, detection_scope_id=scope_id)
    )
    assert result.total == 1
    assert result.items[0].shadow_only is True

    other_tenant_result = await runtime.query_candidates(
        CandidateDetectionQuery(source_tenant_id=f"other-{suffix}")
    )
    assert other_tenant_result.total == 0


@pytest.mark.asyncio
async def test_draft_package_rejected_when_package_id_explicit(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    rule = DetectionRuleDefinition(
        rule_id="rule-match",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    service = DetectionRuleService(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[rule],
        author="tester",
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    with pytest.raises(ValidationError, match="not shadow_active"):
        await runtime.execute_shadow(
            source_tenant_id=tenant_id,
            cutoff_at=cutoff,
            package_id=package.package_id,
        )


@pytest.mark.asyncio
async def test_shadow_execute_updates_candidate_on_late_data(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-0",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=40),
    )
    rule = DetectionRuleDefinition(
        rule_id="rule-count",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_COUNT,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={},
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    first = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(first.candidates) == 1
    assert first.candidates[0].matched_value == 1.0
    assert len(first.errors) == 0

    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-1",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=35),
    )
    second = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(second.errors) == 0
    assert len(second.candidates) == 1
    assert second.candidates[0].candidate_detection_id == first.candidates[0].candidate_detection_id
    assert second.candidates[0].matched_value == 2.0
    assert len(second.candidates[0].provenance.observation_ids) == 2


@pytest.mark.asyncio
async def test_shadow_execute_stable_with_out_of_order_observations(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((45, 30, 60)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    rule = DetectionRuleDefinition(
        rule_id="rule-count",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_COUNT,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=3.0,
        severity="medium",
        match_criteria={},
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(result.candidates) == 1
    assert result.candidates[0].matched_value == 3.0


@pytest.mark.asyncio
async def test_shadow_execute_value_count_cold_start_no_candidate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    rule = DetectionRuleDefinition(
        rule_id="rule-value",
        rule_version=1,
        operator=RuleOperatorKind.VALUE_COUNT,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="high",
        match_criteria={"entity_type": "ip", "entity_id": "10.0.0.10"},
        value_field="observation_count",
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.candidates == []
    assert result.errors == []


@pytest.mark.asyncio
async def test_value_count_invalid_feature_produces_typed_error(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    snapshot_service = FeatureSnapshotService(session_factory)
    snapshot = await snapshot_service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert snapshot.status is FeatureSnapshotStatus.READY

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.FeatureSnapshot, snapshot.snapshot_id)
            assert row is not None
            row.features = {"observation_count": "not-a-number"}
            await session.flush()

    rule = DetectionRuleDefinition(
        rule_id="rule-value",
        rule_version=1,
        operator=RuleOperatorKind.VALUE_COUNT,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="high",
        missing_data_policy=MissingDataPolicy.FAIL,
        match_criteria={"entity_type": "ip", "entity_id": "10.0.0.10"},
        value_field="observation_count",
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.candidates == []
    assert len(result.errors) == 1
    assert result.errors[0].error_category == "validation_error"
    assert "non-numeric" in result.errors[0].error_message


@pytest.mark.asyncio
async def test_runtime_error_idempotent_on_repeated_failure(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index in range(5):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=60 - index * 5),
        )
    rule = DetectionRuleDefinition(
        rule_id="rule-count",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_COUNT,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={},
        max_observation_scan=3,
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    first = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    second = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(first.errors) == 1
    assert len(second.errors) == 1
    assert first.errors[0].error_id == second.errors[0].error_id

    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.DetectionRuleRuntimeError).where(
                    orm.DetectionRuleRuntimeError.package_id == package_id
                )
            )
        )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_value_count_uses_latest_snapshot_revision_after_late_recompute(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    for index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=minutes),
        )
    snapshot_service = FeatureSnapshotService(session_factory)
    first_snapshot = await snapshot_service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert first_snapshot.status is FeatureSnapshotStatus.READY
    assert first_snapshot.features["observation_count"] == 3

    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-late",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=35),
    )
    latest_snapshot = await snapshot_service.materialize_or_recompute(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="ip",
        entity_id="10.0.0.10",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert latest_snapshot.revision > first_snapshot.revision
    assert latest_snapshot.features["observation_count"] == 4

    rule = DetectionRuleDefinition(
        rule_id="rule-value",
        rule_version=1,
        operator=RuleOperatorKind.VALUE_COUNT,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=3.0,
        severity="high",
        match_criteria={"entity_type": "ip", "entity_id": "10.0.0.10"},
        value_field="observation_count",
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.matched_value == 4.0
    assert candidate.provenance.snapshot_ids == [latest_snapshot.snapshot_id]


@pytest.mark.asyncio
async def test_execute_shadow_all_active_packages_without_package_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-0",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=30),
    )
    rule_a = DetectionRuleDefinition(
        rule_id="rule-a",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    rule_b = DetectionRuleDefinition(
        rule_id="rule-b",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="high",
        match_criteria={"action": "create_process"},
    )
    service = DetectionRuleService(session_factory)
    for index, rule in enumerate((rule_a, rule_b), start=1):
        package = await service.register_package(
            source_tenant_id=tenant_id,
            package_version=index,
            rules=[rule],
            author="tester",
        )
        await service.validate_package(source_tenant_id=tenant_id, package_id=package.package_id)
        await service.activate_shadow(source_tenant_id=tenant_id, package_id=package.package_id)

    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
    )
    assert result.rules_evaluated == 2
    assert len(result.candidates) == 2


@pytest.mark.asyncio
async def test_shadow_execute_includes_observation_in_lateness_band(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    # cutoff within lateness band after 1h window_end (15:00 -> upper 15:10)
    cutoff = datetime(2026, 8, 1, 15, 10, 0, tzinfo=UTC)
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-late",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=datetime(2026, 8, 1, 15, 5, 0, tzinfo=UTC),
    )
    rule = DetectionRuleDefinition(
        rule_id="rule-match",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(result.candidates) == 1
    assert result.candidates[0].provenance.window_end is not None


@pytest.mark.asyncio
async def test_shadow_execute_isolates_unexpected_operator_failure(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    rule_ok = DetectionRuleDefinition(
        rule_id="rule-ok",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="medium",
        match_criteria={"action": "create_process"},
    )
    rule_bad = rule_ok.model_copy(update={"rule_id": "rule-bad"})
    service = DetectionRuleService(session_factory)
    package = await service.register_package(
        source_tenant_id=tenant_id,
        package_version=1,
        rules=[rule_ok, rule_bad],
        author="tester",
    )
    await service.validate_package(source_tenant_id=tenant_id, package_id=package.package_id)
    await service.activate_shadow(source_tenant_id=tenant_id, package_id=package.package_id)

    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-0",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=40),
    )

    from app.detection.operators.event_match import EventMatchOperator

    original_evaluate = EventMatchOperator.evaluate

    def _flaky_evaluate(
        self: EventMatchOperator,
        rule: DetectionRuleDefinition,
        context: object,
    ) -> list[object]:
        if rule.rule_id == "rule-bad":
            raise RuntimeError("simulated operator failure")
        return original_evaluate(self, rule, context)

    monkeypatch.setattr(EventMatchOperator, "evaluate", _flaky_evaluate)

    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package.package_id,
    )
    assert result.rules_evaluated == 2
    assert len(result.errors) == 1
    assert result.errors[0].error_category == "internal_error"
    assert len(result.candidates) == 1


@pytest.mark.asyncio
async def test_statistical_anomaly_operator_produces_shadow_candidate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    day_one = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    day_two = datetime(2026, 8, 2, 15, 30, 0, tzinfo=UTC)
    day_three = datetime(2026, 8, 3, 15, 30, 0, tzinfo=UTC)
    snapshot_service = FeatureSnapshotService(session_factory)
    baseline_service = DetectionBaselineService(session_factory)

    for day_index, day_cutoff in enumerate((day_one, day_two), start=1):
        minutes_before = (60, 45, 30) if day_index == 1 else (60, 50, 40, 30)
        for obs_index, minutes in enumerate(minutes_before):
            await _insert_observation(
                session_factory,
                suffix=f"{suffix}-d{day_index}-{obs_index}",
                tenant_id=tenant_id,
                scope_id=scope_id,
                observed_at=day_cutoff - timedelta(minutes=minutes),
                entity_type=entity_type,
                entity_id=entity_id,
                action=f"action-{obs_index % 2}",
            )
        await snapshot_service.materialize(
            source_tenant_id=tenant_id,
            detection_scope_id=scope_id,
            entity_type=entity_type,
            entity_id=entity_id,
            window_kind=FeatureWindowKind.ONE_HOUR,
            cutoff_at=day_cutoff,
        )

    baseline = await baseline_service.materialize_baseline(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type=entity_type,
        entity_id=entity_id,
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=day_three,
    )
    assert baseline.status is DetectionBaselineStatus.READY
    assert "robust" in baseline.stats

    # Observations must fall within window_end (15:00 for 15:30 cutoff) and span >=30min.
    for minutes_before in range(60, 29, -3):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-burst-{minutes_before}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=day_three - timedelta(minutes=minutes_before),
            entity_type=entity_type,
            entity_id=entity_id,
            action=f"rare-action-{minutes_before}",
        )
    current_snapshot = await snapshot_service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type=entity_type,
        entity_id=entity_id,
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=day_three,
    )
    assert current_snapshot.status is FeatureSnapshotStatus.READY
    assert int(current_snapshot.features["observation_count"]) >= 10

    rule = DetectionRuleDefinition(
        rule_id="rule-account-mad",
        rule_version=1,
        operator=RuleOperatorKind.STATISTICAL_ANOMALY,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=3.5,
        severity="medium",
        missing_data_policy=MissingDataPolicy.FAIL,
        match_criteria={
            "entity_type": entity_type,
            "entity_id": entity_id,
            "model_release_id": MOCK_ACCOUNT_MAD_RELEASE.release_id,
            "model_release_hash": MOCK_ACCOUNT_MAD_RELEASE.release_hash,
        },
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=day_three,
        package_id=package_id,
    )
    assert result.errors == []
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.operator is RuleOperatorKind.STATISTICAL_ANOMALY
    assert candidate.shadow_only is True
    assert candidate.provenance.detection_score is not None
    assert candidate.provenance.detection_score == candidate.matched_value
    assert candidate.provenance.model_release_id == MOCK_ACCOUNT_MAD_RELEASE.release_id
    assert candidate.provenance.contributing_features
    assert candidate.provenance.baseline_content_hash == baseline.content_hash
    assert candidate.provenance.source_watermark is not None

    second = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=day_three,
        package_id=package_id,
    )
    assert second.candidates[0].candidate_detection_id == candidate.candidate_detection_id


@pytest.mark.asyncio
async def test_statistical_anomaly_tenant_isolation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    scope_a = await _seed_scope(session_factory, suffix=f"a-{suffix}", tenant_id=tenant_a)
    cutoff = datetime(2026, 8, 3, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"

    for obs_index, minutes in enumerate((60, 45, 30)):
        await _insert_observation(
            session_factory,
            suffix=f"{suffix}-hist-{obs_index}",
            tenant_id=tenant_a,
            scope_id=scope_a,
            observed_at=cutoff - timedelta(minutes=minutes),
            entity_type=entity_type,
            entity_id=entity_id,
        )

    snapshot_service = FeatureSnapshotService(session_factory)
    baseline_service = DetectionBaselineService(session_factory)
    await snapshot_service.materialize(
        source_tenant_id=tenant_a,
        detection_scope_id=scope_a,
        entity_type=entity_type,
        entity_id=entity_id,
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    await baseline_service.materialize_baseline(
        source_tenant_id=tenant_a,
        detection_scope_id=scope_a,
        entity_type=entity_type,
        entity_id=entity_id,
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )

    rule = DetectionRuleDefinition(
        rule_id="rule-mad-iso",
        rule_version=1,
        operator=RuleOperatorKind.STATISTICAL_ANOMALY,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_a,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=3.5,
        severity="medium",
        missing_data_policy=MissingDataPolicy.SKIP,
        match_criteria={
            "entity_type": entity_type,
            "entity_id": entity_id,
            "model_release_id": MOCK_ACCOUNT_MAD_RELEASE.release_id,
        },
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_a,
        scope_id=scope_a,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    with pytest.raises(ValidationError, match="not found for tenant"):
        await runtime.execute_shadow(
            source_tenant_id=tenant_b,
            cutoff_at=cutoff,
            package_id=package_id,
        )


@pytest.mark.asyncio
async def test_statistical_anomaly_insufficient_history_records_typed_runtime_error(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    snapshot_service = FeatureSnapshotService(session_factory)
    baseline_service = DetectionBaselineService(session_factory)
    await _insert_observation(
        session_factory,
        suffix=f"{suffix}-solo",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=30),
        entity_type="user",
        entity_id="account-cold",
    )
    await snapshot_service.materialize(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="user",
        entity_id="account-cold",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    baseline = await baseline_service.materialize_baseline(
        source_tenant_id=tenant_id,
        detection_scope_id=scope_id,
        entity_type="user",
        entity_id="account-cold",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
    )
    assert baseline.status is DetectionBaselineStatus.INSUFFICIENT_HISTORY

    rule = DetectionRuleDefinition(
        rule_id="rule-cold",
        rule_version=1,
        operator=RuleOperatorKind.STATISTICAL_ANOMALY,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=3.5,
        severity="medium",
        missing_data_policy=MissingDataPolicy.SKIP,
        match_criteria={
            "entity_type": "user",
            "entity_id": "account-cold",
            "model_release_id": MOCK_ACCOUNT_MAD_RELEASE.release_id,
        },
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.candidates == []
    assert len(result.errors) == 1
    assert result.errors[0].error_category == "validation_error"
    assert result.errors[0].detail.get("category") == "insufficient_history"


async def _insert_sequence_observation(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
    scope_id: str,
    observed_at: datetime,
    action: str,
    category: str,
    entity_type: str = "user",
    entity_id: str = "account-1",
) -> None:
    await _insert_observation(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=observed_at,
        action=action,
        category=category,
        entity_type=entity_type,
        entity_id=entity_id,
    )


@pytest.mark.asyncio
async def test_event_sequence_identity_exfil_produces_shadow_candidate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    steps = IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps
    for index, step in enumerate(steps):
        await _insert_sequence_observation(
            session_factory,
            suffix=f"{suffix}-step-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=55 - index * 5),
            action=step["action"],
            category=step["category"],
            entity_type=entity_type,
            entity_id=entity_id,
        )

    rule = DetectionRuleDefinition(
        rule_id="rule-identity-exfil",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.errors == []
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.operator is RuleOperatorKind.EVENT_SEQUENCE
    assert candidate.shadow_only is True
    assert candidate.provenance.sequence_id == IDENTITY_EXFIL_SEQUENCE_V1.sequence_id
    assert candidate.provenance.sequence_hash == IDENTITY_EXFIL_SEQUENCE_V1.sequence_hash
    assert len(candidate.provenance.ordered_observation_ids) == 4
    assert candidate.provenance.observation_ids == candidate.provenance.ordered_observation_ids
    assert candidate.provenance.sequence_step_matches
    assert "login" in (candidate.provenance.match_explanation or "")

    second = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert second.candidates[0].candidate_detection_id == candidate.candidate_detection_id
    assert second.candidates[0].content_hash == candidate.content_hash


@pytest.mark.asyncio
async def test_event_sequence_benign_partial_sequence_no_candidate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    for index, step in enumerate(IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps[:3]):
        await _insert_sequence_observation(
            session_factory,
            suffix=f"{suffix}-partial-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=50 - index * 10),
            action=step["action"],
            category=step["category"],
            entity_type=entity_type,
            entity_id=entity_id,
        )

    rule = DetectionRuleDefinition(
        rule_id="rule-partial",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.candidates == []
    assert result.errors == []


@pytest.mark.asyncio
async def test_event_sequence_out_of_order_observations_still_matches(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    steps = list(IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps)
    insert_order = [3, 0, 2, 1]
    for position, step_index in enumerate(insert_order):
        step = steps[step_index]
        await _insert_sequence_observation(
            session_factory,
            suffix=f"{suffix}-oo-{position}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=55 - step_index * 5),
            action=step["action"],
            category=step["category"],
            entity_type=entity_type,
            entity_id=entity_id,
        )

    rule = DetectionRuleDefinition(
        rule_id="rule-oo",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(result.candidates) == 1
    assert len(result.candidates[0].provenance.ordered_observation_ids) == 4


@pytest.mark.asyncio
async def test_event_sequence_tenant_isolation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    scope_a = await _seed_scope(session_factory, suffix=f"a-{suffix}", tenant_id=tenant_a)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    rule = DetectionRuleDefinition(
        rule_id="rule-seq-iso",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_a,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_a,
        scope_id=scope_a,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    with pytest.raises(ValidationError, match="not found for tenant"):
        await runtime.execute_shadow(
            source_tenant_id=tenant_b,
            cutoff_at=cutoff,
            package_id=package_id,
        )


@pytest.mark.asyncio
async def test_geo_sensitive_sequence_produces_shadow_candidate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    for index, step in enumerate(GEO_SENSITIVE_SEQUENCE_V1.sequence_steps):
        await _insert_sequence_observation(
            session_factory,
            suffix=f"{suffix}-geo-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=40 - index * 5),
            action=step["action"],
            category=step["category"],
            entity_type=entity_type,
            entity_id=entity_id,
        )

    rule = DetectionRuleDefinition(
        rule_id="rule-geo-sensitive",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(GEO_SENSITIVE_SEQUENCE_V1),
        severity="medium",
        match_criteria=GEO_SENSITIVE_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert len(result.candidates) == 1
    assert result.candidates[0].provenance.sequence_id == GEO_SENSITIVE_SEQUENCE_V1.sequence_id
    assert len(result.candidates[0].provenance.ordered_observation_ids) == 2


@pytest.mark.asyncio
async def test_event_sequence_late_step_completes_sequence(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    steps = IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps
    for index, step in enumerate(steps[:3]):
        await _insert_sequence_observation(
            session_factory,
            suffix=f"{suffix}-late-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=55 - index * 5),
            action=step["action"],
            category=step["category"],
            entity_type=entity_type,
            entity_id=entity_id,
        )

    rule = DetectionRuleDefinition(
        rule_id="rule-late-seq",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    first = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert first.candidates == []
    assert first.errors == []

    final_step = steps[3]
    await _insert_sequence_observation(
        session_factory,
        suffix=f"{suffix}-late-final",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=40),
        action=final_step["action"],
        category=final_step["category"],
        entity_type=entity_type,
        entity_id=entity_id,
    )
    second = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert second.errors == []
    assert len(second.candidates) == 1
    assert len(second.candidates[0].provenance.ordered_observation_ids) == 4


@pytest.mark.asyncio
async def test_event_sequence_duplicate_step_action_at_runtime(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    steps = GEO_SENSITIVE_SEQUENCE_V1.sequence_steps
    await _insert_sequence_observation(
        session_factory,
        suffix=f"{suffix}-dup-a",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=40),
        action=steps[0]["action"],
        category=steps[0]["category"],
        entity_type=entity_type,
        entity_id=entity_id,
    )
    await _insert_sequence_observation(
        session_factory,
        suffix=f"{suffix}-dup-b",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=35),
        action=steps[0]["action"],
        category=steps[0]["category"],
        entity_type=entity_type,
        entity_id=entity_id,
    )
    await _insert_sequence_observation(
        session_factory,
        suffix=f"{suffix}-dup-c",
        tenant_id=tenant_id,
        scope_id=scope_id,
        observed_at=cutoff - timedelta(minutes=30),
        action=steps[1]["action"],
        category=steps[1]["category"],
        entity_type=entity_type,
        entity_id=entity_id,
    )

    rule = DetectionRuleDefinition(
        rule_id="rule-dup-seq",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(GEO_SENSITIVE_SEQUENCE_V1),
        severity="medium",
        match_criteria=GEO_SENSITIVE_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.errors == []
    assert len(result.candidates) == 1
    assert len(result.candidates[0].provenance.ordered_observation_ids) == 2


@pytest.mark.asyncio
async def test_event_sequence_scope_isolation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_a = await _seed_scope(session_factory, suffix=f"a-{suffix}", tenant_id=tenant_id)
    scope_b = await _seed_scope(session_factory, suffix=f"b-{suffix}", tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    for index, step in enumerate(IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps):
        await _insert_sequence_observation(
            session_factory,
            suffix=f"{suffix}-scope-b-{index}",
            tenant_id=tenant_id,
            scope_id=scope_b,
            observed_at=cutoff - timedelta(minutes=55 - index * 5),
            action=step["action"],
            category=step["category"],
            entity_type=entity_type,
            entity_id=entity_id,
        )

    rule = DetectionRuleDefinition(
        rule_id="rule-scope-iso",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_a,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_a,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.candidates == []
    assert result.errors == []


@pytest.mark.asyncio
async def test_event_sequence_cold_start_no_candidate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    rule = DetectionRuleDefinition(
        rule_id="rule-cold-seq",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria(),
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.candidates == []
    assert result.errors == []


@pytest.mark.asyncio
async def test_event_sequence_max_observation_scan_raises(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    scope_id = await _seed_scope(session_factory, suffix=suffix, tenant_id=tenant_id)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    entity_type = "user"
    entity_id = f"account-{suffix}"
    for index, step in enumerate(IDENTITY_EXFIL_SEQUENCE_V1.sequence_steps):
        await _insert_sequence_observation(
            session_factory,
            suffix=f"{suffix}-scan-{index}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=55 - index * 5),
            action=step["action"],
            category=step["category"],
            entity_type=entity_type,
            entity_id=entity_id,
        )
    for filler in range(3):
        await _insert_sequence_observation(
            session_factory,
            suffix=f"{suffix}-filler-{filler}",
            tenant_id=tenant_id,
            scope_id=scope_id,
            observed_at=cutoff - timedelta(minutes=10 - filler),
            action="noise",
            category="process_create",
            entity_type=entity_type,
            entity_id=entity_id,
        )

    rule = DetectionRuleDefinition(
        rule_id="rule-scan-seq",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_SEQUENCE,
        feature_contract_version=FEATURE_CONTRACT_VERSION,
        detection_scope_id=scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=sequence_match_threshold(IDENTITY_EXFIL_SEQUENCE_V1),
        severity="high",
        match_criteria=IDENTITY_EXFIL_SEQUENCE_V1.as_match_criteria(),
        max_observation_scan=3,
    )
    package_id = await _register_shadow_package(
        session_factory,
        tenant_id=tenant_id,
        scope_id=scope_id,
        rule=rule,
    )
    runtime = DetectionRuleRuntimeService(session_factory)
    result = await runtime.execute_shadow(
        source_tenant_id=tenant_id,
        cutoff_at=cutoff,
        package_id=package_id,
    )
    assert result.candidates == []
    assert len(result.errors) == 1
    assert result.errors[0].error_category == "validation_error"
