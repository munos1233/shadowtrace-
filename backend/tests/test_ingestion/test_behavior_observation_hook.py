"""SourceIngester hook tests for BehaviorObservation projection (ISSUE-119 / #624)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.source.base import SourcePage
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.models.behavior_observation import (
    BehaviorObservationProjectionStatus,
    BehaviorObservationQuery,
)
from app.models.detection_scope import (
    DetectionScopeIdentity,
    UpstreamConnectorMember,
)
from app.models.enums import SourceDisposition, SourceObjectKind
from app.models.source import SourceConnector, SourceLog, SourceReference
from app.services.behavior_observation_projection import BehaviorObservationProjection
from app.services.behavior_observation_service import BehaviorObservationService
from app.services.detection_scope_service import DetectionScopeService
from app.services.event_service import EventService
from tests.test_ingestion.test_source_ingester import FakePagedAdapter


@pytest_asyncio.fixture(autouse=True)
async def clean_hook_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
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


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


def _connector(connector_id: str) -> SourceConnector:
    return SourceConnector(
        connector_id=connector_id,
        source_product="mock_xdr",
        display_name=f"Test {connector_id}",
    )


class HookAdapter(FakePagedAdapter):
    def __init__(
        self,
        name: str,
        pages: dict,
        *,
        connectors: list[SourceConnector],
    ) -> None:
        super().__init__(name, pages)
        self._connectors = connectors

    async def list_connectors(self) -> list[SourceConnector]:
        return list(self._connectors)


def _log_item(suffix: str, connector_id: str, tenant_id: str) -> SourceLog:
    return SourceLog(
        reference=SourceReference(
            source_kind=SourceObjectKind.LOG,
            source_product="mock_xdr",
            source_tenant_id=tenant_id,
            connector_id=connector_id,
            source_object_type="edr",
            source_object_id=f"log-{suffix}",
            source_status_raw="indexed",
            source_disposition=SourceDisposition.UNKNOWN,
            source_updated_at=datetime(2026, 8, 1, tzinfo=UTC),
            schema_version="1",
            ingested_at=datetime(2026, 8, 1, tzinfo=UTC),
            raw_payload_hash=f"hash-{suffix}",
        ),
        raw_payload={"cmdline": "keep-in-source-store-only"},
        normalized={
            "channel": "endpoint",
            "category": "process_create",
            "action": "create_process",
            "src_ip": "10.1.1.1",
            "detection_score": 42,
            "logged_at": "2026-08-01T00:00:00+00:00",
        },
        device_source="edr",
        logged_at=datetime(2026, 8, 1, tzinfo=UTC),
        src_ip="10.1.1.1",
        category="process_create",
    )


@pytest.mark.asyncio
async def test_source_ingester_projects_behavior_observation_for_supporting_object(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    suffix = _suffix()
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    connector = _connector(connector_id)
    adapter = HookAdapter(
        "mock_xdr",
        {
            (SourceObjectKind.LOG.value, connector_id, None): SourcePage(
                items=[_log_item(suffix, connector_id, tenant_id)],
                object_kind=SourceObjectKind.LOG,
                connector_id=connector_id,
                next_cursor=None,
                has_more=False,
            ),
        },
        connectors=[connector],
    )
    ingester = SourceIngester(event_service, session_factory)
    summary = await ingester.poll(
        adapter,
        [SourceObjectKind.LOG],
        batch_size=10,
    )
    assert summary.accepted >= 1
    assert summary.degraded is False

    observations = await BehaviorObservationService(session_factory).query_observations(
        BehaviorObservationQuery(source_tenant_id=tenant_id)
    )
    assert observations.total >= 1
    item = observations.items[0]
    assert item.detection_score == 42.0
    assert item.provenance.raw_payload_hash == f"hash-{suffix}"
    assert "cmdline" not in item.normalized_attributes


@pytest.mark.asyncio
async def test_poll_uses_registered_detection_scope_when_available(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    suffix = _suffix()
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    instance_id = f"inst-{suffix}"
    connector = _connector(connector_id)
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
                        "integration_instance_id": instance_id,
                        "connector_set_version": 1,
                    },
                )
            )
    scope_service = DetectionScopeService(session_factory)
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

    adapter = HookAdapter(
        "mock_xdr",
        {
            (SourceObjectKind.LOG.value, connector_id, None): SourcePage(
                items=[_log_item(suffix, connector_id, tenant_id)],
                object_kind=SourceObjectKind.LOG,
                connector_id=connector_id,
                next_cursor=None,
                has_more=False,
            ),
        },
        connectors=[connector],
    )
    ingester = SourceIngester(event_service, session_factory)
    summary = await ingester.poll(
        adapter,
        [SourceObjectKind.LOG],
        batch_size=10,
    )
    assert summary.accepted >= 1
    assert summary.degraded is False

    observations = await BehaviorObservationService(session_factory).query_observations(
        BehaviorObservationQuery(source_tenant_id=tenant_id)
    )
    assert observations.total >= 1
    assert observations.items[0].detection_scope_id == activated.detection_scope_id


@pytest.mark.asyncio
async def test_poll_marks_degraded_when_behavior_projection_fails(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    suffix = _suffix()
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    connector = _connector(connector_id)
    adapter = HookAdapter(
        "mock_xdr",
        {
            (SourceObjectKind.LOG.value, connector_id, None): SourcePage(
                items=[_log_item(suffix, connector_id, tenant_id)],
                object_kind=SourceObjectKind.LOG,
                connector_id=connector_id,
                next_cursor=None,
                has_more=False,
            ),
        },
        connectors=[connector],
    )
    ingester = SourceIngester(event_service, session_factory)
    assert ingester._behavior_observation is not None

    async def _projection_failed(_record_id: str) -> bool:
        return False

    with patch.object(
        ingester._behavior_observation,
        "on_source_record_persisted",
        side_effect=_projection_failed,
    ):
        summary = await ingester.poll(
            adapter,
            [SourceObjectKind.LOG],
            batch_size=10,
        )
    assert summary.accepted >= 1
    assert summary.degraded is True
    assert any(error.get("stage") == "behavior_observation_projection" for error in summary.errors)


@pytest.mark.asyncio
async def test_hook_records_failure_without_rolling_back_source(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"
    record_id = f"src-hook-{suffix}"
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
                        "integration_instance_id": f"inst-{suffix}",
                        "connector_set_version": 1,
                    },
                )
            )
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
                    normalized={"detection_score": 10, "logged_at": "2026-08-01T00:00:00+00:00"},
                    raw_payload={"cmdline": "keep"},
                    current_source_status_raw="indexed",
                    current_source_disposition=SourceDisposition.UNKNOWN.value,
                    current_state_version=1,
                    source_sync_state="synced",
                )
            )

    projection = BehaviorObservationProjection(session_factory)
    with patch.object(
        projection._service,
        "project_source_object",
        side_effect=RuntimeError("hook projection boom"),
    ):
        await projection.on_source_record_persisted(record_id)

    async with session_factory() as session:
        source_row = await session.get(orm.SourceObject, record_id)
        assert source_row is not None
        failure = await session.scalar(
            select(orm.BehaviorObservationProjectionFailure).where(
                orm.BehaviorObservationProjectionFailure.source_record_id == record_id
            )
        )
        quality = await session.scalar(
            select(orm.DataQualityError).where(
                orm.DataQualityError.stage == "behavior_observation_projection"
            )
        )
    assert failure is not None
    assert failure.status == BehaviorObservationProjectionStatus.PENDING_RETRY.value
    assert quality is not None
    observations = await BehaviorObservationService(session_factory).query_observations(
        BehaviorObservationQuery(source_tenant_id=tenant_id)
    )
    assert observations.total == 0


@pytest.mark.asyncio
async def test_ingest_telemetry_reports_behavior_projection_degraded(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    suffix = _suffix()
    ingester = SourceIngester(event_service, session_factory)
    assert ingester._behavior_observation is not None

    async def _projection_failed(_record_id: str) -> bool:
        return False

    with patch.object(
        ingester._behavior_observation,
        "on_source_record_persisted",
        side_effect=_projection_failed,
    ):
        inserted, degraded = await ingester.ingest_telemetry(
            {
                "log": [
                    {
                        "channel": "endpoint",
                        "logged_at": "2026-08-01T00:00:00+00:00",
                        "src_ip": "10.0.0.1",
                        "detection_score": 12,
                    }
                ],
            },
            source_type="mock_xdr",
            connector_id=f"conn-telemetry-{suffix}",
            source_tenant_id=f"tenant-telemetry-{suffix}",
        )
    assert inserted >= 1
    assert degraded is True


@pytest.mark.asyncio
async def test_hook_marks_non_retryable_scope_errors_dead_letter(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    tenant_id = f"tenant-{suffix}"
    scoped_connector = f"conn-scoped-{suffix}"
    missing_connector = f"conn-missing-{suffix}"
    instance_id = f"inst-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            for connector_id in (scoped_connector, missing_connector):
                session.add(
                    orm.SourceConnector(
                        connector_id=connector_id,
                        source_product="mock_xdr",
                        display_name=f"Test {connector_id}",
                        status="online",
                        schema_version="1",
                        connector_metadata={
                            "source_tenant_id": tenant_id,
                            "integration_instance_id": instance_id,
                            "connector_set_version": 1,
                        },
                    )
                )
    scope_service = DetectionScopeService(session_factory)
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

    record_id = f"src-dead-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceObject(
                    source_record_id=record_id,
                    source_product="mock_xdr",
                    source_tenant_id=tenant_id,
                    connector_id=missing_connector,
                    source_kind=SourceObjectKind.LOG.value,
                    source_object_id=f"log-{suffix}",
                    source_object_type="edr",
                    source_status_raw="indexed",
                    source_disposition=SourceDisposition.UNKNOWN.value,
                    schema_version="1",
                    ingested_at=datetime(2026, 8, 1, tzinfo=UTC),
                    raw_payload_hash=f"hash-{suffix}",
                    normalized={"detection_score": 10, "logged_at": "2026-08-01T00:00:00+00:00"},
                    raw_payload={"cmdline": "keep"},
                    current_source_status_raw="indexed",
                    current_source_disposition=SourceDisposition.UNKNOWN.value,
                    current_state_version=1,
                    source_sync_state="synced",
                )
            )

    projection = BehaviorObservationProjection(session_factory)
    assert await projection.on_source_record_persisted(record_id) is False

    async with session_factory() as session:
        failure = await session.scalar(
            select(orm.BehaviorObservationProjectionFailure).where(
                orm.BehaviorObservationProjectionFailure.source_record_id == record_id
            )
        )
    assert failure is not None
    assert failure.status == BehaviorObservationProjectionStatus.DEAD_LETTER.value
    assert failure.error_category == "projection_non_retryable"
    assert failure.attempt == 5
