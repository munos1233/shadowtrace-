"""Unit tests for DispositionSourceService (ISSUE-280)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.core.errors import (
    DispositionPermissionDenied,
    WritebackConflictError,
)
from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.source import SourceReference
from app.services.disposition_source_service import DispositionSourceService
from app.services.event_service import EventService, _ref_dump
from app.services.writeback_readiness_resolver import WritebackReadinessResolver

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _tenant_ref(*, tenant_id: str = "tenant-demo", object_id: str | None = None) -> SourceReference:
    oid = object_id or f"INC-{_sfx()}"
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id=tenant_id,
        connector_id="conn-disposition",
        source_object_id=oid,
        ingested_at=datetime.now(UTC),
    )


async def _seed_event_with_source(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: str = "tenant-demo",
    other_tenant_source: bool = False,
) -> tuple[str, str, str]:
    sfx = _sfx()
    event_id = f"evt-{sfx}"
    source_record_id = f"src-{sfx}"
    ref = _tenant_ref(tenant_id=tenant_id)
    other_record_id = f"src-other-{_sfx()}"

    async with session_factory() as session:
        async with session.begin():
            connector = await session.get(orm.SourceConnector, "conn-disposition")
            if connector is None:
                session.add(
                    orm.SourceConnector(
                        connector_id="conn-disposition",
                        source_product="mock_xdr",
                        display_name="Mock XDR",
                        disposition_policy_default=DispositionPolicy.REQUIRED.value,
                    )
                )
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product=ref.source_product,
                    source_tenant_id=ref.source_tenant_id,
                    connector_id=ref.connector_id,
                    source_kind=ref.source_kind.value,
                    source_object_id=ref.source_object_id,
                )
            )
            if other_tenant_source:
                other_ref = _tenant_ref(tenant_id="tenant-other")
                session.add(
                    orm.SourceObject(
                        source_record_id=other_record_id,
                        source_product=other_ref.source_product,
                        source_tenant_id=other_ref.source_tenant_id,
                        connector_id=other_ref.connector_id,
                        source_kind=other_ref.source_kind.value,
                        source_object_id=other_ref.source_object_id,
                    )
                )
                session.add(
                    orm.SourceEventLink(
                        source_record_id=other_record_id,
                        event_id=event_id,
                        role="related",
                    )
                )
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.INSIDER_THREAT.value,
                    title="disposition source test",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.NONE.value,
                    creation_source_ref=_ref_dump(ref),
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                )
            )
            session.add(
                orm.SourceEventLink(
                    source_record_id=source_record_id,
                    event_id=event_id,
                    role="primary",
                )
            )
    linked_source = other_record_id if other_tenant_source else source_record_id
    return event_id, linked_source, source_record_id


@pytest.fixture
def adapter_registry() -> DispositionAdapterRegistry:
    registry = DispositionAdapterRegistry()
    registry.register(
        "mock_xdr",
        MockXDRDispositionAdapter(
            base_url="http://mock-xdr",
            read_token="mock-read-token",
            write_token="mock-write-token",
        ),
    )
    return registry


@pytest.fixture
def disposition_source_service(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    adapter_registry: DispositionAdapterRegistry,
) -> DispositionSourceService:
    return DispositionSourceService(
        session_factory,
        event_service=event_service,
        adapter_registry=adapter_registry,
        readiness_resolver=WritebackReadinessResolver(),
    )


@pytest.mark.asyncio
async def test_select_persists_locator_and_row_version(
    session_factory: async_sessionmaker[AsyncSession],
    disposition_source_service: DispositionSourceService,
) -> None:
    event_id, source_record_id, _ = await _seed_event_with_source(session_factory)

    result = await disposition_source_service.select_disposition_source(
        event_id,
        source_record_id=source_record_id,
        expected_event_version=1,
        operator="op-1",
        comment="manual pick",
    )
    assert result.event_version == 2
    assert result.disposition_source_ref.source_object_id.startswith("INC-")

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.row_version == 2
        assert row.disposition_source_ref is not None
        assert (
            row.disposition_source_ref["source_object_id"]
            == result.disposition_source_ref.source_object_id
        )


@pytest.mark.asyncio
async def test_select_rejects_unassociated_source(
    disposition_source_service: DispositionSourceService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, _, primary_source = await _seed_event_with_source(session_factory)

    with pytest.raises(DispositionPermissionDenied):
        await disposition_source_service.select_disposition_source(
            event_id,
            source_record_id="src-unlinked",
            expected_event_version=1,
            operator="op-1",
        )

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.disposition_source_ref is None
        assert row.row_version == 1
        _ = primary_source


@pytest.mark.asyncio
async def test_select_rejects_tenant_mismatch(
    disposition_source_service: DispositionSourceService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, other_record_id, _ = await _seed_event_with_source(
        session_factory,
        other_tenant_source=True,
    )

    with pytest.raises(DispositionPermissionDenied):
        await disposition_source_service.select_disposition_source(
            event_id,
            source_record_id=other_record_id,
            expected_event_version=1,
            operator="op-1",
        )


@pytest.mark.asyncio
async def test_select_version_conflict_returns_409_semantics(
    disposition_source_service: DispositionSourceService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, source_record_id, _ = await _seed_event_with_source(session_factory)

    with pytest.raises(WritebackConflictError) as exc:
        await disposition_source_service.select_disposition_source(
            event_id,
            source_record_id=source_record_id,
            expected_event_version=999,
            operator="op-1",
        )
    assert exc.value.details["expected"] == 999
    assert exc.value.details["actual"] == 1


@pytest.mark.asyncio
async def test_recheck_uses_adapter_resolver_when_locator_present(
    disposition_source_service: DispositionSourceService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, source_record_id, _ = await _seed_event_with_source(session_factory)
    await disposition_source_service.select_disposition_source(
        event_id,
        source_record_id=source_record_id,
        expected_event_version=1,
        operator="op-1",
    )

    result = await disposition_source_service.recheck_disposition_readiness(
        event_id,
        expected_event_version=2,
    )
    assert result.writeback_readiness is WritebackReadiness.CONNECTOR_UNAVAILABLE
    assert result.blocked_reason == "connector_offline"
    assert result.event_version == 2


@pytest.mark.asyncio
async def test_recheck_source_unresolved_without_selection(
    disposition_source_service: DispositionSourceService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, _, _ = await _seed_event_with_source(session_factory)

    result = await disposition_source_service.recheck_disposition_readiness(
        event_id,
        expected_event_version=1,
    )
    assert result.writeback_readiness is WritebackReadiness.SOURCE_UNRESOLVED
    assert result.blocked_reason == "source_unresolved"


@pytest.mark.asyncio
async def test_permission_error_not_swallowed_by_db_path(
    disposition_source_service: DispositionSourceService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Regression: permission failures must not fall through to fixture success."""
    event_id, _, _ = await _seed_event_with_source(session_factory)

    with pytest.raises(DispositionPermissionDenied):
        await disposition_source_service.select_disposition_source(
            event_id,
            source_record_id="src-missing",
            expected_event_version=1,
            operator="op-1",
        )

    async with session_factory() as session:
        audit_count = await session.scalar(
            select(func.count()).select_from(orm.EventAuditLog).where(
                orm.EventAuditLog.event_id == event_id
            )
        )
        assert int(audit_count or 0) == 0
