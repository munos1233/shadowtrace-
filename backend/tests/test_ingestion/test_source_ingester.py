"""Incremental pagination/watermark tests for SourceIngester."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.source.base import BaseSourceAdapter, SourcePage
from app.db import models as orm
from app.ingestion.source_ingester import CheckpointConflictError, SourceIngester
from app.models.enums import (
    CapabilityState,
    ConnectorCapability,
    ConnectorStatus,
    SourceObjectKind,
)
from app.models.source import SourceAlert, SourceAsset, SourceIncident, SourceReference


class FakePagedAdapter(BaseSourceAdapter):
    def __init__(
        self,
        name: str,
        pages: dict[str | None | tuple[str, str | None], SourcePage | Exception],
        *,
        health: ConnectorStatus | Exception = ConnectorStatus.ONLINE,
    ) -> None:
        self.name = name
        self.pages = pages
        self.health = health
        self.calls: list[tuple[str | None, str | None, datetime | None, int]] = []

    def capabilities(self) -> dict[ConnectorCapability, CapabilityState]:
        return {
            ConnectorCapability.LOG_INGESTION: CapabilityState.SUPPORTED,
            ConnectorCapability.QUERY: CapabilityState.SUPPORTED,
        }

    async def list_objects(
        self,
        object_types: Sequence[SourceObjectKind | str],
        *,
        connector_id: str | None = None,
        cursor: str | None = None,
        updated_after: datetime | None = None,
        limit: int = 100,
    ) -> SourcePage:
        assert len(object_types) == 1
        raw_kind = object_types[0]
        kind = raw_kind if isinstance(raw_kind, SourceObjectKind) else SourceObjectKind(raw_kind)
        self.calls.append((connector_id, cursor, updated_after, limit))
        result = self.pages.get(
            (kind.value, connector_id, cursor),
            self.pages.get((kind.value, cursor), self.pages.get(cursor)),
        )
        if result is None:
            raise KeyError((kind.value, cursor))
        if isinstance(result, Exception):
            raise result
        return result

    async def health_check(self) -> ConnectorStatus:
        if isinstance(self.health, Exception):
            raise self.health
        return self.health


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


def _ref(
    kind: SourceObjectKind,
    object_id: str,
    connector_id: str,
    *,
    updated_at: datetime,
) -> SourceReference:
    return SourceReference(
        source_kind=kind,
        source_product="mock_xdr",
        source_tenant_id="tenant-ingestion",
        connector_id=connector_id,
        source_object_id=object_id,
        source_updated_at=updated_at,
        schema_version="1",
    )


def _incident(
    object_id: str,
    connector_id: str,
    *,
    updated_at: datetime,
    related_alert_refs: list[SourceReference] | None = None,
) -> SourceIncident:
    return SourceIncident(
        reference=_ref(
            SourceObjectKind.INCIDENT,
            object_id,
            connector_id,
            updated_at=updated_at,
        ),
        title=f"incident-{object_id}",
        related_alert_refs=related_alert_refs or [],
    )


@pytest.mark.asyncio
async def test_incremental_pagination_and_next_poll_uses_committed_time(
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-page-{suffix}"
    adapter_name = f"adapter-page-{suffix}"
    base = datetime(2026, 7, 13, 8, 0, tzinfo=UTC)
    first = _incident(f"INC-{suffix}-1", connector_id, updated_at=base)
    second = _incident(
        f"INC-{suffix}-2",
        connector_id,
        updated_at=base + timedelta(minutes=1),
    )
    adapter = FakePagedAdapter(
        adapter_name,
        {
            None: SourcePage(
                items=[first],
                object_kind=SourceObjectKind.INCIDENT,
                next_cursor="c1",
                has_more=True,
                server_time=base + timedelta(minutes=2),
            ),
            "c1": SourcePage(
                items=[second],
                object_kind=SourceObjectKind.INCIDENT,
                next_cursor=None,
                has_more=False,
                server_time=base + timedelta(minutes=3),
            ),
        },
    )

    summary = await source_ingester.poll(
        adapter,
        [SourceObjectKind.INCIDENT],
        batch_size=1,
    )
    assert summary.accepted == 2
    assert summary.duplicate == 0
    assert summary.rejected == 0
    assert summary.watermark_before is None
    assert summary.watermark_after == {
        "cursor": None,
        "updated_after": (base + timedelta(minutes=3)).isoformat(),
    }
    assert [call[1] for call in adapter.calls] == [None, "c1"]

    empty = FakePagedAdapter(
        adapter_name,
        {
            None: SourcePage(
                items=[],
                object_kind=SourceObjectKind.INCIDENT,
                has_more=False,
                server_time=base + timedelta(minutes=4),
            )
        },
    )
    second_summary = await source_ingester.poll(
        empty,
        [SourceObjectKind.INCIDENT],
        batch_size=10,
    )
    assert second_summary.accepted == 0
    assert empty.calls[0][2] == base + timedelta(minutes=3)

    async with session_factory() as session:
        checkpoint = await session.get(
            orm.SourceCheckpoint,
            (connector_id, SourceObjectKind.INCIDENT.value, ""),
        )
        assert checkpoint is not None
        assert checkpoint.status == ConnectorStatus.ONLINE.value
        assert checkpoint.watermark == second_summary.watermark_after


@pytest.mark.asyncio
async def test_failure_does_not_advance_failed_page_and_resume_uses_cursor(
    source_ingester: SourceIngester,
) -> None:
    suffix = _suffix()
    connector_id = f"conn-resume-{suffix}"
    adapter_name = f"adapter-resume-{suffix}"
    base = datetime(2026, 7, 13, 9, 0, tzinfo=UTC)
    first = _incident(f"INC-{suffix}-1", connector_id, updated_at=base)

    failing = FakePagedAdapter(
        adapter_name,
        {
            None: SourcePage(
                items=[first],
                object_kind=SourceObjectKind.INCIDENT,
                next_cursor="resume-cursor",
                has_more=True,
                server_time=base,
            ),
            "resume-cursor": RuntimeError("temporary adapter failure"),
        },
    )
    failed = await source_ingester.poll(
        failing,
        [SourceObjectKind.INCIDENT],
        batch_size=1,
    )
    assert failed.accepted == 1
    assert failed.degraded is True
    assert failed.watermark_after == {
        "cursor": "resume-cursor",
        "updated_after": None,
    }

    missing = _incident(
        f"INC-{suffix}-2",
        connector_id,
        updated_at=base + timedelta(minutes=1),
    )
    recovered_adapter = FakePagedAdapter(
        adapter_name,
        {
            "resume-cursor": SourcePage(
                items=[missing],
                object_kind=SourceObjectKind.INCIDENT,
                has_more=False,
                server_time=base + timedelta(minutes=2),
            )
        },
    )
    recovered = await source_ingester.poll(
        recovered_adapter,
        [SourceObjectKind.INCIDENT],
        batch_size=1,
    )
    assert recovered.accepted == 1
    assert recovered.duplicate == 0
    assert recovered.degraded is False
    assert recovered_adapter.calls[0][1] == "resume-cursor"


@pytest.mark.asyncio
async def test_out_of_order_alert_and_incident_merge_to_one_event(
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-order-{suffix}"
    adapter_name = f"adapter-order-{suffix}"
    occurred = datetime(2026, 7, 13, 10, 0, tzinfo=UTC)
    incident_ref = _ref(
        SourceObjectKind.INCIDENT,
        f"INC-{suffix}",
        connector_id,
        updated_at=occurred,
    )
    alert_ref = _ref(
        SourceObjectKind.ALERT,
        f"AL-{suffix}",
        connector_id,
        updated_at=occurred - timedelta(minutes=1),
    )
    alert = SourceAlert(reference=alert_ref, incident_ref=incident_ref)
    incident = SourceIncident(
        reference=incident_ref,
        title="out-of-order",
        related_alert_refs=[alert_ref],
    )
    adapter = FakePagedAdapter(
        adapter_name,
        {
            (SourceObjectKind.ALERT.value, None): SourcePage(
                items=[alert],
                object_kind=SourceObjectKind.ALERT,
                has_more=False,
                server_time=occurred,
            ),
            (SourceObjectKind.INCIDENT.value, None): SourcePage(
                items=[incident],
                object_kind=SourceObjectKind.INCIDENT,
                has_more=False,
                server_time=occurred,
            ),
        },
    )

    summary = await source_ingester.poll(
        adapter,
        [SourceObjectKind.ALERT, SourceObjectKind.INCIDENT],
        batch_size=10,
    )
    assert summary.accepted == 2
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.SecurityEvent)
            .where(
                orm.SecurityEvent.creation_source_ref["connector_id"].as_string() == connector_id
            )
        )
        assert count == 1


@pytest.mark.asyncio
async def test_unsupported_schema_rejected_without_watermark_advance(
    event_service,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-schema-{suffix}"
    adapter_name = f"adapter-schema-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name="schema-test",
                    status=ConnectorStatus.ONLINE.value,
                    disposition_policy_default="required",
                    connector_metadata={"ingestion_adapter": adapter_name},
                )
            )

    ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="mock_xdr",
    )
    adapter = FakePagedAdapter(
        adapter_name,
        {
            None: SourcePage(
                items=[],
                object_kind=SourceObjectKind.INCIDENT,
                has_more=False,
                schema_version="2",
                server_time=datetime.now(UTC),
            )
        },
    )
    summary = await ingester.poll(
        adapter,
        [SourceObjectKind.INCIDENT],
        batch_size=10,
    )
    assert summary.rejected == 1
    assert summary.degraded is True
    assert summary.watermark_after is None

    async with session_factory() as session:
        connector = await session.get(orm.SourceConnector, connector_id)
        checkpoint = await session.get(
            orm.SourceCheckpoint,
            (connector_id, SourceObjectKind.INCIDENT.value, ""),
        )
        assert connector is not None
        assert connector.watermark is None
        assert connector.status == ConnectorStatus.ONLINE.value
        assert checkpoint is not None
        assert checkpoint.watermark is None
        assert checkpoint.status == ConnectorStatus.DEGRADED.value


@pytest.mark.asyncio
async def test_supporting_object_cannot_reassign_connector_tenant(
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-owner-{suffix}"
    adapter_name = f"adapter-owner-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name="owner-test",
                    status=ConnectorStatus.ONLINE.value,
                    connector_metadata={
                        "ingestion_adapter": adapter_name,
                        "source_tenant_id": "tenant-a",
                    },
                )
            )

    ref = _ref(
        SourceObjectKind.ASSET,
        f"ASSET-{suffix}",
        connector_id,
        updated_at=datetime.now(UTC),
    ).model_copy(update={"source_tenant_id": "tenant-b"})
    summary, _ = await source_ingester.ingest_items(
        [SourceAsset(reference=ref, hostname="owner-conflict")],
        source_type=adapter_name,
    )

    assert summary.accepted == 0
    assert summary.rejected == 1
    assert summary.errors[0]["error_category"] == "object_rejected"
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.SourceObject)
            .where(orm.SourceObject.connector_id == connector_id)
        )
    assert count == 0


@pytest.mark.asyncio
async def test_offline_health_never_calls_list_or_advances(
    source_ingester: SourceIngester,
) -> None:
    adapter = FakePagedAdapter(
        f"adapter-offline-{_suffix()}",
        {},
        health=ConnectorStatus.OFFLINE,
    )
    summary = await source_ingester.poll(
        adapter,
        [SourceObjectKind.INCIDENT],
        batch_size=10,
    )
    assert summary.degraded is True
    assert summary.watermark_before is None
    assert summary.watermark_after is None
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_health_exception_is_reported_as_degraded(
    source_ingester: SourceIngester,
) -> None:
    adapter = FakePagedAdapter(
        f"adapter-health-error-{_suffix()}",
        {},
        health=RuntimeError("health endpoint unavailable"),
    )
    summary = await source_ingester.poll(
        adapter,
        [SourceObjectKind.INCIDENT],
        batch_size=10,
    )
    assert summary.degraded is True
    assert {error["error_category"] for error in summary.errors} == {
        "health_check_failed",
        "connector_unavailable",
    }
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_checkpoints_are_isolated_per_connector_and_kind(
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    adapter_name = f"adapter-isolated-{suffix}"
    connector_a = f"conn-a-{suffix}"
    connector_b = f"conn-b-{suffix}"
    base = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    async with session_factory() as session:
        async with session.begin():
            for connector_id in (connector_a, connector_b):
                session.add(
                    orm.SourceConnector(
                        connector_id=connector_id,
                        source_product="mock_xdr",
                        display_name=connector_id,
                        connector_metadata={"ingestion_adapter": adapter_name},
                    )
                )

    adapter = FakePagedAdapter(
        adapter_name,
        {
            (SourceObjectKind.INCIDENT.value, connector_a, None): SourcePage(
                items=[_incident(f"INC-a-{suffix}", connector_a, updated_at=base)],
                object_kind=SourceObjectKind.INCIDENT,
                connector_id=connector_a,
                server_time=base + timedelta(minutes=1),
            ),
            (SourceObjectKind.INCIDENT.value, connector_b, None): SourcePage(
                items=[_incident(f"INC-b-{suffix}", connector_b, updated_at=base)],
                object_kind=SourceObjectKind.INCIDENT,
                connector_id=connector_b,
                server_time=base + timedelta(minutes=2),
            ),
        },
    )

    summary = await source_ingester.poll(
        adapter,
        [SourceObjectKind.INCIDENT],
        batch_size=10,
    )

    assert summary.accepted == 2
    assert summary.watermark_after is None
    assert {call[0] for call in adapter.calls} == {connector_a, connector_b}
    async with session_factory() as session:
        checkpoint_a = await session.get(
            orm.SourceCheckpoint,
            (connector_a, SourceObjectKind.INCIDENT.value, ""),
        )
        checkpoint_b = await session.get(
            orm.SourceCheckpoint,
            (connector_b, SourceObjectKind.INCIDENT.value, ""),
        )
        assert checkpoint_a is not None
        assert checkpoint_b is not None
        assert checkpoint_a.watermark != checkpoint_b.watermark


@pytest.mark.asyncio
async def test_checkpoint_insert_conflict_uses_real_cas(
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-cas-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name=connector_id,
                )
            )

    first_watermark = {"cursor": "a", "updated_after": "2026-07-13T12:00:00+00:00"}
    second_watermark = {"cursor": "b", "updated_after": "2026-07-13T12:01:00+00:00"}
    results = await asyncio.gather(
        source_ingester._commit_checkpoint(
            connector_id=connector_id,
            object_kind=SourceObjectKind.INCIDENT,
            stream_scope="",
            watermark=first_watermark,
            schema_version="1",
            expected_watermark=None,
            expected_row_version=None,
        ),
        source_ingester._commit_checkpoint(
            connector_id=connector_id,
            object_kind=SourceObjectKind.INCIDENT,
            stream_scope="",
            watermark=second_watermark,
            schema_version="1",
            expected_watermark=None,
            expected_row_version=None,
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(result, CheckpointConflictError) for result in results) == 1
    async with session_factory() as session:
        checkpoint = await session.get(
            orm.SourceCheckpoint,
            (connector_id, SourceObjectKind.INCIDENT.value, ""),
        )
        assert checkpoint is not None
        assert checkpoint.row_version == 1
        assert checkpoint.watermark in (first_watermark, second_watermark)


@pytest.mark.asyncio
async def test_malformed_page_never_advances_checkpoint(
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-malformed-{suffix}"
    adapter_name = f"adapter-malformed-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name=connector_id,
                    connector_metadata={"ingestion_adapter": adapter_name},
                )
            )
    adapter = FakePagedAdapter(
        adapter_name,
        {
            None: SourcePage(
                object_kind=SourceObjectKind.INCIDENT,
                connector_id=connector_id,
                next_cursor="unsafe",
                has_more=True,
                malformed_items=1,
            )
        },
    )

    summary = await source_ingester.poll(
        adapter,
        [SourceObjectKind.INCIDENT],
        batch_size=10,
    )

    assert summary.rejected == 1
    assert summary.watermark_after is None
    async with session_factory() as session:
        checkpoint = await session.get(
            orm.SourceCheckpoint,
            (connector_id, SourceObjectKind.INCIDENT.value, ""),
        )
        assert checkpoint is not None
        assert checkpoint.watermark is None
        assert checkpoint.status == ConnectorStatus.DEGRADED.value


@pytest.mark.asyncio
async def test_schema_failure_is_kind_local_and_connector_health_stays_online(
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-kind-local-{suffix}"
    adapter_name = f"adapter-kind-local-{suffix}"
    now = datetime(2026, 7, 13, 13, 0, tzinfo=UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name=connector_id,
                    connector_metadata={"ingestion_adapter": adapter_name},
                )
            )
    alert = SourceAlert(
        reference=_ref(
            SourceObjectKind.ALERT,
            f"AL-{suffix}",
            connector_id,
            updated_at=now,
        )
    )
    adapter = FakePagedAdapter(
        adapter_name,
        {
            (SourceObjectKind.INCIDENT.value, None): SourcePage(
                object_kind=SourceObjectKind.INCIDENT,
                connector_id=connector_id,
                schema_version="2",
            ),
            (SourceObjectKind.ALERT.value, None): SourcePage(
                items=[alert],
                object_kind=SourceObjectKind.ALERT,
                connector_id=connector_id,
                server_time=now,
            ),
        },
    )

    summary = await source_ingester.poll(
        adapter,
        [SourceObjectKind.INCIDENT, SourceObjectKind.ALERT],
        batch_size=10,
    )

    assert summary.kind_summaries[SourceObjectKind.INCIDENT.value].degraded is True
    assert summary.kind_summaries[SourceObjectKind.ALERT.value].accepted == 1
    async with session_factory() as session:
        connector = await session.get(orm.SourceConnector, connector_id)
        incident_checkpoint = await session.get(
            orm.SourceCheckpoint,
            (connector_id, SourceObjectKind.INCIDENT.value, ""),
        )
        alert_checkpoint = await session.get(
            orm.SourceCheckpoint,
            (connector_id, SourceObjectKind.ALERT.value, ""),
        )
        assert connector is not None
        assert connector.status == ConnectorStatus.ONLINE.value
        assert incident_checkpoint is not None
        assert incident_checkpoint.status == ConnectorStatus.DEGRADED.value
        assert alert_checkpoint is not None
        assert alert_checkpoint.status == ConnectorStatus.ONLINE.value


@pytest.mark.asyncio
async def test_legacy_global_watermark_is_ignored_and_replayed(
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-legacy-{suffix}"
    adapter_name = f"adapter-legacy-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name=connector_id,
                    watermark={"cursor": "unsafe-global", "updated_after": "2099-01-01T00:00:00Z"},
                    connector_metadata={"ingestion_adapter": adapter_name},
                )
            )
    adapter = FakePagedAdapter(
        adapter_name,
        {
            None: SourcePage(
                object_kind=SourceObjectKind.INCIDENT,
                connector_id=connector_id,
                server_time=datetime(2026, 7, 13, 14, 0, tzinfo=UTC),
            )
        },
    )

    summary = await source_ingester.poll(
        adapter,
        [SourceObjectKind.INCIDENT],
        batch_size=10,
    )

    assert adapter.calls[0][1] is None
    assert summary.watermark_before is None
