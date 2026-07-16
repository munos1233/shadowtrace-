"""AlertBuilder and explicit file fallback tests (ISSUE-016)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.ingestion.alert_builder import AlertBuilder
from app.ingestion.file_ingester import FileIngester
from app.ingestion.source_ingester import SourceIngester
from app.models.enums import EventStatus, SourceObjectKind
from app.services.event_service import EventService

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_alert_builder_groups_same_entities_and_window() -> None:
    base = datetime(2026, 7, 13, 7, 0, tzinfo=UTC)
    records = [
        {
            "record_id": "r1",
            "channel": "dlp",
            "logged_at": base.isoformat(),
            "is_key_event": True,
            "account": "user-1",
            "hostname": "host-1",
            "action": "archive",
        },
        {
            "record_id": "r2",
            "channel": "dlp",
            "logged_at": (base + timedelta(minutes=5)).isoformat(),
            "is_key_event": True,
            "account": "user-1",
            "hostname": "host-1",
            "action": "upload",
        },
    ]
    alerts = AlertBuilder().build(records)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "data_exfiltration"
    assert alerts[0]["source_type"] == "file"
    assert [row["record_id"] for row in alerts[0]["records"]] == ["r1", "r2"]
    assert alerts[0]["primary_entities"] == ["account:user-1", "hostname:host-1"]
    assert alerts[0]["occurred_at"] == base.isoformat()


def test_alert_builder_noise_produces_no_alert() -> None:
    records = [
        {
            "record_id": "noise-1",
            "channel": "network",
            "logged_at": "2026-07-13T08:00:00+00:00",
            "is_noise": True,
            "src_ip": "192.0.2.1",
        },
        {
            "record_id": "noise-2",
            "channel": "network",
            "logged_at": "2026-07-13T08:01:00+00:00",
            "is_key_event": False,
            "src_ip": "192.0.2.2",
        },
        {
            "record_id": "provider-observation",
            "channel": "identity",
            "logged_at": "2026-07-13T08:02:00+00:00",
            "is_key_event": True,
            "event_type": "provider_error",
            "account": "system",
        },
        {
            "record_id": "id-noise-42-0001",
            "channel": "identity",
            "logged_at": "2026-07-13T08:03:00+00:00",
            "is_key_event": True,
            "event_type": "login",
            "result": "success",
            "account": "ops-bot",
        },
    ]
    assert AlertBuilder().build(records) == []


@pytest.mark.asyncio
async def test_file_fallback_requires_explicit_mode(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    source_ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="mock_xdr",
    )
    file_ingester = FileIngester(
        source_ingester,
        event_service,
        source_mode="mock_xdr",
    )
    with pytest.raises(RuntimeError, match="SOURCE_MODE=file"):
        await file_ingester.ingest(REPO_ROOT / "data" / "mock")


@pytest.mark.asyncio
async def test_main_scenario_file_ingest_creates_exactly_one_new_event(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    source_ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="file",
    )
    file_ingester = FileIngester(
        source_ingester,
        event_service,
        source_mode="file",
    )
    summary = await file_ingester.ingest(
        REPO_ROOT / "data" / "mock",
        scenario="insider_data_exfiltration",
    )
    assert summary.rejected == 0
    assert summary.degraded is False, summary.errors

    async with session_factory() as session:
        events = (
            await session.scalars(
                select(orm.SecurityEvent).where(
                    orm.SecurityEvent.source_type == "file",
                    orm.SecurityEvent.creation_source_ref["connector_id"].as_string()
                    == "conn-disposition",
                )
            )
        ).all()
        assert len(events) == 1
        assert events[0].status == EventStatus.NEW.value

    replay = await file_ingester.ingest(
        REPO_ROOT / "data" / "mock",
        scenario="insider_data_exfiltration",
    )
    assert replay.accepted == 0
    assert replay.duplicate == 0
    assert replay.rejected == 0


@pytest.mark.asyncio
async def test_file_ingest_completes_when_batch_size_smaller_than_scenario(
    tmp_path: Path,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """FileSourceAdapter must page with cursors so SourceIngester can finish."""
    source_dir = tmp_path / uuid.uuid4().hex
    source_dir.mkdir()
    source_ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="file",
    )
    file_ingester = FileIngester(
        source_ingester,
        event_service,
        source_mode="file",
    )
    summary = await file_ingester.ingest(
        source_dir,
        scenario="insider_data_exfiltration",
        batch_size=1,
    )
    assert summary.rejected == 0
    assert summary.degraded is False
    assert not any(err.get("error_category") == "invalid_pagination" for err in summary.errors)
    assert summary.watermark_after is None
    assert summary.accepted + summary.duplicate > 0

    async with session_factory() as session:
        events = (
            await session.scalars(
                select(orm.SecurityEvent).where(
                    orm.SecurityEvent.source_type == "file",
                    orm.SecurityEvent.creation_source_ref["connector_id"].as_string()
                    == "conn-disposition",
                )
            )
        ).all()
        assert len(events) >= 1
        assert any(row.status == EventStatus.NEW.value for row in events)
        checkpoint_count = await session.scalar(
            select(func.count())
            .select_from(orm.SourceCheckpoint)
            .where(
                orm.SourceCheckpoint.object_kind.in_(
                    [
                        SourceObjectKind.INCIDENT.value,
                        SourceObjectKind.ALERT.value,
                        SourceObjectKind.ASSET.value,
                        SourceObjectKind.LOG.value,
                    ]
                )
            )
        )
        assert checkpoint_count


@pytest.mark.asyncio
async def test_file_watermarks_are_scoped_per_scenario(
    tmp_path: Path,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    source_dir = tmp_path / uuid.uuid4().hex
    source_dir.mkdir()
    source_ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="file",
    )
    file_ingester = FileIngester(
        source_ingester,
        event_service,
        source_mode="file",
    )

    insider = await file_ingester.ingest(
        source_dir,
        scenario="insider_data_exfiltration",
    )
    account = await file_ingester.ingest(
        source_dir,
        scenario="account_anomaly_fp",
    )
    assert insider.watermark_before is None
    assert account.watermark_before is None
    assert insider.rejected == 0
    assert account.rejected == 0
    async with session_factory() as session:
        scopes = set(
            (
                await session.scalars(
                    select(orm.SourceCheckpoint.stream_scope).where(
                        orm.SourceCheckpoint.connector_id.in_(
                            {
                                "conn-log-only",
                                "conn-disposition",
                                "conn-log-fp",
                                "conn-disp-fp",
                            }
                        ),
                        orm.SourceCheckpoint.stream_scope != "",
                    )
                )
            ).all()
        )
    assert len(scopes) >= 2


@pytest.mark.asyncio
async def test_noise_only_directory_creates_no_event(
    tmp_path: Path,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    connector_marker = "noise-only-unique-marker"
    (tmp_path / "network_logs.json").write_text(
        json.dumps(
            [
                {
                    "record_id": connector_marker,
                    "channel": "network",
                    "logged_at": "2026-07-13T10:00:00+00:00",
                    "is_key_event": False,
                    "src_ip": "192.0.2.1",
                }
            ]
        ),
        encoding="utf-8",
    )
    source_ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="file",
    )
    file_ingester = FileIngester(
        source_ingester,
        event_service,
        source_mode="file",
    )
    summary = await file_ingester.ingest(tmp_path)
    assert summary.accepted == 0
    assert summary.duplicate == 0
    assert summary.rejected == 0

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.SecurityEvent)
            .where(orm.SecurityEvent.title.ilike(f"%{connector_marker}%"))
        )
        assert count == 0


@pytest.mark.asyncio
async def test_legacy_suspicious_records_use_event_service_idempotently(
    tmp_path: Path,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    marker = uuid.uuid4().hex
    base = "2026-07-13T11:00:00+00:00"
    (tmp_path / "dlp_logs.json").write_text(
        json.dumps(
            [
                {
                    "record_id": f"{marker}-1",
                    "channel": "dlp",
                    "logged_at": base,
                    "is_key_event": True,
                    "account": marker,
                    "hostname": f"host-{marker}",
                    "action": "upload",
                }
            ]
        ),
        encoding="utf-8",
    )
    source_ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="file",
    )
    file_ingester = FileIngester(
        source_ingester,
        event_service,
        source_mode="file",
    )

    first = await file_ingester.ingest(tmp_path)
    second = await file_ingester.ingest(tmp_path)
    assert first.accepted == 1
    assert second.duplicate == 1

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.SecurityEvent)
            .where(orm.SecurityEvent.title == "file fallback: data_exfiltration")
        )
        assert count >= 1
