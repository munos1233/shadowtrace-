"""BehaviorObservation Celery retry task tests (ISSUE-156)."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.db import models as orm
from app.models.behavior_observation import (
    BehaviorObservationProjectionStatus,
    BehaviorObservationQuery,
)
from app.services.behavior_observation_service import BehaviorObservationService
from app.tasks.behavior_observation_tasks import (
    RETRY_PENDING_TASK,
    retry_behavior_observation_pending,
)
from tests.test_services.behavior_observation_fixtures import (
    seed_behavior_observation_connector,
    seed_behavior_observation_source_log,
    truncate_behavior_observation_tables,
)


def test_retry_pending_task_name_registered() -> None:
    from app.core.celery_app import celery_app

    assert celery_app.tasks[RETRY_PENDING_TASK].name == RETRY_PENDING_TASK


def test_beat_schedule_empty_when_retry_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEHAVIOR_OBSERVATION_RETRY_ENABLED", "false")
    monkeypatch.setenv("INGESTION_SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "false")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    assert "shadowtrace-behavior-observation-retry-pending" not in _build_beat_schedule()
    get_settings.cache_clear()


def test_beat_schedule_present_when_retry_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEHAVIOR_OBSERVATION_RETRY_ENABLED", "true")
    monkeypatch.setenv("BEHAVIOR_OBSERVATION_RETRY_INTERVAL_S", "180")
    monkeypatch.setenv("INGESTION_SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "false")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    schedule = _build_beat_schedule()
    entry = schedule["shadowtrace-behavior-observation-retry-pending"]
    assert entry["task"] == RETRY_PENDING_TASK
    assert entry["schedule"] == 180.0
    assert entry["options"] == {"queue": "ingestion"}
    get_settings.cache_clear()


def test_retry_pending_task_eager(celery_eager: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEHAVIOR_OBSERVATION_RETRY_BATCH_LIMIT", "25")
    get_settings.cache_clear()

    async def _fake_retry_pending(*, limit: int) -> int:
        assert limit == 25
        return 2

    with patch(
        "app.tasks.behavior_observation_tasks.BehaviorObservationService.retry_pending",
        new=AsyncMock(side_effect=_fake_retry_pending),
    ):
        with patch(
            "app.tasks.behavior_observation_tasks._snapshot_failure_counts",
            new=AsyncMock(side_effect=[(3, 1), (1, 0)]),
        ):
            result = retry_behavior_observation_pending.apply().result

    assert result["retried"] == 2
    assert result["limit"] == 25
    assert result["pending_retry_before"] == 3
    assert result["pending_retry_after"] == 1
    get_settings.cache_clear()


@pytest.mark.integration
def test_celery_retry_pending_resolves_transient_failure(
    session_factory: async_sessionmaker[AsyncSession],
    celery_eager: None,
) -> None:
    suffix = uuid.uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    connector_id = f"conn-{suffix}"

    asyncio.run(truncate_behavior_observation_tables(session_factory))
    try:
        record_id = asyncio.run(
            _prepare_celery_retry_failure(
                session_factory,
                suffix=suffix,
                tenant_id=tenant_id,
                connector_id=connector_id,
            )
        )

        result = retry_behavior_observation_pending.apply(args=[10]).result
        assert result["retried"] >= 1

        asyncio.run(
            _verify_celery_retry_resolved(
                session_factory,
                tenant_id=tenant_id,
                record_id=record_id,
            )
        )
    finally:
        asyncio.run(truncate_behavior_observation_tables(session_factory))


async def _prepare_celery_retry_failure(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
    connector_id: str,
) -> str:
    await seed_behavior_observation_connector(
        session_factory,
        connector_id=connector_id,
        tenant_id=tenant_id,
    )
    record_id = await seed_behavior_observation_source_log(
        session_factory,
        suffix=suffix,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    service = BehaviorObservationService(session_factory)
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
        async with session.begin():
            failure = await session.scalar(
                select(orm.BehaviorObservationProjectionFailure).where(
                    orm.BehaviorObservationProjectionFailure.source_record_id == record_id
                )
            )
            assert failure is not None
            failure.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)
    return record_id


async def _verify_celery_retry_resolved(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: str,
    record_id: str,
) -> None:
    service = BehaviorObservationService(session_factory)
    observations = await service.query_observations(
        BehaviorObservationQuery(source_tenant_id=tenant_id)
    )
    assert observations.total == 1
    assert observations.items[0].provenance.source_record_id == record_id

    async with session_factory() as session:
        failure = await session.scalar(
            select(orm.BehaviorObservationProjectionFailure).where(
                orm.BehaviorObservationProjectionFailure.source_record_id == record_id
            )
        )
    assert failure is not None
    assert failure.status == BehaviorObservationProjectionStatus.RESOLVED.value
