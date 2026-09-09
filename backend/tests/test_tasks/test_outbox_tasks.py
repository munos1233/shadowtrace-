"""Durable outbox delivery task guards."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.core.celery_app import _build_beat_schedule, celery_app
from app.core.config import TaskMode
from app.tasks.outbox_tasks import (
    PROCESS_DISPOSITION_OUTBOXES_TASK,
    _process_once_async,
)


def test_outbox_task_is_registered_and_scheduled_in_celery_mode() -> None:
    assert celery_app.tasks[PROCESS_DISPOSITION_OUTBOXES_TASK].name == (
        PROCESS_DISPOSITION_OUTBOXES_TASK
    )
    schedule = _build_beat_schedule(task_mode=TaskMode.CELERY)
    entry = schedule["shadowtrace-process-disposition-outboxes"]
    assert entry["task"] == PROCESS_DISPOSITION_OUTBOXES_TASK
    assert entry["options"] == {"queue": "investigation"}


@pytest.mark.asyncio
async def test_outbox_task_repairs_saga_tail_before_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import deps

    order: list[str] = []
    rollback = SimpleNamespace(
        repair_completed_rollbacks=AsyncMock(
            side_effect=lambda **_kwargs: order.append("repair") or 2
        )
    )
    sync = SimpleNamespace(
        process_ready_outboxes=AsyncMock(side_effect=lambda **_kwargs: order.append("deliver") or 5)
    )
    redis = SimpleNamespace(aclose=AsyncMock())
    reset = Mock()
    monkeypatch.setattr(deps, "_get_redis", lambda: redis)
    monkeypatch.setattr(deps, "get_rollback_service", AsyncMock(return_value=rollback))
    monkeypatch.setattr(deps, "get_disposition_sync", AsyncMock(return_value=sync))
    monkeypatch.setattr(deps, "reset_loop_bound_redis_resources", reset)

    result = await _process_once_async()

    assert result == {"delivered": 5, "rollback_compensations_repaired": 2}
    assert order == ["repair", "deliver"]
    redis.aclose.assert_awaited_once()
    reset.assert_called_once()
