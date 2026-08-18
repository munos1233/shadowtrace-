"""Celery broker/worker health probe tests (ISSUE-117 / #622 Phase A)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.celery_health import (
    build_celery_health,
    check_celery_broker,
    check_investigation_intent_beat_schedule,
    probe_celery_workers,
)


@pytest.mark.asyncio
async def test_check_celery_broker_ok() -> None:
    client = AsyncMock()
    client.ping = AsyncMock(return_value=True)
    client.aclose = AsyncMock()
    with patch("app.core.celery_health.Redis.from_url", return_value=client):
        assert await check_celery_broker("redis://localhost:6379/0") == "ok"


@pytest.mark.asyncio
async def test_check_celery_broker_error_on_ping_failure() -> None:
    client = AsyncMock()
    client.ping = AsyncMock(side_effect=ConnectionError("down"))
    client.aclose = AsyncMock()
    with patch("app.core.celery_health.Redis.from_url", return_value=client):
        assert await check_celery_broker("redis://localhost:6379/0") == "error"


def test_probe_celery_workers_ok() -> None:
    from app.core.celery_app import celery_app

    inspector = MagicMock()
    inspector.ping.return_value = {
        "celery@host-a": {"ok": "pong"},
        "celery@host-b": {"ok": "pong"},
    }
    with patch.object(celery_app.control, "inspect", return_value=inspector):
        result = probe_celery_workers(timeout=1.0)
    assert result["status"] == "ok"
    assert result["workers"] == 2


def test_probe_celery_workers_degraded_when_no_replies() -> None:
    from app.core.celery_app import celery_app

    inspector = MagicMock()
    inspector.ping.return_value = None
    with patch.object(celery_app.control, "inspect", return_value=inspector):
        result = probe_celery_workers(timeout=1.0)
    assert result["status"] == "degraded"
    assert result["workers"] == 0


def test_probe_celery_workers_degraded_when_empty_replies() -> None:
    from app.core.celery_app import celery_app

    inspector = MagicMock()
    inspector.ping.return_value = {}
    with patch.object(celery_app.control, "inspect", return_value=inspector):
        result = probe_celery_workers(timeout=1.0)
    assert result["status"] == "degraded"
    assert result["workers"] == 0


def test_probe_celery_workers_error_on_inspect_exception() -> None:
    from app.core.celery_app import celery_app

    with patch.object(
        celery_app.control,
        "inspect",
        side_effect=TimeoutError("inspect timed out"),
    ):
        result = probe_celery_workers(timeout=1.0)
    assert result["status"] == "error"
    assert result["workers"] == 0
    assert result["reason"] == "TimeoutError"


@pytest.mark.asyncio
async def test_build_celery_health_skips_worker_probe_in_background_mode() -> None:
    with patch(
        "app.core.celery_health.check_celery_broker",
        new_callable=AsyncMock,
        return_value="ok",
    ) as broker_mock:
        result = await build_celery_health(
            task_mode="background",
            broker_url="redis://localhost:6379/0",
        )
    broker_mock.assert_awaited_once()
    assert result["task_mode"] == "background"
    assert result["worker"]["status"] == "not_applicable"


@pytest.mark.asyncio
async def test_build_celery_health_probes_workers_in_celery_mode() -> None:
    with (
        patch(
            "app.core.celery_health.check_celery_broker",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.core.celery_health.check_celery_workers",
            new_callable=AsyncMock,
            return_value={"status": "degraded", "workers": 0, "worker_ids": []},
        ) as worker_mock,
    ):
        result = await build_celery_health(
            task_mode="celery",
            broker_url="redis://localhost:6379/0",
        )
    worker_mock.assert_awaited_once()
    assert result["worker"]["status"] == "degraded"
    assert result["investigation_intent_beat"]["status"] == "ok"


def test_investigation_intent_beat_schedule_not_applicable_in_background_mode() -> None:
    result = check_investigation_intent_beat_schedule(task_mode="background")
    assert result["status"] == "not_applicable"


def test_investigation_intent_beat_schedule_ok_in_celery_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    result = check_investigation_intent_beat_schedule(task_mode="celery")
    assert result["status"] == "ok"
    assert result["dispatch_scheduled"] is True
    assert result["reconcile_scheduled"] is True
    get_settings.cache_clear()


def test_investigation_intent_beat_schedule_uses_passed_mode_not_forced_celery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("TASK_MODE", "background")
    get_settings.cache_clear()
    background = check_investigation_intent_beat_schedule(task_mode="background")
    assert background["status"] == "not_applicable"
    celery = check_investigation_intent_beat_schedule(task_mode="celery")
    assert celery["status"] == "ok"
    get_settings.cache_clear()
