"""Test doubles aligned with investigation Celery task contracts (ISSUE-264)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.tasks.investigation_task_contract import (
    EXECUTE_INVESTIGATION_KWARG_NAMES,
    RUN_INVESTIGATION_BODY_KWARG_NAMES,
)


def make_execute_investigation_double(
    captured: dict[str, Any],
    *,
    result_status: str = "completed",
) -> Callable[..., Any]:
    """Return an ``execute_investigation`` double that accepts the production kwargs."""

    async def _fake_execute_investigation(event_id: str, **kwargs: Any) -> dict[str, str]:
        captured.clear()
        captured.update(kwargs)
        captured["event_id"] = event_id
        return {"status": result_status, "event_id": event_id}

    return _fake_execute_investigation


def make_run_investigation_body_double(
    captured: dict[str, Any],
    *,
    result_status: str = "completed",
) -> Callable[..., Any]:
    """Return a ``_run_investigation_body`` double that accepts the production kwargs."""

    async def _fake_body(event_id: str, **kwargs: Any) -> dict[str, str]:
        captured.clear()
        captured.update(kwargs)
        captured["event_id"] = event_id
        return {"status": result_status, "event_id": event_id}

    return _fake_body


def assert_double_covers_execute_contract(double: Callable[..., Any]) -> None:
    sig_params = double.__code__.co_varnames
    assert "kwargs" in sig_params or EXECUTE_INVESTIGATION_KWARG_NAMES.issubset(set(sig_params))


def assert_double_covers_body_contract(double: Callable[..., Any]) -> None:
    sig_params = double.__code__.co_varnames
    assert "kwargs" in sig_params or RUN_INVESTIGATION_BODY_KWARG_NAMES.issubset(set(sig_params))
