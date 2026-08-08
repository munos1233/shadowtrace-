"""Test doubles aligned with ``investigation_task_contract`` (ISSUE-264 / ISSUE-283)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.tasks.investigation_task_contract import (
    AnalysisOnlyDispatchKwargs,
    InvestigationDispatchKwargs,
    InvestigationIntentPublishKwargs,
)


def capture_run_investigation_apply_async(
    monkeypatch: pytest.MonkeyPatch,
    captured: dict[str, Any],
) -> None:
    from app.tasks import investigation_tasks as tasks

    def _fake_apply_async(*args: Any, **kwargs: Any) -> MagicMock:
        captured.clear()
        captured["args"] = args
        captured.update(kwargs)
        return MagicMock(id=kwargs.get("task_id", "task-mock"))

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)


def assert_dispatch_kwargs(
    captured: dict[str, Any],
    expected: InvestigationDispatchKwargs,
) -> None:
    assert captured.get("kwargs") == expected.to_apply_async_kwargs()


def assert_intent_publish_kwargs(
    captured: dict[str, Any],
    expected: InvestigationIntentPublishKwargs,
) -> None:
    assert captured.get("kwargs") == expected.to_apply_async_kwargs()


def assert_analysis_only_dispatch_kwargs(
    captured: dict[str, Any],
    expected: AnalysisOnlyDispatchKwargs,
) -> None:
    assert captured.get("kwargs") == expected.to_apply_async_kwargs()


ApplyAsyncCaptureFactory = Callable[[pytest.MonkeyPatch], dict[str, Any]]


def make_apply_async_capture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    capture_run_investigation_apply_async(monkeypatch, captured)
    return captured
