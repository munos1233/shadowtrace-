"""Contract tests for investigation Celery payloads (ISSUE-264 / ISSUE-283)."""

from __future__ import annotations

import inspect

from app.tasks import investigation_tasks as tasks
from app.tasks.investigation_task_contract import (
    ANALYSIS_ONLY_TASK_PARAM_NAMES,
    INVESTIGATION_TASK_PARAM_NAMES,
)


def test_run_investigation_signature_matches_contract() -> None:
    params = list(inspect.signature(tasks.run_investigation).parameters)
    assert params == list(INVESTIGATION_TASK_PARAM_NAMES)


def test_run_analysis_only_signature_matches_contract() -> None:
    params = list(inspect.signature(tasks.run_analysis_only_investigation).parameters)
    assert params == list(ANALYSIS_ONLY_TASK_PARAM_NAMES)
