"""Callable signature contract tests for investigation Celery tasks (ISSUE-264)."""

from __future__ import annotations

import inspect

from app.tasks import investigation_tasks as tasks
from app.tasks.investigation_task_contract import (
    EXECUTE_INVESTIGATION_KWARG_NAMES,
    RUN_ANALYSIS_ONLY_BODY_KWARG_NAMES,
    RUN_INVESTIGATION_BODY_KWARG_NAMES,
    assert_callable_accepts_kwarg_names,
    build_analysis_only_dispatch_kwargs,
    build_investigation_dispatch_kwargs,
)
from tests.support.investigation_task_doubles import (
    assert_double_covers_body_contract,
    assert_double_covers_execute_contract,
    make_execute_investigation_double,
    make_run_investigation_body_double,
)


def test_execute_investigation_signature_contract() -> None:
    sig = inspect.signature(tasks.execute_investigation)
    assert sig.parameters["generate_report"].default is True
    assert_callable_accepts_kwarg_names(
        tasks.execute_investigation,
        EXECUTE_INVESTIGATION_KWARG_NAMES,
        label="execute_investigation",
    )


def test_run_investigation_body_signature_contract() -> None:
    sig = inspect.signature(tasks._run_investigation_body)
    assert sig.parameters["generate_report"].default is True
    assert_callable_accepts_kwarg_names(
        tasks._run_investigation_body,
        RUN_INVESTIGATION_BODY_KWARG_NAMES,
        label="_run_investigation_body",
    )


def test_run_analysis_only_body_signature_contract() -> None:
    assert_callable_accepts_kwarg_names(
        tasks._run_analysis_only_body,
        RUN_ANALYSIS_ONLY_BODY_KWARG_NAMES,
        label="_run_analysis_only_body",
    )


def test_run_investigation_task_signature_includes_generate_report() -> None:
    sig = inspect.signature(tasks.run_investigation)
    assert "generate_report" in sig.parameters
    assert sig.parameters["generate_report"].default is True


def test_shared_dispatch_builders_include_generate_report() -> None:
    assert build_investigation_dispatch_kwargs()["generate_report"] is True
    assert build_investigation_dispatch_kwargs(generate_report=False)["generate_report"] is False
    assert build_analysis_only_dispatch_kwargs()["generate_report"] is True


def test_test_doubles_accept_production_execute_kwargs() -> None:
    captured: dict[str, object] = {}
    double = make_execute_investigation_double(captured)
    assert_double_covers_execute_contract(double)


def test_test_doubles_accept_production_body_kwargs() -> None:
    captured: dict[str, object] = {}
    double = make_run_investigation_body_double(captured)
    assert_double_covers_body_contract(double)
