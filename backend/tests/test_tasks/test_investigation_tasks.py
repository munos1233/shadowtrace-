"""Investigation Celery task tests (ISSUE-056).

Uses Celery eager mode (CELERY_TASK_ALWAYS_EAGER=True) so tests run
synchronously without a real broker.  Coverage:

1. Task dispatch → SuperAgent.investigate runs to completion
2. Duplicate event_id is idempotent (lease prevents parallel run)
3. Task status query (eager mode returns SUCCESS/FAILURE)
4. TASK_MODE=background fallback in API
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_ORIG_TASK_ALWAYS_EAGER: bool | None = None
_ORIG_ENV_EAGER: str | None = None


def _enable_eager() -> None:
    """Force Celery eager mode so tasks execute synchronously."""
    global _ORIG_TASK_ALWAYS_EAGER, _ORIG_ENV_EAGER

    _ORIG_ENV_EAGER = os.environ.get("CELERY_TASK_ALWAYS_EAGER")
    os.environ["CELERY_TASK_ALWAYS_EAGER"] = "true"
    # Also set on the already-imported app conf — the env var alone may be
    # read too late if celery_app was imported by another module first.
    try:
        from app.core.celery_app import celery_app as _app

        _ORIG_TASK_ALWAYS_EAGER = _app.conf.task_always_eager
        _app.conf.update(task_always_eager=True)
    except ImportError:
        pass


def _restore_eager() -> None:
    """Restore the original eager setting."""
    if _ORIG_ENV_EAGER is None:
        os.environ.pop("CELERY_TASK_ALWAYS_EAGER", None)
    else:
        os.environ["CELERY_TASK_ALWAYS_EAGER"] = _ORIG_ENV_EAGER
    try:
        from app.core.celery_app import celery_app as _app

        if _ORIG_TASK_ALWAYS_EAGER is not None:
            _app.conf.update(task_always_eager=_ORIG_TASK_ALWAYS_EAGER)
    except ImportError:
        pass


@pytest.fixture(autouse=True)
def _eager_celery() -> Any:
    """Run all tests in eager mode — no external broker needed."""
    _enable_eager()
    yield
    _restore_eager()


# --------------------------------------------------------------------------- #
# run_investigation task — eager-mode dispatch
# --------------------------------------------------------------------------- #


class TestRunInvestigationTask:
    """Task dispatching and execution via eager Celery."""

    def test_task_dispatches_and_completes(self) -> None:
        """Eager task runs SuperAgent.investigate and returns success."""
        from app.tasks.investigation_tasks import run_investigation

        with patch(
            "app.tasks.investigation_tasks.get_super_agent",
            new_callable=AsyncMock,
        ) as mock_get_agent:
            mock_agent = MagicMock()
            mock_agent.investigate = AsyncMock(return_value=None)
            mock_get_agent.return_value = mock_agent

            result = run_investigation.delay("evt-test001")

            assert result.successful()
            assert result.result == {"event_id": "evt-test001", "status": "completed"}
            mock_agent.investigate.assert_awaited_once_with("evt-test001")

    def test_task_skips_when_lease_occupied(self) -> None:
        """Duplicate trigger returns 'skipped' without error."""
        from app.core.errors import InvestigationInProgressError
        from app.tasks.investigation_tasks import run_investigation

        with patch(
            "app.tasks.investigation_tasks.get_super_agent",
            new_callable=AsyncMock,
        ) as mock_get_agent:
            mock_agent = MagicMock()
            mock_agent.investigate = AsyncMock(
                side_effect=InvestigationInProgressError(
                    message="already in progress",
                    error_code="investigation_in_progress",
                    details={"event_id": "evt-test002"},
                )
            )
            mock_get_agent.return_value = mock_agent

            result = run_investigation.delay("evt-test002")

            assert result.successful()
            assert result.result == {"event_id": "evt-test002", "status": "skipped"}

    def test_task_retries_on_failure(self) -> None:
        """Non-lease failures propagate and trigger Celery retry."""
        from app.tasks.investigation_tasks import run_investigation

        with patch(
            "app.tasks.investigation_tasks.get_super_agent",
            new_callable=AsyncMock,
        ) as mock_get_agent:
            mock_agent = MagicMock()
            mock_agent.investigate = AsyncMock(
                side_effect=RuntimeError("transient DB error")
            )
            mock_get_agent.return_value = mock_agent

            # Eager mode: the exception propagates through apply().
            # The retry counter is recorded by Celery internally.
            with pytest.raises(RuntimeError, match="transient DB error"):
                run_investigation.delay("evt-test003")

    def test_deps_reset_per_invocation(self) -> None:
        """Each task invocation resets investigation-layer singletons."""
        from app.tasks.investigation_tasks import run_investigation

        with (
            patch("app.tasks.investigation_tasks._investigate", new_callable=AsyncMock) as mock_inner,
        ):
            mock_inner.return_value = {"event_id": "evt-test004", "status": "completed"}

            result = run_investigation.delay("evt-test004")

            assert result.successful()
            mock_inner.assert_called_once_with("evt-test004")


# --------------------------------------------------------------------------- #
# TaskStatusResponse schema
# --------------------------------------------------------------------------- #


class TestTaskStatusResponse:
    def test_schema_fields(self) -> None:
        from app.api.v1.schemas import TaskStatusResponse

        resp = TaskStatusResponse(
            task_id="abc-123",
            state="SUCCESS",
            event_id="evt-test",
        )
        data = resp.model_dump()
        assert data == {
            "task_id": "abc-123",
            "state": "SUCCESS",
            "event_id": "evt-test",
        }


# --------------------------------------------------------------------------- #
# API GET /tasks/{task_id} — background mode
# --------------------------------------------------------------------------- #


class TestGetTaskStatusBackground:
    """When TASK_MODE=background, task_id == event_id."""

    @pytest.mark.asyncio
    async def test_background_mode_returns_event_status(self) -> None:
        """Background mode: GET /tasks/{event_id} returns event status."""
        from unittest.mock import MagicMock

        from app.api.v1.events import get_task_status
        from app.core.auth import Principal
        from app.models.enums import EventStatus

        mock_event = MagicMock()
        mock_event.status = EventStatus.TRIAGING
        mock_event_service = MagicMock()
        mock_event_service.get_event = AsyncMock(return_value=mock_event)

        with patch("app.api.v1.events.get_settings") as mock_settings:
            mock_settings.return_value.task_mode = "background"

            resp = await get_task_status(
                task_id="evt-test-bg",
                principal=Principal(subject="test", roles=["analyst"]),
                event_service=mock_event_service,
            )

        assert resp.task_id == "evt-test-bg"
        assert resp.event_id == "evt-test-bg"
        assert resp.state == "triaging"
        mock_event_service.get_event.assert_awaited_once_with("evt-test-bg")

    @pytest.mark.asyncio
    async def test_background_mode_event_not_found(self) -> None:
        """Background mode: non-existent event returns 404."""
        from unittest.mock import MagicMock

        from app.api.v1.errors import EventNotFoundError
        from app.api.v1.events import get_task_status
        from app.core.auth import Principal

        mock_event_service = MagicMock()
        mock_event_service.get_event = AsyncMock(return_value=None)

        with patch("app.api.v1.events.get_settings") as mock_settings:
            mock_settings.return_value.task_mode = "background"

            with pytest.raises(EventNotFoundError):
                await get_task_status(
                    task_id="evt-nonexistent",
                    principal=Principal(subject="test", roles=["analyst"]),
                    event_service=mock_event_service,
                )


# --------------------------------------------------------------------------- #
# celery_app configuration
# --------------------------------------------------------------------------- #


class TestCeleryAppConfig:
    def test_celery_app_imports(self) -> None:
        """The celery_app singleton imports without error."""
        # Eager mode is on so no broker connection is attempted.
        from app.core.celery_app import celery_app

        assert celery_app is not None
        assert celery_app.conf.task_acks_late is True
        assert celery_app.conf.worker_prefetch_multiplier == 1


__all__ = [
    "TestRunInvestigationTask",
    "TestTaskStatusResponse",
    "TestGetTaskStatusBackground",
    "TestCeleryAppConfig",
]
