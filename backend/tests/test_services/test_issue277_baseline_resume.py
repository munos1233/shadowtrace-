"""ISSUE-277 baseline + wired `_maybe_resume` probes."""

from __future__ import annotations

import logging
import sys
from types import SimpleNamespace

import pytest

from app.models.enums import ExecutionSubstate
from app.services.disposition_sync_service import DispositionSyncService


class _ResumeIntent:
    def __init__(self, intent_id: str) -> None:
        self.intent_id = intent_id


@pytest.mark.asyncio
async def test_baseline_maybe_resume_skips_manual_resolution_when_unwired() -> None:
    """Without ManualResolutionService, MANUAL_RESOLUTION must not direct-resume."""
    calls: list[str] = []

    async def _resume(event_id: str) -> None:
        calls.append(event_id)

    class _Session:
        async def scalar(self, _stmt):  # noqa: ANN001
            return ExecutionSubstate.MANUAL_RESOLUTION.value

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class _Factory:
        def __call__(self):
            return _Session()

    svc = DispositionSyncService(
        _Factory(),  # type: ignore[arg-type]
        context_store=None,
        adapter_registry={},
        resume_investigation=_resume,
    )
    await svc._maybe_resume("evt-manual-hold")
    assert calls == []


@pytest.mark.asyncio
async def test_maybe_resume_manual_resolution_enqueues_durable_intent() -> None:
    """Wired path must enqueue durable intent instead of calling _resume."""
    resume_calls: list[str] = []
    created: list[str] = []
    scheduled: list[str | None] = []

    async def _resume(event_id: str) -> None:
        resume_calls.append(event_id)

    class _Manual:
        async def create_or_replay_resume_intent(self, event_id: str, **_kwargs: object):
            created.append(event_id)
            return _ResumeIntent(f"intent-{event_id}")

        def schedule_dispatch(
            self,
            *,
            event_id: str | None = None,
            intent_id: str | None = None,
            trigger: str = "unspecified",
        ) -> None:
            del event_id, trigger
            scheduled.append(intent_id)

    class _Session:
        async def scalar(self, _stmt):  # noqa: ANN001
            return ExecutionSubstate.MANUAL_RESOLUTION.value

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class _Factory:
        def __call__(self):
            return _Session()

    svc = DispositionSyncService(
        _Factory(),  # type: ignore[arg-type]
        context_store=None,
        adapter_registry={},
        resume_investigation=_resume,
        manual_resolution=_Manual(),  # type: ignore[arg-type]
    )
    await svc._maybe_resume("evt-manual-wired")
    assert resume_calls == []
    assert created == ["evt-manual-wired"]
    assert scheduled == ["intent-evt-manual-wired"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resume_intent",
    [
        object(),
        SimpleNamespace(intent_id=None),
        SimpleNamespace(intent_id=""),
        SimpleNamespace(intent_id=" "),
    ],
    ids=["missing-attr", "none", "empty", "whitespace"],
)
async def test_maybe_resume_manual_resolution_requires_intent_id(
    monkeypatch: pytest.MonkeyPatch,
    resume_intent: object,
) -> None:
    """Missing intent_id on resume intent must not silently schedule dispatch."""
    resume_calls: list[str] = []
    created: list[str] = []
    scheduled: list[str] = []
    warning_messages: list[str] = []
    warning_exc_types: list[type[BaseException] | None] = []

    service_logger = logging.getLogger("app.services.disposition_sync_service")
    original_warning = service_logger.warning

    def _capture_warning(message: str, *args: object, **kwargs: object) -> None:
        warning_messages.append(message % args if args else str(message))
        exc_info = kwargs.get("exc_info")
        if exc_info is True:
            warning_exc_types.append(sys.exc_info()[0])
        elif isinstance(exc_info, tuple) and exc_info:
            warning_exc_types.append(exc_info[0])  # type: ignore[arg-type]
        else:
            warning_exc_types.append(None)
        return original_warning(message, *args, **kwargs)

    monkeypatch.setattr(service_logger, "warning", _capture_warning)

    async def _resume(event_id: str) -> None:
        resume_calls.append(event_id)

    class _Manual:
        async def create_or_replay_resume_intent(self, event_id: str, **_kwargs: object):
            del _kwargs
            created.append(event_id)
            return resume_intent

        def schedule_dispatch(
            self,
            *,
            event_id: str | None = None,
            intent_id: str | None = None,
            trigger: str = "unspecified",
        ) -> None:
            del event_id, intent_id, trigger
            scheduled.append("yes")

    class _Session:
        async def scalar(self, _stmt):  # noqa: ANN001
            return ExecutionSubstate.MANUAL_RESOLUTION.value

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class _Factory:
        def __call__(self):
            return _Session()

    svc = DispositionSyncService(
        _Factory(),  # type: ignore[arg-type]
        context_store=None,
        adapter_registry={},
        resume_investigation=_resume,
        manual_resolution=_Manual(),  # type: ignore[arg-type]
    )
    await svc._maybe_resume("evt-manual-missing-intent")
    assert created == ["evt-manual-missing-intent"]
    assert resume_calls == []
    assert scheduled == []
    assert any(
        "failed to enqueue durable graph resume intent" in message for message in warning_messages
    )
    assert AttributeError in warning_exc_types
