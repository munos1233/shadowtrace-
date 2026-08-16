"""Shared production Settings kwargs for fail-closed acceptance tests (ISSUE-363).

Production fail-closed (ISSUE-217) rejects default ``TASK_MODE=background``; any
test that constructs ``Settings`` or monkeypatches ``APP_ENV=production`` must
also supply celery execution and live-shaped runtime modes so unrelated gates do
not mask the assertion under test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.config import Settings

if TYPE_CHECKING:
    from pytest import MonkeyPatch


def production_settings_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "APP_ENV": "production",
        "SOURCE_MODE": "live_edr",
        "TOOL_MODE": "live",
        "DISPOSITION_MODE": "live_xdr",
        "DISPOSITION_ADAPTER_KIND": "http",
        "LLM_MODE": "openai_compatible",
        "EMBEDDING_MODE": "remote",
        "SIMULATION_ENABLED": False,
        "SOCKETIO_CORS_ALLOWED_ORIGINS": "https://app.example",
        "TASK_MODE": "celery",
    }
    kwargs.update(overrides)
    return kwargs


def production_settings(**overrides: object) -> Settings:
    return Settings(**production_settings_kwargs(**overrides))


def apply_production_env(monkeypatch: MonkeyPatch, **overrides: object) -> None:
    """Monkeypatch env vars for API tests that exercise production auth gates."""
    for key, value in production_settings_kwargs(**overrides).items():
        monkeypatch.setenv(key, str(value))
