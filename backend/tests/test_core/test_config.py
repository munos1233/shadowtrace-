"""Production fail-closed settings validation (ISSUE-093 §5).

A ``production`` deployment silently running mock sources/tools/disposition
or simulation mode is a security incident, not a warning: ``Settings``
construction must raise ``ConfigurationError`` and prevent the process from
starting.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.core.config import (
    Settings,
    TaskMode,
    is_mock_disposition_mode,
    is_mock_source_mode,
    live_reasoning_card_enabled,
)
from app.core.errors import ConfigurationError
from tests.test_support.production_settings import production_settings_kwargs


@pytest.fixture(autouse=True)
def _no_dev_auth_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep DEV_AUTH_TOKENS out of the environment for deterministic tests.

    ISSUE-217: a non-empty DEV_AUTH_TOKENS is a production fail-closed
    violation, so acceptance tests must not accidentally inherit one from the
    host environment.
    """
    monkeypatch.delenv("DEV_AUTH_TOKENS", raising=False)


def _base_kwargs(**overrides: object) -> dict[str, object]:
    return production_settings_kwargs(**overrides)


def test_production_with_all_live_modes_is_accepted() -> None:
    settings = Settings(**_base_kwargs())
    assert settings.app_env == "production"
    assert settings.production_fail_closed_violations() == []


def test_development_allows_mock_and_simulation() -> None:
    settings = Settings(
        APP_ENV="development",
        SOURCE_MODE="mock_xdr",
        TOOL_MODE="mock",
        DISPOSITION_MODE="mock_xdr",
        DISPOSITION_ADAPTER_KIND="mock",
        SIMULATION_ENABLED=True,
    )
    assert settings.production_fail_closed_violations() == []


def test_unknown_task_mode_fails_settings_construction() -> None:
    with pytest.raises(PydanticValidationError):
        Settings(TASK_MODE="celrey")


@pytest.mark.parametrize("raw_mode", ["CELERY", " celery "])
def test_task_mode_preserves_case_and_whitespace_compatibility(raw_mode: str) -> None:
    settings = Settings(TASK_MODE=raw_mode)
    assert settings.task_mode is TaskMode.CELERY


def test_development_allows_explicit_volatile_task_mode() -> None:
    settings = Settings(APP_ENV="development", TASK_MODE="background")
    assert settings.task_mode is TaskMode.BACKGROUND


def test_production_rejects_volatile_task_mode() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(**_base_kwargs(TASK_MODE="background"))
    assert "task_mode=background" in str(exc_info.value)


@pytest.mark.parametrize(
    "overrides",
    [
        {"SIMULATION_ENABLED": True},
        {"SOURCE_MODE": "mock_xdr"},
        {"TOOL_MODE": "mock"},
        {"DISPOSITION_MODE": "mock_xdr"},
        {"DISPOSITION_ADAPTER_KIND": "mock"},
        {"LLM_MODE": "mock"},
        {"EMBEDDING_MODE": "mock"},
    ],
    ids=[
        "simulation_enabled",
        "source_mode_mock",
        "tool_mode_mock",
        "disposition_mode_mock",
        "disposition_adapter_kind_mock",
        "llm_mode_mock",
        "embedding_mode_mock",
    ],
)
def test_production_rejects_any_single_mock_or_simulation_mode(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(**_base_kwargs(**overrides))
    assert exc_info.value.error_code == "configuration_error"
    assert exc_info.value.retryable is False


def test_production_rejects_multiple_mock_modes_with_all_violations_listed() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(
            **_base_kwargs(
                SIMULATION_ENABLED=True,
                SOURCE_MODE="mock_xdr",
                TOOL_MODE="mock",
            )
        )
    violations = exc_info.value.details["violations"]
    assert any("simulation_enabled" in v for v in violations)
    assert any("source_mode" in v for v in violations)
    assert any("tool_mode" in v for v in violations)


def test_app_env_matching_is_case_insensitive() -> None:
    with pytest.raises(ConfigurationError):
        Settings(**_base_kwargs(APP_ENV="Production", SIMULATION_ENABLED=True))


def test_staging_env_is_not_subject_to_production_gate() -> None:
    settings = Settings(
        APP_ENV="staging",
        SOURCE_MODE="mock_xdr",
        TOOL_MODE="mock",
        DISPOSITION_MODE="mock_xdr",
        DISPOSITION_ADAPTER_KIND="mock",
        SIMULATION_ENABLED=True,
    )
    assert settings.production_fail_closed_violations() == []


def test_llm_thinking_type_defaults_empty_and_accepts_disabled() -> None:
    settings = Settings(APP_ENV="development")
    assert settings.llm_thinking_type == ""
    disabled = Settings(APP_ENV="development", LLM_THINKING_TYPE="Disabled")
    assert disabled.llm_thinking_type == "disabled"


def test_llm_thinking_type_rejects_unknown_values() -> None:
    with pytest.raises(PydanticValidationError):
        Settings(APP_ENV="development", LLM_THINKING_TYPE="reasoner")


def test_event_chat_can_be_disabled_independently() -> None:
    settings = Settings(APP_ENV="development", EVENT_CHAT_ENABLED=False)

    assert settings.event_chat_enabled is False


def test_production_rejects_react_without_tool_call_grant() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(**_base_kwargs(REACT_ENABLED=True, TOOL_CALL_GRANT_REQUIRED=False))
    violations = exc_info.value.details["violations"]
    assert any("tool_call_grant_required" in v for v in violations)


def test_production_accepts_react_with_tool_call_grant() -> None:
    settings = Settings(**_base_kwargs(REACT_ENABLED=True, TOOL_CALL_GRANT_REQUIRED=True))
    assert settings.react_enabled is True
    assert settings.tool_call_grant_required is True
    assert settings.production_fail_closed_violations() == []


def test_production_rejects_decision_rationale_short_text() -> None:
    """ISSUE-243: production may only use off|structured for decision rationale mode."""
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(**_base_kwargs(DECISION_RATIONALE_MODE="short_text"))
    violations = exc_info.value.details["violations"]
    assert any("decision_rationale_mode=short_text" in v for v in violations)


def test_production_accepts_structured_decision_rationale_mode() -> None:
    settings = Settings(**_base_kwargs(DECISION_RATIONALE_MODE="structured"))
    assert settings.decision_rationale_mode == "structured"
    assert settings.production_fail_closed_violations() == []


def test_development_allows_trusted_proxy_with_empty_allowlist() -> None:
    settings = Settings(
        APP_ENV="development",
        TRUSTED_AUTH_PROXY_ENABLED=True,
        TRUSTED_PROXY_ALLOWLIST="",
    )
    assert settings.trusted_proxy_fail_closed_violations() == []


def test_production_rejects_trusted_proxy_with_empty_allowlist() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(
            **_base_kwargs(
                TRUSTED_AUTH_PROXY_ENABLED=True,
                TRUSTED_PROXY_ALLOWLIST="",
            )
        )
    assert exc_info.value.error_code == "configuration_error"
    assert "TRUSTED_PROXY_ALLOWLIST" in str(exc_info.value)


def test_production_rejects_trusted_proxy_with_wildcard_allowlist() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(
            **_base_kwargs(
                TRUSTED_AUTH_PROXY_ENABLED=True,
                TRUSTED_PROXY_ALLOWLIST="*",
            )
        )
    violations = exc_info.value.details["violations"]
    assert any("wildcard" in v for v in violations)


def test_production_accepts_trusted_proxy_with_explicit_allowlist() -> None:
    settings = Settings(
        **_base_kwargs(
            TRUSTED_AUTH_PROXY_ENABLED=True,
            TRUSTED_PROXY_ALLOWLIST="10.0.0.5,127.0.0.1",
        )
    )
    assert settings.trusted_proxy_fail_closed_violations() == []


def test_production_rejects_empty_socketio_cors_origins() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(
            **_base_kwargs(
                SOCKETIO_CORS_ALLOWED_ORIGINS="",
            )
        )
    violations = exc_info.value.details["violations"]
    assert any("SOCKETIO_CORS_ALLOWED_ORIGINS" in v for v in violations)


def test_production_rejects_wildcard_socketio_cors_origins() -> None:
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(
            **_base_kwargs(
                SOCKETIO_CORS_ALLOWED_ORIGINS="https://app.example,*",
            )
        )
    violations = exc_info.value.details["violations"]
    assert any("wildcard" in v for v in violations)


def test_development_defaults_socketio_cors_to_localhost() -> None:
    settings = Settings(APP_ENV="development")
    origins = settings.resolved_socketio_cors_origins()
    assert "http://localhost:5173" in origins
    assert "*" not in origins


def test_production_accepts_explicit_socketio_cors_origins() -> None:
    settings = Settings(
        **_base_kwargs(
            SOCKETIO_CORS_ALLOWED_ORIGINS="https://app.example,https://soc.example",
        )
    )
    assert settings.socketio_fail_closed_violations() == []


def test_production_rejects_dev_auth_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """ISSUE-217: DEV_AUTH_TOKENS is a fail-closed violation in production."""
    monkeypatch.setenv("DEV_AUTH_TOKENS", '{"dev-token": {"subject": "dev", "roles": ["admin"]}}')
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(**_base_kwargs())
    violations = exc_info.value.details["violations"]
    assert any("DEV_AUTH_TOKENS" in v for v in violations)
    assert "unsafe runtime configuration" in str(exc_info.value)


def test_production_accepts_blank_dev_auth_tokens() -> None:
    """ISSUE-217: an unset/blank DEV_AUTH_TOKENS stays a valid production config."""
    settings = Settings(**_base_kwargs())
    assert settings.production_fail_closed_violations() == []


def test_production_with_whitespace_app_env_rejects_dev_auth_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-217: whitespace-padded APP_ENV matches the strip() semantics of the gate."""
    monkeypatch.setenv("DEV_AUTH_TOKENS", '{"dev-token": {"subject": "dev", "roles": ["admin"]}}')
    with pytest.raises(ConfigurationError) as exc_info:
        Settings(**_base_kwargs(APP_ENV=" production "))
    violations = exc_info.value.details["violations"]
    assert any("DEV_AUTH_TOKENS" in v for v in violations)


@pytest.mark.parametrize(
    "app_env,expected",
    [
        ("production", True),
        (" production", True),
        ("production ", True),
        ("  production  ", True),
        ("Production", True),
        ("development", False),
        ("staging", False),
    ],
)
def test_is_production_strips_and_normalizes_app_env(app_env: str, expected: bool) -> None:
    """ISSUE-217: Settings.is_production() is the single source of truth."""
    settings = Settings(**_base_kwargs(APP_ENV=app_env))
    assert settings.is_production() is expected


def test_super_agent_transition_retry_settings_defaults() -> None:
    """ISSUE-234: bounded transition retry defaults are production-safe."""
    settings = Settings(APP_ENV="development")
    assert settings.super_agent_transition_max_retries == 3
    assert settings.super_agent_transition_retry_backoff_seconds == 0.2


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("mock_xdr", True),
        (" MOCK_XDR ", True),
        ("live", False),
        ("live_xdr", False),
        ("openai_compatible", False),
        ("not_mock", False),
        ("mockish", False),
        ("disabled", False),
    ],
)
def test_is_mock_disposition_mode_uses_explicit_allowlist(mode: str, expected: bool) -> None:
    """ISSUE-344: disposition mock gate must not substring-match arbitrary values."""
    assert is_mock_disposition_mode(mode) is expected


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("mock_xdr", True),
        (" MOCK_XDR ", True),
        ("live", False),
        ("not_mock", False),
        ("mockish", False),
    ],
)
def test_is_mock_source_mode_uses_explicit_allowlist(mode: str, expected: bool) -> None:
    """ISSUE-344: source mock identity must not substring-match arbitrary values."""
    assert is_mock_source_mode(mode) is expected


def test_production_does_not_reject_disposition_mode_with_mock_substring_only() -> None:
    """ISSUE-344: ``not_mock`` is not a documented mock disposition mode."""
    settings = Settings(**_base_kwargs(DISPOSITION_MODE="not_mock"))
    assert settings.production_fail_closed_violations() == []


def test_production_does_not_reject_mockish_disposition_mode() -> None:
    """ISSUE-344: ``mockish`` is not a documented mock disposition mode."""
    settings = Settings(**_base_kwargs(DISPOSITION_MODE="mockish"))
    assert settings.production_fail_closed_violations() == []


def test_auto_response_rejects_mockish_disposition_mode() -> None:
    """ISSUE-344: auto-response requires explicit mock_xdr disposition mode."""
    with pytest.raises(ConfigurationError, match="disposition_mode=mockish"):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="mockish",
        )


def test_auto_response_rejects_not_mock_disposition_mode_at_construction() -> None:
    """ISSUE-344: auto-response fail-closed rejects non-allowlisted mock substring."""
    with pytest.raises(ConfigurationError, match="disposition_mode=not_mock"):
        Settings(
            AUTO_RESPONSE_ENABLED=True,
            SOURCE_MODE="mock_xdr",
            TOOL_MODE="mock",
            DISPOSITION_MODE="not_mock",
        )


def test_live_reasoning_card_enabled_by_llm_required_or_card_name() -> None:
    assert live_reasoning_card_enabled(Settings(LLM_REQUIRED=False)) is False
    assert live_reasoning_card_enabled(Settings(LLM_REQUIRED=True)) is True
    assert (
        live_reasoning_card_enabled(
            Settings(LLM_REQUIRED=False, CERTIFICATION_CARD="live_reasoning")
        )
        is True
    )
