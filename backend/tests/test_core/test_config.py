"""Production fail-closed settings validation (ISSUE-093 §5).

A ``production`` deployment silently running mock sources/tools/disposition
or simulation mode is a security incident, not a warning: ``Settings``
construction must raise ``ConfigurationError`` and prevent the process from
starting.
"""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import ConfigurationError


@pytest.fixture(autouse=True)
def _no_dev_auth_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep DEV_AUTH_TOKENS out of the environment for deterministic tests.

    ISSUE-217: a non-empty DEV_AUTH_TOKENS is a production fail-closed
    violation, so acceptance tests must not accidentally inherit one from the
    host environment.
    """
    monkeypatch.delenv("DEV_AUTH_TOKENS", raising=False)


def _base_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "APP_ENV": "production",
        "SOURCE_MODE": "live_edr",
        "TOOL_MODE": "live",
        "DISPOSITION_MODE": "live_xdr",
        "DISPOSITION_ADAPTER_KIND": "http",
        "LLM_MODE": "openai_compatible",
        "EMBEDDING_MODE": "remote",
        "SIMULATION_ENABLED": False,
    }
    kwargs.update(overrides)
    return kwargs


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
