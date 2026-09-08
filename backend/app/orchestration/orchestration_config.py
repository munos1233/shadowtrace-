"""Orchestration mode startup gates (ISSUE-054)."""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.core.errors import ConfigurationError
from app.services.analysis_only_pipeline import assert_analysis_only_mode


def assert_graph_orchestration_config(settings: Settings | None = None) -> None:
    """Validate SuperAgent / graph-mode configuration at startup.

    ReAct executor presence is checked separately via
    ``assert_react_executor_wired`` once the investigation stack is assembled.
    """
    settings or get_settings()


def assert_react_executor_wired(
    settings: Settings | None = None,
    *,
    executor_wired: bool,
) -> None:
    """REACT_ENABLED=true requires a ReadOnlyReActExecutor (or factory)."""
    cfg = settings or get_settings()
    if cfg.react_enabled and not executor_wired:
        raise ConfigurationError(
            "REACT_ENABLED=true requires ReadOnlyReActExecutor wiring (ISSUE-053)",
            error_code="configuration_error",
            details={"react_enabled": True, "executor_wired": False},
        )


def assert_shadow_pivot_retrieval_ready(settings: Settings | None = None) -> None:
    """Fail closed when shadow pivot is enabled but retrieval pipeline is not attached."""
    cfg = settings or get_settings()
    if not cfg.react_shadow_pivot_enabled:
        return
    from app.rag.resources import peek_loaded_retrieval_resources

    loaded = peek_loaded_retrieval_resources()
    if loaded is None or loaded.pipeline is None:
        raise ConfigurationError(
            "REACT_SHADOW_PIVOT_ENABLED=true requires an attached RetrievalPipeline",
            error_code="configuration_error",
            details={"react_shadow_pivot_enabled": True, "pipeline_attached": False},
        )


def assert_shadow_pivot_config(settings: Settings | None = None) -> None:
    """Validate shadow query pivot prerequisites at startup (#641 Phase A)."""
    cfg = settings or get_settings()
    if not cfg.react_shadow_pivot_enabled:
        return
    if not cfg.tool_call_grant_required:
        raise ConfigurationError(
            "REACT_SHADOW_PIVOT_ENABLED=true requires TOOL_CALL_GRANT_REQUIRED=true",
            error_code="configuration_error",
            details={"react_shadow_pivot_enabled": True},
        )
    if not cfg.knowledge_release_require_active:
        raise ConfigurationError(
            "REACT_SHADOW_PIVOT_ENABLED=true requires KNOWLEDGE_RELEASE_REQUIRE_ACTIVE=true",
            error_code="configuration_error",
            details={"react_shadow_pivot_enabled": True},
        )
    if cfg.retrieval_fixture_fallback:
        raise ConfigurationError(
            "REACT_SHADOW_PIVOT_ENABLED=true forbids RETRIEVAL_FIXTURE_FALLBACK=true",
            error_code="configuration_error",
            details={"react_shadow_pivot_enabled": True},
        )
    assert_shadow_pivot_retrieval_ready(cfg)


def assert_orchestration_mode(settings: Settings | None = None) -> None:
    """Apply the env gate for the active orchestration mode."""
    cfg = settings or get_settings()
    assert_shadow_pivot_config(cfg)
    mode = (cfg.orchestration_mode or "graph").strip().lower()
    if mode == "analysis_only":
        assert_analysis_only_mode(cfg)
    elif mode == "graph":
        assert_graph_orchestration_config(cfg)
    else:
        raise ConfigurationError(
            f"unsupported ORCHESTRATION_MODE: {cfg.orchestration_mode!r}",
            error_code="configuration_error",
            details={"orchestration_mode": cfg.orchestration_mode},
        )


__all__ = [
    "assert_graph_orchestration_config",
    "assert_orchestration_mode",
    "assert_react_executor_wired",
    "assert_shadow_pivot_config",
    "assert_shadow_pivot_retrieval_ready",
]
