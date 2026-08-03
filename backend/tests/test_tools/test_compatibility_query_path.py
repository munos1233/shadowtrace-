"""Compatibility query path tests (ISSUE-134)."""

from __future__ import annotations

import uuid

import pytest

from app.core.config import Settings
from app.core.errors import ToolCallGrantUnavailableError
from app.models.enums import ToolCategory
from app.models.tool_meta import RoutingKind, ToolMeta
from app.providers.tools.mock_provider import MockToolProvider, bind_mock_tool_provider
from app.tools.circuit_breaker import CircuitBreakerRegistry
from app.tools.compatibility_query_path import COMPATIBILITY_PATH_NAME, CompatibilityQueryToolPath
from app.tools.executor import ToolExecutor
from app.tools.mock_state import MockEnvironmentState
from app.tools.registry import ToolRegistry

WINDOW = {
    "start": "2024-06-15T08:00:00Z",
    "end": "2024-06-15T10:00:00Z",
}


def _query_meta(name: str) -> ToolMeta:
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.QUERY,
        routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
        input_schema={"type": "object", "properties": {}, "additionalProperties": True},
        output_schema={"type": "object", "additionalProperties": True},
    )


def _response_meta(name: str) -> ToolMeta:
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.RESPONSE,
        routing_kind=RoutingKind.OWNER_ROUTED,
        input_schema={"type": "object", "properties": {}, "additionalProperties": True},
        output_schema={"type": "object", "additionalProperties": True},
    )


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.auto_discover()
    return reg


@pytest.fixture
def mock_provider() -> MockToolProvider:
    return MockToolProvider(MockEnvironmentState())


@pytest.fixture
def compat_path(
    registry: ToolRegistry, mock_provider: MockToolProvider
) -> CompatibilityQueryToolPath:
    settings = Settings(
        TOOL_CALL_COMPATIBILITY_PATH_ENABLED=True,
        TOOL_CALL_GRANT_REQUIRED=True,
    )
    inner = ToolExecutor(
        registry=registry,
        breaker_registry=CircuitBreakerRegistry(),
        provider_context=lambda: bind_mock_tool_provider(mock_provider),
    )
    return CompatibilityQueryToolPath(inner=inner, registry=registry, settings=settings)


@pytest.mark.asyncio
async def test_compatibility_path_allows_evidence_query(
    compat_path: CompatibilityQueryToolPath,
) -> None:
    result = await compat_path.call(
        "query_dns",
        {"domain": "example.com", "time_range": WINDOW},
        f"evt-compat-{uuid.uuid4().hex[:8]}",
    )
    assert result.tool_name == "query_dns"


@pytest.mark.asyncio
async def test_compatibility_path_rejects_non_allowlisted_tool(
    registry: ToolRegistry,
    mock_provider: MockToolProvider,
) -> None:
    settings = Settings(TOOL_CALL_COMPATIBILITY_PATH_ENABLED=True)
    inner = ToolExecutor(
        registry=registry,
        breaker_registry=CircuitBreakerRegistry(),
        provider_context=lambda: bind_mock_tool_provider(mock_provider),
    )
    path = CompatibilityQueryToolPath(inner=inner, registry=registry, settings=settings)
    with pytest.raises(ToolCallGrantUnavailableError, match="not allowed"):
        await path.call("isolate_host", {}, "evt-compat-x")


@pytest.mark.asyncio
async def test_compatibility_path_disabled_fail_closed(
    registry: ToolRegistry,
    mock_provider: MockToolProvider,
) -> None:
    settings = Settings(TOOL_CALL_COMPATIBILITY_PATH_ENABLED=False)
    inner = ToolExecutor(
        registry=registry,
        breaker_registry=CircuitBreakerRegistry(),
        provider_context=lambda: bind_mock_tool_provider(mock_provider),
    )
    path = CompatibilityQueryToolPath(inner=inner, registry=registry, settings=settings)
    with pytest.raises(ToolCallGrantUnavailableError, match="disabled"):
        await path.call("query_dns", {}, "evt-compat-x")


def test_compatibility_path_is_named_and_observable(
    compat_path: CompatibilityQueryToolPath,
) -> None:
    assert compat_path.path_name == COMPATIBILITY_PATH_NAME
    assert compat_path.policy_version


@pytest.mark.asyncio
async def test_compatibility_path_sunset_blocks_calls(
    registry: ToolRegistry,
    mock_provider: MockToolProvider,
) -> None:
    settings = Settings(
        TOOL_CALL_COMPATIBILITY_PATH_ENABLED=True,
        TOOL_CALL_COMPATIBILITY_SUNSET="2000-01-01",
    )
    inner = ToolExecutor(
        registry=registry,
        breaker_registry=CircuitBreakerRegistry(),
        provider_context=lambda: bind_mock_tool_provider(mock_provider),
    )
    path = CompatibilityQueryToolPath(inner=inner, registry=registry, settings=settings)
    with pytest.raises(ToolCallGrantUnavailableError, match="sunset"):
        await path.call("query_dns", {}, "evt-compat-sunset")
