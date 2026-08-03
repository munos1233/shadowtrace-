"""Shadow ReAct runtime wiring tests (ISSUE-135 / #641 Phase A)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import Settings
from app.models.shadow_run import ShadowQueryPivotRequest, ShadowRunStatus
from app.models.tool_call_grant import (
    BoundExecutionPrincipal,
    ToolCallGrant,
    ToolCallGrantIssueResult,
    ToolCallGrantScope,
    ToolCallMode,
)
from app.orchestration.react_engine import ReadOnlyReActExecutor
from app.services.safe_tool_projection import SafeToolProjectionService
from app.services.shadow_query_pivot_service import ShadowQueryPivotService
from app.services.shadow_run_service import ShadowRunService
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry
from app.tools.tool_call_runtime import ReactToolExecutorFactory


@pytest.mark.asyncio
async def test_for_shadow_run_mints_shadow_grant() -> None:
    registry = ToolRegistry()
    registry.auto_discover()
    inner = ToolExecutor(registry=registry)
    now = datetime.now(tz=UTC)
    grant = ToolCallGrant(
        grant_id="tcg-shadow01",
        mode=ToolCallMode.SHADOW,
        namespace_key="shadow:sr-test-001",
        shadow_run_id="sr-test-001",
        event_id="evt-shadow-factory",
        tenant_id="tenant-a",
        scope=ToolCallGrantScope(allowed_tools=["query_dns"]),
        execution_principal=BoundExecutionPrincipal(
            principal_id="tcp-shadow01",
            agent_name="shadow_query_pivot",
            actor_type="react_engine",
        ),
        max_calls=3,
        valid_from=now,
        expires_at=now.replace(year=now.year + 1),
        policy_version="tool-grant-v1",
        created_at=now,
    )
    grant_service = MagicMock()
    grant_service.available = True
    grant_service.issue_grant = AsyncMock(
        return_value=ToolCallGrantIssueResult(grant=grant, grant_token="token-shadow")
    )
    grant_service.load_grant_trusted = AsyncMock(return_value=grant)

    factory = ReactToolExecutorFactory(
        inner_executor=inner,
        grant_service=grant_service,
        settings=Settings(TOOL_CALL_GRANT_REQUIRED=True),
        projection_service=SafeToolProjectionService(registry),
    )
    react_exec = await factory.for_shadow_run(
        "evt-shadow-factory",
        shadow_run_id="sr-test-001",
        tenant_id="tenant-a",
        allowed_agents={"mock_query_retrieval": AsyncMock(return_value={"status": "success"})},
        max_calls=3,
    )
    assert isinstance(react_exec, ReadOnlyReActExecutor)
    call_request = grant_service.issue_grant.await_args[0][0]
    assert call_request.mode is ToolCallMode.SHADOW
    assert call_request.shadow_run_id == "sr-test-001"


def test_assert_shadow_pivot_config_requires_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.errors import ConfigurationError
    from app.orchestration.orchestration_config import assert_shadow_pivot_config
    from app.rag.resources import LoadedRetrievalResources

    attached = LoadedRetrievalResources(
        status="ready",
        mode="mock",
        pipeline=MagicMock(),
    )
    monkeypatch.setattr(
        "app.rag.resources.peek_loaded_retrieval_resources",
        lambda: attached,
    )

    with pytest.raises(ConfigurationError, match="TOOL_CALL_GRANT_REQUIRED"):
        assert_shadow_pivot_config(
            Settings(REACT_SHADOW_PIVOT_ENABLED=True, TOOL_CALL_GRANT_REQUIRED=False)
        )

    with pytest.raises(ConfigurationError, match="KNOWLEDGE_RELEASE_REQUIRE_ACTIVE"):
        assert_shadow_pivot_config(
            Settings(
                REACT_SHADOW_PIVOT_ENABLED=True,
                TOOL_CALL_GRANT_REQUIRED=True,
                KNOWLEDGE_RELEASE_REQUIRE_ACTIVE=False,
            )
        )

    with pytest.raises(ConfigurationError, match="RETRIEVAL_FIXTURE_FALLBACK"):
        assert_shadow_pivot_config(
            Settings(
                REACT_SHADOW_PIVOT_ENABLED=True,
                TOOL_CALL_GRANT_REQUIRED=True,
                KNOWLEDGE_RELEASE_REQUIRE_ACTIVE=True,
                RETRIEVAL_FIXTURE_FALLBACK=True,
            )
        )

    assert_shadow_pivot_config(
        Settings(
            REACT_SHADOW_PIVOT_ENABLED=True,
            TOOL_CALL_GRANT_REQUIRED=True,
            KNOWLEDGE_RELEASE_REQUIRE_ACTIVE=True,
            RETRIEVAL_FIXTURE_FALLBACK=False,
        )
    )

    assert_shadow_pivot_config(
        Settings(REACT_SHADOW_PIVOT_ENABLED=False, TOOL_CALL_GRANT_REQUIRED=False)
    )


def test_assert_shadow_pivot_config_requires_attached_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.errors import ConfigurationError
    from app.orchestration.orchestration_config import assert_shadow_pivot_config

    monkeypatch.setattr(
        "app.rag.resources.peek_loaded_retrieval_resources",
        lambda: None,
    )
    with pytest.raises(ConfigurationError, match="RetrievalPipeline"):
        assert_shadow_pivot_config(
            Settings(
                REACT_SHADOW_PIVOT_ENABLED=True,
                TOOL_CALL_GRANT_REQUIRED=True,
                KNOWLEDGE_RELEASE_REQUIRE_ACTIVE=True,
                RETRIEVAL_FIXTURE_FALLBACK=False,
            )
        )


@pytest.mark.asyncio
async def test_pivot_rejected_when_pipeline_unavailable() -> None:
    pivot = ShadowQueryPivotService(
        ShadowRunService(MagicMock()),
        settings=Settings(REACT_SHADOW_PIVOT_ENABLED=True),
    )
    result = await pivot.run_pivot(
        ShadowQueryPivotRequest(
            event_id="evt-no-pipeline",
            tenant_id="tenant-a",
            principal="investigation:test",
            trace_id="trace-no-pipeline",
            goal="test",
        ),
        llm_client=MagicMock(),
        react_factory=MagicMock(),
        pipeline=None,  # type: ignore[arg-type]
    )
    assert result.status is ShadowRunStatus.REJECTED
    assert "retrieval_pipeline_unavailable" in result.rejected_reasons
    assert result.shadow_run_id == ""


@pytest.mark.asyncio
async def test_for_shadow_run_scopes_query_tools_only() -> None:
    registry = ToolRegistry()
    registry.auto_discover()
    inner = ToolExecutor(registry=registry)
    now = datetime.now(tz=UTC)
    grant = ToolCallGrant(
        grant_id="tcg-shadow02",
        mode=ToolCallMode.SHADOW,
        namespace_key="shadow:sr-test-002",
        shadow_run_id="sr-test-002",
        event_id="evt-shadow-scope",
        tenant_id="tenant-a",
        scope=ToolCallGrantScope(allowed_tools=["query_dns"]),
        execution_principal=BoundExecutionPrincipal(
            principal_id="tcp-shadow02",
            agent_name="shadow_query_pivot",
            actor_type="react_engine",
        ),
        max_calls=2,
        valid_from=now,
        expires_at=now.replace(year=now.year + 1),
        policy_version="tool-grant-v1",
        created_at=now,
    )
    grant_service = MagicMock()
    grant_service.available = True
    grant_service.issue_grant = AsyncMock(
        return_value=ToolCallGrantIssueResult(grant=grant, grant_token="token-shadow")
    )
    grant_service.load_grant_trusted = AsyncMock(return_value=grant)

    factory = ReactToolExecutorFactory(
        inner_executor=inner,
        grant_service=grant_service,
        settings=Settings(TOOL_CALL_GRANT_REQUIRED=True),
        projection_service=SafeToolProjectionService(registry),
    )
    await factory.for_shadow_run(
        "evt-shadow-scope",
        shadow_run_id="sr-test-002",
        tenant_id="tenant-a",
        allowed_agents={"mock_query_retrieval": AsyncMock(return_value={"status": "success"})},
        allowed_tools=["write_disposition"],
        max_calls=2,
    )
    call_request = grant_service.issue_grant.await_args[0][0]
    assert "write_disposition" not in call_request.scope.allowed_tools
    assert call_request.scope.allowed_tools


@pytest.mark.asyncio
async def test_pivot_rejected_when_disabled() -> None:
    pivot = ShadowQueryPivotService(
        ShadowRunService(MagicMock()),
        settings=Settings(REACT_SHADOW_PIVOT_ENABLED=False),
    )
    result = await pivot.run_pivot(
        ShadowQueryPivotRequest(
            event_id="evt-disabled",
            tenant_id="tenant-a",
            principal="investigation:test",
            trace_id="trace-disabled",
            goal="test",
        ),
        llm_client=MagicMock(),
        react_factory=MagicMock(),
        pipeline=MagicMock(),
    )
    assert result.status is ShadowRunStatus.REJECTED
    assert "shadow_pivot_disabled" in result.rejected_reasons
