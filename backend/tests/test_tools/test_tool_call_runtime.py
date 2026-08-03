"""Tool call runtime wiring tests (ISSUE-134)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import Settings
from app.core.errors import ToolCallGrantUnavailableError
from app.models.tool_call_grant import ToolCallGrantIssueResult, ToolCallMode
from app.services.safe_tool_projection import SafeToolProjectionService
from app.tools.compatibility_query_path import COMPATIBILITY_PATH_NAME, CompatibilityQueryToolPath
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry
from app.tools.tool_call_runtime import ReactToolExecutorFactory, build_evidence_query_executor


def test_build_evidence_query_executor_wraps_compatibility_path() -> None:
    registry = ToolRegistry()
    inner = ToolExecutor(registry=registry)
    settings = Settings(TOOL_CALL_COMPATIBILITY_PATH_ENABLED=True)
    wrapped = build_evidence_query_executor(inner, settings=settings)
    assert isinstance(wrapped, CompatibilityQueryToolPath)
    assert wrapped.path_name == COMPATIBILITY_PATH_NAME


@pytest.mark.asyncio
async def test_react_factory_fail_closed_when_grant_required_and_unavailable() -> None:
    registry = ToolRegistry()
    inner = ToolExecutor(registry=registry)
    grant_service = MagicMock()
    grant_service.available = False
    factory = ReactToolExecutorFactory(
        inner_executor=inner,
        grant_service=grant_service,
        settings=Settings(TOOL_CALL_GRANT_REQUIRED=True),
        projection_service=SafeToolProjectionService(registry),
    )
    with pytest.raises(ToolCallGrantUnavailableError):
        await factory.for_event("evt-react-test", tenant_id="tenant-a")


@pytest.mark.asyncio
async def test_react_factory_uses_plain_executor_when_grant_not_required() -> None:
    from app.orchestration.react_engine import ReadOnlyReActExecutor

    registry = ToolRegistry()
    inner = ToolExecutor(registry=registry)
    grant_service = MagicMock()
    grant_service.available = True
    factory = ReactToolExecutorFactory(
        inner_executor=inner,
        grant_service=grant_service,
        settings=Settings(TOOL_CALL_GRANT_REQUIRED=False),
        projection_service=SafeToolProjectionService(registry),
    )
    react_exec = await factory.for_event("evt-react-plain", tenant_id="tenant-a")
    assert isinstance(react_exec, ReadOnlyReActExecutor)
    grant_service.issue_grant.assert_not_called()


@pytest.mark.asyncio
async def test_react_factory_idempotent_replay_uses_trusted_load() -> None:
    from datetime import UTC, datetime

    from app.models.tool_call_grant import (
        BoundExecutionPrincipal,
        ToolCallGrant,
        ToolCallGrantScope,
    )
    from app.orchestration.react_engine import ReadOnlyReActExecutor

    registry = ToolRegistry()
    registry.auto_discover()
    inner = ToolExecutor(registry=registry)
    now = datetime.now(tz=UTC)
    grant = ToolCallGrant(
        grant_id="tcg-replay01",
        mode=ToolCallMode.PRODUCTION,
        namespace_key="production:evt-react-replay",
        event_id="evt-react-replay",
        tenant_id="tenant-a",
        scope=ToolCallGrantScope(allowed_tools=["query_dns"]),
        execution_principal=BoundExecutionPrincipal(
            principal_id="tcp-replay01",
            agent_name="react_engine",
            actor_type="react_engine",
        ),
        max_calls=5,
        valid_from=now,
        expires_at=now.replace(year=now.year + 1),
        policy_version="tool-grant-v1",
        created_at=now,
    )
    grant_service = MagicMock()
    grant_service.available = True
    grant_service.issue_grant = AsyncMock(
        return_value=ToolCallGrantIssueResult(grant=grant, grant_token="")
    )
    grant_service.load_grant_trusted = AsyncMock(return_value=grant)
    factory = ReactToolExecutorFactory(
        inner_executor=inner,
        grant_service=grant_service,
        settings=Settings(TOOL_CALL_GRANT_REQUIRED=True, EMBEDDING_MODE="mock"),
        projection_service=SafeToolProjectionService(registry),
    )
    react_exec = await factory.for_event("evt-react-replay", tenant_id="tenant-a")
    assert isinstance(react_exec, ReadOnlyReActExecutor)
    grant_service.load_grant_trusted.assert_awaited_once_with("tcg-replay01")


@pytest.mark.asyncio
async def test_react_factory_grant_scope_matches_plan_step() -> None:
    from datetime import UTC, datetime

    from app.models.agent_io import PlanStep
    from app.models.tool_call_grant import (
        BoundExecutionPrincipal,
        ToolCallGrant,
        ToolCallGrantCreateRequest,
        ToolCallGrantScope,
    )
    from app.orchestration.react_engine import ReadOnlyReActExecutor

    registry = ToolRegistry()
    registry.auto_discover()
    inner = ToolExecutor(registry=registry)
    now = datetime.now(tz=UTC)
    captured: dict[str, object] = {}

    async def _issue_grant(request: ToolCallGrantCreateRequest) -> ToolCallGrantIssueResult:
        captured["allowed_tools"] = list(request.scope.allowed_tools)
        captured["plan_step_id"] = request.plan_step_id
        grant = ToolCallGrant(
            grant_id="tcg-scope01",
            mode=ToolCallMode.PRODUCTION,
            namespace_key="production:evt-react-scope",
            event_id="evt-react-scope",
            tenant_id="tenant-a",
            scope=ToolCallGrantScope(allowed_tools=list(request.scope.allowed_tools)),
            execution_principal=BoundExecutionPrincipal(
                principal_id="tcp-scope01",
                agent_name="react_engine",
                actor_type="react_engine",
            ),
            max_calls=5,
            valid_from=now,
            expires_at=now.replace(year=now.year + 1),
            policy_version="tool-grant-v1",
            created_at=now,
        )
        return ToolCallGrantIssueResult(grant=grant, grant_token="scope-token")

    grant_service = MagicMock()
    grant_service.available = True
    grant_service.issue_grant = AsyncMock(side_effect=_issue_grant)
    factory = ReactToolExecutorFactory(
        inner_executor=inner,
        grant_service=grant_service,
        settings=Settings(TOOL_CALL_GRANT_REQUIRED=True, EMBEDDING_MODE="mock"),
        projection_service=SafeToolProjectionService(registry),
    )
    step = PlanStep(
        step_order=2,
        step_goal="Fill evidence gaps",
        assigned_agent="tool_agent",
        required_tools=["query_dns"],
        success_criteria="gap closed",
    )
    react_exec = await factory.for_event(
        "evt-react-scope",
        tenant_id="tenant-a",
        plan_step=step,
    )
    assert isinstance(react_exec, ReadOnlyReActExecutor)
    assert captured["allowed_tools"] == ["query_dns"]
    assert captured["plan_step_id"] == "react-step-2"


@pytest.mark.asyncio
async def test_react_factory_reuses_grant_on_step_retry() -> None:
    """Same event+plan_step must use stable idempotency key for grant replay."""
    from datetime import UTC, datetime

    from app.models.agent_io import PlanStep
    from app.models.tool_call_grant import (
        BoundExecutionPrincipal,
        ToolCallGrant,
        ToolCallGrantCreateRequest,
        ToolCallGrantScope,
    )
    from app.orchestration.react_engine import DEFAULT_TOOL_CALL_BUDGET, ReadOnlyReActExecutor
    from app.services.tool_call_grant_service import build_react_grant_request

    registry = ToolRegistry()
    registry.auto_discover()
    inner = ToolExecutor(registry=registry)
    now = datetime.now(tz=UTC)
    stored_grant = ToolCallGrant(
        grant_id="tcg-retry01",
        mode=ToolCallMode.PRODUCTION,
        namespace_key="production:evt-react-retry",
        event_id="evt-react-retry",
        tenant_id="tenant-a",
        scope=ToolCallGrantScope(allowed_tools=["query_dns"]),
        execution_principal=BoundExecutionPrincipal(
            principal_id="tcp-retry01",
            agent_name="react_engine",
            actor_type="react_engine",
        ),
        max_calls=5,
        valid_from=now,
        expires_at=now.replace(year=now.year + 1),
        policy_version="tool-grant-v1",
        created_at=now,
    )
    idempotency_keys: list[str] = []

    async def _issue_grant(request: ToolCallGrantCreateRequest) -> ToolCallGrantIssueResult:
        idempotency_keys.append(request.idempotency_key)
        if len(idempotency_keys) == 1:
            return ToolCallGrantIssueResult(grant=stored_grant, grant_token="fresh-token")
        return ToolCallGrantIssueResult(grant=stored_grant, grant_token="")

    grant_service = MagicMock()
    grant_service.available = True
    grant_service.issue_grant = AsyncMock(side_effect=_issue_grant)
    grant_service.load_grant_trusted = AsyncMock(return_value=stored_grant)
    factory = ReactToolExecutorFactory(
        inner_executor=inner,
        grant_service=grant_service,
        settings=Settings(TOOL_CALL_GRANT_REQUIRED=True, EMBEDDING_MODE="mock"),
        projection_service=SafeToolProjectionService(registry),
    )
    step = PlanStep(
        step_order=3,
        step_goal="Retry step",
        assigned_agent="tool_agent",
        required_tools=["query_dns"],
        success_criteria="ok",
    )
    expected_key = build_react_grant_request(
        event_id="evt-react-retry",
        tenant_id="tenant-a",
        allowed_tools=["query_dns"],
        plan_step_id="react-step-3",
        max_calls=max(1, DEFAULT_TOOL_CALL_BUDGET),
    ).idempotency_key

    first = await factory.for_event(
        "evt-react-retry",
        tenant_id="tenant-a",
        plan_step=step,
    )
    second = await factory.for_event(
        "evt-react-retry",
        tenant_id="tenant-a",
        plan_step=step,
    )
    assert isinstance(first, ReadOnlyReActExecutor)
    assert isinstance(second, ReadOnlyReActExecutor)
    assert idempotency_keys == [expected_key, expected_key]
    grant_service.load_grant_trusted.assert_awaited_once_with("tcg-retry01")
