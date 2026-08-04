"""ISSUE-168: production DI must share ONE ConvergenceGuard instance.

The SuperAgent graph, the LLM client and the ToolExecutor must count tool and
LLM traffic against the same real ``ConvergenceGuard`` (the default
``NoopConvergenceGuard`` on the executor singleton must be replaced, and the
LLM client must receive the same instance — no second counter set).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1 import deps
from app.core.config import Settings
from app.core.llm.base import (
    InMemoryLLMCallAuditRecorder,
    LLMMessage,
    LLMProviderError,
)
from app.core.llm.mock_client import MockLLMClient
from app.models.enums import ToolCategory
from app.models.tool_meta import (
    RoutingKind,
    ToolMeta,
    ToolResultStatus,
)
from app.orchestration import convergence_guard as guard_module
from app.orchestration.convergence_guard import ConvergenceGuard
from app.tools.executor import NoopConvergenceGuard, ToolExecutor
from app.tools.registry import ToolRegistry
from app.tools.retry import RetryPolicy

MESSAGES = [LLMMessage(role="user", content="Classify this event")]


def _settings() -> Settings:
    return Settings(
        APP_ENV="development",
        LLM_MODE="mock",
        EMBEDDING_MODE="mock",
        ORCHESTRATION_MODE="graph",
        REACT_ENABLED=False,
    )


def _patch_deps_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shared dependency stubs for a real ``_build_investigation_agents`` run."""
    monkeypatch.setattr(deps, "get_settings", lambda: _settings())
    monkeypatch.setattr(deps, "get_event_service", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_state_machine", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(
        deps,
        "_get_wm",
        AsyncMock(
            return_value=MagicMock(
                for_writer=MagicMock(return_value=MagicMock()),
            )
        ),
    )
    monkeypatch.setattr(deps, "_get_session_factory", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_redis", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_context_store", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_degraded_flags", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_event_bus", lambda: MagicMock())
    monkeypatch.setattr(deps, "get_graph_sync_service", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_audit_log", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_decision_record_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_tool_call_log_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_tool_call_grant_service", lambda: MagicMock())
    # Probe of the (mock) playbook release would run a DB query on the stub
    # session; short-circuit it the same way test_retrieval_pipeline_wiring
    # does so the stack assembly stays focused on the guard wiring.
    from app.playbook.resources import LoadedPlaybookResources

    mock_playbook_resources = LoadedPlaybookResources(
        status="ready",
        mode="test",
        playbook_kb_service=MagicMock(),
        playbook_release_service=MagicMock(),
        active_release_id="pbrel-test",
    )
    monkeypatch.setattr(
        "app.playbook.resources.get_loaded_playbook_resources",
        lambda **_kwargs: mock_playbook_resources,
    )
    monkeypatch.setattr(
        "app.playbook.resources.probe_playbook_resources",
        AsyncMock(return_value=mock_playbook_resources),
    )
    monkeypatch.setattr(
        "app.services.false_positive_matcher.FalsePositiveMatcher",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.profile_service.ProfileService",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.memory_governance.MemoryGovernance",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr("app.agents.memory_agent.MemoryAgent", lambda **_k: MagicMock())


@pytest.mark.asyncio
async def test_build_investigation_agents_wires_single_real_convergence_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LLM client and ToolExecutor must receive the SAME real ConvergenceGuard."""
    _patch_deps_dependencies(monkeypatch)

    llm_kwargs: dict[str, Any] = {}

    def _capture_llm(**kwargs: Any) -> MagicMock:
        llm_kwargs.update(kwargs)
        return MagicMock()

    # spec=ToolExecutor keeps the attribute surface honest (e.g. the
    # audit_service isinstance check must still work as in production).
    mock_executor = MagicMock(
        spec=ToolExecutor,
        audit_service=MagicMock(),
        budget_service=None,
    )
    monkeypatch.setattr("app.core.llm.factory.get_llm_client", _capture_llm)
    monkeypatch.setattr("app.tools.executor.get_tool_executor", lambda: mock_executor)

    deps.reset_deps()
    try:
        stack = await deps._build_investigation_agents()
    finally:
        deps.reset_deps()

    guard = stack["convergence_guard"]
    assert isinstance(guard, ConvergenceGuard)
    assert not isinstance(guard, NoopConvergenceGuard)
    # One instance everywhere: stack entry == LLM client == ToolExecutor.
    assert llm_kwargs["convergence_guard"] is guard
    assert mock_executor.convergence_guard is guard


@pytest.mark.asyncio
async def test_get_super_agent_reuses_stack_convergence_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_super_agent must reuse the stack guard, never build a second one."""
    sentinel_guard: Any = object()
    graph_kwargs: dict[str, Any] = {}
    constructed: list[dict[str, Any]] = []

    def _boom_construct(**kwargs: Any) -> Any:
        constructed.append(kwargs)
        raise AssertionError("get_super_agent must not construct a second ConvergenceGuard")

    settings = _settings()
    fake_stack = {
        "settings": settings,
        "wm": MagicMock(for_writer=MagicMock(return_value=MagicMock())),
        "llm_client": MagicMock(),
        "convergence_guard": sentinel_guard,
        "budget_service": MagicMock(),
        "output_guard": MagicMock(),
        "trace_service": MagicMock(),
        "triage": MagicMock(),
        "evidence": MagicMock(),
        "rag": MagicMock(),
        "risk": MagicMock(),
        "report": MagicMock(),
        "graph_agent": MagicMock(),
        "storyline_service": MagicMock(),
        "memory": MagicMock(),
        "event_service": MagicMock(),
        "context_store": MagicMock(),
        "tool_executor": MagicMock(),
        "session_factory": MagicMock(),
        "state_machine": MagicMock(),
        "degraded_flags": MagicMock(),
        "react_executor_factory": MagicMock(),
    }
    monkeypatch.setattr(deps, "_get_investigation_stack", AsyncMock(return_value=fake_stack))
    monkeypatch.setattr(deps, "get_event_lease", lambda: MagicMock())
    monkeypatch.setattr(deps, "get_event_disposition_service", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_disposition_sync", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_approval_engine", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_action_execution", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_workflow_runtime", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_redis", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_audit_log", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_event_bus", lambda: MagicMock())

    monkeypatch.setattr("app.agents.planner_agent.PlannerAgent", lambda **_k: MagicMock())
    monkeypatch.setattr("app.agents.response_agent.ResponseAgent", lambda **_k: MagicMock())
    monkeypatch.setattr("app.agents.verify_agent.VerifyAgent", lambda **_k: MagicMock())
    monkeypatch.setattr(
        "app.orchestration.convergence_guard.ConvergenceGuard",
        _boom_construct,
    )
    monkeypatch.setattr(
        "app.orchestration.checkpointer.build_checkpointer",
        AsyncMock(return_value=MagicMock()),
    )

    def _capture_graph(agents: Any, services: dict[str, Any], **kwargs: Any) -> MagicMock:
        graph_kwargs.update(kwargs)
        graph_kwargs["agents"] = agents
        graph_kwargs["services"] = services
        return MagicMock()

    monkeypatch.setattr(
        "app.orchestration.workflow_graph.build_investigation_graph",
        _capture_graph,
    )
    monkeypatch.setattr("app.agents.super_agent.SuperAgent", lambda **_k: MagicMock(**_k))

    deps.reset_deps()
    try:
        await deps.get_super_agent()
    finally:
        deps.reset_deps()

    assert constructed == []
    # services["convergence_guard"] is what the investigation graph consumes.
    assert graph_kwargs["services"]["convergence_guard"] is sentinel_guard


@pytest.mark.asyncio
async def test_shared_guard_blocks_llm_call_after_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LLM client wired with the real guard stops once MAX_TOTAL_LLM_CALLS is hit."""
    monkeypatch.setattr(guard_module, "MAX_TOTAL_LLM_CALLS", 1)
    guard = ConvergenceGuard()
    client = MockLLMClient(
        audit_recorder=InMemoryLLMCallAuditRecorder(),
        convergence_guard=guard,
    )

    # BaseLLMClient records the step BEFORE checking should_stop, so the
    # first call already trips a MAX_TOTAL_LLM_CALLS=1 limit.
    with pytest.raises(LLMProviderError, match="convergence guard"):
        await client.chat(
            MESSAGES,
            event_id="evt-iss168-llm",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
        )

    assert guard.get_state("evt-iss168-llm").llm_calls == 1


@pytest.mark.asyncio
async def test_shared_guard_blocks_tool_dispatch_after_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ToolExecutor wired with the real guard refuses dispatch once the step cap is hit."""
    monkeypatch.setattr(guard_module, "GLOBAL_MAX_STEPS", 1)
    guard = ConvergenceGuard()

    registry = ToolRegistry()

    async def ok_execute(params: dict[str, Any]) -> dict[str, Any]:
        return {
            "call_id": "call-iss168",
            "tool_name": "fake_ok",
            "provider_name": "fake",
            "status": "success",
            "data": {"ok": True},
        }

    registry.register(
        ToolMeta(
            tool_name="fake_ok",
            tool_category=ToolCategory.QUERY,
            routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
            default_timeout_s=5.0,
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            output_schema={
                "type": "object",
                "properties": {"status": {"type": "string"}},
                "additionalProperties": True,
            },
        ),
        ok_execute,
    )
    executor = ToolExecutor(
        registry=registry,
        convergence_guard=guard,
        sleep=lambda _delay: asyncio.sleep(0),
    )

    event_id = "evt-iss168-tool"
    first = await executor.call("fake_ok", {}, event_id, retry_policy=RetryPolicy(max_retries=0))
    assert first.status == ToolResultStatus.SUCCESS

    # Executor checks should_stop BEFORE record_step per dispatch, so the
    # second call trips GLOBAL_MAX_STEPS=1 (total_steps already == 1).
    second = await executor.call("fake_ok", {}, event_id, retry_policy=RetryPolicy(max_retries=0))
    assert second.status == ToolResultStatus.FAILED
    assert second.error_detail == "convergence guard stopped execution"


@pytest.mark.asyncio
async def test_get_pipeline_wires_stack_convergence_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AnalysisOnlyPipeline must own the shared stack guard (reset lifecycle)."""
    sentinel_guard: Any = object()
    pipeline_kwargs: dict[str, Any] = {}

    def _capture_pipeline(**kwargs: Any) -> MagicMock:
        pipeline_kwargs.update(kwargs)
        return MagicMock()

    settings = _settings()
    fake_stack = {
        "settings": settings,
        "wm": MagicMock(for_writer=MagicMock(return_value=MagicMock())),
        "llm_client": MagicMock(),
        "convergence_guard": sentinel_guard,
        "budget_service": MagicMock(),
        "output_guard": MagicMock(),
        "trace_service": MagicMock(),
        "triage": MagicMock(),
        "evidence": MagicMock(),
        "rag": MagicMock(),
        "risk": MagicMock(),
        "report": MagicMock(),
        "graph_agent": MagicMock(),
        "storyline_service": MagicMock(),
        "memory": MagicMock(),
        "event_service": MagicMock(),
        "context_store": MagicMock(),
        "tool_executor": MagicMock(),
        "session_factory": MagicMock(),
        "state_machine": MagicMock(),
        "degraded_flags": MagicMock(),
        "react_executor_factory": MagicMock(),
    }
    monkeypatch.setattr(deps, "_get_investigation_stack", AsyncMock(return_value=fake_stack))
    monkeypatch.setattr(deps, "_get_agent_task_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_agent_artifact_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_content_projection_service", lambda: MagicMock())
    monkeypatch.setattr(
        "app.services.analysis_only_pipeline.AnalysisOnlyPipeline",
        _capture_pipeline,
    )

    deps.reset_deps()
    try:
        await deps.get_pipeline()
    finally:
        deps.reset_deps()

    assert pipeline_kwargs["convergence_guard"] is sentinel_guard


@pytest.mark.asyncio
async def test_tool_traffic_trips_llm_stop_on_shared_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tool steps and LLM calls share ONE counter set: tool traffic can trip the
    stop that blocks a subsequent LLM call (and vice versa)."""
    monkeypatch.setattr(guard_module, "GLOBAL_MAX_STEPS", 1)
    guard = ConvergenceGuard()

    registry = ToolRegistry()

    async def ok_execute(params: dict[str, Any]) -> dict[str, Any]:
        return {
            "call_id": "call-iss168",
            "tool_name": "fake_ok",
            "provider_name": "fake",
            "status": "success",
            "data": {"ok": True},
        }

    registry.register(
        ToolMeta(
            tool_name="fake_ok",
            tool_category=ToolCategory.QUERY,
            routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
            default_timeout_s=5.0,
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            output_schema={
                "type": "object",
                "properties": {"status": {"type": "string"}},
                "additionalProperties": True,
            },
        ),
        ok_execute,
    )
    executor = ToolExecutor(
        registry=registry,
        convergence_guard=guard,
        sleep=lambda _delay: asyncio.sleep(0),
    )
    client = MockLLMClient(
        audit_recorder=InMemoryLLMCallAuditRecorder(),
        convergence_guard=guard,
    )

    event_id = "evt-iss168-cross"
    # One tool dispatch fills the GLOBAL_MAX_STEPS=1 budget.
    result = await executor.call("fake_ok", {}, event_id, retry_policy=RetryPolicy(max_retries=0))
    assert result.status == ToolResultStatus.SUCCESS

    # The same guard's state (total_steps == 1) now blocks the LLM path.
    with pytest.raises(LLMProviderError, match="convergence guard"):
        await client.chat(
            MESSAGES,
            event_id=event_id,
            agent_name="TriageAgent",
            prompt_key="triage_extract",
        )
