"""ISSUE-169: production VerifyAgent must receive the shared OutputGuard.

VerifyAgent previously skipped the unified structured-output guard (BaseAgent
skips validation when ``output_guard is None``), leaving verification output
outside the same protection contract as the other production agents.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1 import deps
from app.core.config import Settings


def _settings() -> Settings:
    return Settings(
        APP_ENV="development",
        LLM_MODE="mock",
        EMBEDDING_MODE="mock",
        ORCHESTRATION_MODE="graph",
        REACT_ENABLED=False,
    )


@pytest.mark.asyncio
async def test_production_verify_agent_receives_shared_output_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VerifyAgent must run verification output through the same OutputGuard
    instance as ResponseAgent / the other production agents."""
    sentinel_guard: Any = object()
    verify_kwargs: dict[str, Any] = {}
    response_kwargs: dict[str, Any] = {}

    def _capture_verify(**kwargs: Any) -> MagicMock:
        verify_kwargs.update(kwargs)
        return MagicMock()

    def _capture_response(**kwargs: Any) -> MagicMock:
        response_kwargs.update(kwargs)
        return MagicMock()

    settings = _settings()
    fake_stack = {
        "settings": settings,
        "wm": MagicMock(for_writer=MagicMock(return_value=MagicMock())),
        "llm_client": MagicMock(),
        "convergence_guard": MagicMock(),
        "budget_service": MagicMock(),
        "output_guard": sentinel_guard,
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
    monkeypatch.setattr(deps, "_get_event_bus", lambda: MagicMock())
    monkeypatch.setattr(deps, "get_event_disposition_service", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_disposition_sync", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_approval_engine", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_action_execution", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_workflow_runtime", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_agent_task_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_agent_artifact_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_content_projection_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_redis", lambda: MagicMock())
    monkeypatch.setattr(
        "app.orchestration.checkpointer.build_checkpointer",
        AsyncMock(return_value=MagicMock()),
    )
    monkeypatch.setattr(
        "app.orchestration.workflow_graph.build_investigation_graph",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr("app.agents.response_agent.ResponseAgent", _capture_response)
    monkeypatch.setattr("app.agents.verify_agent.VerifyAgent", _capture_verify)

    deps.reset_deps()
    try:
        await deps._build_production_investigation_graph(
            planner_agent=MagicMock(),
            convergence_guard=MagicMock(),
        )
    finally:
        deps.reset_deps()

    # Both ResponseAgent (pre-existing contract) and VerifyAgent (ISSUE-169)
    # must receive the very same OutputGuard instance from the stack.
    assert verify_kwargs["output_guard"] is sentinel_guard
    assert response_kwargs["output_guard"] is sentinel_guard
