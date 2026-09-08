"""LangGraph react_node tests — optional read-only fill after evidence."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.models.react import ReActResult, ReActStopReason
from app.orchestration.workflow_graph import (
    NODE_FP_ADJUDICATION,
    NODE_GRAPH,
    NODE_REACT,
    NODE_RISK,
    build_investigation_graph,
)
from tests.test_orchestration.test_workflow_graph import (
    FakeStateMachine,
    FixedEvidencePlanPlanner,
    _agents,
    _base_state,
    _services,
)


@pytest.mark.asyncio
async def test_react_node_absent_when_disabled() -> None:
    graph = build_investigation_graph(_agents(), _services())
    assert NODE_REACT not in graph.get_graph().nodes


@pytest.mark.asyncio
async def test_react_node_skips_fill_without_react_step(monkeypatch: pytest.MonkeyPatch) -> None:
    fill = AsyncMock(return_value=ReActResult(stop_reason=ReActStopReason.FINISHED))
    monkeypatch.setattr("app.orchestration.react_fill.run_readonly_react_fill", fill)
    services = _services(FakeStateMachine())
    services["react_enabled"] = True
    services["llm_client"] = object()
    services["react_executor_factory"] = object()
    agents = _agents()
    agents["planner_agent"] = FixedEvidencePlanPlanner()
    final = await build_investigation_graph(agents, services).ainvoke(
        _base_state(defer_response_execution=True),
        {"configurable": {"thread_id": "evt-react-skip"}},
    )
    assert NODE_REACT in final["node_trace"]
    fill.assert_not_awaited()


@pytest.mark.asyncio
async def test_react_node_calls_fill_when_plan_has_react_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fill = AsyncMock(return_value=ReActResult(stop_reason=ReActStopReason.FINISHED))
    monkeypatch.setattr("app.orchestration.react_fill.run_readonly_react_fill", fill)
    services = _services(FakeStateMachine())
    services["react_enabled"] = True
    services["llm_client"] = object()
    services["react_executor_factory"] = object()
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(defer_response_execution=True),
        {"configurable": {"thread_id": "evt-react-fill"}},
    )
    assert NODE_REACT in final["node_trace"]
    fill.assert_awaited()
    assert NODE_FP_ADJUDICATION in final["node_trace"]
    assert NODE_GRAPH in final["node_trace"]
    assert NODE_RISK in final["node_trace"]
    assert final.get("halted") is not True


@pytest.mark.asyncio
async def test_react_node_error_does_not_halt(monkeypatch: pytest.MonkeyPatch) -> None:
    fill = AsyncMock(return_value=ReActResult(stop_reason=ReActStopReason.ERROR))
    monkeypatch.setattr("app.orchestration.react_fill.run_readonly_react_fill", fill)
    services = _services(FakeStateMachine())
    services["react_enabled"] = True
    services["llm_client"] = object()
    services["react_executor_factory"] = object()
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(defer_response_execution=True),
        {"configurable": {"thread_id": "evt-react-error"}},
    )
    assert final.get("halted") is not True
    flags = final.get("degraded_flags") or []
    assert any("react_fill_degraded" in str(flag) for flag in flags)
