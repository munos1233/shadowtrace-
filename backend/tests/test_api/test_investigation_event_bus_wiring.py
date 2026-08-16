"""ISSUE-075: investigation stack Agents must receive EventBus for live status."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1 import deps
from app.core.config import Settings


class _SentinelBus:
    """Unique EventBus stand-in for identity asserts."""


@pytest.mark.asyncio
async def test_build_investigation_agents_wires_event_bus(monkeypatch: pytest.MonkeyPatch) -> None:
    """Triage/Evidence/RAG/Risk/Report must share the same EventBus instance."""
    bus = _SentinelBus()
    captured: dict[str, Any] = {}

    def _capture(name: str) -> Any:
        def _factory(**kwargs: Any) -> MagicMock:
            captured[name] = kwargs.get("event_bus")
            agent = MagicMock()
            agent.agent_name = name
            agent.event_bus = kwargs.get("event_bus")
            return agent

        return _factory

    monkeypatch.setattr(deps, "_get_event_bus", lambda: bus)
    monkeypatch.setattr(
        deps,
        "get_settings",
        lambda: Settings(
            APP_ENV="development",
            LLM_MODE="mock",
            EMBEDDING_MODE="mock",
            ORCHESTRATION_MODE="graph",
            REACT_ENABLED=False,
        ),
    )
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
    monkeypatch.setattr(deps, "get_graph_sync_service", AsyncMock(return_value=MagicMock()))

    monkeypatch.setattr("app.agents.triage_agent.TriageAgent", _capture("triage"))
    monkeypatch.setattr("app.agents.evidence_agent.EvidenceAgent", _capture("evidence"))
    monkeypatch.setattr("app.agents.graph_agent.GraphAgent", _capture("graph"))
    monkeypatch.setattr("app.agents.rag_agent.RAGAgent", _capture("rag"))
    monkeypatch.setattr("app.agents.risk_agent.RiskAgent", _capture("risk"))
    monkeypatch.setattr("app.agents.report_agent.ReportAgent", _capture("report"))
    monkeypatch.setattr(
        "app.services.budget_service.BudgetService",
        lambda **kwargs: MagicMock(),
    )
    monkeypatch.setattr("app.core.guardrails.OutputGuard", lambda **kwargs: MagicMock())
    monkeypatch.setattr(
        "app.services.agent_trace_service.AgentTraceService",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.core.llm.factory.get_llm_client",
        lambda **kwargs: MagicMock(),
    )
    monkeypatch.setattr(
        "app.tools.executor.get_tool_executor",
        lambda: MagicMock(),
    )
    # Probe of the (mock) playbook release runs a DB query on the stub
    # session; short-circuit it like test_retrieval_pipeline_wiring does.
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
        "app.core.embedding.service.EmbeddingService",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.knowledge_store.KnowledgeStore",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.case_kb_service.CaseKBService",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.false_positive_matcher.FalsePositiveMatcher",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr(
        "app.services.profile_service.ProfileService",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr("app.agents.memory_agent.MemoryAgent", _capture("memory"))

    deps.reset_deps()
    try:
        stack = await deps._build_investigation_agents()
    finally:
        deps.reset_deps()

    assert stack["triage"].event_bus is bus
    assert stack["evidence"].event_bus is bus
    assert stack["rag"].event_bus is bus
    assert stack["risk"].event_bus is bus
    assert stack["report"].event_bus is bus
    assert stack["graph_agent"].event_bus is bus
    assert stack["memory"].event_bus is bus
    wired = ("triage", "evidence", "rag", "risk", "report", "graph", "memory")
    assert all(captured[name] is bus for name in wired)


@pytest.mark.asyncio
async def test_planner_and_response_receive_event_bus(monkeypatch: pytest.MonkeyPatch) -> None:
    """Planner (get_super_agent) and Response (graph build) must get EventBus."""
    bus = _SentinelBus()
    planner_bus: Any = None
    response_bus: Any = None

    class _FakePlanner:
        def __init__(self, **kwargs: Any) -> None:
            nonlocal planner_bus
            planner_bus = kwargs.get("event_bus")
            self.event_bus = planner_bus

    class _FakeResponse:
        def __init__(self, **kwargs: Any) -> None:
            nonlocal response_bus
            response_bus = kwargs.get("event_bus")
            self.event_bus = response_bus

    class _FakeVerify:
        def __init__(self, **kwargs: Any) -> None:
            self.event_bus = kwargs.get("event_bus")

    monkeypatch.setattr(deps, "_get_event_bus", lambda: bus)
    settings = Settings(
        APP_ENV="development",
        LLM_MODE="mock",
        EMBEDDING_MODE="mock",
        ORCHESTRATION_MODE="graph",
        REACT_ENABLED=False,
    )
    monkeypatch.setattr(deps, "get_settings", lambda: settings)

    fake_stack = {
        "settings": settings,
        "wm": MagicMock(for_writer=MagicMock(return_value=MagicMock())),
        "llm_client": MagicMock(),
        "convergence_guard": MagicMock(),
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
        "output_quality_evaluator": MagicMock(),
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

    monkeypatch.setattr("app.agents.planner_agent.PlannerAgent", _FakePlanner)
    monkeypatch.setattr("app.agents.response_agent.ResponseAgent", _FakeResponse)
    monkeypatch.setattr("app.agents.verify_agent.VerifyAgent", _FakeVerify)
    monkeypatch.setattr(
        "app.orchestration.convergence_guard.ConvergenceGuard",
        lambda **kwargs: MagicMock(),
    )
    monkeypatch.setattr(
        "app.orchestration.checkpointer.build_checkpointer",
        AsyncMock(return_value=MagicMock()),
    )
    monkeypatch.setattr(
        "app.orchestration.workflow_graph.build_investigation_graph",
        lambda *_a, **_k: MagicMock(),
    )
    monkeypatch.setattr("app.agents.super_agent.SuperAgent", lambda **kwargs: MagicMock(**kwargs))

    deps.reset_deps()
    try:
        await deps.get_super_agent()
    finally:
        deps.reset_deps()

    assert planner_bus is bus
    assert response_bus is bus
