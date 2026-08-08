"""ToolCallGrant runtime wiring tests (ISSUE-134)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agents.evidence_agent import EvidenceAgent
from app.api.v1 import deps
from app.core.config import Settings
from app.core.llm.base import InMemoryLLMCallAuditRecorder
from app.core.llm.mock_client import MockLLMClient
from app.rag.resources import reset_loaded_retrieval_resources
from app.tools.compatibility_query_path import CompatibilityQueryToolPath
from app.tools.executor import NullAuditService


@pytest.mark.asyncio
async def test_build_investigation_agents_wires_evidence_compat_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EvidenceAgent must use the named compatibility query path wrapper."""
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
    monkeypatch.setattr(deps, "_get_event_bus", lambda: MagicMock())
    monkeypatch.setattr(deps, "get_graph_sync_service", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_audit_log", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_decision_record_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_tool_call_log_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_tool_call_grant_service", lambda: MagicMock())

    mock_executor = MagicMock(audit_service=NullAuditService(), budget_service=None)
    monkeypatch.setattr(
        "app.core.llm.factory.get_llm_client",
        lambda **kwargs: MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
    )
    monkeypatch.setattr("app.tools.executor.get_tool_executor", lambda: mock_executor)
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
    monkeypatch.setattr(
        "app.services.knowledge_release_service.KnowledgeReleaseService.get_active_release",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr("app.agents.memory_agent.MemoryAgent", lambda **_k: MagicMock())

    reset_loaded_retrieval_resources()
    deps.reset_deps()
    try:
        stack = await deps._build_investigation_agents()
    finally:
        deps.reset_deps()
        reset_loaded_retrieval_resources()

    evidence = stack["evidence"]
    assert isinstance(evidence, EvidenceAgent)
    assert isinstance(evidence.tool_executor, CompatibilityQueryToolPath)
    assert stack["react_executor_factory"] is not None
