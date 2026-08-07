"""Production DI must not hardcode demo scenario_id (ISSUE-199)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1 import deps

_DEPS_PATH = Path(__file__).resolve().parents[2] / "app" / "api" / "v1" / "deps.py"


def test_deps_module_has_no_hardcoded_insider_scenario_id() -> None:
    source = _DEPS_PATH.read_text(encoding="utf-8")
    assert 'scenario_id="insider_data_exfiltration"' not in source
    assert "scenario_id='insider_data_exfiltration'" not in source


def _patch_production_graph_build_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_stack = {
        "wm": MagicMock(for_writer=MagicMock(return_value=MagicMock())),
        "llm_client": MagicMock(),
        "budget_service": MagicMock(),
        "output_guard": MagicMock(),
        "trace_service": MagicMock(),
        "event_service": MagicMock(),
        "session_factory": MagicMock(),
        "tool_executor": MagicMock(),
        "playbook_kb_service": MagicMock(),
        "playbook_release_service": MagicMock(),
        "triage": MagicMock(),
        "evidence": MagicMock(),
        "risk": MagicMock(),
        "report": MagicMock(),
        "rag": MagicMock(),
        "graph_agent": MagicMock(),
        "state_machine": MagicMock(),
        "context_store": MagicMock(),
        "degraded_flags": MagicMock(),
    }
    monkeypatch.setattr(deps, "_get_investigation_stack", AsyncMock(return_value=fake_stack))
    monkeypatch.setattr(deps, "_get_event_bus", lambda: MagicMock())
    monkeypatch.setattr(deps, "get_event_disposition_service", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_disposition_sync", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_approval_engine", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "get_action_execution", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_workflow_runtime", AsyncMock(return_value=MagicMock()))
    monkeypatch.setattr(deps, "_get_redis", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_agent_task_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_agent_artifact_service", lambda: MagicMock())
    monkeypatch.setattr(deps, "_get_content_projection_service", lambda: MagicMock())
    monkeypatch.setattr(
        "app.orchestration.checkpointer.build_checkpointer",
        AsyncMock(return_value=MagicMock()),
    )
    monkeypatch.setattr("app.agents.response_agent.ResponseAgent", lambda **_k: MagicMock())
    monkeypatch.setattr("app.agents.verify_agent.VerifyAgent", lambda **_k: MagicMock())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("missing_name", "apply_missing"),
    [
        (
            "response_agent",
            lambda mp: mp.setattr("app.agents.response_agent.ResponseAgent", lambda **_k: None),
        ),
        (
            "verify_agent",
            lambda mp: mp.setattr("app.agents.verify_agent.VerifyAgent", lambda **_k: None),
        ),
        (
            "approval_engine",
            lambda mp: mp.setattr(deps, "get_approval_engine", AsyncMock(return_value=None)),
        ),
        (
            "action_execution",
            lambda mp: mp.setattr(deps, "get_action_execution", AsyncMock(return_value=None)),
        ),
        (
            "disposition_sync",
            lambda mp: mp.setattr(deps, "get_disposition_sync", AsyncMock(return_value=None)),
        ),
        (
            "event_disposition",
            lambda mp: mp.setattr(
                deps, "get_event_disposition_service", AsyncMock(return_value=None)
            ),
        ),
    ],
)
async def test_production_graph_fails_fast_on_missing_di(
    monkeypatch: pytest.MonkeyPatch,
    missing_name: str,
    apply_missing: Callable[[pytest.MonkeyPatch], None],
) -> None:
    """ISSUE-218: production graph build must fail fast when key DI is missing."""
    _patch_production_graph_build_baseline(monkeypatch)
    apply_missing(monkeypatch)

    with pytest.raises(RuntimeError, match="miswired") as exc_info:
        await deps._build_production_investigation_graph(
            planner_agent=MagicMock(),
            convergence_guard=MagicMock(),
        )
    assert missing_name in str(exc_info.value)


@pytest.mark.asyncio
async def test_production_graph_response_agent_default_scenario_id_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _capture_response(**kwargs: Any) -> MagicMock:
        captured["response"] = kwargs
        return MagicMock()

    _patch_production_graph_build_baseline(monkeypatch)
    monkeypatch.setattr("app.agents.response_agent.ResponseAgent", _capture_response)
    monkeypatch.setattr(
        "app.orchestration.workflow_graph.build_investigation_graph",
        lambda *_a, **_k: MagicMock(),
    )

    await deps._build_production_investigation_graph(
        planner_agent=MagicMock(),
        convergence_guard=MagicMock(),
    )

    assert captured["response"].get("scenario_id") is None
    assert "insider_data_exfiltration" not in str(captured)
