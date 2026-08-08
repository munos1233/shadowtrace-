"""Production approval_wait → END → resume_investigation CI regression (ISSUE-194).

Unlike ``test_autonomous_mock_full_loop_e2e`` scenario B (which uses
``build_approval_engine()`` without ``resume_investigation`` and manually calls
``ActionExecutionService.execute_action``), this test wires production deps and
asserts the graph continues through execute/verify after ``engine.approve()``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import get_approval_engine, get_super_agent, reset_deps
from app.core.auth import Principal
from app.core.config import get_settings
from app.db import models as orm
from app.models.enums import ActionLevel, ActionStatus, EventStatus, ExecutionSubstate
from app.orchestration.workflow_graph import NODE_APPROVAL_WAIT, NODE_EXECUTE, NODE_VERIFY
from app.services.context_service import EventContextStore
from app.tasks import investigation_tasks as tasks
from tests.integration.autonomous_e2e.helpers import (
    build_autonomous_stack as _build_autonomous_stack,
)
from tests.integration.autonomous_e2e.helpers import (
    incident_source,
    mock_autonomous_settings,
    patch_production_session_factory,
    select_human_gated_action,
    unique_id,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.orchestration,
    pytest.mark.e2e_response,
    pytest.mark.usefixtures("clean_state"),
]


async def _checkpoint_snapshot(event_id: str) -> dict[str, Any]:
    agent = await get_super_agent()
    graph = getattr(agent, "_investigation_graph", None)
    if graph is None:
        return {"graph_wired": False}
    config = {"configurable": {"thread_id": event_id}}
    snap = await graph.aget_state(config)
    if snap is None or not snap.values:
        return {"graph_wired": True, "checkpoint_present": False}
    return {
        "graph_wired": True,
        "checkpoint_present": True,
        "halted": snap.values.get("halted"),
        "needs_approval_wait": snap.values.get("needs_approval_wait"),
        "execution_substate": snap.values.get("execution_substate"),
        "event_status": snap.values.get("event_status"),
        "next": list(snap.next or ()),
        "node_trace": list(snap.values.get("node_trace") or []),
    }


@pytest.mark.asyncio
async def test_production_resume_hook_after_real_approval_wait_halt(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    context_store: EventContextStore,
) -> None:
    """CI contract: approve triggers deps resume hook — no manual execute_action bypass."""
    reset_deps()
    get_settings.cache_clear()
    monkeypatch.setenv("ORCHESTRATION_MODE", "graph")
    monkeypatch.setenv("TASK_MODE", "background")
    get_settings.cache_clear()

    settings = mock_autonomous_settings(AUTO_RESPONSE_ENABLED=True)
    events, _intent_service, _store = _build_autonomous_stack(
        session_factory,
        redis_client,
        settings=settings,
    )
    ingest = await events.ingest_source_object(
        incident_source(object_id=unique_id("inc-prod-resume-ci"))
    )
    event_id = ingest.event_id
    patch_production_session_factory(monkeypatch, session_factory)

    result = await tasks.execute_investigation(event_id, include_response_execution=True)
    assert result["status"] == "completed"

    async with session_factory() as session:
        pending_rows = list(
            await session.scalars(
                select(orm.Action).where(
                    orm.Action.event_id == event_id,
                    orm.Action.status == ActionStatus.WAITING_APPROVAL.value,
                )
            )
        )
    target = select_human_gated_action(pending_rows, prefer_level=ActionLevel.L2)
    assert target.action_level in {
        ActionLevel.L2.value,
        ActionLevel.L3.value,
        ActionLevel.L4.value,
        ActionLevel.L5.value,
    }

    pre_checkpoint = await _checkpoint_snapshot(event_id)
    assert pre_checkpoint.get("checkpoint_present") is True
    assert pre_checkpoint.get("halted") is True
    assert pre_checkpoint.get("execution_substate") == ExecutionSubstate.WAITING_APPROVAL.value
    assert pre_checkpoint.get("next") == []
    pre_trace = pre_checkpoint.get("node_trace") or []
    assert NODE_APPROVAL_WAIT in pre_trace
    assert NODE_EXECUTE not in pre_trace

    from app.api.v1 import deps

    resume_hook_calls: list[str] = []
    real_resume = deps._resume_investigation

    async def _tracking_resume(event_id: str) -> None:
        resume_hook_calls.append(event_id)
        await real_resume(event_id)

    monkeypatch.setattr(deps, "_resume_investigation", _tracking_resume)
    reset_deps()
    get_settings.cache_clear()

    engine = await get_approval_engine()
    await engine.approve(
        target.action_id,
        Principal(subject="ci-resume-approver", roles=["approver"]),
        "production resume hook regression",
        f"dec-resume-{uuid.uuid4().hex[:10]}",
    )

    async with session_factory() as session:
        db_status_after = await session.scalar(
            select(orm.SecurityEvent.status).where(orm.SecurityEvent.event_id == event_id)
        )
        verify_trace = await session.scalar(
            select(orm.AgentTrace.trace_id).where(
                orm.AgentTrace.event_id == event_id,
                orm.AgentTrace.agent_name == "verify_agent",
            )
        )
        approved_status = await session.scalar(
            select(orm.Action.status).where(orm.Action.action_id == target.action_id)
        )

    post_checkpoint = await _checkpoint_snapshot(event_id)
    verification = await context_store.get(event_id, "verification_result")
    node_trace = post_checkpoint.get("node_trace") or []

    assert approved_status == ActionStatus.APPROVED.value
    assert resume_hook_calls == [event_id], (
        "approve must invoke production resume_investigation hook"
    )
    assert db_status_after != EventStatus.FAILED.value, (
        f"status={db_status_after} trace={node_trace}"
    )
    assert post_checkpoint.get("needs_approval_wait") is False, post_checkpoint
    assert NODE_EXECUTE in node_trace, node_trace
    assert NODE_VERIFY in node_trace or verify_trace is not None or bool(verification), (
        f"resume must reach verify tail; trace={node_trace}"
    )

    reset_deps()
    get_settings.cache_clear()
