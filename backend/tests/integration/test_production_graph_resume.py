"""Production approval_wait → END → resume_investigation CI regression (ISSUE-194).

ISSUE-282 / ID-REL-001 adds isolated consecutive probes for the SUSPECTED
``needs_approval_wait=false`` + ``halted=true`` tail-chain anomaly after
production approval resume.
"""

from __future__ import annotations

import uuid
from pathlib import Path
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
from tests.integration.resume_isolation_support import (
    ISOLATION_PASSES,
    IsolationRunRecord,
    assert_not_reproduced,
    assert_resume_snapshot_coherent,
    build_artifact,
    capture_graph_checkpoint_snapshot,
    summarize_consecutive_runs,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.orchestration,
    pytest.mark.e2e_response,
    pytest.mark.usefixtures("clean_state"),
]


async def _run_production_approval_wait_resume_probe(
    *,
    monkeypatch: pytest.MonkeyPatch,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    context_store: EventContextStore,
    run_index: int,
) -> IsolationRunRecord:
    """Single isolated production approval_wait → approve → resume probe."""
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
        incident_source(object_id=unique_id(f"inc-prod-resume-{run_index}"))
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

    agent = await get_super_agent()
    graph = getattr(agent, "_investigation_graph", None)
    pre_resume = await capture_graph_checkpoint_snapshot(
        graph=graph,
        event_id=event_id,
        phase="pre_resume",
        session_factory=session_factory,
        graph_wired=graph is not None,
    )
    assert pre_resume.checkpoint_present is True
    assert pre_resume.halted is True
    assert pre_resume.execution_substate == ExecutionSubstate.WAITING_APPROVAL.value
    assert pre_resume.next_nodes == ()
    assert NODE_APPROVAL_WAIT in pre_resume.node_trace
    assert NODE_EXECUTE not in pre_resume.node_trace

    from app.api.v1 import deps

    resume_hook_calls: list[str] = []
    real_resume = deps._resume_investigation

    async def _tracking_resume(resume_event_id: str) -> None:
        resume_hook_calls.append(resume_event_id)
        await real_resume(resume_event_id)

    monkeypatch.setattr(deps, "_resume_investigation", _tracking_resume)
    reset_deps()
    get_settings.cache_clear()

    engine = await get_approval_engine()
    outcome = await engine.approve(
        target.action_id,
        Principal(subject="ci-resume-approver", roles=["approver"]),
        "production resume hook regression",
        f"dec-resume-{uuid.uuid4().hex[:10]}",
    )
    assert outcome.resume_status == "ok", (
        f"approve must resume graph; outcome={outcome!r} pre={pre_resume.to_dict()}"
    )
    assert resume_hook_calls == [event_id], (
        "approve must invoke production resume_investigation hook"
    )

    agent_after = await get_super_agent()
    graph_after = getattr(agent_after, "_investigation_graph", None)
    post_resume = await capture_graph_checkpoint_snapshot(
        graph=graph_after,
        event_id=event_id,
        phase="post_resume",
        session_factory=session_factory,
        graph_wired=graph_after is not None,
    )
    verification = await context_store.get(event_id, "verification_result")
    node_trace = post_resume.node_trace

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

    assert approved_status == ActionStatus.APPROVED.value
    assert db_status_after != EventStatus.FAILED.value, (
        f"status={db_status_after} trace={node_trace}"
    )
    assert post_resume.needs_approval_wait is False, post_resume.to_dict()
    assert NODE_EXECUTE in node_trace, node_trace
    assert NODE_VERIFY in node_trace or verify_trace is not None or bool(verification), (
        f"resume must reach verify tail; trace={node_trace}"
    )
    assert_resume_snapshot_coherent(post_resume)

    reset_deps()
    get_settings.cache_clear()

    artifact = build_artifact(
        phenomenon="approval_resume_halted_stale",
        pre_resume=pre_resume,
        post_resume=post_resume,
        run_index=run_index,
    )
    return IsolationRunRecord(run_index=run_index, artifact=artifact)


@pytest.mark.asyncio
async def test_production_resume_hook_after_real_approval_wait_halt(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    context_store: EventContextStore,
    tmp_path: Path,
) -> None:
    """ISSUE-282 / ID-REL-001: isolated production approval_wait resume probe.

    Wires production deps (not runner-owned resume bypass), records resume
    before/after snapshots, and runs ``ISOLATION_PASSES`` consecutive probes.
    """
    from tests.integration.integration_fixtures import (
        _clear_shadowtrace_keys,
        _truncate_business_tables,
    )

    records: list[IsolationRunRecord] = []
    for run_index in range(1, ISOLATION_PASSES + 1):
        if run_index > 1:
            await _truncate_business_tables(session_factory)
            await _clear_shadowtrace_keys(redis_client)
            reset_deps()
            get_settings.cache_clear()
        record = await _run_production_approval_wait_resume_probe(
            monkeypatch=monkeypatch,
            session_factory=session_factory,
            redis_client=redis_client,
            context_store=context_store,
            run_index=run_index,
        )
        assert_not_reproduced(record.artifact)
        records.append(record)

    summary = summarize_consecutive_runs(records)
    assert summary.verdict == "NOT_REPRODUCED"
    summary.write_json(tmp_path / "issue-282-approval-resume-artifact.json")
