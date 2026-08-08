"""Unit tests for graph checkpoint resume helpers (ISSUE-192 / ISSUE-196 / ISSUE-205)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.enums import (
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    WritebackStatus,
)
from app.orchestration.graph_resume import (
    _reconcile_verify_resume_patch,
    resume_investigation_from_checkpoint,
)
from app.orchestration.graph_resume_observability import GraphResumeFailedError

OutboxRow = tuple[str, str | None]


class _SessionFactory:
    def __init__(
        self,
        status: str,
        *,
        outbox_rows: list[OutboxRow] | None = None,
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows or []

    def __call__(self) -> _SessionCtx:
        return _SessionCtx(self._status, outbox_rows=self._outbox_rows)


class _OutboxExecuteResult:
    def __init__(self, rows: list[OutboxRow]) -> None:
        self._rows = rows

    def all(self) -> list[OutboxRow]:
        return self._rows


class _ScalarSession:
    def __init__(
        self,
        status: str,
        *,
        outbox_rows: list[OutboxRow] | None = None,
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows or []

    async def scalar(self, _stmt: Any) -> str:
        return self._status

    async def execute(self, _stmt: Any) -> _OutboxExecuteResult:
        return _OutboxExecuteResult(self._outbox_rows)


class _SessionCtx:
    def __init__(
        self,
        status: str,
        *,
        outbox_rows: list[OutboxRow] | None = None,
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows

    async def __aenter__(self) -> _ScalarSession:
        return _ScalarSession(
            self._status,
            outbox_rows=self._outbox_rows,
        )

    async def __aexit__(self, *_args: Any) -> None:
        return None


def _terminal_confirmed() -> list[OutboxRow]:
    return [
        (
            DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            WritebackStatus.CONFIRMED.value,
        )
    ]


@pytest.mark.asyncio
async def test_reconcile_verify_resume_clears_stale_manual_when_terminal_confirmed() -> None:
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=_terminal_confirmed(),
        ),
        "evt-196",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
            "disposition_policy": DispositionPolicy.REQUIRED.value,
        },
    )
    assert patch["halted"] is False
    assert patch["verify_need_manual_resolution"] is False
    assert patch["execution_substate"] == ExecutionSubstate.NONE.value
    assert "verify_degraded=True" not in patch.get("degraded_flags", [])


@pytest.mark.asyncio
async def test_reconcile_verify_resume_keeps_legitimate_manual_hold() -> None:
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=_terminal_confirmed(),
        ),
        "evt-196-legit",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "degraded_flags": ["missing_response_plan_for_required_policy=True"],
            "disposition_policy": DispositionPolicy.REQUIRED.value,
        },
    )
    assert patch.get("halted") is False
    assert "verify_need_manual_resolution" not in patch


@pytest.mark.asyncio
async def test_reconcile_verify_resume_keeps_manual_when_no_outbox() -> None:
    """ISSUE-196: verify_degraded without outbox evidence must stay manual."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[],
        ),
        "evt-196-no-outbox",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
            "disposition_policy": DispositionPolicy.REQUIRED.value,
        },
    )
    assert patch.get("halted") is False
    assert patch.get("verify_need_manual_resolution") is not False


@pytest.mark.asyncio
async def test_reconcile_verify_resume_clears_stale_manual_when_terminal_accepted() -> None:
    """ISSUE-196: ACCEPTED terminal outbox is sufficient to resume toward REPORTING."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[
                (
                    DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    WritebackStatus.ACCEPTED.value,
                )
            ],
        ),
        "evt-196-accepted",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
            "disposition_policy": DispositionPolicy.REQUIRED.value,
        },
    )
    assert patch["halted"] is False
    assert patch["verify_need_manual_resolution"] is False


@pytest.mark.asyncio
async def test_reconcile_verify_resume_keeps_manual_for_entity_only_accepted() -> None:
    """ISSUE-205: entity outbox alone must not clear manual without terminal writeback."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[
                (
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    WritebackStatus.ACCEPTED.value,
                ),
                (
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    WritebackStatus.ACCEPTED.value,
                ),
            ],
        ),
        "evt-205-entity-only",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
            "disposition_policy": DispositionPolicy.REQUIRED.value,
        },
    )
    assert patch.get("halted") is False
    assert patch.get("verify_need_manual_resolution") is not False


@pytest.mark.asyncio
async def test_reconcile_verify_resume_clears_manual_when_terminal_and_entity_accepted() -> None:
    """ISSUE-205: terminal + entity outboxes resolved clears stale manual."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[
                (
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    WritebackStatus.ACCEPTED.value,
                ),
                (
                    DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    WritebackStatus.ACCEPTED.value,
                ),
            ],
        ),
        "evt-205-terminal-entity",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
            "disposition_policy": DispositionPolicy.REQUIRED.value,
        },
    )
    assert patch["verify_need_manual_resolution"] is False


@pytest.mark.asyncio
async def test_reconcile_verify_resume_keeps_disposition_writeback_blocked_manual() -> None:
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=_terminal_confirmed(),
        ),
        "evt-205-blocked",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "degraded_flags": ["disposition_writeback_blocked=capability_unknown"],
            "disposition_policy": DispositionPolicy.REQUIRED.value,
        },
    )
    assert "verify_need_manual_resolution" not in patch


@pytest.mark.asyncio
async def test_reconcile_verify_resume_optional_policy_stale_without_terminal() -> None:
    """Optional disposition: verify_degraded-only may clear when no terminal outbox exists."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[
                (
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    WritebackStatus.CONFIRMED.value,
                ),
            ],
        ),
        "evt-205-optional-stale",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
            "disposition_policy": DispositionPolicy.NOT_REQUIRED.value,
        },
    )
    assert patch["verify_need_manual_resolution"] is False


@pytest.mark.asyncio
async def test_reconcile_verify_resume_keeps_manual_entity_only_no_degraded() -> None:
    """ISSUE-205: phase2 legitimate manual (no verify_degraded) must not clear on entity-only."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[
                (
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    WritebackStatus.ACCEPTED.value,
                ),
            ],
        ),
        "evt-205-legit-no-degraded",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": [],
            "disposition_policy": DispositionPolicy.REQUIRED.value,
        },
    )
    assert patch.get("halted") is False
    assert patch.get("verify_need_manual_resolution") is not False


@pytest.mark.asyncio
async def test_reconcile_verify_resume_keeps_manual_when_policy_missing_and_entity_only() -> None:
    """Missing disposition_policy must not use optional stale path with entity-only outboxes."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[
                (
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    WritebackStatus.ACCEPTED.value,
                ),
            ],
        ),
        "evt-205-missing-policy",
        {
            "halted": True,
            "verify_need_manual_resolution": True,
            "verify_need_writeback_recovery": False,
            "verify_failed_writebacks": [],
            "degraded_flags": ["verify_degraded=True"],
        },
    )
    assert patch.get("halted") is False
    assert patch.get("verify_need_manual_resolution") is not False


@pytest.mark.asyncio
async def test_resume_raises_when_checkpoint_missing_mid_flight() -> None:
    """ISSUE-193: lost checkpoint during pause surfaces GraphResumeFailedError."""
    graph = MagicMock()
    graph.aget_state = AsyncMock(return_value=MagicMock(values={}))
    agent = MagicMock()
    agent._investigation_graph = graph
    agent.investigate = AsyncMock()

    async def _get_super_agent() -> Any:
        return agent

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    async def _get_runtime() -> Any:
        return runtime

    session_factory = _SessionFactory(EventStatus.EXECUTING_RESPONSE.value)

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await resume_investigation_from_checkpoint(
            session_factory,
            "evt-no-checkpoint",
            get_super_agent=_get_super_agent,
            get_workflow_runtime=_get_runtime,
        )

    assert exc_info.value.error_type == "checkpoint_missing"
    agent.investigate.assert_not_called()
    graph.ainvoke.assert_not_called()


@pytest.mark.asyncio
async def test_resume_fallback_execute_investigation_when_graph_never_started() -> None:
    """ISSUE-192: no checkpoint + NEW status may delegate to Celery investigate task."""
    graph = MagicMock()
    graph.aget_state = AsyncMock(return_value=MagicMock(values={}))
    agent = MagicMock()
    agent._investigation_graph = graph

    async def _get_super_agent() -> Any:
        return agent

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    async def _get_runtime() -> Any:
        return runtime

    session_factory = _SessionFactory(EventStatus.NEW.value)

    with (
        patch(
            "app.services.investigation_guidance.resolve_include_response_execution_for_resume",
            new_callable=AsyncMock,
            return_value=True,
        ) as resolve_include,
        patch(
            "app.tasks.investigation_tasks.execute_investigation",
            new_callable=AsyncMock,
        ) as execute,
    ):
        await resume_investigation_from_checkpoint(
            session_factory,
            "evt-never-started",
            get_super_agent=_get_super_agent,
            get_workflow_runtime=_get_runtime,
        )

    resolve_include.assert_awaited_once()
    execute.assert_awaited_once_with(
        "evt-never-started",
        include_response_execution=True,
    )
    graph.ainvoke.assert_not_called()


@pytest.mark.asyncio
async def test_resume_reporting_without_graph_uses_report_only_not_full_restart() -> None:
    """ISSUE-247: REPORTING + graph=None must not call execute_investigation()."""
    from app.models.agent_io import CollectionStatus, EvidenceOutput, RiskAssessment, ScoringMode
    from app.models.enums import Severity

    report = MagicMock()
    report_agent = MagicMock()
    report_agent.execute = AsyncMock(return_value=report)
    context_store = MagicMock()
    context_store.get = AsyncMock(
        side_effect=lambda _eid, field: {
            "evidence_output": EvidenceOutput(collection_status=CollectionStatus.COMPLETED),
            "risk_assessment": RiskAssessment(
                risk_score=70,
                severity=Severity.HIGH,
                confidence=0.8,
                scoring_mode=ScoringMode.RULE_ONLY,
            ),
        }.get(field)
    )
    context_store.set = AsyncMock()
    event_service = MagicMock()
    event_service.get_report = AsyncMock(return_value=None)

    agent = MagicMock()
    agent._investigation_graph = None
    agent.report_agent = report_agent
    agent.context_store = context_store
    agent.event_service = event_service

    with (
        patch(
            "app.tasks.investigation_tasks.execute_investigation",
            new_callable=AsyncMock,
        ) as execute,
        patch(
            "app.orchestration.workflow_graph.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as invoke,
    ):
        await resume_investigation_from_checkpoint(
            _SessionFactory(EventStatus.REPORTING.value),
            "evt-247-report-only",
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
        )

    execute.assert_not_awaited()
    invoke.assert_not_awaited()
    report_agent.execute.assert_awaited_once()
    set_fields = {call.args[1] for call in context_store.set.await_args_list}
    assert "report_generated" in set_fields
    assert "analysis_only_complete" in set_fields


@pytest.mark.asyncio
async def test_resume_closed_or_failed_without_graph_is_noop() -> None:
    """ISSUE-247: CLOSED/FAILED must never full-graph restart when graph is absent."""
    for status in (EventStatus.CLOSED.value, EventStatus.FAILED.value):
        agent = MagicMock()
        agent._investigation_graph = None
        agent.report_agent = MagicMock(execute=AsyncMock())

        with patch(
            "app.tasks.investigation_tasks.execute_investigation",
            new_callable=AsyncMock,
        ) as execute:
            await resume_investigation_from_checkpoint(
                _SessionFactory(status),
                f"evt-247-{status}",
                get_super_agent=AsyncMock(return_value=agent),
                get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            )

        execute.assert_not_awaited()
        agent.report_agent.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_resume_closed_or_failed_with_graph_is_noop() -> None:
    """ISSUE-247: terminal statuses skip resume even when a graph is wired."""
    graph = MagicMock()
    graph.aget_state = AsyncMock()
    for status in (EventStatus.CLOSED.value, EventStatus.FAILED.value):
        agent = MagicMock()
        agent._investigation_graph = graph

        with patch(
            "app.tasks.investigation_tasks.execute_investigation",
            new_callable=AsyncMock,
        ) as execute:
            await resume_investigation_from_checkpoint(
                _SessionFactory(status),
                f"evt-247-graph-{status}",
                get_super_agent=AsyncMock(return_value=agent),
                get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            )

        execute.assert_not_awaited()
    graph.aget_state.assert_not_called()


@pytest.mark.asyncio
async def test_resume_reporting_missing_checkpoint_keeps_reporting_error() -> None:
    """ISSUE-247: REPORTING + missing checkpoint raises checkpoint_missing (no restart)."""
    graph = MagicMock()
    graph.aget_state = AsyncMock(return_value=MagicMock(values={}))
    agent = MagicMock()
    agent._investigation_graph = graph

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    with (
        patch(
            "app.tasks.investigation_tasks.execute_investigation",
            new_callable=AsyncMock,
        ) as execute,
        pytest.raises(GraphResumeFailedError) as exc_info,
    ):
        await resume_investigation_from_checkpoint(
            _SessionFactory(EventStatus.REPORTING.value),
            "evt-247-no-ckpt",
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=runtime),
        )

    assert exc_info.value.error_type == "checkpoint_missing"
    execute.assert_not_awaited()
    graph.ainvoke.assert_not_called()


@pytest.mark.asyncio
async def test_resume_reporting_with_checkpoint_invokes_graph_not_execute() -> None:
    """ISSUE-247 / ISSUE-192: REPORTING + checkpoint continues via ainvoke(None)."""
    graph = MagicMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "halted": True,
                "needs_approval_wait": True,
                "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
                "event_status": EventStatus.WAITING_APPROVAL.value,
            }
        )
    )
    graph.aupdate_state = AsyncMock()
    agent = MagicMock()
    agent._investigation_graph = graph

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    with (
        patch(
            "app.tasks.investigation_tasks.execute_investigation",
            new_callable=AsyncMock,
        ) as execute,
        patch(
            "app.orchestration.graph_resume.invoke_investigation_graph",
            new_callable=AsyncMock,
        ) as invoke,
    ):
        await resume_investigation_from_checkpoint(
            _SessionFactory(EventStatus.REPORTING.value),
            "evt-247-ckpt-reporting",
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=runtime),
        )

    execute.assert_not_awaited()
    invoke.assert_awaited_once()
    graph.aupdate_state.assert_awaited()
    runtime.set_execution_substate.assert_awaited()


@pytest.mark.asyncio
async def test_resume_executing_without_graph_still_delegates_execute() -> None:
    """ISSUE-247 must not break approve→EXECUTING_RESPONSE graph=None fallback."""
    agent = MagicMock()
    agent._investigation_graph = None

    with (
        patch(
            "app.services.investigation_guidance.resolve_include_response_execution_for_resume",
            new_callable=AsyncMock,
            return_value=True,
        ),
        patch(
            "app.tasks.investigation_tasks.execute_investigation",
            new_callable=AsyncMock,
        ) as execute,
    ):
        await resume_investigation_from_checkpoint(
            _SessionFactory(EventStatus.EXECUTING_RESPONSE.value),
            "evt-247-executing-fallback",
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
        )

    execute.assert_awaited_once_with(
        "evt-247-executing-fallback",
        include_response_execution=True,
    )


@pytest.mark.asyncio
async def test_reconcile_stale_approval_wait_flags_clears_checkpoint() -> None:
    """ISSUE-282: post-resume checkpoint must not keep needs_approval_wait=true."""
    from app.orchestration.graph_resume import _reconcile_stale_approval_wait_flags

    graph = MagicMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "needs_approval_wait": True,
                "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
                "halted": True,
            }
        )
    )
    graph.aupdate_state = AsyncMock()

    await _reconcile_stale_approval_wait_flags(
        _SessionFactory(EventStatus.VERIFYING.value),
        graph,
        "evt-282-stale-wait",
    )

    graph.aupdate_state.assert_awaited_once()
    call = graph.aupdate_state.await_args
    assert call is not None
    assert call.args[1]["needs_approval_wait"] is False
    assert call.args[1]["execution_substate"] == ExecutionSubstate.NONE.value
