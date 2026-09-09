"""Unit tests for graph checkpoint resume helpers (ISSUE-192 / ISSUE-196 / ISSUE-205)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.errors import ValidationError
from app.models.enums import (
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    WritebackStatus,
)
from app.orchestration.graph_resume import (
    _reconcile_verify_resume_patch,
    _saga_manual_hold_resolved,
    maybe_catchup_approval_resume_same_lease,
    prepare_graph_resume_state,
    resume_investigation_from_checkpoint,
)
from app.orchestration.graph_resume_observability import GraphResumeFailedError
from app.orchestration.workflow_graph import NODE_EXECUTE

OutboxRow = tuple[str, str | None]


class _SessionFactory:
    def __init__(
        self,
        status: str,
        *,
        outbox_rows: list[OutboxRow] | None = None,
        final_verdict: str = "none",
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows or []
        self._final_verdict = final_verdict

    def __call__(self) -> _SessionCtx:
        return _SessionCtx(
            self._status,
            outbox_rows=self._outbox_rows,
            final_verdict=self._final_verdict,
        )


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
        final_verdict: str = "none",
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows or []
        self._final_verdict = final_verdict

    async def scalar(self, stmt: Any) -> str:
        rendered = str(stmt)
        if "final_verdict" in rendered:
            return self._final_verdict
        return self._status

    async def execute(self, _stmt: Any) -> _OutboxExecuteResult:
        return _OutboxExecuteResult(self._outbox_rows)


class _SessionCtx:
    def __init__(
        self,
        status: str,
        *,
        outbox_rows: list[OutboxRow] | None = None,
        final_verdict: str = "none",
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows
        self._final_verdict = final_verdict

    async def __aenter__(self) -> _ScalarSession:
        return _ScalarSession(
            self._status,
            outbox_rows=self._outbox_rows,
            final_verdict=self._final_verdict,
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
async def test_prepare_verify_resume_schedules_fresh_verify_after_recovery() -> None:
    graph = MagicMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "halted": True,
                "verify_overall_status": "waiting",
                "verify_need_manual_resolution": True,
                "verify_need_writeback_recovery": False,
                "verify_failed_writebacks": [],
                "degraded_flags": ["verify_degraded=True"],
                "disposition_policy": DispositionPolicy.REQUIRED.value,
                "execution_substate": ExecutionSubstate.MANUAL_RESOLUTION.value,
            }
        )
    )
    graph.aupdate_state = AsyncMock()
    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    found = await prepare_graph_resume_state(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=_terminal_confirmed(),
        ),
        graph,
        "evt-261-reverify",
        runtime,
    )

    assert found is True
    assert graph.aupdate_state.await_args.kwargs["as_node"] == NODE_EXECUTE


@pytest.mark.asyncio
async def test_prepare_graph_resume_skips_patch_on_executing_response_mismatch() -> None:
    class _SequenceSessionFactory:
        def __init__(self, statuses: list[str]) -> None:
            self._statuses = statuses
            self._reads = 0

        def __call__(self) -> Any:
            return _SequenceSessionCtx(self)

    class _SequenceSessionCtx:
        def __init__(self, factory: _SequenceSessionFactory) -> None:
            self._factory = factory

        async def __aenter__(self) -> _SequenceScalarSession:
            return _SequenceScalarSession(self._factory)

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class _SequenceScalarSession:
        def __init__(self, factory: _SequenceSessionFactory) -> None:
            self._factory = factory

        async def scalar(self, stmt: Any) -> str:
            del stmt
            idx = min(self._factory._reads, len(self._factory._statuses) - 1)
            self._factory._reads += 1
            return self._factory._statuses[idx]

        async def execute(self, _stmt: Any) -> _OutboxExecuteResult:
            return _OutboxExecuteResult([])

    graph = MagicMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "halted": True,
                "needs_approval_wait": True,
                "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
            }
        )
    )
    graph.aupdate_state = AsyncMock()
    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock(
        side_effect=ValidationError(
            "caller EventStatus does not match authoritative state",
            details={
                "caller_status": EventStatus.EXECUTING_RESPONSE.value,
                "authoritative_status": EventStatus.FAILED.value,
            },
        )
    )

    found = await prepare_graph_resume_state(
        _SequenceSessionFactory(
            [EventStatus.EXECUTING_RESPONSE.value, EventStatus.FAILED.value],
        ),
        graph,
        "evt-exec-mismatch",
        runtime,
    )

    assert found is True
    graph.aupdate_state.assert_not_awaited()


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
async def test_reconcile_verify_resume_clears_converged_saga_hold() -> None:
    saga_resolved = AsyncMock(return_value=True)
    with patch(
        "app.orchestration.graph_resume._saga_manual_hold_resolved",
        new=saga_resolved,
    ):
        resume_patch = await _reconcile_verify_resume_patch(
            _SessionFactory(EventStatus.VERIFYING.value),
            "evt-saga-resolved",
            {
                "halted": True,
                "verify_need_manual_resolution": True,
                "verify_need_action_replan": True,
                "manual_hold_pending_ids": ["act-rollback"],
                "rollback_results": [
                    {
                        "action_id": "act-source",
                        "rollback_action_id": "act-rollback",
                        "rolled_back": False,
                    }
                ],
                "degraded_flags": ["saga_compensation_incomplete=True"],
                "disposition_policy": DispositionPolicy.NOT_REQUIRED.value,
            },
        )

    assert saga_resolved.await_count == 1
    assert saga_resolved.await_args.args[1:] == (
        ["act-rollback"],
        [
            {
                "action_id": "act-source",
                "rollback_action_id": "act-rollback",
                "rolled_back": False,
            }
        ],
    )

    assert resume_patch["halted"] is False
    assert resume_patch["verify_need_manual_resolution"] is False
    assert resume_patch["saga_compensation_resolved"] is True
    assert resume_patch["manual_hold_pending_ids"] == []
    assert "saga_compensation_incomplete=True" not in resume_patch["degraded_flags"]


@pytest.mark.asyncio
async def test_saga_hold_keeps_unmaterialized_compensation_blocked() -> None:
    resolved = await _saga_manual_hold_resolved(
        _SessionFactory(EventStatus.VERIFYING.value),
        ["act-failed-boundary"],
        [
            {
                "action_id": "act-nonrollbackable",
                "rollback_action_id": None,
                "rolled_back": False,
                "warning": "not_rollbackable",
            }
        ],
    )

    assert resolved is False


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
async def test_reconcile_verify_resume_reenters_verify_after_analyst_terminal_verdict() -> None:
    """Analyst confirmed_threat with no outbox yet must re-enter Verify."""
    patch = await _reconcile_verify_resume_patch(
        _SessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[],
            final_verdict="confirmed_threat",
        ),
        "evt-analyst-verdict",
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
    assert patch["verify_need_manual_resolution"] is False
    assert patch["execution_substate"] == ExecutionSubstate.NONE.value


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
            lease_acquired=True,
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
            lease_acquired=True,
        )

    resolve_include.assert_awaited_once()
    execute.assert_awaited_once_with(
        "evt-never-started",
        include_response_execution=True,
    )
    graph.ainvoke.assert_not_called()


@pytest.mark.asyncio
async def test_resume_report_only_reraises_soft_time_limit() -> None:
    """ISSUE-314: report-only path must not rewrite SoftTimeLimitExceeded."""
    from celery.exceptions import SoftTimeLimitExceeded

    from app.models.agent_io import CollectionStatus, EvidenceOutput, RiskAssessment, ScoringMode
    from app.models.enums import Severity
    from app.orchestration.graph_resume import _resume_report_only_from_analysis

    report_agent = MagicMock()
    report_agent.execute = AsyncMock(side_effect=SoftTimeLimitExceeded())
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
    agent.report_agent = report_agent
    agent.context_store = context_store
    agent.event_service = event_service

    with (
        patch(
            "app.services.report_input_builder.build_report_agent_input",
            new=AsyncMock(return_value=object()),
        ),
        pytest.raises(SoftTimeLimitExceeded),
    ):
        await _resume_report_only_from_analysis(
            MagicMock(),
            "evt-314-report-only-soft",
            agent,
        )


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
    context_store.set_analysis_only_complete = AsyncMock(
        return_value=MagicMock(redis_ok=True, version=1)
    )
    event_service = MagicMock()
    event_service.get_report = AsyncMock(return_value=None)
    event_service.merge_analysis_only_complete_context_snapshot = AsyncMock()

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
            lease_acquired=True,
        )

    execute.assert_not_awaited()
    invoke.assert_not_awaited()
    report_agent.execute.assert_awaited_once()
    set_fields = {call.args[1] for call in context_store.set.await_args_list}
    assert "report_generated" in set_fields
    assert "analysis_only_complete" not in set_fields
    context_store.set_analysis_only_complete.assert_awaited_once_with("evt-247-report-only", True)
    event_service.merge_analysis_only_complete_context_snapshot.assert_not_awaited()


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
            outcome = await resume_investigation_from_checkpoint(
                _SessionFactory(status),
                f"evt-247-{status}",
                get_super_agent=AsyncMock(return_value=agent),
                get_workflow_runtime=AsyncMock(return_value=MagicMock()),
                lease_acquired=True,
            )

        assert outcome == "skipped"
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
            outcome = await resume_investigation_from_checkpoint(
                _SessionFactory(status),
                f"evt-247-graph-{status}",
                get_super_agent=AsyncMock(return_value=agent),
                get_workflow_runtime=AsyncMock(return_value=MagicMock()),
                lease_acquired=True,
            )

        assert outcome == "skipped"
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
            lease_acquired=True,
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
            lease_acquired=True,
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
            lease_acquired=True,
        )

    execute.assert_awaited_once_with(
        "evt-247-executing-fallback",
        include_response_execution=True,
    )


@pytest.mark.asyncio
async def test_resume_returns_deferred_when_lease_held(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = MagicMock()
    graph.ainvoke = AsyncMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "halted": True,
                "needs_approval_wait": True,
                "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
            }
        )
    )
    agent = MagicMock()
    agent._investigation_graph = graph

    lease = MagicMock()
    lease.acquire = AsyncMock(return_value=False)
    monkeypatch.setattr("app.api.v1.deps.get_event_lease", lambda: lease)

    outcome = await resume_investigation_from_checkpoint(
        _SessionFactory(EventStatus.EXECUTING_RESPONSE.value),
        "evt-lease-held",
        get_super_agent=AsyncMock(return_value=agent),
        get_workflow_runtime=AsyncMock(return_value=MagicMock()),
        lease_acquired=False,
    )

    assert outcome == "deferred"
    graph.ainvoke.assert_not_called()
    lease.acquire.assert_awaited_once()


@pytest.mark.asyncio
async def test_resume_acquires_with_caller_owner_not_generated_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = MagicMock()
    lease.acquire = AsyncMock(return_value=False)
    monkeypatch.setattr("app.api.v1.deps.get_event_lease", lambda: lease)

    outcome = await resume_investigation_from_checkpoint(
        _SessionFactory(EventStatus.EXECUTING_RESPONSE.value),
        "evt-owner-match",
        get_super_agent=AsyncMock(return_value=MagicMock()),
        get_workflow_runtime=AsyncMock(return_value=MagicMock()),
        lease_acquired=False,
        owner_id="celery-task-abc",
    )

    assert outcome == "deferred"
    lease.acquire.assert_awaited_once()
    assert lease.acquire.await_args.args[1] == "celery-task-abc"


@pytest.mark.asyncio
async def test_catchup_resumes_once_from_approval_wait_halt() -> None:
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

    with patch(
        "app.orchestration.graph_resume.invoke_investigation_graph",
        new_callable=AsyncMock,
    ) as invoke:
        await maybe_catchup_approval_resume_same_lease(
            _SessionFactory(EventStatus.EXECUTING_RESPONSE.value),
            "evt-catchup-wait",
            graph,
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=runtime),
        )

    invoke.assert_awaited_once()
    graph.aupdate_state.assert_awaited()


@pytest.mark.asyncio
async def test_catchup_noop_when_checkpoint_not_halted() -> None:
    graph = MagicMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "halted": False,
                "needs_approval_wait": False,
                "execution_substate": ExecutionSubstate.NONE.value,
            }
        )
    )
    agent = MagicMock()
    agent._investigation_graph = graph

    with patch(
        "app.orchestration.graph_resume.invoke_investigation_graph",
        new_callable=AsyncMock,
    ) as invoke:
        await maybe_catchup_approval_resume_same_lease(
            _SessionFactory(EventStatus.EXECUTING_RESPONSE.value),
            "evt-catchup-noop",
            graph,
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
        )

    invoke.assert_not_awaited()
    graph.aupdate_state.assert_not_called()


@pytest.mark.asyncio
async def test_resume_waiting_approval_returns_skipped_not_ok() -> None:
    agent = MagicMock()
    agent._investigation_graph = MagicMock()

    with patch(
        "app.orchestration.graph_resume.invoke_investigation_graph",
        new_callable=AsyncMock,
    ) as invoke:
        outcome = await resume_investigation_from_checkpoint(
            _SessionFactory(EventStatus.WAITING_APPROVAL.value),
            "evt-still-waiting",
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            lease_acquired=True,
        )

    assert outcome == "skipped"
    invoke.assert_not_awaited()
