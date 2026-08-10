"""Unit tests for graph resume failure observability (ISSUE-193)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import InvalidStateTransitionError, ValidationError
from app.models.enums import EventStatus
from app.orchestration.graph_resume_observability import (
    GRAPH_RESUME_FAILED_FLAG,
    GraphResumeFailedError,
    GraphResumeFailureContext,
    execute_graph_resume_with_retry,
    record_graph_resume_failure,
)
from app.services.approval_engine import ApprovalEngine


class _BeginCtx:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _ScalarSession:
    def __init__(self, status: str) -> None:
        self._status = status

    def begin(self) -> _BeginCtx:
        return _BeginCtx()

    async def scalar(self, _stmt: Any) -> str:
        return self._status

    def add(self, _row: Any) -> None:
        return None

    async def get(self, _model: Any, _key: str) -> MagicMock:
        row = MagicMock()
        row.degraded_flags = []
        return row


class _SessionCtx:
    def __init__(self, status: str) -> None:
        self._status = status

    async def __aenter__(self) -> _ScalarSession:
        return _ScalarSession(self._status)

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _SessionFactory:
    def __init__(self, status: str = EventStatus.EXECUTING_RESPONSE.value) -> None:
        self._status = status

    def __call__(self) -> _SessionCtx:
        return _SessionCtx(self._status)


@pytest.mark.asyncio
async def test_execute_graph_resume_records_degraded_and_raises() -> None:
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=["graph_resume_failed=checkpoint_missing"])
    degraded.has_flag = AsyncMock(return_value=False)

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

    session_factory = _SessionFactory()

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-resume-fail",
            session_factory=session_factory,
            get_super_agent=_get_super_agent,
            get_workflow_runtime=_get_runtime,
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "checkpoint_missing"
    degraded.set_flag.assert_awaited_once()
    call = degraded.set_flag.await_args
    assert call is not None
    assert call.args[1] == GRAPH_RESUME_FAILED_FLAG


@pytest.mark.asyncio
async def test_reporting_checkpoint_missing_keeps_status_reporting() -> None:
    """ISSUE-247: checkpoint_missing on REPORTING must not mark the event FAILED."""
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=["graph_resume_failed=checkpoint_missing"])
    degraded.has_flag = AsyncMock(return_value=False)

    graph = MagicMock()
    graph.aget_state = AsyncMock(return_value=MagicMock(values={}))
    agent = MagicMock()
    agent._investigation_graph = graph
    factory = _SessionFactory(EventStatus.REPORTING.value)

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-247-keep-reporting",
            session_factory=factory,
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(
                return_value=MagicMock(set_execution_substate=AsyncMock())
            ),
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "checkpoint_missing"
    # Observability records degraded/audit in-place; status stays REPORTING.
    assert factory._status == EventStatus.REPORTING.value
    degraded.set_flag.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_graph_resume_retries_transient_errors() -> None:
    degraded = MagicMock()
    degraded.has_flag = AsyncMock(return_value=False)
    degraded.set_flag = AsyncMock()
    graph = MagicMock()
    call_count = 0

    async def _aget_state(_config: dict[str, Any]) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise TimeoutError("redis read timeout")
        return MagicMock(
            values={
                "halted": False,
                "event_status": EventStatus.EXECUTING_RESPONSE.value,
            }
        )

    graph.aget_state = _aget_state
    graph.aupdate_state = AsyncMock()
    graph.ainvoke = AsyncMock(return_value={"halted": False})
    agent = MagicMock()
    agent._investigation_graph = graph

    async def _get_super_agent() -> Any:
        return agent

    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock()

    async def _get_runtime() -> Any:
        return runtime

    await execute_graph_resume_with_retry(
        "evt-retry",
        session_factory=_SessionFactory(),
        get_super_agent=_get_super_agent,
        get_workflow_runtime=_get_runtime,
        degraded_flags=degraded,
    )

    assert call_count == 3
    degraded.set_flag.assert_not_awaited()


@pytest.mark.asyncio
async def test_approve_returns_resume_failed_without_rollback() -> None:
    async def _failing_resume(_event_id: str) -> None:
        raise GraphResumeFailedError(
            "invalid transition",
            event_id=_event_id,
            error_type="invalid_state_transition",
        )

    engine = ApprovalEngine(
        MagicMock(),
        resume_investigation=_failing_resume,
    )
    engine.is_plan_fully_decided = AsyncMock(return_value=True)  # type: ignore[method-assign]
    engine._load_plan_response_actions = AsyncMock(return_value=[MagicMock(status=MagicMock())])  # type: ignore[method-assign]
    engine._event_status = AsyncMock(return_value=EventStatus.WAITING_APPROVAL)  # type: ignore[method-assign]
    engine._state_machine = None

    status = await engine._maybe_advance_plan("evt-1", 1)
    assert status == "failed"


@pytest.mark.asyncio
async def test_maybe_advance_plan_returns_skipped_without_resume_hook() -> None:
    engine = ApprovalEngine(MagicMock(), resume_investigation=None)
    engine.is_plan_fully_decided = AsyncMock(return_value=True)  # type: ignore[method-assign]
    engine._load_plan_response_actions = AsyncMock(return_value=[MagicMock(status=MagicMock())])  # type: ignore[method-assign]
    engine._event_status = AsyncMock(return_value=EventStatus.WAITING_APPROVAL)  # type: ignore[method-assign]
    engine._state_machine = None

    status = await engine._maybe_advance_plan("evt-skipped", 1)
    assert status == "skipped"


@pytest.mark.asyncio
async def test_record_graph_resume_failure_uses_error_type_in_flag() -> None:
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=[])

    await record_graph_resume_failure(
        _SessionFactory(),
        degraded,
        GraphResumeFailureContext(
            event_id="evt-audit",
            error_type="invalid_state_transition",
            message="bad transition",
            execution_substate="waiting_approval",
        ),
    )

    degraded.set_flag.assert_awaited_once()
    call = degraded.set_flag.await_args
    assert call is not None
    assert call.kwargs["writer"] == "GraphResumeService"
    assert "invalid_state_transition" in str(call.args[2])


@pytest.mark.asyncio
async def test_execute_graph_resume_classifies_invalid_transition() -> None:
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=[])
    degraded.has_flag = AsyncMock(return_value=False)
    exc = InvalidStateTransitionError(
        "bad transition",
        current=EventStatus.EXECUTING_RESPONSE.value,
        target=EventStatus.COLLECTING_EVIDENCE.value,
    )
    agent = MagicMock()
    agent._investigation_graph = MagicMock(aget_state=AsyncMock(side_effect=exc))

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-invalid",
            session_factory=_SessionFactory(),
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "invalid_state_transition"
    degraded.set_flag.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_graph_resume_skips_nested_active_graph() -> None:
    resume = AsyncMock()
    agent = MagicMock()
    agent._investigation_graph = MagicMock()

    async def _get_super_agent() -> Any:
        return agent

    from app.orchestration.graph_invocation import bind_investigation_graph

    async with bind_investigation_graph("evt-nested"):
        await execute_graph_resume_with_retry(
            "evt-nested",
            session_factory=_SessionFactory(),
            get_super_agent=_get_super_agent,
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
            degraded_flags=MagicMock(),
        )

    agent._investigation_graph.aget_state.assert_not_called()


@pytest.mark.asyncio
async def test_execute_graph_resume_state_mismatch_is_not_retried() -> None:
    degraded = MagicMock()
    degraded.set_flag = AsyncMock(return_value=[])
    degraded.has_flag = AsyncMock(return_value=False)
    exc = ValidationError(
        "caller EventStatus does not match authoritative state",
        details={
            "caller_status": EventStatus.EXECUTING_RESPONSE.value,
            "authoritative_status": EventStatus.FAILED.value,
        },
    )
    graph = MagicMock()
    graph.aget_state = AsyncMock(
        return_value=MagicMock(
            values={
                "halted": True,
                "needs_approval_wait": True,
                "execution_substate": "waiting_approval",
            }
        )
    )
    agent = MagicMock()
    agent._investigation_graph = graph
    runtime = MagicMock()
    runtime.set_execution_substate = AsyncMock(side_effect=exc)

    with pytest.raises(GraphResumeFailedError) as exc_info:
        await execute_graph_resume_with_retry(
            "evt-state-mismatch",
            session_factory=_SessionFactory(),
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=runtime),
            degraded_flags=degraded,
        )

    assert exc_info.value.error_type == "state_mismatch"
    degraded.set_flag.assert_awaited_once()
    assert runtime.set_execution_substate.await_count == 1
