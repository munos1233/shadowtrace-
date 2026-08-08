"""Celery investigation task tests (ISSUE-056)."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from kombu.exceptions import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.celery_app import celery_app
from app.core.celery_delivery import celery_task_owner_id
from app.core.errors import (
    DependencyUnavailableError,
    InvalidStateTransitionError,
    InvestigationInProgressError,
    InvestigationLeaseLostError,
)
from app.models.enums import EventStatus
from app.tasks import investigation_tasks as tasks


@pytest.mark.asyncio
async def test_execute_investigation_skips_when_lease_already_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _boom(_event_id: str, **_kwargs: Any) -> None:
        raise InvestigationInProgressError(
            message="investigation already in progress for this event",
            error_code="investigation_in_progress",
            details={"event_id": "evt-skip"},
        )

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _boom
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation("evt-skip")
    assert result == {
        "status": "skipped",
        "event_id": "evt-skip",
        "reason": "investigation_in_progress",
    }


@pytest.mark.asyncio
async def test_execute_investigation_skips_when_lease_lost_mid_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _lost(_event_id: str, **_kwargs: Any) -> None:
        raise InvestigationLeaseLostError(
            message="investigation lease lost during orchestration",
            error_code="investigation_lease_lost",
            details={"event_id": "evt-lease-lost"},
        )

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _lost
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation("evt-lease-lost")
    assert result == {
        "status": "skipped",
        "event_id": "evt-lease-lost",
        "reason": "investigation_lease_lost",
    }


@pytest.mark.asyncio
async def test_execute_investigation_runs_super_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def _investigate(event_id: str, **_kwargs: Any) -> None:
        calls.append(event_id)

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation("evt-run")
    assert result == {"status": "completed", "event_id": "evt-run"}
    assert calls == ["evt-run"]


def _null_context() -> Any:
    from contextlib import nullcontext

    return nullcontext()


def test_run_investigation_eager_executes_task(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)
    result = tasks.run_investigation.apply(args=["evt-eager"]).result
    assert result == {"status": "completed", "event_id": "evt-eager"}


def test_duplicate_delivery_is_idempotent(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        if calls["n"] == 1:
            return {"status": "completed", "event_id": event_id}
        return {"status": "skipped", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    first = tasks.run_investigation.apply(args=["evt-dup"]).result
    second = tasks.run_investigation.apply(args=["evt-dup"]).result
    assert first["status"] == "completed"
    assert second["status"] == "skipped"


@pytest.mark.asyncio
async def test_execute_investigation_records_workflow_path_when_full_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: dict[str, object] = {}

    async def _record(
        _factory: object,
        event_id: str,
        *,
        workflow_path: str,
        include_response_execution: bool,
    ) -> None:
        recorded["event_id"] = event_id
        recorded["workflow_path"] = workflow_path
        recorded["include_response_execution"] = include_response_execution

    async def _investigate(event_id: str, **kwargs: object) -> None:
        recorded["investigate_kwargs"] = kwargs

    async def _fake_super_agent() -> object:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        _record,
    )
    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: object())
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation(
        "evt-workflow-trace",
        include_response_execution=True,
    )
    assert result == {"status": "completed", "event_id": "evt-workflow-trace"}
    assert recorded["workflow_path"] == "full_loop"
    assert recorded["include_response_execution"] is True


@pytest.mark.asyncio
async def test_execute_investigation_forwards_include_response_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    async def _investigate(event_id: str, **kwargs: Any) -> None:
        seen["event_id"] = event_id
        seen["include_response_execution"] = kwargs.get("include_response_execution")

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: object())
    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        AsyncMock(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation(
        "evt-include",
        include_response_execution=True,
    )
    assert result == {"status": "completed", "event_id": "evt-include"}
    assert seen == {
        "event_id": "evt-include",
        "include_response_execution": True,
    }


@pytest.mark.asyncio
async def test_dispatch_investigation_passes_include_response_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)
    captured: dict[str, Any] = {}

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_investigation(
        "evt-dispatch-include",
        include_response_execution=True,
    )
    assert task_id
    assert captured["args"] == ["evt-dispatch-include"]
    assert captured["kwargs"] == {
        "include_response_execution": True,
        "generate_report": True,
    }


@pytest.mark.asyncio
async def test_dispatch_investigation_forwards_owner_id_and_lease_acquired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-186: dispatch_investigation threads owner_id + lease_acquired to the Celery task."""
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)
    captured: dict[str, Any] = {}

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_investigation(
        "evt-dispatch-lease",
        owner_id="owner-http-1",
        lease_acquired=True,
    )
    assert task_id
    assert captured["kwargs"] == {
        "include_response_execution": False,
        "generate_report": True,
        "owner_id": "owner-http-1",
        "lease_acquired": True,
    }


@pytest.mark.asyncio
async def test_dispatch_investigation_omits_owner_id_when_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-186: backward compat — dispatch without owner_id emits only include_response."""
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)
    captured: dict[str, Any] = {}

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_investigation("evt-dispatch-no-owner")
    assert task_id
    assert captured["kwargs"] == {"include_response_execution": False, "generate_report": True}
    assert "owner_id" not in captured["kwargs"]
    assert "lease_acquired" not in captured["kwargs"]


def test_publish_investigation_for_intent_forwards_include_response_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    tasks.publish_investigation_for_intent(
        event_id="evt-intent-include",
        task_id="task-intent-include",
        intent_id="iin-intent-include",
        include_response_execution=True,
    )
    assert captured["args"] == ["evt-intent-include"]
    assert captured["kwargs"] == {
        "include_response_execution": True,
        "generate_report": True,
        "intent_id": "iin-intent-include",
    }
    assert captured["task_id"] == "task-intent-include"


def test_publish_investigation_for_intent_forwards_generate_report_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    tasks.publish_investigation_for_intent(
        event_id="evt-intent-no-report",
        task_id="task-intent-no-report",
        intent_id="iin-intent-no-report",
        include_response_execution=False,
        generate_report=False,
    )
    assert captured["kwargs"] == {
        "include_response_execution": False,
        "generate_report": False,
        "intent_id": "iin-intent-no-report",
    }


@pytest.mark.asyncio
async def test_dispatch_investigation_returns_celery_task_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_investigation("evt-dispatch")
    assert task_id
    assert task_id != "evt-dispatch"


@pytest.mark.asyncio
async def test_resolve_task_state_reads_registered_event_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)

    async def _fake_lookup(task_id: str) -> str | None:
        return "evt-status"

    monkeypatch.setattr(tasks, "lookup_task_event_id", _fake_lookup)

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_investigation("evt-status")
    state, event_id = await tasks.resolve_task_state(task_id)
    assert event_id == "evt-status"
    assert state in {"SUCCESS", "PENDING", "STARTED", "FAILURE", "UNKNOWN"}


@pytest.mark.asyncio
async def test_dispatch_broker_unavailable_raises_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)
    monkeypatch.setattr(tasks, "delete_task_metadata", _noop_delete)

    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise OperationalError("broker down")

    monkeypatch.setattr(tasks.run_investigation, "apply_async", _boom)

    with pytest.raises(DependencyUnavailableError) as exc_info:
        await tasks.dispatch_investigation("evt-broker-down")

    assert exc_info.value.error_code == "task_unavailable"


@pytest.mark.asyncio
async def test_dispatch_metadata_failure_prevents_enqueue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def _fail_register(*_args: Any, **_kwargs: Any) -> None:
        raise DependencyUnavailableError(
            message="task metadata store unavailable",
            error_code="dependency_unavailable",
            details={"dependency": "redis"},
        )

    def _apply_async(*_args: Any, **_kwargs: Any) -> MagicMock:
        calls.append("apply_async")
        return MagicMock(id="should-not-run")

    monkeypatch.setattr(tasks, "register_task_metadata", _fail_register)
    monkeypatch.setattr(tasks.run_investigation, "apply_async", _apply_async)

    with pytest.raises(DependencyUnavailableError):
        await tasks.dispatch_investigation("evt-meta-fail")

    assert calls == []


def test_celery_task_uses_locked_name_and_queue() -> None:
    task = celery_app.tasks[tasks.TASK_NAME]
    assert task.name == "shadowtrace.run_investigation"
    assert task.acks_late is True
    assert task.max_retries == 2
    assert task.retry_backoff is True
    assert task.soft_time_limit == 600
    route = celery_app.conf.task_routes.get(tasks.TASK_NAME)
    assert route == {"queue": "investigation"}


async def _noop_register(*_args: Any, **_kwargs: Any) -> None:
    return None


async def _noop_delete(*_args: Any, **_kwargs: Any) -> None:
    return None


def test_run_investigation_unhandled_exception_marks_intent_dead(
    session_factory: async_sessionmaker[AsyncSession],
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    from app.db import models as orm
    from app.models.enums import EventStatus, InvestigationIntentStatus, Severity

    intent_id = f"iin-dead-{uuid4().hex[:8]}"
    event_id = f"evt-dead-{uuid4().hex[:8]}"

    async def _seed() -> None:
        async with session_factory() as session:
            async with session.begin():
                session.add(
                    orm.SecurityEvent(
                        event_id=event_id,
                        event_type="malicious_process",
                        title="Suspicious process",
                        description="",
                        status=EventStatus.NEW.value,
                        severity=Severity.HIGH.value,
                        final_verdict="none",
                        creation_source_ref={"source_product": "mock_xdr"},
                        source_reference_snapshots=[],
                        disposition_policy="not_required",
                        raw_alert_ids=[],
                        source_type="mock_xdr",
                    )
                )
                await session.flush()
                session.add(
                    orm.InvestigationIntent(
                        intent_id=intent_id,
                        event_id=event_id,
                        intent_kind="auto_investigate",
                        intent_version="issue108_v1",
                        status=InvestigationIntentStatus.ENQUEUED.value,
                        revision=1,
                        attempt=0,
                        broker_task_id="task-dead",
                    )
                )

    asyncio.run(_seed())

    async def _boom(*_args: object, **_kwargs: object) -> dict[str, str]:
        raise RuntimeError("investigation exploded")

    monkeypatch.setattr(tasks, "execute_investigation", _boom)

    with pytest.raises(RuntimeError, match="investigation exploded"):
        tasks.run_investigation.apply(
            args=[event_id],
            kwargs={"intent_id": intent_id},
            task_id="task-dead",
        ).get()

    async def _verify() -> None:
        async with session_factory() as session:
            row = await session.get(orm.InvestigationIntent, intent_id)
            assert row is not None
            assert row.status == InvestigationIntentStatus.DEAD.value

    asyncio.run(_verify())


def test_run_investigation_skips_body_when_broker_task_superseded(
    session_factory: async_sessionmaker[AsyncSession],
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    from app.db import models as orm
    from app.models.enums import EventStatus, InvestigationIntentStatus, Severity

    intent_id = f"iin-skip-body-{uuid4().hex[:8]}"
    event_id = f"evt-skip-body-{uuid4().hex[:8]}"
    current_task = "task-current"
    stale_task = "task-stale"

    async def _seed() -> None:
        async with session_factory() as session:
            async with session.begin():
                session.add(
                    orm.SecurityEvent(
                        event_id=event_id,
                        event_type="malicious_process",
                        title="Suspicious process",
                        description="",
                        status=EventStatus.NEW.value,
                        severity=Severity.HIGH.value,
                        final_verdict="none",
                        creation_source_ref={"source_product": "mock_xdr"},
                        source_reference_snapshots=[],
                        disposition_policy="not_required",
                        raw_alert_ids=[],
                        source_type="mock_xdr",
                    )
                )
                await session.flush()
                session.add(
                    orm.InvestigationIntent(
                        intent_id=intent_id,
                        event_id=event_id,
                        intent_kind="auto_investigate",
                        intent_version="issue108_v1",
                        status=InvestigationIntentStatus.ENQUEUED.value,
                        revision=1,
                        attempt=0,
                        broker_task_id=current_task,
                    )
                )

    asyncio.run(_seed())

    calls = {"n": 0}

    async def _execute(*_args: object, **_kwargs: object) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _execute)

    result = tasks.run_investigation.apply(
        args=[event_id],
        kwargs={"intent_id": intent_id},
        task_id=stale_task,
    ).result

    assert result["status"] == "skipped"
    assert result["reason"] == "stale_broker_task"
    assert calls["n"] == 0

    async def _verify() -> None:
        async with session_factory() as session:
            row = await session.get(orm.InvestigationIntent, intent_id)
            assert row is not None
            assert row.status == InvestigationIntentStatus.ENQUEUED.value

    asyncio.run(_verify())


def test_run_investigation_stale_retry_state_skips_without_dead(
    session_factory: async_sessionmaker[AsyncSession],
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    from app.db import models as orm
    from app.models.enums import EventStatus, InvestigationIntentStatus, Severity

    intent_id = f"iin-retry-skip-{uuid4().hex[:8]}"
    event_id = f"evt-retry-skip-{uuid4().hex[:8]}"

    async def _seed() -> None:
        async with session_factory() as session:
            async with session.begin():
                session.add(
                    orm.SecurityEvent(
                        event_id=event_id,
                        event_type="malicious_process",
                        title="Suspicious process",
                        description="",
                        status=EventStatus.NEW.value,
                        severity=Severity.HIGH.value,
                        final_verdict="none",
                        creation_source_ref={"source_product": "mock_xdr"},
                        source_reference_snapshots=[],
                        disposition_policy="not_required",
                        raw_alert_ids=[],
                        source_type="mock_xdr",
                    )
                )
                await session.flush()
                session.add(
                    orm.InvestigationIntent(
                        intent_id=intent_id,
                        event_id=event_id,
                        intent_kind="auto_investigate",
                        intent_version="issue108_v1",
                        status=InvestigationIntentStatus.RETRY.value,
                        revision=2,
                        attempt=1,
                    )
                )

    asyncio.run(_seed())

    async def _execute(*_args: object, **_kwargs: object) -> dict[str, str]:
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _execute)

    result = tasks.run_investigation.apply(
        args=[event_id],
        kwargs={"intent_id": intent_id},
        task_id="task-old",
    ).result

    assert result["reason"] == "stale_broker_task"

    async def _verify() -> None:
        async with session_factory() as session:
            row = await session.get(orm.InvestigationIntent, intent_id)
            assert row is not None
            assert row.status == InvestigationIntentStatus.RETRY.value

    asyncio.run(_verify())


def test_celery_retries_exhausted_marks_intent_retry(
    session_factory: async_sessionmaker[AsyncSession],
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    from celery.app.task import Context
    from kombu.exceptions import OperationalError

    from app.db import models as orm
    from app.models.enums import EventStatus, InvestigationIntentStatus, Severity

    intent_id = f"iin-exhaust-{uuid4().hex[:8]}"
    event_id = f"evt-exhaust-{uuid4().hex[:8]}"

    async def _seed() -> None:
        async with session_factory() as session:
            async with session.begin():
                session.add(
                    orm.SecurityEvent(
                        event_id=event_id,
                        event_type="malicious_process",
                        title="Suspicious process",
                        description="",
                        status=EventStatus.NEW.value,
                        severity=Severity.HIGH.value,
                        final_verdict="none",
                        creation_source_ref={"source_product": "mock_xdr"},
                        source_reference_snapshots=[],
                        disposition_policy="not_required",
                        raw_alert_ids=[],
                        source_type="mock_xdr",
                    )
                )
                await session.flush()
                session.add(
                    orm.InvestigationIntent(
                        intent_id=intent_id,
                        event_id=event_id,
                        intent_kind="auto_investigate",
                        intent_version="issue108_v1",
                        status=InvestigationIntentStatus.ENQUEUED.value,
                        revision=1,
                        attempt=0,
                        broker_task_id="task-exhaust",
                    )
                )

    asyncio.run(_seed())

    async def _boom(*_args: object, **_kwargs: object) -> dict[str, str]:
        raise OperationalError("broker down")

    monkeypatch.setattr(tasks, "execute_investigation", _boom)

    ctx = Context(id="task-exhaust", delivery_info={}, retries=2)
    tasks.run_investigation.request_stack.push(ctx)
    try:
        with pytest.raises(OperationalError):
            tasks.run_investigation.run(
                event_id,
                include_response_execution=False,
                intent_id=intent_id,
            )
    finally:
        tasks.run_investigation.request_stack.pop()

    async def _verify() -> None:
        async with session_factory() as session:
            row = await session.get(orm.InvestigationIntent, intent_id)
            assert row is not None
            assert row.status == InvestigationIntentStatus.RETRY.value

    asyncio.run(_verify())


@pytest.mark.asyncio
async def test_execute_investigation_forwards_lease_acquired_to_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-186: execute_investigation passes lease_acquired through to agent.investigate."""
    seen: dict[str, Any] = {}

    async def _investigate(event_id: str, **kwargs: Any) -> None:
        seen["event_id"] = event_id
        seen["owner_id"] = kwargs.get("owner_id")
        seen["lease_acquired"] = kwargs.get("lease_acquired")
        seen["include_response_execution"] = kwargs.get("include_response_execution")

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    result = await tasks.execute_investigation(
        "evt-lease-acquired",
        owner_id="owner-http-2",
        lease_acquired=True,
        include_response_execution=True,
    )
    assert result == {"status": "completed", "event_id": "evt-lease-acquired"}
    assert seen == {
        "event_id": "evt-lease-acquired",
        "owner_id": "owner-http-2",
        "lease_acquired": True,
        "include_response_execution": True,
    }


@pytest.mark.asyncio
async def test_execute_investigation_defaults_lease_acquired_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-186: backward compat — execute_investigation without lease_acquired defaults False."""
    seen: dict[str, Any] = {}

    async def _investigate(event_id: str, **kwargs: Any) -> None:
        seen["lease_acquired"] = kwargs.get("lease_acquired")

    async def _fake_super_agent() -> Any:
        agent = MagicMock()
        agent.investigate = _investigate
        return agent

    monkeypatch.setattr("app.api.v1.deps.get_super_agent", _fake_super_agent)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        lambda _projection: _null_context(),
    )
    monkeypatch.setattr(
        "app.services.evidence_projection.EvidenceProjection",
        lambda _factory: MagicMock(),
    )

    await tasks.execute_investigation("evt-default-lease")
    assert seen["lease_acquired"] is False


def test_run_investigation_soft_time_limit_releases_with_resolved_owner(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-186: soft time limit must release lease with resolved_owner, not nullable owner_id."""
    from celery.app.task import Context
    from celery.exceptions import SoftTimeLimitExceeded

    from app.core.celery_delivery import celery_task_owner_id

    released: list[tuple[str, str]] = []

    class _TrackingLease:
        async def release(self, event_id: str, owner_id: str) -> bool:
            released.append((event_id, owner_id))
            return True

    monkeypatch.setattr("app.api.v1.deps.get_event_lease", lambda: _TrackingLease())

    async def _boom(*_args: object, **_kwargs: object) -> dict[str, str]:
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(tasks, "_run_investigation_body", _boom)

    ctx = Context(id="task-soft-limit-001", delivery_info={}, retries=0)
    tasks.run_investigation.request_stack.push(ctx)
    try:
        with pytest.raises(SoftTimeLimitExceeded):
            tasks.run_investigation.run(
                "evt-soft-limit",
                include_response_execution=False,
                lease_acquired=True,
            )
    finally:
        tasks.run_investigation.request_stack.pop()

    expected_owner = celery_task_owner_id("task-soft-limit-001")
    assert released == [("evt-soft-limit", expected_owner)]


# --------------------------------------------------------------------------- #
# Analysis-only Celery task tests (ISSUE-225)
# --------------------------------------------------------------------------- #


async def _fake_renewal_coro() -> None:
    """Smallest awaitable for fake start_renewal."""
    pass


def _make_fake_lease(
    *,
    acquire_result: bool = True,
    release_result: bool = True,
) -> MagicMock:
    """Build a minimal EventLease-alike for execute_analysis_only_investigation."""
    lease = MagicMock()
    lease.acquire = AsyncMock(return_value=acquire_result)
    lease.release = AsyncMock(return_value=release_result)

    async def _start_renewal(
        event_id: str,
        owner_id: str,
        *,
        on_renewal_failed: Any = None,
        max_renew_failures: int = 3,
    ) -> asyncio.Task[None]:
        return asyncio.ensure_future(_fake_renewal_coro())

    lease.start_renewal = AsyncMock(side_effect=_start_renewal)
    return lease


def _patch_analysis_only_deps(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fake_lease: MagicMock | None = None,
    pipeline: Any | None = None,
) -> MagicMock:
    """Wire common deps for execute_analysis_only_investigation tests."""
    lease = fake_lease or _make_fake_lease()
    monkeypatch.setattr("app.api.v1.deps.get_event_lease", lambda: lease)
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: object())
    if pipeline is not None:

        async def _fake_pipeline() -> Any:
            return pipeline

        monkeypatch.setattr("app.api.v1.deps.get_pipeline", _fake_pipeline)
    return lease


@pytest.mark.asyncio
async def test_execute_analysis_only_runs_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Success path: pipeline runs, renewal starts, and returns completed."""
    calls: list[str] = []

    async def _fake_run(event_id: str, *, generate_report: bool = True) -> None:
        calls.append(event_id)

    pipeline = MagicMock()
    pipeline.run = _fake_run
    fake_lease = _patch_analysis_only_deps(monkeypatch, pipeline=pipeline)
    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        AsyncMock(),
    )

    result = await tasks.execute_analysis_only_investigation(
        "evt-ao-001",
        owner_id="worker-test",
        lease_acquired=True,
    )
    assert result == {"status": "completed", "event_id": "evt-ao-001"}
    assert calls == ["evt-ao-001"]
    fake_lease.start_renewal.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_analysis_only_binds_evidence_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-225: Celery path binds EvidenceProjection like the background runner."""
    bound: dict[str, object] = {"count": 0}

    @contextmanager
    def _tracking_bind(projection: object) -> Any:
        bound["count"] = int(bound["count"]) + 1
        bound["projection"] = projection
        yield

    async def _fake_run(_event_id: str, *, generate_report: bool = True) -> None:
        return None

    pipeline = MagicMock()
    pipeline.run = _fake_run
    _patch_analysis_only_deps(monkeypatch, pipeline=pipeline)
    monkeypatch.setattr(
        "app.services.evidence_projection.bind_evidence_projection",
        _tracking_bind,
    )
    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        AsyncMock(),
    )

    await tasks.execute_analysis_only_investigation(
        "evt-ao-projection",
        owner_id="worker-test",
        lease_acquired=True,
    )
    assert bound["count"] == 1
    assert bound["projection"] is not None


@pytest.mark.asyncio
async def test_execute_analysis_only_skips_on_invalid_state_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """InvalidStateTransitionError from pipeline returns skipped (background parity)."""

    async def _stale(event_id: str, **kwargs: Any) -> None:
        raise InvalidStateTransitionError(
            message="stale transition",
            error_code="invalid_state_transition",
            details={"event_id": event_id},
        )

    pipeline = MagicMock()
    pipeline.run = _stale
    _patch_analysis_only_deps(monkeypatch, pipeline=pipeline)

    result = await tasks.execute_analysis_only_investigation(
        "evt-ao-stale",
        owner_id="worker-test",
        lease_acquired=True,
    )
    assert result == {
        "status": "skipped",
        "event_id": "evt-ao-stale",
        "reason": "invalid_state_transition",
    }


@pytest.mark.asyncio
async def test_execute_analysis_only_skips_when_lease_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pipeline raises InvestigationLeaseLostError → skipped."""

    async def _lost(event_id: str, **kwargs: Any) -> None:
        raise InvestigationLeaseLostError(
            message="investigation lease lost",
            error_code="investigation_lease_lost",
            details={"event_id": event_id},
        )

    pipeline = MagicMock()
    pipeline.run = _lost
    _patch_analysis_only_deps(monkeypatch, pipeline=pipeline)

    result = await tasks.execute_analysis_only_investigation(
        "evt-ao-lost",
        owner_id="worker-test",
        lease_acquired=True,
    )
    assert result == {
        "status": "skipped",
        "event_id": "evt-ao-lost",
        "reason": "investigation_lease_lost",
    }


@pytest.mark.asyncio
async def test_execute_analysis_only_acquires_lease_when_not_preacquired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When lease_acquired=False, the worker acquires the lease itself."""
    calls: list[str] = []

    async def _fake_run(event_id: str, *, generate_report: bool = True) -> None:
        calls.append(event_id)

    pipeline = MagicMock()
    pipeline.run = _fake_run
    fake_lease = _patch_analysis_only_deps(monkeypatch, pipeline=pipeline)
    monkeypatch.setattr(
        "app.services.investigation_guidance.record_investigation_workflow_path",
        AsyncMock(),
    )

    result = await tasks.execute_analysis_only_investigation(
        "evt-ao-acquire",
        owner_id="worker-test",
        lease_acquired=False,
    )
    assert result["status"] == "completed"
    fake_lease.acquire.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_analysis_only_fails_when_lease_already_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When lease_acquired=False and acquire fails, raise immediately."""
    fake_lease = _make_fake_lease(acquire_result=False)
    _patch_analysis_only_deps(monkeypatch, fake_lease=fake_lease)

    with pytest.raises(InvestigationInProgressError, match="already in progress"):
        await tasks.execute_analysis_only_investigation(
            "evt-ao-busy",
            owner_id="worker-test",
            lease_acquired=False,
        )


@pytest.mark.asyncio
async def test_execute_analysis_only_marks_failed_on_pipeline_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected pipeline errors transition the event to FAILED before re-raise."""

    async def _fail(_event_id: str, **kwargs: Any) -> None:
        raise RuntimeError("pipeline crash")

    pipeline = MagicMock()
    pipeline.run = _fail
    _patch_analysis_only_deps(monkeypatch, pipeline=pipeline)

    transition_calls: list[tuple[str, EventStatus]] = []

    async def _transition(
        event_id: str,
        target: EventStatus,
        **kwargs: object,
    ) -> None:
        transition_calls.append((event_id, target))

    state_machine = MagicMock()
    state_machine.transition = _transition

    async def _fake_state_machine() -> MagicMock:
        return state_machine

    monkeypatch.setattr("app.api.v1.deps.get_state_machine", _fake_state_machine)

    with pytest.raises(RuntimeError, match="pipeline crash"):
        await tasks.execute_analysis_only_investigation(
            "evt-ao-failed",
            owner_id="worker-test",
            lease_acquired=True,
        )

    assert transition_calls == [("evt-ao-failed", EventStatus.FAILED)]


@pytest.mark.asyncio
async def test_execute_analysis_only_releases_lease_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pipeline raises an unexpected error → lease is released in finally."""

    async def _fail(event_id: str, **kwargs: Any) -> None:
        raise RuntimeError("pipeline crash")

    pipeline = MagicMock()
    pipeline.run = _fail
    fake_lease = _patch_analysis_only_deps(monkeypatch, pipeline=pipeline)

    async def _fake_state_machine() -> MagicMock:
        machine = MagicMock()
        machine.transition = AsyncMock()
        return machine

    monkeypatch.setattr("app.api.v1.deps.get_state_machine", _fake_state_machine)

    with pytest.raises(RuntimeError, match="pipeline crash"):
        await tasks.execute_analysis_only_investigation(
            "evt-ao-crash",
            owner_id="worker-test",
            lease_acquired=True,
        )
    fake_lease.release.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatch_analysis_only_forwards_owner_id_and_lease_acquired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-225: dispatch threads owner_id + lease_acquired to the Celery task."""
    monkeypatch.setattr(tasks, "register_task_metadata", _noop_register)
    captured: dict[str, Any] = {}

    def _fake_apply_async(*_args: Any, **kwargs: Any) -> MagicMock:
        captured.update(kwargs)
        return MagicMock(id=kwargs["task_id"])

    monkeypatch.setattr(tasks.run_analysis_only_investigation, "apply_async", _fake_apply_async)

    task_id = await tasks.dispatch_analysis_only_investigation(
        "evt-ao-dispatch",
        owner_id="owner-http-1",
        lease_acquired=True,
        generate_report=False,
    )
    assert task_id
    assert captured["kwargs"] == {
        "generate_report": False,
        "owner_id": "owner-http-1",
        "lease_acquired": True,
    }


def test_run_analysis_only_eager_executes_task(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Eager mode: the Celery task runs execute_analysis_only_investigation."""

    async def _fake_execute(event_id: str, **kwargs: Any) -> dict[str, str]:
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_analysis_only_investigation", _fake_execute)
    result = tasks.run_analysis_only_investigation.apply(args=["evt-ao-eager"]).result
    assert result == {"status": "completed", "event_id": "evt-ao-eager"}


def test_run_analysis_only_redelivery_skips_terminal_event(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Broker redelivery after a terminal event must not re-run analysis_only."""
    from celery.app.task import Context

    calls = {"n": 0}

    async def _fake_execute(event_id: str, **kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_analysis_only_investigation", _fake_execute)

    async def _skip_redelivery(_event_id: str) -> tuple[bool, str]:
        return True, "terminal_event"

    monkeypatch.setattr(tasks, "evaluate_redelivered_investigation_skip", _skip_redelivery)

    ctx = Context(id="task-ao-redelivery", delivery_info={"redelivered": True}, retries=0)
    tasks.run_analysis_only_investigation.request_stack.push(ctx)
    try:
        result = tasks.run_analysis_only_investigation.run("evt-ao-terminal")
    finally:
        tasks.run_analysis_only_investigation.request_stack.pop()

    assert result["status"] == "skipped"
    assert result.get("reason") == "terminal_event"
    assert calls["n"] == 0


def test_run_analysis_only_honors_delivery_info_redelivered_flag(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise request.delivery_info['redelivered'] for analysis_only task."""
    from celery.app.task import Context

    captured: dict[str, Any] = {}

    async def _fake_body(
        event_id: str,
        *,
        generate_report: bool,
        owner_id: str,
        redelivered: bool,
        lease_acquired: bool = False,
    ) -> dict[str, str]:
        captured["redelivered"] = redelivered
        captured["owner_id"] = owner_id
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "_run_analysis_only_body", _fake_body)

    ctx = Context(id="task-ao-redelivery-flag", delivery_info={"redelivered": True}, retries=0)
    tasks.run_analysis_only_investigation.request_stack.push(ctx)
    try:
        result = tasks.run_analysis_only_investigation.run("evt-ao-redelivery-flag")
    finally:
        tasks.run_analysis_only_investigation.request_stack.pop()

    assert result["status"] == "completed"
    assert captured["redelivered"] is True
    assert captured["owner_id"] == celery_task_owner_id("task-ao-redelivery-flag")


@pytest.mark.asyncio
async def test_schedule_investigation_analysis_only_celery_routes_to_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-225: _schedule_investigation uses dispatch_analysis_only_investigation."""
    from fastapi import BackgroundTasks

    from app.api.v1.events import _schedule_investigation
    from app.core.config import get_settings

    monkeypatch.setenv("ORCHESTRATION_MODE", "analysis_only")
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    captured: dict[str, object] = {}

    class _TrackingLease:
        async def acquire(self, _event_id: str, owner_id: str, ttl_s: int = 600) -> bool:
            captured["owner_id"] = owner_id
            return True

        async def release(self, ev_id: str, owner_id: str) -> bool:
            captured["released"] = (ev_id, owner_id)
            return True

    async def _dispatch(
        event_id: str,
        *,
        generate_report: bool = True,
        owner_id: str | None = None,
        lease_acquired: bool = False,
    ) -> str:
        captured["event_id"] = event_id
        captured["generate_report"] = generate_report
        captured["dispatch_owner_id"] = owner_id
        captured["lease_acquired"] = lease_acquired
        return "task-analysis-only-schedule"

    async def _noop_record(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr("app.api.v1.events.get_event_lease", lambda: _TrackingLease())
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.dispatch_analysis_only_investigation",
        _dispatch,
    )
    monkeypatch.setattr(
        "app.api.v1.events.record_investigation_workflow_path",
        _noop_record,
    )

    task_id = await _schedule_investigation(
        event_id="evt-schedule-ao",
        background=BackgroundTasks(),
        state_machine=MagicMock(),
    )
    assert task_id == "task-analysis-only-schedule"
    assert captured["event_id"] == "evt-schedule-ao"
    assert captured["lease_acquired"] is True
    assert captured["dispatch_owner_id"] == captured["owner_id"]
    assert "released" not in captured
