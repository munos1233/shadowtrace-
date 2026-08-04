"""Celery redelivery matrix + lease fencing tests (ISSUE-117 / #622 Phase B)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.celery_app import celery_app
from app.core.celery_delivery import celery_task_owner_id, normalize_public_task_state
from app.core.errors import InvestigationInProgressError
from app.core.redis_client import RedisClient
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    Severity,
    SourceObjectKind,
)
from app.models.security_event import SecurityEvent
from app.models.source import SourceReference
from app.orchestration.lease import EventLease, generate_owner_id
from app.tasks import investigation_tasks as tasks


def test_celery_app_rejects_lost_worker_tasks() -> None:
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.task_reject_on_worker_lost is True
    assert celery_app.conf.worker_prefetch_multiplier == 1
    assert celery_app.conf.broker_transport_options.get("visibility_timeout") == 900


def test_celery_task_owner_id_is_stable_per_task() -> None:
    assert celery_task_owner_id("task-abc-123") == "celery-task-abc-123"
    assert celery_task_owner_id("task-abc-123") == celery_task_owner_id("task-abc-123")
    assert celery_task_owner_id("other") != celery_task_owner_id("task-abc-123")


@pytest.mark.parametrize(
    ("celery_state", "expected"),
    [
        ("SUCCESS", "SUCCESS"),
        ("PENDING", "PENDING"),
        ("FAILURE", "FAILURE"),
        ("STARTED", "STARTED"),
        ("RETRY", "UNKNOWN"),
        ("REVOKED", "UNKNOWN"),
    ],
)
def test_normalize_public_task_state_matrix(celery_state: str, expected: str) -> None:
    assert normalize_public_task_state(celery_state) == expected


@pytest.mark.asyncio
async def test_execute_investigation_forwards_celery_owner_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    async def _investigate(event_id: str, **kwargs: Any) -> None:
        seen["event_id"] = event_id
        seen["owner_id"] = kwargs.get("owner_id")

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

    owner_id = celery_task_owner_id("task-owner-forward")
    result = await tasks.execute_investigation(
        "evt-owner",
        owner_id=owner_id,
    )
    assert result == {"status": "completed", "event_id": "evt-owner"}
    assert seen == {"event_id": "evt-owner", "owner_id": owner_id}


def test_run_investigation_uses_task_id_owner(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def _fake_execute(
        event_id: str,
        *,
        include_response_execution: bool = False,
        owner_id: str | None = None,
        lease_acquired: bool = False,
    ) -> dict[str, str]:
        captured["event_id"] = event_id
        captured["owner_id"] = owner_id
        captured["include_response_execution"] = include_response_execution
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)
    async_result = tasks.run_investigation.apply(
        args=["evt-celery-owner"],
        task_id="task-fixed-owner-001",
    )
    assert async_result.result["status"] == "completed"
    assert captured["owner_id"] == celery_task_owner_id("task-fixed-owner-001")


@pytest.mark.asyncio
async def test_redelivery_skips_when_lease_still_held(
    monkeypatch: pytest.MonkeyPatch,
    redis_client: RedisClient,
) -> None:
    """Crash-before-ack redelivery while the first delivery still holds the lease."""
    lease = EventLease(redis_client)
    event_id = "evt-redelivery-skip"
    task_id = "task-redelivery-skip"
    owner_id = celery_task_owner_id(task_id)

    assert await lease.acquire(event_id, owner_id, ttl_s=600)

    async def _investigate(event_id: str, *, owner_id: str | None = None, **_kwargs: Any) -> None:
        resolved_owner = owner_id or generate_owner_id()
        if not await lease.acquire(event_id, resolved_owner):
            raise InvestigationInProgressError(
                message="investigation already in progress for this event",
                error_code="investigation_in_progress",
                details={"event_id": event_id},
            )

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

    result = await tasks.execute_investigation(event_id, owner_id=owner_id)
    assert result == {
        "status": "skipped",
        "event_id": event_id,
        "reason": "investigation_in_progress",
    }

    stale_owner = generate_owner_id()
    assert stale_owner != owner_id
    assert await lease.acquire(event_id, stale_owner) is False

    await lease.release(event_id, owner_id)


@pytest.mark.asyncio
async def test_redelivery_runs_after_lease_expires(
    monkeypatch: pytest.MonkeyPatch,
    redis_client: RedisClient,
) -> None:
    """After the original delivery releases, the same celery owner id can acquire again."""
    lease = EventLease(redis_client)
    event_id = "evt-redelivery-retry"
    task_id = "task-redelivery-retry"
    owner_id = celery_task_owner_id(task_id)

    assert await lease.acquire(event_id, owner_id, ttl_s=60)
    assert await lease.release(event_id, owner_id)
    assert await lease.acquire(event_id, owner_id, ttl_s=60) is True

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

    result = await tasks.execute_investigation(event_id, owner_id=owner_id)
    assert result == {"status": "completed", "event_id": event_id}
    assert calls == [event_id]
    await lease.release(event_id, owner_id)


def test_after_success_first_delivery_runs_once(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful delivery executes investigation exactly once."""
    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    result = tasks.run_investigation.apply(
        args=["evt-after-ack"],
        task_id="task-after-ack-1",
    ).result
    assert result["status"] == "completed"
    assert calls["n"] == 1


def _run_with_redelivered_request(
    *,
    task_id: str,
    event_id: str,
) -> dict[str, str]:
    """Push a Celery request context with ``delivery_info.redelivered=True``."""
    from celery.app.task import Context

    ctx = Context(id=task_id, delivery_info={"redelivered": True}, retries=0)
    tasks.run_investigation.request_stack.push(ctx)
    try:
        return tasks.run_investigation.run(event_id)
    finally:
        tasks.run_investigation.request_stack.pop()


def test_run_investigation_honors_delivery_info_redelivered_flag(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise ``request.delivery_info['redelivered']`` without patching the body helper."""
    captured: dict[str, Any] = {}

    async def _fake_body(
        event_id: str,
        *,
        include_response_execution: bool,
        owner_id: str,
        redelivered: bool,
        lease_acquired: bool = False,
    ) -> dict[str, str]:
        captured["redelivered"] = redelivered
        captured["owner_id"] = owner_id
        return {"status": "completed", "event_id": event_id}

    monkeypatch.setattr(tasks, "_run_investigation_body", _fake_body)

    result = _run_with_redelivered_request(
        task_id="task-redelivery-flag",
        event_id="evt-redelivery-flag",
    )

    assert result["status"] == "completed"
    assert captured["redelivered"] is True
    assert captured["owner_id"] == celery_task_owner_id("task-redelivery-flag")


def test_redelivery_skips_when_event_terminal(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Broker redelivery after a terminal event must not re-run investigation."""
    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    closed_event = SecurityEvent(
        event_id="evt-terminal-redelivery",
        event_type=EventType.OTHER,
        title="closed",
        status=EventStatus.CLOSED,
        severity=Severity.LOW,
        creation_source_ref=SourceReference(
            source_kind=SourceObjectKind.INCIDENT,
            source_product="manual",
            source_tenant_id="tenant-test",
            connector_id="conn-test",
            source_object_id="manual-1",
            ingested_at=datetime.now(UTC),
        ),
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return closed_event

    async def _fake_get_event_service() -> _EventService:
        return _EventService()

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fake_get_event_service)
    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    result = _run_with_redelivered_request(
        task_id="task-terminal-redelivery",
        event_id="evt-terminal-redelivery",
    )

    assert result["status"] == "skipped"
    assert result.get("reason") == "terminal_event"
    assert calls["n"] == 0


def test_redelivery_skips_with_lookup_degraded_reason(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    async def _fail_service() -> None:
        from app.core.errors import DependencyUnavailableError

        raise DependencyUnavailableError(
            message="postgres unavailable",
            error_code="dependency_unavailable",
            details={"dependency": "postgres"},
        )

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fail_service)
    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    result = _run_with_redelivered_request(
        task_id="task-degraded-redelivery",
        event_id="evt-degraded-redelivery",
    )

    assert result["status"] == "skipped"
    assert result.get("reason") == "lookup_degraded"
    assert calls["n"] == 0


@pytest.mark.parametrize(
    "status",
    [
        EventStatus.WAITING_APPROVAL,
        EventStatus.EXECUTING_RESPONSE,
        EventStatus.VERIFYING,
    ],
)
def test_redelivery_skips_for_post_response_terminal_states(
    celery_eager: None,
    monkeypatch: pytest.MonkeyPatch,
    status: EventStatus,
) -> None:
    calls = {"n": 0}

    async def _fake_execute(event_id: str, **_kwargs: Any) -> dict[str, str]:
        calls["n"] += 1
        return {"status": "completed", "event_id": event_id}

    event = SecurityEvent(
        event_id=f"evt-{status.value}",
        event_type=EventType.OTHER,
        title="terminal",
        status=status,
        severity=Severity.LOW,
        creation_source_ref=SourceReference(
            source_kind=SourceObjectKind.INCIDENT,
            source_product="manual",
            source_tenant_id="tenant-test",
            connector_id="conn-test",
            source_object_id="manual-1",
            ingested_at=datetime.now(UTC),
        ),
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
    )

    class _EventService:
        async def get_event(self, _event_id: str) -> SecurityEvent:
            return event

    async def _fake_get_event_service() -> _EventService:
        return _EventService()

    monkeypatch.setattr("app.api.v1.deps.get_event_service", _fake_get_event_service)
    monkeypatch.setattr(tasks, "execute_investigation", _fake_execute)

    result = _run_with_redelivered_request(
        task_id=f"task-{status.value}",
        event_id=event.event_id,
    )

    assert result["status"] == "skipped"
    assert result.get("reason") == "terminal_event"
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_resolve_task_state_maps_retry_to_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tasks, "lookup_task_event_id", AsyncMock(return_value="evt-unknown"))

    class _FakeResult:
        state = "RETRY"
        info = None
        args = ("evt-unknown",)

    with patch("celery.result.AsyncResult", return_value=_FakeResult()):
        state, event_id = await tasks.resolve_task_state("task-retry-unknown")

    assert state == "UNKNOWN"
    assert event_id == "evt-unknown"


def _null_context() -> Any:
    from contextlib import nullcontext

    return nullcontext()
