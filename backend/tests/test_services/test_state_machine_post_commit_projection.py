"""ISSUE-285: committed state transitions survive post-commit projection faults."""

from __future__ import annotations

import copy
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from app.api.v1.events import close_event, repair_event_projection
from app.api.v1.schemas import EventCloseRequest
from app.core.auth import ROLE_ADMIN, Principal
from app.core.metrics import (
    reset_metrics_for_tests,
    state_projection_health_snapshot,
)
from app.models.enums import EventStatus, FinalVerdict
from app.models.workflow import TransitionContext
from app.orchestration.workflow_graph import _transition_status
from app.services.context_service import SetResult
from app.services.degraded_flag_service import apply_flag_to_list
from app.services.state_machine_service import (
    STATE_TRANSITION_PROJECTION_DEGRADED_FLAG,
    PostCommitProjectionOutcome,
    StateMachineService,
)


@dataclass
class _Row:
    event_id: str = "evt-post-commit"
    status: str = EventStatus.NEW.value
    row_version: int = 1
    replan_count: int = 0
    degraded_flags: list[str] = field(default_factory=list)
    external_unsynced: bool = False
    escalated: bool = False
    closed_at: Any = None
    updated_at: Any = None
    final_verdict: str = FinalVerdict.NONE.value
    disposition_policy: str = "not_required"


@dataclass
class _DurableState:
    row: _Row
    audits: list[dict[str, Any]] = field(default_factory=list)
    committed_transactions: int = 0


class _Result:
    def __init__(self, items: list[Any]) -> None:
        self._items = items

    def all(self) -> list[Any]:
        return list(self._items)


class _Transaction:
    def __init__(self, session: _Session) -> None:
        self._session = session

    async def __aenter__(self) -> None:
        self._session.working_row = copy.deepcopy(self._session.state.row)
        self._session.pending_audits = []

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc, traceback
        if exc_type is None:
            assert self._session.working_row is not None
            self._session.state.row = self._session.working_row
            self._session.state.audits.extend(self._session.pending_audits)
            self._session.state.committed_transactions += 1
        self._session.working_row = None
        self._session.pending_audits = []


class _Session:
    def __init__(self, state: _DurableState) -> None:
        self.state = state
        self.working_row: _Row | None = None
        self.pending_audits: list[dict[str, Any]] = []

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback

    def begin(self) -> _Transaction:
        return _Transaction(self)

    async def get(self, _model: Any, event_id: str, **_kwargs: Any) -> _Row | None:
        row = self.working_row if self.working_row is not None else self.state.row
        return row if row.event_id == event_id else None

    async def scalars(self, statement: Any) -> _Result:
        text = str(statement).lower()
        if "event_audit_log" in text:
            return _Result(
                [
                    SimpleNamespace(
                        id=audit["id"],
                        event_id=audit["event_id"],
                        from_status=audit["from_status"],
                        to_status=audit["to_status"],
                        operator=audit["operator"],
                        reason=audit["reason"],
                        created_at=None,
                    )
                    for audit in self.state.audits
                    if audit["event_id"] == self.state.row.event_id
                ]
            )
        if (
            STATE_TRANSITION_PROJECTION_DEGRADED_FLAG.replace("_", "") in text.replace("_", "")
            or "degraded_flags" in text
        ):
            if any(
                str(flag).startswith(f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=")
                for flag in self.state.row.degraded_flags
            ):
                return _Result([self.state.row.event_id])
            return _Result([])
        return _Result([])

    async def flush(self) -> None:
        return None

    async def scalar(self, _statement: Any) -> Any:
        return None

    async def refresh(self, _row: _Row) -> None:
        return None


class _SessionFactory:
    def __init__(self, state: _DurableState) -> None:
        self.state = state

    def __call__(self) -> _Session:
        return _Session(self.state)


class _AuditLog:
    async def log_transition_in_session(
        self,
        session: _Session,
        event_id: str,
        from_status: str | None,
        to_status: str | None,
        operator: str | None,
        reason: str | None,
    ) -> str:
        audit_id = len(session.state.audits) + len(session.pending_audits) + 1
        session.pending_audits.append(
            {
                "id": audit_id,
                "event_id": event_id,
                "from_status": from_status,
                "to_status": to_status,
                "operator": operator,
                "reason": reason,
            }
        )
        return str(audit_id)


class _ProjectionStore:
    def __init__(self) -> None:
        self.values: dict[str, Any] = {"state_history": []}
        self.raise_step: str | None = None
        self.degraded_step: str | None = None
        self.raise_get_history = False
        self.calls: Counter[str] = Counter()

    @staticmethod
    def _step_for_key(key: str) -> str:
        return {
            "event": "summary",
            "state_history": "history",
            "replan_count": "replan_count",
            "degraded_flags": "degraded_flag",
        }.get(key, key)

    async def set(self, _event_id: str, key: str, value: Any) -> SetResult:
        step = self._step_for_key(key)
        self.calls[step] += 1
        if self.raise_step == step:
            raise RuntimeError(f"{step} direct failure")
        self.values[key] = value
        return SetResult(redis_ok=self.degraded_step != step, version=self.calls[step])

    async def get(self, _event_id: str, key: str) -> Any:
        self.calls[f"get:{key}"] += 1
        if key == "state_history" and self.raise_get_history:
            raise RuntimeError("history get failure")
        return copy.deepcopy(self.values.get(key, []))

    async def refresh_closed_snapshot(self, _event_id: str) -> SimpleNamespace:
        self.calls["snapshot"] += 1
        if self.raise_step == "snapshot":
            raise RuntimeError("snapshot direct failure")
        self.values["snapshot"] = {"rebuilt": True}
        return SimpleNamespace()

    async def set_closed_ttl(self, _event_id: str) -> bool:
        self.calls["closed_ttl"] += 1
        if self.raise_step == "closed_ttl":
            raise RuntimeError("TTL direct failure")
        return self.degraded_step != "closed_ttl"


class _DegradedFlags:
    def __init__(self, state: _DurableState) -> None:
        self.state = state

    async def set_flag(
        self,
        _event_id: str,
        flag_name: str,
        value: Any,
        writer: str,
    ) -> list[str]:
        assert writer == "StateMachineService"
        updated = apply_flag_to_list(self.state.row.degraded_flags, flag_name, value)
        self.state.row.degraded_flags = updated
        return updated

    async def get_flag_value(self, _event_id: str, flag_name: str) -> str | None:
        prefix = f"{flag_name}="
        for flag in self.state.row.degraded_flags:
            text = str(flag)
            if text == flag_name:
                return "true"
            if text.startswith(prefix):
                return text[len(prefix) :]
        return None

    async def has_flag(self, event_id: str, flag_name: str) -> bool:
        return (await self.get_flag_value(event_id, flag_name)) is not None


class _FailingBus:
    def __init__(self) -> None:
        self.calls = 0

    async def publish_event(self, *_args: Any, **_kwargs: Any) -> None:
        self.calls += 1
        raise RuntimeError("bus down")


def _event_from_row(row: _Row) -> SimpleNamespace:
    return SimpleNamespace(
        event_id=row.event_id,
        status=EventStatus(row.status),
        final_verdict=FinalVerdict(row.final_verdict),
        external_unsynced=row.external_unsynced,
        degraded_flags=list(row.degraded_flags),
    )


async def _authoritative_context(*_args: Any, **_kwargs: Any) -> TransitionContext:
    return TransitionContext()


async def _noop_reconcile_stale_executions(*_args: Any, **_kwargs: Any) -> int:
    return 0


def _build_service(
    monkeypatch: pytest.MonkeyPatch,
    *,
    initial: EventStatus = EventStatus.NEW,
    bus: Any | None = None,
) -> tuple[StateMachineService, _DurableState, _ProjectionStore]:
    state = _DurableState(row=_Row(status=initial.value))
    store = _ProjectionStore()
    monkeypatch.setattr(
        "app.services.state_machine_service.reconcile_stale_executions_before_close",
        _noop_reconcile_stale_executions,
    )
    monkeypatch.setattr(
        "app.services.state_machine_service._build_authoritative_context",
        _authoritative_context,
    )
    monkeypatch.setattr(
        "app.services.state_machine_service.validate_transition",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "app.services.state_machine_service.event_summary_from_security_event",
        lambda row: {"event_id": row.event_id, "status": row.status},
    )
    monkeypatch.setattr(
        "app.services.state_machine_service._security_event_from_row",
        _event_from_row,
    )
    service = StateMachineService(
        _SessionFactory(state),  # type: ignore[arg-type]
        store,  # type: ignore[arg-type]
        event_bus=bus,
        audit_log=_AuditLog(),  # type: ignore[arg-type]
        degraded_flags=_DegradedFlags(state),  # type: ignore[arg-type]
    )
    return service, state, store


@pytest.fixture(autouse=True)
def _reset_projection_metrics() -> Iterator[None]:
    reset_metrics_for_tests()
    yield
    reset_metrics_for_tests()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("step", "initial", "target"),
    [
        ("summary", EventStatus.NEW, EventStatus.TRIAGING),
        ("history", EventStatus.NEW, EventStatus.TRIAGING),
        ("snapshot", EventStatus.REPORTING, EventStatus.CLOSED),
    ],
)
async def test_direct_projection_exception_returns_committed_state_and_repairs_safely(
    monkeypatch: pytest.MonkeyPatch,
    step: str,
    initial: EventStatus,
    target: EventStatus,
) -> None:
    service, state, store = _build_service(monkeypatch, initial=initial)
    store.raise_step = step

    result = await service.transition(
        state.row.event_id,
        target,
        operator="fault-injection",
        reason=f"raise:{step}",
    )

    assert result.status is target
    assert state.row.status == target.value
    assert state.row.row_version == 2
    assert state.committed_transactions == 1
    assert len(state.audits) == 1
    assert any(
        flag.startswith(f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=")
        and f"{step}:raised" in flag
        and "proj=audit:1" in flag
        for flag in state.row.degraded_flags
    )

    store.raise_step = None
    repaired = await service.repair_post_commit_projection(
        state.row.event_id,
        backoff_seconds=0,
    )
    repeated = await service.repair_post_commit_projection(
        state.row.event_id,
        backoff_seconds=0,
    )

    assert repaired == PostCommitProjectionOutcome(
        committed=True,
        projection_id="audit:1",
        attempts=1,
    )
    assert repeated.degraded is False
    assert state.row.status == target.value
    assert state.row.row_version == 2
    assert state.committed_transactions == 1
    assert len(state.audits) == 1
    assert store.values["event"]["status"] == target.value
    assert len(store.values["state_history"]) == 1
    assert store.values["state_history"][0]["transition_id"] == "audit:1"
    if step == "snapshot" or target is EventStatus.CLOSED:
        assert store.values.get("snapshot") == {"rebuilt": True}
    assert not any(
        flag.startswith(f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=")
        for flag in state.row.degraded_flags
    )


@pytest.mark.asyncio
async def test_returned_degraded_is_distinct_from_direct_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch)
    store.degraded_step = "summary"

    result = await service.transition(state.row.event_id, EventStatus.TRIAGING)

    assert result.status is EventStatus.TRIAGING
    assert len(state.audits) == 1
    assert any("summary:returned_degraded" in flag for flag in state.row.degraded_flags)
    assert "redis_context_unavailable=true" in state.row.degraded_flags
    assert state_projection_health_snapshot()["projection_failures"] == 1

    store.degraded_step = None
    repaired = await service.repair_post_commit_projection(
        state.row.event_id,
        backoff_seconds=0,
    )
    assert repaired.degraded is False
    # Shared Redis flag is owned by recovery wiring — repair must not clear it.
    assert "redis_context_unavailable=true" in state.row.degraded_flags
    assert not any(
        flag.startswith(f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=")
        for flag in state.row.degraded_flags
    )


@pytest.mark.asyncio
async def test_closed_ttl_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch, initial=EventStatus.REPORTING)
    store.raise_step = "closed_ttl"
    raised = await service.transition(state.row.event_id, EventStatus.CLOSED)
    assert raised.status is EventStatus.CLOSED
    assert any("closed_ttl:raised" in flag for flag in state.row.degraded_flags)


@pytest.mark.asyncio
async def test_closed_ttl_returned_degraded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch, initial=EventStatus.REPORTING)
    store.degraded_step = "closed_ttl"
    degraded = await service.force_close(
        state.row.event_id,
        principal=Principal(subject="admin-1", roles=[ROLE_ADMIN]),
        reason="ttl-degraded",
    )
    assert degraded.status is EventStatus.CLOSED
    assert any("closed_ttl:returned_degraded" in flag for flag in state.row.degraded_flags)


@pytest.mark.asyncio
async def test_history_get_exception_does_not_overwrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch)
    store.values["state_history"] = [{"transition_id": "seed", "to_status": "new"}]
    store.raise_get_history = True
    result = await service.transition(state.row.event_id, EventStatus.TRIAGING)
    assert result.status is EventStatus.TRIAGING
    assert store.values["state_history"] == [{"transition_id": "seed", "to_status": "new"}]
    assert any("history:raised" in flag for flag in state.row.degraded_flags)


@pytest.mark.asyncio
async def test_event_bus_publish_failure_does_not_imply_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _FailingBus()
    service, state, _store = _build_service(monkeypatch, bus=bus)
    result = await service.transition(state.row.event_id, EventStatus.TRIAGING)
    assert result.status is EventStatus.TRIAGING
    assert state.committed_transactions == 1
    assert bus.calls == 1


@pytest.mark.asyncio
async def test_projection_repair_is_bounded_and_never_replays_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch)
    store.raise_step = "history"
    await service.transition(state.row.event_id, EventStatus.TRIAGING)
    transition_commits = state.committed_transactions
    transition_audits = len(state.audits)
    transition_version = state.row.row_version

    outcome = await service.repair_post_commit_projection(
        state.row.event_id,
        max_attempts=99,
        backoff_seconds=0,
    )

    assert outcome.degraded is True
    assert outcome.attempts == 3
    assert store.calls["history"] == 4  # initial projection + three repair attempts
    assert state.committed_transactions == transition_commits
    assert len(state.audits) == transition_audits
    assert state.row.row_version == transition_version
    assert state.row.status == EventStatus.TRIAGING.value
    assert state_projection_health_snapshot()["projection_repairs"] == 1


@pytest.mark.asyncio
async def test_repair_degraded_projections_entrypoint_clears_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch)
    store.raise_step = "summary"
    await service.transition(state.row.event_id, EventStatus.TRIAGING)
    assert any(
        flag.startswith(f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=")
        for flag in state.row.degraded_flags
    )
    store.raise_step = None

    summary = await service.repair_degraded_projections(limit=10)
    assert summary == {"scanned": 1, "repaired": 1, "exhausted": 0}
    assert not any(
        flag.startswith(f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=")
        for flag in state.row.degraded_flags
    )
    assert store.values["event"]["status"] == EventStatus.TRIAGING.value


@pytest.mark.asyncio
async def test_admin_projection_repair_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch)
    store.raise_step = "summary"
    await service.transition(state.row.event_id, EventStatus.TRIAGING)
    store.raise_step = None

    class _EventService:
        async def get_event(self, _event_id: str) -> SimpleNamespace:
            return _event_from_row(state.row)

    response = await repair_event_projection(
        event_id=state.row.event_id,
        principal=Principal(subject="admin-1", roles=[ROLE_ADMIN]),
        event_service=_EventService(),  # type: ignore[arg-type]
        state_machine=service,
    )
    assert response.degraded is False
    assert response.projection_id == "audit:1"
    assert not any(
        flag.startswith(f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=")
        for flag in state.row.degraded_flags
    )


@pytest.mark.asyncio
async def test_stale_marker_is_not_cleared_by_older_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch)
    store.raise_step = "summary"
    await service.transition(state.row.event_id, EventStatus.TRIAGING)
    store.raise_step = None
    # Simulate a newer degradation generation written by a concurrent transition.
    state.row.degraded_flags = [
        f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=summary:raised|proj=audit:99"
    ]
    outcome = await service.repair_post_commit_projection(
        state.row.event_id,
        backoff_seconds=0,
    )
    assert outcome.degraded is False
    assert any("proj=audit:99" in flag for flag in state.row.degraded_flags)


@pytest.mark.asyncio
async def test_graph_receives_committed_status_without_retrying_projection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch)
    store.raise_step = "summary"
    monkeypatch.setattr(
        "app.orchestration.workflow_graph.get_settings",
        lambda: SimpleNamespace(
            super_agent_transition_max_retries=3,
            super_agent_transition_retry_backoff_seconds=0,
        ),
    )

    patch = await _transition_status(
        {"state_machine": service},
        {"event_id": state.row.event_id, "event_status": EventStatus.NEW.value},
        EventStatus.TRIAGING,
        reason="graph:fault-injection",
    )

    assert patch["event_status"] == EventStatus.TRIAGING.value
    assert state.row.status == EventStatus.TRIAGING.value
    assert state.row.row_version == 2
    assert len(state.audits) == 1


@pytest.mark.asyncio
async def test_api_force_close_returns_committed_status_when_snapshot_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch, initial=EventStatus.REPORTING)
    store.raise_step = "snapshot"

    class _EventService:
        async def get_event(self, _event_id: str) -> SimpleNamespace:
            return _event_from_row(state.row)

    response = await close_event(
        event_id=state.row.event_id,
        body=EventCloseRequest(reason="admin close", force_local_close=True),
        principal=Principal(subject="admin-1", roles=[ROLE_ADMIN]),
        event_service=_EventService(),  # type: ignore[arg-type]
        state_machine=service,
    )

    assert response.status is EventStatus.CLOSED
    assert response.external_unsynced is True
    assert state.row.status == EventStatus.CLOSED.value
    assert state.row.row_version == 2
    assert len(state.audits) == 1


@pytest.mark.asyncio
async def test_repair_without_transition_audit_remains_explicitly_unrepairable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, state, store = _build_service(monkeypatch)
    state.row.status = EventStatus.TRIAGING.value
    state.row.degraded_flags = [
        f"{STATE_TRANSITION_PROJECTION_DEGRADED_FLAG}=history:raised|proj=row-version:2"
    ]
    outcome = await service.repair_post_commit_projection(
        state.row.event_id,
        backoff_seconds=0,
    )
    assert outcome.degraded is True
    assert any(failure.step == "history" for failure in outcome.failures)
    assert "state_history" not in store.values or store.values["state_history"] == []
