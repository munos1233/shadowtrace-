"""StateMachineService tests — lifecycle, invalid edges, concurrency, side effects.

Requires Compose PostgreSQL + Redis.  Run from ``backend/``:

    pytest tests/test_services/test_state_machine_service.py -v
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import EventNotFoundError, InvalidStateTransitionError
from app.core.event_bus import EventBus
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
)
from app.models.source import SourceReference
from app.models.workflow import MAX_REPLAN_COUNT
from app.services.context_service import EventContextStore, event_summary_from_security_event
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.state_machine_service import StateMachineService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# --------------------------------------------------------------------------- #
# Module-level fixtures
# --------------------------------------------------------------------------- #


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[RedisClient]:
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def store(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> EventContextStore:
    return EventContextStore(redis_client, session_factory)


@pytest_asyncio.fixture
async def degraded(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> DegradedFlagService:
    return DegradedFlagService(store, session_factory)


@pytest_asyncio.fixture
async def audit_log(
    session_factory: async_sessionmaker[AsyncSession],
) -> EventAuditLogService:
    return EventAuditLogService(session_factory)


@pytest_asyncio.fixture
async def state_machine(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    redis_client: RedisClient,
    audit_log: EventAuditLogService,
    degraded: DegradedFlagService,
) -> StateMachineService:
    bus = EventBus(redis_client)
    return StateMachineService(
        session_factory,
        store,
        event_bus=bus,
        audit_log=audit_log,
        degraded_flags=degraded,
    )


@pytest_asyncio.fixture
async def state_machine_minimal(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> StateMachineService:
    """StateMachineService with all optional dependencies set to None."""
    return StateMachineService(session_factory, store)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _ref(*, kind: SourceObjectKind, object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=kind,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-mock",
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )


async def _create_event(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    **overrides,
) -> str:
    """Create a minimal SecurityEvent in NEW status and return its event_id."""
    sfx = _sfx()
    event_id = f"evt-20260720-{sfx}"
    now = datetime.now(UTC)
    ref = _ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}")

    async with session_factory() as session:
        async with session.begin():
            row = orm.SecurityEvent(
                event_id=event_id,
                event_type=overrides.get("event_type", EventType.OTHER.value),
                title=overrides.get("title", "test-event"),
                description=overrides.get("description", ""),
                status=overrides.get("status", EventStatus.NEW.value),
                severity=overrides.get("severity", Severity.LOW.value),
                risk_score=overrides.get("risk_score", 10),
                confidence=overrides.get("confidence", 0.5),
                final_verdict=overrides.get("final_verdict", FinalVerdict.NONE.value),
                creation_source_ref=ref.model_dump(mode="json"),
                source_reference_snapshots=[ref.model_dump(mode="json")],
                disposition_policy=overrides.get(
                    "disposition_policy", DispositionPolicy.NOT_REQUIRED.value
                ),
                occurred_at=now,
                replan_count=overrides.get("replan_count", 0),
            )
            session.add(row)
            await session.flush()

    # Initialise EventContext.
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        summary = event_summary_from_security_event(row)
    await store.init_context(event_id, summary)
    return event_id


async def _walk_to_reporting(
    state_machine: StateMachineService,
    event_id: str,
) -> None:
    """Convenience helper: walk NEW → … → REPORTING."""
    for target, op in [
        (EventStatus.TRIAGING, "TriageAgent"),
        (EventStatus.COLLECTING_EVIDENCE, "EvidenceAgent"),
        (EventStatus.ANALYZING, "SuperAgent"),
        (EventStatus.SCORING, "RiskAgent"),
        (EventStatus.REPORTING, "SuperAgent"),
    ]:
        await state_machine.transition(event_id, target, operator=op, reason="test")


async def _walk_to_verifying(
    state_machine: StateMachineService,
    event_id: str,
) -> None:
    """Convenience helper: walk NEW → … → VERIFYING."""
    for target, op in [
        (EventStatus.TRIAGING, "TriageAgent"),
        (EventStatus.COLLECTING_EVIDENCE, "EvidenceAgent"),
        (EventStatus.ANALYZING, "SuperAgent"),
        (EventStatus.SCORING, "RiskAgent"),
        (EventStatus.PLANNING_RESPONSE, "ResponseAgent"),
        (EventStatus.EXECUTING_RESPONSE, "SuperAgent"),
        (EventStatus.VERIFYING, "VerifyAgent"),
    ]:
        await state_machine.transition(event_id, target, operator=op, reason="test")


async def _add_report(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> None:
    async with session_factory() as s:
        async with s.begin():
            s.add(
                orm.Report(
                    report_id=f"rpt-{uuid.uuid4().hex[:8]}",
                    event_id=event_id,
                    title="test report",
                    report_data={"sections": []},
                )
            )


@pytest_asyncio.fixture(autouse=True)
async def cleanup(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    """Clean all event-related rows between tests."""
    yield
    async with session_factory() as session:
        async with session.begin():
            for table in (
                orm.EventAuditLog,
                orm.EventContextJournal,
                orm.EventContextFieldVersion,
                orm.DispositionOutbox,
                orm.Action,
                orm.Report,
                orm.SourceEventLink,
                orm.SourceObject,
                orm.SecurityEvent,
            ):
                await session.execute(delete(table))


# ===================================================================
# Basic lifecycle
# ===================================================================


@pytest.mark.asyncio
async def test_new_to_triaging(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    result = await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="start triage"
    )
    assert result.status == EventStatus.TRIAGING
    assert result.row_version == 2

    async with session_factory() as s:
        row = await s.get(orm.SecurityEvent, event_id)
        assert row is not None and row.status == EventStatus.TRIAGING.value


@pytest.mark.asyncio
async def test_full_happy_path_new_to_closed_not_required(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    audit_log: EventAuditLogService,
) -> None:
    """Walk NEW → … → CLOSED for a not_required event (each step must succeed)."""
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)

    path = [
        (EventStatus.TRIAGING, "TriageAgent", "triage"),
        (EventStatus.COLLECTING_EVIDENCE, "EvidenceAgent", "collect"),
        (EventStatus.ANALYZING, "SuperAgent", "analyze"),
        (EventStatus.SCORING, "RiskAgent", "score"),
        (EventStatus.REPORTING, "SuperAgent", "skip plan"),
    ]

    for target, op, reason in path:
        result = await state_machine.transition(event_id, target, operator=op, reason=reason)
        assert result.status == target, f"failed at {target.value}"

    await _add_report(session_factory, event_id)

    final = await state_machine.transition(
        event_id, EventStatus.CLOSED, operator="SuperAgent", reason="done"
    )
    assert final.status == EventStatus.CLOSED
    assert final.closed_at is not None

    logs = await audit_log.get_logs_by_event(event_id)
    assert len(logs) >= len(path) + 1  # +1 for CLOSED


# ===================================================================
# Invalid transitions
# ===================================================================


@pytest.mark.asyncio
async def test_invalid_transition_raises(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)

    with pytest.raises(InvalidStateTransitionError, match="illegal transition"):
        await state_machine.transition(
            event_id, EventStatus.ANALYZING, operator="test", reason="bad jump"
        )

    current = await state_machine.get_current_status(event_id)
    assert current == EventStatus.NEW


@pytest.mark.asyncio
async def test_closed_is_terminal(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)
    await state_machine.transition(
        event_id, EventStatus.CLOSED, operator="SuperAgent", reason="done"
    )

    with pytest.raises(InvalidStateTransitionError):
        await state_machine.transition(
            event_id, EventStatus.REPORTING, operator="test", reason="reopen"
        )


# ===================================================================
# REPLANNING limit
# ===================================================================


@pytest.mark.asyncio
async def test_replan_count_limit(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    await _walk_to_verifying(state_machine, event_id)

    for i in range(MAX_REPLAN_COUNT):
        result = await state_machine.transition(
            event_id, EventStatus.REPLANNING, operator="SuperAgent", reason=f"replan {i + 1}"
        )
        assert result.replan_count == i + 1
        # Move back to a REPLANNING-capable state.
        await state_machine.transition(
            event_id, EventStatus.PLANNING_RESPONSE, operator="ResponseAgent", reason="re-plan"
        )
        await state_machine.transition(
            event_id, EventStatus.EXECUTING_RESPONSE, operator="SuperAgent", reason="re-exec"
        )
        await state_machine.transition(
            event_id, EventStatus.VERIFYING, operator="VerifyAgent", reason="re-verify"
        )

    with pytest.raises(InvalidStateTransitionError, match="replan_count"):
        await state_machine.transition(
            event_id, EventStatus.REPLANNING, operator="SuperAgent", reason="over limit"
        )


# ===================================================================
# Concurrent transition race
# ===================================================================


@pytest.mark.asyncio
async def test_concurrent_transition_only_one_wins(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)

    async def try_triaging() -> bool:
        try:
            await state_machine.transition(
                event_id, EventStatus.TRIAGING, operator="A", reason="race"
            )
            return True
        except InvalidStateTransitionError:
            # The loser gets an invalid-state error because the row was already
            # updated by the winner — legitimate race outcome.
            return False

    results = await asyncio.gather(try_triaging(), try_triaging())
    winners = sum(1 for r in results if r)
    assert winners == 1, f"Expected exactly 1 winner, got {winners}"

    current = await state_machine.get_current_status(event_id)
    assert current == EventStatus.TRIAGING


# ===================================================================
# force_close
# ===================================================================


@pytest.mark.asyncio
async def test_force_close_sets_external_unsynced(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    result = await state_machine.force_close(event_id, principal="admin1", reason="manual override")
    assert result.status == EventStatus.CLOSED
    assert result.external_unsynced is True
    assert result.closed_at is not None

    async with session_factory() as s:
        row = await s.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.external_unsynced is True

    history = await state_machine.get_transition_history(event_id)
    force_entries = [e for e in history if e["to_status"] == EventStatus.CLOSED.value]
    assert len(force_entries) >= 1
    assert "force_close" in force_entries[-1]["reason"]


@pytest.mark.asyncio
async def test_force_close_syncs_event_context(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """force_close must update state_history and event summary in Redis."""
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    await state_machine.force_close(event_id, principal="admin", reason="emergency close")

    # Verify Redis state_history has the force-close entry.
    sh = await store.get(event_id, "state_history")
    assert isinstance(sh, list)
    close_entries = [e for e in sh if e["to_status"] == "closed"]
    assert len(close_entries) >= 1
    assert "force_close" in close_entries[-1].get("reason", "")

    # Verify Redis event summary shows closed status.
    ev = await store.get(event_id, "event")
    assert ev is not None
    assert ev["status"] == "closed"
    assert ev["external_unsynced"] is True


@pytest.mark.asyncio
async def test_force_close_on_already_closed_raises(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)
    await state_machine.transition(
        event_id, EventStatus.CLOSED, operator="SuperAgent", reason="done"
    )

    with pytest.raises(InvalidStateTransitionError, match="already CLOSED"):
        await state_machine.force_close(event_id, principal="admin1", reason="double")


@pytest.mark.asyncio
async def test_force_close_from_new_raises(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)

    with pytest.raises(InvalidStateTransitionError, match="illegal transition"):
        await state_machine.force_close(event_id, principal="admin1", reason="bad")


# ===================================================================
# Audit log
# ===================================================================


@pytest.mark.asyncio
async def test_transition_writes_audit_log(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)

    await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="triage started"
    )

    history = await state_machine.get_transition_history(event_id)
    assert len(history) >= 1
    last = history[-1]
    assert last["from_status"] == "new"
    assert last["to_status"] == "triaging"
    assert last["operator"] == "TriageAgent"
    assert last["reason"] == "triage started"


# ===================================================================
# EventContext state_history sync
# ===================================================================


@pytest.mark.asyncio
async def test_state_history_synced_to_context(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)

    await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="step 1"
    )
    await state_machine.transition(
        event_id, EventStatus.COLLECTING_EVIDENCE, operator="EvidenceAgent", reason="step 2"
    )

    sh = await store.get(event_id, "state_history")
    assert isinstance(sh, list)
    assert len(sh) >= 2
    assert sh[0]["to_status"] == "triaging"
    assert sh[1]["to_status"] == "collecting_evidence"


# ===================================================================
# get_current_status / get_transition_history
# ===================================================================


@pytest.mark.asyncio
async def test_get_current_status(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    assert await state_machine.get_current_status(event_id) == EventStatus.NEW

    await state_machine.transition(event_id, EventStatus.TRIAGING, operator="test", reason="test")
    assert await state_machine.get_current_status(event_id) == EventStatus.TRIAGING


@pytest.mark.asyncio
async def test_get_current_status_not_found(
    state_machine: StateMachineService,
) -> None:
    with pytest.raises(EventNotFoundError):
        await state_machine.get_current_status("evt-nonexistent")


# ===================================================================
# TRIAGING → CLOSED (not_required, low severity)
# ===================================================================


@pytest.mark.asyncio
async def test_triaging_to_closed_not_required_low(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
        severity=Severity.LOW.value,
    )
    await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="triage"
    )

    await _add_report(session_factory, event_id)

    result = await state_machine.transition(
        event_id, EventStatus.CLOSED, operator="TriageAgent", reason="low-fp close"
    )
    assert result.status == EventStatus.CLOSED


@pytest.mark.asyncio
async def test_triaging_to_closed_required_blocked(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """required disposition_policy blocks TRIAGING→CLOSED."""
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
        severity=Severity.LOW.value,
    )
    await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="triage"
    )

    with pytest.raises(InvalidStateTransitionError, match="disposition_policy=not_required"):
        await state_machine.transition(
            event_id, EventStatus.CLOSED, operator="TriageAgent", reason="should be blocked"
        )


# ===================================================================
# FAILED path
# ===================================================================


@pytest.mark.asyncio
async def test_any_state_can_transition_to_failed(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)

    result = await state_machine.transition(
        event_id, EventStatus.FAILED, operator="SuperAgent", reason="fatal error"
    )
    assert result.status == EventStatus.FAILED


@pytest.mark.asyncio
async def test_failed_to_reporting(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    await state_machine.transition(event_id, EventStatus.FAILED, operator="test", reason="fail")
    result = await state_machine.transition(
        event_id, EventStatus.REPORTING, operator="test", reason="report after fail"
    )
    assert result.status == EventStatus.REPORTING


# ===================================================================
# operator normalisation
# ===================================================================


@pytest.mark.asyncio
async def test_operator_defaults_to_state_machine_service(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    await state_machine.transition(event_id, EventStatus.TRIAGING)

    history = await state_machine.get_transition_history(event_id)
    assert history[-1]["operator"] == "StateMachineService"


# ===================================================================
# REPLANNING increments replan_count and syncs context
# ===================================================================


@pytest.mark.asyncio
async def test_replanning_increments_replan_count_in_context(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    await _walk_to_verifying(state_machine, event_id)

    await state_machine.transition(
        event_id, EventStatus.REPLANNING, operator="SuperAgent", reason="need replan"
    )

    async with session_factory() as s:
        row = await s.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.replan_count == 1

    ctx_replan = await store.get(event_id, "replan_count")
    assert ctx_replan == 1


# ===================================================================
# CLOSED event context snapshot — correctness
# ===================================================================


@pytest.mark.asyncio
async def test_closed_writes_event_context_snapshot(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)

    await state_machine.transition(
        event_id, EventStatus.CLOSED, operator="SuperAgent", reason="done"
    )

    async with session_factory() as s:
        row = await s.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.event_context_snapshot is not None
        assert "event" in row.event_context_snapshot
        assert "state_history" in row.event_context_snapshot


@pytest.mark.asyncio
async def test_closed_snapshot_has_correct_status(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """The snapshot written post-commit MUST show status='closed' (not stale)."""
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)

    await state_machine.transition(
        event_id, EventStatus.CLOSED, operator="SuperAgent", reason="done"
    )

    async with session_factory() as s:
        row = await s.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.event_context_snapshot is not None
        snapshot = row.event_context_snapshot
        assert "event" in snapshot
        assert snapshot["event"]["status"] == "closed", (
            f"snapshot status is {snapshot['event']['status']!r}, expected 'closed'"
        )


# ===================================================================
# force_close principal normalisation
# ===================================================================


@pytest.mark.asyncio
async def test_force_close_normalises_principal(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    await state_machine.force_close(event_id, principal="admin", reason="emergency")

    history = await state_machine.get_transition_history(event_id)
    close_entry = [e for e in history if e["to_status"] == "closed"][-1]
    assert close_entry["operator"] == "principal:admin"


# ===================================================================
# Optional dependencies = None
# ===================================================================


@pytest.mark.asyncio
async def test_transition_without_optional_dependencies(
    state_machine_minimal: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """transition() must not raise when event_bus/audit_log/degraded_flags are None."""
    event_id = await _create_event(session_factory, store)

    result = await state_machine_minimal.transition(
        event_id, EventStatus.TRIAGING, operator="test", reason="no optionals"
    )
    assert result.status == EventStatus.TRIAGING

    # get_transition_history returns [] when audit_log is None.
    history = await state_machine_minimal.get_transition_history(event_id)
    assert history == []


@pytest.mark.asyncio
async def test_force_close_without_optional_dependencies(
    state_machine_minimal: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """force_close() must not raise when event_bus/audit_log/degraded_flags are None."""
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine_minimal, event_id)

    result = await state_machine_minimal.force_close(
        event_id, principal="admin", reason="no optionals"
    )
    assert result.status == EventStatus.CLOSED
    assert result.external_unsynced is True


# ===================================================================
# Redis-degraded path
# ===================================================================


@pytest.mark.asyncio
async def test_redis_failure_marks_degraded_flag(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """When Redis writes fail, degraded flag must be set without raising."""
    event_id = await _create_event(session_factory, store)

    # Mock store.set to simulate Redis failure while keeping PG working.
    original_set = store.set

    async def failing_set(event_id: str, key: str, value, **kwargs):  # noqa: ARG001
        from app.services.context_service import SetResult

        if key == "event":
            return SetResult(redis_ok=False, version=99)
        return await original_set(event_id, key, value, **kwargs)

    with patch.object(store, "set", side_effect=failing_set):
        result = await state_machine.transition(
            event_id, EventStatus.TRIAGING, operator="test", reason="redis down"
        )

    assert result.status == EventStatus.TRIAGING

    # degraded flag must be set.
    async with session_factory() as s:
        row = await s.get(orm.SecurityEvent, event_id)
        assert row is not None
        flags = [str(f) for f in (row.degraded_flags or [])]
        assert any("redis_context_unavailable" in f for f in flags), (
            f"expected redis_context_unavailable in {flags}"
        )


# ===================================================================
# Edge cases
# ===================================================================


@pytest.mark.asyncio
async def test_transition_nonexistent_event_raises(
    state_machine: StateMachineService,
) -> None:
    with pytest.raises(EventNotFoundError):
        await state_machine.transition(
            "evt-20260720-deadbeef", EventStatus.TRIAGING, operator="test", reason="nope"
        )


@pytest.mark.asyncio
async def test_self_loop_transition_is_rejected(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """NEW→NEW is illegal (no self-loop), but e.g. FAILED→FAILED is also illegal."""
    event_id = await _create_event(session_factory, store)

    # NEW → NEW is not a legal edge.
    with pytest.raises(InvalidStateTransitionError):
        await state_machine.transition(event_id, EventStatus.NEW, operator="test", reason="noop")
