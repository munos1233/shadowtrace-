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
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.auth import ROLE_ADMIN, ROLE_ANALYST, AuthorizationError, Principal
from app.core.errors import (
    EventNotFoundError,
    InvalidStateTransitionError,
    InvalidVerdictStatusCombinationError,
)
from app.core.event_bus import EventBus
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.disposition import (
    DispositionCommand,
    SetEventDispositionParams,
    SourceObjectLocator,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    ConfirmationEvidence,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionJobStatus,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    SourceDisposition,
    SourceObjectKind,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.source import SourceReference
from app.models.tool_meta import TERMINAL_DISPOSITION_TOOL
from app.models.workflow import MAX_REPLAN_COUNT, TransitionContext
from app.services.context_service import EventContextStore, event_summary_from_security_event
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.state_machine_service import StateMachineService, _build_terminal_writeback_view

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _admin_principal(subject: str = "admin1") -> Principal:
    return Principal(subject=subject, roles=[ROLE_ADMIN])


def _analyst_principal(subject: str = "analyst1") -> Principal:
    return Principal(subject=subject, roles=[ROLE_ANALYST])


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
                    sections=[],
                )
            )


async def _write_journal_scalar(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    field_name: str,
    value: object,
    *,
    version: int = 1,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.EventContextJournal(
                    event_id=event_id,
                    field_name=field_name,
                    value={"_scalar": value},
                    version=version,
                )
            )


async def _add_response_action(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    action_name: str = "block_ip",
    plan_revision: int = 1,
) -> str:
    action_id = f"act-{uuid.uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=plan_revision,
                    action_fingerprint=f"fp-{action_id}",
                    action_category="response",
                    action_name=action_name,
                    tool_name=action_name,
                    action_level="l2",
                )
            )
    return action_id


async def _ensure_mock_connector(session: AsyncSession) -> None:
    existing = await session.get(orm.SourceConnector, "conn-mock")
    if existing is None:
        session.add(
            orm.SourceConnector(
                connector_id="conn-mock",
                source_product="mock_xdr",
                display_name="Mock XDR",
            )
        )


async def _seed_applicable_confirmed_writeback_action(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    plan_revision: int = 1,
) -> str:
    """Seed one response Action that satisfies the REQUIRED writeback close gate."""
    action_id = f"act-wb-{_sfx()}"
    writeback_id = f"wbk-{_sfx()}"
    outbox_id = f"obx-{_sfx()}"
    disposition_id = f"disp-{_sfx()}"
    source_record_id = f"src-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            await _ensure_mock_connector(session)
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product="mock_xdr",
                    source_tenant_id="tenant-1",
                    connector_id="conn-mock",
                    source_kind=SourceObjectKind.INCIDENT.value,
                    source_object_id="INC-writeback",
                )
            )
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=plan_revision,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block_ip",
                    tool_name="block_ip",
                    action_level="l2",
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.SUCCESS.value,
                    auto_execute=False,
                    reason="confirmed writeback",
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    writeback_status=WritebackStatus.CONFIRMED.value,
                )
            )
            await session.flush()
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=writeback_id,
                    disposition_id=disposition_id,
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="c" * 64,
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    logical_slot="default",
                    idempotency_key=f"idem-{action_id}",
                    command_payload={"intent_kind": "entity_action_submit"},
                    command_payload_sha256="d" * 64,
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.CONFIRMED.value,
                )
            )
    return action_id


def _event_status_update_payload(
    *,
    action_id: str,
    target_disposition: SourceDisposition,
    disposition_id: str | None = None,
) -> dict[str, object]:
    disp_id = disposition_id or f"disp-{action_id}"
    command = DispositionCommand(
        disposition_id=disp_id,
        action_id=action_id,
        closure_cycle=1,
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-1",
            connector_id="conn-mock",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id="INC-terminal",
        ),
        operation_code="set_event_disposition",
        operation_params=SetEventDispositionParams(target_disposition=target_disposition),
        operator_id="system",
        idempotency_key=f"{action_id}:terminal",
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )
    return command.model_dump(mode="json")


async def _seed_terminal_writeback_fixture(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    plan_revision: int = 1,
    approved: SourceDisposition = SourceDisposition.CONTAINED,
    target_disposition: SourceDisposition = SourceDisposition.CONTAINED,
    command_payload: dict[str, object] | None = None,
    receipt_simulated: bool | None = None,
    receipt_confirmation_evidence: ConfirmationEvidence | None = None,
    action_name: str = TERMINAL_DISPOSITION_TOOL,
) -> str:
    action_id = f"act-term-{_sfx()}"
    writeback_id = f"wbk-{_sfx()}"
    outbox_id = f"obx-{_sfx()}"
    disposition_id = f"disp-{_sfx()}"
    source_record_id = f"src-{_sfx()}"
    payload = command_payload or _event_status_update_payload(
        action_id=action_id,
        target_disposition=target_disposition,
        disposition_id=disposition_id,
    )
    async with session_factory() as session:
        async with session.begin():
            await _ensure_mock_connector(session)
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product="mock_xdr",
                    source_tenant_id="tenant-1",
                    connector_id="conn-mock",
                    source_kind=SourceObjectKind.INCIDENT.value,
                    source_object_id="INC-terminal",
                )
            )
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=plan_revision,
                    action_fingerprint=f"fp-{action_id}",
                    action_category="response",
                    action_name=action_name,
                    tool_name=TERMINAL_DISPOSITION_TOOL,
                    action_level="l4",
                    execution_phase=ActionExecutionPhase.POST_VERIFY.value,
                    activation_condition="after_effect_resolution",
                    approved_terminal_dispositions=[approved.value],
                    status="success",
                    auto_execute=False,
                    reason="terminal disposition",
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    writeback_required=False,
                )
            )
            await session.flush()
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=writeback_id,
                    disposition_id=disposition_id,
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="a" * 64,
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    logical_slot="terminal",
                    idempotency_key=f"idem-{action_id}",
                    command_payload=payload,
                    command_payload_sha256="b" * 64,
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.CONFIRMED.value,
                )
            )
            if receipt_simulated is not None:
                session.add(
                    orm.DispositionReceipt(
                        writeback_id=writeback_id,
                        sequence=1,
                        disposition_id=disposition_id,
                        action_id=action_id,
                        source_record_id=source_record_id,
                        status=WritebackStatus.CONFIRMED.value,
                        simulated=receipt_simulated,
                        confirmation_evidence=(
                            receipt_confirmation_evidence.value
                            if receipt_confirmation_evidence is not None
                            else None
                        ),
                    )
                )
    return action_id


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
                orm.ActionTargetResult,  # FK → action_execution_job
                orm.ActionExecutionJob,  # FK → action
                orm.DispositionReceipt,  # FK → action
                orm.DispositionOutbox,  # FK → action
                orm.Action,
                orm.Evidence,  # FK → security_event
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

    result = await state_machine.force_close(
        event_id,
        principal=_admin_principal("admin1"),
        reason="manual override",
    )
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
    assert "subject=admin1" in force_entries[-1]["reason"]


@pytest.mark.asyncio
async def test_force_close_syncs_event_context(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """force_close must update state_history and event summary in Redis."""
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    await state_machine.force_close(
        event_id,
        principal=_admin_principal("admin"),
        reason="emergency close",
    )

    # Verify Redis state_history has the force-close entry.
    sh = await store.get(event_id, "state_history")
    assert isinstance(sh, list)
    close_entries = [e for e in sh if e["to_status"] == "closed"]
    assert len(close_entries) >= 1
    assert "force_close" in close_entries[-1].get("reason", "")
    assert "subject=admin" in close_entries[-1].get("reason", "")

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
        await state_machine.force_close(
            event_id,
            principal=_admin_principal("admin1"),
            reason="double",
        )


@pytest.mark.asyncio
async def test_force_close_from_new_raises(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)

    with pytest.raises(InvalidStateTransitionError, match="illegal transition"):
        await state_machine.force_close(
            event_id,
            principal=_admin_principal("admin1"),
            reason="bad",
        )


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
async def test_force_close_requires_admin_at_service_layer(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    with pytest.raises(AuthorizationError) as exc_info:
        await state_machine.force_close(
            event_id,
            principal=_analyst_principal(),
            reason="must fail",
        )
    assert exc_info.value.required == [ROLE_ADMIN]


@pytest.mark.asyncio
async def test_force_close_denied_leaves_event_unchanged(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """ISSUE-308: service-layer RBAC denial must not mutate event state."""
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    with pytest.raises(AuthorizationError):
        await state_machine.force_close(
            event_id,
            principal=_analyst_principal(),
            reason="must fail",
        )

    assert await state_machine.get_current_status(event_id) == EventStatus.REPORTING
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.status == EventStatus.REPORTING.value
        assert row.external_unsynced is False


@pytest.mark.asyncio
async def test_force_close_denied_records_denied_metric(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    with patch("app.services.state_machine_service.record_force_close") as record:
        with pytest.raises(AuthorizationError):
            await state_machine.force_close(
                event_id,
                principal=_analyst_principal(),
                reason="must fail",
            )
        record.assert_called_once_with(result="denied")


@pytest.mark.asyncio
async def test_force_close_success_records_success_metric(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    with patch("app.services.state_machine_service.record_force_close") as record:
        await state_machine.force_close(
            event_id,
            principal=_admin_principal("admin1"),
            reason="manual override",
        )
        record.assert_called_once_with(result="success")


@pytest.mark.asyncio
async def test_force_close_normalises_principal(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store, severity=Severity.LOW.value)
    await _walk_to_reporting(state_machine, event_id)

    await state_machine.force_close(
        event_id,
        principal=_admin_principal("admin"),
        reason="emergency",
    )

    history = await state_machine.get_transition_history(event_id)
    close_entry = [e for e in history if e["to_status"] == "closed"][-1]
    assert close_entry["operator"] == "principal:admin"


@pytest.mark.asyncio
async def test_force_close_bypasses_side_effect_gate_at_service_layer(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """ISSUE-308: admin force_close bypasses side-effect gate at service layer."""
    sfx = uuid.uuid4().hex[:8]
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
        severity=Severity.HIGH.value,
        final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
    )
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)

    action_id = f"act-{sfx}"
    job_id = f"job-{sfx}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="isolate host",
                    tool_name="isolate_host",
                    action_level="l2",
                    execution_owner=ExecutionOwner.DIRECT_TOOL.value,
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.APPROVED.value,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_tool",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.RUNNING.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )

    with pytest.raises(InvalidStateTransitionError, match="gate-applicable side effects") as exc:
        await state_machine.transition(
            event_id,
            EventStatus.CLOSED,
            operator="SuperAgent",
            reason="close with running side effect",
        )
    assert exc.value.error_code == "closed_side_effects_pending"

    result = await state_machine.force_close(
        event_id,
        principal=_admin_principal("admin1"),
        reason="admin override side effect gate",
    )
    assert result.status == EventStatus.CLOSED
    assert result.external_unsynced is True


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
        event_id,
        principal=_admin_principal("admin"),
        reason="no optionals",
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


# ===================================================================
# disposition_only / CLOSED gate / verdict / EventBus (ISSUE-037)
# ===================================================================


@pytest.mark.asyncio
async def test_forged_disposition_only_intent_rejected(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="triage"
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.final_verdict = FinalVerdict.FALSE_POSITIVE.value

    forged = TransitionContext(disposition_only_intent=True)
    with pytest.raises(InvalidStateTransitionError, match="disposition_only_intent"):
        await state_machine.transition(
            event_id,
            EventStatus.PLANNING_RESPONSE,
            context=forged,
            operator="TriageAgent",
            reason="forged intent",
        )


@pytest.mark.asyncio
async def test_triaging_to_planning_disposition_only_with_journal(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="triage"
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.final_verdict = FinalVerdict.FALSE_POSITIVE.value
    await _write_journal_scalar(session_factory, event_id, "disposition_only_intent", True)

    result = await state_machine.transition(
        event_id,
        EventStatus.PLANNING_RESPONSE,
        operator="TriageAgent",
        reason="disposition-only pre-action",
    )
    assert result.status == EventStatus.PLANNING_RESPONSE


@pytest.mark.asyncio
async def test_closed_gate_blocks_missing_report(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
        severity=Severity.LOW.value,
    )
    await _walk_to_reporting(state_machine, event_id)

    with pytest.raises(InvalidStateTransitionError, match="report") as exc:
        await state_machine.transition(
            event_id, EventStatus.CLOSED, operator="SuperAgent", reason="premature close"
        )
    assert exc.value.error_code == "closed_requires_report"


@pytest.mark.asyncio
async def test_sm_transition_closed_blocked_by_side_effects(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    sfx = uuid.uuid4().hex[:8]
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
        severity=Severity.HIGH.value,
        final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
    )
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)

    action_id = f"act-{sfx}"
    job_id = f"job-{sfx}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="isolate host",
                    tool_name="isolate_host",
                    action_level="l2",
                    execution_owner=ExecutionOwner.DIRECT_TOOL.value,
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.APPROVED.value,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_tool",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.RUNNING.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )

    with pytest.raises(InvalidStateTransitionError, match="gate-applicable side effects") as exc:
        await state_machine.transition(
            event_id,
            EventStatus.CLOSED,
            operator="SuperAgent",
            reason="close with running side effect",
        )
    assert exc.value.error_code == "closed_side_effects_pending"
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_verdict_false_positive_blocks_side_effect_executing(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(session_factory, store)
    await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="triage"
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.final_verdict = FinalVerdict.FALSE_POSITIVE.value
            row.status = EventStatus.PLANNING_RESPONSE.value
    await _write_journal_scalar(session_factory, event_id, "disposition_only_intent", True)
    await _add_response_action(session_factory, event_id, action_name="block_ip")

    with pytest.raises(InvalidVerdictStatusCombinationError, match="entity side effects"):
        await state_machine.transition(
            event_id,
            EventStatus.EXECUTING_RESPONSE,
            operator="SuperAgent",
            reason="execute side-effect plan",
        )


@pytest.mark.asyncio
async def test_transition_publishes_state_change(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    redis_client: RedisClient,
    audit_log: EventAuditLogService,
    degraded: DegradedFlagService,
) -> None:
    bus = EventBus(redis_client)
    bus.publish_event = AsyncMock()  # type: ignore[method-assign]
    state_machine = StateMachineService(
        session_factory,
        store,
        event_bus=bus,
        audit_log=audit_log,
        degraded_flags=degraded,
    )
    event_id = await _create_event(session_factory, store)

    await state_machine.transition(
        event_id, EventStatus.TRIAGING, operator="TriageAgent", reason="bus test"
    )

    bus.publish_event.assert_awaited_once()
    call_args = bus.publish_event.await_args
    assert call_args is not None
    assert call_args.args[0] == event_id
    assert call_args.args[1] == "state_change"
    payload = call_args.args[2]
    assert payload["from_status"] == "new"
    assert payload["to_status"] == "triaging"
    assert payload["operator"] == "TriageAgent"


@pytest.mark.asyncio
async def test_fp_close_reason_with_case_id_in_audit(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    audit_log: EventAuditLogService,
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
    case_reason = "close_as_fp matched case-00000001 ops-change-bot pattern"

    await state_machine.transition(
        event_id,
        EventStatus.CLOSED,
        operator="TriageAgent",
        reason=case_reason,
        context=TransitionContext(recommendation="close_as_fp"),
    )

    logs = await audit_log.get_logs_by_event(event_id)
    close_logs = [row for row in logs if row.to_status == EventStatus.CLOSED.value]
    assert close_logs
    assert "case-00000001" in (close_logs[-1].reason or "")


# ===================================================================
# ISSUE-184: CLOSED gate actual_disposition parsing
# ===================================================================


@pytest.mark.asyncio
async def test_build_terminal_writeback_view_reads_nested_target_disposition(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
    )
    await _seed_terminal_writeback_fixture(
        session_factory,
        event_id,
        approved=SourceDisposition.CONTAINED,
        target_disposition=SourceDisposition.CONTAINED,
    )

    async with session_factory() as session:
        view = await _build_terminal_writeback_view(session, event_id, 1)

    assert view is not None
    assert view.approved_disposition is SourceDisposition.CONTAINED
    assert view.actual_disposition is SourceDisposition.CONTAINED
    assert view.receipt_status is WritebackStatus.CONFIRMED


@pytest.mark.asyncio
async def test_build_terminal_writeback_view_matches_canonical_tool_name(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
    )
    await _seed_terminal_writeback_fixture(
        session_factory,
        event_id,
        action_name="Deferred terminal disposition",
    )

    async with session_factory() as session:
        view = await _build_terminal_writeback_view(session, event_id, 1)

    assert view is not None
    assert view.intent_kind is DispositionIntentKind.EVENT_STATUS_UPDATE


@pytest.mark.asyncio
async def test_build_terminal_writeback_view_projects_simulated_from_receipt(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """ISSUE-227: simulated flag on TerminalEventWritebackView comes from receipt."""
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
    )
    await _seed_terminal_writeback_fixture(
        session_factory,
        event_id,
        approved=SourceDisposition.CONTAINED,
        target_disposition=SourceDisposition.CONTAINED,
        receipt_simulated=True,
    )

    async with session_factory() as session:
        view = await _build_terminal_writeback_view(session, event_id, 1)

    assert view is not None
    assert view.simulated is True


@pytest.mark.asyncio
async def test_build_terminal_writeback_view_projects_confirmation_evidence_from_receipt(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """ISSUE-333: confirmation_evidence on TerminalEventWritebackView comes from receipt."""
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
    )
    await _seed_terminal_writeback_fixture(
        session_factory,
        event_id,
        approved=SourceDisposition.CONTAINED,
        target_disposition=SourceDisposition.CONTAINED,
        receipt_simulated=False,
        receipt_confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
    )

    async with session_factory() as session:
        view = await _build_terminal_writeback_view(session, event_id, 1)

    assert view is not None
    assert view.confirmation_evidence is ConfirmationEvidence.READBACK_VERIFIED


@pytest.mark.asyncio
async def test_close_rejected_when_non_mock_and_weak_confirmation_evidence(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-333: live disposition mode must block CLOSED on adapter_acknowledged."""
    from app.core.config import get_settings

    monkeypatch.setenv("DISPOSITION_MODE", "live_xdr")
    get_settings.cache_clear()

    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
        severity=Severity.LOW.value,
    )
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)
    await _seed_applicable_confirmed_writeback_action(session_factory, event_id)
    await _seed_terminal_writeback_fixture(
        session_factory,
        event_id,
        approved=SourceDisposition.CONTAINED,
        target_disposition=SourceDisposition.CONTAINED,
        receipt_simulated=False,
        receipt_confirmation_evidence=ConfirmationEvidence.ADAPTER_ACKNOWLEDGED,
    )

    with pytest.raises(
        InvalidStateTransitionError, match="strong confirmation_evidence"
    ) as exc:
        await state_machine.transition(
            event_id,
            EventStatus.CLOSED,
            operator="SuperAgent",
            reason="weak evidence in live mode",
        )
    assert exc.value.error_code == "closed_weak_confirmation_evidence"
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_close_rejected_when_non_mock_and_simulated_terminal_receipt(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-227: live disposition mode must block CLOSED on simulated terminal."""
    from app.core.config import get_settings

    monkeypatch.setenv("DISPOSITION_MODE", "live_xdr")
    get_settings.cache_clear()

    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
        severity=Severity.LOW.value,
    )
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)
    await _seed_applicable_confirmed_writeback_action(session_factory, event_id)
    await _seed_terminal_writeback_fixture(
        session_factory,
        event_id,
        approved=SourceDisposition.CONTAINED,
        target_disposition=SourceDisposition.CONTAINED,
        receipt_simulated=True,
    )

    with pytest.raises(InvalidStateTransitionError, match="non-simulated terminal receipt") as exc:
        await state_machine.transition(
            event_id,
            EventStatus.CLOSED,
            operator="SuperAgent",
            reason="simulated terminal in live mode",
        )
    assert exc.value.error_code == "closed_simulated_receipt_rejected"
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_build_terminal_writeback_view_fails_closed_on_forged_top_level_only(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """Top-level target_disposition without operation_params must not spoof actual."""
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
    )
    await _seed_terminal_writeback_fixture(
        session_factory,
        event_id,
        approved=SourceDisposition.CONTAINED,
        command_payload={"target_disposition": SourceDisposition.CONTAINED.value},
    )

    async with session_factory() as session:
        view = await _build_terminal_writeback_view(session, event_id, 1)

    assert view is not None
    assert view.approved_disposition is SourceDisposition.CONTAINED
    assert view.actual_disposition is SourceDisposition.PENDING


@pytest.mark.asyncio
async def test_close_rejected_when_terminal_actual_unparseable(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """Forged top-level disposition must block CLOSED, not only the parsed view."""
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED.value,
        severity=Severity.LOW.value,
    )
    await _walk_to_reporting(state_machine, event_id)
    await _add_report(session_factory, event_id)
    await _seed_applicable_confirmed_writeback_action(session_factory, event_id)
    await _seed_terminal_writeback_fixture(
        session_factory,
        event_id,
        approved=SourceDisposition.CONTAINED,
        command_payload={"target_disposition": SourceDisposition.CONTAINED.value},
    )

    with pytest.raises(InvalidStateTransitionError, match="actual disposition not terminal"):
        await state_machine.transition(
            event_id,
            EventStatus.CLOSED,
            operator="SuperAgent",
            reason="forged terminal actual",
        )


@pytest.mark.asyncio
async def test_close_rejected_when_only_superseded_outboxes_remain(
    state_machine: StateMachineService,
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> None:
    """ISSUE-185: CLOSED must fail when active outbox vacuum would spoof CONFIRMED."""
    from tests.test_services.test_writeback_close_gate import _seed_gate_event_with_outboxes

    event_id = await _seed_gate_event_with_outboxes(
        session_factory,
        outboxes=[(WritebackStatus.CONFIRMED, "obx-head-2")],
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.writeback_status = WritebackStatus.CONFIRMED.value
            action = await session.scalar(
                select(orm.Action).where(orm.Action.event_id == event_id).limit(1)
            )
            assert action is not None
            action.writeback_status = WritebackStatus.CONFIRMED.value

    await _add_report(session_factory, event_id)

    with pytest.raises(InvalidStateTransitionError, match="no disposition command"):
        await state_machine.transition(
            event_id,
            EventStatus.CLOSED,
            operator="SuperAgent",
            reason="vacuum outbox must not close",
        )
