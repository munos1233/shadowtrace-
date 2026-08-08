"""RollbackService tests (ISSUE-061).

Requires Compose PostgreSQL. Run from ``backend/``:

    pytest tests/test_services/test_rollback_service.py -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.agents.rules.rollback_mapping import is_rollbackable
from app.db import models as orm
from app.models.action import Action as ActionModel
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    CapabilityState,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionOwner,
    Severity,
    SourceDisposition,
    SourceObjectKind,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.ids import new_action_id, new_event_id
from app.models.rollback_result import RollbackEffectStatus, RollbackResult
from app.services.event_audit_log_service import EventAuditLogService
from app.services.rollback_service import RollbackService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def migrated() -> None:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)

    async def _probe() -> None:
        try:
            async with engine.connect() as conn:
                await conn.execute(select(1))
        except Exception as exc:  # noqa: BLE001
            await engine.dispose()
            pytest.skip(f"PostgreSQL not reachable: {exc}")

    import asyncio

    asyncio.run(_probe())
    command.upgrade(_alembic_config(), "head")
    asyncio.run(engine.dispose())


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(select(1))
    except Exception as exc:  # noqa: BLE001
        await engine.dispose()
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def audit(session_factory: async_sessionmaker[AsyncSession]) -> EventAuditLogService:
    return EventAuditLogService(session_factory)


@pytest_asyncio.fixture
async def cleanup(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    yield
    async with session_factory() as session:
        async with session.begin():
            for table in (
                orm.EventAuditLog,
                orm.ActionTargetResult,
                orm.ActionExecutionJob,
                orm.DispositionReceipt,
                orm.DispositionOutbox,
                orm.Action,
                orm.Evidence,
                orm.Report,
                orm.SourceEventLink,
                orm.SourceObject,
                orm.SourceConnector,
                orm.SecurityEvent,
            ):
                await session.execute(delete(table))


# ---------------------------------------------------------------------------
# Action seeding helpers
# ---------------------------------------------------------------------------


async def _seed_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str | None = None,
    disposition_policy: DispositionPolicy = DispositionPolicy.NOT_REQUIRED,
) -> str:
    eid = event_id or new_event_id(identity=f"test-rollback:{_sfx()}", occurred_at=_utc_now())
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=eid,
                    title="test-rollback",
                    event_type=EventType.INSIDER_THREAT.value,
                    severity=Severity.MEDIUM.value,
                    status=EventStatus.VERIFYING.value,
                    disposition_policy=disposition_policy.value,
                    occurred_at=_utc_now(),
                    creation_source_ref={
                        "source_product": "mock_xdr",
                        "source_tenant_id": "tenant-test",
                    },
                )
            )
            await session.flush()
    return eid


async def _seed_source_object(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    source_record_id: str | None = None,
    connector_id: str | None = None,
) -> str:
    srid = source_record_id or f"src-{_sfx()}"
    cid = connector_id or f"conn-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=cid,
                    source_product="mock_xdr",
                    display_name="Test connector",
                )
            )
            session.add(
                orm.SourceObject(
                    source_record_id=srid,
                    source_product="mock_xdr",
                    source_tenant_id="tenant-test",
                    connector_id=cid,
                    source_kind=SourceObjectKind.INCIDENT.value,
                    source_object_type="incident",
                    source_object_id=f"incident-{_sfx()}",
                    source_concurrency_token=f"token-{_sfx()}",
                    source_status_raw="contained",
                    source_disposition=SourceDisposition.CONTAINED.value,
                )
            )
            await session.flush()
    return srid


async def _seed_response_action(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    tool_name: str = "block_ip",
    target: str = "203.0.113.100",
    target_type: str = "ip",
    status: ActionStatus = ActionStatus.SUCCESS,
    execution_owner: ExecutionOwner = ExecutionOwner.DIRECT_TOOL,
    writeback_required: bool = False,
    writeback_applicable: bool = False,
    executed_at: datetime | None = None,
    parameters: dict[str, Any] | None = None,
    source_action_id: str | None = None,
    rollback_status: str | None = None,
    effect_verification_status: str | None = "verified",
    disposition_source_ref: dict[str, Any] | None = None,
) -> ActionModel:
    action_id = new_action_id()
    async with session_factory() as session:
        async with session.begin():
            row = orm.Action(
                action_id=action_id,
                event_id=event_id,
                plan_revision=1,
                action_fingerprint=f"fp-{action_id}",
                action_category=ActionCategory.RESPONSE.value,
                action_name=tool_name,
                tool_name=tool_name,
                action_level="l2",
                execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                target_type=target_type,
                target=target,
                parameters=parameters or {"ip": target},
                status=status.value,
                auto_execute=True,
                reason="Test response action",
                execution_owner=execution_owner.value,
                writeback_required=writeback_required,
                writeback_applicable=writeback_applicable,
                writeback_readiness=(
                    WritebackReadiness.READY.value
                    if writeback_required and writeback_applicable
                    else WritebackReadiness.NOT_REQUIRED.value
                ),
                writeback_status=None,
                source_action_id=source_action_id,
                rollback_status=rollback_status,
                effect_verification_status=effect_verification_status,
                executed_at=executed_at or _utc_now(),
                disposition_source_ref=disposition_source_ref,
            )
            session.add(row)
            await session.flush()
    return ActionModel.model_validate(
        {
            "action_id": row.action_id,
            "event_id": row.event_id,
            "plan_revision": row.plan_revision,
            "action_fingerprint": row.action_fingerprint,
            "action_category": row.action_category,
            "action_name": row.action_name,
            "tool_name": row.tool_name,
            "action_level": row.action_level,
            "execution_phase": row.execution_phase,
            "target_type": row.target_type,
            "target": row.target,
            "parameters": row.parameters or {},
            "status": row.status,
            "auto_execute": row.auto_execute,
            "reason": row.reason,
            "execution_owner": row.execution_owner,
            "execution_job_id": row.execution_job_id,
            "tool_call_id": row.tool_call_id,
            "idempotency_key": row.idempotency_key,
            "writeback_required": row.writeback_required,
            "writeback_applicable": row.writeback_applicable,
            "writeback_readiness": row.writeback_readiness,
            "writeback_block_reason": row.writeback_block_reason,
            "writeback_status": row.writeback_status,
            "disposition_source_ref": row.disposition_source_ref,
            "superseded_by_revision": row.superseded_by_revision,
            "executed_at": row.executed_at,
            "effect_verification_status": row.effect_verification_status,
            "rollback_status": row.rollback_status,
            "source_action_id": row.source_action_id,
            "updated_at": row.updated_at,
        }
    )


async def _seed_disposition_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    action_id: str,
    event_id: str,
    source_record_id: str,
    intent_kind: DispositionIntentKind = DispositionIntentKind.ENTITY_ACTION_SUBMIT,
    disposition_id: str | None = None,
    source_sequence: int = 1,
) -> str:
    did = disposition_id or f"disp-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            outbox = orm.DispositionOutbox(
                outbox_id=f"obx-{_sfx()}",
                writeback_id=f"wbk-{_sfx()}",
                disposition_id=did,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=source_record_id,
                source_locator_hash=f"hash-{_sfx()}",
                source_sequence=source_sequence,
                intent_kind=intent_kind.value,
                logical_slot="default",
                idempotency_key=f"idem-{_sfx()}",
                command_payload={"intent": intent_kind.value},
                command_payload_sha256=f"sha256-{_sfx()}",
                delivery_status="ready",
            )
            session.add(outbox)
            # Keep SourceObject.next_outbox_sequence aligned with manually seeded
            # outbox rows so real DispositionSyncService.enqueue_command() allocates
            # the next free (source_record_id, source_sequence) pair (ISSUE-061/#576).
            source_row = await session.get(orm.SourceObject, source_record_id)
            if source_row is not None:
                current = int(source_row.next_outbox_sequence or 0)
                source_row.next_outbox_sequence = max(current, source_sequence)
            await session.flush()
    return did


# ---------------------------------------------------------------------------
# Mock DispositionSync for compensation writeback tests
# ---------------------------------------------------------------------------


class _FakeOutboxRecord:
    """Lightweight record returned by mock enqueue_command."""

    __slots__ = ("writeback_id", "disposition_id")

    def __init__(self, writeback_id: str, disposition_id: str) -> None:
        self.writeback_id = writeback_id
        self.disposition_id = disposition_id


class _MockDispositionSync:
    """Mock that records calls to ``enqueue_command`` and returns plausible
    DispositionOutboxRecord-like objects for compensation writeback tests."""

    def __init__(self) -> None:
        self.call_count = 0
        self.commands: list[Any] = []

    async def enqueue_command(
        self,
        session: Any,
        *,
        command: Any,
        event_id: str,
        source_record_id: str,
        logical_slot: str = "default",
        guard_context: dict[str, Any] | None = None,
    ) -> _FakeOutboxRecord:
        self.call_count += 1
        self.commands.append(command)
        return _FakeOutboxRecord(
            writeback_id=f"mock-wbk-{_sfx()}",
            disposition_id=command.disposition_id,
        )


class _MockEventBus:
    """Records EventBus publish calls for rollback visibility tests."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    async def publish_event(
        self,
        event_id: str,
        message_type: str,
        payload: dict[str, Any] | None = None,
    ) -> bool:
        self.events.append((event_id, message_type, dict(payload or {})))
        return True


# ---------------------------------------------------------------------------
# execute_rollback hook factory
# ---------------------------------------------------------------------------


def _mock_execute_hook(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    succeed: bool = True,
) -> Callable[[str, str], Awaitable[ActionModel]]:
    """Return an execute_rollback hook that simulates tool execution.

    Updates the rollback Action row to SUCCESS (or FAILED) and returns it.
    """

    async def _execute(rollback_action_id: str, operator: str) -> ActionModel:
        target_status = ActionStatus.SUCCESS if succeed else ActionStatus.FAILED
        async with session_factory() as session:
            async with session.begin():
                row = await session.get(orm.Action, rollback_action_id, with_for_update=True)
                assert row is not None, f"Rollback action {rollback_action_id} not found"
                row.status = target_status.value
                row.executed_at = _utc_now()
                row.updated_at = _utc_now()
                await session.flush()

        # Return via the service's _action_from_row equivalent
        from app.services.rollback_service import _action_from_row

        async with session_factory() as session:
            row = await session.get(orm.Action, rollback_action_id)
            assert row is not None
            return _action_from_row(row)

    return _execute


def _mock_verify_hook(
    *,
    verified: bool = True,
    skipped: bool = False,
) -> Callable[[ActionModel, ActionModel], Awaitable[RollbackEffectStatus]]:
    """Return a verify_rollback_effect hook for unit tests."""

    async def _verify(
        original: ActionModel,
        rollback_action: ActionModel,
    ) -> RollbackEffectStatus:
        if rollback_action.status is not ActionStatus.SUCCESS:
            return "failed"
        if skipped:
            return "skipped"
        return "verified" if verified else "failed"

    return _verify


def _rollback_service(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    *,
    execute: Callable[[str, str], Awaitable[ActionModel]] | None = None,
    verify: Callable[[ActionModel, ActionModel], Awaitable[RollbackEffectStatus]] | None = None,
    disposition_sync: Any = None,
    event_bus: Any = None,
    adapter_registry: Any = None,
) -> RollbackService:
    """Construct RollbackService with default verify hook for happy-path tests."""
    return RollbackService(
        session_factory,
        audit=audit,
        execute_rollback=execute,
        verify_rollback_effect=verify or _mock_verify_hook(verified=True),
        disposition_sync=disposition_sync,
        event_bus=event_bus,
        adapter_registry=adapter_registry,
    )


# ---------------------------------------------------------------------------
# Tests: rollback_action
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_action_success_verification_rolls_back_original(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Single action rollback: verification passes → original ROLLED_BACK,
    rollback Action row exists, audit log present."""
    event_id = await _seed_event(session_factory)
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
    )

    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(session_factory, audit, execute=execute)

    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="test rollback",
    )

    # Check result
    assert result.action_id == original.action_id
    assert result.rollback_action_id is not None
    assert result.rollback_tool == "unblock_ip"
    assert result.rollback_effect_status == "verified"
    assert result.rolled_back is True
    assert result.warning is None
    assert result.audit_log_id is not None

    # Verify DB state
    async with session_factory() as session:
        original_row = await session.get(orm.Action, original.action_id)
        assert original_row is not None
        assert ActionStatus(original_row.status) is ActionStatus.ROLLED_BACK
        assert original_row.rollback_status == "completed"

        rb_row = await session.get(orm.Action, result.rollback_action_id)
        assert rb_row is not None
        assert ActionCategory(rb_row.action_category) is ActionCategory.ROLLBACK
        assert rb_row.tool_name == "unblock_ip"
        assert ActionStatus(rb_row.status) is ActionStatus.SUCCESS
        assert rb_row.source_action_id == original.action_id

        # Audit log
        logs = await session.scalars(
            select(orm.EventAuditLog).where(
                orm.EventAuditLog.event_id == event_id,
            )
        )
        log_entries = list(logs)
        assert len(log_entries) >= 1
        assert log_entries[0].reason is not None
        assert "rollback" in log_entries[0].reason.lower()


@pytest.mark.asyncio
async def test_rollback_action_execution_failure_keeps_original_status(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Rollback execution fails → original Action stays SUCCESS,
    rollback Action exists but is FAILED, rolled_back=False, no compensation."""
    event_id = await _seed_event(
        session_factory,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    conn_id = f"conn-{_sfx()}"
    source_record_id = await _seed_source_object(session_factory, event_id, connector_id=conn_id)
    disposition_source_ref = {
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-test",
        "connector_id": conn_id,
        "source_kind": SourceObjectKind.INCIDENT.value,
        "source_object_id": f"incident-{_sfx()}",
    }
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
        writeback_required=True,
        writeback_applicable=True,
        disposition_source_ref=disposition_source_ref,
    )
    await _seed_disposition_outbox(
        session_factory,
        action_id=original.action_id,
        event_id=event_id,
        source_record_id=source_record_id,
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
    )
    mock_sync = _MockDispositionSync()

    execute = _mock_execute_hook(session_factory, succeed=False)
    svc = _rollback_service(
        session_factory,
        audit,
        execute=execute,
        disposition_sync=mock_sync,
    )

    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="failed rollback test",
    )

    assert result.action_id == original.action_id
    assert result.rollback_action_id is not None
    assert result.rollback_effect_status == "failed"
    assert result.rolled_back is False

    async with session_factory() as session:
        original_row = await session.get(orm.Action, original.action_id)
        assert original_row is not None
        assert ActionStatus(original_row.status) is ActionStatus.SUCCESS
        assert original_row.rollback_status != "completed"

        rb_row = await session.get(orm.Action, result.rollback_action_id)
        assert rb_row is not None
        assert ActionStatus(rb_row.status) is ActionStatus.FAILED

    assert result.compensation_writebacks == []
    assert mock_sync.call_count == 0


@pytest.mark.asyncio
async def test_rollback_action_readback_false_keeps_original_success(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Readback returns false after rollback execution SUCCESS → original stays SUCCESS."""
    event_id = await _seed_event(
        session_factory,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    conn_id = f"conn-{_sfx()}"
    source_record_id = await _seed_source_object(session_factory, event_id, connector_id=conn_id)
    disposition_source_ref = {
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-test",
        "connector_id": conn_id,
        "source_kind": SourceObjectKind.INCIDENT.value,
        "source_object_id": f"incident-{_sfx()}",
    }
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
        writeback_required=True,
        writeback_applicable=True,
        disposition_source_ref=disposition_source_ref,
    )
    await _seed_disposition_outbox(
        session_factory,
        action_id=original.action_id,
        event_id=event_id,
        source_record_id=source_record_id,
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
    )
    mock_sync = _MockDispositionSync()

    execute = _mock_execute_hook(session_factory, succeed=True)
    verify = _mock_verify_hook(verified=False)
    svc = _rollback_service(
        session_factory,
        audit,
        execute=execute,
        verify=verify,
        disposition_sync=mock_sync,
    )

    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="readback false test",
    )

    assert result.rollback_effect_status == "failed"
    assert result.rolled_back is False
    assert result.warning == "rollback_effect_not_verified"
    assert result.compensation_writebacks == []
    assert mock_sync.call_count == 0

    async with session_factory() as session:
        original_row = await session.get(orm.Action, original.action_id)
        assert original_row is not None
        assert ActionStatus(original_row.status) is ActionStatus.SUCCESS
        assert original_row.rollback_status != "completed"

        rb_row = await session.get(orm.Action, result.rollback_action_id)
        assert rb_row is not None
        assert ActionStatus(rb_row.status) is ActionStatus.FAILED


@pytest.mark.asyncio
async def test_rollback_non_rollbackable_action_returns_warning(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Non-rollbackable tool → rolled_back=False, warning='not_rollbackable',
    no rollback Action created."""
    event_id = await _seed_event(session_factory)
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="force_logout",
        status=ActionStatus.SUCCESS,
    )

    svc = RollbackService(session_factory, audit=audit)
    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="non-rollbackable test",
    )

    assert result.action_id == original.action_id
    assert result.rolled_back is False
    assert result.warning == "not_rollbackable"
    assert result.rollback_action_id is None

    async with session_factory() as session:
        original_row = await session.get(orm.Action, original.action_id)
        assert original_row is not None
        assert ActionStatus(original_row.status) is ActionStatus.SUCCESS


@pytest.mark.asyncio
async def test_rollback_unknown_action_returns_warning(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """UNKNOWN status action → cannot be auto-rollbacked."""
    event_id = await _seed_event(session_factory)
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.UNKNOWN,
    )

    svc = RollbackService(session_factory, audit=audit)
    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="unknown rollback test",
    )

    assert result.rolled_back is False
    assert result.warning == "unknown_status_cannot_rollback"


@pytest.mark.asyncio
async def test_rollback_post_verify_action_returns_warning(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """POST_VERIFY deferred Action → cannot be rollbacked via entity mapping."""
    event_id = await _seed_event(session_factory)
    action_id = new_action_id()
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="update_source_event_disposition",
                    tool_name="update_source_event_disposition",
                    action_level="l4",
                    execution_phase=ActionExecutionPhase.POST_VERIFY.value,
                    activation_condition="after_effect_resolution",
                    approved_terminal_dispositions=[SourceDisposition.CONTAINED.value],
                    status=ActionStatus.SUCCESS.value,
                    auto_execute=False,
                    reason="Terminal disposition",
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    writeback_required=False,
                )
            )
            await session.flush()

    svc = RollbackService(session_factory, audit=audit)
    result = await svc.rollback_action(
        action_id,
        operator="test-op",
        reason="post_verify test",
    )

    assert result.rolled_back is False
    assert result.warning == "post_verify_not_rollbackable"


@pytest.mark.asyncio
async def test_rollback_already_rolled_back_returns_warning(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Already-rolled-back action → warning, no double-rollback."""
    event_id = await _seed_event(session_factory)
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.ROLLED_BACK,
        rollback_status="completed",
    )

    svc = RollbackService(session_factory, audit=audit)
    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="double rollback test",
    )

    assert result.rolled_back is False
    assert result.warning == "already_rolled_back"


# ---------------------------------------------------------------------------
# Tests: rollback_event
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_event_reverse_order_batch(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Event-level batch rollback executes in reverse order by executed_at."""
    event_id = await _seed_event(session_factory)

    t1 = _utc_now()
    t2 = datetime.fromtimestamp(t1.timestamp() + 10, tz=UTC)
    t3 = datetime.fromtimestamp(t1.timestamp() + 20, tz=UTC)

    # Create 3 response actions at different times
    a1 = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        target="10.0.0.1",
        status=ActionStatus.SUCCESS,
        executed_at=t1,
    )
    a2 = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_domain",
        target="evil.example",
        target_type="domain",
        status=ActionStatus.SUCCESS,
        executed_at=t2,
    )
    a3 = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="disable_account",
        target="user@test.com",
        target_type="account",
        status=ActionStatus.SUCCESS,
        executed_at=t3,
    )

    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(session_factory, audit, execute=execute)

    results = await svc.rollback_event(
        event_id,
        operator="test-op",
        reason="batch rollback",
    )

    assert len(results) == 3
    # Must be reverse order: a3 (latest) first, a1 (earliest) last
    assert results[0].action_id == a3.action_id
    assert results[1].action_id == a2.action_id
    assert results[2].action_id == a1.action_id

    assert all(r.rolled_back for r in results)
    assert results[0].rollback_tool == "restore_account"
    assert results[1].rollback_tool == "unblock_domain"
    assert results[2].rollback_tool == "unblock_ip"


@pytest.mark.asyncio
async def test_rollback_event_skips_non_rollbackable(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """rollback_event skips non-rollbackable actions, returns warning."""
    event_id = await _seed_event(session_factory)

    _a1 = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        target="10.0.0.1",
        status=ActionStatus.SUCCESS,
    )
    a2 = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="force_logout",
        target="user@test.com",
        target_type="account",
        status=ActionStatus.SUCCESS,
    )

    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(session_factory, audit, execute=execute)

    results = await svc.rollback_event(
        event_id,
        operator="test-op",
        reason="batch with non-rollbackable",
    )

    warnings = [r for r in results if r.warning == "not_rollbackable"]
    assert len(warnings) == 1
    assert warnings[0].action_id == a2.action_id


# ---------------------------------------------------------------------------
# Tests: compensate (Saga)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compensate_creates_pending_rollback_before_failed_only(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Saga compensation: only actions executed *before* the failed action
    get rollback Actions, in reverse order.

    L2+ tools on the automated Saga path stop at PENDING (ApprovalEngine gate);
    predecessors are not effect-rolled-back until approval and execution complete.
    """
    event_id = await _seed_event(session_factory)

    t1 = _utc_now()
    t2 = datetime.fromtimestamp(t1.timestamp() + 10, tz=UTC)
    t3 = datetime.fromtimestamp(t1.timestamp() + 20, tz=UTC)
    t4 = datetime.fromtimestamp(t1.timestamp() + 30, tz=UTC)

    a1 = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        target="10.0.0.1",
        status=ActionStatus.SUCCESS,
        executed_at=t1,
    )
    a2 = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_domain",
        target="evil.example",
        target_type="domain",
        status=ActionStatus.SUCCESS,
        executed_at=t2,
    )
    # a3 is the failed action
    a3_failed = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="disable_account",
        target="user@test.com",
        target_type="account",
        status=ActionStatus.FAILED,
        executed_at=t3,
    )
    # a4 was executed AFTER the failure and should NOT be compensated
    _a4 = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="isolate_host",
        target="host-99",
        target_type="host",
        status=ActionStatus.SUCCESS,
        executed_at=t4,
    )

    svc = RollbackService(session_factory, audit=audit)

    results = await svc.compensate(
        event_id,
        failed_action_id=a3_failed.action_id,
        operator="saga-test",
        reason="saga compensation test",
    )

    # Only a1 and a2 should be compensated (executed before a3), in reverse order
    assert len(results) == 2
    assert results[0].action_id == a2.action_id  # latest first
    assert results[1].action_id == a1.action_id
    assert all(r.warning == "awaiting_approval" for r in results)
    assert all(r.rolled_back is False for r in results)
    assert all(r.rollback_action_id is not None for r in results)

    async with session_factory() as session:
        for result, predecessor in (
            (results[0], a2),
            (results[1], a1),
        ):
            rb_row = await session.get(orm.Action, result.rollback_action_id)
            assert rb_row is not None
            assert ActionStatus(rb_row.status) is ActionStatus.PENDING
            assert rb_row.source_action_id == predecessor.action_id

        # Original predecessors stay SUCCESS until rollback executes post-approval.
        for original_id in (a1.action_id, a2.action_id):
            orig_row = await session.get(orm.Action, original_id)
            assert orig_row is not None
            assert ActionStatus(orig_row.status) is ActionStatus.SUCCESS


# ---------------------------------------------------------------------------
# Tests: compensation writebacks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_action_with_writeback_required_creates_compensation(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """When original action has writeback_required=True, rollback creates
    compensation writebacks for each applicable outbox record."""
    event_id = await _seed_event(
        session_factory,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    conn_id = f"conn-{_sfx()}"
    source_record_id = await _seed_source_object(session_factory, event_id, connector_id=conn_id)
    disposition_source_ref = {
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-test",
        "connector_id": conn_id,
        "source_kind": SourceObjectKind.INCIDENT.value,
        "source_object_id": f"incident-{_sfx()}",
    }
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
        writeback_required=True,
        writeback_applicable=True,
        disposition_source_ref=disposition_source_ref,
    )
    # Create one ENTITY_ACTION_SUBMIT outbox record for the original action
    _ = await _seed_disposition_outbox(
        session_factory,
        action_id=original.action_id,
        event_id=event_id,
        source_record_id=source_record_id,
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
    )

    # Mock disposition_sync that returns plausible DispositionOutboxRecord
    mock_sync = _MockDispositionSync()

    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(
        session_factory,
        audit,
        execute=execute,
        disposition_sync=mock_sync,
    )

    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="compensation test",
    )

    assert result.rolled_back is True
    assert result.compensation_writeback_required is True
    assert len(result.compensation_writebacks) == 1
    wb = result.compensation_writebacks[0]
    assert wb.intent_kind == DispositionIntentKind.COMPENSATION_RECORD.value
    assert wb.status is WritebackStatus.PENDING
    assert wb.disposition_id is not None
    assert wb.writeback_id is not None
    # Verify enqueue_command was called exactly once
    assert mock_sync.call_count == 1


@pytest.mark.asyncio
async def test_rollback_action_multiple_dispositions_creates_multiple_compensations(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """One rollback on an action with multiple disposition outbox records
    produces one COMPENSATION_RECORD per applicable original writeback."""
    event_id = await _seed_event(
        session_factory,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    conn_id = f"conn-{_sfx()}"
    source_record_id = await _seed_source_object(session_factory, event_id, connector_id=conn_id)
    disposition_source_ref = {
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-test",
        "connector_id": conn_id,
        "source_kind": SourceObjectKind.INCIDENT.value,
        "source_object_id": f"incident-{_sfx()}",
    }
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
        writeback_required=True,
        writeback_applicable=True,
        disposition_source_ref=disposition_source_ref,
    )
    # Create two outbox records: ENTITY_ACTION_SUBMIT + EXECUTION_RESULT_RECORD
    await _seed_disposition_outbox(
        session_factory,
        action_id=original.action_id,
        event_id=event_id,
        source_record_id=source_record_id,
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
    )
    await _seed_disposition_outbox(
        session_factory,
        action_id=original.action_id,
        event_id=event_id,
        source_record_id=source_record_id,
        intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD,
        source_sequence=2,
    )

    mock_sync = _MockDispositionSync()
    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(
        session_factory,
        audit,
        execute=execute,
        disposition_sync=mock_sync,
    )

    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="multi-disposition compensation test",
    )

    assert result.rolled_back is True
    assert result.compensation_writeback_required is True
    assert len(result.compensation_writebacks) == 2
    # Verify compatibility field: null when >1 writeback
    assert result.compensation_writeback_id is None
    assert result.compensation_writeback_status is not None
    assert mock_sync.call_count == 2


# ---------------------------------------------------------------------------
# Tests: edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_action_nonexistent_action_returns_warning(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Non-existent action_id → rolled_back=False, warning='action_not_found'."""
    svc = RollbackService(session_factory, audit=audit)
    result = await svc.rollback_action(
        "nonexistent-action-id",
        operator="test-op",
        reason="ghost action test",
    )

    assert result.action_id == "nonexistent-action-id"
    assert result.rolled_back is False
    assert result.warning == "action_not_found"
    assert result.rollback_action_id is None


@pytest.mark.asyncio
async def test_rollback_event_no_eligible_actions(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """rollback_event returns empty list when no SUCCESS response actions exist."""
    event_id = await _seed_event(session_factory)

    svc = RollbackService(session_factory, audit=audit)
    results = await svc.rollback_event(
        event_id,
        operator="test-op",
        reason="empty event test",
    )

    assert results == []


@pytest.mark.asyncio
async def test_rollback_event_all_non_rollbackable(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """rollback_event returns warnings when all actions are non-rollbackable."""
    event_id = await _seed_event(session_factory)

    await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="force_logout",
        target="user-a@test.com",
        target_type="account",
        status=ActionStatus.SUCCESS,
    )
    await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="notify_security_team",
        target="team-channel",
        target_type="channel",
        status=ActionStatus.SUCCESS,
    )

    svc = RollbackService(session_factory, audit=audit)
    results = await svc.rollback_event(
        event_id,
        operator="test-op",
        reason="all non-rollbackable test",
    )

    assert len(results) == 2
    assert all(r.rolled_back is False for r in results)
    assert all(r.warning == "not_rollbackable" for r in results)


@pytest.mark.asyncio
async def test_compensate_no_actions_before_failed(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """compensate returns empty when no SUCCESS actions precede the failure."""
    event_id = await _seed_event(session_factory)

    t1 = _utc_now()
    # The failed action is the earliest — nothing to compensate.
    failed = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        target="10.0.0.1",
        status=ActionStatus.FAILED,
        executed_at=t1,
    )
    # Action executed AFTER the failure, should NOT be compensated.
    await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_domain",
        target="evil.example",
        target_type="domain",
        status=ActionStatus.SUCCESS,
        executed_at=datetime.fromtimestamp(t1.timestamp() + 10, tz=UTC),
    )

    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(session_factory, audit, execute=execute)

    results = await svc.compensate(
        event_id,
        failed_action_id=failed.action_id,
        operator="saga-test",
        reason="no predecessors test",
    )

    assert results == []


@pytest.mark.asyncio
async def test_rollback_action_partial_success_rejected(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """PARTIAL_SUCCESS actions must not be auto-rollbacked per spec."""
    event_id = await _seed_event(session_factory)
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.PARTIAL_SUCCESS,
        effect_verification_status=None,  # PARTIAL_SUCCESS: per-target check needed
    )

    svc = RollbackService(session_factory, audit=audit)
    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="partial success test",
    )

    assert result.rolled_back is False
    assert result.warning is not None
    assert "partial_success" in result.warning


@pytest.mark.asyncio
async def test_rollback_event_skips_unverified_effect(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """rollback_event skips SUCCESS actions whose effect_verification_status
    is not 'verified'."""
    event_id = await _seed_event(session_factory)

    # Action with verified effect — eligible for rollback
    await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        target="10.0.0.1",
        status=ActionStatus.SUCCESS,
        effect_verification_status="verified",
    )
    # Action with unverified effect — NOT eligible
    await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_domain",
        target="evil.example",
        target_type="domain",
        status=ActionStatus.SUCCESS,
        effect_verification_status=None,
    )

    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(session_factory, audit, execute=execute)

    results = await svc.rollback_event(
        event_id,
        operator="test-op",
        reason="unverified effect test",
    )

    # Only the verified action should be rolled back
    assert len(results) == 1
    assert results[0].rolled_back is True
    assert results[0].rollback_tool == "unblock_ip"


@pytest.mark.asyncio
async def test_rollback_action_publishes_event_on_success_and_rejection(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Rollback success and pre_check rejection both publish action_executed."""
    event_id = await _seed_event(session_factory)
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
    )
    bus = _MockEventBus()
    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(
        session_factory,
        audit,
        execute=execute,
        event_bus=bus,
    )

    success = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="event bus success",
    )
    assert success.rolled_back is True
    assert len(bus.events) == 1
    assert bus.events[0][1] == "action_executed"
    assert bus.events[0][2]["rollback"] is True
    assert bus.events[0][2]["rolled_back"] is True

    non_rb = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="force_logout",
        target="user@test.com",
        target_type="account",
        status=ActionStatus.SUCCESS,
    )
    rejected = await svc.rollback_action(
        non_rb.action_id,
        operator="test-op",
        reason="event bus rejection",
    )
    assert rejected.warning == "not_rollbackable"
    assert len(bus.events) == 2
    assert bus.events[1][2]["rejected"] is True
    assert bus.events[1][2]["rolled_back"] is False


@pytest.mark.asyncio
async def test_compensate_returns_warning_for_non_rollbackable_predecessor(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Saga compensate returns RollbackResult for skipped non-rollbackable actions."""
    event_id = await _seed_event(session_factory)
    t1 = _utc_now()
    t2 = datetime.fromtimestamp(t1.timestamp() + 10, tz=UTC)
    t3 = datetime.fromtimestamp(t1.timestamp() + 20, tz=UTC)

    await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="force_logout",
        target="user@test.com",
        target_type="account",
        status=ActionStatus.SUCCESS,
        executed_at=t1,
    )
    failed = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        target="10.0.0.1",
        status=ActionStatus.FAILED,
        executed_at=t3,
    )
    await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_domain",
        target="evil.example",
        target_type="domain",
        status=ActionStatus.SUCCESS,
        executed_at=t2,
    )

    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(session_factory, audit, execute=execute)
    results = await svc.compensate(
        event_id,
        failed_action_id=failed.action_id,
        operator="saga-test",
    )

    skipped = [r for r in results if r.warning == "not_rollbackable"]
    assert len(skipped) == 1


@pytest.mark.asyncio
async def test_rollback_compensation_skipped_when_xdr_writeback_disallowed(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live mode without ALLOW_XDR_WRITEBACK must not enqueue compensation."""
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "disposition_mode", "live")
    monkeypatch.setattr(settings, "allow_xdr_writeback", False)

    event_id = await _seed_event(
        session_factory,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    conn_id = f"conn-{_sfx()}"
    source_record_id = await _seed_source_object(session_factory, event_id, connector_id=conn_id)
    disposition_source_ref = {
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-test",
        "connector_id": conn_id,
        "source_kind": SourceObjectKind.INCIDENT.value,
        "source_object_id": f"incident-{_sfx()}",
    }
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
        writeback_required=True,
        writeback_applicable=True,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        disposition_source_ref=disposition_source_ref,
    )
    await _seed_disposition_outbox(
        session_factory,
        action_id=original.action_id,
        event_id=event_id,
        source_record_id=source_record_id,
    )
    mock_sync = _MockDispositionSync()
    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(
        session_factory,
        audit,
        execute=execute,
        disposition_sync=mock_sync,
    )

    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="live gate test",
    )

    assert result.rolled_back is True
    assert result.compensation_writeback_readiness is WritebackReadiness.CAPABILITY_UNSUPPORTED
    assert result.compensation_writebacks == []
    assert mock_sync.call_count == 0


@pytest.mark.asyncio
async def test_compensate_automated_l2_creates_pending_rollback_action(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Automated Saga path creates PENDING rollback for L2+ tools."""
    event_id = await _seed_event(session_factory)
    t1 = _utc_now()
    t2 = datetime.fromtimestamp(t1.timestamp() + 10, tz=UTC)

    predecessor = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        target="10.0.0.1",
        status=ActionStatus.SUCCESS,
        executed_at=t1,
    )
    failed = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_domain",
        target="evil.example",
        target_type="domain",
        status=ActionStatus.FAILED,
        executed_at=t2,
    )

    svc = RollbackService(session_factory, audit=audit)
    results = await svc.compensate(
        event_id,
        failed_action_id=failed.action_id,
        operator="SagaCompensation",
    )

    assert len(results) == 1
    assert results[0].warning == "awaiting_approval"
    assert results[0].rolled_back is False
    assert results[0].rollback_action_id is not None

    async with session_factory() as session:
        rb_row = await session.get(orm.Action, results[0].rollback_action_id)
        assert rb_row is not None
        assert ActionStatus(rb_row.status) is ActionStatus.PENDING
        assert rb_row.source_action_id == predecessor.action_id


class _StubDispositionAdapter:
    """Minimal adapter for XDR capability gate tests."""

    def __init__(self, *, supported: bool) -> None:
        self._supported = supported

    def capabilities(self) -> Any:
        from app.adapters.disposition.base import DispositionAdapterCapabilities

        if self._supported:
            return DispositionAdapterCapabilities(
                intents={
                    DispositionIntentKind.COMPENSATION_RECORD: CapabilityState.SUPPORTED,
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT: CapabilityState.SUPPORTED,
                },
                operations={"record_compensation": CapabilityState.SUPPORTED},
            )
        return DispositionAdapterCapabilities(
            intents={
                DispositionIntentKind.COMPENSATION_RECORD: CapabilityState.UNSUPPORTED,
                DispositionIntentKind.ENTITY_ACTION_SUBMIT: CapabilityState.UNSUPPORTED,
            },
            operations={"record_compensation": CapabilityState.UNSUPPORTED},
        )


class _StubAdapterRegistry:
    def __init__(self, adapter: _StubDispositionAdapter) -> None:
        self._adapter = adapter

    def get(self, name: str) -> _StubDispositionAdapter:
        return self._adapter


@pytest.mark.asyncio
async def test_xdr_managed_original_uses_direct_tool_execution_with_supported_adapter(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """Local rollback executes via DIRECT_TOOL; adapter only gates compensation."""
    event_id = await _seed_event(
        session_factory,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    conn_id = f"conn-{_sfx()}"
    disposition_source_ref = {
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-test",
        "connector_id": conn_id,
        "source_kind": SourceObjectKind.INCIDENT.value,
        "source_object_id": f"incident-{_sfx()}",
    }
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=True,
        disposition_source_ref=disposition_source_ref,
    )
    registry = _StubAdapterRegistry(_StubDispositionAdapter(supported=True))
    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(
        session_factory,
        audit,
        execute=execute,
        adapter_registry=registry,
    )

    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="xdr supported adapter",
    )

    assert result.rolled_back is True
    assert result.compensation_writeback_readiness is WritebackReadiness.READY
    async with session_factory() as session:
        rb_row = await session.get(orm.Action, result.rollback_action_id)
        assert rb_row is not None
        assert ExecutionOwner(rb_row.execution_owner) is ExecutionOwner.DIRECT_TOOL


@pytest.mark.asyncio
async def test_xdr_managed_original_unsupported_adapter_marks_compensation_blocked(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
) -> None:
    """When adapter lacks compensation capability, readiness is CAPABILITY_UNSUPPORTED."""
    event_id = await _seed_event(
        session_factory,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    conn_id = f"conn-{_sfx()}"
    disposition_source_ref = {
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-test",
        "connector_id": conn_id,
        "source_kind": SourceObjectKind.INCIDENT.value,
        "source_object_id": f"incident-{_sfx()}",
    }
    original = await _seed_response_action(
        session_factory,
        event_id=event_id,
        tool_name="block_ip",
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=True,
        disposition_source_ref=disposition_source_ref,
    )
    registry = _StubAdapterRegistry(_StubDispositionAdapter(supported=False))
    execute = _mock_execute_hook(session_factory, succeed=True)
    svc = _rollback_service(
        session_factory,
        audit,
        execute=execute,
        adapter_registry=registry,
    )

    result = await svc.rollback_action(
        original.action_id,
        operator="test-op",
        reason="xdr unsupported adapter",
    )

    assert result.rolled_back is True
    assert result.compensation_writeback_readiness is WritebackReadiness.CAPABILITY_UNSUPPORTED
    async with session_factory() as session:
        rb_row = await session.get(orm.Action, result.rollback_action_id)
        assert rb_row is not None
        assert ExecutionOwner(rb_row.execution_owner) is ExecutionOwner.DIRECT_TOOL


@pytest.mark.asyncio
async def test_rollback_compensation_confirmed_via_mock_xdr(
    session_factory: async_sessionmaker[AsyncSession],
    audit: EventAuditLogService,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """COMPENSATION_RECORD delivered via MockXDR reaches CONFIRMED with parent link."""
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()
    import httpx
    from httpx import ASGITransport

    from app.adapters.mock_xdr import MockXDRDispositionAdapter
    from app.adapters.registry import DispositionAdapterRegistry
    from app.core.guardrails import OutboundDispositionGuard
    from app.core.redis_client import RedisClient
    from app.data_generators.scenarios import build_scenario
    from app.mock_xdr.api import create_app
    from app.mock_xdr.state import MockXDRState
    from app.services.context_service import EventContextStore, event_summary_from_security_event
    from app.services.disposition_sync_service import DispositionSyncService
    from tests.test_services._mock_xdr_test_helpers import (
        SCENARIO_INCIDENT_ID,
        fetch_mock_concurrency_token,
    )

    try:
        redis = RedisClient(REDIS_URL)
        await redis.get_client().ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable: {exc}")

    state = MockXDRState()
    state.load_scenario(build_scenario("insider_data_exfiltration", seed=42))
    app = create_app(state=state)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://mock-xdr",
        timeout=30.0,
    ) as mock_xdr_client:
        store = EventContextStore(redis, session_factory)
        registry = DispositionAdapterRegistry()
        adapter = MockXDRDispositionAdapter(
            client=mock_xdr_client,
            read_token="mock-read-token",
            write_token="mock-write-token",
        )
        registry.register("mock_xdr", adapter)
        disposition_sync = DispositionSyncService(
            session_factory,
            context_store=store,
            adapter_registry=registry,
            outbound_guard=OutboundDispositionGuard(),
        )

        connector_id = "conn-disposition"
        source_record_id = f"src-{_sfx()}"
        object_id = SCENARIO_INCIDENT_ID
        concurrency_token = await fetch_mock_concurrency_token(
            mock_xdr_client,
            object_id=object_id,
        )
        disposition_source_ref = {
            "source_product": "mock_xdr",
            "source_tenant_id": "tenant-demo",
            "connector_id": connector_id,
            "source_kind": SourceObjectKind.INCIDENT.value,
            "source_object_id": object_id,
        }
        event_id = await _seed_event(
            session_factory,
            disposition_policy=DispositionPolicy.REQUIRED,
        )
        async with session_factory() as session:
            async with session.begin():
                session.add(
                    orm.SourceConnector(
                        connector_id=connector_id,
                        source_product="mock_xdr",
                        display_name="Mock XDR",
                    )
                )
                session.add(
                    orm.SourceObject(
                        source_record_id=source_record_id,
                        source_product="mock_xdr",
                        source_tenant_id="tenant-demo",
                        connector_id=connector_id,
                        source_kind=SourceObjectKind.INCIDENT.value,
                        source_object_type="incident",
                        source_object_id=object_id,
                        source_concurrency_token=concurrency_token,
                        current_concurrency_token=concurrency_token,
                        source_status_raw="contained",
                        source_disposition=SourceDisposition.CONTAINED.value,
                        next_outbox_sequence=0,
                    )
                )
        async with session_factory() as session:
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            await store.init_context(event_id, event_summary_from_security_event(row))

        parent_disposition_id = f"disp-parent-{_sfx()}"
        original = await _seed_response_action(
            session_factory,
            event_id=event_id,
            tool_name="block_ip",
            status=ActionStatus.SUCCESS,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            writeback_required=True,
            writeback_applicable=True,
            disposition_source_ref=disposition_source_ref,
        )
        await _seed_disposition_outbox(
            session_factory,
            action_id=original.action_id,
            event_id=event_id,
            source_record_id=source_record_id,
            intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
            disposition_id=parent_disposition_id,
        )

        execute = _mock_execute_hook(session_factory, succeed=True)
        svc = _rollback_service(
            session_factory,
            audit,
            execute=execute,
            disposition_sync=disposition_sync,
            adapter_registry=registry,
        )
        result = await svc.rollback_action(
            original.action_id,
            operator="test-op",
            reason="mock xdr compensation confirmed",
        )
        assert result.rolled_back is True
        assert len(result.compensation_writebacks) == 1

        delivered = await disposition_sync.process_ready_outboxes(limit=5)
        assert delivered >= 1

        async with session_factory() as session:
            comp_outbox = await session.scalar(
                select(orm.DispositionOutbox)
                .where(
                    orm.DispositionOutbox.action_id == result.rollback_action_id,
                    orm.DispositionOutbox.intent_kind
                    == DispositionIntentKind.COMPENSATION_RECORD.value,
                )
                .order_by(orm.DispositionOutbox.created_at.desc())
            )
            assert comp_outbox is not None
            payload = comp_outbox.command_payload or {}
            assert payload.get("parent_disposition_id") == parent_disposition_id
            assert comp_outbox.latest_writeback_status in {
                WritebackStatus.CONFIRMED.value,
                WritebackStatus.ACCEPTED.value,
            }
            receipt = await session.scalar(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == comp_outbox.writeback_id
                )
            )
            assert receipt is not None
            assert receipt.status in {
                WritebackStatus.CONFIRMED.value,
                WritebackStatus.ACCEPTED.value,
            }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_rollback_mapping_covers_all_expected_tools() -> None:
    """Verify that the 6 rollbackable tools have mappings."""
    from app.agents.rules.rollback_mapping import ROLLBACK_VERIFY_MAP, get_rollback_verify_tool

    assert is_rollbackable("block_ip")
    assert is_rollbackable("block_domain")
    assert is_rollbackable("isolate_host")
    assert is_rollbackable("quarantine_file")
    assert is_rollbackable("disable_account")
    assert is_rollbackable("create_ticket")

    assert not is_rollbackable("force_logout")
    assert not is_rollbackable("reset_password")
    assert not is_rollbackable("revoke_token")
    assert not is_rollbackable("notify_security_team")
    assert not is_rollbackable("nonexistent_tool")

    assert get_rollback_verify_tool("unblock_ip") == "check_ip_block_status"
    assert get_rollback_verify_tool("close_false_positive_ticket") is None
    assert len(ROLLBACK_VERIFY_MAP) == 6


def test_rollback_result_compatibility_field() -> None:
    """compensation_writeback_id is populated when exactly 1 writeback."""
    from app.models.rollback_result import CompensationWritebackItem

    # 0 writebacks -> None
    r0 = RollbackResult(action_id="act-01")
    assert r0.compensation_writeback_id is None

    # 1 writeback -> the writeback_id
    r1 = RollbackResult(
        action_id="act-01",
        compensation_writebacks=[
            CompensationWritebackItem(
                writeback_id="wbk-test",
                disposition_id="disp-test",
            )
        ],
    )
    assert r1.compensation_writeback_id == "wbk-test"

    # 2 writebacks -> None
    r2 = RollbackResult(
        action_id="act-01",
        compensation_writebacks=[
            CompensationWritebackItem(writeback_id="wbk-1", disposition_id="disp-1"),
            CompensationWritebackItem(writeback_id="wbk-2", disposition_id="disp-2"),
        ],
    )
    assert r2.compensation_writeback_id is None
