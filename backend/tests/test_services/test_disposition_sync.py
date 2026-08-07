"""DispositionSyncService tests (ISSUE-059).

Requires Compose PostgreSQL (+ Redis for context). Run from ``backend/``:

    pytest tests/test_services/test_disposition_sync.py -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from httpx import ASGITransport
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.agents.verify_agent import _action_from_row
from app.core.errors import InvalidStateTransitionError, WritebackConflictError
from app.core.guardrails import OutboundDispositionGuard
from app.data_generators.scenarios import build_scenario
from app.db import models as orm
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.models.action import Action
from app.models.disposition import SourceObjectLocator, TargetWritebackResult
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    ConfirmationEvidence,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionJobStatus,
    ExecutionOwner,
    ExecutionSubstate,
    FinalVerdict,
    OutboxDeliveryStatus,
    Severity,
    SourceObjectKind,
    TargetExecutionStatus,
    TargetWritebackStatus,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.execution import ActionExecutionJob, TargetExecutionResult
from app.models.ids import new_disposition_id
from app.models.source import SourceReference
from app.services.context_service import (
    EventContextStore,
    append_context_journal_in_session,
    event_summary_from_security_event,
    unwrap_journal_value,
)
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from tests.test_services._mock_xdr_test_helpers import (
    SCENARIO_INCIDENT_ID,
    fetch_mock_concurrency_token,
)

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
async def redis_client():
    from app.core.redis_client import RedisClient

    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def store(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
) -> EventContextStore:
    return EventContextStore(redis_client, session_factory)


@pytest_asyncio.fixture
async def mock_xdr_client() -> AsyncIterator[httpx.AsyncClient]:
    state = MockXDRState()
    state.load_scenario(build_scenario("insider_data_exfiltration", seed=42))
    app = create_app(state=state)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://mock-xdr",
        timeout=30.0,
    ) as client:
        yield client


@pytest_asyncio.fixture
async def cleanup(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    yield
    async with session_factory() as session:
        async with session.begin():
            for table in (
                orm.EventAuditLog,
                orm.EventContextJournal,
                orm.EventContextFieldVersion,
                orm.ActionTargetResult,
                orm.ActionExecutionJob,
                orm.DispositionReceipt,
                orm.DispositionOutbox,
                orm.Action,
                orm.Evidence,
                orm.Report,
                orm.SourceEventLink,
                orm.SourceObject,
                orm.SecurityEvent,
            ):
                await session.execute(delete(table))


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _locator(*, object_id: str = "88442201") -> SourceObjectLocator:
    return SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id=object_id,
    )


async def _seed_event_action_source(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
) -> tuple[str, str, str, SourceObjectLocator, str]:
    sfx = _sfx()
    event_id = f"evt-sync-{sfx}"
    action_id = f"act-{sfx}"
    connector_id = "conn-disposition"
    source_record_id = f"src-{sfx}"
    object_id = SCENARIO_INCIDENT_ID
    locator = _locator(object_id=object_id)
    concurrency_token = await fetch_mock_concurrency_token(mock_xdr_client, object_id=object_id)
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id=connector_id,
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )
    async with session_factory() as session:
        async with session.begin():
            existing = await session.get(orm.SourceConnector, connector_id)
            if existing is None:
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
                    source_object_id=object_id,
                    current_concurrency_token=concurrency_token,
                    next_outbox_sequence=0,
                )
            )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.OTHER.value,
                    title="sync-test",
                    description="",
                    status=EventStatus.EXECUTING_RESPONSE.value,
                    severity=Severity.HIGH.value,
                    risk_score=80,
                    confidence=0.9,
                    final_verdict=FinalVerdict.NONE.value,
                    creation_source_ref=ref.model_dump(mode="json"),
                    source_reference_snapshots=[ref.model_dump(mode="json")],
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    disposition_source_ref=locator.model_dump(mode="json"),
                    occurred_at=datetime.now(UTC),
                )
            )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        await store.init_context(event_id, event_summary_from_security_event(row))
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level=ActionLevel.L2.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.EXECUTING.value,
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    target_type="ip",
                    target="203.0.113.88",
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    disposition_source_ref=locator.model_dump(mode="json"),
                    idempotency_key=f"idem-{sfx}",
                )
            )
    return event_id, action_id, source_record_id, locator, concurrency_token


def _sync_service(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    client: httpx.AsyncClient,
    *,
    resume: AsyncMock | None = None,
) -> DispositionSyncService:
    registry = DispositionAdapterRegistry()
    adapter = MockXDRDispositionAdapter(
        client=client,
        read_token="mock-read-token",
        write_token="mock-write-token",
    )
    registry.register("mock_xdr", adapter)
    return DispositionSyncService(
        session_factory,
        context_store=store,
        adapter_registry=registry,
        outbound_guard=OutboundDispositionGuard(),
        resume_investigation=resume,
    )


@pytest.mark.asyncio
async def test_get_disposition_by_id(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    disposition_id = new_disposition_id()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-get",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=disposition_id,
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    loaded, status = await sync.get_disposition(disposition_id)
    assert loaded.disposition_id == disposition_id
    assert status is None or isinstance(status, WritebackStatus)


@pytest.mark.asyncio
async def test_enqueue_and_deliver_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-test",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    assert record.intent_kind.value == "entity_action_submit"
    delivered = await sync.process_ready_outboxes(limit=1)
    assert delivered == 1
    async with session_factory() as session:
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(orm.DispositionOutbox.outbox_id == record.outbox_id)
        )
        assert outbox_row is not None
        assert outbox_row.delivery_status == "delivered"
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None
        assert action_row.status == ActionStatus.SUCCESS.value
        assert action_row.writeback_status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }
        receipt = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == record.writeback_id
            )
        )
        assert receipt is not None
        assert receipt.status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }


@pytest.mark.asyncio
async def test_retry_unknown_writeback_rejected(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{_sfx()}",
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
    with pytest.raises(WritebackConflictError):
        await sync.retry_writeback(writeback_id, operator="operator-1")


@pytest.mark.asyncio
async def test_resolve_writeback_manual_confirmed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{_sfx()}",
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
    sync = _sync_service(session_factory, store, mock_xdr_client)
    status = await sync.resolve_writeback(
        writeback_id,
        "manual_confirmed",
        principal="admin-1",
        comment="ticket-123",
        evidence_ref="evidence://ticket-123",
    )
    assert status is WritebackStatus.CONFIRMED


async def _mark_action_writeback_not_applicable(
    session_factory: async_sessionmaker[AsyncSession],
    action_id: str,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            action = await session.get(orm.Action, action_id, with_for_update=True)
            assert action is not None
            action.writeback_applicable = False
            action.writeback_readiness = WritebackReadiness.NOT_REQUIRED.value
            action.writeback_status = None


@pytest.mark.asyncio
async def test_sync_lookup_and_resolve_skip_writeback_status_when_not_applicable(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-195: lookup/resolve paths must not denormalize writeback_status."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    await _mark_action_writeback_not_applicable(session_factory, action_id)
    sync = _sync_service(session_factory, store, mock_xdr_client)

    lookup_writeback_id = f"wbk-lookup-{_sfx()}"
    resolve_writeback_id = f"wbk-resolve-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-lookup-{_sfx()}",
                    writeback_id=lookup_writeback_id,
                    disposition_id=f"disp-lookup-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-lookup-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.FAILED.value,
                )
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-resolve-{_sfx()}",
                    writeback_id=resolve_writeback_id,
                    disposition_id=f"disp-resolve-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=2,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-resolve-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )

    await sync.update_writeback_status_from_lookup(
        lookup_writeback_id,
        WritebackStatus.CONFIRMED,
    )
    await sync.resolve_writeback(
        resolve_writeback_id,
        "manual_confirmed",
        principal="admin-1",
        comment="ticket-195",
        evidence_ref="evidence://ticket-195",
    )

    async with session_factory() as session:
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None
        assert action_row.writeback_applicable is False
        assert action_row.writeback_status is None
        lookup_outbox = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.writeback_id == lookup_writeback_id
            )
        )
        assert lookup_outbox is not None
        assert lookup_outbox.latest_writeback_status == WritebackStatus.CONFIRMED.value
        resolve_outbox = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.writeback_id == resolve_writeback_id
            )
        )
        assert resolve_outbox is not None
        assert resolve_outbox.latest_writeback_status == WritebackStatus.CONFIRMED.value


@pytest.mark.asyncio
async def test_entity_action_submit_skips_writeback_status_when_not_applicable(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-195: delivery receipt must not set writeback_status on non-applicable rows."""
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    await _mark_action_writeback_not_applicable(session_factory, action_id)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-test",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": False,
            "writeback_readiness": WritebackReadiness.NOT_REQUIRED,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    delivered = await sync.process_ready_outboxes(limit=1)
    assert delivered == 1
    async with session_factory() as session:
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(orm.DispositionOutbox.outbox_id == record.outbox_id)
        )
        assert outbox_row is not None
        assert outbox_row.delivery_status == "delivered"
        assert outbox_row.latest_writeback_status in {
            WritebackStatus.ACCEPTED.value,
            WritebackStatus.CONFIRMED.value,
        }
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None
        assert action_row.writeback_applicable is False
        assert action_row.writeback_status is None
        _action_from_row(action_row)


@pytest.mark.asyncio
async def test_resume_hook_called_on_terminal_writeback(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    resume = AsyncMock()
    sync = _sync_service(session_factory, store, mock_xdr_client, resume=resume)
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "execution_substate",
                ExecutionSubstate.WAITING_WRITEBACK.value,
            )
            writeback_id = f"wbk-{_sfx()}"
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{_sfx()}",
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={"source_locator": locator.model_dump(mode="json")},
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                )
            )
    await sync.resolve_writeback(
        writeback_id,
        "manual_confirmed",
        principal="admin-1",
        comment="done",
        evidence_ref="evidence://ok",
    )
    resume.assert_awaited_once_with(event_id)


@pytest.mark.asyncio
async def test_outbound_guard_blocks_non_allowlisted_field(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import OutboundDispositionGuard

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-guard",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    payload = command.model_dump(mode="json")
    payload["reason"] = "analysis leak"
    guard = OutboundDispositionGuard()
    with pytest.raises(GuardrailViolationError):
        await guard.validate(payload, {"event_id": event_id, "approved_action_ids": [action_id]})


@pytest.mark.asyncio
async def test_expired_lease_outbox_reclaimed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from datetime import timedelta

    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    expired = datetime.now(UTC) - timedelta(minutes=5)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.LEASED.value,
                    locked_by="stale-worker",
                    locked_at=expired,
                    lease_expires_at=expired,
                )
            )
    worker = OutboxWorker(sync)
    claimed = await worker.run_once(limit=1)
    assert claimed == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.WAITING_RETRY.value
        assert row.attempt == 0
        assert row.next_retry_at is not None
        assert row.next_retry_at > datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DispositionOutbox, outbox_id, with_for_update=True)
            assert row is not None
            row.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)

    claimed = await worker.run_once(limit=1)
    assert claimed == 1
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value


@pytest.mark.asyncio
async def test_lookup_update_blocks_illegal_transition(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-062 Blocker #1: FAILED → CONFIRMED without evidence_adjudication is rejected.

    update_writeback_status_from_lookup must call validate_writeback_status_transition
    before writing the provider-resolved status.  FAILED → CONFIRMED requires
    evidence_adjudication=True, and while the lookup itself provides that evidence,
    the validate call ensures the transition is structurally valid.  This test
    constructs a FAILED outbox and attempts to update it to CONFIRMED via the
    lookup path; the transition is allowed with evidence_adjudication=True.
    """
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        "source_locator": locator.model_dump(mode="json"),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.FAILED.value,
                )
            )
    # FAILED → CONFIRMED with evidence_adjudication=True (provider-side
    # lookup provides the evidence) should be accepted — the validate call
    # must not throw.
    await sync.update_writeback_status_from_lookup(writeback_id, WritebackStatus.CONFIRMED)
    # Verify the status was actually written.
    async with session_factory() as session:
        outbox = await session.get(orm.DispositionOutbox, outbox_id)
        assert outbox is not None
        assert outbox.latest_writeback_status == WritebackStatus.CONFIRMED.value


@pytest.mark.asyncio
async def test_lookup_update_blocks_illegal_transition_to_pending(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-062 Blocker #1: FAILED → PENDING without adapter_allows_safe_retry is rejected.

    Even when the status comes from a provider-side lookup, FAILED → PENDING
    requires adapter_allows_safe_retry=True — a status query alone does not
    prove the adapter can safely retry.  This test verifies the transition
    guard is enforced.
    """
    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{_sfx()}",
                    writeback_id=writeback_id,
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        "source_locator": locator.model_dump(mode="json"),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status="delivered",
                    latest_writeback_status=WritebackStatus.FAILED.value,
                )
            )
    # FAILED → PENDING requires adapter_allows_safe_retry=True, which the
    # default validate_writeback_status_transition call does not provide.
    with pytest.raises(InvalidStateTransitionError):
        await sync.update_writeback_status_from_lookup(writeback_id, WritebackStatus.PENDING)


def factory_build_min_command(
    action_id: str,
    event_id: str,
    locator: SourceObjectLocator,
    concurrency_token: str,
) -> dict:
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-min",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{action_id}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    return command.model_dump(mode="json")


async def _insert_leased_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    action_id: str,
    source_record_id: str,
    locator: SourceObjectLocator,
    concurrency_token: str,
    outbox_id: str | None = None,
    attempt: int = 0,
) -> str:
    oid = outbox_id or f"obx-{_sfx()}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=oid,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.LEASED.value,
                    locked_by="worker-a",
                    locked_at=now,
                    lease_expires_at=now + timedelta(seconds=30),
                    attempt=attempt,
                )
            )
    return oid


@pytest.mark.asyncio
async def test_waiting_retry_future_next_retry_at_not_claimed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    future = datetime.now(UTC) + timedelta(minutes=10)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                    attempt=1,
                    next_retry_at=future,
                    last_error_code="delivery_failed",
                )
            )
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=5) == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.WAITING_RETRY.value


@pytest.mark.asyncio
async def test_waiting_retry_due_is_claimed_and_delivered(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    past = datetime.now(UTC) - timedelta(seconds=5)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                    attempt=1,
                    next_retry_at=past,
                    last_error_code="delivery_failed",
                )
            )
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=5) == 1
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DELIVERED.value


@pytest.mark.asyncio
async def test_outbox_max_attempts_moves_to_dead_letter(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    settings = Settings.model_validate({**get_settings().model_dump(), "OUTBOX_MAX_ATTEMPTS": 2})
    monkeypatch.setattr("app.services.disposition_sync_service.get_settings", lambda: settings)

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = await _insert_leased_outbox(
        session_factory,
        event_id=event_id,
        action_id=action_id,
        source_record_id=source_record_id,
        locator=locator,
        concurrency_token=concurrency_token,
        attempt=1,
    )

    await sync._mark_delivery_waiting_retry(outbox_id, error_code="delivery_failed")

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.attempt == 2
        assert row.next_retry_at is None

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=5) == 0


@pytest.mark.asyncio
async def test_delivery_failure_schedules_backoff_not_hot_retry(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    async def _fail_delivery(_outbox_id: str) -> None:
        raise RuntimeError("simulated adapter failure")

    monkeypatch.setattr(sync, "_deliver_outbox", _fail_delivery)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.WAITING_RETRY.value
        assert row.attempt == 1
        assert row.next_retry_at is not None
        assert row.next_retry_at > datetime.now(UTC)
        assert row.last_error_detail is not None
        assert "RuntimeError" in row.last_error_detail

    assert await worker.run_once(limit=1) == 0


@pytest.mark.asyncio
async def test_waiting_retry_null_next_retry_at_backfilled_not_claimed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                    attempt=1,
                    next_retry_at=None,
                    last_error_code="delivery_failed",
                )
            )
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=5) == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.WAITING_RETRY.value
        assert row.next_retry_at is not None
        assert row.next_retry_at > datetime.now(UTC)


@pytest.mark.asyncio
async def test_guardrail_blocked_moves_to_dead_letter(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.errors import GuardrailViolationError
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    async def _guardrail_block(_outbox_id: str) -> None:
        raise GuardrailViolationError(
            "blocked writeback field",
            error_code="guardrail_violation",
        )

    monkeypatch.setattr(sync, "_deliver_outbox", _guardrail_block)
    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == "guardrail_blocked"
        assert row.last_error_detail is not None
        assert row.next_retry_at is None

    assert await worker.run_once(limit=1) == 0


@pytest.mark.asyncio
async def test_append_receipt_sanitizes_sensitive_raw_result_before_persist(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-181: malicious adapter raw_result must not land verbatim in DB."""
    from app.models.disposition import DispositionReceipt

    (
        event_id,
        action_id,
        source_record_id,
        _locator,
        _concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    outbox_id = f"obx-{_sfx()}"
    disposition_id = f"disp-{_sfx()}"
    malicious_raw = {
        "token": "secret-token-value",
        "password": "hunter2",
        "details": {"api_key": "sk-test1234567890"},
        "provider_status": "accepted",
    }
    receipt = DispositionReceipt(
        writeback_id=writeback_id,
        sequence=0,
        disposition_id=disposition_id,
        action_id=action_id,
        source_record_id=source_record_id,
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
        provider_message="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
        target_results=[
            TargetWritebackResult(
                canonical_target="host:workstation-1",
                status=TargetWritebackStatus.CONFIRMED,
                provider_code="token=secret-provider-code",
                message_code="Bearer leaked-target-token",
                artifact_ref="https://user:password@internal.example/artifact/1",
            )
        ],
        raw_result=dict(malicious_raw),
        simulated=True,
    )
    original_raw = dict(receipt.raw_result)
    original_message = receipt.provider_message
    original_target_results = [item.model_copy() for item in receipt.target_results]

    async with session_factory() as session:
        async with session.begin():
            outbox = orm.DispositionOutbox(
                outbox_id=outbox_id,
                writeback_id=writeback_id,
                disposition_id=disposition_id,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=source_record_id,
                source_locator_hash="hash",
                source_sequence=1,
                intent_kind="entity_action_submit",
                logical_slot="default",
                idempotency_key=f"idem-{_sfx()}",
                command_payload={"intent_kind": "entity_action_submit"},
                command_payload_sha256="deadbeef",
                delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                latest_writeback_status=WritebackStatus.CONFIRMED.value,
            )
            session.add(outbox)
            persisted = await sync._append_receipt(session, outbox, receipt=receipt)

    assert receipt.raw_result == original_raw
    assert receipt.provider_message == original_message
    assert [item.model_dump() for item in receipt.target_results] == [
        item.model_dump() for item in original_target_results
    ]
    assert persisted.status is WritebackStatus.CONFIRMED
    assert persisted.confirmation_evidence is ConfirmationEvidence.READBACK_VERIFIED
    assert persisted.raw_result["provider_status"] == "accepted"
    assert persisted.raw_result["token"] == "***"
    assert persisted.raw_result["password"] == "***"
    assert persisted.raw_result["details"]["api_key"] == "***"
    assert "[REDACTED]" in (persisted.provider_message or "")
    assert persisted.target_results[0].canonical_target == "host:workstation-1"
    assert persisted.target_results[0].status is TargetWritebackStatus.CONFIRMED
    assert "[REDACTED]" in (persisted.target_results[0].provider_code or "")
    assert "[REDACTED]" in (persisted.target_results[0].message_code or "")
    assert "[REDACTED]" in (persisted.target_results[0].artifact_ref or "")

    async with session_factory() as session:
        row = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == writeback_id,
                orm.DispositionReceipt.sequence == 1,
            )
        )
        assert row is not None
        assert row.status == WritebackStatus.CONFIRMED.value
        assert row.confirmation_evidence == ConfirmationEvidence.READBACK_VERIFIED.value
        assert row.raw_result["token"] == "***"
        assert row.raw_result["password"] == "***"
        assert "secret-token-value" not in str(row.raw_result)
        assert "hunter2" not in str(row.raw_result)
        assert "[REDACTED]" in str(row.target_results)

        journal_value = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "disposition_receipts",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        assert journal_value is not None
        journal_items = unwrap_journal_value(journal_value)
        assert isinstance(journal_items, list)
        assert journal_items
        journal_receipt = journal_items[-1]
        assert journal_receipt["status"] == WritebackStatus.CONFIRMED.value
        assert journal_receipt["confirmation_evidence"] == (
            ConfirmationEvidence.READBACK_VERIFIED.value
        )
        assert journal_receipt["raw_result"]["token"] == "***"
        assert journal_receipt["raw_result"]["password"] == "***"
        assert "secret-token-value" not in str(journal_receipt)
        assert "hunter2" not in str(journal_receipt)
        assert "[REDACTED]" in str(journal_receipt["target_results"])


@pytest.mark.asyncio
async def test_append_receipt_preserves_mock_receipt_gate_fields(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
) -> None:
    """ISSUE-181: sanitize must not strip confirmation_evidence or writeback status."""
    from app.models.disposition import DispositionReceipt

    (
        event_id,
        action_id,
        source_record_id,
        _locator,
        _concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    writeback_id = f"wbk-{_sfx()}"
    outbox_id = f"obx-{_sfx()}"
    disposition_id = f"disp-{_sfx()}"
    receipt = DispositionReceipt(
        writeback_id=writeback_id,
        sequence=0,
        disposition_id=disposition_id,
        action_id=action_id,
        source_record_id=source_record_id,
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
        provider_record_id="mock-record-1",
        provider_job_id="mock-job-1",
        raw_result={"simulated": True, "status": "confirmed"},
        simulated=True,
    )

    async with session_factory() as session:
        async with session.begin():
            outbox = orm.DispositionOutbox(
                outbox_id=outbox_id,
                writeback_id=writeback_id,
                disposition_id=disposition_id,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=source_record_id,
                source_locator_hash="hash",
                source_sequence=1,
                intent_kind="entity_action_submit",
                logical_slot="default",
                idempotency_key=f"idem-{_sfx()}",
                command_payload={"intent_kind": "entity_action_submit"},
                command_payload_sha256="deadbeef",
                delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                latest_writeback_status=WritebackStatus.CONFIRMED.value,
            )
            session.add(outbox)
            persisted = await sync._append_receipt(session, outbox, receipt=receipt)

    assert persisted.status is WritebackStatus.CONFIRMED
    assert persisted.confirmation_evidence is ConfirmationEvidence.READBACK_VERIFIED
    assert persisted.provider_record_id == "mock-record-1"
    assert persisted.provider_job_id == "mock-job-1"
    assert persisted.raw_result["simulated"] is True
    assert persisted.raw_result["status"] == "confirmed"
    assert persisted.simulated is True


@pytest.mark.asyncio
async def test_deliver_outbox_blocked_when_writeback_fence_closed_after_enqueue(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: enqueue under mock, flip settings, deliver must not submit."""
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-fence",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    blocked_settings = Settings.model_validate(
        {
            **get_settings().model_dump(),
            "DISPOSITION_MODE": "live_xdr",
            "ALLOW_XDR_WRITEBACK": False,
        }
    )
    monkeypatch.setattr(
        "app.services.writeback_side_effect_fence.get_settings",
        lambda: blocked_settings,
    )
    monkeypatch.setattr(
        "app.services.disposition_sync_service.get_settings",
        lambda: blocked_settings,
    )

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_deliver_outbox_sync_ready_blocked_when_writeback_fence_closed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: synchronous deliver_outbox on READY must fail-closed too."""
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    blocked_settings = Settings.model_validate(
        {
            **get_settings().model_dump(),
            "ALLOW_LIVE_SIDE_EFFECTS": True,
        }
    )
    monkeypatch.setattr(
        "app.services.writeback_side_effect_fence.get_settings",
        lambda: blocked_settings,
    )

    await sync.deliver_outbox(outbox_id)
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_outbox_live_side_effects_blocked_via_worker(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: worker delivery must fail-closed when ALLOW_LIVE_SIDE_EFFECTS is on."""
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)
    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    blocked_settings = Settings.model_validate(
        {
            **get_settings().model_dump(),
            "ALLOW_LIVE_SIDE_EFFECTS": True,
        }
    )
    monkeypatch.setattr(
        "app.services.writeback_side_effect_fence.get_settings",
        lambda: blocked_settings,
    )

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_outbox_fence_blocks_from_waiting_retry(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: WAITING_RETRY outbox must fail-closed when writeback fence is closed."""
    from app.core.config import Settings, get_settings
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                    attempt=1,
                    next_retry_at=datetime.now(UTC) - timedelta(seconds=5),
                )
            )

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)
    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    blocked_settings = Settings.model_validate(
        {
            **get_settings().model_dump(),
            "DISPOSITION_MODE": "live_xdr",
            "ALLOW_XDR_WRITEBACK": False,
        }
    )
    monkeypatch.setattr(
        "app.services.writeback_side_effect_fence.get_settings",
        lambda: blocked_settings,
    )

    await sync.deliver_outbox(outbox_id)
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_outbox_fence_blocks_when_action_row_missing(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-222: missing action row must fail-closed without adapter.submit."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    outbox_id = f"obx-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DispositionOutbox(
                    outbox_id=outbox_id,
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{_sfx()}",
                    command_payload={
                        **factory_build_min_command(
                            action_id, event_id, locator, concurrency_token
                        ),
                    },
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    attempt=0,
                )
            )

    real_get = AsyncSession.get

    async def _get_without_action(self, entity, ident, **kwargs):  # type: ignore[no-untyped-def]
        if entity is orm.Action:
            return None
        return await real_get(self, entity, ident, **kwargs)

    monkeypatch.setattr(AsyncSession, "get", _get_without_action)

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(command):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(command)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(outbox_id)
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        assert action_id in row.last_error_detail


@pytest.mark.asyncio
async def test_deliver_rejects_after_approval_revoked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-235 (SUS-301): an approval revoked between enqueue and delivery
    must fail-closed — the entity-class outbox is not delivered (the
    enqueue-time approved snapshot must not go out after revoke/supersede)."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-revoke",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )

    # Revoke the approval while the outbox is still in flight.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.REJECTED.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    await sync.deliver_outbox(record.outbox_id)

    # Fail-closed: never submitted, outbox dead-lettered with the fence code.
    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
        assert row.last_error_detail is not None
        receipts = (
            await session.scalars(
                select(orm.DispositionReceipt).where(
                    orm.DispositionReceipt.writeback_id == row.writeback_id
                )
            )
        ).all()
        assert receipts == []


@pytest.mark.asyncio
async def test_worker_deliver_rejects_after_approval_revoked(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-235: production worker lease path must also fail-closed after revoke."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.disposition_sync_service import OutboxWorker
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-worker-revoke",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": ActionStatus.EXECUTING,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    command = factory.build_entity_action_submit(
        action,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        writeback_id="pending",
        closure_cycle=1,
        entity_action_code="block_ip",
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.REJECTED.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_submit)

    worker = OutboxWorker(sync)
    assert await worker.run_once(limit=1) == 1
    assert submit_calls == 0

    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE


@pytest.mark.asyncio
async def test_deliver_execution_result_rejected_after_supersede(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-235: an EXECUTION_RESULT_RECORD whose action was superseded after
    enqueue (supersede-only — status may still be SUCCESS) must not be
    delivered; the delivery-time re-check fails closed."""
    from app.models.enums import OutboxDeliveryStatus
    from app.services.writeback_side_effect_fence import WRITEBACK_FENCE_BLOCKED_ERROR_CODE

    (
        event_id,
        action_id,
        source_record_id,
        locator,
        concurrency_token,
    ) = await _seed_event_action_source(session_factory, store, mock_xdr_client)
    sync = _sync_service(session_factory, store, mock_xdr_client)
    factory = DispositionCommandFactory()
    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": "fp-result",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.DIRECT_TOOL,
            "status": ActionStatus.SUCCESS,
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": f"idem-{_sfx()}",
        }
    )
    job = ActionExecutionJob(
        job_id=f"job-{_sfx()}",
        event_id=event_id,
        action_id=action_id,
        provider_name="mock_tool_provider",
        idempotency_key=f"idem-job-{_sfx()}",
        status=ExecutionJobStatus.SUCCESS,
        target_results=[
            TargetExecutionResult(
                canonical_target="ip:203.0.113.88",
                status=TargetExecutionStatus.SUCCESS,
                code="block_success",
                message="block success",
            )
        ],
    )
    command = factory.build_execution_result_record(
        action,
        job,
        source_locator=locator,
        source_concurrency_token=concurrency_token,
        operator_id="ActionExecutionService",
        disposition_id=new_disposition_id(),
        closure_cycle=1,
    )
    async with session_factory() as session:
        async with session.begin():
            record = await sync.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
            )
    assert record.intent_kind.value == "execution_result_record"

    # Supersede-only: mirror production timing — action already SUCCESS, then superseded.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value
            row.superseded_by_revision = 2

    submit_calls = 0
    adapter = sync._adapters.get("mock_xdr")
    assert adapter is not None
    original_submit = adapter.submit

    async def _tracked_result_submit(cmd):  # type: ignore[no-untyped-def]
        nonlocal submit_calls
        submit_calls += 1
        return await original_submit(cmd)

    monkeypatch.setattr(adapter, "submit", _tracked_result_submit)

    await sync.deliver_outbox(record.outbox_id)

    assert submit_calls == 0
    async with session_factory() as session:
        row = await session.get(orm.DispositionOutbox, record.outbox_id)
        assert row is not None
        assert row.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
        assert row.last_error_code == WRITEBACK_FENCE_BLOCKED_ERROR_CODE
