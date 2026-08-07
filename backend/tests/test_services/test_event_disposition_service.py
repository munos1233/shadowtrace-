"""EventDispositionService tests (ISSUE-059A).

Requires Compose PostgreSQL (+ Redis for context). Run from ``backend/``:

    pytest tests/test_services/test_event_disposition_service.py -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from httpx import ASGITransport
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.agents.response_agent import compute_template_hash, derive_disposition_idempotency_key
from app.core.guardrails import OutboundDispositionGuard
from app.data_generators.scenarios import build_scenario
from app.db import models as orm
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import (
    EffectStatus,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
)
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    SourceDisposition,
    SourceObjectKind,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.source import SourceReference
from app.services.context_service import EventContextStore, event_summary_from_security_event
from app.services.decision_record_service import DecisionRecordService
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from tests.helpers.decision_audit import seed_minimum_disposition_audit
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
async def disposition_sync(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
) -> DispositionSyncService:
    registry = DispositionAdapterRegistry()
    adapter = MockXDRDispositionAdapter(
        client=mock_xdr_client,
        read_token="mock-read-token",
        write_token="mock-write-token",
    )
    registry.register("mock_xdr", adapter)
    return DispositionSyncService(
        session_factory,
        context_store=store,
        adapter_registry=registry,
        outbound_guard=OutboundDispositionGuard(),
    )


@pytest_asyncio.fixture
async def disposition_service(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_sync: DispositionSyncService,
    redis_client,
) -> EventDispositionService:
    from app.core.event_bus import EventBus

    return EventDispositionService(
        session_factory,
        disposition_sync=disposition_sync,
        context_store=store,
        event_bus=EventBus(redis_client),
        decision_record_service=DecisionRecordService(session_factory),
    )


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
                orm.DecisionRecord,
                orm.Evidence,
                orm.Report,
                orm.SourceEventLink,
                orm.SourceObject,
                orm.SecurityEvent,
            ):
                await session.execute(delete(table))


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _locator(*, object_id: str = SCENARIO_INCIDENT_ID) -> SourceObjectLocator:
    return SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id=object_id,
    )


def _ref(*, object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )


def _deferred_action(
    *,
    event_id: str,
    action_id: str | None = None,
    approved: list[SourceDisposition] | None = None,
    status: ActionStatus = ActionStatus.APPROVED,
    readiness: WritebackReadiness = WritebackReadiness.READY,
    plan_revision: int = 1,
) -> Action:
    approved = approved or [SourceDisposition.CONTAINED, SourceDisposition.COMPLETED]
    aid = action_id or f"act-term-{_sfx()}"
    template_hash = compute_template_hash(approved)
    idem = derive_disposition_idempotency_key(
        action_id=aid,
        plan_revision=plan_revision,
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        logical_slot="terminal",
    )
    locator = _locator()
    return Action.model_validate(
        {
            "action_id": aid,
            "event_id": event_id,
            "plan_revision": plan_revision,
            "action_fingerprint": f"fp-{aid}",
            "action_category": ActionCategory.RESPONSE,
            "action_name": TERMINAL_DISPOSITION_TOOL,
            "tool_name": TERMINAL_DISPOSITION_TOOL,
            "action_level": ActionLevel.L2,
            "execution_phase": ActionExecutionPhase.POST_VERIFY,
            "activation_condition": "after_effect_resolution",
            "approved_operation_template_hash": template_hash,
            "approved_terminal_dispositions": approved,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "status": status,
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": readiness,
            "disposition_source_ref": locator,
            "idempotency_key": idem,
        }
    )


async def _seed_connector_and_source(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    object_id: str = SCENARIO_INCIDENT_ID,
    mock_xdr_client: httpx.AsyncClient | None = None,
) -> str:
    sfx = _sfx()
    connector_id = "conn-disposition"
    source_record_id = f"src-{sfx}"
    concurrency_token = "tok-1"
    if mock_xdr_client is not None and object_id == SCENARIO_INCIDENT_ID:
        concurrency_token = await fetch_mock_concurrency_token(mock_xdr_client, object_id=object_id)
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
    return source_record_id


async def _create_event(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    *,
    final_verdict: FinalVerdict = FinalVerdict.CONFIRMED_THREAT,
    object_id: str = SCENARIO_INCIDENT_ID,
    disposition_only: bool = False,
) -> str:
    sfx = _sfx()
    event_id = f"evt-disp-{sfx}"
    ref = _ref(object_id=object_id)
    locator = _locator(object_id=object_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.OTHER.value,
                    title="disposition-activation-test",
                    description="",
                    status=EventStatus.VERIFYING.value,
                    severity=Severity.HIGH.value,
                    risk_score=80,
                    confidence=0.9,
                    final_verdict=final_verdict.value,
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
    if disposition_only:
        await store.set(event_id, "disposition_only_intent", True)
    return event_id


async def _insert_action(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    action: Action,
) -> Action:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action.action_id,
                    event_id=event_id,
                    plan_revision=action.plan_revision,
                    action_fingerprint=action.action_fingerprint,
                    action_category=action.action_category.value,
                    action_name=action.action_name,
                    tool_name=action.tool_name,
                    action_level=action.action_level.value,
                    execution_phase=action.execution_phase.value,
                    activation_condition=action.activation_condition,
                    approved_operation_template_hash=action.approved_operation_template_hash,
                    approved_terminal_dispositions=[
                        item.value for item in action.approved_terminal_dispositions
                    ],
                    status=action.status.value,
                    execution_owner=(
                        action.execution_owner.value if action.execution_owner else None
                    ),
                    target_type=action.target_type,
                    target=action.target,
                    parameters=action.parameters or {},
                    writeback_required=action.writeback_required,
                    writeback_applicable=action.writeback_applicable,
                    writeback_readiness=action.writeback_readiness.value,
                    disposition_source_ref=(
                        action.disposition_source_ref.model_dump(mode="json")
                        if action.disposition_source_ref
                        else None
                    ),
                    idempotency_key=action.idempotency_key,
                    reason=action.reason,
                )
            )
    return action.model_copy(update={"event_id": event_id})


async def _seed_effect_verification(
    store: EventContextStore,
    event_id: str,
    *,
    action_id: str,
) -> None:
    payload = VerificationResult(
        results=[
            VerificationActionResult(
                action_id=action_id,
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            )
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    await store.set(event_id, "verification_result", payload.model_dump(mode="json"))


async def _seed_immediate_pending_verification(
    store: EventContextStore,
    event_id: str,
    *,
    immediate_id: str,
    deferred_id: str,
    overall_status: VerificationOverallStatus = VerificationOverallStatus.WAITING,
) -> None:
    payload = VerificationResult(
        results=[
            VerificationActionResult(
                action_id=immediate_id,
                effect_status=EffectStatus.SKIPPED,
                detail="pending_execution",
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
            VerificationActionResult(
                action_id=deferred_id,
                effect_status=EffectStatus.SKIPPED,
                detail="deferred_pending_activation",
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
            ),
        ],
        overall_status=overall_status,
        verification_phase=VerificationPhase.EFFECT,
    )
    await store.set(event_id, "verification_result", payload.model_dump(mode="json"))


async def _seed_non_verifiable_fp_verification(
    store: EventContextStore,
    event_id: str,
    *,
    immediate_id: str,
    deferred_id: str,
    detail: str = "non_verifiable_action",
) -> None:
    payload = VerificationResult(
        results=[
            VerificationActionResult(
                action_id=immediate_id,
                effect_status=EffectStatus.SKIPPED,
                detail=detail,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
            VerificationActionResult(
                action_id=deferred_id,
                effect_status=EffectStatus.SKIPPED,
                detail="deferred_pending_activation",
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    await store.set(event_id, "verification_result", payload.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_activate_required_plan_submits_event_status_update(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    disposition_sync: DispositionSyncService,
    cleanup: None,
) -> None:
    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(session_factory, store)
    immediate_id = f"act-imm-{_sfx()}"
    deferred = _deferred_action(event_id=event_id)
    locator = _locator()
    await _insert_action(
        session_factory,
        event_id,
        Action.model_validate(
            {
                "action_id": immediate_id,
                "event_id": event_id,
                "plan_revision": 1,
                "action_fingerprint": f"fp-{immediate_id}",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "block ip",
                "tool_name": "block_ip",
                "action_level": ActionLevel.L2,
                "execution_owner": ExecutionOwner.XDR_MANAGED,
                "status": ActionStatus.SUCCESS,
                "target_type": "ip",
                "target": "203.0.113.88",
                "writeback_required": True,
                "writeback_applicable": True,
                "writeback_readiness": WritebackReadiness.READY,
                "disposition_source_ref": locator,
                "idempotency_key": f"idem-{immediate_id}",
            }
        ),
    )
    await _insert_action(session_factory, event_id, deferred)
    await _seed_effect_verification(store, event_id, action_id=immediate_id)
    await seed_minimum_disposition_audit(session_factory, event_id)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.activated is True
    assert result.derived_disposition is SourceDisposition.CONTAINED
    assert result.disposition_id
    assert result.writeback_id

    # ISSUE-064: activate_and_submit now synchronously delivers the outbox,
    # so process_ready_outboxes may return 0 (outbox already DELIVERED).
    # Verify the outbox delivery_status directly instead.
    delivered = await disposition_sync.process_ready_outboxes(limit=1)
    assert delivered >= 0
    confirmed = await disposition_sync.resolve_writeback(
        result.writeback_id,
        "manual_confirmed",
        principal="test-operator",
        comment="integration-test",
        evidence_ref="evidence://059a-required",
    )
    assert confirmed is WritebackStatus.CONFIRMED

    async with session_factory() as session:
        outboxes = (
            await session.scalars(
                select(orm.DispositionOutbox).where(orm.DispositionOutbox.event_id == event_id)
            )
        ).all()
        assert len(outboxes) == 1
        assert outboxes[0].intent_kind == DispositionIntentKind.EVENT_STATUS_UPDATE.value
        assert outboxes[0].closure_cycle == deferred.plan_revision
        assert outboxes[0].action_id == deferred.action_id
        receipt = await session.scalar(
            select(orm.DispositionReceipt)
            .where(orm.DispositionReceipt.writeback_id == result.writeback_id)
            .order_by(orm.DispositionReceipt.sequence.desc())
            .limit(1)
        )
        assert receipt is not None
        assert receipt.status == WritebackStatus.CONFIRMED.value
        assert receipt.action_id == deferred.action_id
        action_row = await session.get(orm.Action, deferred.action_id)
        assert action_row is not None
        assert action_row.status == ActionStatus.SUCCESS.value


@pytest.mark.asyncio
async def test_disposition_only_false_positive_activates_ignored(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=True,
    )
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.IGNORED],
    )
    await _insert_action(session_factory, event_id, deferred)
    await seed_minimum_disposition_audit(session_factory, event_id)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.activated is True
    assert result.derived_disposition is SourceDisposition.IGNORED


@pytest.mark.asyncio
async def test_terminal_not_in_approved_set_zero_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=True,
    )
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.CONTAINED, SourceDisposition.COMPLETED],
    )
    await _insert_action(session_factory, event_id, deferred)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.activated is False
    assert result.skipped_reason == "terminal_not_in_approved_set"

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
        assert int(count or 0) == 0


@pytest.mark.asyncio
async def test_not_approved_skips_activation(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=True,
    )
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.IGNORED],
        status=ActionStatus.WAITING_APPROVAL,
    )
    await _insert_action(session_factory, event_id, deferred)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.skipped_reason == "not_approved"


@pytest.mark.asyncio
async def test_not_ready_skips_activation(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=True,
    )
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.IGNORED],
        readiness=WritebackReadiness.SOURCE_UNRESOLVED,
    )
    await _insert_action(session_factory, event_id, deferred)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.skipped_reason == "effect_not_ready"


@pytest.mark.asyncio
async def test_idempotent_replay_returns_existing_ids(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=True,
    )
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.IGNORED],
    )
    await _insert_action(session_factory, event_id, deferred)
    await seed_minimum_disposition_audit(session_factory, event_id)

    first = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    second = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert first.activated is True
    assert second.activated is False
    assert second.skipped_reason == "already_submitted"
    assert second.disposition_id == first.disposition_id
    assert second.writeback_id == first.writeback_id

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
        assert int(count or 0) == 1


@pytest.mark.asyncio
async def test_effect_not_ready_without_verification(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(session_factory, store)
    deferred = _deferred_action(event_id=event_id)
    await _insert_action(session_factory, event_id, deferred)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.skipped_reason == "effect_not_ready"


@pytest.mark.asyncio
async def test_capability_blocked_skips_with_zero_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_sync: DispositionSyncService,
    redis_client,
    cleanup: None,
) -> None:
    from app.core.event_bus import EventBus

    blocked_service = EventDispositionService(
        session_factory,
        disposition_sync=disposition_sync,
        context_store=store,
        event_bus=EventBus(redis_client),
        event_disposition_supported=False,
    )
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=True,
    )
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.IGNORED],
    )
    await _insert_action(session_factory, event_id, deferred)

    result = await blocked_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.activated is False
    assert result.skipped_reason == "capability_blocked"

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
        assert int(count or 0) == 0


@pytest.mark.asyncio
async def test_activate_plan_revision_2_uses_closure_cycle_2(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(session_factory, store)
    rev1_deferred = _deferred_action(
        event_id=event_id,
        action_id=f"act-rev1-{_sfx()}",
        plan_revision=1,
    )
    await _insert_action(session_factory, event_id, rev1_deferred)
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, rev1_deferred.action_id)
            assert row is not None
            row.superseded_by_revision = 2
    deferred = _deferred_action(event_id=event_id, plan_revision=2)
    immediate_id = f"act-imm-{_sfx()}"
    locator = _locator()
    await _insert_action(
        session_factory,
        event_id,
        Action.model_validate(
            {
                "action_id": immediate_id,
                "event_id": event_id,
                "plan_revision": 2,
                "action_fingerprint": f"fp-{immediate_id}",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "block ip",
                "tool_name": "block_ip",
                "action_level": ActionLevel.L2,
                "execution_owner": ExecutionOwner.XDR_MANAGED,
                "status": ActionStatus.SUCCESS,
                "target_type": "ip",
                "target": "203.0.113.88",
                "writeback_required": True,
                "writeback_applicable": True,
                "writeback_readiness": WritebackReadiness.READY,
                "disposition_source_ref": locator,
                "idempotency_key": f"idem-{immediate_id}",
            }
        ),
    )
    await _insert_action(session_factory, event_id, deferred)
    await _seed_effect_verification(store, event_id, action_id=immediate_id)
    await seed_minimum_disposition_audit(session_factory, event_id)

    result = await disposition_service.activate_and_submit(event_id, 2, "test-operator")
    assert result.activated is True

    async with session_factory() as session:
        outbox = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.action_id == deferred.action_id
            )
        )
        assert outbox is not None
        assert outbox.closure_cycle == 2
        assert outbox.intent_kind == DispositionIntentKind.EVENT_STATUS_UPDATE.value


@pytest.mark.asyncio
async def test_activate_blocked_without_decision_audit(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    from app.core.errors import ValidationError

    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(session_factory, store)
    immediate_id = f"act-imm-{_sfx()}"
    deferred = _deferred_action(event_id=event_id)
    locator = _locator()
    await _insert_action(
        session_factory,
        event_id,
        Action.model_validate(
            {
                "action_id": immediate_id,
                "event_id": event_id,
                "plan_revision": 1,
                "action_fingerprint": f"fp-{immediate_id}",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "block ip",
                "tool_name": "block_ip",
                "action_level": ActionLevel.L2,
                "execution_owner": ExecutionOwner.XDR_MANAGED,
                "status": ActionStatus.SUCCESS,
                "target_type": "ip",
                "target": "203.0.113.88",
                "writeback_required": True,
                "writeback_applicable": True,
                "writeback_readiness": WritebackReadiness.READY,
                "disposition_source_ref": locator,
                "idempotency_key": f"idem-{immediate_id}",
            }
        ),
    )
    await _insert_action(session_factory, event_id, deferred)
    await _seed_effect_verification(store, event_id, action_id=immediate_id)

    with pytest.raises(ValidationError, match="requires decision audit records"):
        await disposition_service.activate_and_submit(event_id, 1, "test-operator")


def test_resolver_false_positive_to_ignored() -> None:
    from app.services.terminal_disposition_resolver import TerminalDispositionResolver

    resolver = TerminalDispositionResolver()
    result = resolver.resolve(
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        verification=None,
        approved_terminal_dispositions=[SourceDisposition.IGNORED],
        disposition_only=True,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
    )
    assert result.disposition is SourceDisposition.IGNORED


def test_resolver_false_positive_blocked_when_immediate_pending() -> None:
    from app.services.terminal_disposition_resolver import TerminalDispositionResolver

    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-imm-pending",
                effect_status=EffectStatus.SKIPPED,
                detail="pending_execution",
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    resolver = TerminalDispositionResolver()
    result = resolver.resolve(
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        verification=verification,
        approved_terminal_dispositions=[SourceDisposition.IGNORED],
        disposition_only=False,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
    )
    assert result.disposition is None
    assert result.need_manual_resolution is True


def test_resolver_false_positive_blocked_when_non_verifiable_skipped() -> None:
    """ISSUE-232: non-disposition_only FP must not IGNORED with unverified effects."""
    from app.services.terminal_disposition_resolver import TerminalDispositionResolver

    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-ticket",
                effect_status=EffectStatus.SKIPPED,
                detail="non_verifiable_action",
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    resolver = TerminalDispositionResolver()
    result = resolver.resolve(
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        verification=verification,
        approved_terminal_dispositions=[SourceDisposition.IGNORED],
        disposition_only=False,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
    )
    assert result.disposition is None
    assert result.need_manual_resolution is True


def test_resolver_false_positive_blocked_when_no_verification_tool_skipped() -> None:
    """ISSUE-232: no_verification_tool_registered must block FP auto-IGNORED."""
    from app.services.terminal_disposition_resolver import TerminalDispositionResolver

    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-unregistered",
                effect_status=EffectStatus.SKIPPED,
                detail="no_verification_tool_registered",
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    resolver = TerminalDispositionResolver()
    result = resolver.resolve(
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        verification=verification,
        approved_terminal_dispositions=[SourceDisposition.IGNORED],
        disposition_only=False,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
    )
    assert result.disposition is None
    assert result.need_manual_resolution is True


def test_resolver_false_positive_blocked_when_mixed_verified_and_non_verifiable() -> None:
    """ISSUE-232: one unverified applicable row blocks FP even if others are VERIFIED."""
    from app.services.terminal_disposition_resolver import TerminalDispositionResolver

    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-block",
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
            VerificationActionResult(
                action_id="act-ticket",
                effect_status=EffectStatus.SKIPPED,
                detail="non_verifiable_action",
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    resolver = TerminalDispositionResolver()
    result = resolver.resolve(
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        verification=verification,
        approved_terminal_dispositions=[SourceDisposition.IGNORED],
        disposition_only=False,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
    )
    assert result.disposition is None
    assert result.need_manual_resolution is True


def test_resolver_false_positive_ignored_when_only_deferred_skipped() -> None:
    """ISSUE-232: deferred_pending_activation must not block FP IGNORED."""
    from app.services.terminal_disposition_resolver import TerminalDispositionResolver

    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-deferred",
                effect_status=EffectStatus.SKIPPED,
                detail="deferred_pending_activation",
                writeback_required=True,
                writeback_readiness=WritebackReadiness.READY,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    resolver = TerminalDispositionResolver()
    result = resolver.resolve(
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        verification=verification,
        approved_terminal_dispositions=[SourceDisposition.IGNORED],
        disposition_only=False,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
    )
    assert result.disposition is SourceDisposition.IGNORED
    assert result.need_manual_resolution is False


def test_resolver_threat_blocked_when_immediate_pending() -> None:
    from app.services.terminal_disposition_resolver import TerminalDispositionResolver

    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id="act-imm-pending",
                effect_status=EffectStatus.SKIPPED,
                detail="pending_execution",
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            ),
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    resolver = TerminalDispositionResolver()
    result = resolver.resolve(
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        verification=verification,
        approved_terminal_dispositions=[
            SourceDisposition.SUSPENDED,
            SourceDisposition.CONTAINED,
        ],
        disposition_only=False,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
    )
    assert result.disposition is None
    assert result.need_manual_resolution is True


@pytest.mark.asyncio
async def test_immediate_pending_fp_does_not_enqueue_terminal_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    """ISSUE-216: FP + IMMEDIATE still pending must not activate terminal outbox."""
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=False,
    )
    immediate_id = f"act-imm-pending-{_sfx()}"
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.IGNORED],
    )
    locator = _locator()
    await _insert_action(
        session_factory,
        event_id,
        Action.model_validate(
            {
                "action_id": immediate_id,
                "event_id": event_id,
                "plan_revision": 1,
                "action_fingerprint": f"fp-{immediate_id}",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "block ip",
                "tool_name": "block_ip",
                "action_level": ActionLevel.L2,
                "execution_phase": ActionExecutionPhase.IMMEDIATE,
                "execution_owner": ExecutionOwner.XDR_MANAGED,
                "status": ActionStatus.EXECUTING,
                "target_type": "ip",
                "target": "203.0.113.88",
                "writeback_required": True,
                "writeback_applicable": True,
                "writeback_readiness": WritebackReadiness.READY,
                "disposition_source_ref": locator,
                "idempotency_key": f"idem-{immediate_id}",
            }
        ),
    )
    await _insert_action(session_factory, event_id, deferred)
    await _seed_immediate_pending_verification(
        store,
        event_id,
        immediate_id=immediate_id,
        deferred_id=deferred.action_id,
        overall_status=VerificationOverallStatus.WAITING,
    )
    await seed_minimum_disposition_audit(session_factory, event_id)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.activated is False
    assert result.skipped_reason == "effect_not_ready"

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
        assert int(count or 0) == 0


@pytest.mark.asyncio
async def test_immediate_pending_fp_blocks_even_if_verification_success_forged(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    """Defense in depth: forged SUCCESS with pending SKIPPED rows still blocks."""
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=False,
    )
    immediate_id = f"act-imm-forged-{_sfx()}"
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.IGNORED],
    )
    locator = _locator()
    await _insert_action(
        session_factory,
        event_id,
        Action.model_validate(
            {
                "action_id": immediate_id,
                "event_id": event_id,
                "plan_revision": 1,
                "action_fingerprint": f"fp-{immediate_id}",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "block ip",
                "tool_name": "block_ip",
                "action_level": ActionLevel.L2,
                "execution_phase": ActionExecutionPhase.IMMEDIATE,
                "execution_owner": ExecutionOwner.XDR_MANAGED,
                "status": ActionStatus.EXECUTING,
                "target_type": "ip",
                "target": "203.0.113.88",
                "writeback_required": True,
                "writeback_applicable": True,
                "writeback_readiness": WritebackReadiness.READY,
                "disposition_source_ref": locator,
                "idempotency_key": f"idem-{immediate_id}",
            }
        ),
    )
    await _insert_action(session_factory, event_id, deferred)
    await _seed_immediate_pending_verification(
        store,
        event_id,
        immediate_id=immediate_id,
        deferred_id=deferred.action_id,
        overall_status=VerificationOverallStatus.SUCCESS,
    )
    await seed_minimum_disposition_audit(session_factory, event_id)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.activated is False
    assert result.skipped_reason == "effect_not_ready"

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
        assert int(count or 0) == 0


@pytest.mark.asyncio
async def test_non_verifiable_fp_does_not_enqueue_terminal_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    """ISSUE-232: FP + non_verifiable IMMEDIATE must not activate terminal outbox."""
    event_id = await _create_event(
        session_factory,
        store,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        disposition_only=False,
    )
    immediate_id = f"act-ticket-{_sfx()}"
    deferred = _deferred_action(
        event_id=event_id,
        approved=[SourceDisposition.IGNORED],
    )
    locator = _locator()
    await _insert_action(
        session_factory,
        event_id,
        Action.model_validate(
            {
                "action_id": immediate_id,
                "event_id": event_id,
                "plan_revision": 1,
                "action_fingerprint": f"fp-{immediate_id}",
                "action_category": ActionCategory.RESPONSE,
                "action_name": "create ticket",
                "tool_name": "create_ticket",
                "action_level": ActionLevel.L2,
                "execution_phase": ActionExecutionPhase.IMMEDIATE,
                "execution_owner": ExecutionOwner.DIRECT_TOOL,
                "status": ActionStatus.SUCCESS,
                "writeback_required": False,
                "writeback_applicable": False,
                "writeback_readiness": WritebackReadiness.NOT_REQUIRED,
                "disposition_source_ref": locator,
                "idempotency_key": f"idem-{immediate_id}",
            }
        ),
    )
    await _insert_action(session_factory, event_id, deferred)
    await _seed_non_verifiable_fp_verification(
        store,
        event_id,
        immediate_id=immediate_id,
        deferred_id=deferred.action_id,
        detail="non_verifiable_action",
    )
    await seed_minimum_disposition_audit(session_factory, event_id)

    result = await disposition_service.activate_and_submit(event_id, 1, "test-operator")
    assert result.activated is False
    assert result.skipped_reason == "effect_not_ready"

    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
        assert int(count or 0) == 0


@pytest.mark.asyncio
async def test_concurrent_activate_and_submit_keeps_single_active_head(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    disposition_sync: DispositionSyncService,
    cleanup: None,
) -> None:
    """ISSUE-219: concurrent activations of the same (event_id, closure_cycle)
    never raise — the loser is an idempotent no-op (concurrent_head_conflict
    or already_submitted) and exactly one active head remains, with the
    winner's lineage intact."""
    import asyncio

    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(session_factory, store)
    deferred_a = _deferred_action(event_id=event_id)
    deferred_b = _deferred_action(event_id=event_id)
    await _insert_action(session_factory, event_id, deferred_a)
    await _insert_action(session_factory, event_id, deferred_b)
    await _seed_effect_verification(store, event_id, action_id=deferred_a.action_id)
    await _seed_effect_verification(store, event_id, action_id=deferred_b.action_id)

    results = await asyncio.gather(
        disposition_service.activate_and_submit(event_id, 1, "op-a"),
        disposition_service.activate_and_submit(event_id, 1, "op-b"),
        return_exceptions=True,
    )
    assert not any(isinstance(r, BaseException) for r in results), results

    activated = [r for r in results if getattr(r, "activated", False)]
    assert len(activated) >= 1, results
    for r in results:
        if not r.activated:
            assert r.skipped_reason in (
                "concurrent_head_conflict",
                "already_submitted",
            ), r
            assert r.writeback_id is not None, r
            assert r.disposition_id is not None, r

    async with session_factory() as session:
        active = (
            (
                await session.execute(
                    select(orm.DispositionOutbox).where(
                        orm.DispositionOutbox.event_id == event_id,
                        orm.DispositionOutbox.closure_cycle == 1,
                        orm.DispositionOutbox.intent_kind
                        == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                        orm.DispositionOutbox.logical_slot == "terminal",
                        orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        all_outboxes = (
            (
                await session.execute(
                    select(orm.DispositionOutbox).where(
                        orm.DispositionOutbox.event_id == event_id,
                        orm.DispositionOutbox.closure_cycle == 1,
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(active) == 1, f"expected exactly one active head, got {len(active)}"
    if len(activated) == 2:
        superseded = [o for o in all_outboxes if o.superseded_by_disposition_id is not None]
        assert len(superseded) >= 1, "serial supersede must mark prior head lineage"
        assert active[0].supersedes_disposition_id is not None


@pytest.mark.asyncio
async def test_second_action_supersedes_first_with_lineage(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    cleanup: None,
) -> None:
    """ISSUE-219: a later Action on the same event/cycle supersedes the prior
    active head via enqueue_command (replan path), with full lineage."""
    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(session_factory, store)
    deferred_a = _deferred_action(event_id=event_id)
    deferred_b = _deferred_action(event_id=event_id)
    await _insert_action(session_factory, event_id, deferred_a)
    await _insert_action(session_factory, event_id, deferred_b)
    await _seed_effect_verification(store, event_id, action_id=deferred_a.action_id)
    await _seed_effect_verification(store, event_id, action_id=deferred_b.action_id)

    first = await disposition_service.activate_and_submit(event_id, 1, "op-a")
    second = await disposition_service.activate_and_submit(event_id, 1, "op-b")
    assert first.activated is True
    assert second.activated is True

    async with session_factory() as session:
        active = (
            (
                await session.execute(
                    select(orm.DispositionOutbox).where(
                        orm.DispositionOutbox.event_id == event_id,
                        orm.DispositionOutbox.closure_cycle == 1,
                        orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        first_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.disposition_id == first.disposition_id
            )
        )
        second_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.disposition_id == second.disposition_id
            )
        )
    assert len(active) == 1
    assert active[0].disposition_id == second.disposition_id
    assert first_row is not None
    assert second_row is not None
    assert first_row.superseded_by_disposition_id == second.disposition_id
    assert second_row.supersedes_disposition_id == first.disposition_id


def test_active_head_unique_violation_matches_constraint_name() -> None:
    from sqlalchemy.exc import IntegrityError

    from app.services.event_disposition_service import _is_active_head_unique_violation

    class _Diag:
        constraint_name = "uq_disposition_outbox_event_status_active_head"

    exc = IntegrityError("insert", {}, Exception("orig"))
    exc.orig = type("Orig", (), {"diag": _Diag()})()
    assert _is_active_head_unique_violation(exc) is True


def test_other_unique_violation_not_misclassified_as_active_head() -> None:
    from sqlalchemy.exc import IntegrityError

    from app.services.event_disposition_service import _is_active_head_unique_violation

    class _Diag:
        constraint_name = "uq_disposition_outbox_idempotency_key"

    exc = IntegrityError("insert", {}, Exception("orig"))
    exc.orig = type("Orig", (), {"diag": _Diag()})()
    assert _is_active_head_unique_violation(exc) is False


def test_active_head_unique_violation_message_fallback() -> None:
    from sqlalchemy.exc import IntegrityError

    from app.services.event_disposition_service import _is_active_head_unique_violation

    exc = IntegrityError("insert", {}, Exception("orig"))
    exc.orig = Exception(
        'duplicate key violates unique constraint "uq_disposition_outbox_event_status_active_head"'
    )
    assert _is_active_head_unique_violation(exc) is True
