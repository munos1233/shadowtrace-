"""ActionExecutionService tests (ISSUE-059).

Requires Compose PostgreSQL (+ Redis for context). Run from ``backend/``:

    pytest tests/test_services/test_action_execution.py -v
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

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
from app.core.errors import InvalidStateTransitionError, ValidationError
from app.core.guardrails import OutboundDispositionGuard
from app.data_generators.scenarios import build_scenario
from app.db import models as orm
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionJobStatus,
    ExecutionOwner,
    ExecutionSubstate,
    FinalVerdict,
    InvestigationIntentStatus,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.source import SourceReference
from app.services.action_execution_service import ActionExecutionService
from app.services.context_service import (
    EventContextStore,
    append_context_journal_in_session,
    event_summary_from_security_event,
)
from app.services.manual_resolution_service import ManualResolutionService
from app.services.degraded_flag_service import DegradedFlagService
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.state_machine_service import StateMachineService
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry
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
async def tool_executor() -> ToolExecutor:
    registry = ToolRegistry()
    await registry.auto_discover_for_mode(tool_mode="mock")
    return ToolExecutor(registry=registry)


@pytest_asyncio.fixture
async def state_machine(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    redis_client,
) -> StateMachineService:
    from app.core.event_bus import EventBus

    return StateMachineService(
        session_factory,
        store,
        event_bus=EventBus(redis_client),
        audit_log=EventAuditLogService(session_factory),
        degraded_flags=DegradedFlagService(store, session_factory),
    )


@pytest_asyncio.fixture
async def execution_service(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_sync: DispositionSyncService,
    tool_executor: ToolExecutor,
    state_machine: StateMachineService,
) -> ActionExecutionService:
    return ActionExecutionService(
        session_factory,
        disposition_sync=disposition_sync,
        tool_executor=tool_executor,
        state_machine=state_machine,
        context_store=store,
    )


@pytest.fixture(autouse=True)
def _isolate_mock_tool_provider() -> Iterator[None]:
    """Prevent singleton MockToolProvider state leaking between integration tests."""
    import app.providers.tools.mock_provider as mock_provider_module

    mock_provider_module._default_provider = None
    mock_provider_module._execution_context.set(None)
    yield
    mock_provider_module._default_provider = None
    mock_provider_module._execution_context.set(None)


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
                orm.GraphResumeIntent,
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


def _ref(*, object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )


def _action_model(**overrides: object) -> Action:
    locator = _locator()
    base = {
        "action_id": f"act-{_sfx()}",
        "event_id": "evt-placeholder",
        "plan_revision": 1,
        "action_fingerprint": f"fp-{_sfx()}",
        "action_category": ActionCategory.RESPONSE,
        "action_name": "block ip",
        "tool_name": "block_ip",
        "action_level": ActionLevel.L2,
        "execution_owner": ExecutionOwner.XDR_MANAGED,
        "status": ActionStatus.APPROVED,
        "target_type": "ip",
        "target": "203.0.113.88",
        "writeback_required": True,
        "writeback_applicable": True,
        "writeback_readiness": WritebackReadiness.READY,
        "disposition_source_ref": locator,
        "idempotency_key": f"idem-{_sfx()}",
    }
    base.update(overrides)
    return Action.model_validate(base)


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
    status: EventStatus = EventStatus.EXECUTING_RESPONSE,
    object_id: str | None = None,
) -> str:
    sfx = _sfx()
    event_id = f"evt-exec-{sfx}"
    resolved_object_id = object_id or f"INC-{sfx}"
    ref = _ref(object_id=resolved_object_id)
    locator = _locator(object_id=resolved_object_id)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.OTHER.value,
                    title="execution-test",
                    description="",
                    status=status.value,
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


@pytest.mark.asyncio
async def test_empty_immediate_transitions_to_verifying(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(session_factory, store)
    await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            tool_name=TERMINAL_DISPOSITION_TOOL,
            activation_condition="after_effect_resolution",
            execution_owner=ExecutionOwner.XDR_MANAGED,
        ),
    )
    summary = await execution_service.execute_plan(event_id)
    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.VERIFYING.value
    assert summary.action_counts.get(ActionStatus.APPROVED.value, 0) == 1


@pytest.mark.asyncio
async def test_xdr_managed_execute_plan_submits_outbox(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    oid = SCENARIO_INCIDENT_ID
    await _seed_connector_and_source(
        session_factory, object_id=oid, mock_xdr_client=mock_xdr_client
    )
    event_id = await _create_event(session_factory, store, object_id=oid)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            disposition_source_ref=_locator(object_id=oid),
        ),
    )
    summary = await execution_service.execute_plan(event_id)
    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status in {
            ActionStatus.SUCCESS.value,
            ActionStatus.EXECUTING.value,
        }
        outboxes = (
            await session.scalars(
                select(orm.DispositionOutbox).where(orm.DispositionOutbox.event_id == event_id)
            )
        ).all()
        assert len(outboxes) == 1
        assert outboxes[0].intent_kind == "entity_action_submit"
    assert len(summary.jobs) == 1
    assert summary.jobs[0].status is ExecutionJobStatus.RUNNING
    assert summary.jobs[0].provider_name == "mock_xdr"


@pytest.mark.asyncio
async def test_post_verify_action_rejected_by_execute_action(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            tool_name=TERMINAL_DISPOSITION_TOOL,
            activation_condition="after_effect_resolution",
        ),
    )
    with pytest.raises(ValidationError, match="POST_VERIFY"):
        await execution_service.execute_action(action.action_id)


@pytest.mark.asyncio
async def test_resolve_unknown_action(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, status=ActionStatus.UNKNOWN),
    )
    resolved = await execution_service.resolve_unknown(
        action.action_id,
        "mark_success",
        principal="admin-1",
        comment="verified offline",
    )
    assert resolved.status is ActionStatus.SUCCESS


@pytest.mark.asyncio
async def test_resolve_unknown_requires_unknown_status(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, status=ActionStatus.APPROVED),
    )
    with pytest.raises(InvalidStateTransitionError):
        await execution_service.resolve_unknown(
            action.action_id,
            "mark_failed",
            principal="admin-1",
            comment="n/a",
        )


@pytest.mark.asyncio
async def test_resolve_unknown_partial_success(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, status=ActionStatus.UNKNOWN),
    )
    resolved = await execution_service.resolve_unknown(
        action.action_id,
        "partial_success",
        principal="admin-1",
        comment="partially effective",
    )
    assert resolved.status is ActionStatus.PARTIAL_SUCCESS


@pytest.mark.asyncio
async def test_claim_rejected_when_writeback_not_ready(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    oid = f"INC-{_sfx()}"
    await _seed_connector_and_source(session_factory, object_id=oid)
    event_id = await _create_event(session_factory, store, object_id=oid)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            disposition_source_ref=_locator(object_id=oid),
            writeback_readiness=WritebackReadiness.CONNECTOR_UNAVAILABLE,
        ),
    )
    with pytest.raises(ValidationError, match="writeback readiness blocks"):
        await execution_service.execute_action(action.action_id)


@pytest.mark.asyncio
async def test_direct_tool_enqueue_execution_result_record(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    oid = SCENARIO_INCIDENT_ID
    await _seed_connector_and_source(
        session_factory, object_id=oid, mock_xdr_client=mock_xdr_client
    )
    event_id = await _create_event(session_factory, store, object_id=oid)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
            disposition_source_ref=_locator(object_id=oid),
            target="203.0.113.88",
            parameters={"target_type": "ip", "target": "203.0.113.88"},
        ),
    )
    summary = await execution_service.execute_plan(event_id)
    async with session_factory() as session:
        jobs = (
            await session.scalars(
                select(orm.ActionExecutionJob).where(
                    orm.ActionExecutionJob.action_id == action.action_id
                )
            )
        ).all()
        outboxes = (
            await session.scalars(
                select(orm.DispositionOutbox).where(orm.DispositionOutbox.event_id == event_id)
            )
        ).all()
    assert jobs
    assert any(o.intent_kind == "execution_result_record" for o in outboxes)
    assert summary.writeback_ids


@pytest.mark.asyncio
async def test_concurrent_claim_single_winner(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    oid = f"INC-{_sfx()}"
    await _seed_connector_and_source(session_factory, object_id=oid)
    event_id = await _create_event(session_factory, store, object_id=oid)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            disposition_source_ref=_locator(object_id=oid),
        ),
    )
    results = await asyncio.gather(
        execution_service.execute_action(action.action_id),
        execution_service.execute_action(action.action_id),
        return_exceptions=True,
    )
    successes = [r for r in results if not isinstance(r, BaseException)]
    failures = [r for r in results if isinstance(r, BaseException)]
    assert len(successes) == 1
    assert len(failures) == 1


@pytest.mark.asyncio
async def test_execute_plan_partial_failure_others_succeed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    execution_service: ActionExecutionService,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oid = SCENARIO_INCIDENT_ID
    await _seed_connector_and_source(
        session_factory, object_id=oid, mock_xdr_client=mock_xdr_client
    )
    event_id = await _create_event(session_factory, store, object_id=oid)
    action_ok = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            disposition_source_ref=_locator(object_id=oid),
        ),
    )
    action_fail = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            disposition_source_ref=_locator(object_id=oid),
        ),
    )
    original = execution_service._execute_xdr_managed
    calls: list[str] = []

    async def _flaky_execute(action: Action, *, operator: str) -> None:
        calls.append(action.action_id)
        if action.action_id == action_fail.action_id:
            raise ValidationError(
                "injected execution failure",
                details={"action_id": action.action_id},
            )
        await original(action, operator=operator)

    monkeypatch.setattr(execution_service, "_execute_xdr_managed", _flaky_execute)
    summary = await execution_service.execute_plan(event_id)
    assert len(calls) == 2
    assert summary.action_counts.get(ActionStatus.FAILED.value, 0) == 1
    assert summary.action_counts.get(ActionStatus.SUCCESS.value, 0) == 1
    async with session_factory() as session:
        ok_row = await session.get(orm.Action, action_ok.action_id)
        fail_row = await session.get(orm.Action, action_fail.action_id)
        assert ok_row is not None and ok_row.status == ActionStatus.SUCCESS.value
        assert fail_row is not None and fail_row.status == ActionStatus.FAILED.value


async def _insert_stale_executing_with_job(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    lease_expires_at: datetime,
    attempt: int = 1,
    job_status: ExecutionJobStatus = ExecutionJobStatus.RUNNING,
) -> tuple[str, str]:
    action_id = f"act-{_sfx()}"
    job_id = f"job-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_tool_provider",
                    idempotency_key=f"idem-{action_id}",
                    status=job_status.value,
                    claimed_by="worker-stale",
                    lease_expires_at=lease_expires_at,
                    attempt=attempt,
                )
            )
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level=ActionLevel.L2.value,
                    execution_owner=ExecutionOwner.DIRECT_TOOL.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.EXECUTING.value,
                    target_type="ip",
                    target="203.0.113.88",
                    parameters={"target_type": "ip", "target": "203.0.113.88"},
                    writeback_required=False,
                    writeback_applicable=False,
                    writeback_readiness=WritebackReadiness.READY.value,
                    execution_job_id=job_id,
                    idempotency_key=f"idem-{action_id}",
                )
            )
    return action_id, job_id


@pytest.mark.asyncio
async def test_stale_running_job_reclaimed_and_action_returns_to_approved(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(session_factory, store, object_id=f"INC-{_sfx()}")
    expired = datetime.now(UTC) - timedelta(seconds=30)
    action_id, job_id = await _insert_stale_executing_with_job(
        session_factory,
        event_id=event_id,
        lease_expires_at=expired,
        attempt=1,
    )

    reconciled = await execution_service.reconcile_stale_executions(limit=10)
    assert reconciled >= 1

    async with session_factory() as session:
        action_row = await session.get(orm.Action, action_id)
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert action_row is not None
        assert job_row is not None
        assert action_row.status == ActionStatus.APPROVED.value
        assert action_row.execution_job_id is None
        assert job_row.status == ExecutionJobStatus.QUEUED.value
        assert job_row.lease_expires_at is None
        assert job_row.claimed_by is None
        assert job_row.attempt == 2


@pytest.mark.asyncio
async def test_active_execution_lease_not_reclaimed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(session_factory, store, object_id=f"INC-{_sfx()}")
    future = datetime.now(UTC) + timedelta(seconds=300)
    action_id, job_id = await _insert_stale_executing_with_job(
        session_factory,
        event_id=event_id,
        lease_expires_at=future,
        attempt=1,
    )

    reconciled = await execution_service.reconcile_stale_executions(limit=10)
    assert reconciled == 0

    async with session_factory() as session:
        action_row = await session.get(orm.Action, action_id)
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert action_row is not None
        assert job_row is not None
        assert action_row.status == ActionStatus.EXECUTING.value
        assert job_row.status == ExecutionJobStatus.RUNNING.value
        assert job_row.lease_expires_at == future


@pytest.mark.asyncio
async def test_max_attempts_fails_stale_job_and_executing_action(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import Settings, get_settings

    monkeypatch.setattr(
        get_settings,
        "cache_clear",
        lambda: None,
    )
    settings = Settings.model_validate(
        {
            **get_settings().model_dump(),
            "ACTION_EXECUTION_MAX_ATTEMPTS": 3,
        }
    )
    monkeypatch.setattr(
        "app.services.action_execution_service.get_settings",
        lambda: settings,
    )

    event_id = await _create_event(session_factory, store, object_id=f"INC-{_sfx()}")
    expired = datetime.now(UTC) - timedelta(seconds=30)
    action_id, job_id = await _insert_stale_executing_with_job(
        session_factory,
        event_id=event_id,
        lease_expires_at=expired,
        attempt=3,
    )

    reconciled = await execution_service.reconcile_stale_executions(limit=10)
    assert reconciled >= 1

    async with session_factory() as session:
        action_row = await session.get(orm.Action, action_id)
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert action_row is not None
        assert job_row is not None
        assert action_row.status == ActionStatus.FAILED.value
        assert job_row.status == ExecutionJobStatus.TIMED_OUT.value


@pytest.mark.asyncio
async def test_reclaimed_action_can_be_executed_again(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    oid = f"INC-{_sfx()}"
    await _seed_connector_and_source(
        session_factory, object_id=oid, mock_xdr_client=mock_xdr_client
    )
    event_id = await _create_event(session_factory, store, object_id=oid)
    expired = datetime.now(UTC) - timedelta(seconds=30)
    action_id, _job_id = await _insert_stale_executing_with_job(
        session_factory,
        event_id=event_id,
        lease_expires_at=expired,
        attempt=1,
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id)
            assert row is not None
            row.disposition_source_ref = _locator(object_id=oid).model_dump(mode="json")
            row.writeback_applicable = True
            row.writeback_required = True
            row.execution_owner = ExecutionOwner.XDR_MANAGED.value

    await execution_service.reconcile_stale_executions(limit=10)

    async with session_factory() as session:
        outbox_count_before = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )

    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.status == ActionStatus.APPROVED.value

    # ISSUE-220: re-executing after reclaim must attach the existing job (same
    # idempotency_key) instead of inserting a duplicate job / re-enqueuing a
    # command.  The reclaimed job is non-terminal, so the action moves to
    # UNKNOWN for human confirmation — never a blind second side-effect.
    await execution_service.execute_action(action_id)
    await execution_service._sync.process_ready_outboxes(limit=5)
    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.status == ActionStatus.UNKNOWN.value
        assert row.execution_job_id == _job_id
        jobs = (
            await session.scalars(
                select(orm.ActionExecutionJob).where(orm.ActionExecutionJob.action_id == action_id)
            )
        ).all()
        assert len(jobs) == 1
        assert jobs[0].job_id == _job_id
        outbox_count_after = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
        assert int(outbox_count_after or 0) == int(outbox_count_before or 0)


@pytest.mark.asyncio
async def test_concurrent_execute_same_idempotency_key_single_job(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-220: concurrent claim+insert for the same idempotency_key leaves
    one authoritative job and at most one Provider invocation."""
    from types import SimpleNamespace

    shared_idem = f"idem-shared-{_sfx()}"
    event_id = await _create_event(session_factory, store, object_id=f"INC-{_sfx()}")
    action_a = _action_model(
        event_id=event_id,
        action_id=f"act-a-{_sfx()}",
        action_fingerprint=f"fp-a-{_sfx()}",
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        writeback_required=False,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_source_ref=None,
        idempotency_key=shared_idem,
    )
    action_b = _action_model(
        event_id=event_id,
        action_id=f"act-b-{_sfx()}",
        action_fingerprint=f"fp-b-{_sfx()}",
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        writeback_required=False,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_source_ref=None,
        idempotency_key=shared_idem,
    )
    await _insert_action(session_factory, event_id, action_a)
    await _insert_action(session_factory, event_id, action_b)

    provider_calls = {"n": 0}

    class _CountingExecutor:
        async def call(self, *args: object, **kwargs: object) -> SimpleNamespace:
            provider_calls["n"] += 1
            return SimpleNamespace(status="success")

    monkeypatch.setattr(execution_service, "_executor", _CountingExecutor())

    results = await asyncio.gather(
        execution_service.execute_action(action_a.action_id),
        execution_service.execute_action(action_b.action_id),
        return_exceptions=True,
    )
    assert not any(isinstance(r, BaseException) for r in results), results
    assert provider_calls["n"] == 1

    async with session_factory() as session:
        jobs = (
            await session.scalars(
                select(orm.ActionExecutionJob).where(
                    orm.ActionExecutionJob.idempotency_key == shared_idem
                )
            )
        ).all()
        assert len(jobs) == 1


@pytest.mark.asyncio
async def test_max_attempts_fails_stale_queued_job(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import Settings, get_settings

    monkeypatch.setattr(get_settings, "cache_clear", lambda: None)
    settings = Settings.model_validate(
        {**get_settings().model_dump(), "ACTION_EXECUTION_MAX_ATTEMPTS": 3}
    )
    monkeypatch.setattr("app.services.action_execution_service.get_settings", lambda: settings)

    event_id = await _create_event(session_factory, store, object_id=f"INC-{_sfx()}")
    expired = datetime.now(UTC) - timedelta(seconds=30)
    action_id, job_id = await _insert_stale_executing_with_job(
        session_factory,
        event_id=event_id,
        lease_expires_at=expired,
        attempt=3,
        job_status=ExecutionJobStatus.QUEUED,
    )

    reconciled = await execution_service.reconcile_stale_executions(limit=10)
    assert reconciled >= 1

    async with session_factory() as session:
        action_row = await session.get(orm.Action, action_id)
        job_row = await session.get(orm.ActionExecutionJob, job_id)
        assert action_row is not None
        assert job_row is not None
        assert action_row.status == ActionStatus.FAILED.value
        assert action_row.execution_job_id is None
        assert job_row.status == ExecutionJobStatus.TIMED_OUT.value


@pytest.mark.asyncio
async def test_reconcile_skips_verification_executing(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    event_id = await _create_event(session_factory, store, object_id=f"INC-{_sfx()}")
    expired = datetime.now(UTC) - timedelta(seconds=600)
    stale_action_id, _ = await _insert_stale_executing_with_job(
        session_factory,
        event_id=event_id,
        lease_expires_at=expired,
        attempt=1,
    )
    verification_action_id = f"act-verify-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=verification_action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{verification_action_id}",
                    action_category=ActionCategory.VERIFICATION.value,
                    action_name="verify containment",
                    tool_name="verify_containment",
                    action_level=ActionLevel.L0.value,
                    execution_owner=ExecutionOwner.DIRECT_TOOL.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.EXECUTING.value,
                    target_type="ip",
                    target="203.0.113.1",
                    parameters={},
                    writeback_required=False,
                    writeback_applicable=False,
                    writeback_readiness=WritebackReadiness.READY.value,
                    updated_at=expired,
                )
            )

    reconciled = await execution_service.reconcile_stale_executions(limit=10)
    assert reconciled >= 1

    async with session_factory() as session:
        stale_row = await session.get(orm.Action, stale_action_id)
        verify_row = await session.get(orm.Action, verification_action_id)
        assert stale_row is not None and stale_row.status == ActionStatus.APPROVED.value
        assert verify_row is not None and verify_row.status == ActionStatus.EXECUTING.value


@pytest.mark.asyncio
async def test_xdr_executing_with_active_outbox_not_reclaimed(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    from app.models.enums import OutboxDeliveryStatus

    oid = f"INC-{_sfx()}"
    await _seed_connector_and_source(
        session_factory, object_id=oid, mock_xdr_client=mock_xdr_client
    )
    event_id = await _create_event(session_factory, store, object_id=oid)
    action_id = f"act-xdr-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            source = await session.scalar(
                select(orm.SourceObject).where(orm.SourceObject.source_object_id == oid)
            )
            assert source is not None
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level=ActionLevel.L2.value,
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.EXECUTING.value,
                    target_type="ip",
                    target="203.0.113.88",
                    parameters={"target_type": "ip", "target": "203.0.113.88"},
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    disposition_source_ref=_locator(object_id=oid).model_dump(mode="json"),
                    updated_at=datetime.now(UTC) - timedelta(seconds=600),
                )
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{_sfx()}",
                    writeback_id=f"wbk-{_sfx()}",
                    disposition_id=f"disp-{_sfx()}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=source.source_record_id,
                    source_locator_hash="hash",
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="default",
                    idempotency_key=f"idem-{action_id}",
                    command_payload={"action_id": action_id},
                    command_payload_sha256="deadbeef",
                    delivery_status=OutboxDeliveryStatus.READY.value,
                )
            )

    reconciled = await execution_service.reconcile_stale_executions(limit=10)
    assert reconciled == 0

    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.status == ActionStatus.EXECUTING.value


@pytest.mark.asyncio
async def test_direct_tool_reclaimed_reuses_job_without_reinvoking_provider(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-220: after reclaim, re-executing a DIRECT_TOOL action with the
    same idempotency_key must attach the existing job and never invoke the
    Provider a second time (countable side-effect)."""
    from types import SimpleNamespace

    event_id = await _create_event(session_factory, store, object_id=f"INC-{_sfx()}")
    expired = datetime.now(UTC) - timedelta(seconds=30)
    action_id, job_id = await _insert_stale_executing_with_job(
        session_factory,
        event_id=event_id,
        lease_expires_at=expired,
        attempt=1,
    )
    await execution_service.reconcile_stale_executions(limit=10)

    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.status == ActionStatus.APPROVED.value

    provider_calls = {"n": 0}

    class _CountingExecutor:
        async def call(self, *args: object, **kwargs: object) -> SimpleNamespace:
            provider_calls["n"] += 1
            return SimpleNamespace(status="success")

    monkeypatch.setattr(execution_service, "_executor", _CountingExecutor())

    await execution_service.execute_action(action_id)

    # The Provider must not be re-invoked; the original job is attached and
    # the action requires human resolution (non-terminal reclaimed job).
    assert provider_calls["n"] == 0
    async with session_factory() as session:
        jobs = (
            await session.scalars(
                select(orm.ActionExecutionJob).where(
                    orm.ActionExecutionJob.idempotency_key == f"idem-{action_id}"
                )
            )
        ).all()
        assert len(jobs) == 1
        assert jobs[0].job_id == job_id
        row = await session.get(orm.Action, action_id)
        assert row is not None
        assert row.execution_job_id == job_id
        assert row.status == ActionStatus.UNKNOWN.value


@pytest.mark.asyncio
async def test_xdr_managed_replan_enqueue_uses_action_plan_revision(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    """ISSUE-231: after replan (plan_revision>=2) an XDR_MANAGED entity
    submission must enqueue with closure_cycle = action.plan_revision (not the
    hardcoded 1), so the guard's approved_action_ids resolution (by
    plan_revision) finds the rev-N approved set instead of failing closed."""
    oid = f"INC-{_sfx()}"
    await _seed_connector_and_source(
        session_factory, object_id=oid, mock_xdr_client=mock_xdr_client
    )
    event_id = await _create_event(session_factory, store, object_id=oid)
    await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            disposition_source_ref=_locator(object_id=oid),
            plan_revision=2,
        ),
    )

    await execution_service.execute_plan(event_id)

    async with session_factory() as session:
        outboxes = (
            await session.scalars(
                select(orm.DispositionOutbox).where(orm.DispositionOutbox.event_id == event_id)
            )
        ).all()
        assert len(outboxes) == 1, "replan entity submission must enqueue (not fail closed)"
        assert outboxes[0].intent_kind == "entity_action_submit"
        assert outboxes[0].closure_cycle == 2


@pytest.mark.asyncio
async def test_direct_tool_replan_execution_result_enqueues_with_snapshot(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    execution_service: ActionExecutionService,
    cleanup: None,
) -> None:
    """ISSUE-231/SUS-304: a DIRECT_TOOL rev=2 execution-result writeback is
    enqueued only after the action reached SUCCESS — it must use
    closure_cycle=2 and the approved snapshot resolved while the action was
    still EXECUTING (resolve by status would find an empty set)."""
    oid = f"INC-replan-{_sfx()}"
    target_ip = f"203.0.113.{int(uuid.uuid4().hex[:2], 16) % 200 + 1}"
    await _seed_connector_and_source(session_factory, object_id=oid)
    event_id = await _create_event(session_factory, store, object_id=oid)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
            disposition_source_ref=_locator(object_id=oid),
            target=target_ip,
            parameters={"target_type": "ip", "target": target_ip},
            plan_revision=2,
        ),
    )

    summary = await execution_service.execute_plan(event_id)

    async with session_factory() as session:
        action_row = await session.get(orm.Action, action.action_id)
        assert action_row is not None
        assert action_row.status == ActionStatus.SUCCESS.value
        outboxes = (
            await session.scalars(
                select(orm.DispositionOutbox).where(orm.DispositionOutbox.event_id == event_id)
            )
        ).all()
        assert len(outboxes) == 1, (
            "execution-result writeback after SUCCESS must enqueue via the "
            "approved snapshot (SUS-304), not fail closed"
        )
        assert outboxes[0].intent_kind == "execution_result_record"
        assert outboxes[0].closure_cycle == 2
        assert outboxes[0].action_id == action.action_id
    assert summary.writeback_ids


async def _seed_manual_hold(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    generation: int = 1,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "manual_hold_generation",
                generation,
            )
            await append_context_journal_in_session(
                session,
                event_id,
                "manual_hold_detail",
                {
                    "reason": "verify_manual_resolution",
                    "pending_action_ids": [],
                    "pending_writeback_ids": [],
                    "checkpoint_version": generation,
                },
            )
            await append_context_journal_in_session(
                session,
                event_id,
                "execution_substate",
                ExecutionSubstate.MANUAL_RESOLUTION.value,
            )


@pytest.mark.asyncio
async def test_resolve_unknown_creates_graph_resume_intent_on_manual_hold(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    disposition_sync: DispositionSyncService,
    tool_executor: ToolExecutor,
    state_machine: StateMachineService,
    cleanup: None,
) -> None:
    resume = AsyncMock()
    manual_resolution = ManualResolutionService(
        session_factory,
        resume_investigation=resume,
    )
    execution_service = ActionExecutionService(
        session_factory,
        disposition_sync=disposition_sync,
        tool_executor=tool_executor,
        state_machine=state_machine,
        context_store=store,
        manual_resolution=manual_resolution,
    )
    event_id = await _create_event(session_factory, store)
    await _seed_manual_hold(session_factory, event_id)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, status=ActionStatus.UNKNOWN),
    )
    await execution_service.resolve_unknown(
        action.action_id,
        "mark_success",
        principal="admin-1",
        comment="verified offline",
    )
    async with session_factory() as session:
        intent = await session.scalar(
            select(orm.GraphResumeIntent).where(orm.GraphResumeIntent.event_id == event_id)
        )
        assert intent is not None
        assert intent.resolution_kind == "action"
        assert intent.subject_id == action.action_id
        assert intent.hold_generation == 1
        assert intent.status == InvestigationIntentStatus.PENDING.value
    await manual_resolution.dispatch_sync_batch(limit=5)
    resume.assert_awaited_once_with(event_id)
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.GraphResumeIntent).where(orm.GraphResumeIntent.event_id == event_id)
        )
        assert row is not None
        assert row.status == InvestigationIntentStatus.TERMINAL.value


@pytest.mark.asyncio
async def test_resolve_unknown_resume_intent_idempotent_by_operation(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    cleanup: None,
) -> None:
    manual_resolution = ManualResolutionService(session_factory, resume_investigation=AsyncMock())
    event_id = await _create_event(session_factory, store)
    await _seed_manual_hold(session_factory, event_id)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, status=ActionStatus.UNKNOWN),
    )
    first = await manual_resolution.create_resume_intent_after_resolution(
        event_id=event_id,
        resolution_kind="action",
        subject_id=action.action_id,
        operation_id="op-fixed-1",
        resolution="mark_success",
        principal="admin-1",
        comment="same",
    )
    assert first is not None
    assert first.idempotent_replay is False
    second = await manual_resolution.create_resume_intent_after_resolution(
        event_id=event_id,
        resolution_kind="action",
        subject_id=action.action_id,
        operation_id="op-fixed-1",
        resolution="mark_success",
        principal="admin-1",
        comment="same",
    )
    assert second is not None
    assert second.idempotent_replay is True
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count()).select_from(orm.GraphResumeIntent).where(
                orm.GraphResumeIntent.event_id == event_id
            )
        )
        assert count == 1
