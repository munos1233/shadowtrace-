"""ActionExecutionJob target-row persistence tests (ISSUE-272)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.db import models as orm
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
    FinalVerdict,
    Severity,
    SourceObjectKind,
    TargetExecutionStatus,
    WritebackReadiness,
)
from app.models.source import SourceReference
from tests.test_support.db_isolation import truncate_business_tables
from app.models.execution import ActionExecutionJob, TargetExecutionResult
from app.providers.tools.mock_provider import MockToolProvider, MockToolProviderConfig
from app.services.action_execution_service import DbExecutionJobStore
from app.services.context_service import EventContextStore, event_summary_from_security_event
from app.services.execution_job_persistence import load_target_results_for_job

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


def _source_ref() -> dict[str, object]:
    sfx = _sfx()
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-job-persist",
        source_object_id=f"INC-{sfx}",
        ingested_at=datetime.now(UTC),
    ).model_dump(mode="json")


def _job(**overrides: object) -> ActionExecutionJob:
    job_id = f"job-{_sfx()}"
    base = {
        "job_id": job_id,
        "event_id": f"evt-{_sfx()}",
        "action_id": f"act-{_sfx()}",
        "provider_name": "mock_tool_provider",
        "idempotency_key": f"idem-{job_id}",
        "status": ExecutionJobStatus.RUNNING,
        "attempt": 0,
    }
    base.update(overrides)
    return ActionExecutionJob.model_validate(base)


def _target(
    canonical: str,
    *,
    status: TargetExecutionStatus = TargetExecutionStatus.SUCCESS,
    code: str | None = "applied",
) -> TargetExecutionResult:
    return TargetExecutionResult(
        canonical_target=canonical,
        status=status,
        code=code,
        message=code,
        raw_result={"code": code} if code else {},
    )


@pytest.fixture(scope="module")
def migrated() -> None:
    import asyncio

    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)

    async def _probe() -> None:
        try:
            async with engine.connect() as conn:
                await conn.execute(select(1))
        except Exception as exc:  # noqa: BLE001
            await engine.dispose()
            pytest.skip(f"PostgreSQL not reachable: {exc}")

    asyncio.run(_probe())
    command.upgrade(_alembic_config(), "head")
    asyncio.run(engine.dispose())


@pytest_asyncio.fixture
async def session_factory(migrated: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
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
async def job_store(
    session_factory: async_sessionmaker[AsyncSession],
) -> DbExecutionJobStore:
    return DbExecutionJobStore(session_factory)


@pytest_asyncio.fixture
async def cleanup(session_factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[None]:
    await truncate_business_tables(session_factory)
    yield
    await truncate_business_tables(session_factory)


async def _seed_job_fk_parents(
    session: AsyncSession,
    job: ActionExecutionJob,
) -> None:
    """Seed security_event + action before action_execution_job (FK order)."""
    now = datetime.now(UTC)
    ref = _source_ref()
    session.add(
        orm.SecurityEvent(
            event_id=job.event_id,
            event_type=EventType.OTHER.value,
            title="execution job persistence fixture",
            description="ISSUE-364 FK seed",
            status=EventStatus.EXECUTING_RESPONSE.value,
            severity=Severity.MEDIUM.value,
            risk_score=50,
            confidence=0.8,
            final_verdict=FinalVerdict.NONE.value,
            creation_source_ref=ref,
            source_reference_snapshots=[ref],
            disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
            occurred_at=now,
        )
    )
    await session.flush()
    session.add(
        orm.Action(
            action_id=job.action_id,
            event_id=job.event_id,
            plan_revision=1,
            action_fingerprint=f"fp-{job.action_id}",
            action_category=ActionCategory.RESPONSE.value,
            action_name="block ip",
            tool_name="block_ip",
            action_level=ActionLevel.L2.value,
            execution_owner=ExecutionOwner.DIRECT_TOOL.value,
            execution_phase=ActionExecutionPhase.IMMEDIATE.value,
            status=ActionStatus.APPROVED.value,
            target_type="ip",
            target="203.0.113.1",
            parameters={},
            writeback_required=False,
            writeback_applicable=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED.value,
            idempotency_key=f"idem-{job.action_id}",
        )
    )
    await session.flush()


async def _insert_job_row(
    session_factory: async_sessionmaker[AsyncSession],
    job: ActionExecutionJob,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            await _seed_job_fk_parents(session, job)
            session.add(
                orm.ActionExecutionJob(
                    job_id=job.job_id,
                    event_id=job.event_id,
                    action_id=job.action_id,
                    provider_name=job.provider_name,
                    idempotency_key=job.idempotency_key,
                    status=job.status.value,
                    attempt=job.attempt,
                )
            )


@pytest.mark.asyncio
async def test_cas_persists_target_results_and_round_trips(
    session_factory: async_sessionmaker[AsyncSession],
    job_store: DbExecutionJobStore,
    cleanup: None,
) -> None:
    job = _job(
        target_results=[
            _target("host:host-a"),
            _target("host:host-b", status=TargetExecutionStatus.FAILED, code="device_offline"),
        ]
    )
    await _insert_job_row(session_factory, job)

    updated = job.model_copy(
        update={
            "status": ExecutionJobStatus.PARTIAL_SUCCESS,
            "target_results": job.target_results,
        }
    )
    assert await job_store.cas_update_job(
        job.job_id,
        updated,
        expected_status=ExecutionJobStatus.RUNNING,
    )

    loaded = await job_store.get_job(job.job_id)
    assert loaded is not None
    assert loaded.status is ExecutionJobStatus.PARTIAL_SUCCESS
    assert [item.canonical_target for item in loaded.target_results] == [
        "host:host-a",
        "host:host-b",
    ]
    assert loaded.target_results[1].status is TargetExecutionStatus.FAILED

    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.ActionTargetResult).where(orm.ActionTargetResult.job_id == job.job_id)
            )
        ).all()
        assert len(rows) == 2
        assert sorted(row.canonical_target for row in rows) == ["host:host-a", "host:host-b"]


@pytest.mark.asyncio
async def test_cas_target_conflict_fails_closed_and_leaves_job_unchanged(
    session_factory: async_sessionmaker[AsyncSession],
    job_store: DbExecutionJobStore,
    cleanup: None,
) -> None:
    job = _job(target_results=[_target("ip:203.0.113.1")])
    await _insert_job_row(session_factory, job)
    first = job.model_copy(
        update={
            "status": ExecutionJobStatus.SUCCESS,
            "target_results": job.target_results,
        }
    )
    assert await job_store.cas_update_job(
        job.job_id,
        first,
        expected_status=ExecutionJobStatus.RUNNING,
    )

    conflicting = job.model_copy(
        update={
            "status": ExecutionJobStatus.PARTIAL_SUCCESS,
            "target_results": [
                _target(
                    "ip:203.0.113.1",
                    status=TargetExecutionStatus.FAILED,
                    code="device_offline",
                )
            ],
        }
    )
    assert not await job_store.cas_update_job(
        job.job_id,
        conflicting,
        expected_status=ExecutionJobStatus.SUCCESS,
    )

    loaded = await job_store.get_job(job.job_id)
    assert loaded is not None
    assert loaded.status is ExecutionJobStatus.SUCCESS
    assert len(loaded.target_results) == 1
    assert loaded.target_results[0].status is TargetExecutionStatus.SUCCESS


@pytest.mark.asyncio
async def test_cas_idempotent_replay_does_not_duplicate_targets(
    session_factory: async_sessionmaker[AsyncSession],
    job_store: DbExecutionJobStore,
    cleanup: None,
) -> None:
    targets = [_target("ip:203.0.113.9"), _target("ip:203.0.113.10")]
    job = _job(target_results=targets)
    await _insert_job_row(session_factory, job)
    terminal = job.model_copy(
        update={"status": ExecutionJobStatus.PARTIAL_SUCCESS, "target_results": targets}
    )
    assert await job_store.cas_update_job(
        job.job_id,
        terminal,
        expected_status=ExecutionJobStatus.RUNNING,
    )
    replay = terminal.model_copy()
    assert await job_store.cas_update_job(
        job.job_id,
        replay,
        expected_status=ExecutionJobStatus.PARTIAL_SUCCESS,
    )

    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.ActionTargetResult).where(orm.ActionTargetResult.job_id == job.job_id)
            )
        ).all()
        assert len(rows) == 2


@pytest.mark.asyncio
async def test_cas_failure_rolls_back_target_rows(
    session_factory: async_sessionmaker[AsyncSession],
    job_store: DbExecutionJobStore,
    cleanup: None,
) -> None:
    job = _job()
    await _insert_job_row(session_factory, job)
    updated = job.model_copy(
        update={
            "status": ExecutionJobStatus.SUCCESS,
            "target_results": [_target("ip:203.0.113.55")],
        }
    )
    assert not await job_store.cas_update_job(
        job.job_id,
        updated,
        expected_status=ExecutionJobStatus.QUEUED,
    )

    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(orm.ActionTargetResult).where(orm.ActionTargetResult.job_id == job.job_id)
            )
        ).all()
        assert rows == []
        row = await session.get(orm.ActionExecutionJob, job.job_id)
        assert row is not None
        assert row.status == ExecutionJobStatus.RUNNING.value


@pytest.mark.asyncio
async def test_duplicate_targets_in_payload_fail_closed(
    session_factory: async_sessionmaker[AsyncSession],
    job_store: DbExecutionJobStore,
    cleanup: None,
) -> None:
    job = _job()
    await _insert_job_row(session_factory, job)
    updated = job.model_copy(
        update={
            "status": ExecutionJobStatus.SUCCESS,
            "target_results": [
                _target("ip:203.0.113.1"),
                _target("ip:203.0.113.1", code="other"),
            ],
        }
    )
    assert not await job_store.cas_update_job(
        job.job_id,
        updated,
        expected_status=ExecutionJobStatus.RUNNING,
    )


@pytest.mark.asyncio
async def test_attempt_scoped_target_rows(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
) -> None:
    job = _job(attempt=1)
    await _insert_job_row(session_factory, job)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.ActionTargetResult(
                    job_id=job.job_id,
                    attempt=0,
                    canonical_target="ip:203.0.113.1",
                    status=TargetExecutionStatus.SUCCESS.value,
                    raw_result={},
                )
            )
            session.add(
                orm.ActionTargetResult(
                    job_id=job.job_id,
                    attempt=1,
                    canonical_target="ip:203.0.113.1",
                    status=TargetExecutionStatus.FAILED.value,
                    code="device_offline",
                    raw_result={"code": "device_offline"},
                )
            )

    async with session_factory() as session:
        attempt0 = await load_target_results_for_job(session, job.job_id, 0)
        attempt1 = await load_target_results_for_job(session, job.job_id, 1)
    assert attempt0[0].status is TargetExecutionStatus.SUCCESS
    assert attempt1[0].status is TargetExecutionStatus.FAILED


@pytest.mark.asyncio
async def test_direct_tool_partial_success_db_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.providers.tools.mock_provider as mock_provider_module
    from app.adapters.registry import DispositionAdapterRegistry
    from app.core.event_bus import EventBus
    from app.core.guardrails import OutboundDispositionGuard
    from app.core.redis_client import RedisClient
    from app.models.action import Action
    from app.models.disposition import SourceObjectLocator
    from app.models.enums import DispositionPolicy, SourceObjectKind
    from app.models.source import SourceReference
    from app.services.action_execution_service import ActionExecutionService
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.disposition_sync_service import DispositionSyncService
    from app.services.event_audit_log_service import EventAuditLogService
    from app.services.state_machine_service import StateMachineService
    from app.tools.executor import ToolExecutor
    from app.tools.registry import ToolRegistry

    if not await RedisClient(url=REDIS_URL).ping():
        pytest.skip("Redis not reachable")

    provider = MockToolProvider(
        config=MockToolProviderConfig(offline_targets={"host-b"}),
    )
    mock_provider_module._default_provider = provider

    redis = RedisClient(url=REDIS_URL)
    store = EventContextStore(redis, session_factory)
    registry = ToolRegistry()
    await registry.auto_discover_for_mode(tool_mode="mock")
    executor = ToolExecutor(registry=registry)
    disposition_sync = DispositionSyncService(
        session_factory,
        context_store=store,
        adapter_registry=DispositionAdapterRegistry(),
        outbound_guard=OutboundDispositionGuard(),
    )
    state_machine = StateMachineService(
        session_factory,
        store,
        event_bus=EventBus(redis),
        audit_log=EventAuditLogService(session_factory),
        degraded_flags=DegradedFlagService(store, session_factory),
    )
    execution_service = ActionExecutionService(
        session_factory,
        disposition_sync=disposition_sync,
        tool_executor=executor,
        state_machine=state_machine,
        context_store=store,
    )

    sfx = _sfx()
    event_id = f"evt-partial-{sfx}"
    action_id = f"act-partial-{sfx}"
    locator = SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id=f"INC-{sfx}",
    )
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_object_id=f"INC-{sfx}",
        ingested_at=datetime.now(UTC),
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.OTHER.value,
                    title="partial-success",
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

    action = Action.model_validate(
        {
            "action_id": action_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": f"fp-{sfx}",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "isolate hosts",
            "tool_name": "isolate_host",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.DIRECT_TOOL,
            "status": ActionStatus.APPROVED,
            "target_type": "host",
            "target": "host-a",
            "parameters": {
                "target_type": "host",
                "target": "host-a",
                "parameters": {"targets": ["host-a", "host-b"]},
            },
            "writeback_required": False,
            "writeback_applicable": False,
            "writeback_readiness": WritebackReadiness.NOT_REQUIRED,
            "idempotency_key": f"idem-{action_id}",
            "execution_phase": ActionExecutionPhase.IMMEDIATE,
        }
    )
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
                    status=action.status.value,
                    execution_owner=action.execution_owner.value,
                    target_type=action.target_type,
                    target=action.target,
                    parameters=action.parameters,
                    writeback_required=action.writeback_required,
                    writeback_applicable=action.writeback_applicable,
                    writeback_readiness=WritebackReadiness.NOT_REQUIRED.value,
                    idempotency_key=action.idempotency_key,
                )
            )

    summary = await execution_service.execute_plan(event_id)
    assert summary.action_counts.get(ActionStatus.PARTIAL_SUCCESS.value, 0) == 1

    async with session_factory() as session:
        job_row = (
            await session.scalars(
                select(orm.ActionExecutionJob).where(orm.ActionExecutionJob.action_id == action_id)
            )
        ).one()
        target_rows = (
            await session.scalars(
                select(orm.ActionTargetResult).where(
                    orm.ActionTargetResult.job_id == job_row.job_id
                )
            )
        ).all()
        assert len(target_rows) == 2

    reloaded_store = DbExecutionJobStore(session_factory)
    reloaded = await reloaded_store.get_job(job_row.job_id)
    assert reloaded is not None
    assert reloaded.status is ExecutionJobStatus.PARTIAL_SUCCESS
    assert [item.canonical_target for item in reloaded.target_results] == [
        "host:host-a",
        "host:host-b",
    ]
    assert reloaded.target_results[1].code == "device_offline"

    summary_job = next(item for item in summary.jobs if item.action_id == action_id)
    assert summary_job.target_results[1].status is TargetExecutionStatus.FAILED

    await redis.aclose()
