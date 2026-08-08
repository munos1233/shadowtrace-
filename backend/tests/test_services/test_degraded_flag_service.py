"""DegradedFlagService tests (ISSUE-014)."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.schemas import EventSummary
from app.core.errors import GuardrailViolationError, ValidationError
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import (
    DEGRADED_FLAG_ALLOWLIST,
    DegradedFlagService,
    apply_flag_to_list,
    wire_redis_context_recovery,
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
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(migrated: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
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
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> DegradedFlagService:
    return DegradedFlagService(store, session_factory)


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


async def _seed_ready(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> str:
    event_id = f"evt-20260713-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="insider_threat",
                    title="degraded-flag-test",
                    creation_source_ref={"source_object_id": f"INC-{_sfx()}"},
                )
            )
    await store.init_context(
        event_id,
        EventSummary(
            event_id=event_id,
            event_type=EventType.INSIDER_THREAT,
            title="degraded-flag-test",
            status=EventStatus.NEW,
            severity=Severity.LOW,
            risk_score=1,
            final_verdict=FinalVerdict.NONE,
            writeback_required=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
        ),
    )
    return event_id


def test_apply_flag_to_list_set_and_clear() -> None:
    base = ["other=1"]
    updated = apply_flag_to_list(base, "redis_context_unavailable", True)
    assert "redis_context_unavailable=true" in updated
    assert "other=1" in updated
    cleared = apply_flag_to_list(updated, "redis_context_unavailable", False)
    assert cleared == ["other=1"]


def test_allowlist_contains_p0_flags() -> None:
    assert "redis_context_unavailable" in DEGRADED_FLAG_ALLOWLIST
    assert "disposition_writeback_blocked" in DEGRADED_FLAG_ALLOWLIST
    assert "graph_resume_failed" in DEGRADED_FLAG_ALLOWLIST
    assert "event_type_from_heuristic" in DEGRADED_FLAG_ALLOWLIST
    assert "event_type_from_llm_fallback" in DEGRADED_FLAG_ALLOWLIST


def test_wire_redis_context_recovery_registers_callback() -> None:
    from unittest.mock import MagicMock

    store = MagicMock()
    degraded = MagicMock(spec=DegradedFlagService)
    wire_redis_context_recovery(store, degraded)
    store.set_on_redis_recovery.assert_called_once()
    callback = store.set_on_redis_recovery.call_args[0][0]
    assert callable(callback)


@pytest.mark.asyncio
async def test_set_flag_dual_writes_security_event_and_context(
    degraded: DegradedFlagService,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_ready(session_factory, store)
    result = await degraded.set_flag(
        event_id,
        "redis_context_unavailable",
        True,
        writer="WorkingMemory",
    )
    assert "redis_context_unavailable=true" in result

    async with session_factory() as session:
        se = await session.get(orm.SecurityEvent, event_id)
        assert se is not None
        assert se.degraded_flags == result

    ctx_flags = await store.get(event_id, "degraded_flags")
    assert ctx_flags == result


@pytest.mark.asyncio
async def test_set_flag_rejects_untrusted_caller(
    degraded: DegradedFlagService,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_ready(session_factory, store)
    with pytest.raises(GuardrailViolationError):
        await degraded.set_flag(
            event_id,
            "redis_context_unavailable",
            True,
            writer="UntrustedFixtureWriter",
        )


@pytest.mark.asyncio
async def test_set_flag_rejects_unknown_flag(
    degraded: DegradedFlagService,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_ready(session_factory, store)
    with pytest.raises(ValidationError):
        await degraded.set_flag(
            event_id,
            "not_a_real_flag",
            True,
            writer="EventService",
        )


@pytest.mark.asyncio
async def test_disposition_writeback_blocked_value(
    degraded: DegradedFlagService,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_ready(session_factory, store)
    result = await degraded.set_flag(
        event_id,
        "disposition_writeback_blocked",
        "capability_unknown",
        writer="EventService",
    )
    assert "disposition_writeback_blocked=capability_unknown" in result
    assert await store.get(event_id, "degraded_flags") == result
