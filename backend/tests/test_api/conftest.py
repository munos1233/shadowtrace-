"""Fixtures for API integration tests (ISSUE-038).

Provides real PostgreSQL + Redis-backed services for the event lifecycle tests.
All fixtures are opt-in — only tests that explicitly request them pull in DB/Redis.

Usage::

    pytestmark = [pytest.mark.integration]

    @pytest.mark.asyncio
    async def test_something(session_factory, event_service): ...
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.redis_client import RedisClient
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="session")
def migrated_database() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
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
        pytest.fail("Redis is required for API integration tests")
    yield client
    await client.aclose()


@pytest.fixture
def context_store(
    redis_client: RedisClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> EventContextStore:
    return EventContextStore(redis_client, session_factory)


@pytest.fixture
def degraded_flags(
    context_store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> DegradedFlagService:
    return DegradedFlagService(context_store, session_factory)


@pytest.fixture
def audit_log(
    session_factory: async_sessionmaker[AsyncSession],
) -> EventAuditLogService:
    return EventAuditLogService(session_factory)


@pytest.fixture
def state_machine_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    audit_log: EventAuditLogService,
    degraded_flags: DegradedFlagService,
) -> StateMachineService:
    return StateMachineService(
        session_factory,
        context_store,
        audit_log=audit_log,
        degraded_flags=degraded_flags,
    )


@pytest.fixture
def event_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    degraded_flags: DegradedFlagService,
    state_machine_service: StateMachineService,
) -> EventService:
    return EventService(
        session_factory,
        context_store,
        degraded_flags=degraded_flags,
        state_machine=state_machine_service,
    )
