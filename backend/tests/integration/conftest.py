"""Real PostgreSQL/Redis fixtures for the ISSUE-017 quality gate."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from httpx import ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.core.redis_client import RedisClient
from app.data_generators.scenarios import build_scenario, write_scenario_artifacts
from app.db.base import Base
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
BUSINESS_TABLES = tuple(sorted(Base.metadata.tables))


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
async def db_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[RedisClient]:
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.fail("Redis is required for integration tests; run `make integration-test`")
    yield client
    await client.aclose()


async def _truncate_business_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    quoted = ", ".join(f'"{table}"' for table in BUSINESS_TABLES)
    async with session_factory() as session:
        async with session.begin():
            await session.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))


async def _clear_shadowtrace_keys(redis_client: RedisClient) -> None:
    client = redis_client.get_client()
    keys = [key async for key in client.scan_iter(match="shadowtrace:*", count=500)]
    if keys:
        await client.delete(*keys)


@pytest_asyncio.fixture(autouse=True)
async def clean_state(request: pytest.FixtureRequest) -> AsyncIterator[None]:
    """Reset PG/Redis only for real ``@pytest.mark.integration`` tests.

    Tests under this package that omit the ``integration`` marker (including
    ISSUE-025 ``tool_system`` chains) run in-memory and must not require
    Dockerized PostgreSQL/Redis. Always mark true Redis/PG cases with
    ``@pytest.mark.integration`` so cleanup still runs.
    """
    if request.node.get_closest_marker("integration") is None:
        yield
        return

    session_factory = request.getfixturevalue("session_factory")
    redis_client = request.getfixturevalue("redis_client")
    await _truncate_business_tables(session_factory)
    await _clear_shadowtrace_keys(redis_client)
    yield
    await _clear_shadowtrace_keys(redis_client)
    await _truncate_business_tables(session_factory)


@pytest.fixture
def mock_data_dir(tmp_path: Path) -> Path:
    target = tmp_path / "mock-data"
    scenario = build_scenario("insider_data_exfiltration", seed=42)
    write_scenario_artifacts(scenario, target)
    return target


@pytest.fixture
def mock_xdr_state() -> MockXDRState:
    state = MockXDRState()
    state.load_scenario(build_scenario("insider_data_exfiltration", seed=42))
    return state


@pytest_asyncio.fixture
async def mock_xdr_client(
    mock_xdr_state: MockXDRState,
) -> AsyncIterator[httpx.AsyncClient]:
    transport = ASGITransport(app=create_app(state=mock_xdr_state))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://mock-xdr",
        timeout=30.0,
    ) as client:
        yield client


@pytest.fixture
def source_adapter(mock_xdr_client: httpx.AsyncClient) -> MockXDRSourceAdapter:
    return MockXDRSourceAdapter(
        base_url="http://mock-xdr",
        read_token="mock-read-token",
        write_token="mock-write-token",
        client=mock_xdr_client,
        max_retries=0,
    )


@pytest.fixture
def context_store(
    redis_client: RedisClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> EventContextStore:
    return EventContextStore(redis_client, session_factory)


@pytest.fixture
def event_service(
    context_store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> EventService:
    degraded = DegradedFlagService(context_store, session_factory)
    return EventService(
        session_factory,
        context_store,
        degraded_flags=degraded,
    )


@pytest.fixture
def source_ingester(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> SourceIngester:
    return SourceIngester(
        event_service,
        session_factory,
        source_mode="mock_xdr",
    )
