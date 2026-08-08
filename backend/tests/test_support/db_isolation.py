"""Shared PostgreSQL/Redis isolation for backend tests (ISSUE-267).

Centralizes TRUNCATE CASCADE + Redis key cleanup so ingestion, service, API,
and integration suites do not cross-contaminate when sharing one database.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.redis_client import RedisClient
from app.db.base import Base

# Register all ORM tables on Base.metadata before reading table names.
import app.db.models  # noqa: F401


def business_tables() -> tuple[str, ...]:
    return tuple(sorted(Base.metadata.tables))


async def truncate_business_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tables = business_tables()
    if not tables:
        return
    quoted = ", ".join(f'"{table}"' for table in tables)
    async with session_factory() as session:
        async with session.begin():
            await session.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))


async def clear_shadowtrace_redis_keys(redis_client: RedisClient) -> None:
    try:
        client = redis_client.get_client()
        keys = [key async for key in client.scan_iter(match="shadowtrace:*", count=500)]
        if keys:
            await client.delete(*keys)
    except RuntimeError:
        # TestClient may close the asyncio loop before fixture teardown runs.
        pass


@pytest_asyncio.fixture
async def clean_state(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> AsyncIterator[None]:
    """Reset PG/Redis around a test. Opt-in via fixture request or autouse conftest."""
    await truncate_business_tables(session_factory)
    await clear_shadowtrace_redis_keys(redis_client)
    yield
    await clear_shadowtrace_redis_keys(redis_client)
    await truncate_business_tables(session_factory)
