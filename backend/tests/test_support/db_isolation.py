"""Shared PostgreSQL/Redis isolation for backend tests (ISSUE-267).

Centralizes TRUNCATE CASCADE + Redis key cleanup so ingestion, service, API,
and integration suites do not cross-contaminate when sharing one database.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# Register all ORM tables on Base.metadata before reading table names.
import app.db.models  # noqa: F401
from app.core.redis_client import RedisClient
from app.db.base import Base


def business_tables() -> tuple[str, ...]:
    return tuple(sorted(Base.metadata.tables))


async def truncate_business_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tables = business_tables()
    if not tables:
        return
    async with session_factory() as session:
        async with session.begin():
            existing_rows = await session.execute(
                text(
                    "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = current_schema()"
                )
            )
            present = {str(row[0]) for row in existing_rows}
            to_truncate = [table for table in tables if table in present]
            if not to_truncate:
                return
            quoted = ", ".join(f'"{table}"' for table in to_truncate)
            await session.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))


async def clear_shadowtrace_redis_keys(redis_client: RedisClient) -> None:
    try:
        client = redis_client.get_client()
        keys = [key async for key in client.scan_iter(match="shadowtrace:*", count=500)]
        if keys:
            await client.delete(*keys)
    except RuntimeError:
        # TestClient may close the asyncio loop before fixture teardown runs.
        # Recreate a short-lived client so CI cleanup still clears leases/checkpoints.
        if os.environ.get("CI") != "true" and os.environ.get("GITHUB_ACTIONS") != "true":
            return
        fallback = RedisClient(url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
        try:
            client = fallback.get_client()
            keys = [key async for key in client.scan_iter(match="shadowtrace:*", count=500)]
            if keys:
                await client.delete(*keys)
        finally:
            await fallback.aclose()


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
