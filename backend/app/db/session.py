"""Async engine, session factory and the FastAPI ``get_session`` dependency."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings


@lru_cache
def get_engine() -> AsyncEngine:
    """Return the cached async engine built from ``DATABASE_URL``."""
    settings = get_settings()
    return create_async_engine(settings.database_url, pool_pre_ping=True, future=True)


@lru_cache
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the cached session factory."""
    return async_session_factory


async_session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=get_engine(),
    expire_on_commit=False,
    autoflush=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async session with commit/rollback handling."""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
