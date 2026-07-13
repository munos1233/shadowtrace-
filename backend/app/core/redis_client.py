"""Async Redis client with orjson serialization (ISSUE-013)."""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

import orjson
from pydantic import BaseModel
from redis.asyncio import ConnectionPool, Redis

from app.core.config import get_settings

_DEFAULT_MAX_CONNECTIONS = 20


def _json_default(obj: Any) -> Any:
    """Fallback encoder for types orjson does not handle natively."""
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class RedisClient:
    """Thin async Redis wrapper: connection pool + orjson helpers + ping."""

    def __init__(
        self,
        url: str | None = None,
        *,
        max_connections: int = _DEFAULT_MAX_CONNECTIONS,
    ) -> None:
        self._url = url if url is not None else get_settings().redis_url
        self._pool = ConnectionPool.from_url(
            self._url,
            max_connections=max_connections,
            decode_responses=False,
        )
        self._client = Redis(connection_pool=self._pool)

    def get_client(self) -> Redis:
        """Return the shared async Redis client bound to the connection pool."""
        return self._client

    async def ping(self) -> bool:
        """Return True when Redis answers PING; False on any failure."""
        try:
            return bool(await self._client.ping())
        except Exception:  # noqa: BLE001 — health/degrade path must not raise
            return False

    async def aclose(self) -> None:
        """Close the client and disconnect the pool."""
        await self._client.aclose()
        await self._pool.disconnect()

    @staticmethod
    def dumps(value: Any) -> bytes:
        """Serialize ``value`` to UTF-8 JSON bytes via orjson."""
        return orjson.dumps(value, default=_json_default)

    @staticmethod
    def loads(data: bytes | str | memoryview) -> Any:
        """Deserialize orjson / UTF-8 JSON bytes or str."""
        if isinstance(data, memoryview):
            data = data.tobytes()
        if isinstance(data, str):
            data = data.encode("utf-8")
        return orjson.loads(data)
