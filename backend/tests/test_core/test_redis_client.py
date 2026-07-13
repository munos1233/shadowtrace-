"""RedisClient tests against Compose Redis (ISSUE-013)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from app.core.redis_client import RedisClient

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[RedisClient]:
    client = RedisClient(url=REDIS_URL, max_connections=20)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_ping_ok(redis_client: RedisClient) -> None:
    assert await redis_client.ping() is True


@pytest.mark.asyncio
async def test_get_client_roundtrip_orjson(redis_client: RedisClient) -> None:
    r = redis_client.get_client()
    key = "shadowtrace:test:redis_client:orjson"
    payload = {"event_id": "evt-20260101-abcd1234", "n": 1, "ok": True}
    await r.set(key, RedisClient.dumps(payload))
    raw = await r.get(key)
    assert raw is not None
    assert RedisClient.loads(raw) == payload
    await r.delete(key)


@pytest.mark.asyncio
async def test_ping_false_when_unreachable() -> None:
    client = RedisClient(url="redis://127.0.0.1:1/0", max_connections=1)
    try:
        assert await client.ping() is False
    finally:
        await client.aclose()
