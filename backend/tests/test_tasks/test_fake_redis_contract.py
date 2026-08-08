"""Fake Redis NX/EX semantics for lease tests (ISSUE-264 / ISSUE-283)."""

from __future__ import annotations

import pytest

from app.orchestration.lease import EventLease
from tests.support.fake_redis import InMemoryFakeRedis, InMemoryFakeRedisClient


@pytest.mark.asyncio
async def test_in_memory_fake_redis_set_nx_ex_conflict() -> None:
    raw = InMemoryFakeRedis()
    assert await raw.set("k1", "owner-a", nx=True, ex=60) is True
    assert await raw.set("k1", "owner-b", nx=True, ex=60) is None
    assert (await raw.get("k1")).decode() == "owner-a"


@pytest.mark.asyncio
async def test_event_lease_acquire_respects_nx() -> None:
    raw = InMemoryFakeRedis()
    lease = EventLease(InMemoryFakeRedisClient(raw))  # type: ignore[arg-type]
    assert await lease.acquire("evt-nx", "owner-1", ttl_s=60)
    assert await lease.acquire("evt-nx", "owner-2", ttl_s=60) is False
    assert await lease.get_owner("evt-nx") == "owner-1"
    assert await lease.release("evt-nx", "owner-1")
    assert await lease.acquire("evt-nx", "owner-2", ttl_s=60)
