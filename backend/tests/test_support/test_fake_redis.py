"""Unit tests for shared in-memory Redis fake (ISSUE-264)."""

from __future__ import annotations

import pytest

from app.orchestration.lease import EventLease, generate_owner_id
from tests.support.fake_redis import InMemoryFakeRedis, InMemoryFakeRedisClient


def _lease_with_fake(fake: InMemoryFakeRedis) -> EventLease:
    return EventLease(InMemoryFakeRedisClient(fake))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_set_nx_rejects_conflicting_owner() -> None:
    fake = InMemoryFakeRedis()
    lease = _lease_with_fake(fake)
    event_id = "evt-fake-nx-conflict"
    first_owner = generate_owner_id()
    second_owner = generate_owner_id()

    assert await lease.acquire(event_id, first_owner, ttl_s=60) is True
    assert await lease.acquire(event_id, second_owner, ttl_s=60) is False
    assert await lease.get_owner(event_id) == first_owner


@pytest.mark.asyncio
async def test_release_script_owner_mismatch() -> None:
    fake = InMemoryFakeRedis()
    lease = _lease_with_fake(fake)
    event_id = "evt-fake-release-mismatch"
    owner = generate_owner_id()
    other = generate_owner_id()

    assert await lease.acquire(event_id, owner, ttl_s=60) is True
    assert await lease.release(event_id, other) is False
    assert await lease.get_owner(event_id) == owner
    assert await lease.release(event_id, owner) is True
