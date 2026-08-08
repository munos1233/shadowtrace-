"""Cross-process checkpoint generation fence tests (ISSUE-284 / ID-REL-008)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.orchestration.checkpointer import (
    CHECKPOINT_ENVELOPE_FORMAT,
    CHECKPOINT_GEN_KEY_PREFIX,
    RedisCheckpointer,
    checkpoint_gen_key_for_event,
    checkpoint_key_for_event,
    reset_checkpoint_health_state_for_tests,
)


class FakeRedisStore:
    def __init__(self, *, fail_set: bool = False, fail_delete: bool = False) -> None:
        self.values: dict[str, bytes] = {}
        self.fail_set = fail_set
        self.fail_delete = fail_delete

    async def get(self, key: str) -> bytes | None:
        return self.values.get(key)

    async def set(self, key: str, value: bytes, *, ex: int | None = None) -> None:
        del ex
        if self.fail_set and not key.startswith(CHECKPOINT_GEN_KEY_PREFIX):
            raise ConnectionError("redis set failed")
        self.values[key] = value

    async def delete(self, key: str) -> None:
        if self.fail_delete:
            raise ConnectionError("redis delete failed")
        self.values.pop(key, None)


class FakeRedisClient:
    def __init__(self, *, available: bool = True, fail_set: bool = False) -> None:
        self.available = available
        self.store = FakeRedisStore(fail_set=fail_set)

    async def ping(self) -> bool:
        return self.available

    def get_client(self) -> FakeRedisStore:
        return self.store


def _marker(thread_id: str, version: str) -> dict[str, Any]:
    return {"marker": version, "thread_id": thread_id}


@pytest.fixture(autouse=True)
def _reset_checkpoint_observability() -> None:
    reset_checkpoint_health_state_for_tests()
    yield
    reset_checkpoint_health_state_for_tests()


@pytest.mark.asyncio
async def test_cross_process_stale_checkpoint_not_resurrected_after_persist_failure() -> None:
    """Process A N+1 persist failure must not let process B resume stale N."""
    redis = FakeRedisClient()
    event_id = "evt-cross-stale"

    process_a = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    process_a._memory.storage[event_id] = _marker(event_id, "N")
    await process_a._persist(event_id)
    assert checkpoint_key_for_event(event_id) in redis.store.values
    assert redis.store.values[checkpoint_gen_key_for_event(event_id)] == b"1"

    redis.store.fail_set = True
    process_a._memory.storage[event_id] = _marker(event_id, "N+1")
    await process_a._persist(event_id)

    assert process_a.memory_fallback is True
    assert event_id in process_a._memory_pinned_threads
    fence = int(redis.store.values[checkpoint_gen_key_for_event(event_id)])
    assert fence == 2
    payload = redis.store.values.get(checkpoint_key_for_event(event_id))
    if payload is not None:
        envelope = json.loads(payload.decode())
        assert envelope["generation"] <= fence

    redis.store.fail_set = False
    process_b = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await process_b._hydrate(event_id)

    assert event_id not in process_b._memory.storage


@pytest.mark.asyncio
async def test_cross_process_resume_latest_successful_generation() -> None:
    """Process B resumes the latest generation that was durably persisted."""
    redis = FakeRedisClient()
    event_id = "evt-cross-resume"

    process_a = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    process_a._memory.storage[event_id] = _marker(event_id, "N")
    await process_a._persist(event_id)
    process_a._memory.storage[event_id] = _marker(event_id, "N+1")
    await process_a._persist(event_id)

    process_b = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await process_b._hydrate(event_id)

    assert event_id in process_b._memory.storage
    assert process_b._memory.storage[event_id]["marker"] == "N+1"
    assert process_b._thread_generations[event_id] == 2


@pytest.mark.asyncio
async def test_hydrate_rejects_stale_payload_when_fence_is_ahead() -> None:
    """A fenced generation blocks loading an older payload left in Redis."""
    redis = FakeRedisClient()
    event_id = "evt-fence-reject"
    seed = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]

    seed._memory.storage[event_id] = _marker(event_id, "stale")
    stale_raw = seed._export(event_id, generation=1)
    assert stale_raw is not None
    redis.store.values[checkpoint_key_for_event(event_id)] = stale_raw
    redis.store.values[checkpoint_gen_key_for_event(event_id)] = b"2"

    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await saver._hydrate(event_id)
    assert event_id not in saver._memory.storage


@pytest.mark.asyncio
async def test_persist_failure_writes_format2_envelope_with_generation() -> None:
    redis = FakeRedisClient()
    event_id = "evt-format2"
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    saver._memory.storage[event_id] = _marker(event_id, "v1")
    await saver._persist(event_id)

    raw = redis.store.values[checkpoint_key_for_event(event_id)]
    envelope = json.loads(raw.decode())
    assert envelope["format"] == CHECKPOINT_ENVELOPE_FORMAT
    assert envelope["generation"] == 1


@pytest.mark.asyncio
async def test_pinned_thread_delete_removes_redis_keys() -> None:
    """Memory-pinned threads must still best-effort delete Redis checkpoint keys."""
    redis = FakeRedisClient()
    event_id = "evt-pinned-delete"
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]

    saver._memory.storage[event_id] = _marker(event_id, "pinned")
    await saver._persist(event_id)
    assert checkpoint_key_for_event(event_id) in redis.store.values

    redis.store.fail_set = True
    saver._memory.storage[event_id] = _marker(event_id, "pinned-v2")
    await saver._persist(event_id)
    assert event_id in saver._memory_pinned_threads

    redis.store.fail_set = False
    await saver.adelete_thread(event_id)

    assert checkpoint_key_for_event(event_id) not in redis.store.values
    assert checkpoint_gen_key_for_event(event_id) not in redis.store.values
    assert event_id not in saver._memory.storage


@pytest.mark.asyncio
async def test_legacy_format1_payload_hydrates_without_fence() -> None:
    """Format-1 envelopes remain readable when no generation fence key exists."""
    import base64

    redis = FakeRedisClient()
    event_id = "evt-legacy"
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]

    payload = {"storage": _marker(event_id, "legacy"), "writes": {}, "blobs": {}}
    type_tag, raw = saver._serde.dumps_typed(payload)
    legacy_envelope = {
        "format": 1,
        "serde": type_tag,
        "payload": base64.b64encode(raw).decode("ascii"),
    }
    redis.store.values[checkpoint_key_for_event(event_id)] = json.dumps(
        legacy_envelope,
        separators=(",", ":"),
    ).encode()

    process_b = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await process_b._hydrate(event_id)

    assert event_id in process_b._memory.storage
    assert process_b._memory.storage[event_id]["marker"] == "legacy"
    assert process_b._thread_generations[event_id] == 1
