"""Checkpoint memory fallback observability tests (ISSUE-175 / #701)."""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from app.core.metrics import checkpoint_health_snapshot, reset_checkpoint_metrics_for_tests
from app.orchestration.checkpointer import (
    CHECKPOINT_GENERATION_SEQUENCE_KEY,
    CheckpointPersistenceError,
    RedisCheckpointer,
    checkpoint_generation_key_for_event,
    checkpoint_key_for_event,
    get_checkpoint_health,
    reset_checkpoint_health_state_for_tests,
)


class FakeRedisStore:
    def __init__(self, *, fail_set: bool = False, fail_incr: bool = False) -> None:
        self.values: dict[str, bytes] = {}
        self.fail_set = fail_set
        self.fail_incr = fail_incr

    async def get(self, key: str) -> bytes | None:
        return self.values.get(key)

    async def set(self, key: str, value: bytes, *, ex: int | None = None) -> None:
        if self.fail_set:
            raise ConnectionError("redis set failed")
        self.values[key] = value

    async def incr(self, key: str) -> int:
        if self.fail_incr:
            raise ConnectionError("redis incr failed")
        generation = int(self.values.get(key, b"0")) + 1
        self.values[key] = str(generation).encode()
        return generation

    async def expire(self, key: str, seconds: int) -> bool:
        del key, seconds
        return True

    async def eval(self, script: str, numkeys: int, *args: object) -> int:
        del numkeys
        if "checkpoint-reserve-generation-v2" in script:
            sequence_key, generation_key, _ttl = args
            assert isinstance(sequence_key, str)
            assert isinstance(generation_key, str)
            if self.fail_incr:
                raise ConnectionError("redis generation reserve failed")
            generation = int(self.values.get(sequence_key, b"0")) + 1
            self.values[sequence_key] = str(generation).encode()
            self.values[generation_key] = str(generation).encode()
            await asyncio.sleep(0)
            return generation
        if "checkpoint-publish-v2" not in script:
            raise AssertionError("unexpected Redis script")
        checkpoint_key, generation_key, generation, value, _ttl = args
        assert isinstance(checkpoint_key, str)
        assert isinstance(generation_key, str)
        assert isinstance(generation, int)
        assert isinstance(value, bytes)
        if self.fail_set:
            raise ConnectionError("redis set failed")
        current = int(self.values.get(generation_key, b"0"))
        if current != generation:
            return 0
        self.values[checkpoint_key] = value
        return 1

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)


class FakeRedisClient:
    def __init__(
        self,
        *,
        available: bool = True,
        fail_set: bool = False,
        fail_incr: bool = False,
    ) -> None:
        self.available = available
        self.store = FakeRedisStore(fail_set=fail_set, fail_incr=fail_incr)

    async def ping(self) -> bool:
        return self.available

    def get_client(self) -> FakeRedisStore:
        return self.store


class _SharedRedisStore:
    """SQLite-backed Redis double used by the real process-boundary artifact."""

    def __init__(self, database_path: str, *, fail_set: bool) -> None:
        self.database_path = database_path
        self.fail_set = fail_set
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS checkpoint_kv "
                "(key TEXT PRIMARY KEY, value BLOB NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path, timeout=5)

    async def get(self, key: str) -> bytes | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM checkpoint_kv WHERE key = ?", (key,)
            ).fetchone()
        return bytes(row[0]) if row is not None else None

    async def incr(self, key: str) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT value FROM checkpoint_kv WHERE key = ?", (key,)
            ).fetchone()
            generation = int(row[0]) + 1 if row is not None else 1
            connection.execute(
                "INSERT INTO checkpoint_kv(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(generation).encode()),
            )
            return generation

    async def expire(self, key: str, seconds: int) -> bool:
        del key, seconds
        return True

    async def eval(self, script: str, numkeys: int, *args: object) -> int:
        del numkeys
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if "checkpoint-reserve-generation-v2" in script:
                sequence_key, generation_key, _ttl = args
                assert isinstance(sequence_key, str)
                assert isinstance(generation_key, str)
                row = connection.execute(
                    "SELECT value FROM checkpoint_kv WHERE key = ?", (sequence_key,)
                ).fetchone()
                generation = int(row[0]) + 1 if row is not None else 1
                for key in (sequence_key, generation_key):
                    connection.execute(
                        "INSERT INTO checkpoint_kv(key, value) VALUES (?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (key, str(generation).encode()),
                    )
                return generation
            assert "checkpoint-publish-v2" in script
            checkpoint_key, generation_key, generation, value, _ttl = args
            assert isinstance(checkpoint_key, str)
            assert isinstance(generation_key, str)
            assert isinstance(generation, int)
            assert isinstance(value, bytes)
            if self.fail_set:
                raise ConnectionError("injected Redis SET failure")
            row = connection.execute(
                "SELECT value FROM checkpoint_kv WHERE key = ?", (generation_key,)
            ).fetchone()
            if row is None or int(row[0]) != generation:
                return 0
            connection.execute(
                "INSERT INTO checkpoint_kv(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (checkpoint_key, value),
            )
            return 1

    async def delete(self, key: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM checkpoint_kv WHERE key = ?", (key,))


class _SharedRedisClient:
    def __init__(self, database_path: str, *, fail_set: bool) -> None:
        self.store = _SharedRedisStore(database_path, fail_set=fail_set)

    async def ping(self) -> bool:
        return True

    def get_client(self) -> _SharedRedisStore:
        return self.store


def _process_persist(
    database_path: str,
    fail_set: bool,
    thread_id: str,
    state: str,
    result_queue: Any,
) -> None:
    async def _run() -> None:
        redis = _SharedRedisClient(database_path, fail_set=fail_set)
        saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
        saver._memory.storage[thread_id] = {"state": state}
        try:
            await saver._persist(thread_id)
        except CheckpointPersistenceError:
            result_queue.put("halted")
        else:
            result_queue.put("persisted")

    asyncio.run(_run())


def _process_hydrate(
    database_path: str,
    thread_id: str,
    result_queue: Any,
) -> None:
    async def _run() -> None:
        redis = _SharedRedisClient(database_path, fail_set=False)
        saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
        await saver._hydrate(thread_id)
        result_queue.put(saver._memory.storage.get(thread_id))

    asyncio.run(_run())


def _config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}}


@pytest.fixture(autouse=True)
def _reset_checkpoint_observability() -> None:
    reset_checkpoint_health_state_for_tests()
    yield
    reset_checkpoint_health_state_for_tests()


@pytest.mark.asyncio
async def test_redis_client_none_records_fallback_trigger() -> None:
    saver = await RedisCheckpointer.create(None)  # type: ignore[arg-type]
    assert saver.memory_fallback is True
    health = get_checkpoint_health()
    assert health["fallback_triggers"] == 1
    assert health["memory_fallback"] is True


@pytest.mark.asyncio
async def test_hydrate_failure_pins_thread_and_fallback() -> None:
    redis = FakeRedisClient()

    class FailingGetStore(FakeRedisStore):
        async def get(self, key: str) -> bytes | None:
            raise ConnectionError("redis get failed")

    redis.store = FailingGetStore()  # type: ignore[assignment]
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    assert saver.memory_fallback is False

    await saver._hydrate("evt-load-fail")
    assert saver.memory_fallback is True
    assert saver._memory_pinned_threads == {"evt-load-fail"}
    health = get_checkpoint_health()
    assert health["memory_pinned_thread_count"] == 1


@pytest.mark.asyncio
async def test_recovery_health_shows_pinned_threads_while_redis_resumed() -> None:
    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(
        redis,  # type: ignore[arg-type]
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )
    redis.store.fail_set = True
    saver._memory.storage["evt-pinned"] = {}
    with pytest.raises(CheckpointPersistenceError):
        await saver._persist("evt-pinned")

    redis.store.fail_set = False
    await saver._maybe_attempt_redis_recovery()
    health = get_checkpoint_health()
    assert health["memory_fallback"] is False
    assert health["memory_pinned_thread_count"] == 1
    assert health["persistence_failed_thread_count"] == 1
    assert health["status"] == "degraded"
    assert health["recoverable"] is False


@pytest.mark.asyncio
async def test_any_live_checkpointer_fallback_marks_health_degraded() -> None:
    await RedisCheckpointer.create(FakeRedisClient())  # type: ignore[arg-type]
    await RedisCheckpointer.create(FakeRedisClient(available=False))  # type: ignore[arg-type]

    health = get_checkpoint_health()
    assert health["status"] == "degraded"
    assert health["memory_fallback"] is True


@pytest.mark.asyncio
async def test_fallback_sets_health_and_metrics() -> None:
    redis = FakeRedisClient(available=False)
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]

    assert saver.memory_fallback is True
    assert saver.recoverable is False

    health = get_checkpoint_health()
    assert health["status"] == "degraded"
    assert health["memory_fallback"] is True
    assert health["recoverable"] is False
    assert health["fallback_triggers"] == 1
    assert health["redis_recovery_enabled"] is False
    assert health["memory_pinned_thread_count"] == 0

    snapshot = checkpoint_health_snapshot()
    assert snapshot["memory_fallback"] is True
    assert snapshot["fallback_triggers"] == 1


@pytest.mark.asyncio
async def test_default_memory_fallback_without_recovery_flag() -> None:
    redis = FakeRedisClient()
    redis.store.fail_set = True
    saver = await RedisCheckpointer.create(
        redis,  # type: ignore[arg-type]
        attempt_redis_recovery=False,
    )
    assert saver.memory_fallback is False

    saver._memory.storage["evt-fallback-default"] = {}
    with pytest.raises(CheckpointPersistenceError):
        await saver._persist("evt-fallback-default")
    assert saver.memory_fallback is True
    assert saver._memory_pinned_threads == {"evt-fallback-default"}
    assert redis.store.values[CHECKPOINT_GENERATION_SEQUENCE_KEY] == b"1"
    assert redis.store.values[checkpoint_generation_key_for_event("evt-fallback-default")] == b"1"

    saver._memory.storage["evt-fallback-default-2"] = {}
    await saver._persist("evt-fallback-default-2")
    assert checkpoint_key_for_event("evt-fallback-default-2") not in redis.store.values


@pytest.mark.asyncio
async def test_recovery_restores_redis_only_for_new_threads() -> None:
    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(
        redis,  # type: ignore[arg-type]
        attempt_redis_recovery=True,
        recovery_interval_seconds=0.0,
    )
    redis.store.fail_set = True

    saver._memory.storage["evt-pinned"] = {}
    with pytest.raises(CheckpointPersistenceError):
        await saver._persist("evt-pinned")
    assert saver.memory_fallback is True
    assert saver._memory_pinned_threads == {"evt-pinned"}

    redis.store.fail_set = False
    await saver._maybe_attempt_redis_recovery()
    saver._memory.storage["evt-redis-resumed"] = {}
    await saver._persist("evt-redis-resumed")

    assert saver.memory_fallback is False
    assert saver.recoverable is True
    assert checkpoint_key_for_event("evt-redis-resumed") in redis.store.values
    assert checkpoint_key_for_event("evt-pinned") not in redis.store.values

    with pytest.raises(CheckpointPersistenceError):
        await saver._persist("evt-pinned")
    assert checkpoint_key_for_event("evt-pinned") not in redis.store.values


@pytest.mark.asyncio
async def test_failed_persist_fences_stale_checkpoint_from_new_saver() -> None:
    """ISSUE-284: process B must not revive N after process A loses N+1."""
    redis = FakeRedisClient()
    thread_id = "evt-generation-fence"
    checkpoint_key = checkpoint_key_for_event(thread_id)
    generation_key = checkpoint_generation_key_for_event(thread_id)

    seed = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    seed._memory.storage[thread_id] = {"state": "N"}
    await seed._persist(thread_id)
    persisted_n = redis.store.values[checkpoint_key]
    assert redis.store.values[generation_key] == b"1"

    process_a = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    process_a._memory.storage[thread_id] = {"state": "N+1"}
    redis.store.fail_set = True
    with pytest.raises(CheckpointPersistenceError, match="publish"):
        await process_a._persist(thread_id)

    assert redis.store.values[checkpoint_key] == persisted_n
    assert redis.store.values[generation_key] == b"2"
    redis.store.fail_set = False

    process_b = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await process_b._hydrate(thread_id)
    assert thread_id not in process_b._memory.storage


@pytest.mark.asyncio
async def test_legacy_checkpoint_loads_only_when_no_generation_fence_exists() -> None:
    """Format-1 deployments remain readable, but never bypass an active fence."""
    redis = FakeRedisClient()
    thread_id = "evt-legacy-generation"
    checkpoint_key = checkpoint_key_for_event(thread_id)
    generation_key = checkpoint_generation_key_for_event(thread_id)
    seed = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    seed._memory.storage[thread_id] = {"state": "legacy-N"}
    await seed._persist(thread_id)

    envelope = json.loads(redis.store.values[checkpoint_key])
    envelope["format"] = 1
    envelope.pop("generation")
    redis.store.values[checkpoint_key] = json.dumps(envelope).encode()
    redis.store.values.pop(generation_key)

    compatible_reader = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await compatible_reader._hydrate(thread_id)
    assert compatible_reader._memory.storage[thread_id] == {"state": "legacy-N"}

    redis.store.values[generation_key] = b"1"
    fenced_reader = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await fenced_reader._hydrate(thread_id)
    assert thread_id not in fenced_reader._memory.storage


def test_failed_persist_cannot_resurrect_stale_checkpoint_across_os_processes(
    tmp_path: Path,
) -> None:
    """Repeatable ISSUE-284 artifact: seed N, fail A/N+1, then start B."""
    context = multiprocessing.get_context("spawn")
    database_path = str(tmp_path / "cross-process-checkpoint.sqlite3")
    results = context.Queue()
    thread_id = "evt-cross-process-generation"

    seed = context.Process(
        target=_process_persist,
        args=(database_path, False, thread_id, "N", results),
    )
    seed.start()
    seed.join(15)
    assert seed.exitcode == 0
    assert results.get(timeout=2) == "persisted"

    process_a = context.Process(
        target=_process_persist,
        args=(database_path, True, thread_id, "N+1", results),
    )
    process_a.start()
    process_a.join(15)
    assert process_a.exitcode == 0
    assert results.get(timeout=2) == "halted"

    process_b = context.Process(
        target=_process_hydrate,
        args=(database_path, thread_id, results),
    )
    process_b.start()
    process_b.join(15)
    assert process_b.exitcode == 0
    assert results.get(timeout=2) is None


@pytest.mark.asyncio
async def test_failed_generation_fence_deletes_stale_checkpoint_and_halts() -> None:
    redis = FakeRedisClient()
    thread_id = "evt-generation-fence-failure"

    seed = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    seed._memory.storage[thread_id] = {"state": "N"}
    await seed._persist(thread_id)
    assert checkpoint_key_for_event(thread_id) in redis.store.values

    process_a = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    process_a._memory.storage[thread_id] = {"state": "N+1"}
    redis.store.fail_incr = True
    with pytest.raises(CheckpointPersistenceError, match="fence"):
        await process_a._persist(thread_id)
    assert checkpoint_key_for_event(thread_id) not in redis.store.values

    with pytest.raises(CheckpointPersistenceError, match="blocked"):
        await process_a._persist(thread_id)


@pytest.mark.asyncio
async def test_late_lower_generation_cannot_overwrite_latest_checkpoint() -> None:
    redis = FakeRedisClient()
    thread_id = "evt-concurrent-generation"
    slower = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    faster = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]

    slower._memory.storage[thread_id] = {"state": "N+1"}
    slow_generation = await slower._reserve_generation(thread_id)
    slow_payload = slower._export(thread_id, generation=slow_generation)
    faster._memory.storage[thread_id] = {"state": "N+2"}
    fast_generation = await faster._reserve_generation(thread_id)
    fast_payload = faster._export(thread_id, generation=fast_generation)

    assert slow_payload is not None
    assert fast_payload is not None
    await faster._publish(thread_id, fast_generation, fast_payload)
    with pytest.raises(CheckpointPersistenceError, match="superseded"):
        await slower._publish(thread_id, slow_generation, slow_payload)

    process_b = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await process_b._hydrate(thread_id)
    assert process_b._memory.storage[thread_id] == {"state": "N+2"}


@pytest.mark.asyncio
async def test_same_saver_serializes_concurrent_persists_for_one_thread() -> None:
    """LangGraph aput/aput_writes concurrency must not self-supersede."""
    redis = FakeRedisClient()
    thread_id = "evt-concurrent-same-saver"
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    saver._memory.storage[thread_id] = {"state": "latest"}

    await asyncio.gather(saver._persist(thread_id), saver._persist(thread_id))

    assert redis.store.values[checkpoint_generation_key_for_event(thread_id)] == b"2"
    reader = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await reader._hydrate(thread_id)
    assert reader._memory.storage[thread_id] == {"state": "latest"}


@pytest.mark.asyncio
async def test_generation_is_not_reused_after_thread_fence_expires() -> None:
    """Global sequence prevents an old generation-1 publisher from winning an ABA race."""
    redis = FakeRedisClient()
    thread_id = "evt-generation-aba"
    old_process = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    old_process._memory.storage[thread_id] = {"state": "old-lifecycle"}
    old_generation = await old_process._reserve_generation(thread_id)
    old_payload = old_process._export(thread_id, generation=old_generation)
    assert old_payload is not None

    redis.store.values.pop(checkpoint_generation_key_for_event(thread_id))
    new_process = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    new_process._memory.storage[thread_id] = {"state": "new-lifecycle"}
    await new_process._persist(thread_id)

    assert old_generation == 1
    assert redis.store.values[checkpoint_generation_key_for_event(thread_id)] == b"2"
    with pytest.raises(CheckpointPersistenceError, match="superseded"):
        await old_process._publish(thread_id, old_generation, old_payload)


@pytest.mark.asyncio
async def test_pinned_cleanup_removes_loadable_checkpoint_and_keeps_fence() -> None:
    redis = FakeRedisClient()
    thread_id = "evt-pinned-cleanup"
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    saver._memory.storage[thread_id] = {"state": "N"}
    await saver._persist(thread_id)

    saver._pin_thread_to_memory(thread_id)
    saver.memory_fallback = True
    await saver.adelete_thread(thread_id)

    assert checkpoint_key_for_event(thread_id) not in redis.store.values
    assert int(redis.store.values[checkpoint_generation_key_for_event(thread_id)]) >= 2

    process_b = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await process_b._hydrate(thread_id)
    assert thread_id not in process_b._memory.storage


@pytest.mark.asyncio
async def test_sync_api_still_downgrades_recoverability_once() -> None:
    saver = await RedisCheckpointer.create(FakeRedisClient())  # type: ignore[arg-type]
    assert saver.recoverable is True

    assert saver.get_tuple(_config("evt-sync")) is None
    assert saver.recoverable is False
    assert checkpoint_health_snapshot()["fallback_triggers"] == 1


def test_reset_checkpoint_metrics_for_tests_clears_counters() -> None:
    reset_checkpoint_metrics_for_tests()
    assert checkpoint_health_snapshot()["fallback_triggers"] == 0
