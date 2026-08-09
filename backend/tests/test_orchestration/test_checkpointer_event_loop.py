"""Celery asyncio.run × Redis checkpointer lifecycle (ISSUE-252 / ID-R2-009)."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.core.metrics import checkpoint_health_snapshot
from app.core.redis_client import RedisClient, is_event_loop_error
from app.orchestration.checkpointer import (
    CheckpointPersistenceError,
    RedisCheckpointer,
    checkpoint_key_for_event,
    get_checkpoint_health,
    reset_checkpoint_health_state_for_tests,
)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _redis_reachable() -> bool:
    client = RedisClient(url=REDIS_URL, max_connections=2)

    async def _ping() -> bool:
        try:
            return await client.ping()
        finally:
            await client.aclose()

    try:
        return bool(asyncio.run(_ping()))
    except Exception:
        return False


@pytest.fixture(autouse=True)
def _reset_checkpoint_observability() -> None:
    reset_checkpoint_health_state_for_tests()
    yield
    reset_checkpoint_health_state_for_tests()


def _empty_checkpoint() -> dict[str, Any]:
    return {
        "v": 1,
        "id": "cp-test",
        "ts": "2026-01-01T00:00:00+00:00",
        "channel_values": {},
        "channel_versions": {},
        "versions_seen": {},
    }


def _config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}


@pytest.mark.skipif(not _redis_reachable(), reason="Redis not reachable")
def test_redis_client_survives_consecutive_asyncio_run() -> None:
    """Strategy B defense: same RedisClient across two asyncio.run loops."""
    client = RedisClient(url=REDIS_URL, max_connections=2)
    key = "shadowtrace:test:issue252:loop"

    async def _roundtrip(value: bytes) -> bytes | None:
        r = client.get_client()
        await r.set(key, value, ex=60)
        return await r.get(key)

    try:
        assert asyncio.run(_roundtrip(b"first")) == b"first"
        assert asyncio.run(_roundtrip(b"second")) == b"second"
    finally:
        asyncio.run(client.aclose())


@pytest.mark.skipif(not _redis_reachable(), reason="Redis not reachable")
def test_checkpointer_persist_load_across_celery_style_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two investigate+resume-style asyncio.run cycles must keep Redis checkpoints."""
    from app.api.v1 import deps
    from app.core.config import get_settings
    from app.tasks.investigation_tasks import _release_celery_task_loop_resources

    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    get_settings.cache_clear()
    deps.reset_deps()
    event_a = "evt-issue252-a"
    event_b = "evt-issue252-b"
    loop_closed_hits = 0

    class _CountingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            nonlocal loop_closed_hits
            msg = record.getMessage().lower()
            if "event loop is closed" in msg:
                loop_closed_hits += 1

    handler = _CountingHandler()
    root = logging.getLogger()
    root.addHandler(handler)
    try:

        async def _investigate_persist(event_id: str) -> None:
            redis = deps._get_redis()
            saver = await RedisCheckpointer.create(redis)
            assert saver.memory_fallback is False
            # Seed InMemorySaver storage the same way production aput does,
            # then exercise the Redis persist path under a fresh loop.
            config = _config(event_id)
            saver._memory.put(
                config,
                _empty_checkpoint(),  # type: ignore[arg-type]
                {},  # type: ignore[arg-type]
                {},
            )
            await saver._persist(event_id)
            assert saver.memory_fallback is False
            raw = await redis.get_client().get(checkpoint_key_for_event(event_id))
            assert raw is not None

        async def _resume_load(event_id: str) -> None:
            redis = deps._get_redis()
            saver = await RedisCheckpointer.create(redis)
            assert saver.memory_fallback is False
            await saver._hydrate(event_id)
            assert saver.memory_fallback is False
            assert event_id in saver._memory.storage

        # investigate → release → investigate → release → resume ×2
        asyncio.run(_investigate_persist(event_a))
        _release_celery_task_loop_resources()
        asyncio.run(_investigate_persist(event_b))
        _release_celery_task_loop_resources()
        asyncio.run(_resume_load(event_a))
        _release_celery_task_loop_resources()
        asyncio.run(_resume_load(event_b))

        health = get_checkpoint_health()
        assert health["memory_fallback"] is False
        assert loop_closed_hits == 0
    finally:
        root.removeHandler(handler)
        _release_celery_task_loop_resources()
        deps.reset_deps()
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_persist_recovers_from_event_loop_error_without_sticky_fallback() -> None:
    """Closed-loop persist errors rebind + retry; must not stick memory_fallback."""

    class _LoopAwareStore:
        def __init__(self) -> None:
            self.values: dict[str, bytes] = {}
            self.calls = 0

        async def get(self, key: str) -> bytes | None:
            return self.values.get(key)

        async def set(self, key: str, value: bytes, *, ex: int | None = None) -> None:
            del ex
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("Event loop is closed")
            self.values[key] = value

        async def incr(self, key: str) -> int:
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
                generation = int(self.values.get(sequence_key, b"0")) + 1
                self.values[sequence_key] = str(generation).encode()
                self.values[generation_key] = str(generation).encode()
                return generation
            assert "checkpoint-publish-v2" in script
            checkpoint_key, generation_key, generation, value, ttl = args
            assert isinstance(checkpoint_key, str)
            assert isinstance(generation_key, str)
            assert isinstance(generation, int)
            assert isinstance(value, bytes)
            assert isinstance(ttl, int)
            if int(self.values.get(generation_key, b"0")) != generation:
                return 0
            await self.set(checkpoint_key, value, ex=ttl)
            return 1

        async def delete(self, key: str) -> None:
            self.values.pop(key, None)

    class _LoopAwareRedis:
        def __init__(self) -> None:
            self.store = _LoopAwareStore()
            self.rebinds = 0

        async def ping(self) -> bool:
            return True

        def get_client(self) -> _LoopAwareStore:
            return self.store

        async def rebind_to_current_loop(self) -> None:
            self.rebinds += 1

    redis = _LoopAwareRedis()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    saver._memory.storage["evt-loop-recover"] = {}
    await saver._persist("evt-loop-recover")

    assert saver.memory_fallback is False
    assert redis.rebinds == 1
    assert checkpoint_key_for_event("evt-loop-recover") in redis.store.values
    snapshot = checkpoint_health_snapshot()
    assert snapshot["loop_rebinds"] == 1
    assert snapshot["fallback_triggers"] == 0


@pytest.mark.asyncio
async def test_persist_loop_error_falls_back_when_rebind_retry_fails() -> None:
    class _AlwaysClosedStore:
        async def set(self, key: str, value: bytes, *, ex: int | None = None) -> None:
            del key, value, ex
            raise RuntimeError("Event loop is closed")

        async def get(self, key: str) -> bytes | None:
            del key
            raise RuntimeError("Event loop is closed")

        async def incr(self, key: str) -> int:
            del key
            raise RuntimeError("Event loop is closed")

        async def expire(self, key: str, seconds: int) -> bool:
            del key, seconds
            raise RuntimeError("Event loop is closed")

        async def delete(self, key: str) -> None:
            del key
            raise RuntimeError("Event loop is closed")

        async def eval(self, script: str, numkeys: int, *args: object) -> int:
            del script, numkeys, args
            raise RuntimeError("Event loop is closed")

    class _BrokenRedis:
        def __init__(self) -> None:
            self.store = _AlwaysClosedStore()

        async def ping(self) -> bool:
            return True

        def get_client(self) -> _AlwaysClosedStore:
            return self.store

        async def rebind_to_current_loop(self) -> None:
            return None

    redis = _BrokenRedis()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    saver._memory.storage["evt-loop-fail"] = {}
    with pytest.raises(CheckpointPersistenceError, match="generation fence"):
        await saver._persist("evt-loop-fail")

    assert saver.memory_fallback is True
    assert "evt-loop-fail" in saver._memory_pinned_threads
    health = get_checkpoint_health()
    assert health["fallback_triggers"] == 1


def test_is_event_loop_error_detects_common_messages() -> None:
    assert is_event_loop_error(RuntimeError("Event loop is closed"))
    assert is_event_loop_error(RuntimeError("Task got Future attached to a different loop"))
    assert not is_event_loop_error(ConnectionError("redis down"))


def test_release_celery_resources_clears_redis_singleton(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.v1 import deps
    from app.tasks.investigation_tasks import _release_celery_task_loop_resources

    fake = MagicMock()
    fake.aclose = MagicMock()
    deps._redis_client = fake  # type: ignore[assignment]
    deps._event_lease = object()
    deps._context_store = object()
    deps._event_bus = object()
    deps._decision_record_service = object()
    deps._degraded_flags = object()

    stack_mock = MagicMock()
    retrieval_mock = MagicMock()
    playbook_mock = MagicMock()
    embed_mock = MagicMock()
    monkeypatch.setattr(deps, "reset_investigation_stack_cache", stack_mock)
    monkeypatch.setattr(
        "app.rag.resources.reset_loaded_retrieval_resources",
        retrieval_mock,
    )
    monkeypatch.setattr(
        "app.playbook.resources.reset_playbook_resources_cache",
        playbook_mock,
    )
    monkeypatch.setattr(
        "app.core.embedding.factory.reset_embedding_client",
        embed_mock,
    )

    # Avoid nested asyncio.run against MagicMock.aclose — null path is enough.
    async def _noop_aclose() -> None:
        return None

    fake.aclose = _noop_aclose

    _release_celery_task_loop_resources()

    stack_mock.assert_called_once()
    retrieval_mock.assert_called_once()
    playbook_mock.assert_called_once()
    embed_mock.assert_called_once()
    assert deps._redis_client is None
    assert deps._event_lease is None
    assert deps._context_store is None
    assert deps._event_bus is None
    assert deps._decision_record_service is None
    assert deps._degraded_flags is None


@pytest.mark.asyncio
async def test_rebind_to_current_loop_force_rebuilds_even_when_needs_rebind_false() -> None:
    """Explicit rebind must rebuild even when loop tracking still looks healthy."""
    client = RedisClient(url=REDIS_URL, max_connections=2)
    try:
        first = client.get_client()
        assert client._needs_rebind(asyncio.get_running_loop()) is False
        await client.rebind_to_current_loop()
        second = client.get_client()
        assert first is not second
        assert client._pool is not None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_hydrate_recovers_from_event_loop_error_without_sticky_fallback() -> None:
    """Closed-loop hydrate errors rebind + retry; must not stick memory_fallback."""

    class _LoopAwareStore:
        def __init__(self) -> None:
            self.values: dict[str, bytes] = {}
            self.get_calls = 0

        async def get(self, key: str) -> bytes | None:
            self.get_calls += 1
            if self.get_calls == 1:
                raise RuntimeError("Event loop is closed")
            return self.values.get(key)

        async def set(self, key: str, value: bytes, *, ex: int | None = None) -> None:
            del ex
            self.values[key] = value

        async def incr(self, key: str) -> int:
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
                generation = int(self.values.get(sequence_key, b"0")) + 1
                self.values[sequence_key] = str(generation).encode()
                self.values[generation_key] = str(generation).encode()
                return generation
            assert "checkpoint-publish-v2" in script
            checkpoint_key, generation_key, generation, value, _ttl = args
            assert isinstance(checkpoint_key, str)
            assert isinstance(generation_key, str)
            assert isinstance(generation, int)
            assert isinstance(value, bytes)
            if int(self.values.get(generation_key, b"0")) != generation:
                return 0
            self.values[checkpoint_key] = value
            return 1

        async def delete(self, key: str) -> None:
            self.values.pop(key, None)

    class _LoopAwareRedis:
        def __init__(self) -> None:
            self.store = _LoopAwareStore()
            self.rebinds = 0

        async def ping(self) -> bool:
            return True

        def get_client(self) -> _LoopAwareStore:
            return self.store

        async def rebind_to_current_loop(self) -> None:
            self.rebinds += 1

    redis = _LoopAwareRedis()
    seed = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    seed._memory.storage["evt-loop-hydrate"] = {}
    await seed._persist("evt-loop-hydrate")
    assert checkpoint_key_for_event("evt-loop-hydrate") in redis.store.values

    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    await saver._hydrate("evt-loop-hydrate")

    assert saver.memory_fallback is False
    assert redis.rebinds >= 1
    assert "evt-loop-hydrate" in saver._memory.storage


@pytest.mark.asyncio
async def test_new_checkpointer_clears_process_fallback_gauge_after_prior_fallback() -> None:
    from app.core.metrics import set_checkpoint_memory_fallback

    class _OkRedis:
        async def ping(self) -> bool:
            return True

        def get_client(self) -> Any:
            raise AssertionError("unused")

    set_checkpoint_memory_fallback(True)
    assert checkpoint_health_snapshot()["memory_fallback"] is True
    saver = await RedisCheckpointer.create(_OkRedis())  # type: ignore[arg-type]
    assert saver.memory_fallback is False
    assert checkpoint_health_snapshot()["memory_fallback"] is False


@pytest.mark.skipif(not _redis_reachable(), reason="Redis not reachable")
def test_checkpointer_survives_consecutive_asyncio_run_without_strategy_b_release() -> None:
    """Defense-in-depth: same RedisClient + saver across loops without Strategy B."""
    redis = RedisClient(url=REDIS_URL, max_connections=2)
    event_id = "evt-issue252-no-release"

    async def _persist_round() -> None:
        saver = await RedisCheckpointer.create(redis)
        assert saver.memory_fallback is False
        config = _config(event_id)
        saver._memory.put(
            config,
            _empty_checkpoint(),  # type: ignore[arg-type]
            {},  # type: ignore[arg-type]
            {},
        )
        await saver._persist(event_id)
        assert saver.memory_fallback is False

    async def _hydrate_round() -> None:
        saver = await RedisCheckpointer.create(redis)
        assert saver.memory_fallback is False
        await saver._hydrate(event_id)
        assert saver.memory_fallback is False
        assert event_id in saver._memory.storage

    try:
        asyncio.run(_persist_round())
        asyncio.run(_hydrate_round())
        health = get_checkpoint_health()
        assert health["memory_fallback"] is False
    finally:
        asyncio.run(redis.aclose())
