"""Redis-backed LangGraph checkpoints for ISSUE-048."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
import weakref
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
)
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from app.core.metrics import (
    record_checkpoint_fallback,
    record_checkpoint_loop_rebind,
    set_checkpoint_memory_fallback,
)
from app.core.redis_client import RedisClient, is_event_loop_error

logger = logging.getLogger(__name__)

CHECKPOINT_KEY_PREFIX = "shadowtrace:checkpoint:"
CHECKPOINT_GENERATION_KEY_PREFIX = "shadowtrace:checkpoint-generation:"
CHECKPOINT_GENERATION_SEQUENCE_KEY = "shadowtrace:checkpoint-generation-sequence"
CHECKPOINT_TTL_SECONDS = 7 * 24 * 60 * 60

# ARGV[1]=ttl, ARGV[2]=expected fence (-1 = force advance for cleanup/tombstone).
# When expected >= 0, refuse must still equal the caller's loaded/persisted basis
# before a new generation is allocated — blocking stale writers from minting N+2.
_CHECKPOINT_RESERVE_SCRIPT = """
-- checkpoint-reserve-generation-v3
local expected = tonumber(ARGV[2])
local current = tonumber(redis.call('GET', KEYS[2]) or '0')
if expected >= 0 and current ~= expected then
  return -1
end
local generation = redis.call('INCR', KEYS[1])
redis.call('SET', KEYS[2], generation, 'EX', ARGV[1])
return generation
"""

_CHECKPOINT_PUBLISH_SCRIPT = """
-- checkpoint-publish-v2
local current = tonumber(redis.call('GET', KEYS[2]) or '-1')
if current ~= tonumber(ARGV[1]) then
    return 0
end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
return 1
"""

_PERSIST_TRANSIENT_RETRIES = 2
_PERSIST_TRANSIENT_BACKOFF_S = 0.05
_FORCE_GENERATION_EXPECTED = -1

_PROCESS_LAST_FALLBACK_REMINDER_AT = 0.0
_CHECKPOINTERS: weakref.WeakSet[Any] = weakref.WeakSet()


def _register_checkpointer(saver: RedisCheckpointer) -> None:
    _CHECKPOINTERS.add(saver)


def _live_checkpointers() -> list[RedisCheckpointer]:
    return [saver for saver in list(_CHECKPOINTERS) if saver is not None]


def checkpoint_key_for_event(event_id: str) -> str:
    return f"{CHECKPOINT_KEY_PREFIX}{event_id}"


def checkpoint_generation_key_for_event(event_id: str) -> str:
    return f"{CHECKPOINT_GENERATION_KEY_PREFIX}{event_id}"


class CheckpointPersistenceError(RuntimeError):
    """Checkpoint durability could not be guaranteed; graph progress must halt."""


def _fallback_reason_category(message: str) -> str:
    lowered = message.lower()
    if "event loop" in lowered or "different loop" in lowered:
        return "event_loop"
    if "unavailable" in lowered:
        return "unavailable"
    if "load" in lowered:
        return "load"
    if "persist" in lowered or "publish" in lowered or "generation fence" in lowered:
        return "persist"
    if "delete" in lowered:
        return "delete"
    if "synchronous" in lowered:
        return "sync_api"
    return "other"


def get_checkpoint_health() -> dict[str, object]:
    """Process-wide checkpoint readiness snapshot for health probes (ISSUE-175)."""
    from app.core.config import get_settings
    from app.core.metrics import checkpoint_health_snapshot

    snapshot = checkpoint_health_snapshot()
    settings = get_settings()
    live = _live_checkpointers()
    if live:
        memory_fallback = any(saver.memory_fallback for saver in live)
        memory_pinned_thread_count = sum(saver.memory_pinned_thread_count for saver in live)
        persistence_failed_thread_count = sum(
            saver.persistence_failed_thread_count for saver in live
        )
    else:
        memory_fallback = bool(snapshot["memory_fallback"])
        memory_pinned_thread_count = 0
        persistence_failed_thread_count = 0
    durability_degraded = memory_fallback or persistence_failed_thread_count > 0
    return {
        "status": "degraded" if durability_degraded else "ok",
        "memory_fallback": memory_fallback,
        "recoverable": not durability_degraded,
        "fallback_triggers": snapshot["fallback_triggers"],
        "loop_rebinds": snapshot["loop_rebinds"],
        "memory_pinned_thread_count": memory_pinned_thread_count,
        "persistence_failed_thread_count": persistence_failed_thread_count,
        "redis_recovery_enabled": settings.checkpoint_attempt_redis_recovery,
    }


class RedisCheckpointer(BaseCheckpointSaver[str]):
    """LangGraph saver persisted as one JSON-safe Redis envelope per event."""

    def __init__(
        self,
        redis_client: RedisClient | None,
        *,
        ttl_seconds: int = CHECKPOINT_TTL_SECONDS,
        attempt_redis_recovery: bool = False,
        recovery_interval_seconds: float = 30.0,
        fallback_reminder_interval_seconds: float = 300.0,
    ) -> None:
        super().__init__()
        self._redis = redis_client
        self._ttl_seconds = ttl_seconds
        self._memory = InMemorySaver()
        self._serde = JsonPlusSerializer()
        self._attempt_redis_recovery = attempt_redis_recovery
        self._recovery_interval_seconds = recovery_interval_seconds
        self._fallback_reminder_interval_seconds = fallback_reminder_interval_seconds
        self._last_recovery_probe_at = 0.0
        self._memory_pinned_threads: set[str] = set()
        self._persistence_failed_threads: set[str] = set()
        # Last Redis generation this saver loaded or successfully published.
        # Persist refuses to mint a newer generation unless the fence still matches.
        self._thread_basis_generation: dict[str, int] = {}
        self._thread_locks: dict[
            str,
            tuple[asyncio.AbstractEventLoop, asyncio.Lock],
        ] = {}
        self.memory_fallback = False
        self._fallback_warned = False

    @property
    def recoverable(self) -> bool:
        """Whether this run qualifies as process-recoverable P0 execution."""
        return not self.memory_fallback

    @property
    def memory_pinned_thread_count(self) -> int:
        """Threads that must stay in-memory after fallback (ISSUE-175)."""
        return len(self._memory_pinned_threads)

    @property
    def persistence_failed_thread_count(self) -> int:
        """Threads halted because their latest checkpoint was not durable."""
        return len(self._persistence_failed_threads)

    @classmethod
    async def create(
        cls,
        redis_client: RedisClient | None,
        *,
        ttl_seconds: int = CHECKPOINT_TTL_SECONDS,
        attempt_redis_recovery: bool | None = None,
        recovery_interval_seconds: float | None = None,
        fallback_reminder_interval_seconds: float | None = None,
    ) -> RedisCheckpointer:
        from app.core.config import get_settings

        settings = get_settings()
        saver = cls(
            redis_client,
            ttl_seconds=ttl_seconds,
            attempt_redis_recovery=(
                settings.checkpoint_attempt_redis_recovery
                if attempt_redis_recovery is None
                else attempt_redis_recovery
            ),
            recovery_interval_seconds=(
                settings.checkpoint_redis_recovery_interval_seconds
                if recovery_interval_seconds is None
                else recovery_interval_seconds
            ),
            fallback_reminder_interval_seconds=(
                settings.checkpoint_fallback_reminder_interval_seconds
                if fallback_reminder_interval_seconds is None
                else fallback_reminder_interval_seconds
            ),
        )
        try:
            available = redis_client is not None and await redis_client.ping()
        except Exception:
            available = False
        if not available:
            saver._enable_memory_fallback("Redis checkpoint unavailable")
        else:
            # Clear sticky process gauge left by prior savers that Strategy B discarded.
            set_checkpoint_memory_fallback(False)
        _register_checkpointer(saver)
        return saver

    def _mark_sync_nonrecoverable(self) -> None:
        self._enable_memory_fallback(
            "Synchronous LangGraph checkpoint API cannot perform async Redis I/O"
        )

    def _pin_thread_to_memory(self, thread_id: str) -> None:
        self._memory_pinned_threads.add(thread_id)

    def _uses_redis_for_thread(self, thread_id: str) -> bool:
        if self._redis is None or thread_id in self._memory_pinned_threads:
            return False
        return not self.memory_fallback

    async def _maybe_attempt_redis_recovery(self) -> None:
        if not self._attempt_redis_recovery or not self.memory_fallback or self._redis is None:
            return
        now = time.monotonic()
        if now - self._last_recovery_probe_at < self._recovery_interval_seconds:
            return
        self._last_recovery_probe_at = now
        try:
            if await self._redis.ping():
                self.memory_fallback = False
                set_checkpoint_memory_fallback(False)
                logger.info(
                    "checkpoint Redis recovered; new thread_ids resume Redis persistence "
                    "(%s thread(s) remain memory-pinned until event completion)",
                    len(self._memory_pinned_threads),
                )
        except Exception as exc:
            if is_event_loop_error(exc):
                try:
                    await self._rebind_redis_client()
                    if await self._redis.ping():
                        self.memory_fallback = False
                        set_checkpoint_memory_fallback(False)
                        record_checkpoint_loop_rebind(op="recovery_probe")
                        logger.info(
                            "checkpoint Redis recovered after event-loop rebind; "
                            "new thread_ids resume Redis persistence "
                            "(%s thread(s) remain memory-pinned)",
                            len(self._memory_pinned_threads),
                        )
                except Exception:
                    return
            return

    async def _rebind_redis_client(self) -> None:
        redis = self._redis
        if redis is None:
            return
        rebind = getattr(redis, "rebind_to_current_loop", None)
        if callable(rebind):
            await rebind()

    @staticmethod
    def _is_transient_redis_error(exc: BaseException) -> bool:
        if isinstance(exc, (ConnectionError, TimeoutError, asyncio.TimeoutError, OSError)):
            return True
        name = type(exc).__name__.lower()
        if "timeout" in name or "connection" in name:
            return True
        text = str(exc).lower()
        return any(
            marker in text
            for marker in (
                "timeout",
                "connection",
                "temporarily unavailable",
                "try again",
                "broken pipe",
            )
        )

    async def _redis_call_with_loop_retry(
        self,
        op: str,
        awaitable_factory: Any,
    ) -> Any:
        """Run a Redis awaitable; on closed/cross-loop errors, rebind once and retry."""
        try:
            return await awaitable_factory()
        except Exception as exc:
            if not is_event_loop_error(exc):
                raise
            logger.warning(
                "checkpoint Redis %s hit event-loop error; rebinding client and retrying",
                op,
                exc_info=True,
            )
            await self._rebind_redis_client()
            result = await awaitable_factory()
            record_checkpoint_loop_rebind(op=op)
            return result

    async def _redis_call_with_transient_retry(
        self,
        op: str,
        awaitable_factory: Any,
    ) -> Any:
        """Retry transient Redis I/O; event-loop rebind still happens per attempt."""
        attempt = 0
        while True:
            try:
                return await self._redis_call_with_loop_retry(op, awaitable_factory)
            except Exception as exc:
                if attempt >= _PERSIST_TRANSIENT_RETRIES or not self._is_transient_redis_error(exc):
                    raise
                attempt += 1
                logger.warning(
                    "checkpoint Redis %s transient failure (attempt %s/%s); retrying",
                    op,
                    attempt,
                    _PERSIST_TRANSIENT_RETRIES,
                    exc_info=True,
                )
                await asyncio.sleep(_PERSIST_TRANSIENT_BACKOFF_S * attempt)

    def _enable_memory_fallback(self, message: str, *, exc_info: bool = False) -> None:
        global _PROCESS_LAST_FALLBACK_REMINDER_AT

        already_active = self.memory_fallback
        if not self._fallback_warned:
            logger.warning(
                "%s; using in-memory fallback (process restart cannot recover)",
                message,
                exc_info=exc_info,
            )
            self._fallback_warned = True
        elif not already_active:
            logger.warning("%s; using in-memory fallback", message, exc_info=exc_info)
        else:
            now = time.monotonic()
            if now - _PROCESS_LAST_FALLBACK_REMINDER_AT >= self._fallback_reminder_interval_seconds:
                _PROCESS_LAST_FALLBACK_REMINDER_AT = now
                logger.warning(
                    "checkpoint still on in-memory fallback (%s); "
                    "process restart cannot recover persisted graph state",
                    message,
                )

        if not already_active:
            self.memory_fallback = True
            set_checkpoint_memory_fallback(True)
            record_checkpoint_fallback(reason=_fallback_reason_category(message))

    # The synchronous protocol remains usable in-process, but explicitly
    # downgrades the saver so callers cannot mistake it for Redis-recoverable.
    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        self._mark_sync_nonrecoverable()
        return self._memory.get_tuple(config)

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        self._mark_sync_nonrecoverable()
        yield from self._memory.list(config, filter=filter, before=before, limit=limit)

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        self._mark_sync_nonrecoverable()
        return self._memory.put(config, checkpoint, metadata, new_versions)

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        self._mark_sync_nonrecoverable()
        self._memory.put_writes(config, writes, task_id, task_path=task_path)

    def delete_thread(self, thread_id: str) -> None:
        self._mark_sync_nonrecoverable()
        self._memory.delete_thread(thread_id)

    def _ensure_thread_readable(self, thread_id: str) -> None:
        if thread_id in self._persistence_failed_threads:
            raise CheckpointPersistenceError(
                f"checkpoint read blocked after prior persistence failure for thread_id={thread_id}"
            )

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id = str(config["configurable"]["thread_id"])
        self._ensure_thread_readable(thread_id)
        await self._maybe_attempt_redis_recovery()
        await self._hydrate(thread_id)
        return self._memory.get_tuple(config)

    async def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        if config is not None:
            thread_id = str(config["configurable"]["thread_id"])
            self._ensure_thread_readable(thread_id)
            await self._maybe_attempt_redis_recovery()
            await self._hydrate(thread_id)
        for item in self._memory.list(config, filter=filter, before=before, limit=limit):
            yield item

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        thread_id = str(config["configurable"]["thread_id"])
        await self._maybe_attempt_redis_recovery()
        result = self._memory.put(config, checkpoint, metadata, new_versions)
        await self._persist(thread_id)
        return result

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        thread_id = str(config["configurable"]["thread_id"])
        await self._maybe_attempt_redis_recovery()
        self._memory.put_writes(config, writes, task_id, task_path=task_path)
        await self._persist(thread_id)

    def _thread_lock(self, thread_id: str) -> asyncio.Lock:
        """Return a per-thread lock scoped to the active event loop.

        Idle locks may be rebound after a Celery loop recycle.  A lock still held
        on another loop means concurrent cross-loop use of the same saver, which
        is rejected instead of silently replacing the in-flight mutex.
        """
        loop = asyncio.get_running_loop()
        existing = self._thread_locks.get(thread_id)
        if existing is None:
            lock = asyncio.Lock()
            self._thread_locks[thread_id] = (loop, lock)
            return lock
        existing_loop, lock = existing
        if existing_loop is loop:
            return lock
        if lock.locked():
            raise CheckpointPersistenceError(
                f"checkpoint thread lock is held on another event loop for thread_id={thread_id}"
            )
        rebound = asyncio.Lock()
        self._thread_locks[thread_id] = (loop, rebound)
        return rebound

    async def adelete_thread(self, thread_id: str) -> None:
        async with self._thread_lock(thread_id):
            await self._adelete_thread_locked(thread_id)

    async def _adelete_thread_locked(self, thread_id: str) -> None:
        had_persistence_failure = thread_id in self._persistence_failed_threads
        self._memory.delete_thread(thread_id)
        self._memory_pinned_threads.discard(thread_id)
        self._thread_basis_generation.pop(thread_id, None)
        if self._redis is None:
            self._thread_locks.pop(thread_id, None)
            return
        redis = self._redis
        try:
            # Force-advance the fence before deleting the payload.  A pinned
            # thread may still have an older Redis value, and a late publisher
            # must not be able to make that value loadable again after cleanup.
            await self._advance_generation_fence(
                thread_id,
                op="cleanup fence",
                expected=_FORCE_GENERATION_EXPECTED,
            )
            await self._redis_call_with_loop_retry(
                "delete",
                lambda: redis.get_client().delete(checkpoint_key_for_event(thread_id)),
            )
            self._persistence_failed_threads.discard(thread_id)
            self._thread_locks.pop(thread_id, None)
        except Exception as exc:
            if had_persistence_failure:
                self._persistence_failed_threads.add(thread_id)
            await self._best_effort_delete_stale_payload(thread_id)
            if is_event_loop_error(exc):
                self._enable_memory_fallback(
                    "Redis checkpoint delete failed (event loop)",
                    exc_info=True,
                )
            else:
                self._enable_memory_fallback("Redis checkpoint delete failed", exc_info=True)
            # Cleanup is best-effort.  Keeping the saver degraded makes the
            # isolation failure visible without resurrecting local graph state.

    def _export(self, thread_id: str, *, generation: int) -> bytes | None:
        if thread_id not in self._memory.storage:
            return None
        payload = {
            "storage": self._memory.storage[thread_id],
            "writes": {
                key: value for key, value in self._memory.writes.items() if key[0] == thread_id
            },
            "blobs": {
                key: value for key, value in self._memory.blobs.items() if key[0] == thread_id
            },
        }
        type_tag, raw = self._serde.dumps_typed(payload)
        envelope = {
            "format": 2,
            "generation": generation,
            "serde": type_tag,
            "payload": base64.b64encode(raw).decode("ascii"),
        }
        return json.dumps(envelope, separators=(",", ":")).encode()

    def _import(self, thread_id: str, raw: bytes) -> None:
        envelope = json.loads(raw.decode())
        if envelope.get("format") not in {1, 2}:
            raise ValueError("unsupported Redis checkpoint envelope format")
        payload = self._serde.loads_typed(
            (
                envelope["serde"],
                base64.b64decode(envelope["payload"]),
            )
        )
        self._memory.storage[thread_id] = payload["storage"]
        self._memory.writes.update(payload.get("writes", {}))
        self._memory.blobs.update(payload.get("blobs", {}))

    async def _hydrate(self, thread_id: str) -> None:
        if not self._uses_redis_for_thread(thread_id) or thread_id in self._memory.storage:
            return
        redis = self._redis
        if redis is None:
            return
        try:
            raw = await self._redis_call_with_loop_retry(
                "load",
                lambda: redis.get_client().get(checkpoint_key_for_event(thread_id)),
            )
            if raw is not None:
                value = raw if isinstance(raw, bytes) else str(raw).encode()
                # Read payload before fence: if a writer reserves N+1 between
                # these reads, the old N is rejected.  This ordering makes the
                # two-command read linearizable without requiring MGET support.
                fence_raw = await self._redis_call_with_loop_retry(
                    "load generation fence",
                    lambda: redis.get_client().get(checkpoint_generation_key_for_event(thread_id)),
                )
                envelope = json.loads(value.decode())
                payload_generation = int(envelope.get("generation", 0))
                fence_generation = (
                    int(fence_raw if isinstance(fence_raw, bytes) else str(fence_raw))
                    if fence_raw is not None
                    else 0
                )
                is_legacy = envelope.get("format") == 1
                is_stale = (
                    fence_generation > 0 if is_legacy else payload_generation != fence_generation
                )
                if is_stale:
                    logger.error(
                        "rejecting stale Redis checkpoint for thread_id=%s "
                        "(payload generation=%s, fence generation=%s)",
                        thread_id,
                        payload_generation,
                        fence_generation,
                    )
                    return
                self._import(thread_id, value)
                self._thread_basis_generation[thread_id] = (
                    fence_generation if fence_generation > 0 else payload_generation
                )
        except Exception as exc:
            self._pin_thread_to_memory(thread_id)
            if is_event_loop_error(exc):
                self._enable_memory_fallback(
                    "Redis checkpoint load failed (event loop)",
                    exc_info=True,
                )
            else:
                self._enable_memory_fallback("Redis checkpoint load failed", exc_info=True)

    async def _best_effort_delete_stale_payload(self, thread_id: str) -> None:
        redis = self._redis
        if redis is None:
            return
        try:
            await self._redis_call_with_loop_retry(
                "stale payload isolation",
                lambda: redis.get_client().delete(checkpoint_key_for_event(thread_id)),
            )
        except Exception:
            logger.exception(
                "failed to isolate stale Redis checkpoint for thread_id=%s",
                thread_id,
            )

    def _mark_persistence_failure(
        self,
        thread_id: str,
        message: str,
        *,
        exc_info: bool = False,
    ) -> None:
        self._pin_thread_to_memory(thread_id)
        self._persistence_failed_threads.add(thread_id)
        self._enable_memory_fallback(message, exc_info=exc_info)

    async def _advance_generation_fence(
        self,
        thread_id: str,
        *,
        op: str,
        expected: int,
    ) -> int:
        redis = self._redis
        if redis is None:
            raise CheckpointPersistenceError(
                f"checkpoint generation fence unavailable for thread_id={thread_id}"
            )
        generation = await self._redis_call_with_transient_retry(
            op,
            lambda: redis.get_client().eval(
                _CHECKPOINT_RESERVE_SCRIPT,
                2,
                CHECKPOINT_GENERATION_SEQUENCE_KEY,
                checkpoint_generation_key_for_event(thread_id),
                self._ttl_seconds,
                expected,
            ),
        )
        return int(generation)

    async def _reserve_generation(self, thread_id: str) -> int:
        expected = self._thread_basis_generation.get(thread_id, 0)
        try:
            generation = await self._advance_generation_fence(
                thread_id,
                op="generation fence",
                expected=expected,
            )
        except Exception as exc:
            # If the fence itself cannot advance, remove the old payload when
            # possible.  Either outcome is explicit: execution halts here.
            await self._best_effort_delete_stale_payload(thread_id)
            self._mark_persistence_failure(
                thread_id,
                "Redis checkpoint generation fence failed",
                exc_info=True,
            )
            raise CheckpointPersistenceError(
                f"checkpoint generation fence failed for thread_id={thread_id}"
            ) from exc
        if generation < 0:
            self._mark_persistence_failure(
                thread_id,
                "Redis checkpoint generation fence rejected stale writer basis",
            )
            raise CheckpointPersistenceError(
                f"checkpoint generation fence rejected stale basis "
                f"for thread_id={thread_id} expected={expected}"
            )
        return generation

    async def _publish(self, thread_id: str, generation: int, raw: bytes) -> None:
        redis = self._redis
        if redis is None:
            raise CheckpointPersistenceError(
                f"checkpoint publish unavailable for thread_id={thread_id}"
            )
        try:
            published = await self._redis_call_with_transient_retry(
                "persist",
                lambda: redis.get_client().eval(
                    _CHECKPOINT_PUBLISH_SCRIPT,
                    2,
                    checkpoint_key_for_event(thread_id),
                    checkpoint_generation_key_for_event(thread_id),
                    generation,
                    raw,
                    self._ttl_seconds,
                ),
            )
        except Exception as exc:
            self._mark_persistence_failure(
                thread_id,
                "Redis checkpoint publish failed",
                exc_info=True,
            )
            raise CheckpointPersistenceError(
                f"checkpoint publish failed for thread_id={thread_id} generation={generation}"
            ) from exc
        if int(published) != 1:
            self._mark_persistence_failure(
                thread_id,
                "Redis checkpoint publish superseded by a newer generation",
            )
            raise CheckpointPersistenceError(
                f"checkpoint publish superseded for thread_id={thread_id} generation={generation}"
            )

    async def _persist(self, thread_id: str) -> None:
        # LangGraph may schedule aput/aput_writes concurrently for one thread.
        # Serialize the complete reserve/export/publish sequence within a saver;
        # Redis fencing still arbitrates independent processes and savers.
        async with self._thread_lock(thread_id):
            await self._persist_locked(thread_id)

    async def _persist_locked(self, thread_id: str) -> None:
        if thread_id in self._persistence_failed_threads:
            raise CheckpointPersistenceError(
                f"checkpoint persistence blocked after prior failure for thread_id={thread_id}"
            )
        if not self._uses_redis_for_thread(thread_id):
            if self.memory_fallback:
                self._pin_thread_to_memory(thread_id)
            return
        if thread_id not in self._memory.storage:
            return
        generation = await self._reserve_generation(thread_id)
        raw = self._export(thread_id, generation=generation)
        if raw is not None:
            await self._publish(thread_id, generation, raw)
            self._thread_basis_generation[thread_id] = generation


async def invalidate_event_checkpoint(
    event_id: str,
    *,
    redis_client: RedisClient | None = None,
) -> None:
    """Force-advance generation fence and delete stale checkpoint payload (ISSUE-296)."""
    saver = await build_checkpointer(redis_client)
    await saver.adelete_thread(event_id)


async def build_checkpointer(
    redis_client: RedisClient | None,
) -> RedisCheckpointer:
    return await RedisCheckpointer.create(redis_client)


def reset_checkpoint_health_state_for_tests() -> None:
    """Reset module reminder clock, metrics counters, and registry between tests."""
    global _PROCESS_LAST_FALLBACK_REMINDER_AT, _CHECKPOINTERS
    _PROCESS_LAST_FALLBACK_REMINDER_AT = 0.0
    _CHECKPOINTERS = weakref.WeakSet()
    from app.core.metrics import reset_checkpoint_metrics_for_tests

    reset_checkpoint_metrics_for_tests()
    set_checkpoint_memory_fallback(False)


__all__ = [
    "CHECKPOINT_GENERATION_KEY_PREFIX",
    "CHECKPOINT_GENERATION_SEQUENCE_KEY",
    "CHECKPOINT_KEY_PREFIX",
    "CHECKPOINT_TTL_SECONDS",
    "CheckpointPersistenceError",
    "RedisCheckpointer",
    "build_checkpointer",
    "checkpoint_generation_key_for_event",
    "checkpoint_key_for_event",
    "get_checkpoint_health",
    "invalidate_event_checkpoint",
    "reset_checkpoint_health_state_for_tests",
]
