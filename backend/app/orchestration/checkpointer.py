"""Redis-backed LangGraph checkpoints for ISSUE-048."""

from __future__ import annotations

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
CHECKPOINT_GEN_KEY_PREFIX = "shadowtrace:checkpoint:gen:"
CHECKPOINT_TTL_SECONDS = 7 * 24 * 60 * 60
CHECKPOINT_ENVELOPE_FORMAT = 2

_PROCESS_LAST_FALLBACK_REMINDER_AT = 0.0
_CHECKPOINTERS: weakref.WeakSet[Any] = weakref.WeakSet()


def _register_checkpointer(saver: RedisCheckpointer) -> None:
    _CHECKPOINTERS.add(saver)


def _live_checkpointers() -> list[RedisCheckpointer]:
    return [saver for saver in list(_CHECKPOINTERS) if saver is not None]


def checkpoint_key_for_event(event_id: str) -> str:
    return f"{CHECKPOINT_KEY_PREFIX}{event_id}"


def checkpoint_gen_key_for_event(event_id: str) -> str:
    return f"{CHECKPOINT_GEN_KEY_PREFIX}{event_id}"


def _fallback_reason_category(message: str) -> str:
    lowered = message.lower()
    if "event loop" in lowered or "different loop" in lowered:
        return "event_loop"
    if "unavailable" in lowered:
        return "unavailable"
    if "load" in lowered:
        return "load"
    if "persist" in lowered:
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
    else:
        memory_fallback = bool(snapshot["memory_fallback"])
        memory_pinned_thread_count = 0
    return {
        "status": "degraded" if memory_fallback else "ok",
        "memory_fallback": memory_fallback,
        "recoverable": not memory_fallback,
        "fallback_triggers": snapshot["fallback_triggers"],
        "loop_rebinds": snapshot["loop_rebinds"],
        "memory_pinned_thread_count": memory_pinned_thread_count,
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
        self._thread_generations: dict[str, int] = {}
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

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id = str(config["configurable"]["thread_id"])
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

    async def adelete_thread(self, thread_id: str) -> None:
        self._memory.delete_thread(thread_id)
        self._memory_pinned_threads.discard(thread_id)
        self._thread_generations.pop(thread_id, None)
        if self._redis is None:
            return
        redis = self._redis
        try:
            await self._redis_call_with_loop_retry(
                "delete",
                lambda: self._redis_delete_thread_keys(redis, thread_id),
            )
        except Exception as exc:
            if is_event_loop_error(exc):
                self._enable_memory_fallback(
                    "Redis checkpoint delete failed (event loop)",
                    exc_info=True,
                )
            else:
                self._enable_memory_fallback("Redis checkpoint delete failed", exc_info=True)
            # Memory thread already deleted; align with persist/hydrate (no re-raise).

    @staticmethod
    def _generation_from_envelope(envelope: dict[str, Any]) -> int:
        fmt = envelope.get("format", 1)
        if fmt == 1:
            return 1
        if fmt != CHECKPOINT_ENVELOPE_FORMAT:
            raise ValueError("unsupported Redis checkpoint envelope format")
        return int(envelope["generation"])

    def _peek_generation(self, raw: bytes) -> int:
        envelope = json.loads(raw.decode())
        return self._generation_from_envelope(envelope)

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
            "format": CHECKPOINT_ENVELOPE_FORMAT,
            "generation": generation,
            "serde": type_tag,
            "payload": base64.b64encode(raw).decode("ascii"),
        }
        return json.dumps(envelope, separators=(",", ":")).encode()

    def _import(self, thread_id: str, raw: bytes) -> int:
        envelope = json.loads(raw.decode())
        generation = self._generation_from_envelope(envelope)
        payload = self._serde.loads_typed(
            (
                envelope["serde"],
                base64.b64decode(envelope["payload"]),
            )
        )
        self._memory.storage[thread_id] = payload["storage"]
        self._memory.writes.update(payload.get("writes", {}))
        self._memory.blobs.update(payload.get("blobs", {}))
        return generation

    async def _redis_delete_thread_keys(self, redis: RedisClient, thread_id: str) -> None:
        client = redis.get_client()
        await client.delete(checkpoint_key_for_event(thread_id))
        await client.delete(checkpoint_gen_key_for_event(thread_id))

    async def _redis_persist_checkpoint(
        self,
        redis: RedisClient,
        thread_id: str,
        *,
        generation: int,
        raw: bytes,
    ) -> None:
        client = redis.get_client()
        payload_key = checkpoint_key_for_event(thread_id)
        gen_key = checkpoint_gen_key_for_event(thread_id)
        await client.set(payload_key, raw, ex=self._ttl_seconds)
        await client.set(gen_key, str(generation).encode(), ex=self._ttl_seconds)

    async def _redis_tombstone_checkpoint(
        self,
        redis: RedisClient,
        thread_id: str,
        *,
        generation: int,
    ) -> None:
        """Bump generation fence and drop payload so stale values cannot resume."""
        client = redis.get_client()
        gen_key = checkpoint_gen_key_for_event(thread_id)
        payload_key = checkpoint_key_for_event(thread_id)
        await client.set(gen_key, str(generation).encode(), ex=self._ttl_seconds)
        await client.delete(payload_key)

    async def _tombstone(self, thread_id: str, generation: int) -> None:
        if self._redis is None:
            return
        redis = self._redis
        try:
            await self._redis_call_with_loop_retry(
                "tombstone",
                lambda: self._redis_tombstone_checkpoint(
                    redis,
                    thread_id,
                    generation=generation,
                ),
            )
        except Exception:
            logger.warning(
                "checkpoint tombstone failed for thread=%s generation=%s",
                thread_id,
                generation,
                exc_info=True,
            )

    async def _read_fence_generation(self, redis: RedisClient, thread_id: str) -> int:
        raw = await self._redis_call_with_loop_retry(
            "load_fence",
            lambda: redis.get_client().get(checkpoint_gen_key_for_event(thread_id)),
        )
        if raw is None:
            return 0
        if isinstance(raw, bytes):
            return int(raw.decode())
        return int(str(raw))

    async def _hydrate(self, thread_id: str) -> None:
        if not self._uses_redis_for_thread(thread_id) or thread_id in self._memory.storage:
            return
        redis = self._redis
        if redis is None:
            return
        try:
            fence_generation = await self._read_fence_generation(redis, thread_id)
            raw = await self._redis_call_with_loop_retry(
                "load",
                lambda: redis.get_client().get(checkpoint_key_for_event(thread_id)),
            )
            if raw is None:
                return
            value = raw if isinstance(raw, bytes) else str(raw).encode()
            payload_generation = self._peek_generation(value)
            if fence_generation > 0 and payload_generation < fence_generation:
                logger.warning(
                    "checkpoint rejected stale payload for thread=%s "
                    "(payload_generation=%s fence_generation=%s)",
                    thread_id,
                    payload_generation,
                    fence_generation,
                )
                return
            imported_generation = self._import(thread_id, value)
            self._thread_generations[thread_id] = imported_generation
        except Exception as exc:
            self._pin_thread_to_memory(thread_id)
            if is_event_loop_error(exc):
                self._enable_memory_fallback(
                    "Redis checkpoint load failed (event loop)",
                    exc_info=True,
                )
            else:
                self._enable_memory_fallback("Redis checkpoint load failed", exc_info=True)

    async def _persist(self, thread_id: str) -> None:
        if not self._uses_redis_for_thread(thread_id):
            if self.memory_fallback:
                self._pin_thread_to_memory(thread_id)
            return
        generation = self._thread_generations.get(thread_id, 0) + 1
        raw = self._export(thread_id, generation=generation)
        if raw is None:
            return
        redis = self._redis
        if redis is None:
            return
        try:
            await self._redis_call_with_loop_retry(
                "persist",
                lambda: self._redis_persist_checkpoint(
                    redis,
                    thread_id,
                    generation=generation,
                    raw=raw,
                ),
            )
            self._thread_generations[thread_id] = generation
        except Exception as exc:
            await self._tombstone(thread_id, generation)
            self._pin_thread_to_memory(thread_id)
            if is_event_loop_error(exc):
                self._enable_memory_fallback(
                    "Redis checkpoint persist failed (event loop)",
                    exc_info=True,
                )
            else:
                self._enable_memory_fallback(
                    "Redis checkpoint persist failed",
                    exc_info=True,
                )


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
    "CHECKPOINT_ENVELOPE_FORMAT",
    "CHECKPOINT_GEN_KEY_PREFIX",
    "CHECKPOINT_KEY_PREFIX",
    "CHECKPOINT_TTL_SECONDS",
    "RedisCheckpointer",
    "build_checkpointer",
    "checkpoint_gen_key_for_event",
    "checkpoint_key_for_event",
    "get_checkpoint_health",
    "reset_checkpoint_health_state_for_tests",
]
