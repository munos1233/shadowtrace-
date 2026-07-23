"""LangGraph checkpoint persistence (ISSUE-048).

Redis key: ``shadowtrace:checkpoint:{event_id}`` with 7-day TTL.
Falls back to in-memory storage when Redis is unavailable.
"""

from __future__ import annotations

import logging
import pickle
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

from app.core.redis_client import RedisClient

logger = logging.getLogger(__name__)

CHECKPOINT_KEY_PREFIX = "shadowtrace:checkpoint:"
CHECKPOINT_TTL_SECONDS = 7 * 24 * 3600


def checkpoint_key_for_event(event_id: str) -> str:
    """Return the Redis key for an investigation thread."""
    return f"{CHECKPOINT_KEY_PREFIX}{event_id}"


class RedisCheckpointer(BaseCheckpointSaver[str]):
    """Redis-backed checkpointer delegating to ``InMemorySaver`` for graph ops."""

    def __init__(
        self,
        redis_client: RedisClient | None = None,
        *,
        ttl_seconds: int = CHECKPOINT_TTL_SECONDS,
    ) -> None:
        super().__init__()
        self._redis = redis_client
        self._ttl = ttl_seconds
        self._inner = InMemorySaver()
        self.memory_fallback = False

    @classmethod
    async def create(
        cls,
        redis_client: RedisClient | None = None,
        *,
        ttl_seconds: int = CHECKPOINT_TTL_SECONDS,
    ) -> RedisCheckpointer:
        """Build a checkpointer, falling back to memory when Redis is down."""
        saver = cls(redis_client, ttl_seconds=ttl_seconds)
        if redis_client is None or not await redis_client.ping():
            saver.memory_fallback = True
            logger.warning(
                "Redis checkpoint unavailable; using in-memory fallback "
                "(process restart will not recover state)"
            )
        return saver

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        return self._inner.get_tuple(config)

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        yield from self._inner.list(config, filter=filter, before=before, limit=limit)

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        return self._inner.put(config, checkpoint, metadata, new_versions)

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        self._inner.put_writes(config, writes, task_id, task_path=task_path)

    def delete_thread(self, thread_id: str) -> None:
        self._inner.delete_thread(thread_id)

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id = config["configurable"]["thread_id"]
        await self._ahydrate_thread(thread_id)
        return self._inner.get_tuple(config)

    async def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        if config is not None:
            await self._ahydrate_thread(config["configurable"]["thread_id"])
        for item in self._inner.list(config, filter=filter, before=before, limit=limit):
            yield item

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        result = self._inner.put(config, checkpoint, metadata, new_versions)
        thread_id = config["configurable"]["thread_id"]
        await self._apersist_thread(thread_id)
        return result

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        self._inner.put_writes(config, writes, task_id, task_path=task_path)
        thread_id = config["configurable"]["thread_id"]
        await self._apersist_thread(thread_id)

    async def adelete_thread(self, thread_id: str) -> None:
        self._inner.delete_thread(thread_id)
        await self._delete_redis_key(thread_id)

    def _export_thread_state(self, thread_id: str) -> bytes | None:
        if thread_id not in self._inner.storage:
            return None
        writes = {key: value for key, value in self._inner.writes.items() if key[0] == thread_id}
        blobs = {key: value for key, value in self._inner.blobs.items() if key[0] == thread_id}
        payload = {
            "storage": self._inner.storage[thread_id],
            "writes": writes,
            "blobs": blobs,
        }
        return pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)

    def _import_thread_state(self, thread_id: str, raw: bytes) -> None:
        payload = pickle.loads(raw)
        self._inner.storage[thread_id] = payload["storage"]
        for key, value in payload.get("writes", {}).items():
            self._inner.writes[key] = value
        for key, value in payload.get("blobs", {}).items():
            self._inner.blobs[key] = value

    async def _ahydrate_thread(self, thread_id: str) -> None:
        if self.memory_fallback or self._redis is None:
            return
        if thread_id in self._inner.storage:
            return
        try:
            raw = await self._redis.get_client().get(checkpoint_key_for_event(thread_id))
            if raw:
                self._import_thread_state(thread_id, raw)
        except Exception:
            logger.warning(
                "failed to load checkpoint from Redis for event=%s; continuing empty",
                thread_id,
                exc_info=True,
            )

    async def _apersist_thread(self, thread_id: str) -> None:
        if self.memory_fallback or self._redis is None:
            return
        blob = self._export_thread_state(thread_id)
        if blob is None:
            return
        try:
            await self._redis.get_client().set(
                checkpoint_key_for_event(thread_id),
                blob,
                ex=self._ttl,
            )
        except Exception:
            logger.warning(
                "failed to persist checkpoint to Redis for event=%s",
                thread_id,
                exc_info=True,
            )

    async def _delete_redis_key(self, thread_id: str) -> None:
        if self.memory_fallback or self._redis is None:
            return
        try:
            await self._redis.get_client().delete(checkpoint_key_for_event(thread_id))
        except Exception:
            logger.debug("failed to delete redis checkpoint for %s", thread_id, exc_info=True)


async def build_checkpointer(
    redis_client: RedisClient | None = None,
) -> RedisCheckpointer:
    """Factory used by workflow runtime to obtain a configured checkpointer."""
    return await RedisCheckpointer.create(redis_client)


__all__ = [
    "CHECKPOINT_KEY_PREFIX",
    "CHECKPOINT_TTL_SECONDS",
    "RedisCheckpointer",
    "build_checkpointer",
    "checkpoint_key_for_event",
]
