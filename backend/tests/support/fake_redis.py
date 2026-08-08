"""In-memory Redis double with SET NX EX semantics (ISSUE-264 / ISSUE-283)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from app.core.redis_client import RedisClient


@dataclass
class _Entry:
    value: str
    expires_at: float | None = None


class InMemoryFakeRedis:
    """Minimal async Redis stand-in supporting NX/EX/TTL used by EventLease."""

    def __init__(self) -> None:
        self._store: dict[str, _Entry] = {}

    def _purge_expired(self, key: str) -> None:
        entry = self._store.get(key)
        if entry is None:
            return
        if entry.expires_at is not None and entry.expires_at <= time.monotonic():
            del self._store[key]

    async def set(
        self,
        key: str,
        value: str,
        *,
        ex: int | None = None,
        nx: bool = False,
        **kwargs: Any,
    ) -> bool | None:
        del kwargs
        self._purge_expired(key)
        if nx and key in self._store:
            return None
        expires_at = time.monotonic() + ex if ex is not None else None
        self._store[key] = _Entry(value=value, expires_at=expires_at)
        return True

    async def get(self, key: str) -> bytes | None:
        self._purge_expired(key)
        entry = self._store.get(key)
        if entry is None:
            return None
        return entry.value.encode("utf-8")

    async def delete(self, key: str) -> int:
        self._purge_expired(key)
        if key in self._store:
            del self._store[key]
            return 1
        return 0

    async def ttl(self, key: str) -> int:
        self._purge_expired(key)
        entry = self._store.get(key)
        if entry is None:
            return -2
        if entry.expires_at is None:
            return -1
        remaining = int(entry.expires_at - time.monotonic())
        return max(remaining, 0)

    def register_script(self, _script: str) -> Any:
        store = self._store

        async def _release(keys: list[str], args: list[str]) -> int:
            key = keys[0]
            owner = args[0]
            entry = store.get(key)
            if entry is None:
                return -1
            if entry.value != owner:
                return 0
            del store[key]
            return 1

        return _release


class InMemoryFakeRedisClient:
    """``RedisClient``-shaped wrapper for ``InMemoryFakeRedis``."""

    def __init__(self, raw: InMemoryFakeRedis | None = None) -> None:
        self._raw = raw or InMemoryFakeRedis()

    async def ping(self) -> bool:
        return True

    def get_client(self) -> InMemoryFakeRedis:
        return self._raw

    async def aclose(self) -> None:
        return None


def patch_redis_client(monkeypatch: Any, raw: InMemoryFakeRedis | None = None) -> InMemoryFakeRedis:
    """Replace ``RedisClient`` network I/O with an in-memory fake for API tests."""
    fake = raw or InMemoryFakeRedis()
    wrapper = InMemoryFakeRedisClient(fake)

    async def _ping(self: RedisClient) -> bool:
        return True

    def _get_client(self: RedisClient) -> InMemoryFakeRedis:
        return wrapper.get_client()

    async def _aclose(self: RedisClient) -> None:
        return None

    monkeypatch.setattr(RedisClient, "ping", _ping)
    monkeypatch.setattr(RedisClient, "get_client", _get_client)
    monkeypatch.setattr(RedisClient, "aclose", _aclose)
    return fake
