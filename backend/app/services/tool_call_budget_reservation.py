"""Atomic grant attempt reservation with shadow namespace isolation (ISSUE-134)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.models.tool_call_grant import ToolCallMode

logger = logging.getLogger(__name__)

PRODUCTION_BUDGET_KEY_PREFIX = "shadowtrace:tool_grant_budget:production:"
SHADOW_BUDGET_KEY_PREFIX = "shadowtrace:tool_grant_budget:shadow:"


def budget_reservation_key(
    mode: ToolCallMode,
    *,
    namespace_key: str,
    grant_id: str,
) -> str:
    if mode is ToolCallMode.SHADOW:
        return f"{SHADOW_BUDGET_KEY_PREFIX}{namespace_key}:{grant_id}"
    if mode is ToolCallMode.PRODUCTION:
        return f"{PRODUCTION_BUDGET_KEY_PREFIX}{namespace_key}:{grant_id}"
    return f"shadowtrace:tool_grant_budget:compat:{namespace_key}:{grant_id}"


@dataclass
class _GrantBudgetCounter:
    reserved: int = 0
    consumed: int = 0


@dataclass
class ToolCallBudgetReservationStore:
    """In-process fallback counters keyed by reservation key."""

    counters: dict[str, _GrantBudgetCounter] = field(default_factory=dict)


class ToolCallBudgetReservationService:
    """Reserve/consume per-grant call budget without touching production ledgers in shadow mode."""

    def __init__(
        self,
        redis: object | None = None,
        *,
        memory_store: ToolCallBudgetReservationStore | None = None,
    ) -> None:
        self._redis = redis
        self._memory = memory_store or ToolCallBudgetReservationStore()
        self._redis_degraded = False

    async def reserve(
        self,
        *,
        mode: ToolCallMode,
        namespace_key: str,
        grant_id: str,
        max_calls: int,
    ) -> int:
        """Atomically reserve one attempt slot; returns 1-based seq or raises ValueError."""

        if max_calls < 1:
            raise ValueError("max_calls must be >= 1")
        key = budget_reservation_key(mode, namespace_key=namespace_key, grant_id=grant_id)
        client = await self._redis_client()
        if client is None:
            counter = self._memory.counters.setdefault(key, _GrantBudgetCounter())
            if counter.reserved >= max_calls:
                raise ValueError("grant max_calls exhausted")
            counter.reserved += 1
            return counter.reserved

        script = """
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        local limit = tonumber(ARGV[1])
        if current >= limit then
            return -1
        end
        return redis.call('INCR', KEYS[1])
        """
        try:
            seq = await client.eval(script, 1, key, str(max_calls))
            seq_int = int(seq)
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("reserve", grant_id)
            counter = self._memory.counters.setdefault(key, _GrantBudgetCounter())
            if counter.reserved >= max_calls:
                raise ValueError("grant max_calls exhausted") from None
            counter.reserved += 1
            return counter.reserved
        if seq_int < 0:
            raise ValueError("grant max_calls exhausted")
        return seq_int

    async def release(
        self,
        *,
        mode: ToolCallMode,
        namespace_key: str,
        grant_id: str,
        count: int = 1,
    ) -> None:
        """Release reserved attempt slots (e.g. when PG authoritative reserve fails)."""

        if count < 1:
            return
        key = budget_reservation_key(mode, namespace_key=namespace_key, grant_id=grant_id)
        client = await self._redis_client()
        if client is None:
            counter = self._memory.counters.setdefault(key, _GrantBudgetCounter())
            counter.reserved = max(0, counter.reserved - count)
            return

        script = """
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        local dec = tonumber(ARGV[1])
        if current <= 0 then
            return 0
        end
        local actual = dec
        if current < dec then
            actual = current
        end
        return redis.call('DECRBY', KEYS[1], actual)
        """
        try:
            await client.eval(script, 1, key, str(count))
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("release", grant_id)
            counter = self._memory.counters.setdefault(key, _GrantBudgetCounter())
            counter.reserved = max(0, counter.reserved - count)

    async def get_reserved_count(
        self,
        *,
        mode: ToolCallMode,
        namespace_key: str,
        grant_id: str,
    ) -> int:
        key = budget_reservation_key(mode, namespace_key=namespace_key, grant_id=grant_id)
        client = await self._redis_client()
        if client is None:
            return self._memory.counters.get(key, _GrantBudgetCounter()).reserved
        try:
            raw = await client.get(key)
            return int(raw or 0)
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("get_reserved_count", grant_id)
            return self._memory.counters.get(key, _GrantBudgetCounter()).reserved

    async def _redis_client(self) -> Any | None:
        if self._redis is None:
            return None
        try:
            ping = getattr(self._redis, "ping", None)
            if callable(ping):
                if not await ping():
                    self._mark_redis_degraded("ping")
                    return None
            get_client = getattr(self._redis, "get_client", None)
            if callable(get_client):
                return get_client()
            return self._redis
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("ping")
            return None

    def _mark_redis_degraded(self, op: str, grant_id: str | None = None) -> None:
        if not self._redis_degraded:
            logger.warning(
                "tool grant budget Redis unavailable; using in-process counters op=%s grant_id=%s",
                op,
                grant_id,
            )
        self._redis_degraded = True


__all__ = [
    "PRODUCTION_BUDGET_KEY_PREFIX",
    "SHADOW_BUDGET_KEY_PREFIX",
    "ToolCallBudgetReservationService",
    "ToolCallBudgetReservationStore",
    "budget_reservation_key",
]
