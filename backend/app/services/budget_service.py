"""Global Token/Cost budget service (ISSUE-029 / intro §4.10)."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import Settings, get_settings
from app.core.errors import BudgetExceededError
from app.core.redis_client import RedisClient
from app.models.budget import BudgetScope, BudgetSnapshot
from app.models.enums import Severity
from app.models.workflow import (
    EVENT_BUDGET_SEVERITY_MULTIPLIER,
    EVENT_COST_BUDGET_USD,
    EVENT_TOKEN_BUDGET,
    GLOBAL_TOKEN_BUDGET,
    MODEL_PRICE_TABLE,
    PER_AGENT_TOKEN_CAP,
)

logger = logging.getLogger(__name__)

SYSTEM_BUDGET_KEY = "shadowtrace:budget:system"
EVENT_BUDGET_KEY_PREFIX = "shadowtrace:budget:event:"

_FIELD_TOKENS = "tokens"
_FIELD_COST_USD = "cost_usd"
_FIELD_TOOL_CALLS = "tool_calls"


class BudgetUsage(BaseModel):
    """Aggregated budget counters for one event plus the system total."""

    model_config = ConfigDict(extra="forbid")

    event_tokens: int = Field(default=0, ge=0)
    event_cost_usd: float = Field(default=0.0, ge=0.0)
    tool_calls: int = Field(default=0, ge=0)
    per_agent: dict[str, dict[str, int | float]] = Field(default_factory=dict)
    system_tokens: int = Field(default=0, ge=0)


@runtime_checkable
class BudgetUsageWriter(Protocol):
    """Optional sink that mirrors usage into EventContext.budget_usage."""

    async def write_budget_usage(self, event_id: str, usage: BudgetUsage) -> None: ...


@dataclass
class _EventCounters:
    tokens: int = 0
    cost_usd: float = 0.0
    tool_calls: int = 0
    per_agent_tokens: dict[str, int] = field(default_factory=dict)
    per_agent_tool_calls: dict[str, int] = field(default_factory=dict)


@dataclass
class _MemoryStore:
    system_tokens: int = 0
    events: dict[str, _EventCounters] = field(default_factory=dict)


def _event_key(event_id: str) -> str:
    return f"{EVENT_BUDGET_KEY_PREFIX}{event_id}"


def _agent_tokens_field(agent_name: str) -> str:
    return f"agent:{agent_name}:tokens"


def _agent_tools_field(agent_name: str) -> str:
    return f"agent:{agent_name}:tool_calls"


def _decode_int(raw: Any) -> int:
    if raw is None:
        return 0
    if isinstance(raw, (bytes, bytearray, memoryview)):
        raw = bytes(raw).decode()
    return int(float(raw))


def _decode_float(raw: Any) -> float:
    if raw is None:
        return 0.0
    if isinstance(raw, (bytes, bytearray, memoryview)):
        raw = bytes(raw).decode()
    return float(raw)


def compute_llm_cost_usd(
    model_name: str,
    prompt_tokens: int,
    completion_tokens: int,
    *,
    force_zero: bool = False,
) -> float:
    """Convert token counts to USD using MODEL_PRICE_TABLE (per 1k tokens)."""

    if force_zero:
        return 0.0
    prices = MODEL_PRICE_TABLE.get(model_name)
    if prices is None:
        logger.debug("MODEL_PRICE_TABLE missing entry for %s; treating cost as 0", model_name)
        return 0.0
    prompt_price, completion_price = prices
    cost = (prompt_tokens / 1000.0) * prompt_price + (completion_tokens / 1000.0) * completion_price
    return round(cost, 8)


class BudgetService:
    """system / event / agent token+cost meter with Redis counters and memory fallback."""

    def __init__(
        self,
        redis: RedisClient | None = None,
        *,
        usage_writer: BudgetUsageWriter | None = None,
        settings: Settings | None = None,
        enabled: bool | None = None,
    ) -> None:
        self._redis = redis
        self._usage_writer = usage_writer
        self._settings = settings or get_settings()
        self._enabled = self._settings.budget_enabled if enabled is None else enabled
        self._memory = _MemoryStore()
        self._redis_degraded = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    def allocate_event_budget(self, severity: Severity | str) -> int:
        """Scale EVENT_TOKEN_BUDGET by severity for adaptive investigation."""

        value = severity.value if isinstance(severity, Severity) else str(severity).strip().lower()
        multiplier = EVENT_BUDGET_SEVERITY_MULTIPLIER.get(value, 1.0)
        base = int(self._settings.event_token_budget or EVENT_TOKEN_BUDGET)
        return max(1, int(math.floor(base * multiplier)))

    async def charge_llm(
        self,
        event_id: str,
        agent_name: str,
        model_name: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> BudgetSnapshot:
        prompt_tokens = max(0, int(prompt_tokens))
        completion_tokens = max(0, int(completion_tokens))
        total_tokens = prompt_tokens + completion_tokens
        force_zero = self._settings.llm_mode.strip().lower() == "mock"
        cost = compute_llm_cost_usd(
            model_name,
            prompt_tokens,
            completion_tokens,
            force_zero=force_zero,
        )
        await self._apply_llm_charge(
            event_id=event_id,
            agent_name=agent_name,
            tokens=total_tokens,
            cost_usd=cost,
        )
        usage = await self.get_usage(event_id)
        await self._mirror_usage(event_id, usage)
        return self._snapshot(event_id, agent_name, usage, scope=BudgetScope.EVENT)

    async def charge_tool(
        self,
        event_id: str,
        agent_name: str,
        tool_name: str,
    ) -> BudgetSnapshot:
        del tool_name  # counted in aggregate tool_calls only
        await self._apply_tool_charge(event_id=event_id, agent_name=agent_name)
        usage = await self.get_usage(event_id)
        await self._mirror_usage(event_id, usage)
        return self._snapshot(event_id, agent_name, usage, scope=BudgetScope.EVENT)

    async def check(self, event_id: str, agent_name: str) -> None:
        if not self._enabled:
            return
        usage = await self.get_usage(event_id)
        self._raise_if_exceeded(event_id, agent_name, usage)

    async def get_usage(self, event_id: str) -> BudgetUsage:
        redis_usage = await self._read_redis_usage(event_id)
        if redis_usage is not None:
            return redis_usage
        return self._read_memory_usage(event_id)

    async def reset_event(self, event_id: str) -> None:
        self._memory.events.pop(event_id, None)
        client = await self._redis_client()
        if client is None:
            return
        try:
            await client.delete(_event_key(event_id))
        except Exception:  # noqa: BLE001 — degrade path must not raise
            self._mark_redis_degraded("reset_event", event_id)

    def _snapshot(
        self,
        event_id: str,
        agent_name: str | None,
        usage: BudgetUsage,
        *,
        scope: BudgetScope | None,
    ) -> BudgetSnapshot:
        return BudgetSnapshot(
            scope=scope,
            event_id=event_id,
            agent_name=agent_name,
            event_tokens=usage.event_tokens,
            event_cost_usd=usage.event_cost_usd,
            tool_calls=usage.tool_calls,
            system_tokens=usage.system_tokens,
            per_agent=dict(usage.per_agent),
            event_token_budget=int(self._settings.event_token_budget or EVENT_TOKEN_BUDGET),
            event_cost_budget_usd=float(
                self._settings.event_cost_budget_usd or EVENT_COST_BUDGET_USD
            ),
            per_agent_token_cap=int(self._settings.per_agent_token_cap or PER_AGENT_TOKEN_CAP),
            global_token_budget=int(self._settings.global_token_budget or GLOBAL_TOKEN_BUDGET),
        )

    def _raise_if_exceeded(self, event_id: str, agent_name: str, usage: BudgetUsage) -> None:
        event_token_budget = int(self._settings.event_token_budget or EVENT_TOKEN_BUDGET)
        event_cost_budget = float(self._settings.event_cost_budget_usd or EVENT_COST_BUDGET_USD)
        per_agent_cap = int(self._settings.per_agent_token_cap or PER_AGENT_TOKEN_CAP)
        global_budget = int(self._settings.global_token_budget or GLOBAL_TOKEN_BUDGET)

        agent_tokens = int(usage.per_agent.get(agent_name, {}).get("tokens", 0))

        if usage.event_tokens > event_token_budget:
            raise BudgetExceededError(
                "event token budget exceeded",
                error_code="budget_exceeded",
                details={
                    "scope": BudgetScope.EVENT.value,
                    "event_id": event_id,
                    "agent_name": agent_name,
                    "current": usage.event_tokens,
                    "limit": event_token_budget,
                    "metric": "tokens",
                },
            )
        if usage.event_cost_usd > event_cost_budget:
            raise BudgetExceededError(
                "event cost budget exceeded",
                error_code="budget_exceeded",
                details={
                    "scope": BudgetScope.EVENT.value,
                    "event_id": event_id,
                    "agent_name": agent_name,
                    "current": usage.event_cost_usd,
                    "limit": event_cost_budget,
                    "metric": "cost_usd",
                },
            )
        if agent_tokens > per_agent_cap:
            raise BudgetExceededError(
                "per-agent token budget exceeded",
                error_code="budget_exceeded",
                details={
                    "scope": BudgetScope.AGENT.value,
                    "event_id": event_id,
                    "agent_name": agent_name,
                    "current": agent_tokens,
                    "limit": per_agent_cap,
                    "metric": "tokens",
                },
            )
        if usage.system_tokens > global_budget:
            raise BudgetExceededError(
                "system token budget exceeded",
                error_code="budget_exceeded",
                details={
                    "scope": BudgetScope.SYSTEM.value,
                    "event_id": event_id,
                    "agent_name": agent_name,
                    "current": usage.system_tokens,
                    "limit": global_budget,
                    "metric": "tokens",
                },
            )

    async def _apply_llm_charge(
        self,
        *,
        event_id: str,
        agent_name: str,
        tokens: int,
        cost_usd: float,
    ) -> None:
        client = await self._redis_client()
        if client is None:
            self._apply_memory_llm_charge(event_id, agent_name, tokens, cost_usd)
            return
        try:
            pipe = client.pipeline()
            pipe.incrby(SYSTEM_BUDGET_KEY, tokens)
            event_key = _event_key(event_id)
            pipe.hincrby(event_key, _FIELD_TOKENS, tokens)
            if cost_usd:
                pipe.hincrbyfloat(event_key, _FIELD_COST_USD, cost_usd)
            pipe.hincrby(event_key, _agent_tokens_field(agent_name), tokens)
            await pipe.execute()
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("charge_llm", event_id)
            self._apply_memory_llm_charge(event_id, agent_name, tokens, cost_usd)

    async def _apply_tool_charge(self, *, event_id: str, agent_name: str) -> None:
        client = await self._redis_client()
        if client is None:
            self._apply_memory_tool_charge(event_id, agent_name)
            return
        try:
            pipe = client.pipeline()
            event_key = _event_key(event_id)
            pipe.hincrby(event_key, _FIELD_TOOL_CALLS, 1)
            pipe.hincrby(event_key, _agent_tools_field(agent_name), 1)
            await pipe.execute()
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("charge_tool", event_id)
            self._apply_memory_tool_charge(event_id, agent_name)

    def _apply_memory_llm_charge(
        self,
        event_id: str,
        agent_name: str,
        tokens: int,
        cost_usd: float,
    ) -> None:
        counters = self._memory.events.setdefault(event_id, _EventCounters())
        counters.tokens += tokens
        counters.cost_usd = round(counters.cost_usd + cost_usd, 8)
        counters.per_agent_tokens[agent_name] = (
            counters.per_agent_tokens.get(agent_name, 0) + tokens
        )
        self._memory.system_tokens += tokens

    def _apply_memory_tool_charge(self, event_id: str, agent_name: str) -> None:
        counters = self._memory.events.setdefault(event_id, _EventCounters())
        counters.tool_calls += 1
        counters.per_agent_tool_calls[agent_name] = (
            counters.per_agent_tool_calls.get(agent_name, 0) + 1
        )

    def _read_memory_usage(self, event_id: str) -> BudgetUsage:
        counters = self._memory.events.get(event_id) or _EventCounters()
        agent_names = set(counters.per_agent_tokens) | set(counters.per_agent_tool_calls)
        per_agent: dict[str, dict[str, int | float]] = {}
        for name in sorted(agent_names):
            per_agent[name] = {
                "tokens": counters.per_agent_tokens.get(name, 0),
                "tool_calls": counters.per_agent_tool_calls.get(name, 0),
            }
        return BudgetUsage(
            event_tokens=counters.tokens,
            event_cost_usd=counters.cost_usd,
            tool_calls=counters.tool_calls,
            per_agent=per_agent,
            system_tokens=self._memory.system_tokens,
        )

    async def _read_redis_usage(self, event_id: str) -> BudgetUsage | None:
        client = await self._redis_client()
        if client is None:
            return None
        try:
            event_key = _event_key(event_id)
            mapping = await client.hgetall(event_key)
            system_raw = await client.get(SYSTEM_BUDGET_KEY)
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("get_usage", event_id)
            return None

        decoded: dict[str, str] = {}
        for raw_key, raw_value in mapping.items():
            key = raw_key.decode() if isinstance(raw_key, (bytes, bytearray)) else str(raw_key)
            value = (
                raw_value.decode() if isinstance(raw_value, (bytes, bytearray)) else str(raw_value)
            )
            decoded[key] = value

        per_agent: dict[str, dict[str, int | float]] = {}
        for key, value in decoded.items():
            if key.startswith("agent:") and key.endswith(":tokens"):
                agent_name = key[len("agent:") : -len(":tokens")]
                per_agent.setdefault(agent_name, {"tokens": 0, "tool_calls": 0})
                per_agent[agent_name]["tokens"] = _decode_int(value)
            elif key.startswith("agent:") and key.endswith(":tool_calls"):
                agent_name = key[len("agent:") : -len(":tool_calls")]
                per_agent.setdefault(agent_name, {"tokens": 0, "tool_calls": 0})
                per_agent[agent_name]["tool_calls"] = _decode_int(value)

        return BudgetUsage(
            event_tokens=_decode_int(decoded.get(_FIELD_TOKENS)),
            event_cost_usd=_decode_float(decoded.get(_FIELD_COST_USD)),
            tool_calls=_decode_int(decoded.get(_FIELD_TOOL_CALLS)),
            per_agent=per_agent,
            system_tokens=_decode_int(system_raw),
        )

    async def _mirror_usage(self, event_id: str, usage: BudgetUsage) -> None:
        if self._usage_writer is None:
            return
        try:
            await self._usage_writer.write_budget_usage(event_id, usage)
        except Exception:  # noqa: BLE001 — budget metering must not fail the caller path
            logger.warning(
                "failed to mirror budget_usage into EventContext event_id=%s",
                event_id,
                exc_info=True,
            )

    async def _redis_client(self) -> Any | None:
        if self._redis is None:
            return None
        try:
            if not await self._redis.ping():
                self._mark_redis_degraded("ping")
                return None
            return self._redis.get_client()
        except Exception:  # noqa: BLE001
            self._mark_redis_degraded("ping")
            return None

    def _mark_redis_degraded(self, op: str, event_id: str | None = None) -> None:
        if not self._redis_degraded:
            logger.warning(
                "budget Redis unavailable; falling back to in-process counters op=%s event_id=%s",
                op,
                event_id,
            )
        self._redis_degraded = True


class WorkingMemoryBudgetUsageWriter:
    """Write EventContext.budget_usage via WorkingMemory as owner BudgetService."""

    def __init__(self, working_memory: Any) -> None:
        self._bound = working_memory.for_writer("BudgetService")

    async def write_budget_usage(self, event_id: str, usage: BudgetUsage) -> None:
        await self._bound.write(event_id, "budget_usage", usage.model_dump(mode="json"))


__all__ = [
    "BudgetService",
    "BudgetUsage",
    "BudgetUsageWriter",
    "WorkingMemoryBudgetUsageWriter",
    "SYSTEM_BUDGET_KEY",
    "EVENT_BUDGET_KEY_PREFIX",
    "compute_llm_cost_usd",
]
