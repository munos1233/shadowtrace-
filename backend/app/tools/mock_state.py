"""Redis-backed state for the mock ToolProvider environment."""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import UTC, datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from app.core.redis_client import RedisClient
from app.models.source import SourceReference

MOCK_TOOL_STATE_KEY = "shadowtrace:mock_tool_state"
MOCK_OBSERVATION_PROJECTION_KEY = "shadowtrace:mock_observation_projection"
MOCK_OBSERVATION_IDEMPOTENCY_KEY = "shadowtrace:mock_observation_idempotency"
MOCK_VERIFY_OVERRIDE_KEY = "shadowtrace:mock_verify_override"
_MAX_OBSERVATION_GENERATIONS = 32
MOCK_STATE_NAMESPACES = frozenset(
    {
        "blocked_ips",
        "blocked_domains",
        "isolated_hosts",
        "quarantined_files",
        "blocked_processes",
        "scan_results",
        "accounts",
        "sessions",
        "tokens",
        "tickets",
        "notifications",
    }
)

_RESERVE_DISPATCH_LUA = """
local existing = redis.call("HGET", KEYS[1], ARGV[1])
if existing then
  return {cjson.decode(existing), 0}
end
redis.call("HSET", KEYS[1],
  ARGV[1], ARGV[3],
  ARGV[4], ARGV[5],
  ARGV[6], ARGV[7])
return {ARGV[2], 1}
"""

_CLAIM_OWNER_LUA = """
local existing = redis.call("HGET", KEYS[1], ARGV[1])
if existing then
  return existing
end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[2])
return ARGV[2]
"""

_CLAIM_JOB_LUA = """
local current = redis.call("HGET", KEYS[1], ARGV[1])
if current then
  local separator = string.find(current, "|")
  local current_owner = string.sub(current, 1, separator - 1)
  local remainder = string.sub(current, separator + 1)
  local second_separator = string.find(remainder, "|")
  local expires_at = tonumber(string.sub(remainder, 1, second_separator - 1))
  if current_owner ~= ARGV[2] and expires_at > tonumber(ARGV[3]) then
    return 0
  end
end
local token = redis.call("HINCRBY", KEYS[1], ARGV[5], 1)
redis.call("HSET", KEYS[1], ARGV[1], ARGV[2] .. "|" .. ARGV[4] .. "|" .. token)
return token
"""

_RELEASE_JOB_LUA = """
local current = redis.call("HGET", KEYS[1], ARGV[1])
if not current then
  return 0
end
local separator = string.find(current, "|")
local token = string.match(current, "|([^|]+)$")
if string.sub(current, 1, separator - 1) ~= ARGV[2] or token ~= ARGV[3] then
  return 0
end
redis.call("HDEL", KEYS[1], ARGV[1])
return 1
"""

_SET_JOB_CLAIMED_LUA = """
local current = redis.call("HGET", KEYS[1], ARGV[1])
if not current then
  return 0
end
local separator = string.find(current, "|")
local token = string.match(current, "|([^|]+)$")
if string.sub(current, 1, separator - 1) ~= ARGV[2] or token ~= ARGV[3] then
  return 0
end
redis.call("HSET", KEYS[1], ARGV[4], ARGV[5])
return 1
"""

_SET_JOB_STATUS_LUA = """
local current = redis.call("HGET", KEYS[1], ARGV[1])
if not current then
  return 0
end
local decoded = cjson.decode(current)
if decoded["status"] ~= ARGV[2] then
  return 0
end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[3])
return 1
"""

_ALLOCATE_TICKET_LUA = """
local existing = redis.call("HGET", KEYS[1], ARGV[1])
if existing then
  return cjson.decode(existing)
end
local sequence = redis.call("HINCRBY", KEYS[1], ARGV[2], 1)
redis.call("HSET", KEYS[1], ARGV[1], cjson.encode(sequence))
return sequence
"""

_APPLY_EFFECT_LUA = """
local prior_effect = redis.call("HGET", KEYS[1], ARGV[1])
if prior_effect then
  local prior_state = redis.call("HGET", KEYS[1], ARGV[2])
  return {prior_state or false, 0, prior_effect}
end

local existing = redis.call("HGET", KEYS[1], ARGV[2])
if existing and ARGV[6] == "0" then
  local decoded = cjson.decode(existing)
  if decoded["status"] == ARGV[5] then
    redis.call("HSET", KEYS[1], ARGV[1], "already_applied")
    return {existing, 0, "already_applied"}
  end
end

if not existing and tonumber(ARGV[7]) >= 0 then
  local fields = redis.call("HKEYS", KEYS[1])
  local count = 0
  for _, field in ipairs(fields) do
    if string.sub(field, 1, string.len(ARGV[3])) == ARGV[3] then
      count = count + 1
    end
  end
  if count >= tonumber(ARGV[7]) then
    return {false, 0, "capacity_exceeded"}
  end
end

local record = cjson.decode(ARGV[4])
local version = 1
if existing then
  local decoded = cjson.decode(existing)
  version = (tonumber(decoded["version"]) or 0) + 1
end
record["version"] = version
local encoded = cjson.encode(record)
redis.call("HSET", KEYS[1], ARGV[2], encoded, ARGV[1], "applied")
return {encoded, 1, "applied"}
"""

_APPEND_OBSERVATION_LUA = """
if redis.call("HSETNX", KEYS[2], ARGV[4], "1") == 0 then
  return 0
end
local existing = redis.call("HGET", KEYS[1], ARGV[1])
local records = {}
local generation = 1
local incoming = cjson.decode(ARGV[2])
if existing then
  local decoded = cjson.decode(existing)
  if decoded["surface"] then
    table.insert(records, decoded)
  else
    records = decoded
  end
  for _, item in ipairs(records) do
    if item["job_id"] == incoming["job_id"] then
      return #records
    end
    generation = math.max(generation, (tonumber(item["projection_generation"]) or 0) + 1)
  end
end
incoming["projection_generation"] = generation
table.insert(records, incoming)
while #records > tonumber(ARGV[3]) do
  table.remove(records, 1)
end
redis.call("HSET", KEYS[1], ARGV[1], cjson.encode(records))
return #records
"""

_APPLY_ROLLBACK_LUA = """
local prior_code = redis.call("HGET", KEYS[1], ARGV[1])
if prior_code then
  local prior_history = redis.call("HGET", KEYS[1], ARGV[3])
  local current_state = redis.call("HGET", KEYS[1], ARGV[2])
  return {prior_history or false, current_state or false, 0, prior_code}
end

local existing = redis.call("HGET", KEYS[1], ARGV[2])
if not existing then
  redis.call("HSET", KEYS[1], ARGV[1], "target_not_found")
  return {false, false, 0, "target_not_found"}
end

local original = cjson.decode(existing)
if ARGV[4] ~= "" and original["status"] ~= ARGV[4] then
  redis.call("HSET", KEYS[1], ARGV[1], "target_not_found")
  return {false, existing, 0, "target_not_found"}
end
if ARGV[7] == "1"
  or (ARGV[5] ~= "" and tonumber(original["version"]) ~= tonumber(ARGV[5]))
  or (ARGV[6] ~= "" and original["job_id"] ~= ARGV[6]) then
  redis.call("HSET", KEYS[1], ARGV[1], "stale_rollback_target")
  return {false, existing, 0, "stale_rollback_target"}
end

local history = cjson.decode(ARGV[9])
history["original_record"] = original
local encoded_history = cjson.encode(history)
local encoded_state = false
if ARGV[8] == "" then
  redis.call("HDEL", KEYS[1], ARGV[2])
else
  original["status"] = ARGV[8]
  original["reason"] = "mock provider rollback"
  original["executed_at"] = history["rolled_back_at"]
  original["effective_at"] = history["rolled_back_at"]
  original["executed_by"] = history["rolled_back_by"]
  original["provider"] = history["provider"]
  original["connector"] = history["connector"]
  original["action_id"] = history["action_id"]
  original["job_id"] = history["job_id"]
  original["version"] = (tonumber(original["version"]) or 0) + 1
  encoded_state = cjson.encode(original)
  redis.call("HSET", KEYS[1], ARGV[2], encoded_state)
end

redis.call("HSET", KEYS[1],
  ARGV[3], encoded_history,
  ARGV[1], "rolled_back")
return {encoded_history, encoded_state, 1, "rolled_back"}
"""


def _utc_now() -> datetime:
    return datetime.now(UTC)


class MockStateRecord(BaseModel):
    """Traceable state produced by one successful mock side effect."""

    model_config = ConfigDict(extra="forbid")

    status: str
    reason: str | None = None
    executed_at: datetime = Field(default_factory=_utc_now)
    executed_by: str
    provider: str
    connector: str
    version: int = Field(default=1, ge=1)
    action_id: str
    job_id: str
    effective_at: datetime = Field(default_factory=_utc_now)
    value: dict[str, Any] = Field(default_factory=dict)


class MockObservationRecord(BaseModel):
    """Read-only observation copied from an effect after an explicit delay."""

    model_config = ConfigDict(extra="forbid")

    surface: str
    target: str
    status: str
    observed_at: datetime
    available_at: datetime
    observed_version: int = Field(ge=1)
    projection_generation: int = Field(default=1, ge=1)
    source_refs: list[SourceReference] = Field(default_factory=list)
    action_id: str
    job_id: str
    provider: str
    connector: str
    value: dict[str, Any] = Field(default_factory=dict)


class MockRollbackHistoryRecord(BaseModel):
    """Immutable audit snapshot captured by one successful rollback effect."""

    model_config = ConfigDict(extra="forbid")

    rollback_tool_name: str
    source_tool_name: str
    namespace: str
    target: str
    original_record: dict[str, Any] = Field(default_factory=dict)
    rolled_back_at: datetime
    rolled_back_by: str
    provider: str
    connector: str
    action_id: str
    job_id: str


class MockEnvironmentState:
    """One logical state store, persisted under a single Redis Hash.

    Runtime construction uses Redis. Tests must opt into :meth:`in_memory`;
    this keeps the P0 dependency explicit instead of silently degrading.
    """

    def __init__(
        self,
        redis_client: RedisClient | None = None,
        *,
        key: str = MOCK_TOOL_STATE_KEY,
        _in_memory: bool = False,
    ) -> None:
        self._redis = None if _in_memory else (redis_client or RedisClient())
        self._key = key
        self._memory: dict[str, bytes] | None = {} if _in_memory else None
        self._observation_memory: dict[str, bytes] | None = {} if _in_memory else None
        self._observation_idempotency_memory: set[str] | None = set() if _in_memory else None
        self._verify_override_memory: dict[str, str] | None = {} if _in_memory else None
        self._lock = asyncio.Lock()

    @classmethod
    def in_memory(cls) -> Self:
        """Create an isolated test state without pretending Redis is available."""

        return cls(_in_memory=True)

    @staticmethod
    def _field(namespace: str, key: str) -> str:
        if not namespace or not key:
            raise ValueError("namespace and key must be non-empty")
        return f"{namespace}:{key}"

    async def set_state(self, namespace: str, key: str, value: Any) -> None:
        field = self._field(namespace, key)
        encoded = RedisClient.dumps(value)
        if self._memory is not None:
            async with self._lock:
                self._memory[field] = encoded
            return
        assert self._redis is not None
        await self._redis.get_client().hset(self._key, field, encoded)

    async def get_state(self, namespace: str, key: str) -> Any | None:
        field = self._field(namespace, key)
        encoded: bytes | str | None
        if self._memory is not None:
            async with self._lock:
                encoded = self._memory.get(field)
        else:
            assert self._redis is not None
            encoded = await self._redis.get_client().hget(self._key, field)
        return None if encoded is None else RedisClient.loads(encoded)

    async def delete_state(self, namespace: str, key: str) -> None:
        field = self._field(namespace, key)
        if self._memory is not None:
            async with self._lock:
                self._memory.pop(field, None)
            return
        assert self._redis is not None
        await self._redis.get_client().hdel(self._key, field)

    async def clear_all(self) -> None:
        if self._memory is not None:
            async with self._lock:
                self._memory.clear()
                assert self._observation_memory is not None
                self._observation_memory.clear()
                assert self._observation_idempotency_memory is not None
                self._observation_idempotency_memory.clear()
                assert self._verify_override_memory is not None
                self._verify_override_memory.clear()
            return
        assert self._redis is not None
        await self._redis.get_client().delete(
            self._key,
            MOCK_OBSERVATION_PROJECTION_KEY,
            MOCK_OBSERVATION_IDEMPOTENCY_KEY,
            MOCK_VERIFY_OVERRIDE_KEY,
        )

    async def list_namespace(self, namespace: str) -> dict[str, Any]:
        prefix = f"{namespace}:"
        snapshot: dict[bytes | str, bytes | str]
        if self._memory is not None:
            async with self._lock:
                snapshot = {field: value for field, value in self._memory.items()}
        else:
            assert self._redis is not None
            snapshot = await self._redis.get_client().hgetall(self._key)

        result: dict[str, Any] = {}
        for raw_field, encoded in snapshot.items():
            field = raw_field.decode() if isinstance(raw_field, bytes) else str(raw_field)
            if field.startswith(prefix):
                result[field[len(prefix) :]] = RedisClient.loads(encoded)
        return result

    async def count_namespace(self, namespace: str) -> int:
        return len(await self.list_namespace(namespace))

    async def set_observation(self, record: MockObservationRecord) -> None:
        """Publish a copied observation; verification code only reads this surface."""

        field = self._field(record.surface, record.target)
        idempotency_field = hashlib.sha256(
            f"{record.surface}|{record.target}|{record.job_id}".encode()
        ).hexdigest()
        encoded_record = RedisClient.dumps(record.model_dump(mode="json"))
        if self._observation_memory is not None:
            async with self._lock:
                assert self._observation_idempotency_memory is not None
                if idempotency_field in self._observation_idempotency_memory:
                    return
                self._observation_idempotency_memory.add(idempotency_field)
                existing = self._observation_memory.get(field)
                decoded = RedisClient.loads(existing) if existing is not None else []
                if isinstance(decoded, dict):
                    records = [decoded]
                elif isinstance(decoded, list):
                    records = list(decoded)
                else:
                    records = []
                if any(
                    isinstance(item, dict) and item.get("job_id") == record.job_id
                    for item in records
                ):
                    return
                generation = (
                    max(
                        (
                            int(item.get("projection_generation", 0))
                            for item in records
                            if isinstance(item, dict)
                        ),
                        default=0,
                    )
                    + 1
                )
                records.append(
                    record.model_copy(update={"projection_generation": generation}).model_dump(
                        mode="json"
                    )
                )
                self._observation_memory[field] = RedisClient.dumps(
                    records[-_MAX_OBSERVATION_GENERATIONS:]
                )
            return
        assert self._redis is not None
        await self._redis.get_client().eval(
            _APPEND_OBSERVATION_LUA,
            2,
            MOCK_OBSERVATION_PROJECTION_KEY,
            MOCK_OBSERVATION_IDEMPOTENCY_KEY,
            field,
            encoded_record,
            str(_MAX_OBSERVATION_GENERATIONS),
            idempotency_field,
        )

    async def get_observation(
        self,
        surface: str,
        target: str,
        *,
        observed_at: datetime | None = None,
        include_pending: bool = False,
        job_id: str | None = None,
    ) -> MockObservationRecord | None:
        """Read a visible observation without materializing or mutating projection state."""

        field = self._field(surface, target)
        encoded: bytes | str | None
        if self._observation_memory is not None:
            async with self._lock:
                encoded = self._observation_memory.get(field)
        else:
            assert self._redis is not None
            encoded = await self._redis.get_client().hget(
                MOCK_OBSERVATION_PROJECTION_KEY,
                field,
            )
        value = None if encoded is None else RedisClient.loads(encoded)
        if isinstance(value, dict):
            raw_records = [value]
        elif isinstance(value, list):
            raw_records = value
        else:
            return None
        records = [
            MockObservationRecord.model_validate(item)
            for item in raw_records
            if isinstance(item, dict)
        ]
        if job_id is not None:
            records = [record for record in records if record.job_id == job_id]
        now = observed_at or _utc_now()
        eligible = (
            records
            if include_pending
            else [record for record in records if record.available_at <= now]
        )
        if not eligible:
            return None
        return max(
            eligible,
            key=lambda record: (
                record.projection_generation,
                record.available_at,
                record.observed_at,
                record.job_id,
            ),
        )

    async def list_observations(self) -> dict[str, Any]:
        """Return a read-only snapshot of the physically separate projection Hash."""

        snapshot: dict[Any, Any]
        if self._observation_memory is not None:
            async with self._lock:
                snapshot = dict(self._observation_memory)
        else:
            assert self._redis is not None
            snapshot = await self._redis.get_client().hgetall(MOCK_OBSERVATION_PROJECTION_KEY)
        return {
            raw_field.decode() if isinstance(raw_field, bytes) else str(raw_field): (
                RedisClient.loads(encoded)
            )
            for raw_field, encoded in snapshot.items()
        }

    async def set_verify_override(
        self,
        tool_name: str,
        target: str,
        value: bool | str,
    ) -> None:
        """Set the documented verification override Hash field."""

        field = self._field(tool_name, target)
        normalized = str(value).lower()
        if normalized not in {"true", "false"}:
            raise ValueError("verification override must be true or false")
        if self._verify_override_memory is not None:
            async with self._lock:
                self._verify_override_memory[field] = normalized
            return
        assert self._redis is not None
        await self._redis.get_client().hset(
            MOCK_VERIFY_OVERRIDE_KEY,
            field,
            normalized,
        )

    async def get_verify_override(self, tool_name: str, target: str) -> bool | None:
        field = self._field(tool_name, target)
        raw: bytes | str | None
        if self._verify_override_memory is not None:
            async with self._lock:
                raw = self._verify_override_memory.get(field)
        else:
            assert self._redis is not None
            raw = await self._redis.get_client().hget(MOCK_VERIFY_OVERRIDE_KEY, field)
        if raw is None:
            return None
        normalized = raw.decode() if isinstance(raw, bytes) else str(raw)
        if normalized == "false":
            return False
        if normalized == "true":
            return True
        raise ValueError(f"invalid verification override value for {field!r}")

    async def delete_verify_override(self, tool_name: str, target: str) -> None:
        field = self._field(tool_name, target)
        if self._verify_override_memory is not None:
            async with self._lock:
                self._verify_override_memory.pop(field, None)
            return
        assert self._redis is not None
        await self._redis.get_client().hdel(MOCK_VERIFY_OVERRIDE_KEY, field)

    async def next_sequence(self, name: str) -> int:
        field = self._field("counter", name)
        if self._memory is not None:
            async with self._lock:
                current = (
                    int(RedisClient.loads(self._memory[field])) if field in self._memory else 0
                )
                current += 1
                self._memory[field] = RedisClient.dumps(current)
                return current
        assert self._redis is not None
        return int(await self._redis.get_client().hincrby(self._key, field, 1))

    async def claim_execution_owner(self, action_id: str, owner: str) -> str:
        """Atomically freeze one execution owner for an action."""

        field = self._field("action_owners", hashlib.sha256(action_id.encode()).hexdigest())
        if self._memory is not None:
            async with self._lock:
                existing = self._memory.get(field)
                if existing is not None:
                    return str(RedisClient.loads(existing))
                self._memory[field] = RedisClient.dumps(owner)
                return owner
        assert self._redis is not None
        result = await self._redis.get_client().eval(
            _CLAIM_OWNER_LUA,
            1,
            self._key,
            field,
            owner,
        )
        return result.decode() if isinstance(result, bytes) else str(result)

    async def claim_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        lease_seconds: float,
    ) -> int:
        """Claim a job once, allowing recovery only after its lease expires."""

        field = self._field("job_claims", job_id)
        fence_field = self._field("counter", f"job_fence:{job_id}")
        now = time.time()
        expires_at = now + lease_seconds
        if self._memory is not None:
            async with self._lock:
                existing = self._memory.get(field)
                if existing is not None:
                    prior = str(RedisClient.loads(existing))
                    prior_worker, raw_expiry, _ = prior.split("|", 2)
                    if prior_worker != worker_id and float(raw_expiry) > now:
                        return 0
                token = (
                    int(RedisClient.loads(self._memory[fence_field])) + 1
                    if fence_field in self._memory
                    else 1
                )
                self._memory[fence_field] = RedisClient.dumps(token)
                claim = f"{worker_id}|{expires_at}|{token}"
                self._memory[field] = RedisClient.dumps(claim)
                return token
        assert self._redis is not None
        result = await self._redis.get_client().eval(
            _CLAIM_JOB_LUA,
            1,
            self._key,
            field,
            worker_id,
            str(now),
            str(expires_at),
            fence_field,
        )
        return int(result)

    async def release_job_claim(self, job_id: str, worker_id: str, token: int) -> None:
        field = self._field("job_claims", job_id)
        if self._memory is not None:
            async with self._lock:
                existing = self._memory.get(field)
                if existing is None:
                    return
                owner, _, raw_token = str(RedisClient.loads(existing)).split("|", 2)
                if owner == worker_id and int(raw_token) == token:
                    self._memory.pop(field, None)
            return
        assert self._redis is not None
        await self._redis.get_client().eval(
            _RELEASE_JOB_LUA,
            1,
            self._key,
            field,
            worker_id,
            str(token),
        )

    async def set_job_if_claimed(
        self,
        job_id: str,
        job: dict[str, Any],
        *,
        worker_id: str,
        token: int,
    ) -> bool:
        """Fence stale workers from overwriting a recovered job."""

        claim_field = self._field("job_claims", job_id)
        job_field = self._field("jobs", job_id)
        encoded = RedisClient.dumps(job)
        if self._memory is not None:
            async with self._lock:
                current = self._memory.get(claim_field)
                if current is None:
                    return False
                owner, _, raw_token = str(RedisClient.loads(current)).split("|", 2)
                if owner != worker_id or int(raw_token) != token:
                    return False
                self._memory[job_field] = encoded
                return True
        assert self._redis is not None
        result = await self._redis.get_client().eval(
            _SET_JOB_CLAIMED_LUA,
            1,
            self._key,
            claim_field,
            worker_id,
            str(token),
            job_field,
            encoded,
        )
        return bool(int(result))

    async def set_job_if_status(
        self,
        job_id: str,
        job: dict[str, Any],
        *,
        expected_status: str,
    ) -> bool:
        """Compare-and-set a job so stale terminal writers cannot win."""

        job_field = self._field("jobs", job_id)
        encoded = RedisClient.dumps(job)
        if self._memory is not None:
            async with self._lock:
                current_raw = self._memory.get(job_field)
                if current_raw is None:
                    return False
                current = RedisClient.loads(current_raw)
                if not isinstance(current, dict) or current.get("status") != expected_status:
                    return False
                self._memory[job_field] = encoded
                return True
        assert self._redis is not None
        result = await self._redis.get_client().eval(
            _SET_JOB_STATUS_LUA,
            1,
            self._key,
            job_field,
            expected_status,
            encoded,
        )
        return bool(int(result))

    async def allocate_ticket_sequence(self, job_id: str) -> int:
        """Allocate exactly one monotonic ticket sequence for a job."""

        artifact_field = self._field("job_artifacts", job_id)
        counter_field = self._field("counter", "tickets")
        if self._memory is not None:
            async with self._lock:
                existing = self._memory.get(artifact_field)
                if existing is not None:
                    return int(RedisClient.loads(existing))
                sequence = (
                    int(RedisClient.loads(self._memory[counter_field])) + 1
                    if counter_field in self._memory
                    else 1
                )
                self._memory[counter_field] = RedisClient.dumps(sequence)
                self._memory[artifact_field] = RedisClient.dumps(sequence)
                return sequence
        assert self._redis is not None
        result = await self._redis.get_client().eval(
            _ALLOCATE_TICKET_LUA,
            1,
            self._key,
            artifact_field,
            counter_field,
        )
        return int(result)

    async def apply_effect(
        self,
        *,
        job_id: str,
        namespace: str,
        key: str,
        record: dict[str, Any],
        desired_status: str,
        allow_update: bool,
        capacity: int | None,
    ) -> tuple[dict[str, Any] | None, bool, str]:
        """Atomically enforce effect idempotency, duplicate rules, and capacity."""

        state_field = self._field(namespace, key)
        effect_digest = hashlib.sha256(f"{namespace}|{key}".encode()).hexdigest()
        effect_field = self._field("effects", f"{job_id}:{effect_digest}")
        prefix = f"{namespace}:"

        if self._memory is not None:
            async with self._lock:
                prior_effect = self._memory.get(effect_field)
                existing_raw = self._memory.get(state_field)
                existing = RedisClient.loads(existing_raw) if existing_raw is not None else None
                if prior_effect is not None:
                    return (
                        existing if isinstance(existing, dict) else None,
                        False,
                        str(RedisClient.loads(prior_effect)),
                    )
                if (
                    isinstance(existing, dict)
                    and not allow_update
                    and existing.get("status") == desired_status
                ):
                    self._memory[effect_field] = RedisClient.dumps("already_applied")
                    return existing, False, "already_applied"
                if existing is None and capacity is not None:
                    current = sum(field.startswith(prefix) for field in self._memory)
                    if current >= capacity:
                        return None, False, "capacity_exceeded"

                stored = dict(record)
                stored["version"] = (
                    int(existing.get("version", 0)) + 1 if isinstance(existing, dict) else 1
                )
                self._memory[state_field] = RedisClient.dumps(stored)
                self._memory[effect_field] = RedisClient.dumps("applied")
                return stored, True, "applied"

        assert self._redis is not None
        result = await self._redis.get_client().eval(
            _APPLY_EFFECT_LUA,
            1,
            self._key,
            effect_field,
            state_field,
            prefix,
            RedisClient.dumps(record),
            desired_status,
            "1" if allow_update else "0",
            str(capacity if capacity is not None else -1),
        )
        encoded, raw_applied, raw_code = result
        decoded_stored = None if encoded in (None, False) else RedisClient.loads(encoded)
        code = raw_code.decode() if isinstance(raw_code, bytes) else str(raw_code)
        return (
            decoded_stored if isinstance(decoded_stored, dict) else None,
            bool(int(raw_applied)),
            code,
        )

    async def apply_rollback(
        self,
        *,
        job_id: str,
        rollback_tool_name: str,
        source_tool_name: str,
        namespace: str,
        key: str,
        expected_status: str,
        expected_source_version: int | None,
        expected_source_job_id: str | None,
        expect_absent: bool,
        replacement_status: str | None,
        rolled_back_at: datetime,
        rolled_back_by: str,
        provider: str,
        connector: str,
        action_id: str,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None, bool, str]:
        """Atomically preserve the original record and undo one provider effect."""

        if expect_absent and (
            expected_source_version is not None or expected_source_job_id is not None
        ):
            raise ValueError("absent rollback expectation cannot include source identity")
        if not expect_absent and (
            expected_source_version is None or expected_source_job_id is None
        ):
            raise ValueError("present rollback expectation requires source version and job_id")
        state_field = self._field(namespace, key)
        effect_digest = hashlib.sha256(f"{namespace}|{key}".encode()).hexdigest()
        effect_field = self._field("rollback_effects", f"{job_id}:{effect_digest}")
        history_field = self._field("rollback_history", f"{job_id}:{effect_digest}")
        metadata = MockRollbackHistoryRecord(
            rollback_tool_name=rollback_tool_name,
            source_tool_name=source_tool_name,
            namespace=namespace,
            target=key,
            rolled_back_at=rolled_back_at,
            rolled_back_by=rolled_back_by,
            provider=provider,
            connector=connector,
            action_id=action_id,
            job_id=job_id,
        ).model_dump(mode="json")

        if self._memory is not None:
            async with self._lock:
                prior_code_raw = self._memory.get(effect_field)
                history_raw = self._memory.get(history_field)
                current_raw = self._memory.get(state_field)
                if prior_code_raw is not None:
                    history = RedisClient.loads(history_raw) if history_raw is not None else None
                    current = RedisClient.loads(current_raw) if current_raw is not None else None
                    return (
                        history if isinstance(history, dict) else None,
                        current if isinstance(current, dict) else None,
                        False,
                        str(RedisClient.loads(prior_code_raw)),
                    )
                if current_raw is None:
                    self._memory[effect_field] = RedisClient.dumps("target_not_found")
                    return None, None, False, "target_not_found"
                original = RedisClient.loads(current_raw)
                if not isinstance(original, dict) or (
                    expected_status and original.get("status") != expected_status
                ):
                    self._memory[effect_field] = RedisClient.dumps("target_not_found")
                    return (
                        None,
                        original if isinstance(original, dict) else None,
                        False,
                        "target_not_found",
                    )
                if (
                    expect_absent
                    or original.get("version") != expected_source_version
                    or original.get("job_id") != expected_source_job_id
                ):
                    self._memory[effect_field] = RedisClient.dumps("stale_rollback_target")
                    return None, original, False, "stale_rollback_target"

                history = {**metadata, "original_record": dict(original)}
                resulting_state: dict[str, Any] | None = None
                if replacement_status is None:
                    self._memory.pop(state_field, None)
                else:
                    resulting_state = {
                        **original,
                        "status": replacement_status,
                        "reason": "mock provider rollback",
                        "executed_at": rolled_back_at.isoformat(),
                        "effective_at": rolled_back_at.isoformat(),
                        "executed_by": rolled_back_by,
                        "provider": provider,
                        "connector": connector,
                        "action_id": action_id,
                        "job_id": job_id,
                        "version": int(original.get("version", 0)) + 1,
                    }
                    self._memory[state_field] = RedisClient.dumps(resulting_state)
                self._memory[history_field] = RedisClient.dumps(history)
                self._memory[effect_field] = RedisClient.dumps("rolled_back")
                return history, resulting_state, True, "rolled_back"

        assert self._redis is not None
        result = await self._redis.get_client().eval(
            _APPLY_ROLLBACK_LUA,
            1,
            self._key,
            effect_field,
            state_field,
            history_field,
            expected_status,
            str(expected_source_version) if expected_source_version is not None else "",
            expected_source_job_id or "",
            "1" if expect_absent else "0",
            replacement_status or "",
            RedisClient.dumps(metadata),
        )
        raw_history, raw_state, raw_applied, raw_code = result
        history = None if raw_history in (None, False) else RedisClient.loads(raw_history)
        resulting_state = None if raw_state in (None, False) else RedisClient.loads(raw_state)
        code = raw_code.decode() if isinstance(raw_code, bytes) else str(raw_code)
        return (
            history if isinstance(history, dict) else None,
            resulting_state if isinstance(resulting_state, dict) else None,
            bool(int(raw_applied)),
            code,
        )

    async def reserve_dispatch(
        self,
        *,
        idempotency_key: str,
        job_id: str,
        job: dict[str, Any],
        intent: dict[str, Any],
    ) -> tuple[str, bool]:
        """Atomically reserve an idempotency key and persist QUEUED intent/job."""

        digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
        idem_field = self._field("idempotency", digest)
        job_field = self._field("jobs", job_id)
        intent_field = self._field("dispatch_intents", job_id)
        encoded_job = RedisClient.dumps(job)
        encoded_intent = RedisClient.dumps(intent)

        if self._memory is not None:
            async with self._lock:
                existing = self._memory.get(idem_field)
                if existing is not None:
                    return str(RedisClient.loads(existing)), False
                self._memory[idem_field] = RedisClient.dumps(job_id)
                self._memory[job_field] = encoded_job
                self._memory[intent_field] = encoded_intent
                return job_id, True

        assert self._redis is not None
        result = await self._redis.get_client().eval(
            _RESERVE_DISPATCH_LUA,
            1,
            self._key,
            idem_field,
            job_id,
            RedisClient.dumps(job_id),
            job_field,
            encoded_job,
            intent_field,
            encoded_intent,
        )
        reserved = result[0].decode() if isinstance(result[0], bytes) else str(result[0])
        return reserved, bool(int(result[1]))

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        value = await self.get_state("jobs", job_id)
        return value if isinstance(value, dict) else None

    async def set_job(self, job_id: str, job: dict[str, Any]) -> None:
        await self.set_state("jobs", job_id, job)

    async def get_dispatch_intent(self, job_id: str) -> dict[str, Any] | None:
        value = await self.get_state("dispatch_intents", job_id)
        return value if isinstance(value, dict) else None


__all__ = [
    "MOCK_STATE_NAMESPACES",
    "MOCK_OBSERVATION_IDEMPOTENCY_KEY",
    "MOCK_OBSERVATION_PROJECTION_KEY",
    "MOCK_TOOL_STATE_KEY",
    "MOCK_VERIFY_OVERRIDE_KEY",
    "MockEnvironmentState",
    "MockObservationRecord",
    "MockRollbackHistoryRecord",
    "MockStateRecord",
]
