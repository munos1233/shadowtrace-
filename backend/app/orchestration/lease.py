"""EventLease — Redis-based distributed lease to prevent duplicate orchestration (ISSUE-054).

Acquire uses ``SET NX EX`` for atomicity; release uses a Lua script to check
owner identity before deleting. When Redis is unavailable ``acquire`` raises
``DependencyUnavailableError`` (HTTP 503); duplicate triggers return ``False``
(HTTP 409).

Lease key: ``shadowtrace:lease:event:{event_id}``
Owner id:    ``worker-{8 hex chars}``
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from app.core.errors import DependencyUnavailableError
from app.core.redis_client import RedisClient

logger = logging.getLogger(__name__)

LEASE_KEY_PREFIX = "shadowtrace:lease:event:"
DEFAULT_LEASE_TTL_S = 600
RENEW_INTERVAL_S = 60

# Lua script: atomically delete the key only when the value matches owner_id.
# Returns: 1 = deleted, 0 = owner mismatch, -1 = key absent.
_RELEASE_SCRIPT = """
local val = redis.call("GET", KEYS[1])
if val == false then
    return -1
end
if val == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
"""


def _lease_key(event_id: str) -> str:
    return f"{LEASE_KEY_PREFIX}{event_id}"


def generate_owner_id() -> str:
    """Return a unique worker identity: ``worker-{8 hex chars}``."""
    return f"worker-{secrets.token_hex(4)}"


class EventLease:
    """Distributed lease backed by Redis.

    When Redis is unavailable, ``acquire`` raises
    :class:`~app.core.errors.DependencyUnavailableError` (HTTP 503).  Other
    methods return falsy values when Redis is down.
    """

    def __init__(self, redis_client: RedisClient | None) -> None:
        self._redis: Any = None
        if redis_client is not None:
            self._redis = redis_client.get_client()
        self._release_script: Any = None  # cached registered Lua script

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def acquire(
        self,
        event_id: str,
        owner_id: str,
        ttl_s: int = DEFAULT_LEASE_TTL_S,
    ) -> bool:
        """Atomically acquire the lease.  Returns ``True`` on success.

        Uses ``SET key owner_id NX EX ttl_s`` so only the first caller for
        a given *event_id* wins.  Returns ``False`` when another owner holds
        the lease.  Raises :class:`~app.core.errors.DependencyUnavailableError`
        when Redis is unavailable.
        """
        if self._redis is None:
            logger.warning(
                "EventLease.acquire: Redis unavailable, refusing lease for event=%s",
                event_id,
            )
            raise DependencyUnavailableError(
                message="event lease store unavailable",
                error_code="dependency_unavailable",
                details={"event_id": event_id, "dependency": "redis"},
            )
        key = _lease_key(event_id)
        acquired = await self._redis.set(key, owner_id, nx=True, ex=ttl_s)
        if acquired:
            logger.info(
                "EventLease: acquired lease for event=%s owner=%s ttl=%ds",
                event_id,
                owner_id,
                ttl_s,
            )
        else:
            logger.info(
                "EventLease: lease already held for event=%s (attempt by %s)",
                event_id,
                owner_id,
            )
        return bool(acquired)

    async def renew(self, event_id: str, owner_id: str) -> bool:
        """Extend the lease TTL — only when *owner_id* still matches.

        Returns ``True`` when the lease was successfully renewed.  Returns
        ``False`` when the key is absent (lease lost / expired / released by
        another party) or the owner no longer matches.
        """
        if self._redis is None:
            return False
        key = _lease_key(event_id)
        current = await self._redis.get(key)
        if current is None:
            # Lease already expired / released — cannot renew what we don't own.
            logger.warning(
                "EventLease.renew: lease key absent for event=%s — "
                "lease may have expired or been released by another worker",
                event_id,
            )
            return False
        decoded = current.decode("utf-8") if isinstance(current, bytes) else current
        if decoded != owner_id:
            logger.warning(
                "EventLease.renew: owner mismatch for event=%s (expected=%s, actual=%s)",
                event_id,
                owner_id,
                decoded,
            )
            return False
        await self._redis.expire(key, DEFAULT_LEASE_TTL_S)
        logger.debug(
            "EventLease: renewed lease for event=%s owner=%s",
            event_id,
            owner_id,
        )
        return True

    async def release(self, event_id: str, owner_id: str) -> bool:
        """Release the lease when *owner_id* matches.

        Uses a Lua script so the check-and-delete is atomic.  Returns
        ``True`` when the key was deleted or was already absent (idempotent).
        Returns ``False`` when the key exists but is owned by a different
        party — the caller must NOT proceed as if the lease is released.
        """
        if self._redis is None:
            return False
        key = _lease_key(event_id)
        if self._release_script is None:
            self._release_script = self._redis.register_script(_RELEASE_SCRIPT)
        result: Any = await self._release_script(keys=[key], args=[owner_id])
        code = int(result) if result is not None else -1
        if code == 1:
            logger.info(
                "EventLease: released lease for event=%s owner=%s",
                event_id,
                owner_id,
            )
            return True
        if code == -1:
            logger.debug(
                "EventLease.release: key already absent for event=%s (idempotent)",
                event_id,
            )
            return True
        # code == 0: owner mismatch — lease held by another worker.
        logger.warning(
            "EventLease.release: owner mismatch for event=%s "
            "(caller=%s) — lease held by another worker, NOT released",
            event_id,
            owner_id,
        )
        return False

    async def get_owner(self, event_id: str) -> str | None:
        """Inspect the current lease owner (for diagnostics only)."""
        if self._redis is None:
            return None
        key = _lease_key(event_id)
        value = await self._redis.get(key)
        if value is None:
            return None
        return value.decode("utf-8") if isinstance(value, bytes) else value

    # ------------------------------------------------------------------ #
    # Background renewal helpers
    # ------------------------------------------------------------------ #

    async def start_renewal(
        self,
        event_id: str,
        owner_id: str,
        *,
        on_renewal_failed: asyncio.Event | None = None,
    ) -> asyncio.Task[None]:
        """Launch a background task that renews the lease every 60 s.

        When *on_renewal_failed* is provided it is set when the renewal loop
        exits because of an owner mismatch (lease stolen).  The caller **must**
        cancel the returned task when the orchestration finishes (or fails) to
        stop the renewal loop.
        """

        async def _renew_loop() -> None:
            while True:
                await asyncio.sleep(RENEW_INTERVAL_S)
                try:
                    ok = await self.renew(event_id, owner_id)
                    if not ok:
                        logger.error(
                            "EventLease: renewal failed for event=%s owner=%s "
                            "- lease may have been stolen",
                            event_id,
                            owner_id,
                        )
                        if on_renewal_failed is not None:
                            on_renewal_failed.set()
                        break
                except Exception:
                    logger.warning(
                        "EventLease: renewal error for event=%s",
                        event_id,
                        exc_info=True,
                    )

        task = asyncio.create_task(_renew_loop())
        return task


__all__ = ["DEFAULT_LEASE_TTL_S", "EventLease", "RENEW_INTERVAL_S", "generate_owner_id"]
