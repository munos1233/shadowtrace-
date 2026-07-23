"""DegradedFlagService — sole writer API for degraded_flags (ISSUE-014)."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import GuardrailViolationError, ValidationError
from app.db import models as orm
from app.services.context_service import EventContextStore

logger = logging.getLogger(__name__)

# Known flag names referenced by P0 issues / intro. Values are encoded as
# ``{flag_name}={value}`` strings inside the degraded_flags list.
DEGRADED_FLAG_ALLOWLIST: frozenset[str] = frozenset(
    {
        "redis_context_unavailable",
        "disposition_writeback_blocked",
    }
)

# Callers permitted to invoke set_flag (service names, not a generic ``system``).
DEGRADED_FLAG_TRUSTED_CALLERS: frozenset[str] = frozenset(
    {
        "WorkingMemory",
        "EventService",
        "StateMachineService",
        "DegradedFlagService",
        "AnalysisOnlyPipeline",
    }
)

DEGRADED_FLAGS_OWNER = "DegradedFlagService"


def format_degraded_flag(flag_name: str, value: Any) -> str | None:
    """Return the list entry to upsert, or None to clear the flag."""
    if value is False or value is None:
        return None
    if value is True:
        return f"{flag_name}=true"
    return f"{flag_name}={value}"


def apply_flag_to_list(flags: list[str], flag_name: str, value: Any) -> list[str]:
    """Return a new list with ``flag_name`` set/cleared; other flags preserved."""
    prefix = f"{flag_name}="
    remaining = [f for f in flags if not (f == flag_name or f.startswith(prefix))]
    entry = format_degraded_flag(flag_name, value)
    if entry is not None:
        remaining.append(entry)
    return remaining


class DegradedFlagService:
    """Unique write path for ``security_event.degraded_flags`` + EventContext mirror."""

    def __init__(
        self,
        store: EventContextStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._store = store
        self._session_factory = session_factory

    async def set_flag(
        self,
        event_id: str,
        flag_name: str,
        value: Any,
        writer: str,
    ) -> list[str]:
        """Upsert one degraded flag into PostgreSQL and EventContext.

        Returns the resulting ``degraded_flags`` list. Unauthorized callers or
        unknown flag names raise; Redis failure does not roll back PostgreSQL.
        """
        if writer not in DEGRADED_FLAG_TRUSTED_CALLERS:
            raise GuardrailViolationError(
                f"untrusted degraded_flags caller: {writer!r}",
                error_code="working_memory_unauthorized_write",
                details={
                    "event_id": event_id,
                    "flag_name": flag_name,
                    "writer": writer,
                    "trusted": sorted(DEGRADED_FLAG_TRUSTED_CALLERS),
                },
            )
        if flag_name not in DEGRADED_FLAG_ALLOWLIST:
            raise ValidationError(
                f"degraded flag not in allowlist: {flag_name!r}",
                error_code="validation_error",
                details={
                    "flag_name": flag_name,
                    "allowlist": sorted(DEGRADED_FLAG_ALLOWLIST),
                },
            )

        async with self._session_factory() as session:
            async with session.begin():
                se = await session.get(orm.SecurityEvent, event_id)
                if se is None:
                    raise ValidationError(
                        f"security_event not found: {event_id}",
                        error_code="event_not_found",
                        details={"event_id": event_id},
                    )
                current = [str(f) for f in (se.degraded_flags or [])]
                updated = apply_flag_to_list(current, flag_name, value)
                se.degraded_flags = updated
                await session.flush()

        # Mirror into EventContext via the store (owner path; skip WM recursion).
        await self._store.set(event_id, "degraded_flags", updated)
        return updated

    async def has_flag(self, event_id: str, flag_name: str) -> bool:
        """Return True when ``flag_name`` (any value) is present on the event."""
        async with self._session_factory() as session:
            se = await session.get(orm.SecurityEvent, event_id)
            if se is None:
                return False
            prefix = f"{flag_name}="
            return any(
                f == flag_name or str(f).startswith(prefix) for f in (se.degraded_flags or [])
            )
