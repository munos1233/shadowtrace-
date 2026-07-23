"""Shared FastAPI dependencies for API v1 (ISSUE-058)."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.redis_client import RedisClient
    from app.services.approval_engine import ApprovalEngine


@lru_cache
def _redis_client() -> RedisClient:
    from app.core.redis_client import RedisClient

    return RedisClient()


def get_approval_engine() -> ApprovalEngine:
    """Construct the tiered approval engine with runtime infrastructure."""
    from app.core.event_bus import EventBus
    from app.db.session import get_session_factory
    from app.services.approval_engine import ApprovalEngine
    from app.services.context_service import EventContextStore
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.event_audit_log_service import EventAuditLogService
    from app.services.state_machine_service import StateMachineService

    session_factory = get_session_factory()
    redis = _redis_client()
    event_bus = EventBus(redis)
    context_store = EventContextStore(redis, session_factory)
    audit_log = EventAuditLogService(session_factory)
    degraded = DegradedFlagService(context_store, session_factory)
    state_machine = StateMachineService(
        session_factory,
        context_store,
        event_bus=event_bus,
        audit_log=audit_log,
        degraded_flags=degraded,
    )
    return ApprovalEngine(
        session_factory,
        event_bus=event_bus,
        state_machine=state_machine,
        context_store=context_store,
    )
