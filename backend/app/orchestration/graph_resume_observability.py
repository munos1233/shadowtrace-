"""Observability for graph resume failures (ISSUE-193 / #735).

Resume hooks must not fail silently after approval or writeback: operators need
degraded flags, audit entries, and API-visible resume status while keeping
approval facts immutable.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import InvalidStateTransitionError, ValidationError
from app.db import models as orm
from app.orchestration.graph_invocation import is_in_investigation_graph
from app.orchestration.graph_resume import (
    GetSuperAgent,
    GetWorkflowRuntime,
    resume_investigation_from_checkpoint,
)
from app.services.degraded_flag_service import DegradedFlagService

logger = logging.getLogger(__name__)

GRAPH_RESUME_FAILED_FLAG = "graph_resume_failed"
GRAPH_RESUME_AUDIT_OPERATOR = "GraphResumeService"
GRAPH_RESUME_WRITER = "GraphResumeService"
_RESUME_MAX_ATTEMPTS = 3
_RESUME_RETRY_BASE_SECONDS = 0.05

ResumeStatus = Literal["ok", "failed", "skipped"]


class GraphResumeFailedError(Exception):
    """Raised when checkpoint resume cannot continue after retries."""

    def __init__(
        self,
        message: str,
        *,
        event_id: str,
        error_type: str,
        execution_substate: str | None = None,
    ) -> None:
        super().__init__(message)
        self.event_id = event_id
        self.error_type = error_type
        self.execution_substate = execution_substate


@dataclass(frozen=True)
class GraphResumeFailureContext:
    event_id: str
    error_type: str
    message: str
    execution_substate: str | None = None


def is_state_mismatch_error(exc: BaseException) -> bool:
    if isinstance(exc, ValidationError):
        return "caller EventStatus does not match authoritative state" in str(exc)
    if isinstance(exc, GraphResumeFailedError):
        return exc.error_type == "state_mismatch"
    return False


def classify_resume_error(exc: BaseException) -> str:
    if isinstance(exc, GraphResumeFailedError):
        return exc.error_type
    if is_state_mismatch_error(exc):
        return "state_mismatch"
    if isinstance(exc, InvalidStateTransitionError):
        return "invalid_state_transition"
    name = type(exc).__name__
    if name in {"TimeoutError", "ConnectionError", "RedisError", "ConnectionResetError"}:
        return "transient_dependency"
    return name


def is_transient_resume_error(exc: BaseException) -> bool:
    if is_state_mismatch_error(exc):
        return False
    if isinstance(exc, InvalidStateTransitionError):
        return False
    if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
        return True
    name = type(exc).__name__
    return name in {
        "TimeoutError",
        "ConnectionError",
        "ConnectionResetError",
        "RedisError",
        "RedisConnectionError",
    }


async def _read_execution_substate(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> str | None:
    async with session_factory() as session:
        substate_raw = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "execution_substate",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
    if isinstance(substate_raw, dict) and set(substate_raw) == {"_scalar"}:
        substate_raw = substate_raw["_scalar"]
    return str(substate_raw) if substate_raw is not None else None


async def record_graph_resume_failure(
    session_factory: async_sessionmaker[AsyncSession],
    degraded_flags: DegradedFlagService | None,
    context: GraphResumeFailureContext,
) -> None:
    """Persist degraded flag + structured audit; never rolls back approval facts."""
    error_type = context.error_type
    substate = context.execution_substate
    flag_value = error_type if substate is None else f"{error_type}|substate={substate}"

    if degraded_flags is not None:
        try:
            await degraded_flags.set_flag(
                context.event_id,
                GRAPH_RESUME_FAILED_FLAG,
                flag_value,
                writer=GRAPH_RESUME_WRITER,
            )
        except Exception:
            logger.exception(
                "failed to set graph_resume_failed degraded flag event=%s",
                context.event_id,
            )

    reason = f"graph_resume_failed:error_type={error_type}:message={context.message[:500]}"
    if substate is not None:
        reason = f"{reason}:execution_substate={substate}"

    async with session_factory() as session:
        async with session.begin():
            event_status = await session.scalar(
                select(orm.SecurityEvent.status).where(
                    orm.SecurityEvent.event_id == context.event_id
                )
            )
            session.add(
                orm.EventAuditLog(
                    event_id=context.event_id,
                    from_status=str(event_status) if event_status else None,
                    to_status=str(event_status) if event_status else None,
                    operator=GRAPH_RESUME_AUDIT_OPERATOR,
                    reason=reason[:4096],
                )
            )


async def clear_graph_resume_failure(
    degraded_flags: DegradedFlagService | None,
    event_id: str,
) -> None:
    if degraded_flags is None:
        return
    if not await degraded_flags.has_flag(event_id, GRAPH_RESUME_FAILED_FLAG):
        return
    try:
        await degraded_flags.set_flag(
            event_id,
            GRAPH_RESUME_FAILED_FLAG,
            False,
            writer=GRAPH_RESUME_WRITER,
        )
    except Exception:
        logger.exception(
            "failed to clear graph_resume_failed degraded flag event=%s",
            event_id,
        )


async def execute_graph_resume_with_retry(
    event_id: str,
    *,
    session_factory: async_sessionmaker[AsyncSession],
    get_super_agent: GetSuperAgent,
    get_workflow_runtime: GetWorkflowRuntime,
    degraded_flags: DegradedFlagService | None,
) -> None:
    """Resume with limited retries; record degraded + audit before raising."""
    if is_in_investigation_graph(event_id=event_id):
        logger.warning(
            "skip nested graph resume while graph active event=%s",
            event_id,
        )
        return

    last_exc: BaseException | None = None
    for attempt in range(_RESUME_MAX_ATTEMPTS):
        try:
            await resume_investigation_from_checkpoint(
                session_factory,
                event_id,
                get_super_agent=get_super_agent,
                get_workflow_runtime=get_workflow_runtime,
            )
            await clear_graph_resume_failure(degraded_flags, event_id)
            return
        except GraphResumeFailedError as exc:
            last_exc = exc
            break
        except Exception as exc:
            last_exc = exc
            if attempt + 1 < _RESUME_MAX_ATTEMPTS and is_transient_resume_error(exc):
                await asyncio.sleep(_RESUME_RETRY_BASE_SECONDS * (attempt + 1))
                continue
            break

    assert last_exc is not None
    if isinstance(last_exc, GraphResumeFailedError):
        error_type = last_exc.error_type
        message = str(last_exc)
        substate = last_exc.execution_substate
    else:
        substate = await _read_execution_substate(session_factory, event_id)
        error_type = classify_resume_error(last_exc)
        message = str(last_exc)
    context = GraphResumeFailureContext(
        event_id=event_id,
        error_type=error_type,
        message=message,
        execution_substate=substate,
    )
    await record_graph_resume_failure(session_factory, degraded_flags, context)
    logger.exception(
        "graph resume failed event=%s error_type=%s substate=%s",
        event_id,
        error_type,
        substate,
    )
    if isinstance(last_exc, GraphResumeFailedError):
        raise last_exc
    raise GraphResumeFailedError(
        message,
        event_id=event_id,
        error_type=error_type,
        execution_substate=substate,
    ) from last_exc


ResumeHook = Callable[[str], Awaitable[None]]


__all__ = [
    "GRAPH_RESUME_FAILED_FLAG",
    "GraphResumeFailedError",
    "GraphResumeFailureContext",
    "ResumeHook",
    "ResumeStatus",
    "clear_graph_resume_failure",
    "execute_graph_resume_with_retry",
    "is_state_mismatch_error",
    "record_graph_resume_failure",
]
