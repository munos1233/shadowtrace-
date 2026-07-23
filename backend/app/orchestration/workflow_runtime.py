"""Workflow runtime orchestration helpers (ISSUE-048).

``WorkflowRuntimeService`` is the sole writer for ``disposition_only_intent`` and
``execution_substate`` (FIELD_OWNERSHIP).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import InvalidStateTransitionError, ValidationError
from app.core.event_bus import EventBus
from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    ExecutionSubstate,
    FinalVerdict,
    Severity,
)
from app.models.workflow import (
    EXECUTION_SUBSTATE_HOSTS,
    EXECUTION_SUBSTATE_TRANSITIONS,
    TransitionContext,
    validate_transition,
)
from app.services.context_service import EventContextStore, append_context_journal_in_session

logger = logging.getLogger(__name__)

_RUNTIME_OPERATOR = "WorkflowRuntimeService"


class WorkflowRuntimeService:
    """Trusted workflow side-effects for LangGraph execution."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        context_store: EventContextStore | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._context_store = context_store
        self._event_bus = event_bus

    async def begin_disposition_only(self, event_id: str) -> None:
        """Atomically mark FP verdict, raise confidence, and persist intent."""
        fp_score = await self._read_fp_max_score(event_id)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
                if row is None:
                    raise KeyError(f"security_event not found: {event_id}")

                if not await self._fp_signal_from_context(session, event_id):
                    raise ValidationError(
                        "begin_disposition_only requires close_as_fp false_positive_match",
                        details={"event_id": event_id},
                    )

                previous_verdict = row.final_verdict
                row.final_verdict = FinalVerdict.FALSE_POSITIVE.value
                row.confidence = max(float(row.confidence or 0.0), fp_score)
                row.row_version = int(row.row_version or 1) + 1
                row.updated_at = datetime.now(UTC)

                await append_context_journal_in_session(
                    session,
                    event_id,
                    "disposition_only_intent",
                    True,
                )
                session.add(
                    orm.EventAuditLog(
                        event_id=event_id,
                        from_status=row.status,
                        to_status=row.status,
                        operator=_RUNTIME_OPERATOR,
                        reason=(
                            f"begin_disposition_only:"
                            f"verdict={previous_verdict}->{FinalVerdict.FALSE_POSITIVE.value}"
                        ),
                    )
                )
                await session.flush()

        if self._context_store is not None:
            await self._context_store.set(event_id, "disposition_only_intent", True)

        if self._event_bus is not None:
            await self._event_bus.publish_event(
                event_id,
                "final_verdict_updated",
                {
                    "final_verdict": FinalVerdict.FALSE_POSITIVE.value,
                    "operator": _RUNTIME_OPERATOR,
                },
            )

    async def set_execution_substate(
        self,
        event_id: str,
        substate: ExecutionSubstate,
        *,
        event_status: EventStatus,
    ) -> None:
        """Validate host status and persist execution_substate."""
        allowed_hosts = EXECUTION_SUBSTATE_HOSTS.get(event_status, frozenset())
        if substate not in allowed_hosts and substate is not ExecutionSubstate.NONE:
            raise InvalidStateTransitionError(
                "execution_substate not allowed for event status",
                current=event_status.value,
                target=substate.value,
                details={"event_id": event_id},
            )

        current = await self._read_execution_substate(event_id)
        allowed = EXECUTION_SUBSTATE_TRANSITIONS.get(current, set())
        if substate is not current and substate not in allowed:
            raise InvalidStateTransitionError(
                "illegal execution_substate transition",
                current=current.value,
                target=substate.value,
                details={"event_id": event_id},
            )

        async with self._session_factory() as session:
            async with session.begin():
                await append_context_journal_in_session(
                    session,
                    event_id,
                    "execution_substate",
                    substate.value,
                )

        if self._context_store is not None:
            await self._context_store.set(event_id, "execution_substate", substate)

    async def assert_disposition_only_transition_allowed(
        self,
        event_id: str,
        *,
        target: EventStatus,
        current: EventStatus,
    ) -> None:
        """Reject forged disposition_only_intent without FP signal."""
        ctx = await self._authoritative_transition_context(event_id)
        validate_transition(current, target, ctx)

    async def _authoritative_transition_context(self, event_id: str) -> TransitionContext:
        async with self._session_factory() as session:
            row = await session.get(orm.SecurityEvent, event_id)
            if row is None:
                raise KeyError(event_id)
            intent = await self._journal_scalar(session, event_id, "disposition_only_intent")
            fp = await self._journal_dict(session, event_id, "false_positive_match")
            recommendation = fp.get("recommendation") if isinstance(fp, dict) else None
            return TransitionContext(
                final_verdict=FinalVerdict(row.final_verdict),
                need_investigation=None,
                disposition_only_intent=bool(intent),
                disposition_policy=DispositionPolicy(row.disposition_policy),
                severity=Severity(row.severity),
                recommendation=recommendation,
            )

    async def _fp_signal_from_context(self, session: AsyncSession, event_id: str) -> bool:
        fp = await self._journal_dict(session, event_id, "false_positive_match")
        return isinstance(fp, dict) and fp.get("recommendation") == "close_as_fp"

    async def _read_fp_max_score(self, event_id: str) -> float:
        async with self._session_factory() as session:
            fp = await self._journal_dict(session, event_id, "false_positive_match")
        if not isinstance(fp, dict):
            return 0.0
        try:
            return float(fp.get("max_score") or 0.0)
        except (TypeError, ValueError):
            return 0.0

    async def _read_execution_substate(self, event_id: str) -> ExecutionSubstate:
        async with self._session_factory() as session:
            raw = await self._journal_scalar(session, event_id, "execution_substate")
        if raw is None:
            return ExecutionSubstate.NONE
        try:
            return ExecutionSubstate(raw)
        except ValueError:
            return ExecutionSubstate.NONE

    async def _journal_scalar(
        self,
        session: AsyncSession,
        event_id: str,
        field_name: str,
    ) -> Any:
        row = await session.scalar(
            select(orm.EventContextJournal)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == field_name,
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        if row is None or row.value is None:
            return None
        value = row.value
        if isinstance(value, dict) and "_scalar" in value:
            return value["_scalar"]
        return value

    async def _journal_dict(
        self,
        session: AsyncSession,
        event_id: str,
        field_name: str,
    ) -> dict[str, Any] | None:
        raw = await self._journal_scalar(session, event_id, field_name)
        return raw if isinstance(raw, dict) else None
