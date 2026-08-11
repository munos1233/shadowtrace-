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
        # ISSUE-062 verify_node escalation flags (InvestigationGraph writer)
        "missing_response_plan_for_required_policy",
        "disposition_activation_failed",
        "verify_degraded",
        "execution_failed_unverified",
        # ISSUE-081 memory governance degradation
        "memory_review_enqueue_failed",
        "memory_governance_maintenance_failed",
        # ISSUE-208 memory consolidation scheduling failures
        "memory_after_analysis_failed",
        "memory_after_close_failed",
        # ISSUE-131 decision audit degradation
        "decision_audit_degraded",
        "auto_investigate_dispatch_unavailable",
        "auto_response_dispatch_unavailable",
        # ISSUE-309 output quality evaluator outage observability
        "output_quality_evaluator_unavailable",
        # ISSUE-193 graph resume observability
        "graph_resume_failed",
        # ISSUE-197 triage event_type fallback audit
        "event_type_from_heuristic",
        "event_type_from_llm_fallback",
        # ISSUE-211 triage list ORM rewrite observability
        "event_type_orm_rewrite_skipped",
        "event_type_orm_rewrite_failed",
        # ISSUE-200 triage vs risk scoring inconsistency
        "triage_risk_inconsistency",
        # ISSUE-242 report persistence contract / generation failure observability
        "report_generation_failed",
        # ISSUE-254 durable event_context_snapshot merge failures
        "event_context_snapshot_merge_failed",
        # ISSUE-275 Celery redelivery exhaustion / manual recovery
        "celery_redelivery_recovery_needed",
        # ISSUE-285 committed state with a degraded post-commit projection.
        "state_transition_projection_degraded",
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
        "SuperAgent",
        "InvestigationGraph",
        "MemoryAgent",
        "AgentTraceService",
        "DecisionRecordService",
        "InvestigationIntentService",
        # ISSUE-179 — EventContextStore clears redis_context_unavailable on recovery.
        "EventContextStore",
        # ISSUE-193 — graph resume failure observability
        "GraphResumeService",
        # ISSUE-197 — auditable event_type heuristic / LLM fallback
        "TriageAgent",
        # ISSUE-200 — triage vs risk scoring inconsistency audit
        "RiskAgent",
        # ISSUE-242 — report persistence failure observability
        "ReportAgent",
        # ISSUE-275 — Celery redelivery exhaustion recovery signal
        "CeleryRedeliveryService",
        # ISSUE-309 — output quality evaluator outage observability
        "OutputQualityEvaluator",
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


REDIS_CONTEXT_UNAVAILABLE_FLAG = "redis_context_unavailable"


def wire_redis_context_recovery(
    store: EventContextStore,
    degraded_flags: DegradedFlagService,
) -> None:
    """Register ISSUE-179 callback: clear sticky flag after rebuild_context Redis write."""

    async def _on_redis_recovery(event_id: str) -> None:
        if await degraded_flags.has_flag(event_id, REDIS_CONTEXT_UNAVAILABLE_FLAG):
            await degraded_flags.set_flag(
                event_id,
                REDIS_CONTEXT_UNAVAILABLE_FLAG,
                False,
                writer="EventContextStore",
            )

    store.set_on_redis_recovery(_on_redis_recovery)


def create_degraded_flag_service(
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> DegradedFlagService:
    """Construct DegradedFlagService with redis_context_unavailable recovery wired."""
    service = DegradedFlagService(store, session_factory)
    wire_redis_context_recovery(store, service)
    return service


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
                was_set = any(f == flag_name or str(f).startswith(f"{flag_name}=") for f in current)
                updated = apply_flag_to_list(current, flag_name, value)

                # ISSUE-179: Skip write and EventContext mirror when flag is
                # already in the desired state — prevents redundant journal
                # entries and Redis writes during concurrent rebuild_context.
                if updated == current:
                    return updated

                se.degraded_flags = updated
                await session.flush()

        # Mirror into EventContext via the store (owner path; skip WM recursion).
        await self._store.set(event_id, "degraded_flags", updated)

        # ISSUE-179: Rate-limited info log on true→false transition.
        if was_set and not value:
            logger.info(
                "degraded flag cleared: event_id=%s flag=%s writer=%s",
                event_id,
                flag_name,
                writer,
            )

        return updated

    async def has_flag(self, event_id: str, flag_name: str) -> bool:
        """Return True when ``flag_name`` (any value) is present on the event."""
        return (await self.get_flag_value(event_id, flag_name)) is not None

    async def get_flag_value(self, event_id: str, flag_name: str) -> str | None:
        """Return the value after ``=``, ``true`` for a bare flag, or None if absent."""
        async with self._session_factory() as session:
            se = await session.get(orm.SecurityEvent, event_id)
            if se is None:
                return None
            prefix = f"{flag_name}="
            for flag in se.degraded_flags or []:
                text = str(flag)
                if text == flag_name:
                    return "true"
                if text.startswith(prefix):
                    return text[len(prefix) :]
            return None
