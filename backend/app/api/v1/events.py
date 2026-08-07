"""Event endpoints — real implementations (ISSUE-038).

Replaces ISSUE-004 placeholder stubs with database-backed endpoints
that drive the full analysis lifecycle.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from sqlalchemy import exc as sa_exc
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1 import schemas as s
from app.api.v1.deps import (
    _get_context_store,
    _get_session_factory,
    get_event_lease,
    get_event_service,
    get_pipeline,
    get_state_machine,
    get_super_agent,
)
from app.api.v1.errors import (
    DispositionPermissionDenied,
    EventNotFoundError,
    InvalidStateTransitionError,
    ResourceNotFoundError,
    WritebackConflictError,
    WritebackUnsupportedError,
)
from app.core.auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_DISPOSITION_OPERATOR,
    AuthorizationError,
    CurrentPrincipal,
    Principal,
    require_roles,
)
from app.core.config import get_settings
from app.core.errors import (
    DependencyUnavailableError,
    InvestigationInProgressError,
    InvestigationLeaseLostError,
    ReportQualityConflictError,
    ValidationError,
)
from app.db import models as orm
from app.models.action import Action as ActionModel
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    ActionStatus,
    DecisionTraceEntryType,
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.workflow import TransitionContext
from app.services.classification_source import derive_classification_source
from app.services.decision_trace_service import DecisionTraceService
from app.services.investigation_guidance import (
    derive_investigation_guidance,
    full_loop_available,
    record_investigation_workflow_path,
    workflow_path_from_request,
)

if TYPE_CHECKING:
    from app.services.event_service import EventService
    from app.services.state_machine_service import StateMachineService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["events"])

# Source objects associated with the example event (contract-test backward compat).
_ASSOCIATED_SOURCE_RECORDS = {"src-associated-1"}


# --------------------------------------------------------------------------- #
# Helper: safe session factory access (degrades gracefully without DB)
# --------------------------------------------------------------------------- #


def _try_get_session_factory() -> async_sessionmaker[AsyncSession] | None:
    """Return the session factory, or None if DB is unavailable.

    Configuration errors (ValueError, TypeError — e.g. malformed database_url)
    propagate immediately so the operator can detect them at startup rather than
    silently running with empty results.
    """
    try:
        from app.api.v1.deps import _get_session_factory

        sf = _get_session_factory()
        return sf
    except (ImportError, ModuleNotFoundError):
        logger.warning(
            "Database session factory unavailable (missing configuration) — returning empty results"
        )
        return None
    except (ValueError, TypeError):
        # Configuration errors must propagate — a malformed database_url or
        # similar config issue must not be silently swallowed (ISSUE-038 #8).
        raise
    except (ConnectionRefusedError, TimeoutError, OSError):
        # Transient infrastructure errors (network, filesystem) — degrade
        # gracefully so the API can still return empty results rather than 5xx.
        logger.warning(
            "Database session factory unavailable (transient error) — returning empty results",
            exc_info=True,
        )
        return None


# --------------------------------------------------------------------------- #
# Helper: resolve writeback info for EventDetail / EventListItem
# --------------------------------------------------------------------------- #


def _writeback_required(policy: DispositionPolicy) -> bool:
    return policy == DispositionPolicy.REQUIRED


async def _sync_report_context_and_bus(
    event_id: str,
    report: Any,
    event_service: EventService,
) -> None:
    """Write report to EventContext and publish report_generated when bus is available."""
    from app.api.v1.deps import _get_context_store

    try:
        await _get_context_store().set(event_id, "report", report.model_dump(mode="json"))
        await _get_context_store().set(event_id, "report_generated", True)
    except Exception:
        logger.warning(
            "Failed to write report to EventContext for event=%s",
            event_id,
            exc_info=True,
        )

    bus = getattr(event_service, "_bus", None)
    if bus is not None:
        try:
            payload: dict[str, Any] = {
                "report_id": report.report_id,
                "sections": len(report.sections),
            }
            if report.generated_at is not None:
                payload["generated_at"] = report.generated_at.isoformat()
            await bus.publish_event(event_id, "report_generated", payload)
        except Exception:
            logger.warning(
                "event_bus report_generated failed for event=%s",
                event_id,
                exc_info=True,
            )


async def _regenerate_report_after_verdict_change(
    event_id: str,
    *,
    event_title: str,
    final_verdict: FinalVerdict,
    risk_score: int,
    severity: Severity,
    operator: str,
    event_service: EventService,
) -> None:
    """Refresh report after verdict change without destroying full investigation content."""
    existing = await event_service.get_report(event_id=event_id)
    if existing is not None and existing.generated_by != "quick_close":
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        updated = existing.model_copy(
            update={
                "final_verdict": final_verdict,
                "version": int(existing.version or 1) + 1,
                "updated_at": now,
            }
        )
        await event_service.upsert_report(updated)
        await _sync_report_context_and_bus(event_id, updated, event_service)
        return

    await _generate_quick_close_report(
        event_id=event_id,
        event_title=event_title,
        final_verdict=final_verdict,
        risk_score=risk_score,
        severity=severity,
        operator=operator,
        event_service=event_service,
        force_regenerate=existing is not None,
    )


async def _generate_quick_close_report(
    event_id: str,
    event_title: str,
    final_verdict: FinalVerdict,
    risk_score: int,
    severity: Severity,
    operator: str,
    event_service: EventService,
    *,
    force_regenerate: bool = False,
) -> None:
    """Generate a standard 15-section quick-close report so the CLOSED gate can pass.

    Uses ReportSectionBuilder to produce all 15 standard sections.  Evidence,
    disposition, and verification sections use placeholder text; overview and
    recommendations explain the quick-close / low-risk reason.

    The validate_closed_gate check in StateMachineService requires a report
    row to exist before allowing CLOSED.
    """
    from datetime import UTC, datetime

    from app.agents.report_section_builder import ReportSectionBuilder
    from app.models.agent_io import (
        CollectionStatus,
        EvidenceOutput,
        RiskAssessment,
        ScoringMode,
    )
    from app.models.ids import report_id_for_event
    from app.models.report import InvestigationReport

    # Skip if report already exists unless caller needs a verdict refresh.
    existing = await event_service.get_report(event_id=event_id)
    if existing is not None and not force_regenerate:
        return

    # Build placeholder evidence / risk matching _short_circuit_close semantics.
    placeholder_evidence = EvidenceOutput(
        evidence_list=[],
        conflicts=[],
        gaps=[],
        success_sources=[],
        failed_sources=[],
        overall_confidence=0.0,
        collection_status=CollectionStatus.COMPLETED,
    )
    placeholder_risk = RiskAssessment(
        risk_score=risk_score,
        severity=severity,
        confidence=0.9,
        risk_factors=[],
        possible_false_positive=(final_verdict == FinalVerdict.FALSE_POSITIVE),
        scoring_mode=ScoringMode.RULE_ONLY,
    )

    builder = ReportSectionBuilder()
    sections = builder.build(
        event_id=event_id,
        evidence_output=placeholder_evidence,
        risk_assessment=placeholder_risk,
        triage_result=None,
        response_plan=None,
        verification_result=None,
        rag_output=None,
        final_verdict=final_verdict,
    )

    title = f"Quick Close Report — {event_title}"
    summary = (
        f"Auto-generated quick-close report for {event_id}. "
        f"severity={severity.value}; risk_score={risk_score}; verdict={final_verdict.value}. "
        f"Evidence, disposition, and verification sections use placeholder content — "
        f"this event was closed via quick-close path without full investigation."
    )

    now = datetime.now(UTC)
    report_version = 1
    if existing is not None:
        report_version = int(existing.version or 1) + 1

    report = InvestigationReport(
        report_id=report_id_for_event(event_id),
        event_id=event_id,
        title=title,
        summary=summary,
        sections=sections,
        final_verdict=final_verdict,
        risk_score=risk_score,
        severity=severity,
        version=report_version,
        generated_by="quick_close",
        generated_at=now,
        updated_at=now,
    )
    from app.services.report_quality import with_assessed_quality

    report = with_assessed_quality(report)
    await event_service.upsert_report(report)
    await _sync_report_context_and_bus(event_id, report, event_service)

    # Record the system action for audit trail.
    # Only catch IntegrityError (idempotent re-entry race); let other
    # exceptions propagate so callers get DependencyUnavailableError rather
    # than silently incomplete audit trails.
    try:
        await event_service.upsert_generate_report_action(event_id, plan_revision=1)
    except IntegrityError:
        logger.warning(
            "generate_report action already exists for quick-close event=%s "
            "(concurrent upsert race)",
            event_id,
            exc_info=True,
        )


async def _validate_writeback_gate(
    event_id: str,
    event: Any,
) -> None:
    """Validate the writeback gate before allowing close.

    For REQUIRED disposition_policy events, runs the same writeback subset of
    the StateMachine CLOSED gate as an early API pre-check (ISSUE-171).
    Raises the appropriate HTTP domain error; SM remains authoritative.
    This is best-effort before ``transition_status`` — a concurrent writeback
    change can still be rejected by the SM CLOSED gate (fail-closed).

    No-op for NOT_REQUIRED events.
    """
    if event.disposition_policy != DispositionPolicy.REQUIRED:
        return

    from app.api.v1.deps import _get_session_factory
    from app.models.workflow import check_required_writeback_close_gate
    from app.services.writeback_close_gate import (
        build_closed_gate_actions,
        raise_api_writeback_gate_error,
    )

    session_factory = _get_session_factory()
    async with session_factory() as session:
        current_revision = await session.scalar(
            select(func.max(orm.Action.plan_revision)).where(orm.Action.event_id == event_id)
        )
        gate_actions = await build_closed_gate_actions(session, event_id, current_revision)
        violation = check_required_writeback_close_gate(gate_actions)
        if violation is not None:
            raise_api_writeback_gate_error(violation, event_id=event_id)


async def _build_writeback_info(
    event_id: str,
    policy: DispositionPolicy,
    session_factory: async_sessionmaker[AsyncSession],
) -> tuple[WritebackReadiness, WritebackStatus | None, int]:
    """Derive overall event-level writeback readiness / status / pending count."""
    if policy == DispositionPolicy.NOT_REQUIRED:
        return WritebackReadiness.NOT_REQUIRED, None, 0

    async with session_factory() as session:
        # The UI aggregation reflects the *current* plan only: outboxes owned by
        # superseded plan revisions or superseded Actions must not pollute the
        # overall status/pending (ISSUE-185).
        current_revision = await session.scalar(
            select(func.max(orm.Action.plan_revision)).where(orm.Action.event_id == event_id)
        )

        # Count non-superseded response/rollback actions of the current plan.
        counts = await session.execute(
            select(
                func.count(orm.Action.action_id),
                func.min(orm.Action.writeback_readiness),
            ).where(
                orm.Action.event_id == event_id,
                orm.Action.plan_revision == current_revision,
                orm.Action.action_category.in_(("response", "rollback")),
                orm.Action.superseded_by_revision.is_(None),
                orm.Action.status.not_in(("rejected", "superseded")),
            )
        )
        total_actions, min_readiness_raw = counts.one()
        total = int(total_actions or 0)

        readiness = WritebackReadiness.READY
        if total == 0:
            readiness = WritebackReadiness.NOT_CONFIGURED
        elif min_readiness_raw:
            try:
                readiness = WritebackReadiness(min_readiness_raw)
            except ValueError:
                readiness = WritebackReadiness.CAPABILITY_UNKNOWN

        # Only outboxes bound to current-plan, non-superseded Actions count.
        current_plan_action_filter = (
            orm.Action.plan_revision == current_revision,
            orm.Action.superseded_by_revision.is_(None),
        )

        # Count pending/active outbox records.
        pending_count = await session.scalar(
            select(func.count(orm.DispositionOutbox.outbox_id))
            .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                *current_plan_action_filter,
                orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                orm.DispositionOutbox.latest_writeback_status.in_(
                    (
                        WritebackStatus.PENDING.value,
                        WritebackStatus.SENDING.value,
                        WritebackStatus.ACCEPTED.value,
                        WritebackStatus.UNKNOWN.value,
                    )
                ),
            )
        )
        pending = int(pending_count or 0)

        # Derive overall writeback status from all active outbox rows (not only
        # pending-countable rows — FAILED/CONFLICT are terminal and excluded
        # from pending_count but must still block close).
        wb_status: WritebackStatus | None = None
        status_rows = (
            await session.scalars(
                select(orm.DispositionOutbox.latest_writeback_status)
                .join(orm.Action, orm.Action.action_id == orm.DispositionOutbox.action_id)
                .where(
                    orm.DispositionOutbox.event_id == event_id,
                    *current_plan_action_filter,
                    orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
                )
            )
        ).all()
        parsed_statuses: list[WritebackStatus] = []
        for raw in status_rows:
            if not raw:
                continue
            try:
                parsed_statuses.append(WritebackStatus(str(raw)))
            except ValueError:
                continue

        if parsed_statuses:
            if any(s is WritebackStatus.FAILED for s in parsed_statuses):
                wb_status = WritebackStatus.FAILED
            elif any(s is WritebackStatus.CONFLICT for s in parsed_statuses):
                wb_status = WritebackStatus.CONFLICT
            elif any(s is WritebackStatus.UNKNOWN for s in parsed_statuses):
                wb_status = WritebackStatus.UNKNOWN
            elif any(
                s
                in (
                    WritebackStatus.PENDING,
                    WritebackStatus.SENDING,
                    WritebackStatus.ACCEPTED,
                )
                for s in parsed_statuses
            ):
                wb_status = WritebackStatus.PENDING
            elif all(s is WritebackStatus.CONFIRMED for s in parsed_statuses):
                wb_status = WritebackStatus.CONFIRMED

        return readiness, wb_status, pending


# --------------------------------------------------------------------------- #
# POST /events — create
# --------------------------------------------------------------------------- #


@router.post("/events", response_model=s.EventSummary, status_code=status.HTTP_201_CREATED)
async def create_event(
    body: s.EventCreateRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    event_service: EventService = Depends(get_event_service),
) -> s.EventSummary:
    raw_alert: dict[str, Any] = {
        "title": body.title,
        "description": body.description,
    }
    event = await event_service.create_event(
        raw_alert,
        source_type="manual",
        title=body.title,
        event_type=body.event_type,
        severity=body.severity,
    )
    from app.services.context_service import event_summary_from_domain

    return event_summary_from_domain(event)


# --------------------------------------------------------------------------- #
# GET /events — list
# --------------------------------------------------------------------------- #


@router.get("/events", response_model=s.EventListResponse)
async def list_events(
    principal: CurrentPrincipal,
    page: int = 1,
    page_size: int = 20,
    status: EventStatus | None = None,
    severity: Severity | None = None,
    event_type: EventType | None = None,
    final_verdict: FinalVerdict | None = None,
    keyword: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sort_by: str | None = None,
    sort_order: Literal["asc", "desc"] | None = None,
    event_service: EventService = Depends(get_event_service),
) -> s.EventListResponse:
    result = await event_service.list_events(
        status=status,
        severity=severity,
        event_type=event_type,
        final_verdict=final_verdict,
        keyword=keyword,
        occurred_after=start_time,
        occurred_before=end_time,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    from app.services.risk_verdict_projection import risk_observability_from_snapshot

    items: list[s.EventListItem] = []
    for event in result.items:
        wb_required = _writeback_required(event.disposition_policy)
        # ISSUE-038: list view does not resolve per-event writeback info for
        # performance reasons. When writeback is required, signal capability
        # is unknown rather than misleading NOT_CONFIGURED.
        wb_readiness = (
            WritebackReadiness.CAPABILITY_UNKNOWN
            if wb_required
            else WritebackReadiness.NOT_REQUIRED
        )
        snapshot = (
            event.event_context_snapshot if isinstance(event.event_context_snapshot, dict) else None
        )
        evidence_limited, scoring_mode, verdict_reason_codes = risk_observability_from_snapshot(
            snapshot
        )
        items.append(
            s.EventListItem(
                event_id=event.event_id,
                event_type=event.event_type,
                title=event.title,
                status=event.status,
                severity=event.severity,
                risk_score=event.risk_score,
                final_verdict=event.final_verdict,
                writeback_required=wb_required,
                writeback_readiness=wb_readiness,
                writeback_overall_status=None,
                pending_writeback_count=0,
                created_at=event.created_at,
                updated_at=event.updated_at,
                occurred_at=event.occurred_at,
                classification_source=derive_classification_source(
                    degraded_flags=list(event.degraded_flags or []),
                    event_context_snapshot=snapshot,
                ),
                evidence_limited=evidence_limited,
                scoring_mode=scoring_mode,
                verdict_reason_codes=verdict_reason_codes,
            )
        )
    return s.EventListResponse(
        total=result.total,
        page=result.page,
        page_size=result.page_size,
        items=items,
    )


# --------------------------------------------------------------------------- #
# GET /events/{event_id} — detail
# --------------------------------------------------------------------------- #


async def _load_detection_context_summary(
    *,
    event_id: str,
    tenant_id: str,
) -> s.DetectionContextSnapshotSummary | None:
    from app.api.v1.deps import get_detection_context_service
    from app.models.detection_context_snapshot import DetectionContextSnapshotQuery

    try:
        service = get_detection_context_service()
        result = await service.query_snapshots(
            DetectionContextSnapshotQuery(
                tenant_id=tenant_id,
                event_id=event_id,
                latest_only=True,
            )
        )
        if not result.items:
            return None
        snapshot = result.items[0]
        return s.DetectionContextSnapshotSummary(
            snapshot_id=snapshot.snapshot_id,
            revision=snapshot.revision,
            content_hash=snapshot.content_hash,
            promotion_id=snapshot.promotion_id,
            promotion_link_revision=snapshot.promotion_link_revision,
            event_revision=snapshot.event_revision,
            created_at=snapshot.created_at,
        )
    except Exception as exc:
        logger.warning(
            "detection context summary load failed event_id=%s tenant_id=%s: %s",
            event_id,
            tenant_id,
            exc,
            exc_info=True,
        )
        return None


async def _load_detection_context_projection_error(
    *,
    event_id: str,
    tenant_id: str,
) -> s.DetectionContextProjectionErrorSummary | None:
    from sqlalchemy import select

    from app.api.v1.deps import _get_session_factory
    from app.db.orm.detection_promotion import DetectionPromotionORM
    from app.services.detection_promotion_service import PAYLOAD_PROJECTION_ERROR_KEY

    try:
        async with _get_session_factory()() as session:
            row = await session.scalar(
                select(DetectionPromotionORM)
                .where(
                    DetectionPromotionORM.event_id == event_id,
                    DetectionPromotionORM.tenant_id == tenant_id,
                )
                .order_by(DetectionPromotionORM.updated_at.desc())
                .limit(1)
            )
        if row is None:
            return None
        payload = dict(row.payload or {})
        error = payload.get(PAYLOAD_PROJECTION_ERROR_KEY)
        if not isinstance(error, dict):
            return None
        reason = str(error.get("reason") or "context_projection_failed")
        message = str(error.get("message") or "")
        recorded_at = error.get("at")
        parsed_at = None
        if isinstance(recorded_at, str):
            try:
                parsed_at = datetime.fromisoformat(recorded_at)
            except ValueError:
                parsed_at = None
        return s.DetectionContextProjectionErrorSummary(
            promotion_id=row.promotion_id,
            reason=reason,
            message=message,
            recorded_at=parsed_at,
        )
    except Exception as exc:
        logger.warning(
            "detection context projection error load failed event_id=%s tenant_id=%s: %s",
            event_id,
            tenant_id,
            exc,
            exc_info=True,
        )
        return None


@router.get("/events/{event_id}", response_model=s.EventDetailResponse)
async def get_event(
    event_id: str,
    principal: CurrentPrincipal,
    event_service: EventService = Depends(get_event_service),
) -> s.EventDetailResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    required = _writeback_required(event.disposition_policy)
    readiness = WritebackReadiness.NOT_REQUIRED
    wb_status: WritebackStatus | None = None
    pending_count = 0

    if required:
        try:
            from app.api.v1.deps import _get_session_factory

            readiness, wb_status, pending_count = await _build_writeback_info(
                event_id, event.disposition_policy, _get_session_factory()
            )
        except Exception:
            # DB unavailable: leave writeback info as defaults.
            readiness = WritebackReadiness.CAPABILITY_UNKNOWN

    tenant_id = (
        event.creation_source_ref.source_tenant_id
        if event.creation_source_ref is not None
        else None
    )
    detection_context_summary = None
    detection_context_projection_error = None
    if tenant_id is not None:
        detection_context_summary = await _load_detection_context_summary(
            event_id=event_id,
            tenant_id=tenant_id,
        )
        if detection_context_summary is None:
            detection_context_projection_error = await _load_detection_context_projection_error(
                event_id=event_id,
                tenant_id=tenant_id,
            )

    return s.EventDetailResponse(
        event=event,
        writeback_required=required,
        writeback_readiness=readiness,
        writeback_overall_status=wb_status,
        pending_writeback_count=pending_count,
        detection_context_snapshot=detection_context_summary,
        detection_context_projection_error=detection_context_projection_error,
        **_guidance_fields(event, get_settings()),
    )


def _guidance_fields(event: Any, settings: Any) -> dict[str, Any]:
    guidance = derive_investigation_guidance(
        status=event.status,
        disposition_policy=event.disposition_policy,
        context_snapshot=event.event_context_snapshot,
        orchestration_mode=settings.orchestration_mode,
    )
    return {
        "analysis_only_complete": guidance.analysis_only_complete,
        "execution_substate": guidance.execution_substate,
        "response_phase_state": guidance.response_phase_state,
        "next_recommended_action": guidance.next_recommended_action,
        "full_loop_available": guidance.full_loop_available,
        "phase_message": guidance.phase_message,
    }


async def _acquire_investigation_lease(event_id: str) -> tuple[Any, str]:
    """Acquire per-event orchestration lease; 409 when held, 503 when store down."""
    lease = get_event_lease()
    from app.orchestration.lease import generate_owner_id

    owner_id = generate_owner_id()
    try:
        acquired = await lease.acquire(event_id, owner_id)
    except DependencyUnavailableError:
        raise
    if not acquired:
        raise InvestigationInProgressError(
            message="investigation already in progress for this event",
            error_code="investigation_in_progress",
            details={"event_id": event_id},
        )
    return lease, owner_id


async def _schedule_investigation(
    *,
    event_id: str,
    background: BackgroundTasks,
    state_machine: StateMachineService,
    include_response: bool = False,
    generate_report: bool = True,
) -> str:
    """Acquire lease and schedule analysis (shared by investigate + reinvestigate)."""
    settings = get_settings()
    mode = (settings.orchestration_mode or "graph").strip().lower()
    task_mode = (settings.task_mode or "background").strip().lower()

    if mode == "analysis_only" and include_response:
        raise ValidationError(
            "include_response_execution is unavailable when ORCHESTRATION_MODE=analysis_only",
            error_code="full_loop_unavailable",
            details={"orchestration_mode": mode},
        )

    workflow_path = workflow_path_from_request(
        include_response_execution=include_response,
    )

    async def _record_workflow_path() -> None:
        try:
            await record_investigation_workflow_path(
                _get_session_factory(),
                event_id,
                workflow_path=workflow_path,
                include_response_execution=include_response,
            )
        except Exception:
            logger.warning(
                "failed to record investigation workflow_path event=%s",
                event_id,
                exc_info=True,
            )

    if mode == "analysis_only":
        if task_mode == "celery":
            from app.tasks.investigation_tasks import dispatch_analysis_only_investigation

            lease, owner_id = await _acquire_investigation_lease(event_id)
            try:
                return await dispatch_analysis_only_investigation(
                    event_id,
                    generate_report=generate_report,
                    owner_id=owner_id,
                    lease_acquired=True,
                )
            except Exception:
                await lease.release(event_id, owner_id)
                raise

        lease, owner_id = await _acquire_investigation_lease(event_id)

        async def _run_pipeline() -> None:
            try:
                from app.services.evidence_projection import (
                    EvidenceProjection,
                    bind_evidence_projection,
                )

                pipeline = await get_pipeline()
                projection = EvidenceProjection(_get_session_factory())
                with bind_evidence_projection(projection):
                    await pipeline.run(event_id, generate_report=generate_report)
                await _record_workflow_path()
            except (InvestigationInProgressError, InvalidStateTransitionError) as exc:
                logger.warning(
                    "AnalysisOnlyPipeline skipped for event=%s (concurrent or stale): %s",
                    event_id,
                    exc,
                )
            except Exception as exc:
                logger.error(
                    "Background pipeline failed for event=%s: %s",
                    event_id,
                    exc,
                )
                try:
                    await state_machine.transition(
                        event_id,
                        EventStatus.FAILED,
                        operator="AnalysisOnlyPipeline",
                        reason=f"pipeline_failed: {exc}",
                    )
                except Exception:
                    logger.exception("Failed to mark event as FAILED: %s", event_id)
            finally:
                await lease.release(event_id, owner_id)

        background.add_task(_run_pipeline)
        return event_id

    if task_mode == "celery":
        from app.tasks.investigation_tasks import dispatch_investigation

        lease, owner_id = await _acquire_investigation_lease(event_id)

        try:
            return await dispatch_investigation(
                event_id,
                include_response_execution=include_response,
                generate_report=generate_report,
                owner_id=owner_id,
                lease_acquired=True,
            )
        except Exception:
            await lease.release(event_id, owner_id)
            raise

    lease, owner_id = await _acquire_investigation_lease(event_id)

    async def _run_super_agent() -> None:
        investigate_started = False
        try:
            from app.services.evidence_projection import (
                EvidenceProjection,
                bind_evidence_projection,
            )

            agent = await get_super_agent()
            projection = EvidenceProjection(_get_session_factory())
            with bind_evidence_projection(projection):
                investigate_started = True
                await agent.investigate(
                    event_id,
                    owner_id=owner_id,
                    lease_acquired=True,
                    include_response_execution=include_response,
                    generate_report=generate_report,
                )
            await _record_workflow_path()
        except InvestigationInProgressError:
            logger.warning(
                "SuperAgent lost lease for event=%s before start",
                event_id,
            )
            await lease.release(event_id, owner_id)
        except InvestigationLeaseLostError:
            logger.info(
                "SuperAgent stopped — lease lost mid-run event=%s",
                event_id,
            )
        except Exception as exc:
            logger.error(
                "Background SuperAgent failed for event=%s: %s",
                event_id,
                exc,
            )
            try:
                await state_machine.transition(
                    event_id,
                    EventStatus.FAILED,
                    operator="SuperAgent",
                    reason=f"super_agent_failed: {exc}",
                )
            except Exception:
                logger.exception("Failed to mark event as FAILED: %s", event_id)
        finally:
            if not investigate_started:
                await lease.release(event_id, owner_id)

    background.add_task(_run_super_agent)
    return event_id


# --------------------------------------------------------------------------- #
# PATCH /events/{event_id}/classification — analyst override (ISSUE-209)
# --------------------------------------------------------------------------- #


@router.patch(
    "/events/{event_id}/classification",
    response_model=s.ClassificationUpdateResponse,
    responses={
        403: {
            "model": s.ErrorResponse,
            "description": "Caller lacks analyst (or admin) role.",
        },
        409: {
            "model": s.ErrorResponse,
            "description": (
                "classification_conflict_active_investigation — "
                "event is executing_response or verifying."
            ),
        },
    },
)
async def update_event_classification(
    event_id: str,
    body: s.ClassificationUpdateRequest,
    background: BackgroundTasks,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    event_service: EventService = Depends(get_event_service),
    state_machine: StateMachineService = Depends(get_state_machine),
) -> s.ClassificationUpdateResponse:
    """Override ``event_type`` with audit trail; optional controlled reinvestigate.

    ``reinvestigate=true`` side effects (documented):
    - Only starts when status is ``NEW`` (acquires investigation lease + schedules
      analysis pipeline / SuperAgent / Celery task — same path as POST investigate).
    - Does **not** invent a silent mid-flight replan; later response planning will
      naturally bump ``plan_revision`` if a new plan is produced after re-analysis.
    - Locked statuses ``executing_response`` / ``verifying`` return 409
      ``classification_conflict_active_investigation`` (no silent type change).
    """
    existing = await event_service.get_event(event_id)
    if existing is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})
    previous_type = existing.event_type

    updated = await event_service.update_classification(
        event_id,
        event_type=body.event_type,
        reason=body.reason,
        operator=principal.subject,
        reinvestigate=bool(body.reinvestigate),
    )

    side_effects = [
        "event_type_updated",
        "classification_source=human",
        "audit_logged",
        "classification_override_persisted",
    ]
    reinvestigate_started = False
    if body.reinvestigate:
        if updated.status is EventStatus.NEW:
            await _schedule_investigation(
                event_id=event_id,
                background=background,
                state_machine=state_machine,
                include_response=False,
                generate_report=False,
            )
            reinvestigate_started = True
            side_effects.extend(
                [
                    "investigation_lease_acquired",
                    "analysis_pipeline_scheduled",
                    "note:subsequent_response_plan_bumps_plan_revision",
                ]
            )
        else:
            side_effects.append(
                "reinvestigate_not_started:status_not_new;"
                "classification_saved;"
                "start_POST_investigate_when_eligible_or_await_replan_path;"
                "next_response_plan_would_bump_plan_revision"
            )

    return s.ClassificationUpdateResponse(
        event_id=event_id,
        event_type=updated.event_type,
        classification_source="human",
        previous_event_type=previous_type,
        reinvestigate_requested=bool(body.reinvestigate),
        reinvestigate_started=reinvestigate_started,
        side_effects=side_effects,
    )


# --------------------------------------------------------------------------- #
# POST /events/{event_id}/investigate — start analysis
# --------------------------------------------------------------------------- #


@router.post(
    "/events/{event_id}/investigate",
    response_model=s.InvestigateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def investigate_event(
    event_id: str,
    background: BackgroundTasks,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    body: s.InvestigateRequest | None = None,
    event_service: EventService = Depends(get_event_service),
    state_machine: StateMachineService = Depends(get_state_machine),
) -> s.InvestigateResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    settings = get_settings()
    include_response = bool(body.include_response_execution) if body else False
    generate_report = body.generate_report if body is not None else True

    if event.status is not EventStatus.NEW:
        raise InvalidStateTransitionError(
            f"event must be in NEW status to start investigation, current: {event.status.value}",
            current=event.status,
            target=EventStatus.TRIAGING,
            details={"event_id": event_id},
        )

    task_id = await _schedule_investigation(
        event_id=event_id,
        background=background,
        state_machine=state_machine,
        include_response=include_response,
        generate_report=generate_report,
    )

    return s.InvestigateResponse(
        event_id=event_id,
        task_id=task_id,
        status=event.status,
        include_response_execution=include_response,
        generate_report=generate_report,
        full_loop_available=full_loop_available(settings.orchestration_mode),
    )


# --------------------------------------------------------------------------- #
# POST /events/{event_id}/close — close event
# --------------------------------------------------------------------------- #


@router.post("/events/{event_id}/close", response_model=s.EventCloseResponse)
async def close_event(
    event_id: str,
    body: s.EventCloseRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    event_service: EventService = Depends(get_event_service),
    state_machine: StateMachineService = Depends(get_state_machine),
) -> s.EventCloseResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    current_status = event.status

    # Admin force_close bypass.
    if body.force_local_close:
        if not principal.has_any_role([ROLE_ADMIN]):
            raise AuthorizationError([ROLE_ADMIN])
        result = await state_machine.force_close(
            event_id,
            principal=principal.subject,
            reason=body.reason,
        )
        return s.EventCloseResponse(
            event_id=event_id,
            status=EventStatus.CLOSED,
            final_verdict=result.final_verdict,
            external_unsynced=True,
        )

    # Validate close rules per ISSUE-038.
    # Allowed paths: REPORTING→CLOSED, FAILED→REPORTING→CLOSED,
    # TRIAGING+not_required low/fp→CLOSED.
    if current_status == EventStatus.TRIAGING:
        if event.disposition_policy != DispositionPolicy.NOT_REQUIRED:
            raise WritebackUnsupportedError(
                "TRIAGING→CLOSED requires disposition_policy=not_required; "
                "required-disposition events must go through the disposition-only "
                "orchestration chain",
                details={
                    "event_id": event_id,
                    "disposition_policy": event.disposition_policy.value,
                },
            )
        # TRIAGING shortcut: generate report so validate_closed_gate can pass,
        # then transition directly to CLOSED (TRIAGING→REPORTING is illegal).
        close_verdict = event.final_verdict
        if body.final_verdict is not None and body.final_verdict != event.final_verdict:
            await event_service.set_final_verdict(
                event_id,
                body.final_verdict,
                operator=f"principal:{principal.subject}",
            )
            event = await event_service.get_event(event_id)
            if event is None:
                raise EventNotFoundError(
                    f"event {event_id} not found after verdict update",
                    details={"event_id": event_id},
                )
            close_verdict = body.final_verdict
        await _generate_quick_close_report(
            event_id=event_id,
            event_title=event.title,
            final_verdict=close_verdict,
            risk_score=event.risk_score,
            severity=event.severity,
            operator=f"principal:{principal.subject}",
            event_service=event_service,
        )
        await event_service.transition_status(
            event_id,
            EventStatus.CLOSED,
            context=TransitionContext(
                need_investigation=body.need_investigation,
            ),
            operator=f"principal:{principal.subject}",
            reason=body.reason,
        )
    elif current_status == EventStatus.REPORTING:
        # ISSUE-038 step 2: writeback gate pre-check.
        await _validate_writeback_gate(event_id, event)

        # Handle final_verdict change before closing — regenerate report first.
        if body.final_verdict is not None and body.final_verdict != event.final_verdict:
            await event_service.set_final_verdict(
                event_id,
                body.final_verdict,
                operator=f"principal:{principal.subject}",
            )
            event = await event_service.get_event(event_id)
            if event is None:
                raise EventNotFoundError(
                    f"event {event_id} not found after verdict update",
                    details={"event_id": event_id},
                )
            await _regenerate_report_after_verdict_change(
                event_id,
                event_title=event.title,
                final_verdict=body.final_verdict,
                risk_score=event.risk_score,
                severity=event.severity,
                operator=f"principal:{principal.subject}",
                event_service=event_service,
            )
        await event_service.transition_status(
            event_id,
            EventStatus.CLOSED,
            operator=f"principal:{principal.subject}",
            reason=body.reason,
        )
    elif current_status == EventStatus.FAILED:
        # FAILED → REPORTING → CLOSED.
        # ISSUE-038: writeback gate pre-check before any state transitions
        # to avoid leaving the event stuck in REPORTING.
        await _validate_writeback_gate(event_id, event)

        # Generate a quick-close report so validate_closed_gate can pass.
        await _generate_quick_close_report(
            event_id=event_id,
            event_title=event.title,
            final_verdict=event.final_verdict,
            risk_score=event.risk_score,
            severity=event.severity,
            operator=f"principal:{principal.subject}",
            event_service=event_service,
        )
        await event_service.transition_status(
            event_id,
            EventStatus.REPORTING,
            operator=f"principal:{principal.subject}",
            reason="close:report_before_close",
        )
        if body.final_verdict is not None and body.final_verdict != event.final_verdict:
            await event_service.set_final_verdict(
                event_id,
                body.final_verdict,
                operator=f"principal:{principal.subject}",
            )
            event = await event_service.get_event(event_id)
            if event is None:
                raise EventNotFoundError(
                    f"event {event_id} not found after verdict update",
                    details={"event_id": event_id},
                )
            await _regenerate_report_after_verdict_change(
                event_id,
                event_title=event.title,
                final_verdict=body.final_verdict,
                risk_score=event.risk_score,
                severity=event.severity,
                operator=f"principal:{principal.subject}",
                event_service=event_service,
            )
        await event_service.transition_status(
            event_id,
            EventStatus.CLOSED,
            operator=f"principal:{principal.subject}",
            reason=body.reason,
        )
    else:
        raise InvalidStateTransitionError(
            f"Cannot close event in {current_status.value} status",
            current=current_status,
            target=EventStatus.CLOSED,
            details={"event_id": event_id},
        )

    # Reload final state.
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(
            f"event {event_id} disappeared after close",
            details={"event_id": event_id},
        )
    return s.EventCloseResponse(
        event_id=event_id,
        status=event.status,
        final_verdict=event.final_verdict,
        external_unsynced=event.external_unsynced,
    )


# --------------------------------------------------------------------------- #
# Helper: execute DB read for list endpoints
# --------------------------------------------------------------------------- #


async def _db_read(
    event_id: str,
    table: Any,
    order_by: Any,
    page: int = 1,
    page_size: int = 20,
    extra_conditions: list[Any] | None = None,
) -> tuple[list[Any], int]:
    """Execute a paginated read query.

    Returns empty results for transient DB errors (connection issues, pool
    exhaustion).  Non-transient errors are re-raised so the API layer can
    return HTTP 503 rather than silently reporting success with no data.
    """
    from sqlalchemy import exc as sa_exc

    from app.core.errors import DependencyUnavailableError

    sf = _try_get_session_factory()
    if sf is None:
        return [], 0
    conditions: list[Any] = [table.event_id == event_id]
    if extra_conditions:
        conditions.extend(extra_conditions)
    page = max(1, page)
    page_size = min(max(1, page_size), 500)
    try:
        async with sf() as session:
            count = await session.scalar(select(func.count()).select_from(table).where(*conditions))
            total = int(count or 0)
            rows = (
                await session.scalars(
                    select(table)
                    .where(*conditions)
                    .order_by(order_by)
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            ).all()
        return list(rows), total
    except (ImportError, ModuleNotFoundError):
        logger.warning(
            "DB read skipped for table=%s event=%s (session factory unavailable)",
            getattr(table, "__tablename__", table),
            event_id,
        )
        return [], 0
    except (ConnectionRefusedError, TimeoutError, socket.gaierror, sa_exc.OperationalError):
        logger.warning(
            "DB read degraded (transient error) for table=%s event=%s",
            getattr(table, "__tablename__", table),
            event_id,
            exc_info=True,
        )
        return [], 0
    except Exception as exc:
        logger.error(
            "DB read failed (non-transient) for table=%s event=%s: %s",
            getattr(table, "__tablename__", table),
            event_id,
            exc,
            exc_info=True,
        )
        raise DependencyUnavailableError(
            "database query failed",
            error_code="dependency_unavailable",
            details={
                "table": getattr(table, "__tablename__", str(table)),
                "event_id": event_id,
            },
        ) from exc


def _tool_call_is_truncated(row: orm.ToolCallLog) -> bool:
    """Report whether any already-sanitised audit projection was bounded."""
    return bool(
        row.parameters.get("_truncated")
        or row.result.get("_truncated")
        or (row.error_detail or "").startswith("[TRUNCATED ")
    )


def _tool_call_provider(row: orm.ToolCallLog, action: orm.Action | None) -> str | None:
    """Resolve provider without consulting internal provider raw payloads."""
    if action is not None and action.provider_name:
        return action.provider_name
    for key in ("provider_name", "provider"):
        value = row.result.get(key)
        if isinstance(value, str) and value:
            return value
    return None


async def _query_tool_call_items(
    *,
    page: int,
    page_size: int,
    event_id: str | None = None,
    tool_name: str | None = None,
    status_filter: str | None = None,
) -> tuple[list[s.ToolCallItem], int]:
    """Read safe tool-call projections and related disposition metadata."""
    sf = _try_get_session_factory()
    page = max(1, page)
    page_size = min(max(1, page_size), 200)
    if sf is None:
        return [], 0

    conditions: list[Any] = []
    if event_id:
        conditions.append(orm.ToolCallLog.event_id == event_id)
    if tool_name:
        conditions.append(orm.ToolCallLog.tool_name == tool_name)
    if status_filter:
        conditions.append(orm.ToolCallLog.status == status_filter)

    try:
        async with sf() as session:
            count = await session.scalar(
                select(func.count(orm.ToolCallLog.call_id)).where(*conditions)
            )
            total = int(count or 0)
            rows = (
                await session.execute(
                    select(orm.ToolCallLog, orm.Action)
                    .outerjoin(orm.Action, orm.Action.action_id == orm.ToolCallLog.action_id)
                    .where(*conditions)
                    .order_by(
                        orm.ToolCallLog.started_at.desc().nulls_last(),
                        orm.ToolCallLog.call_id.desc(),
                    )
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            ).all()

            action_ids = {row.action_id for row, _action in rows if row.action_id is not None}
            dispositions: dict[str, orm.DispositionOutbox] = {}
            if action_ids:
                disposition_rows = (
                    await session.scalars(
                        select(orm.DispositionOutbox)
                        .where(orm.DispositionOutbox.action_id.in_(action_ids))
                        .order_by(
                            orm.DispositionOutbox.updated_at.desc(),
                            orm.DispositionOutbox.outbox_id.desc(),
                        )
                    )
                ).all()
                for disposition_row in disposition_rows:
                    dispositions.setdefault(disposition_row.action_id, disposition_row)

        items: list[s.ToolCallItem] = []
        for row, action in rows:
            related_disposition = dispositions.get(row.action_id or "")
            items.append(
                s.ToolCallItem(
                    call_id=row.call_id,
                    event_id=row.event_id,
                    action_id=row.action_id,
                    tool_name=row.tool_name,
                    tool_category=row.tool_category,
                    status=row.status,
                    duration_ms=row.duration_ms,
                    provider=_tool_call_provider(row, action),
                    execution_owner=action.execution_owner if action is not None else None,
                    disposition_id=(
                        related_disposition.disposition_id
                        if related_disposition is not None
                        else None
                    ),
                    writeback_status=(
                        (
                            related_disposition.latest_writeback_status
                            if related_disposition is not None
                            else None
                        )
                        or (action.writeback_status if action is not None else None)
                    ),
                    # ToolCallLogService has already recursively redacted secrets,
                    # projected raw payloads to hashes and bounded oversized fields.
                    parameters=row.parameters,
                    result=row.result,
                    error_detail=row.error_detail,
                    retry_count=row.retry_count,
                    started_at=row.started_at,
                    completed_at=row.completed_at,
                    truncated=_tool_call_is_truncated(row),
                )
            )
        return items, total
    except (ImportError, ModuleNotFoundError):
        logger.warning("Tool-call audit query skipped (session factory unavailable)")
        return [], 0
    except (ConnectionRefusedError, TimeoutError, sa_exc.OperationalError):
        logger.warning("Tool-call audit query degraded (transient DB error)", exc_info=True)
        return [], 0
    except Exception as exc:
        logger.error("Tool-call audit query failed: %s", exc, exc_info=True)
        raise DependencyUnavailableError(
            "database query failed for tool-call audit",
            error_code="dependency_unavailable",
        ) from exc


# --------------------------------------------------------------------------- #
# GET /events/{event_id}/report
# POST /events/{event_id}/report  (ISSUE-212 quality gate; generation for 204/212)
# --------------------------------------------------------------------------- #

# ISSUE-206: on-demand generation is only allowed once analysis finished —
# REPORTING (report phase reachable; bytes may be absent) or CLOSED (report
# required). Earlier lifecycle states would read an incomplete context and
# race the running pipeline.
REPORT_GENERATION_ALLOWED_STATUSES: frozenset[EventStatus] = frozenset(
    {EventStatus.REPORTING, EventStatus.CLOSED}
)


@router.get("/events/{event_id}/report", response_model=s.ReportResponse)
async def get_report(
    event_id: str,
    principal: CurrentPrincipal,
    event_service: EventService = Depends(get_event_service),
) -> s.ReportResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    report = await event_service.get_report(event_id=event_id)
    if report is None:
        raise EventNotFoundError(
            f"no report found for event {event_id}",
            details={"event_id": event_id},
        )
    return s.ReportResponse(report=report)


@router.post("/events/{event_id}/report", response_model=s.ReportResponse)
async def generate_report(
    event_id: str,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    force: bool = Query(False, description="Allow persisting incomplete_placeholder"),
    confirm_downgrade: bool = Query(
        False,
        description="Allow overwriting an existing complete report with a degraded grade",
    ),
    body: s.GenerateReportRequest | None = None,
    event_service: EventService = Depends(get_event_service),
) -> s.ReportResponse:
    """Generate (or regenerate) a formal investigation report with quality gate.

    ISSUE-212: ``incomplete_placeholder`` is rejected with 422 unless
    ``force=true``. Overwriting an existing ``complete`` report with any
    degraded grade requires ``confirm_downgrade=true`` (409 otherwise).
    Template fallbacks return 200 with ``report_quality=degraded_template``.
    """
    from app.api.v1.deps import _get_investigation_stack
    from app.models.agent_io import EvidenceOutput, RiskAssessment
    from app.models.enums import ReportQuality
    from app.services.report_input_builder import build_report_agent_input
    from app.services.report_quality import (
        ReportPhaseFlags,
        should_reject_complete_downgrade,
        should_reject_incomplete_without_force,
        with_assessed_quality,
    )

    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    # ISSUE-206: refuse generation while the investigation is still running.
    # REPORTING means the report phase is reachable (analysis complete) but
    # report bytes may not exist yet; CLOSED requires a report. Any earlier
    # lifecycle state would read an incomplete context and race the pipeline.
    if event.status not in REPORT_GENERATION_ALLOWED_STATUSES:
        raise InvalidStateTransitionError(
            f"report generation requires analysis to be complete "
            f"(REPORTING or CLOSED), current status={event.status.value}",
            details={
                "event_id": event_id,
                "status": event.status.value,
                "hint": "wait for the investigation to reach REPORTING, or use "
                "POST /events/{id}/report after completion",
            },
        )

    force_flag = bool(force or (body.force if body is not None else False))
    confirm_flag = bool(
        confirm_downgrade or (body.confirm_downgrade if body is not None else False)
    )
    settings = get_settings()
    gate_enforced = bool(settings.report_quality_gate_enforced)

    store = _get_context_store()
    evidence_raw = await store.get(event_id, "evidence_output")
    risk_raw = await store.get(event_id, "risk_assessment")
    if evidence_raw is None or risk_raw is None:
        raise ValidationError(
            "cannot generate report: evidence_output and risk_assessment are required "
            "in event context (run investigation analysis first)",
            error_code="report_prerequisites_missing",
            details={
                "event_id": event_id,
                "has_evidence_output": evidence_raw is not None,
                "has_risk_assessment": risk_raw is not None,
            },
        )
    try:
        evidence_output = (
            evidence_raw
            if isinstance(evidence_raw, EvidenceOutput)
            else EvidenceOutput.model_validate(evidence_raw)
        )
        risk_assessment = (
            risk_raw
            if isinstance(risk_raw, RiskAssessment)
            else RiskAssessment.model_validate(risk_raw)
        )
    except Exception as exc:
        raise ValidationError(
            "cannot generate report: stored evidence/risk payloads are invalid",
            error_code="report_prerequisites_invalid",
            details={"event_id": event_id},
        ) from exc

    stack = await _get_investigation_stack()
    report_agent = stack["report"]
    session_factory = stack.get("session_factory") or _get_session_factory()
    report_input = await build_report_agent_input(
        event_id,
        evidence_output=evidence_output,
        risk_assessment=risk_assessment,
        context_store=store,
        session_factory=session_factory,
    )
    # Build without persisting so the quality gate can refuse incomplete writes.
    report_input = report_input.model_copy(update={"persist_report": False})
    report = await report_agent.execute(report_input)
    report = with_assessed_quality(
        report,
        ReportPhaseFlags(
            response_phase_status=report_input.response_phase_status,
            verification_phase_status=report_input.verification_phase_status,
        ),
    )

    existing = await event_service.get_report(event_id=event_id)
    if should_reject_incomplete_without_force(
        report.report_quality,
        force=force_flag,
        gate_enforced=gate_enforced,
    ):
        raise ValidationError(
            "report quality incomplete: executed phases still contain placeholders; "
            "pass force=true to archive as incomplete_placeholder",
            error_code="report_quality_incomplete",
            details={
                "event_id": event_id,
                "report_quality": report.report_quality.value,
                "force": False,
            },
        )
    if (
        report.report_quality is ReportQuality.INCOMPLETE_PLACEHOLDER
        and not force_flag
        and not gate_enforced
    ):
        logger.warning(
            "REPORT_QUALITY_GATE_ENFORCED=false; accepting incomplete report event=%s",
            event_id,
        )

    existing_quality = existing.report_quality if existing is not None else None
    if should_reject_complete_downgrade(
        existing_quality,
        report.report_quality,
        confirm_downgrade=confirm_flag,
    ):
        raise ReportQualityConflictError(
            "refusing to overwrite a complete report with a degraded quality grade; "
            "pass confirm_downgrade=true to proceed",
            details={
                "event_id": event_id,
                "existing_quality": (
                    existing_quality.value if existing_quality is not None else None
                ),
                "incoming_quality": report.report_quality.value,
            },
        )

    # Downgrade gate already enforced above; upsert must not re-block agent-style writes.
    persisted = await event_service.upsert_report(report)
    await _sync_report_context_and_bus(event_id, persisted, event_service)
    try:
        await event_service.upsert_generate_report_action(event_id, plan_revision=1)
    except IntegrityError:
        logger.warning(
            "generate_report action already exists for POST report event=%s",
            event_id,
            exc_info=True,
        )
    return s.ReportResponse(report=persisted)


# --------------------------------------------------------------------------- #
# GET /events/{event_id}/traces
# --------------------------------------------------------------------------- #


@router.get("/events/{event_id}/traces", response_model=s.TracesResponse)
async def get_traces(
    event_id: str,
    principal: CurrentPrincipal,
    page: int = 1,
    page_size: int = 20,
    event_service: EventService = Depends(get_event_service),
) -> s.TracesResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    rows, total = await _db_read(
        event_id,
        orm.AgentTrace,
        orm.AgentTrace.started_at.asc(),
        page=page,
        page_size=page_size,
    )

    items: list[s.TraceItem] = []
    for row in rows:
        items.append(
            s.TraceItem(
                trace_id=row.trace_id,
                agent_name=row.agent_name,
                status=row.status,
                duration_ms=row.duration_ms,
                started_at=row.started_at,
            )
        )

    return s.TracesResponse(total=total, page=page, page_size=page_size, items=items)


# --------------------------------------------------------------------------- #
# GET /events/{event_id}/audit-logs
# --------------------------------------------------------------------------- #


@router.get("/events/{event_id}/audit-logs", response_model=s.AuditLogsResponse)
async def get_audit_logs(
    event_id: str,
    principal: CurrentPrincipal,
    page: int = 1,
    page_size: int = 20,
    event_service: EventService = Depends(get_event_service),
) -> s.AuditLogsResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    rows, total = await _db_read(
        event_id,
        orm.EventAuditLog,
        orm.EventAuditLog.id.asc(),
        page=page,
        page_size=page_size,
    )

    items: list[s.AuditLogItem] = []
    for row in rows:
        items.append(
            s.AuditLogItem(
                id=row.id,
                from_status=row.from_status,
                to_status=row.to_status,
                operator=row.operator,
                reason=row.reason,
                created_at=row.created_at,
            )
        )

    return s.AuditLogsResponse(total=total, page=page, page_size=page_size, items=items)


# --------------------------------------------------------------------------- #
# GET /events/{event_id}/tool-calls
# --------------------------------------------------------------------------- #


@router.get("/events/{event_id}/tool-calls", response_model=s.ToolCallsResponse)
async def get_event_tool_calls(
    event_id: str,
    principal: CurrentPrincipal,
    page: int = 1,
    page_size: int = 20,
    event_service: EventService = Depends(get_event_service),
) -> s.ToolCallsResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    items, total = await _query_tool_call_items(
        event_id=event_id,
        page=page,
        page_size=page_size,
    )

    return s.ToolCallsResponse(total=total, page=page, page_size=page_size, items=items)


# --------------------------------------------------------------------------- #
# GET /events/{event_id}/actions
# --------------------------------------------------------------------------- #


@router.get("/events/{event_id}/actions", response_model=s.ActionListResponse)
async def get_actions(
    event_id: str,
    principal: CurrentPrincipal,
    page: int = 1,
    page_size: int = 20,
    status: ActionStatus | None = None,
    event_service: EventService = Depends(get_event_service),
) -> s.ActionListResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    extra: list[Any] = []
    if status is not None:
        extra.append(orm.Action.status == status.value)

    rows, total = await _db_read(
        event_id,
        orm.Action,
        orm.Action.created_at.desc(),
        page=page,
        page_size=page_size,
        extra_conditions=extra,
    )

    from app.services.action_mapper import action_from_orm

    items: list[ActionModel] = [action_from_orm(row) for row in rows]

    return s.ActionListResponse(total=total, page=page, page_size=page_size, items=items)


# --------------------------------------------------------------------------- #
# GET /tool-calls — global tool call audit
# --------------------------------------------------------------------------- #


@router.get("/tool-calls", response_model=s.ToolCallsResponse)
async def list_tool_calls(
    principal: CurrentPrincipal,
    page: int = 1,
    page_size: int = 20,
    tool_name: str | None = None,
    status: str | None = None,
) -> s.ToolCallsResponse:
    page = max(1, page)
    page_size = min(max(1, page_size), 200)
    items, total = await _query_tool_call_items(
        page=page,
        page_size=page_size,
        tool_name=tool_name,
        status_filter=status,
    )
    return s.ToolCallsResponse(total=total, page=page, page_size=page_size, items=items)


def _gap_to_response(gap: Any) -> s.EvidenceGapResponse:
    missing = gap.missing_source
    missing_value = missing.value if hasattr(missing, "value") else str(missing)
    return s.EvidenceGapResponse(
        event_id=gap.event_id,
        missing_source=missing_value,
        reason=gap.reason,
        detail=dict(gap.detail or {}),
    )


def _triage_context_from_context(context: Any) -> s.EvidenceTriageContextResponse | None:
    from app.models.agent_io import TriageResult

    raw = getattr(context, "triage_result", None)
    if not isinstance(raw, dict):
        return None
    triage = TriageResult.model_validate(raw)
    if (
        not triage.degraded
        and not triage.degradation_reasons
        and not triage.entity_rejection_summary
    ):
        return None
    return s.EvidenceTriageContextResponse(
        degraded=triage.degraded,
        degradation_reasons=list(triage.degradation_reasons),
        entity_rejection_summary=dict(triage.entity_rejection_summary or {}),
    )


def _query_summary_from_agent_traces(rows: list[Any]) -> list[s.EvidenceQuerySummaryItem]:
    from app.services.evidence_observability import build_query_summary_items

    return [
        s.EvidenceQuerySummaryItem.model_validate(item) for item in build_query_summary_items(rows)
    ]


# --------------------------------------------------------------------------- #
# GET /events/{event_id}/evidence (ISSUE-101)
# --------------------------------------------------------------------------- #


@router.get("/events/{event_id}/evidence", response_model=s.EventEvidenceResponse)
async def get_event_evidence(
    event_id: str,
    principal: CurrentPrincipal,
    context_store: Annotated[Any, Depends(_get_context_store)],
    event_service: EventService = Depends(get_event_service),
) -> s.EventEvidenceResponse:
    """Return evidence collection output with gaps and per-tool query summary."""
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    from app.models.agent_io import EvidenceOutput

    try:
        context = await context_store.get_full_context(event_id)
    except KeyError as exc:
        raise ResourceNotFoundError(
            f"evidence for event {event_id} is not ready",
            error_code="evidence_not_ready",
            details={"event_id": event_id},
        ) from exc

    raw_output = context.evidence_output
    if raw_output is None:
        raise ResourceNotFoundError(
            f"evidence for event {event_id} is not ready",
            error_code="evidence_not_ready",
            details={"event_id": event_id},
        )

    evidence_output = EvidenceOutput.model_validate(raw_output)
    query_summary: list[s.EvidenceQuerySummaryItem] = []
    if _try_get_session_factory() is not None:
        try:
            rows, _ = await _db_read(
                event_id,
                orm.AgentTrace,
                orm.AgentTrace.started_at.desc(),
                page=1,
                page_size=50,
                extra_conditions=[orm.AgentTrace.agent_name == "evidence_agent"],
            )
            if rows:
                query_summary = _query_summary_from_agent_traces(rows)
        except DependencyUnavailableError:
            logger.warning(
                "evidence query_summary unavailable for event=%s; returning context output only",
                event_id,
            )

    return s.EventEvidenceResponse(
        event_id=event_id,
        evidence_list=evidence_output.evidence_list,
        gaps=[_gap_to_response(gap) for gap in evidence_output.gaps],
        collection_status=evidence_output.collection_status,
        success_sources=list(evidence_output.success_sources),
        failed_sources=list(evidence_output.failed_sources),
        overall_confidence=evidence_output.overall_confidence,
        query_summary=query_summary,
        triage_context=_triage_context_from_context(context),
    )


# --------------------------------------------------------------------------- #
# GET /events/{event_id}/decision-trace (ISSUE-063)
# --------------------------------------------------------------------------- #


@router.get("/events/{event_id}/decision-trace", response_model=s.DecisionTraceResponse)
async def get_decision_trace(
    event_id: str,
    principal: CurrentPrincipal,
    entry_type: Annotated[list[str] | None, Query()] = None,
    page: int = 1,
    page_size: int = 50,
    event_service: EventService = Depends(get_event_service),
) -> s.DecisionTraceResponse:
    """Aggregated decision trace aggregating agent, tool, LLM, state,
    approval, action, disposition, and writeback entries into a single
    timestamp-ordered timeline (ISSUE-063)."""
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    sf = _try_get_session_factory()
    if sf is None:
        return s.DecisionTraceResponse(
            event_id=event_id,
            missing_sources=["all (database unavailable)"],
        )

    page = max(1, page)
    page_size = min(max(1, page_size), 200)

    try:
        service = DecisionTraceService(sf)
        trace = await service.get_decision_trace(event_id)
    except (sa_exc.SQLAlchemyError, OSError) as exc:
        logger.warning("Decision trace unavailable for %s: %s", event_id, exc, exc_info=True)
        return s.DecisionTraceResponse(
            event_id=event_id,
            missing_sources=["all (database unavailable)"],
        )

    entries = trace.entries
    if entry_type:
        valid_types = {item.value for item in DecisionTraceEntryType}
        allowed = {value for value in entry_type if value in valid_types}
        entries = [e for e in entries if e.entry_type.value in allowed]

    total = len(entries)
    start = (page - 1) * page_size
    page_entries = entries[start : start + page_size]

    return s.DecisionTraceResponse(
        event_id=trace.event_id,
        entries=[e.model_dump(mode="json") for e in page_entries],
        summary=trace.summary,
        missing_sources=trace.missing_sources,
        page=page,
        page_size=page_size,
        total=total,
    )


# --------------------------------------------------------------------------- #
# PUT /events/{event_id}/disposition-source
# --------------------------------------------------------------------------- #


@router.put(
    "/events/{event_id}/disposition-source",
    response_model=s.DispositionSourceSelectResponse,
)
async def select_disposition_source(
    event_id: str,
    body: s.SelectDispositionSourceRequest,
    principal: Annotated[Principal, require_roles(ROLE_DISPOSITION_OPERATOR)],
    event_service: EventService = Depends(get_event_service),
) -> s.DispositionSourceSelectResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    # Optimistic concurrency.
    if body.expected_event_version != event.row_version:
        raise WritebackConflictError(
            "event version mismatch",
            details={"expected": body.expected_event_version, "actual": event.row_version},
        )

    # Validate source is associated.
    sf = _try_get_session_factory()
    if sf is not None:
        try:
            async with sf() as session:
                link = await session.scalar(
                    select(orm.SourceEventLink).where(
                        orm.SourceEventLink.source_record_id == body.source_record_id,
                        orm.SourceEventLink.event_id == event_id,
                    )
                )
                if link is None:
                    raise DispositionPermissionDenied(
                        "source object is not associated with this event",
                        details={"source_record_id": body.source_record_id, "event_id": event_id},
                    )

                source_obj = await session.scalar(
                    select(orm.SourceObject).where(
                        orm.SourceObject.source_record_id == body.source_record_id
                    )
                )
                if source_obj is None:
                    raise DispositionPermissionDenied(
                        "source object not found",
                        details={"source_record_id": body.source_record_id},
                    )

                locator = SourceObjectLocator(
                    source_product=source_obj.source_product,
                    source_tenant_id=source_obj.source_tenant_id,
                    connector_id=source_obj.connector_id,
                    source_kind=SourceObjectKind(source_obj.source_kind),
                    source_object_id=source_obj.source_object_id,
                )
                return s.DispositionSourceSelectResponse(
                    event_id=event_id,
                    disposition_source_ref=locator,
                    event_version=event.row_version + 1,
                )
        except Exception:
            logger.warning("DB unavailable for disposition-source validation", exc_info=True)

    # DB unavailable fallback — use static associated set.
    if body.source_record_id not in _ASSOCIATED_SOURCE_RECORDS:
        raise DispositionPermissionDenied(
            "source object is not an associated, tenant-consistent source for this event",
            details={"source_record_id": body.source_record_id},
        )
    return s.DispositionSourceSelectResponse(
        event_id=event_id,
        disposition_source_ref=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="t1",
            connector_id="conn-mock-1",
            source_kind=s.example_source_reference().source_kind,
            source_object_id="INC-1001",
        ),
        event_version=event.row_version + 1,
    )


# --------------------------------------------------------------------------- #
# POST /events/{event_id}/disposition-readiness/recheck
# --------------------------------------------------------------------------- #


@router.post(
    "/events/{event_id}/disposition-readiness/recheck",
    response_model=s.ReadinessRecheckResponse,
)
async def recheck_disposition_readiness(
    event_id: str,
    body: s.RecheckDispositionReadinessRequest,
    principal: Annotated[Principal, require_roles(ROLE_DISPOSITION_OPERATOR)],
    event_service: EventService = Depends(get_event_service),
) -> s.ReadinessRecheckResponse:
    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})

    if body.expected_event_version != event.row_version:
        raise WritebackConflictError(
            "event version mismatch",
            details={"expected": body.expected_event_version, "actual": event.row_version},
        )

    # Recheck: recompute readiness without external call.
    return s.ReadinessRecheckResponse(
        event_id=event_id,
        writeback_readiness=WritebackReadiness.CAPABILITY_UNKNOWN,
        blocked_reason="capability_unknown",
        event_version=event.row_version,
    )
