"""Event endpoints (placeholder implementations returning static examples)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, status

from app.api.v1 import schemas as s
from app.api.v1.errors import (
    EventNotFoundError,
    InvalidStateTransitionError,
    WritebackConflictError,
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
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    ActionStatus,
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)

router = APIRouter(tags=["events"])

# Minimal in-memory example store so 404 / invalid-transition / CAS are testable.
_EVENTS: dict[str, dict[str, object]] = {
    s.EXAMPLE_EVENT_ID: {"status": EventStatus.ANALYZING, "version": 1},
    s.EXAMPLE_CLOSED_EVENT_ID: {"status": EventStatus.CLOSED, "version": 3},
}

# Source objects that are associated + tenant/connector-consistent for the example
# event and therefore selectable as its disposition source.
_ASSOCIATED_SOURCE_RECORDS = {"src-associated-1"}


def _require_event(event_id: str) -> dict[str, object]:
    event = _EVENTS.get(event_id)
    if event is None:
        raise EventNotFoundError(f"event {event_id} not found", details={"event_id": event_id})
    return event


@router.post("/events", response_model=s.EventSummary, status_code=status.HTTP_201_CREATED)
async def create_event(
    body: s.EventCreateRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
) -> s.EventSummary:
    item = s.example_event_list_item()
    return s.EventSummary(
        **item.model_dump(),
        disposition_policy=DispositionPolicy.REQUIRED,
        external_unsynced=False,
        escalated=False,
    )


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
) -> s.EventListResponse:
    # Placeholder ignores the filters but declares the full documented query
    # contract (intro §4.2 / ISSUE-004 naming §3) so the frontend can rely on it.
    return s.EventListResponse(
        total=1, page=page, page_size=page_size, items=[s.example_event_list_item()]
    )


@router.get("/events/{event_id}", response_model=s.EventDetailResponse)
async def get_event(event_id: str, principal: CurrentPrincipal) -> s.EventDetailResponse:
    _require_event(event_id)
    return s.EventDetailResponse(
        event=s.example_security_event(event_id),
        writeback_required=True,
        writeback_readiness=WritebackReadiness.CAPABILITY_UNKNOWN,
        writeback_overall_status=None,
        pending_writeback_count=0,
    )


@router.post("/events/{event_id}/investigate", response_model=s.InvestigateResponse)
async def investigate_event(
    event_id: str,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
    body: s.InvestigateRequest | None = None,
) -> s.InvestigateResponse:
    event = _require_event(event_id)
    if event["status"] == EventStatus.CLOSED:
        raise InvalidStateTransitionError(
            "cannot investigate a CLOSED event",
            details={"event_id": event_id, "status": EventStatus.CLOSED.value},
        )
    return s.InvestigateResponse(
        event_id=event_id, task_id="task-0a1b2c3d", status=EventStatus.TRIAGING
    )


@router.post("/events/{event_id}/close", response_model=s.EventCloseResponse)
async def close_event(
    event_id: str,
    body: s.EventCloseRequest,
    principal: Annotated[Principal, require_roles(ROLE_ANALYST)],
) -> s.EventCloseResponse:
    _require_event(event_id)
    # A forced local close (external not synced) is an admin-only override.
    if body.force_local_close and not principal.has_any_role([ROLE_ADMIN]):
        raise AuthorizationError([ROLE_ADMIN])
    return s.EventCloseResponse(
        event_id=event_id,
        status=EventStatus.CLOSED,
        final_verdict=body.final_verdict or FinalVerdict.NONE,
        external_unsynced=body.force_local_close,
    )


@router.get("/events/{event_id}/report", response_model=s.ReportResponse)
async def get_report(event_id: str, principal: CurrentPrincipal) -> s.ReportResponse:
    _require_event(event_id)
    return s.ReportResponse(report=s.example_report(event_id))


@router.get("/events/{event_id}/traces", response_model=s.TracesResponse)
async def get_traces(event_id: str, principal: CurrentPrincipal) -> s.TracesResponse:
    _require_event(event_id)
    return s.TracesResponse(
        total=1,
        items=[s.TraceItem(trace_id="trc-0a1b2c3d", agent_name="TriageAgent", status="completed")],
    )


@router.get("/events/{event_id}/audit-logs", response_model=s.AuditLogsResponse)
async def get_audit_logs(event_id: str, principal: CurrentPrincipal) -> s.AuditLogsResponse:
    _require_event(event_id)
    return s.AuditLogsResponse(
        total=1,
        items=[s.AuditLogItem(id=1, from_status="new", to_status="triaging", operator="system")],
    )


@router.get("/events/{event_id}/tool-calls", response_model=s.ToolCallsResponse)
async def get_event_tool_calls(event_id: str, principal: CurrentPrincipal) -> s.ToolCallsResponse:
    _require_event(event_id)
    return s.ToolCallsResponse(
        total=1,
        items=[
            s.ToolCallItem(
                call_id="call-0a1b2c3d",
                event_id=event_id,
                tool_name="query_asset_info",
                tool_category="query",
                status="success",
            )
        ],
    )


@router.get("/events/{event_id}/timeline", response_model=s.TimelineResponse)
async def get_timeline(event_id: str, principal: CurrentPrincipal) -> s.TimelineResponse:
    _require_event(event_id)
    return s.TimelineResponse(event_id=event_id, items=[])


@router.get("/events/{event_id}/graph", response_model=s.GraphResponse)
async def get_graph(event_id: str, principal: CurrentPrincipal) -> s.GraphResponse:
    _require_event(event_id)
    return s.GraphResponse(event_id=event_id, nodes=[], edges=[])


@router.get("/events/{event_id}/decision-trace", response_model=s.DecisionTraceResponse)
async def get_decision_trace(event_id: str, principal: CurrentPrincipal) -> s.DecisionTraceResponse:
    _require_event(event_id)
    return s.DecisionTraceResponse(event_id=event_id, steps=[])


@router.get("/events/{event_id}/actions", response_model=s.ActionListResponse)
async def get_actions(
    event_id: str,
    principal: CurrentPrincipal,
    page: int = 1,
    page_size: int = 20,
    status: ActionStatus | None = None,
) -> s.ActionListResponse:
    _require_event(event_id)
    # Paginated + status-filterable to stay contract-stable for the real
    # implementation (ISSUE-038/039), which must not change these fields.
    return s.ActionListResponse(
        total=1, page=page, page_size=page_size, items=[s.example_action()]
    )


@router.put(
    "/events/{event_id}/disposition-source",
    response_model=s.DispositionSourceSelectResponse,
)
async def select_disposition_source(
    event_id: str,
    body: s.SelectDispositionSourceRequest,
    principal: Annotated[Principal, require_roles(ROLE_DISPOSITION_OPERATOR)],
) -> s.DispositionSourceSelectResponse:
    event = _require_event(event_id)
    # optimistic concurrency: reject stale writers.
    if body.expected_event_version != event["version"]:
        raise WritebackConflictError(
            "event version mismatch",
            details={"expected": body.expected_event_version, "actual": event["version"]},
        )
    # only associated, writable, tenant/connector-consistent sources are selectable.
    if body.source_record_id not in _ASSOCIATED_SOURCE_RECORDS:
        from app.api.v1.errors import DispositionPermissionDenied

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
        event_version=int(event["version"]) + 1,
    )


@router.post(
    "/events/{event_id}/disposition-readiness/recheck",
    response_model=s.ReadinessRecheckResponse,
)
async def recheck_disposition_readiness(
    event_id: str,
    body: s.RecheckDispositionReadinessRequest,
    principal: Annotated[Principal, require_roles(ROLE_DISPOSITION_OPERATOR)],
) -> s.ReadinessRecheckResponse:
    event = _require_event(event_id)
    if body.expected_event_version != event["version"]:
        raise WritebackConflictError(
            "event version mismatch",
            details={"expected": body.expected_event_version, "actual": event["version"]},
        )
    # Recheck only recomputes config/permission/capability; no external call, no
    # success receipt is created, so it is safe to repeat (idempotent).
    return s.ReadinessRecheckResponse(
        event_id=event_id,
        writeback_readiness=WritebackReadiness.CAPABILITY_UNKNOWN,
        blocked_reason="capability_unknown",
        event_version=int(event["version"]),
    )
