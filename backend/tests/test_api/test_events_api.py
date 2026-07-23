"""API contract tests for event lifecycle endpoints (ISSUE-038).

Tests the 11 core event endpoints with real database-backed services.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import reset_deps
from app.db import models as orm
from app.main import app
from app.models.enums import (
    EventStatus,
    EventType,
    Severity,
)
from app.services.event_service import EventService

pytestmark = [pytest.mark.integration]

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
        "approver-token": {"subject": "approver-1", "roles": ["approver"]},
        "operator-token": {"subject": "op-1", "roles": ["disposition_operator"]},
        "admin-token": {"subject": "admin-1", "roles": ["admin"]},
    }
)


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("LLM_MODE", "mock")
    monkeypatch.setenv("TOOL_MODE", "mock")
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("SIMULATION_ENABLED", "true")


def _hdr(role: str = "analyst") -> dict[str, str]:
    return {"Authorization": f"Bearer {role}-token"}


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _reset_services() -> None:
    """Reset lazy singletons between tests so each test gets clean state."""
    reset_deps()
    app.dependency_overrides.clear()


@pytest.fixture
def client(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> TestClient:
    """Inject test services into the app via dependency overrides."""

    async def _override_event_service() -> EventService:
        return event_service

    app.dependency_overrides[event_service] = _override_event_service
    return TestClient(app)


# --------------------------------------------------------------------------- #
# Helper: create a test event
# --------------------------------------------------------------------------- #


async def _create_test_event(
    event_service: EventService,
    *,
    title: str = "Test event",
    event_type: EventType = EventType.INSIDER_THREAT,
    severity: Severity = Severity.HIGH,
) -> str:
    event = await event_service.create_event(
        {"title": title, "description": "Test event created by API test"},
        source_type="manual",
        title=title,
        event_type=event_type,
        severity=severity,
    )
    return event.event_id


# --------------------------------------------------------------------------- #
# Tests: POST /events
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_event_returns_201(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """POST /events creates an event and returns 201 with valid summary."""
    resp = client.post(
        "/api/v1/events",
        json={
            "event_type": "insider_threat",
            "title": "Test insider threat",
            "description": "API test event",
            "severity": "high",
            "creation_source_ref": {
                "source_kind": "alert",
                "source_product": "mock_xdr",
                "source_tenant_id": "t1",
                "connector_id": "conn-mock-1",
                "source_object_id": "ALT-99901",
                "source_status_raw": "open",
                "source_disposition": "pending",
                "schema_version": 1,
            },
        },
        headers=_hdr(),
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["event_id"].startswith("evt-")
    assert data["status"] == "new"
    assert data["event_type"] == "insider_threat"


@pytest.mark.asyncio
async def test_create_event_rejects_unknown_fields(
    client: TestClient,
) -> None:
    """Extra fields are rejected (extra='forbid' on request model)."""
    resp = client.post(
        "/api/v1/events",
        json={
            "event_type": "insider_threat",
            "title": "Test",
            "severity": "high",
            "unknown_field": "should_reject",
            "creation_source_ref": {
                "source_kind": "alert",
                "source_product": "mock_xdr",
                "source_tenant_id": "t1",
                "connector_id": "conn-mock-1",
                "source_object_id": "ALT-99902",
                "source_status_raw": "open",
                "source_disposition": "pending",
                "schema_version": 1,
            },
        },
        headers=_hdr(),
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Tests: GET /events
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_events_returns_paginated(
    client: TestClient,
    event_service: EventService,
) -> None:
    """GET /events returns correct pagination structure."""
    await _create_test_event(event_service, title="List test 1")
    await _create_test_event(event_service, title="List test 2")

    resp = client.get("/api/v1/events", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "page" in data
    assert "page_size" in data
    assert "items" in data
    assert data["page"] == 1
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_list_events_filters_by_status(
    client: TestClient,
    event_service: EventService,
) -> None:
    """Filtering by status works."""
    await _create_test_event(event_service, title="Status test")

    resp = client.get("/api/v1/events?status=new", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["status"] == "new"


# --------------------------------------------------------------------------- #
# Tests: GET /events/{id}
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_event_returns_detail(
    client: TestClient,
    event_service: EventService,
) -> None:
    """GET /events/{id} returns full event detail."""
    event_id = await _create_test_event(event_service, title="Detail test")

    resp = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["event"]["event_id"] == event_id
    assert data["event"]["title"] == "Detail test"
    assert "writeback_required" in data
    assert "writeback_readiness" in data


@pytest.mark.asyncio
async def test_get_event_404_for_unknown_id(
    client: TestClient,
) -> None:
    """GET /events/{id} returns 404 for unknown ids."""
    resp = client.get("/api/v1/events/evt-99999999-ffffffff", headers=_hdr())
    assert resp.status_code == 404
    data = resp.json()
    assert data["error_code"] == "event_not_found"


# --------------------------------------------------------------------------- #
# Tests: GET /events/{id}/report
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_report_404_when_no_report(
    client: TestClient,
    event_service: EventService,
) -> None:
    """GET /events/{id}/report returns 404 when report doesn't exist."""
    event_id = await _create_test_event(event_service, title="No report")

    resp = client.get(f"/api/v1/events/{event_id}/report", headers=_hdr())
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Tests: GET /events/{id}/traces and audit-logs
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_traces_returns_empty_for_new_event(
    client: TestClient,
    event_service: EventService,
) -> None:
    """GET /events/{id}/traces returns empty list for new event."""
    event_id = await _create_test_event(event_service, title="Traces test")

    resp = client.get(f"/api/v1/events/{event_id}/traces", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_audit_logs_returns_entries(
    client: TestClient,
    event_service: EventService,
) -> None:
    """GET /events/{id}/audit-logs returns creation audit entry."""
    event_id = await _create_test_event(event_service, title="Audit test")

    resp = client.get(f"/api/v1/events/{event_id}/audit-logs", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(entry["reason"] == "event_created" for entry in data["items"])


# --------------------------------------------------------------------------- #
# Tests: GET /events/{id}/actions
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_actions_paginated(
    client: TestClient,
    event_service: EventService,
) -> None:
    """GET /events/{id}/actions returns paginated list."""
    event_id = await _create_test_event(event_service, title="Actions test")

    resp = client.get(
        f"/api/v1/events/{event_id}/actions?page=1&page_size=10",
        headers=_hdr(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "page" in data
    assert "page_size" in data
    assert "items" in data


# --------------------------------------------------------------------------- #
# Tests: GET /events/{id}/tool-calls and GET /tool-calls
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_event_tool_calls_empty(
    client: TestClient,
    event_service: EventService,
) -> None:
    """GET /events/{id}/tool-calls returns empty for new event."""
    event_id = await _create_test_event(event_service, title="Tool calls test")

    resp = client.get(f"/api/v1/events/{event_id}/tool-calls", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_global_tool_calls_paginated(
    client: TestClient,
) -> None:
    """GET /tool-calls returns paginated list with optional filters."""
    resp = client.get(
        "/api/v1/tool-calls?page=1&page_size=10",
        headers=_hdr(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "page" in data
    assert "page_size" in data


@pytest.mark.asyncio
async def test_global_tool_calls_filter_by_tool_name(
    client: TestClient,
) -> None:
    """GET /tool-calls?tool_name=query_asset_info filters correctly."""
    resp = client.get(
        "/api/v1/tool-calls?tool_name=query_asset_info",
        headers=_hdr(),
    )
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["tool_name"] == "query_asset_info"


# --------------------------------------------------------------------------- #
# Tests: POST /events/{id}/close
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_close_event_404(
    client: TestClient,
) -> None:
    """POST /events/{id}/close returns 404 for unknown id."""
    resp = client.post(
        "/api/v1/events/evt-99999999-ffffffff/close",
        json={"reason": "test"},
        headers=_hdr(),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_close_event_invalid_transition_from_new(
    client: TestClient,
    event_service: EventService,
) -> None:
    """Closing a NEW event directly must fail — invalid transition."""
    event_id = await _create_test_event(event_service, title="Close from NEW")

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "test close"},
        headers=_hdr(),
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "invalid_state_transition"


@pytest.mark.asyncio
async def test_force_close_requires_admin(
    client: TestClient,
    event_service: EventService,
) -> None:
    """Force local close requires admin role."""
    event_id = await _create_test_event(event_service, title="Force close test")

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "forced", "force_local_close": True},
        headers=_hdr("analyst"),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_close_triaging_not_required_succeeds(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Close a TRIAGING not_required event succeeds after generating report."""
    event_id = await _create_test_event(
        event_service,
        title="Close TRIAGING test",
        severity=Severity.LOW,
    )

    # Transition to TRIAGING directly via DB.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.TRIAGING.value
            row.row_version = int(row.row_version or 1) + 1
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status="new",
                    to_status="triaging",
                    operator="test",
                    reason="test_setup:triaging",
                )
            )
            await session.flush()

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "quick close test"},
        headers=_hdr(),
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["event_id"] == event_id
    assert data["status"] == "closed"

    # Verify report was generated and is queryable.
    report_resp = client.get(
        f"/api/v1/events/{event_id}/report",
        headers=_hdr(),
    )
    assert report_resp.status_code == 200


@pytest.mark.asyncio
async def test_close_failed_succeeds_with_report(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Close a FAILED event succeeds after generating report."""
    event_id = await _create_test_event(
        event_service,
        title="Close FAILED test",
        severity=Severity.LOW,
    )

    # Transition to FAILED directly via DB.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.FAILED.value
            row.row_version = int(row.row_version or 1) + 1
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status="new",
                    to_status="failed",
                    operator="test",
                    reason="test_setup:failed",
                )
            )
            await session.flush()

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "close failed test"},
        headers=_hdr(),
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["event_id"] == event_id
    assert data["status"] == "closed"

    # Verify report was generated and is queryable.
    report_resp = client.get(
        f"/api/v1/events/{event_id}/report",
        headers=_hdr(),
    )
    assert report_resp.status_code == 200


# --------------------------------------------------------------------------- #
# Tests: POST /events/{id}/investigate
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_investigate_404(
    client: TestClient,
) -> None:
    """POST /events/{id}/investigate returns 404 for unknown id."""
    resp = client.post(
        "/api/v1/events/evt-99999999-ffffffff/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_investigate_closed_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Cannot investigate a CLOSED event."""
    # Directly insert a closed event via session.
    async with session_factory() as session:
        async with session.begin():
            import hashlib
            from datetime import UTC, datetime

            now = datetime.now(UTC)
            eid = "evt-20260101-closed99"
            session.add(
                orm.SecurityEvent(
                    event_id=eid,
                    event_type="insider_threat",
                    title="Closed event",
                    description="Already closed",
                    status="closed",
                    severity="high",
                    final_verdict="none",
                    entities={},
                    creation_source_ref={
                        "source_kind": "alert",
                        "source_product": "file",
                        "source_tenant_id": "local",
                        "connector_id": "file-local",
                        "source_object_id": "file-closed99",
                        "raw_payload_hash": hashlib.sha256(b"closed").hexdigest(),
                        "ingested_at": now.isoformat(),
                    },
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    source_type="manual",
                    occurred_at=now,
                    row_version=1,
                )
            )
            session.add(
                orm.EventAuditLog(
                    event_id=eid,
                    from_status=None,
                    to_status="new",
                    operator="test",
                    reason="test_setup",
                )
            )
            session.add(
                orm.EventAuditLog(
                    event_id=eid,
                    from_status="new",
                    to_status="closed",
                    operator="test",
                    reason="test_setup",
                )
            )
            await session.flush()

    resp = client.post(
        f"/api/v1/events/{eid}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "invalid_state_transition"


@pytest.mark.asyncio
async def test_investigate_returns_202(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """POST /events/{id}/investigate returns 202 with task_id matching event_id."""
    event_id = await _create_test_event(event_service, title="Investigate 202 test")

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, f"Expected 202 Accepted, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["task_id"] == event_id
    assert data["event_id"] == event_id


# --------------------------------------------------------------------------- #
# Conftest-level integration: run the full analysis pipeline end-to-end
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_full_analysis_pipeline_happy_path(
    client: TestClient,
    event_service: EventService,
    state_machine_service,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """End-to-end: create → investigate → poll → report → close.

    For a not_required event, the pipeline should complete with the event CLOSED.
    """
    from app.agents.evidence_agent import EvidenceAgent
    from app.agents.report_agent import ReportAgent
    from app.agents.risk_agent import RiskAgent
    from app.agents.triage_agent import TriageAgent
    from app.core.config import get_settings
    from app.core.redis_client import RedisClient
    from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
    from app.services.context_service import EventContextStore
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.working_memory import WorkingMemory

    settings = get_settings()

    # Create a pipeline with test services.
    redis = RedisClient(url=settings.redis_url)
    store = EventContextStore(redis, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    wm = WorkingMemory(store=store, redis=redis, degraded_flags=degraded)

    triage = TriageAgent(
        llm_client=None,
        working_memory=wm.for_writer("TriageAgent"),
    )
    evidence = EvidenceAgent(
        llm_client=None,
        tool_executor=None,
        working_memory=wm.for_writer("EvidenceAgent"),
    )
    risk = RiskAgent(
        llm_client=None,
        working_memory=wm.for_writer("RiskAgent"),
        event_service=event_service,
    )
    report = ReportAgent(
        llm_client=None,
        working_memory=wm.for_writer("ReportAgent"),
        event_service=event_service,
    )

    pipeline = AnalysisOnlyPipeline(
        event_service=event_service,
        state_machine=state_machine_service,
        triage_agent=triage,
        evidence_agent=evidence,
        risk_agent=risk,
        report_agent=report,
        context_store=store,
    )

    # Create a not_required low-severity event.
    event = await event_service.create_event(
        {"title": "Pipeline test", "description": "Low risk event"},
        source_type="manual",
        title="Pipeline test",
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.LOW,
    )
    event_id = event.event_id
    assert event.status == EventStatus.NEW

    # Run the pipeline directly (bypassing BackgroundTasks).
    result = await pipeline.run(event_id)

    assert result["event_id"] == event_id
    assert result["analysis_only_complete"] is True

    # After pipeline: should be CLOSED (not_required + low severity = short-circuit close).
    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status == EventStatus.CLOSED


@pytest.mark.asyncio
async def test_high_risk_event_stays_reporting(
    client: TestClient,
    event_service: EventService,
    state_machine_service,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """High-risk required events stay at REPORTING after analysis."""
    from app.agents.evidence_agent import EvidenceAgent
    from app.agents.report_agent import ReportAgent
    from app.agents.risk_agent import RiskAgent
    from app.agents.triage_agent import TriageAgent
    from app.core.config import get_settings
    from app.core.redis_client import RedisClient
    from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
    from app.services.context_service import EventContextStore
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.working_memory import WorkingMemory

    settings = get_settings()

    redis = RedisClient(url=settings.redis_url)
    store = EventContextStore(redis, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    wm = WorkingMemory(store=store, redis=redis, degraded_flags=degraded)

    triage = TriageAgent(
        llm_client=None,
        working_memory=wm.for_writer("TriageAgent"),
    )
    evidence = EvidenceAgent(
        llm_client=None,
        tool_executor=None,
        working_memory=wm.for_writer("EvidenceAgent"),
    )
    risk = RiskAgent(
        llm_client=None,
        working_memory=wm.for_writer("RiskAgent"),
        event_service=event_service,
    )
    report = ReportAgent(
        llm_client=None,
        working_memory=wm.for_writer("ReportAgent"),
        event_service=event_service,
    )

    pipeline = AnalysisOnlyPipeline(
        event_service=event_service,
        state_machine=state_machine_service,
        triage_agent=triage,
        evidence_agent=evidence,
        risk_agent=risk,
        report_agent=report,
        context_store=store,
    )

    # Create a required high-severity event by going through the ingest path.
    # For this test, use a mock_xdr source which default to required policy.
    from app.models.enums import SourceDisposition, SourceObjectKind
    from app.models.source import SourceReference
    from app.services.event_service import IngestableSource

    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="t1",
        connector_id="conn-mock-high",
        source_object_id="INC-HIGH-001",
        source_status_raw="open",
        source_disposition=SourceDisposition.PENDING,
        schema_version=1,
    )
    ingest = IngestableSource(
        reference=ref,
        title="High risk incident",
        description="A serious data exfiltration incident",
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
    )
    result = await event_service.ingest_source_object(ingest)
    assert result.event_id is not None
    event_id = result.event_id

    event = await event_service.get_event(event_id)
    assert event is not None

    # Only run pipeline on NEW events.
    if event.status == EventStatus.NEW:
        pipeline_result = await pipeline.run(event_id)
        assert pipeline_result["disposition_policy"] == "required"
        assert pipeline_result["analysis_only_complete"] is True

        event = await event_service.get_event(event_id)
        assert event is not None
        assert event.status == EventStatus.REPORTING


@pytest.mark.asyncio
async def test_analysis_only_complete_persisted_in_context(
    client: TestClient,
    event_service: EventService,
    state_machine_service,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """analysis_only_complete is persisted to EventContextStore after pipeline runs."""
    from app.agents.evidence_agent import EvidenceAgent
    from app.agents.report_agent import ReportAgent
    from app.agents.risk_agent import RiskAgent
    from app.agents.triage_agent import TriageAgent
    from app.core.config import get_settings
    from app.core.redis_client import RedisClient
    from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
    from app.services.context_service import EventContextStore
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.working_memory import WorkingMemory

    settings = get_settings()

    redis = RedisClient(url=settings.redis_url)
    store = EventContextStore(redis, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    wm = WorkingMemory(store=store, redis=redis, degraded_flags=degraded)

    triage = TriageAgent(
        llm_client=None,
        working_memory=wm.for_writer("TriageAgent"),
    )
    evidence = EvidenceAgent(
        llm_client=None,
        tool_executor=None,
        working_memory=wm.for_writer("EvidenceAgent"),
    )
    risk = RiskAgent(
        llm_client=None,
        working_memory=wm.for_writer("RiskAgent"),
        event_service=event_service,
    )
    report = ReportAgent(
        llm_client=None,
        working_memory=wm.for_writer("ReportAgent"),
        event_service=event_service,
    )

    pipeline = AnalysisOnlyPipeline(
        event_service=event_service,
        state_machine=state_machine_service,
        triage_agent=triage,
        evidence_agent=evidence,
        risk_agent=risk,
        report_agent=report,
        context_store=store,
    )

    # Create a not_required low-severity event (short-circuit close path).
    event = await event_service.create_event(
        {"title": "Persistence test", "description": "Low risk"},
        source_type="manual",
        title="Persistence test",
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.LOW,
    )
    event_id = event.event_id

    # Run the pipeline.
    result = await pipeline.run(event_id)
    assert result["analysis_only_complete"] is True

    # Verify persistence via EventContextStore.
    stored_value = await store.get(event_id, "analysis_only_complete")
    assert stored_value is True, f"Expected analysis_only_complete=True in context, got {stored_value!r}"
