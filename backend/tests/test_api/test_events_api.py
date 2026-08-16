"""API contract tests for event lifecycle endpoints (ISSUE-038).

Tests the 11 core event endpoints with real database-backed services.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import BackgroundTasks
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import reset_deps
from app.db import models as orm
from app.main import app
from app.models.enums import (
    ActionCategory,
    ActionStatus,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionJobStatus,
    FinalVerdict,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)
from app.services.context_service import EventContextStore
from app.services.event_service import EventService

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]

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
    from app.core.config import get_settings

    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("LLM_MODE", "mock")
    monkeypatch.setenv("TOOL_MODE", "mock")
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("SIMULATION_ENABLED", "true")
    monkeypatch.setenv("TASK_MODE", "background")
    get_settings.cache_clear()


def _hdr(role: str = "analyst") -> dict[str, str]:
    return {"Authorization": f"Bearer {role}-token"}


def _patch_background_create_task(monkeypatch: pytest.MonkeyPatch) -> None:
    def _add_task(_self: BackgroundTasks, func: Any, *args: Any, **kwargs: Any) -> None:
        coro = func(*args, **kwargs)
        if asyncio.iscoroutine(coro):
            asyncio.create_task(coro)

    monkeypatch.setattr(BackgroundTasks, "add_task", _add_task)


async def _poll_event_status(
    client: TestClient,
    event_id: str,
    expected: str,
    *,
    timeout_s: float = 5.0,
    interval_s: float = 0.2,
) -> dict[str, Any]:
    """Poll GET /events/{id} until status matches or timeout (ISSUE-566)."""
    deadline = time.monotonic() + timeout_s
    last_status: str | None = None
    while time.monotonic() < deadline:
        detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
        assert detail.status_code == 200, detail.text
        payload = detail.json()
        last_status = payload["event"]["status"]
        if last_status == expected:
            return payload
        if last_status == "failed":
            pytest.fail(f"event {event_id} entered failed status while waiting for {expected!r}")
        await asyncio.sleep(interval_s)
    pytest.fail(
        f"event {event_id} did not reach status {expected!r} within {timeout_s}s; "
        f"last={last_status!r}"
    )


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

    from app.api.v1.deps import get_event_service

    async def _override_event_service() -> EventService:
        return event_service

    app.dependency_overrides[get_event_service] = _override_event_service
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


async def _seed_evidence_limited_demotion_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    title: str = "Evidence limited demotion",
) -> str:
    """Seed high risk + none verdict with structured demotion snapshot (ISSUE-241)."""
    from uuid import uuid4

    from app.services.risk_verdict_projection import (
        EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
        merge_risk_assessment_into_snapshot,
    )

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    now = datetime.now(UTC)
    snapshot = merge_risk_assessment_into_snapshot(
        None,
        {
            "risk_score": 70,
            "severity": "high",
            "confidence": 0.08,
            "scoring_mode": "rule_only",
            "evidence_limited": True,
            "verdict_reason_codes": [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT],
        },
    )

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title=title,
                    description="ISSUE-241 demotion observability fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.NONE.value,
                    risk_score=70,
                    confidence=0.08,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": f"conn-{sfx}",
                        "source_object_id": f"INC-{sfx}",
                        "source_status_raw": "open",
                        "source_disposition": "pending",
                        "schema_version": "1",
                    },
                    source_reference_snapshots=[],
                    disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
                    source_type="manual",
                    occurred_at=now,
                    event_context_snapshot=snapshot,
                    row_version=1,
                )
            )
    return event_id


async def _seed_reporting_required_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    title: str = "Reporting required event",
    writeback_readiness: WritebackReadiness = WritebackReadiness.READY,
    outbox_status: WritebackStatus | None = None,
    entity_action_writeback_status: WritebackStatus | None = None,
    include_action: bool = True,
) -> str:
    """Insert a REPORTING event with optional writeback action/outbox rows."""
    import hashlib
    from datetime import UTC, datetime
    from uuid import uuid4

    from app.models.action import TERMINAL_DISPOSITION_TOOL
    from app.models.enums import ActionExecutionPhase, DispositionIntentKind, SourceDisposition

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title=title,
                    description="Writeback gate test fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=85,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": f"conn-{sfx}",
                        "source_object_id": f"INC-{sfx}",
                        "raw_payload_hash": hashlib.sha256(b"wb").hexdigest(),
                        "ingested_at": now.isoformat(),
                    },
                    source_reference_snapshots=[],
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status="new",
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="test_setup:reporting",
                )
            )
            await session.flush()
            if include_action:
                connector_id = f"conn-{sfx}"
                source_record_id = f"src-{sfx}"
                session.add(
                    orm.SourceConnector(
                        connector_id=connector_id,
                        source_product="mock_xdr",
                        display_name="Writeback test connector",
                    )
                )
                session.add(
                    orm.SourceObject(
                        source_record_id=source_record_id,
                        source_product="mock_xdr",
                        source_tenant_id="t1",
                        connector_id=connector_id,
                        source_kind="incident",
                        source_object_id=f"INC-{sfx}",
                    )
                )
                session.add(
                    orm.Action(
                        action_id=f"act-{sfx}",
                        event_id=event_id,
                        plan_revision=1,
                        action_fingerprint=f"fp-{sfx}",
                        action_category="response",
                        action_name="block ip",
                        tool_name="block_ip",
                        action_level="l2",
                        execution_owner="direct_tool",
                        writeback_required=True,
                        writeback_applicable=True,
                        writeback_readiness=writeback_readiness.value,
                        writeback_status=(
                            entity_action_writeback_status.value
                            if entity_action_writeback_status is not None
                            else (
                                WritebackStatus.CONFIRMED.value
                                if outbox_status is WritebackStatus.CONFIRMED
                                else None
                            )
                        ),
                    )
                )
                await session.flush()
                if outbox_status is not None:
                    session.add(
                        orm.DispositionOutbox(
                            outbox_id=f"obx-{sfx}",
                            writeback_id=f"wbk-{sfx}",
                            disposition_id=f"disp-{sfx}",
                            action_id=f"act-{sfx}",
                            event_id=event_id,
                            closure_cycle=1,
                            source_record_id=source_record_id,
                            source_locator_hash="h" * 64,
                            source_sequence=1,
                            intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                            logical_slot="slot-1",
                            idempotency_key=f"idem-{sfx}",
                            command_payload={},
                            command_payload_sha256="a" * 64,
                            delivery_status="delivered",
                            latest_writeback_status=outbox_status.value,
                        )
                    )
                    if outbox_status is WritebackStatus.CONFIRMED:
                        session.add(
                            orm.Action(
                                action_id=f"act-term-{sfx}",
                                event_id=event_id,
                                plan_revision=1,
                                action_fingerprint=f"fp-term-{sfx}",
                                action_category="response",
                                action_name=TERMINAL_DISPOSITION_TOOL,
                                # CLOSED gate resolves terminal via tool_name
                                # (see StateMachineService._build_terminal_writeback_view).
                                tool_name=TERMINAL_DISPOSITION_TOOL,
                                action_level="l1",
                                execution_owner="xdr_managed",
                                execution_phase=ActionExecutionPhase.POST_VERIFY.value,
                                writeback_required=True,
                                writeback_applicable=True,
                                writeback_readiness=WritebackReadiness.READY.value,
                                writeback_status=WritebackStatus.CONFIRMED.value,
                                approved_terminal_dispositions=[SourceDisposition.CONTAINED.value],
                            )
                        )
                        await session.flush()
                        session.add(
                            orm.DispositionOutbox(
                                outbox_id=f"obx-term-{sfx}",
                                writeback_id=f"wbk-term-{sfx}",
                                disposition_id=f"disp-term-{sfx}",
                                action_id=f"act-term-{sfx}",
                                event_id=event_id,
                                closure_cycle=1,
                                source_record_id=source_record_id,
                                source_locator_hash="h" * 64,
                                source_sequence=2,
                                intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                                logical_slot="terminal",
                                idempotency_key=f"idem-term-{sfx}",
                                command_payload={
                                    "operation_params": {
                                        "target_disposition": SourceDisposition.CONTAINED.value,
                                    },
                                },
                                command_payload_sha256="b" * 64,
                                delivery_status="delivered",
                                latest_writeback_status=WritebackStatus.CONFIRMED.value,
                            )
                        )
            await session.flush()
    return event_id


async def _seed_report_with_event(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> None:
    """Insert a minimal report row so REPORTING events can close when gate passes."""
    from datetime import UTC, datetime

    from app.models.ids import report_id_for_event

    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Report(
                    report_id=report_id_for_event(event_id),
                    event_id=event_id,
                    title="Gate test report",
                    summary="fixture",
                    sections=[],
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=85,
                    severity=Severity.HIGH.value,
                    version=1,
                    generated_by="test",
                    generated_at=now,
                    updated_at=now,
                )
            )
            await session.flush()


async def _seed_reporting_required_with_running_side_effect(
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    """REPORTING + REQUIRED with gate-applicable RUNNING job (side-effect gate fixture)."""
    import hashlib
    from uuid import uuid4

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    action_id = f"act-{sfx}"
    job_id = f"job-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="Side-effect gate API fixture",
                    description="ISSUE-302 API fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": f"conn-{sfx}",
                        "source_object_id": f"INC-{sfx}",
                        "raw_payload_hash": hashlib.sha256(b"side-effect").hexdigest(),
                        "ingested_at": now.isoformat(),
                    },
                    source_reference_snapshots=[],
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="isolate host",
                    tool_name="isolate_host",
                    action_level="l2",
                    execution_owner="direct_tool",
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.APPROVED.value,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_tool",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.RUNNING.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )
    return event_id


async def _seed_reporting_not_required_with_running_side_effect(
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    """NOT_REQUIRED REPORTING with background RUNNING job."""
    import hashlib
    from uuid import uuid4

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    action_id = f"act-{sfx}"
    job_id = f"job-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="account_anomaly",
                    title="NOT_REQUIRED background side effects",
                    description="ISSUE-302 API fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.LOW.value,
                    final_verdict=FinalVerdict.FALSE_POSITIVE.value,
                    risk_score=10,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": f"conn-{sfx}",
                        "source_object_id": f"INC-{sfx}",
                        "raw_payload_hash": hashlib.sha256(b"not-required-bg").hexdigest(),
                        "ingested_at": now.isoformat(),
                    },
                    source_reference_snapshots=[],
                    disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block domain",
                    tool_name="block_domain",
                    action_level="l2",
                    execution_owner="direct_tool",
                    writeback_applicable=False,
                    writeback_required=False,
                    status=ActionStatus.APPROVED.value,
                )
            )
            await session.flush()
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_tool",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.RUNNING.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )
    return event_id


async def _seed_reporting_not_required_without_report(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    title: str = "Reporting without report",
) -> str:
    """Insert a NOT_REQUIRED REPORTING event with no report row (ISSUE-204)."""
    import hashlib
    from datetime import UTC, datetime
    from uuid import uuid4

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="other",
                    title=title,
                    description="ISSUE-204 close gate fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.LOW.value,
                    final_verdict=FinalVerdict.NONE.value,
                    risk_score=10,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": f"conn-{sfx}",
                        "source_object_id": f"INC-{sfx}",
                        "raw_payload_hash": hashlib.sha256(b"no-report").hexdigest(),
                        "ingested_at": now.isoformat(),
                    },
                    source_reference_snapshots=[],
                    disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
    return event_id


async def _seed_investigation_report(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    final_verdict: FinalVerdict = FinalVerdict.CONFIRMED_THREAT,
) -> list[dict[str, str]]:
    """Insert a full investigation-style report (not quick_close)."""
    from datetime import UTC, datetime

    from app.models.ids import report_id_for_event

    sections = [
        {"key": "overview", "title": "Overview", "content": "Detailed investigation overview."},
        {"key": "evidence", "title": "Evidence", "content": "Collected DNS and asset evidence."},
    ]
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Report(
                    report_id=report_id_for_event(event_id),
                    event_id=event_id,
                    title="Investigation Report",
                    summary="Full analysis report fixture",
                    sections=sections,
                    final_verdict=final_verdict.value,
                    risk_score=85,
                    severity=Severity.HIGH.value,
                    version=1,
                    generated_by="template",
                    generated_at=now,
                    updated_at=now,
                )
            )
            await session.flush()
    return sections


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
                "schema_version": "1",
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
                "schema_version": "1",
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


@pytest.mark.asyncio
async def test_list_events_projects_evidence_limited_demotion_fields(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """ISSUE-241: list/detail API expose demotion observability from snapshot."""
    from app.services.risk_verdict_projection import (
        EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT,
    )

    event_id = await _seed_evidence_limited_demotion_event(session_factory)

    list_resp = client.get("/api/v1/events", headers=_hdr())
    assert list_resp.status_code == 200, list_resp.text
    item = next(i for i in list_resp.json()["items"] if i["event_id"] == event_id)
    assert item["risk_score"] == 70
    assert item["final_verdict"] == "none"
    assert item["evidence_limited"] is True
    assert item["scoring_mode"] == "rule_only"
    assert item["verdict_reason_codes"] == [EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT]

    detail_resp = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail_resp.status_code == 200, detail_resp.text
    risk = detail_resp.json()["event"]["event_context_snapshot"]["risk_assessment"]
    assert risk["evidence_limited"] is True
    assert EVIDENCE_LIMITED_DEMOTED_FROM_CONFIRMED_THREAT in risk["verdict_reason_codes"]


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
async def test_get_event_surfaces_failed_writeback_status(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """FAILED outbox rows must appear in writeback_overall_status (not omitted)."""
    event_id = await _seed_reporting_required_event(
        session_factory,
        outbox_status=WritebackStatus.FAILED,
    )

    resp = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["writeback_overall_status"] == WritebackStatus.FAILED.value


async def _seed_multi_revision_writeback_event(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    historical_outbox_status: WritebackStatus,
    current_outbox_status: WritebackStatus,
) -> str:
    """Seed REQUIRED event with a revision-1 outbox and a revision-2 (current) outbox.

    Historical-revision outboxes must not pollute the current-plan UI
    aggregation (ISSUE-185).
    """
    import hashlib
    from datetime import UTC, datetime
    from uuid import uuid4

    from app.models.enums import DispositionIntentKind

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="Multi-revision writeback event",
                    description="ISSUE-185 aggregation fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=85,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": f"conn-{sfx}",
                        "source_object_id": f"INC-{sfx}",
                        "raw_payload_hash": hashlib.sha256(b"wb").hexdigest(),
                        "ingested_at": now.isoformat(),
                    },
                    source_reference_snapshots=[],
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status="new",
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="test_setup:multi_revision",
                )
            )
            session.add(
                orm.SourceConnector(
                    connector_id=f"conn-{sfx}",
                    source_product="mock_xdr",
                    display_name="Writeback test connector",
                )
            )
            session.add(
                orm.SourceObject(
                    source_record_id=f"src-{sfx}",
                    source_product="mock_xdr",
                    source_tenant_id="t1",
                    connector_id=f"conn-{sfx}",
                    source_kind="incident",
                    source_object_id=f"INC-{sfx}",
                )
            )
            await session.flush()

            # Historical revision (must be ignored by the UI aggregation).
            session.add(
                orm.Action(
                    action_id=f"act-hist-{sfx}",
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-hist-{sfx}",
                    action_category="response",
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level="l2",
                    execution_owner="direct_tool",
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                )
            )
            await session.flush()
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-hist-{sfx}",
                    writeback_id=f"wbk-hist-{sfx}",
                    disposition_id=f"disp-hist-{sfx}",
                    action_id=f"act-hist-{sfx}",
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    logical_slot="slot-hist",
                    idempotency_key=f"idem-hist-{sfx}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status="delivered",
                    latest_writeback_status=historical_outbox_status.value,
                )
            )

            # Current revision (drives the UI aggregation).
            session.add(
                orm.Action(
                    action_id=f"act-cur-{sfx}",
                    event_id=event_id,
                    plan_revision=2,
                    action_fingerprint=f"fp-cur-{sfx}",
                    action_category="response",
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level="l2",
                    execution_owner="direct_tool",
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                )
            )
            await session.flush()
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-cur-{sfx}",
                    writeback_id=f"wbk-cur-{sfx}",
                    disposition_id=f"disp-cur-{sfx}",
                    action_id=f"act-cur-{sfx}",
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=2,
                    intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    logical_slot="slot-cur",
                    idempotency_key=f"idem-cur-{sfx}",
                    command_payload={},
                    command_payload_sha256="b" * 64,
                    delivery_status="delivered",
                    latest_writeback_status=current_outbox_status.value,
                )
            )
            await session.flush()
    return event_id


@pytest.mark.asyncio
async def test_get_event_ignores_historical_revision_failed_outbox(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Historical-revision FAILED outbox must not override current-plan success.

    ISSUE-185: writeback_overall_status / pending_count only count outboxes of
    the current plan_revision bound to non-superseded Actions.
    """
    event_id = await _seed_multi_revision_writeback_event(
        session_factory,
        historical_outbox_status=WritebackStatus.FAILED,
        current_outbox_status=WritebackStatus.CONFIRMED,
    )

    resp = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["writeback_overall_status"] == WritebackStatus.CONFIRMED.value
    assert data["pending_writeback_count"] == 0


@pytest.mark.asyncio
async def test_get_event_preserves_current_plan_failed_status(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A current-plan FAILED outbox must still surface as FAILED (fail-closed).

    ISSUE-185 forbids silently clearing unconfirmed failures to make the UI
    green.
    """
    event_id = await _seed_multi_revision_writeback_event(
        session_factory,
        historical_outbox_status=WritebackStatus.CONFIRMED,
        current_outbox_status=WritebackStatus.FAILED,
    )

    resp = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["writeback_overall_status"] == WritebackStatus.FAILED.value


@pytest.mark.asyncio
async def test_get_event_returns_detail_without_detection_context_for_manual_event(
    client: TestClient,
    event_service: EventService,
) -> None:
    """Manual/file events should return detail without detection context fields."""
    event_id = await _create_test_event(event_service, title="Manual event no dctx")

    resp = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["event"]["event_id"] == event_id
    assert data["detection_context_snapshot"] is None
    assert data["detection_context_projection_error"] is None


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


@pytest.mark.asyncio
async def test_actions_returns_full_fields_for_waiting_approval(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET /events/{id}/actions must expose fields needed by approval center UI."""
    event_id = await _create_test_event(event_service, title="Waiting approval fields")
    now = datetime.now(UTC)
    disposition_ref = {
        "source_product": "mock_xdr",
        "source_tenant_id": "tenant-1",
        "connector_id": "conn-1",
        "source_kind": "incident",
        "source_object_type": "incident",
        "source_object_id": "INC-001",
    }
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id="act-wait-full",
                    event_id=event_id,
                    plan_revision=2,
                    action_fingerprint="fp-wait-full",
                    action_category="response",
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level="l4",
                    execution_phase="immediate",
                    target_type="ip",
                    target="203.0.113.50",
                    status=ActionStatus.WAITING_APPROVAL.value,
                    reason="High-risk lateral movement",
                    provider_name="mock_xdr",
                    execution_owner="xdr_managed",
                    disposition_source_ref=disposition_ref,
                    updated_at=now,
                )
            )

    resp = client.get(
        f"/api/v1/events/{event_id}/actions?status=waiting_approval",
        headers=_hdr(),
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert len(items) == 1
    item = items[0]
    assert item["action_id"] == "act-wait-full"
    assert item["status"] == "waiting_approval"
    assert item["execution_phase"] == "immediate"
    assert item["execution_owner"] == "xdr_managed"
    assert item["target"] == "203.0.113.50"
    assert item["target_type"] == "ip"
    assert item["reason"] == "High-risk lateral movement"
    assert item["disposition_source_ref"]["source_object_id"] == "INC-001"
    assert item["updated_at"] is not None


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
async def test_tool_call_audit_returns_safe_detail_and_action_metadata(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Tool audit exposes only persisted safe projections plus action metadata."""
    event_id = await _create_test_event(event_service, title="Detailed tool audit")
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id="act-audit-detail",
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint="fp-audit-detail",
                    action_category="response",
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level="l2",
                    provider_name="mock_xdr",
                    execution_owner="direct_tool",
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    writeback_status=WritebackStatus.PENDING.value,
                )
            )
            session.add(
                orm.ToolCallLog(
                    call_id="call-audit-detail",
                    event_id=event_id,
                    action_id="act-audit-detail",
                    tool_name="block_ip",
                    tool_category="response",
                    parameters={
                        "target": "203.0.113.9",
                        "token": "[REDACTED]",
                        "_truncated": True,
                    },
                    result={"provider_code": "accepted"},
                    status="success",
                    started_at=now,
                    completed_at=now,
                    duration_ms=24,
                    retry_count=2,
                )
            )

    response = client.get(
        f"/api/v1/events/{event_id}/tool-calls",
        headers=_hdr(),
    )

    assert response.status_code == 200, response.text
    item = response.json()["items"][0]
    assert item["provider"] == "mock_xdr"
    assert item["execution_owner"] == "direct_tool"
    assert item["writeback_status"] == "pending"
    assert item["parameters"]["token"] == "[REDACTED]"
    assert item["parameters"]["target"] == "203.0.113.9"
    assert item["retry_count"] == 2
    assert item["truncated"] is True
    assert "raw_result" not in item


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

    with patch("app.api.v1.events.record_force_close") as record:
        resp = client.post(
            f"/api/v1/events/{event_id}/close",
            json={"reason": "forced", "force_local_close": True},
            headers=_hdr("analyst"),
        )
        assert resp.status_code == 403
        record.assert_called_once_with(result="denied")


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


@pytest.mark.asyncio
async def test_close_reporting_writeback_not_configured_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """REPORTING + required policy without disposition actions is blocked."""
    event_id = await _seed_reporting_required_event(
        session_factory,
        include_action=False,
    )
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "writeback gate test"},
        headers=_hdr(),
    )
    assert resp.status_code == 422
    assert resp.json()["error_code"] == "writeback_unsupported"


@pytest.mark.asyncio
async def test_close_reporting_writeback_pending_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_required_event(
        session_factory,
        outbox_status=WritebackStatus.PENDING,
    )
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "writeback pending test"},
        headers=_hdr(),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "writeback_pending"


@pytest.mark.asyncio
async def test_close_reporting_side_effects_pending_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_required_with_running_side_effect(session_factory)
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "side effect gate test"},
        headers=_hdr(),
    )
    assert resp.status_code == 409
    data = resp.json()
    assert data["error_code"] == "closed_side_effects_pending"
    assert data["details"]["action_id"].startswith("act-")


@pytest.mark.asyncio
async def test_get_event_surfaces_side_effect_convergence_counts(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_required_with_running_side_effect(session_factory)

    resp = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert resp.status_code == 200
    data = resp.json()
    assert data["gate_applicable_outstanding_count"] == 1
    assert data["outstanding_side_effect_count"] == 1
    outstanding = data["outstanding_side_effects"]
    assert isinstance(outstanding, list) and len(outstanding) == 1
    assert outstanding[0]["blocking_reason"] is not None
    assert outstanding[0]["convergence_policy"] is not None


@pytest.mark.asyncio
async def test_close_not_required_with_background_job_flags_pending(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_not_required_with_running_side_effect(session_factory)
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "not required background side effects"},
        headers=_hdr(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["background_side_effects_pending"] is True
    assert data["outstanding_side_effect_count"] >= 1


@pytest.mark.asyncio
async def test_force_close_bypasses_side_effect_gate(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_required_with_running_side_effect(session_factory)
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "admin force", "force_local_close": True},
        headers=_hdr("admin"),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "closed"
    assert data["external_unsynced"] is True


@pytest.mark.asyncio
async def test_close_reporting_writeback_failed_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_required_event(
        session_factory,
        outbox_status=WritebackStatus.FAILED,
    )
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "writeback failed test"},
        headers=_hdr(),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "writeback_failed"


@pytest.mark.asyncio
async def test_close_reporting_writeback_conflict_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_required_event(
        session_factory,
        outbox_status=WritebackStatus.CONFLICT,
    )
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "writeback conflict test"},
        headers=_hdr(),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "writeback_conflict"


@pytest.mark.asyncio
async def test_close_reporting_writeback_unsupported_readiness_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_required_event(
        session_factory,
        writeback_readiness=WritebackReadiness.CAPABILITY_UNKNOWN,
        outbox_status=WritebackStatus.PENDING,
    )
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "writeback unsupported test"},
        headers=_hdr(),
    )
    assert resp.status_code == 422
    assert resp.json()["error_code"] == "writeback_unsupported"


@pytest.mark.asyncio
async def test_close_reporting_writeback_unknown_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_reporting_required_event(
        session_factory,
        outbox_status=WritebackStatus.UNKNOWN,
    )
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "writeback unknown test"},
        headers=_hdr(),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "writeback_pending"


@pytest.mark.asyncio
async def test_close_reporting_outbox_accepted_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Outbox ACCEPTED must fail API pre-check (intents not all CONFIRMED)."""
    event_id = await _seed_reporting_required_event(
        session_factory,
        outbox_status=WritebackStatus.ACCEPTED,
    )
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "outbox accepted test"},
        headers=_hdr(),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "writeback_pending"


@pytest.mark.asyncio
async def test_close_reporting_action_status_not_confirmed_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Action writeback_status must be CONFIRMED even when outbox rows are CONFIRMED."""
    event_id = await _seed_reporting_required_event(
        session_factory,
        outbox_status=WritebackStatus.CONFIRMED,
        entity_action_writeback_status=WritebackStatus.ACCEPTED,
    )
    await _seed_report_with_event(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "action status mismatch test"},
        headers=_hdr(),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "writeback_pending"
    assert resp.json()["details"]["writeback_status"] == WritebackStatus.ACCEPTED.value


@pytest.mark.asyncio
async def test_close_reporting_verdict_change_preserves_report_sections(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> None:
    """Changing verdict on a full report must not replace sections with quick-close placeholders."""
    event_id = await _seed_reporting_required_event(
        session_factory,
        outbox_status=WritebackStatus.CONFIRMED,
    )
    original_sections = await _seed_investigation_report(session_factory, event_id)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={
            "reason": "verdict change test",
            "final_verdict": "false_positive",
        },
        headers=_hdr(),
    )
    assert resp.status_code == 200, resp.text

    report = await event_service.get_report(event_id=event_id)
    assert report is not None
    assert report.final_verdict == FinalVerdict.FALSE_POSITIVE
    assert report.generated_by == "template"
    assert len(report.sections) == len(original_sections)
    assert report.sections[0].content == original_sections[0]["content"]


@pytest.mark.asyncio
async def test_close_triaging_applies_requested_final_verdict(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _create_test_event(
        event_service,
        title="TRIAGING verdict test",
        severity=Severity.LOW,
    )

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
        json={
            "reason": "triaging fp close",
            "final_verdict": "false_positive",
        },
        headers=_hdr(),
    )
    assert resp.status_code == 200, resp.text

    report = await event_service.get_report(event_id=event_id)
    assert report is not None
    assert report.final_verdict == FinalVerdict.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_investigate_http_low_risk_polls_to_closed(
    client: TestClient,
    event_service: EventService,
) -> None:
    """POST investigate (202) on a low-risk event completes at CLOSED via HTTP."""
    event_id = await _create_test_event(
        event_service,
        title="Investigate HTTP low risk",
        severity=Severity.LOW,
    )

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text

    detail = await _poll_event_status(client, event_id, "closed")
    assert detail["event"]["status"] == "closed"
    assert detail["analysis_only_complete"] is True
    assert detail["response_phase_state"] == "complete"

    report_resp = client.get(f"/api/v1/events/{event_id}/report", headers=_hdr())
    assert report_resp.status_code == 200


@pytest.mark.asyncio
async def test_investigate_high_risk_http_polls_to_reporting(
    client: TestClient,
    event_service: EventService,
) -> None:
    """High-risk required events stay at REPORTING when started via HTTP investigate."""
    from app.models.enums import SourceDisposition, SourceObjectKind
    from app.models.source import SourceReference
    from app.services.event_service import IngestableSource

    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="t1",
        connector_id="conn-mock-http-high",
        source_object_id="INC-HTTP-HIGH-001",
        source_status_raw="open",
        source_disposition=SourceDisposition.PENDING,
        schema_version="1",
    )
    ingest = IngestableSource(
        reference=ref,
        title="HTTP high risk incident",
        description="Serious incident for HTTP investigate test",
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
    )
    result = await event_service.ingest_source_object(ingest)
    assert result.event_id is not None
    event_id = result.event_id

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text

    detail = await _poll_event_status(client, event_id, "reporting")
    assert detail["event"]["status"] == "reporting"

    # ISSUE-242: generate_report=true completion must have persisted report bytes
    # by the time durable REPORTING is visible — GET must not 404.
    report_resp = client.get(f"/api/v1/events/{event_id}/report", headers=_hdr())
    assert report_resp.status_code == 200, report_resp.text
    report = report_resp.json()["report"]
    assert report["event_id"] == event_id
    assert report.get("sections"), "persisted report must include sections"


@pytest.mark.asyncio
async def test_investigate_http_flow_polls_to_completion(
    client: TestClient,
    event_service: EventService,
) -> None:
    """Backward-compatible alias for the low-risk HTTP investigate path."""
    await test_investigate_http_low_risk_polls_to_closed(client, event_service)


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
    """202 exposes the already-committed durable intent and generation task id."""
    event_id = await _create_test_event(event_service, title="Investigate 202 test")

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, f"Expected 202 Accepted, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["task_id"] != event_id
    assert data["event_id"] == event_id
    assert data["intent_id"].startswith("iin-")
    assert data.get("generate_report") is True
    async with session_factory() as session:
        intent = await session.get(orm.InvestigationIntent, data["intent_id"])
        assert intent is not None
        assert intent.event_id == event_id
        assert intent.request_idempotency_key == f"http-investigate:{event_id}"
        assert intent.request_payload_sha256 is not None
        assert intent.requested_by == "analyst-1"


@pytest.mark.asyncio
async def test_investigate_idempotency_replay_and_payload_conflict(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    reset_deps()
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: None,
    )
    event_id = await _create_test_event(event_service, title="Investigate idempotency")
    headers = {**_hdr(), "Idempotency-Key": "investigate-request-1"}

    with client as persistent_client:
        first = persistent_client.post(
            f"/api/v1/events/{event_id}/investigate",
            headers=headers,
            json={"generate_report": True},
        )
        replay = persistent_client.post(
            f"/api/v1/events/{event_id}/investigate",
            headers=headers,
            json={"generate_report": True},
        )
        conflict = persistent_client.post(
            f"/api/v1/events/{event_id}/investigate",
            headers=headers,
            json={"generate_report": False},
        )

    assert first.status_code == 202, first.text
    assert replay.status_code == 202, replay.text
    assert replay.json()["intent_id"] == first.json()["intent_id"]
    assert replay.json()["task_id"] == first.json()["task_id"]
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error_code"] == "idempotency_key_reuse"


@pytest.mark.asyncio
async def test_investigate_echoes_generate_report_false(
    client: TestClient,
    event_service: EventService,
) -> None:
    event_id = await _create_test_event(event_service, title="Investigate generate_report false")
    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
        json={"generate_report": False},
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["generate_report"] is False


@pytest.mark.asyncio
async def test_close_reporting_without_report_returns_closed_requires_report(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """ISSUE-204: CLOSED gate surfaces closed_requires_report at HTTP layer."""
    event_id = await _seed_reporting_not_required_without_report(session_factory)

    resp = client.post(
        f"/api/v1/events/{event_id}/close",
        json={"reason": "attempt close without report"},
        headers=_hdr(),
    )
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["error_code"] == "closed_requires_report"
    assert body["details"]["report_exists"] is False
    assert "POST /api/v1/events/{event_id}/report" in body["error_message"]


@pytest.mark.asyncio
async def test_investigate_background_lease_contention_keeps_accepted_intent(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-276: lease contention after durable commit still returns 202."""
    from app.api.v1 import events as events_module

    event_id = await _create_test_event(event_service, title="Investigate lease contention")

    class _BlockedLease:
        async def acquire(self, _event_id: str, _owner_id: str, ttl_s: int = 600) -> bool:
            return False

        async def release(self, _event_id: str, _owner_id: str) -> bool:
            return True

    monkeypatch.setattr(events_module, "get_event_lease", lambda: _BlockedLease())

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert data["intent_id"].startswith("iin-")
    async with session_factory() as session:
        intent = await session.get(orm.InvestigationIntent, data["intent_id"])
        assert intent is not None
        assert intent.status == "pending"


@pytest.mark.asyncio
async def test_investigate_background_lease_contention_analysis_only_keeps_accepted_intent(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """analysis_only volatile path keeps accepted intent on lease contention."""
    from app.api.v1 import events as events_module
    from app.core.config import get_settings

    monkeypatch.setenv("ORCHESTRATION_MODE", "analysis_only")
    get_settings.cache_clear()

    event_id = await _create_test_event(event_service, title="Analysis-only lease contention")

    class _BlockedLease:
        async def acquire(self, _event_id: str, _owner_id: str, ttl_s: int = 600) -> bool:
            return False

        async def release(self, _event_id: str, _owner_id: str) -> bool:
            return True

    monkeypatch.setattr(events_module, "get_event_lease", lambda: _BlockedLease())

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text
    async with session_factory() as session:
        intent = await session.get(orm.InvestigationIntent, resp.json()["intent_id"])
        assert intent is not None
        assert intent.status == "pending"


@pytest.mark.asyncio
async def test_investigate_celery_mode_commits_without_http_lease(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Durable Celery intake does not hold a process-owned Redis execution lease."""
    from app.api.v1 import events as events_module
    from app.core.config import get_settings

    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()

    event_id = await _create_test_event(event_service, title="Investigate celery duplicate 409")

    def _unexpected_lease() -> None:
        raise AssertionError("Celery HTTP intake must not acquire execution lease")

    monkeypatch.setattr(events_module, "get_event_lease", _unexpected_lease)
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: None,
    )

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["intent_id"].startswith("iin-")


@pytest.mark.asyncio
async def test_investigate_celery_broker_failure_keeps_pending_intent(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Broker trigger failure cannot revoke a committed durable acceptance."""
    from app.api.v1 import events as events_module
    from app.core.config import get_settings

    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    reset_deps()

    event_id = await _create_test_event(event_service, title="Celery broker recovery")
    background_calls = {"n": 0}
    original_add_task = events_module.BackgroundTasks.add_task

    def _broker_down() -> None:
        raise ConnectionError("broker down")

    def _track_add_task(self: object, *args: object, **kwargs: object) -> None:
        background_calls["n"] += 1
        return original_add_task(self, *args, **kwargs)

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _broker_down,
    )
    monkeypatch.setattr(events_module.BackgroundTasks, "add_task", _track_add_task)

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text
    assert background_calls["n"] == 0
    async with session_factory() as session:
        intent = await session.get(orm.InvestigationIntent, resp.json()["intent_id"])
        assert intent is not None
        assert intent.status == "pending"
        assert intent.broker_task_id == resp.json()["task_id"]


@pytest.mark.asyncio
async def test_investigate_commit_failure_does_not_return_202(
    client: TestClient,
    event_service: EventService,
) -> None:
    """ISSUE-276: durable commit failure must not accept the request."""
    from app.api.v1.deps import get_investigation_intent_service
    from app.core.errors import DependencyUnavailableError
    from app.main import app

    event_id = await _create_test_event(event_service, title="Investigate commit failure")

    class _FailingIntentService:
        async def create_or_replay_http_intent(self, *_args: object, **_kwargs: object) -> object:
            raise DependencyUnavailableError(
                "postgres unavailable",
                error_code="dependency_unavailable",
                details={"dependency": "postgres"},
            )

    app.dependency_overrides[get_investigation_intent_service] = lambda: _FailingIntentService()
    try:
        resp = client.post(
            f"/api/v1/events/{event_id}/investigate",
            headers=_hdr(),
        )
    finally:
        app.dependency_overrides.pop(get_investigation_intent_service, None)

    assert resp.status_code >= 400, resp.text
    assert resp.status_code != 202


@pytest.mark.asyncio
async def test_analysis_only_celery_dispatches_dedicated_task(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Analysis-only selection is persisted for restart-safe dispatch."""
    from app.core.config import get_settings

    monkeypatch.setenv("ORCHESTRATION_MODE", "analysis_only")
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    reset_deps()

    event_id = await _create_test_event(event_service, title="Analysis-only celery dispatch")
    dispatches: list[bool] = []
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: dispatches.append(True),
    )

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text
    assert dispatches == [True]
    async with session_factory() as session:
        intent = await session.get(orm.InvestigationIntent, resp.json()["intent_id"])
        assert intent is not None
        assert intent.orchestration_mode == "analysis_only"
        assert intent.status == "pending"


@pytest.mark.asyncio
async def test_analysis_only_celery_trigger_failure_keeps_pending_intent(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Analysis-only broker outage preserves the committed intent."""
    from app.core.config import get_settings

    monkeypatch.setenv("ORCHESTRATION_MODE", "analysis_only")
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    reset_deps()

    event_id = await _create_test_event(event_service, title="Analysis-only broker recovery")

    def _fail_dispatch() -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _fail_dispatch,
    )

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text
    async with session_factory() as session:
        intent = await session.get(orm.InvestigationIntent, resp.json()["intent_id"])
        assert intent is not None
        assert intent.status == "pending"
        assert intent.orchestration_mode == "analysis_only"


@pytest.mark.asyncio
async def test_analysis_only_concurrent_same_request_replays_original_intent(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A concurrent same-key retry returns the original durable acceptance."""
    from app.core.config import get_settings

    monkeypatch.setenv("ORCHESTRATION_MODE", "analysis_only")
    monkeypatch.setenv("TASK_MODE", "celery")
    get_settings.cache_clear()
    reset_deps()
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: None,
    )

    event_id = await _create_test_event(event_service, title="Analysis-only durable replay")

    with client as persistent_client:
        resp_first = persistent_client.post(
            f"/api/v1/events/{event_id}/investigate",
            headers=_hdr(),
        )
        resp_second = persistent_client.post(
            f"/api/v1/events/{event_id}/investigate",
            headers=_hdr(),
        )
    assert resp_first.status_code == 202, resp_first.text
    assert resp_second.status_code == 202, resp_second.text
    assert resp_second.json()["intent_id"] == resp_first.json()["intent_id"]
    assert resp_second.json()["task_id"] == resp_first.json()["task_id"]


@pytest.mark.asyncio
async def test_analysis_only_investigate_invalid_transition_does_not_mark_failed(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-183: concurrent/stale InvalidStateTransition must not poison event to FAILED."""
    from app.api.v1 import deps
    from app.api.v1 import events as events_module
    from app.api.v1.errors import InvalidStateTransitionError
    from app.core.config import get_settings

    monkeypatch.setenv("ORCHESTRATION_MODE", "analysis_only")
    monkeypatch.setenv("TASK_MODE", "background")
    get_settings.cache_clear()
    deps.reset_deps()

    event_id = await _create_test_event(event_service, title="Analysis-only ISTE guard")
    released: list[tuple[str, str]] = []

    class _ConcurrentLoserPipeline:
        async def run(
            self,
            _event_id: str,
            *,
            generate_report: bool = True,
            **kwargs: Any,
        ) -> None:
            del generate_report, kwargs
            raise InvalidStateTransitionError(
                "AnalysisOnlyPipeline requires event in NEW status, got triaging",
                current=EventStatus.TRIAGING,
                target=EventStatus.TRIAGING,
                details={"event_id": _event_id},
            )

    class _TrackingLease:
        async def acquire(self, _event_id: str, _owner_id: str, ttl_s: int = 600) -> bool:
            return True

        async def release(self, _event_id: str, _owner_id: str) -> bool:
            released.append((_event_id, _owner_id))
            return True

    async def _pipeline_factory() -> _ConcurrentLoserPipeline:
        return _ConcurrentLoserPipeline()

    monkeypatch.setattr(events_module, "get_event_lease", lambda: _TrackingLease())
    monkeypatch.setattr(events_module, "get_pipeline", _pipeline_factory)
    monkeypatch.setattr(deps, "get_pipeline", _pipeline_factory)

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text

    deadline = time.time() + 5.0
    while time.time() < deadline and not released:
        await asyncio.sleep(0.05)
    assert released, "background pipeline must complete and release lease"

    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status is not EventStatus.FAILED


@pytest.mark.asyncio
async def test_analysis_only_investigate_releases_lease_when_pipeline_wiring_fails(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-183: analysis_only background wiring failure must release the HTTP-held lease."""
    from app.api.v1 import events as events_module
    from app.core.config import get_settings

    monkeypatch.setenv("ORCHESTRATION_MODE", "analysis_only")
    get_settings.cache_clear()

    event_id = await _create_test_event(event_service, title="Analysis-only wiring fail")
    released: list[tuple[str, str]] = []

    class _TrackingLease:
        async def acquire(self, eid: str, owner_id: str, ttl_s: int = 600) -> bool:
            return True

        async def release(self, eid: str, owner_id: str) -> bool:
            released.append((eid, owner_id))
            return True

    async def _boom_pipeline() -> None:
        raise RuntimeError("pipeline wiring failed")

    monkeypatch.setattr(events_module, "get_event_lease", lambda: _TrackingLease())
    monkeypatch.setattr(events_module, "get_pipeline", _boom_pipeline)

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text

    deadline = time.time() + 5.0
    while time.time() < deadline and not released:
        await asyncio.sleep(0.05)

    assert released, "lease must be released after analysis_only pipeline completes"
    assert released[0][0] == event_id


@pytest.mark.asyncio
async def test_investigate_lease_unavailable_returns_503(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the lease store is down, investigate fails with 503 not 409."""
    from app.api.v1 import events as events_module
    from app.core.errors import DependencyUnavailableError

    event_id = await _create_test_event(event_service, title="Investigate lease down")

    class _UnavailableLease:
        async def acquire(self, _event_id: str, _owner_id: str, ttl_s: int = 600) -> bool:
            raise DependencyUnavailableError(
                message="event lease store unavailable",
                error_code="dependency_unavailable",
                details={"dependency": "redis"},
            )

    monkeypatch.setattr(events_module, "get_event_lease", lambda: _UnavailableLease())

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 503, resp.text
    data = resp.json()
    assert data["error_code"] == "dependency_unavailable"


@pytest.mark.asyncio
async def test_investigate_releases_lease_when_super_agent_wiring_fails(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Background wiring failure must not leave the HTTP-held lease stuck."""
    from app.api.v1 import events as events_module

    event_id = await _create_test_event(event_service, title="Investigate wiring fail")
    released: list[tuple[str, str]] = []

    class _TrackingLease:
        async def acquire(self, eid: str, owner_id: str, ttl_s: int = 600) -> bool:
            return True

        async def release(self, eid: str, owner_id: str) -> bool:
            released.append((eid, owner_id))
            return True

    async def _boom_super_agent() -> None:
        raise RuntimeError("planner wiring failed")

    monkeypatch.setattr(events_module, "get_event_lease", lambda: _TrackingLease())
    monkeypatch.setattr(events_module, "get_super_agent", _boom_super_agent)

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text

    deadline = time.time() + 5.0
    while time.time() < deadline and not released:
        await asyncio.sleep(0.05)

    assert released, "lease must be released when investigate never started"
    assert released[0][0] == event_id


@pytest.mark.asyncio
async def test_investigate_background_lease_lost_does_not_mark_failed(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-189: background SuperAgent must not poison event on lease loss."""
    from app.api.v1 import events as events_module
    from app.core.errors import InvestigationLeaseLostError

    event_id = await _create_test_event(event_service, title="Investigate lease lost bg")
    completed = asyncio.Event()

    class _LeaseLostAgent:
        async def investigate(self, *_args: object, **_kwargs: object) -> None:
            completed.set()
            raise InvestigationLeaseLostError(
                message="investigation lease lost during orchestration",
                error_code="investigation_lease_lost",
                details={"event_id": event_id},
            )

    async def _fake_super_agent() -> _LeaseLostAgent:
        return _LeaseLostAgent()

    monkeypatch.setattr(events_module, "get_super_agent", _fake_super_agent)

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text

    deadline = time.time() + 5.0
    while time.time() < deadline and not completed.is_set():
        await asyncio.sleep(0.05)
    assert completed.is_set(), "background investigate must run"

    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status is EventStatus.NEW


@pytest.mark.asyncio
async def test_investigate_background_real_failure_still_marks_failed(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-189: uncaught investigate errors must still transition to FAILED."""
    from app.api.v1 import events as events_module

    event_id = await _create_test_event(event_service, title="Investigate real failure bg")
    completed = asyncio.Event()

    class _FailingAgent:
        async def investigate(self, *_args: object, **_kwargs: object) -> None:
            completed.set()
            raise RuntimeError("planner wiring failed")

    async def _fake_super_agent() -> _FailingAgent:
        return _FailingAgent()

    monkeypatch.setattr(events_module, "get_super_agent", _fake_super_agent)

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
    )
    assert resp.status_code == 202, resp.text

    deadline = time.time() + 5.0
    while time.time() < deadline and not completed.is_set():
        await asyncio.sleep(0.05)
    assert completed.is_set(), "background investigate must run"

    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status is EventStatus.FAILED


@pytest.mark.asyncio
async def test_investigate_reporting_status_rejected(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """ISSUE-103 / #606: investigate accepts NEW only; REPORTING cannot re-investigate."""
    event_id = await _seed_reporting_required_event(
        session_factory,
        title="Reporting investigate rejected",
        include_action=False,
    )

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
        json={"include_response_execution": True},
    )
    assert resp.status_code == 400, resp.text
    data = resp.json()
    assert data["error_code"] == "invalid_state_transition"


@pytest.mark.asyncio
async def test_investigate_full_loop_unavailable_in_analysis_only_mode(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-103: ORCHESTRATION_MODE=analysis_only rejects include_response_execution."""
    from app.core.config import get_settings

    monkeypatch.setenv("ORCHESTRATION_MODE", "analysis_only")
    get_settings.cache_clear()

    event_id = await _create_test_event(event_service, title="Analysis-only mode gate")

    resp = client.post(
        f"/api/v1/events/{event_id}/investigate",
        headers=_hdr(),
        json={"include_response_execution": True},
    )
    assert resp.status_code == 422, resp.text
    data = resp.json()
    assert data["error_code"] == "full_loop_unavailable"


@pytest.mark.asyncio
async def test_event_get_projects_deferred_analysis_guidance(
    client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
) -> None:
    """ISSUE-103: deferred REPORTING exposes phase guidance without resume CTA."""
    event_id = await _seed_reporting_required_event(
        session_factory,
        title="Deferred analysis guidance",
        include_action=False,
    )

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.event_context_snapshot = {"analysis_only_complete": True}
            await session.flush()

    await context_store.set(event_id, "analysis_only_complete", True)

    resp = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["analysis_only_complete"] is True
    assert data["response_phase_state"] == "analysis_complete_deferred"
    assert data["next_recommended_action"] == "none"
    assert data["phase_message"] is not None


# --------------------------------------------------------------------------- #
# Helper: integration pipeline with tool executor + evidence projection
# --------------------------------------------------------------------------- #


def _build_integration_pipeline(
    *,
    event_service: EventService,
    state_machine_service,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: Any | None = None,
):
    """Build AnalysisOnlyPipeline wired like production deps (ISSUE-039)."""
    from app.agents.evidence_agent import EvidenceAgent
    from app.agents.rag_agent import RAGAgent
    from app.agents.report_agent import ReportAgent
    from app.agents.risk_agent import RiskAgent
    from app.agents.triage_agent import TriageAgent
    from app.core.config import get_settings
    from app.core.redis_client import RedisClient
    from app.services.analysis_only_pipeline import AnalysisOnlyPipeline
    from app.services.context_service import EventContextStore
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.evidence_projection import EvidenceProjection, bind_evidence_projection
    from app.services.working_memory import WorkingMemory
    from app.tools.executor import get_tool_executor

    settings = get_settings()
    redis = RedisClient(url=settings.redis_url)
    store = context_store or EventContextStore(redis, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    wm = WorkingMemory(store=store, redis=redis, degraded_flags=degraded)
    tool_executor = get_tool_executor()

    triage = TriageAgent(
        llm_client=None,
        working_memory=wm.for_writer("TriageAgent"),
    )
    evidence = EvidenceAgent(
        llm_client=None,
        tool_executor=tool_executor,
        working_memory=wm.for_writer("EvidenceAgent"),
        event_service=event_service,
        session_factory=session_factory,
    )
    rag = RAGAgent(
        working_memory=wm.for_writer("RAGAgent"),
        pipeline=None,
    )
    risk = RiskAgent(
        llm_client=None,
        working_memory=wm.for_writer("RiskAgent"),
        event_service=event_service,
        scenario_id="insider_data_exfiltration",
    )
    report = ReportAgent(
        llm_client=None,
        working_memory=wm.for_writer("ReportAgent"),
        event_service=event_service,
        scenario_id="insider_data_exfiltration",
    )

    pipeline = AnalysisOnlyPipeline(
        event_service=event_service,
        state_machine=state_machine_service,
        triage_agent=triage,
        evidence_agent=evidence,
        rag_agent=rag,
        risk_agent=risk,
        report_agent=report,
        context_store=store,
        settings=settings,
    )
    projection = EvidenceProjection(session_factory)
    return pipeline, projection, bind_evidence_projection, store


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
    pipeline, projection, bind_projection, _store = _build_integration_pipeline(
        event_service=event_service,
        state_machine_service=state_machine_service,
        session_factory=session_factory,
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

    with bind_projection(projection):
        result = await pipeline.run(event_id)

    assert result.event_id == event_id
    assert result.analysis_only_complete is True

    # After pipeline: should be CLOSED (not_required + low severity = short-circuit close).
    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status == EventStatus.CLOSED
    assert event.event_context_snapshot is not None
    assert event.event_context_snapshot["analysis_only_complete"] is True

    detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail.status_code == 200
    assert detail.json()["analysis_only_complete"] is True
    assert detail.json()["response_phase_state"] == "complete"


@pytest.mark.asyncio
async def test_high_risk_event_stays_reporting(
    client: TestClient,
    event_service: EventService,
    state_machine_service,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """High-risk required events stay at REPORTING after analysis."""
    from app.models.enums import SourceDisposition, SourceObjectKind
    from app.models.source import SourceReference
    from app.services.event_service import IngestableSource

    pipeline, projection, bind_projection, _store = _build_integration_pipeline(
        event_service=event_service,
        state_machine_service=state_machine_service,
        session_factory=session_factory,
    )

    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="t1",
        connector_id="conn-mock-high",
        source_object_id="INC-HIGH-001",
        source_status_raw="open",
        source_disposition=SourceDisposition.PENDING,
        schema_version="1",
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

    if event.status == EventStatus.NEW:
        with bind_projection(projection):
            pipeline_result = await pipeline.run(event_id)
        assert pipeline_result.disposition_policy == "required"
        assert pipeline_result.analysis_only_complete is True

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
    pipeline, projection, bind_projection, store = _build_integration_pipeline(
        event_service=event_service,
        state_machine_service=state_machine_service,
        session_factory=session_factory,
    )

    event = await event_service.create_event(
        {"title": "Persistence test", "description": "Low risk"},
        source_type="manual",
        title="Persistence test",
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.LOW,
    )
    event_id = event.event_id

    with bind_projection(projection):
        result = await pipeline.run(event_id)
    assert result.analysis_only_complete is True

    stored_value = await store.get(event_id, "analysis_only_complete")
    assert stored_value is True, (
        f"Expected analysis_only_complete=True in context, got {stored_value!r}"
    )
