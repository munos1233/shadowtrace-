"""ISSUE-209 — classification override API + classification_source derivation."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import reset_deps
from app.core.config import get_settings
from app.db import models as orm
from app.main import app
from app.models.enums import EventStatus, EventType, Severity
from app.services.classification import TRIAGE_RESULT_KEY
from app.services.event_service import EventService

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
        "approver-token": {"subject": "approver-1", "roles": ["approver"]},
        "viewer-token": {"subject": "viewer-1", "roles": ["viewer"]},
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
    monkeypatch.setenv("TASK_MODE", "background")
    get_settings.cache_clear()
    reset_deps()
    yield
    reset_deps()
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def _hdr(role: str = "analyst") -> dict[str, str]:
    return {"Authorization": f"Bearer {role}-token"}


@pytest.fixture
def client(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> TestClient:
    from app.api.v1.deps import get_event_service

    async def _override_event_service() -> EventService:
        return event_service

    app.dependency_overrides[get_event_service] = _override_event_service
    return TestClient(app)


async def _create_event(
    event_service: EventService,
    *,
    title: str = "Classification test",
    event_type: EventType = EventType.OTHER,
) -> str:
    event = await event_service.create_event(
        {"title": title, "description": "ISSUE-209 classification fixture"},
        source_type="manual",
        title=title,
        event_type=event_type,
        severity=Severity.MEDIUM,
    )
    return event.event_id


@pytest.mark.asyncio
async def test_patch_classification_then_get_is_human_and_audited(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _create_event(
        event_service,
        title="Patch classification",
        event_type=EventType.OTHER,
    )

    patch = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={
            "event_type": "data_exfiltration",
            "reason": "Source alert_type mismatched exfil pattern",
            "reinvestigate": False,
        },
        headers=_hdr(),
    )
    assert patch.status_code == 200, patch.text
    body = patch.json()
    assert body["event_type"] == "data_exfiltration"
    assert body["classification_source"] == "human"
    assert body["previous_event_type"] == "other"
    assert body["reinvestigate_requested"] is False
    assert body["reinvestigate_started"] is False

    detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail.status_code == 200, detail.text
    event = detail.json()["event"]
    assert event["event_type"] == "data_exfiltration"
    assert event["classification_source"] == "human"
    override = (event.get("event_context_snapshot") or {}).get("classification_override")
    assert isinstance(override, dict)
    assert override.get("source") == "human"

    listed = client.get("/api/v1/events", headers=_hdr())
    assert listed.status_code == 200
    match = next(item for item in listed.json()["items"] if item["event_id"] == event_id)
    assert match["event_type"] == "data_exfiltration"
    assert match["classification_source"] == "human"

    async with session_factory() as session:
        rows = (
            await session.execute(
                select(orm.EventAuditLog).where(orm.EventAuditLog.event_id == event_id)
            )
        ).scalars().all()
    assert any(
        "classification_override:other->data_exfiltration" in (row.reason or "")
        for row in rows
    )


@pytest.mark.asyncio
async def test_get_derives_from_degraded_flags_without_human(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _create_event(
        event_service,
        title="Heuristic flags",
        event_type=EventType.ACCOUNT_ANOMALY,
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.degraded_flags = ["event_type_from_heuristic=true"]

    detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail.status_code == 200, detail.text
    assert detail.json()["event"]["classification_source"] == "heuristic"

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.degraded_flags = [
                "event_type_from_heuristic=true",
                "event_type_from_llm_fallback=true",
            ]

    detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail.status_code == 200
    assert detail.json()["event"]["classification_source"] == "llm_fallback"

    # Explicit source mapping → no machine flags → source
    event_id_src = await _create_event(
        event_service,
        title="Source mapped",
        event_type=EventType.HOST_COMPROMISE,
    )
    detail_src = client.get(f"/api/v1/events/{event_id_src}", headers=_hdr())
    assert detail_src.status_code == 200
    assert detail_src.json()["event"]["classification_source"] == "source"


@pytest.mark.asyncio
async def test_classification_conflict_during_active_investigation(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _create_event(event_service, title="Locked executing")
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.status = EventStatus.EXECUTING_RESPONSE.value

    resp = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={
            "event_type": "lateral_movement",
            "reason": "should be blocked",
        },
        headers=_hdr(),
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["error_code"] == "classification_conflict_active_investigation"

    # Type must remain unchanged
    detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail.json()["event"]["event_type"] == "other"


@pytest.mark.asyncio
async def test_classification_forbidden_and_illegal_type(
    client: TestClient,
    event_service: EventService,
) -> None:
    event_id = await _create_event(event_service, title="Authz + 422")

    forbidden = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={"event_type": "host_compromise", "reason": "approver cannot"},
        headers=_hdr("approver"),
    )
    assert forbidden.status_code == 403

    illegal = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={"event_type": "not_a_real_type", "reason": "bad enum"},
        headers=_hdr(),
    )
    assert illegal.status_code == 422


@pytest.mark.asyncio
async def test_reinvestigate_true_on_new_starts_pipeline(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = await _create_event(event_service, title="Reinvestigate NEW")
    scheduled: list[str] = []

    async def _fake_schedule(**kwargs: object) -> str:
        scheduled.append(str(kwargs.get("event_id") or ""))
        return str(kwargs.get("event_id") or event_id)

    monkeypatch.setattr(
        "app.api.v1.events._schedule_investigation",
        _fake_schedule,
    )

    resp = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={
            "event_type": "malicious_process",
            "reason": "reinvestigate after override",
            "reinvestigate": True,
        },
        headers=_hdr(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reinvestigate_requested"] is True
    assert body["reinvestigate_started"] is True
    assert scheduled == [event_id]
    assert any("investigation_lease_acquired" in s for s in body["side_effects"])
    assert any("analysis_pipeline_scheduled" in s for s in body["side_effects"])


@pytest.mark.asyncio
async def test_patch_syncs_triage_result_event_type(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _create_event(
        event_service,
        title="Triage sync",
        event_type=EventType.OTHER,
    )
    triage_payload = {
        "event_type": "other",
        "severity": "medium",
        "confidence": 0.55,
        "summary": "seeded triage for ISSUE-209",
    }
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            snap = dict(row.event_context_snapshot or {})
            snap[TRIAGE_RESULT_KEY] = triage_payload
            row.event_context_snapshot = snap
    await event_service._store.set(event_id, TRIAGE_RESULT_KEY, triage_payload)

    resp = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={
            "event_type": "data_exfiltration",
            "reason": "align triage with human override",
            "reinvestigate": False,
        },
        headers=_hdr(),
    )
    assert resp.status_code == 200, resp.text

    detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail.status_code == 200
    snap = detail.json()["event"].get("event_context_snapshot") or {}
    assert snap.get(TRIAGE_RESULT_KEY, {}).get("event_type") == "data_exfiltration"

    stored = await event_service._store.get(event_id, TRIAGE_RESULT_KEY)
    assert isinstance(stored, dict)
    assert stored.get("event_type") == "data_exfiltration"

    async with session_factory() as session:
        rows = (
            await session.execute(
                select(orm.EventAuditLog).where(orm.EventAuditLog.event_id == event_id)
            )
        ).scalars().all()
    assert any("triage_result_event_type_synced" in (row.reason or "") for row in rows)


@pytest.mark.asyncio
async def test_patch_allowed_while_waiting_approval(
    client: TestClient,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _create_event(event_service, title="Waiting approval OK")
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.status = EventStatus.WAITING_APPROVAL.value

    resp = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={
            "event_type": "lateral_movement",
            "reason": "allowed while waiting for approval",
        },
        headers=_hdr(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["event_type"] == "lateral_movement"
    detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail.json()["event"]["classification_source"] == "human"
    assert detail.json()["event"]["status"] == EventStatus.WAITING_APPROVAL.value


@pytest.mark.asyncio
async def test_context_store_failure_still_human_via_snapshot(
    client: TestClient,
    event_service: EventService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = await _create_event(event_service, title="Context fail still human")
    original_set = event_service._store.set

    async def _boom_override(eid: str, field: str, value: object, *args: object, **kwargs: object):
        if field == "classification_override":
            raise RuntimeError("injected classification_override context failure")
        return await original_set(eid, field, value, *args, **kwargs)

    monkeypatch.setattr(event_service._store, "set", _boom_override)

    resp = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={
            "event_type": "host_compromise",
            "reason": "snapshot must still mark human",
        },
        headers=_hdr(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["classification_source"] == "human"

    detail = client.get(f"/api/v1/events/{event_id}", headers=_hdr())
    assert detail.status_code == 200
    event = detail.json()["event"]
    assert event["event_type"] == "host_compromise"
    assert event["classification_source"] == "human"
    override = (event.get("event_context_snapshot") or {}).get("classification_override")
    assert isinstance(override, dict)
    assert override.get("source") == "human"


@pytest.mark.asyncio
async def test_reason_max_length_rejected(
    client: TestClient,
    event_service: EventService,
) -> None:
    event_id = await _create_event(event_service, title="Reason too long")
    resp = client.patch(
        f"/api/v1/events/{event_id}/classification",
        json={
            "event_type": "other",
            "reason": "x" * 501,
        },
        headers=_hdr(),
    )
    assert resp.status_code == 422
