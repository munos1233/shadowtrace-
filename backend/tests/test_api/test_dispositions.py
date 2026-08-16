"""Writeback API projection tests (ISSUE-370 / #1048)."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import reset_deps
from app.db import models as orm
from app.main import app
from app.models.enums import (
    ConfirmationEvidence,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("clean_state")]

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
        "admin-token": {"subject": "admin-1", "roles": ["admin"]},
    }
)


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("SIMULATION_ENABLED", "true")
    get_settings.cache_clear()
    reset_deps()
    yield
    reset_deps()


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _hdr(role: str = "analyst") -> dict[str, str]:
    return {"Authorization": f"Bearer {role}-token"}


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


async def _seed_writeback_with_receipt(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    simulated: bool,
    confirmation_evidence: ConfirmationEvidence | None,
    writeback_status: WritebackStatus = WritebackStatus.CONFIRMED,
) -> str:
    sfx = _sfx()
    event_id = f"evt-{sfx}"
    writeback_id = f"wbk-{sfx}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            connector_id = f"conn-{sfx}"
            source_record_id = f"src-{sfx}"
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name="Writeback API test connector",
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
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.DATA_EXFILTRATION.value,
                    title="Writeback simulated projection",
                    description="ISSUE-370 writeback API fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=85,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": connector_id,
                        "source_object_id": f"INC-{sfx}",
                        "raw_payload_hash": "a" * 64,
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
                    writeback_readiness=WritebackReadiness.READY.value,
                    writeback_status=writeback_status.value,
                )
            )
            await session.flush()
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{sfx}",
                    writeback_id=writeback_id,
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
                    latest_writeback_status=writeback_status.value,
                )
            )
            session.add(
                orm.DispositionReceipt(
                    writeback_id=writeback_id,
                    sequence=1,
                    disposition_id=f"disp-{sfx}",
                    action_id=f"act-{sfx}",
                    source_record_id=source_record_id,
                    status=writeback_status.value,
                    confirmation_evidence=(
                        confirmation_evidence.value if confirmation_evidence is not None else None
                    ),
                    simulated=simulated,
                )
            )
    return writeback_id


@pytest.mark.asyncio
async def test_get_writeback_projects_mock_receipt_simulated_true(
    session_factory: async_sessionmaker[AsyncSession],
    client: AsyncClient,
) -> None:
    writeback_id = await _seed_writeback_with_receipt(
        session_factory,
        simulated=True,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
    )
    resp = await client.get(f"/api/v1/writebacks/{writeback_id}", headers=_hdr())
    assert resp.status_code == 200
    body = resp.json()
    assert body["simulated"] is True
    assert body["confirmation_evidence"] == ConfirmationEvidence.READBACK_VERIFIED.value
    assert body["evidence_tier"] == "strong"


@pytest.mark.asyncio
async def test_get_writeback_without_receipt_simulated_false(
    session_factory: async_sessionmaker[AsyncSession],
    client: AsyncClient,
) -> None:
    sfx = _sfx()
    writeback_id = f"wbk-{sfx}"
    now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            connector_id = f"conn-{sfx}"
            source_record_id = f"src-{sfx}"
            event_id = f"evt-{sfx}"
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name="No receipt connector",
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
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.DATA_EXFILTRATION.value,
                    title="Pending writeback",
                    description="ISSUE-370 pending writeback fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=85,
                    entities={},
                    creation_source_ref={
                        "source_kind": "incident",
                        "source_product": "mock_xdr",
                        "source_tenant_id": "t1",
                        "connector_id": connector_id,
                        "source_object_id": f"INC-{sfx}",
                        "raw_payload_hash": "b" * 64,
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
                    writeback_readiness=WritebackReadiness.READY.value,
                )
            )
            await session.flush()
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{sfx}",
                    writeback_id=writeback_id,
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
                    delivery_status="ready",
                    latest_writeback_status=WritebackStatus.PENDING.value,
                )
            )
    resp = await client.get(f"/api/v1/writebacks/{writeback_id}", headers=_hdr())
    assert resp.status_code == 200
    assert resp.json()["simulated"] is False


@pytest.mark.asyncio
async def test_resolve_writeback_manual_confirmed_simulated_false(
    session_factory: async_sessionmaker[AsyncSession],
    client: AsyncClient,
) -> None:
    writeback_id = await _seed_writeback_with_receipt(
        session_factory,
        simulated=False,
        confirmation_evidence=None,
        writeback_status=WritebackStatus.UNKNOWN,
    )
    resolve = await client.post(
        f"/api/v1/writebacks/{writeback_id}/resolve",
        headers=_hdr("admin"),
        json={
            "resolution": "manual_confirmed",
            "comment": "ticket verified",
            "evidence_ref": "evidence://ticket-123",
        },
    )
    assert resolve.status_code == 200
    resp = await client.get(f"/api/v1/writebacks/{writeback_id}", headers=_hdr())
    assert resp.status_code == 200
    body = resp.json()
    assert body["simulated"] is False
    assert body["confirmation_evidence"] == ConfirmationEvidence.MANUAL_CONFIRMED.value
    assert body["evidence_tier"] == "strong"
