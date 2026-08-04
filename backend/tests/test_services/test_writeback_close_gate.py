"""WritebackCloseGate API error mapping and outbox projection helpers (ISSUE-171)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import (
    WritebackConflictError,
    WritebackFailedError,
    WritebackPendingError,
    WritebackUnsupportedError,
)
from app.db import models as orm
from app.models.enums import (
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    FinalVerdict,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.workflow import WritebackCloseGateReason, WritebackCloseGateViolation
from app.services.writeback_close_gate import (
    build_closed_gate_actions,
    raise_api_writeback_gate_error,
)


async def _seed_gate_event_with_outboxes(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    outboxes: list[tuple[WritebackStatus, str | None]],
) -> str:
    """Seed a REQUIRED response Action whose outboxes carry the given states.

    Each outbox is ``(latest_writeback_status, superseded_by_disposition_id)``;
    ``superseded_by=None`` means an active (live) outbox head.
    """
    import hashlib

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="Close gate outbox fixture",
                    description="ISSUE-185 vacuum regression fixture",
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
                    reason="test_setup:close_gate_outbox",
                )
            )
            await session.flush()
            session.add(
                orm.SourceConnector(
                    connector_id=f"conn-{sfx}",
                    source_product="mock_xdr",
                    display_name="Close gate connector",
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
            for idx, (status, superseded_by) in enumerate(outboxes):
                session.add(
                    orm.DispositionOutbox(
                        outbox_id=f"obx-{sfx}-{idx}",
                        writeback_id=f"wbk-{sfx}-{idx}",
                        disposition_id=f"disp-{sfx}-{idx}",
                        action_id=f"act-{sfx}",
                        event_id=event_id,
                        closure_cycle=1,
                        source_record_id=f"src-{sfx}",
                        source_locator_hash="h" * 64,
                        source_sequence=idx + 1,
                        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                        logical_slot=f"slot-{idx}",
                        superseded_by_disposition_id=superseded_by,
                        idempotency_key=f"idem-{sfx}-{idx}",
                        command_payload={},
                        command_payload_sha256="a" * 64,
                        delivery_status="delivered",
                        latest_writeback_status=status.value,
                    )
                )
            await session.flush()
    return event_id


@pytest.mark.parametrize(
    ("violation", "error_type", "error_code"),
    [
        (
            WritebackCloseGateViolation(reason=WritebackCloseGateReason.NO_APPLICABLE),
            WritebackUnsupportedError,
            "writeback_unsupported",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.READINESS_NOT_READY,
                action_id="act-1",
                writeback_readiness="capability_unknown",
            ),
            WritebackUnsupportedError,
            "writeback_unsupported",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.NO_COMMAND,
                action_id="act-1",
            ),
            WritebackUnsupportedError,
            "writeback_unsupported",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.INTENTS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.PENDING.value,
            ),
            WritebackPendingError,
            "writeback_pending",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.INTENTS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.FAILED.value,
            ),
            WritebackFailedError,
            "writeback_failed",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.INTENTS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.CONFLICT.value,
            ),
            WritebackConflictError,
            "writeback_conflict",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.STATUS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.ACCEPTED.value,
            ),
            WritebackPendingError,
            "writeback_pending",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.STATUS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.FAILED.value,
            ),
            WritebackFailedError,
            "writeback_failed",
        ),
        (
            WritebackCloseGateViolation(
                reason=WritebackCloseGateReason.STATUS_NOT_CONFIRMED,
                action_id="act-1",
                writeback_status=WritebackStatus.CONFLICT.value,
            ),
            WritebackConflictError,
            "writeback_conflict",
        ),
    ],
)
def test_raise_api_writeback_gate_error_reason_matrix(
    violation: WritebackCloseGateViolation,
    error_type: type[Exception],
    error_code: str,
) -> None:
    with pytest.raises(error_type) as exc_info:
        raise_api_writeback_gate_error(violation, event_id="evt-matrix")
    err = exc_info.value
    assert getattr(err, "error_code", None) == error_code
    assert err.details["event_id"] == "evt-matrix"  # type: ignore[attr-defined]


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_build_closed_gate_actions_vacuum_all_confirmed(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """All-superseded outboxes must not yield a vacuum ``all_confirmed=True``.

    ISSUE-185: ``has_command`` requires an *active* outbox; ``all([])`` must not
    evaluate to True. Otherwise a stale superseded outbox plus a stale
    ``Action.writeback_status=CONFIRMED`` could wrongly satisfy the CLOSED gate.
    """
    event_id = await _seed_gate_event_with_outboxes(
        session_factory,
        outboxes=[(WritebackStatus.CONFIRMED, "obx-head-2")],
    )

    async with session_factory() as session:
        views = await build_closed_gate_actions(session, event_id, current_revision=1)

    assert len(views) == 1
    view = views[0]
    assert view.has_command is False
    assert view.all_required_intents_confirmed is False


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_build_closed_gate_actions_excludes_superseded_from_worst_status(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Superseded FAILED outboxes must not leak into worst_unconfirmed status.

    A live PENDING head keeps the gate open with PENDING, not FAILED from a
    superseded row (ISSUE-185).
    """
    event_id = await _seed_gate_event_with_outboxes(
        session_factory,
        outboxes=[
            (WritebackStatus.FAILED, "obx-head-2"),  # superseded → ignored
            (WritebackStatus.PENDING, None),  # active → drives the gate
        ],
    )

    async with session_factory() as session:
        views = await build_closed_gate_actions(session, event_id, current_revision=1)

    assert len(views) == 1
    view = views[0]
    assert view.has_command is True
    assert view.all_required_intents_confirmed is False
    assert view.worst_unconfirmed_outbox_status == WritebackStatus.PENDING
