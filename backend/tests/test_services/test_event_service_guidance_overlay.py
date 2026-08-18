"""Unit tests for get_event guidance snapshot overlays (ISSUE-103 / ISSUE-250)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.db import models as orm
from app.models.context import EventContext
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.security_event import EventSummary
from app.services.event_service import EventService


def _reporting_row(event_id: str, *, snapshot: dict | None) -> orm.SecurityEvent:
    now = datetime.now(UTC)
    return orm.SecurityEvent(
        event_id=event_id,
        event_type=EventType.MALICIOUS_PROCESS.value,
        title="overlay test",
        description="",
        status=EventStatus.REPORTING.value,
        severity=Severity.HIGH.value,
        final_verdict=FinalVerdict.NONE.value,
        entities={},
        creation_source_ref={
            "source_kind": "incident",
            "source_product": "mock_xdr",
            "source_tenant_id": "tenant-1",
            "connector_id": "conn-1",
            "source_object_id": "inc-1",
            "ingested_at": now.isoformat(),
        },
        source_reference_snapshots=[],
        disposition_policy=DispositionPolicy.REQUIRED.value,
        source_type="mock_xdr",
        occurred_at=now,
        row_version=1,
        event_context_snapshot=snapshot,
    )


def _service_with_row(
    row: orm.SecurityEvent,
    *,
    store_values: dict[str, object],
    persisted_report_quality: str | None = None,
) -> EventService:
    session = AsyncMock()

    async def _get(_model: type, pk: str) -> orm.SecurityEvent | None:
        assert pk == row.event_id
        return row

    session.get = AsyncMock(side_effect=_get)
    session.scalar = AsyncMock(return_value=persisted_report_quality)
    session_cm = MagicMock()
    session_cm.__aenter__ = AsyncMock(return_value=session)
    session_cm.__aexit__ = AsyncMock(return_value=False)
    session_factory = MagicMock(return_value=session_cm)

    store = AsyncMock()

    async def _store_get(_event_id: str, key: str) -> object | None:
        return store_values.get(key)

    store.get = AsyncMock(side_effect=_store_get)
    # get_event may backfill from WM; keep overlay tests focused on store.get overlays.
    store.get_full_context = AsyncMock(side_effect=RuntimeError("wm-skip"))
    return EventService(session_factory, store, degraded_flags=AsyncMock())


@pytest.mark.asyncio
async def test_get_event_overlays_analysis_only_complete_from_context_store() -> None:
    """Stale security_event snapshot merges analysis_only_complete from context store."""
    event_id = "evt-overlay-103"
    row = _reporting_row(event_id, snapshot={"risk_assessment": {"risk_score": 72}})
    service = _service_with_row(row, store_values={"analysis_only_complete": True})

    event = await service.get_event(event_id)

    assert event is not None
    assert event.event_context_snapshot is not None
    assert event.event_context_snapshot.get("analysis_only_complete") is True
    service._store.get.assert_any_await(event_id, "analysis_only_complete")


@pytest.mark.asyncio
async def test_get_event_never_downgrades_analysis_only_complete_from_snapshot() -> None:
    """ISSUE-266: stale journal false cannot overwrite durable snapshot true."""
    event_id = "evt-overlay-266-monotonic"
    row = _reporting_row(
        event_id,
        snapshot={"analysis_only_complete": True},
    )
    service = _service_with_row(row, store_values={"analysis_only_complete": False})

    event = await service.get_event(event_id)

    assert event is not None
    assert event.event_context_snapshot is not None
    assert event.event_context_snapshot.get("analysis_only_complete") is True


@pytest.mark.asyncio
async def test_get_event_hydration_never_downgrades_analysis_completion() -> None:
    """Partial snapshot hydration must preserve monotonic durable true."""
    event_id = "evt-overlay-266-hydration"
    row = _reporting_row(
        event_id,
        snapshot={"analysis_only_complete": True},
    )
    service = _service_with_row(row, store_values={"analysis_only_complete": False})
    service._store.get_full_context = AsyncMock(
        return_value=EventContext(
            event=EventSummary(
                event_id=event_id,
                event_type=EventType.MALICIOUS_PROCESS,
                title="overlay test",
                status=EventStatus.REPORTING,
                severity=Severity.HIGH,
                final_verdict=FinalVerdict.NONE,
                risk_score=0,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                disposition_policy=DispositionPolicy.REQUIRED,
            ),
            analysis_only_complete=False,
            report_generated=False,
        )
    )

    event = await service.get_event(event_id)

    assert event is not None
    assert event.event_context_snapshot is not None
    assert event.event_context_snapshot.get("analysis_only_complete") is True


@pytest.mark.asyncio
async def test_get_event_overlays_report_generated_from_context_store() -> None:
    """ISSUE-250: stale snapshot merges report_generated like analysis_only_complete."""
    event_id = "evt-overlay-250-flag"
    row = _reporting_row(
        event_id,
        snapshot={"analysis_only_complete": True, "report_generated": False},
    )
    service = _service_with_row(
        row,
        store_values={
            "analysis_only_complete": True,
            "report_generated": True,
        },
        # DB row present so Redis True is consistent with GET /report.
        persisted_report_quality="complete",
    )

    event = await service.get_event(event_id)

    assert event is not None
    assert event.event_context_snapshot is not None
    assert event.event_context_snapshot.get("report_generated") is True
    service._store.get.assert_any_await(event_id, "report_generated")


@pytest.mark.asyncio
async def test_get_event_clears_stale_report_generated_without_db_report() -> None:
    """ISSUE-250: Redis True without report table must not claim readable report."""
    event_id = "evt-overlay-250-stale"
    row = _reporting_row(
        event_id,
        snapshot={
            "analysis_only_complete": True,
            "report_generated": True,
        },
    )
    service = _service_with_row(
        row,
        store_values={
            "analysis_only_complete": True,
            "report_generated": True,
        },
        persisted_report_quality=None,
    )

    event = await service.get_event(event_id)

    assert event is not None
    assert event.event_context_snapshot is not None
    assert event.event_context_snapshot.get("report_generated") is False


@pytest.mark.asyncio
async def test_get_event_overlays_report_presence_from_report_table() -> None:
    """ISSUE-250: DB report row forces report_generated even when Redis flag lags."""
    event_id = "evt-overlay-250-db"
    row = _reporting_row(
        event_id,
        snapshot={
            "analysis_only_complete": True,
            "report_generated": False,
        },
    )
    service = _service_with_row(
        row,
        store_values={
            "analysis_only_complete": True,
            "report_generated": False,
        },
        persisted_report_quality="degraded_template",
    )

    event = await service.get_event(event_id)

    assert event is not None
    assert event.event_context_snapshot is not None
    assert event.event_context_snapshot.get("report_generated") is True
    assert event.event_context_snapshot.get("report_quality") == "degraded_template"


@pytest.mark.asyncio
async def test_get_event_projects_closed_freeze_to_bounded_summary() -> None:
    """ISSUE-254: CLOSED ORM freeze must not leak full EventContext on GET."""
    event_id = "evt-overlay-254-closed"
    row = _reporting_row(
        event_id,
        snapshot={
            "evidence_output": {
                "evidence_list": [],
                "gaps": [{"missing_source": "dns", "reason": "timeout"}],
                "conflicts": [],
                "success_sources": [],
                "failed_sources": ["dns"],
                "overall_confidence": 0.0,
                "collection_status": "failed",
            },
            "storyline": {
                "storyline_id": "stl-closed",
                "grounding_status": "ungrounded",
                "generated_by": "rule",
                "phases": [{"phase_order": 1}],
                "claim_refs": [],
                "narrative_summary": "n/a",
            },
            "report": {"report_id": "rpt-embedded"},
            "risk_assessment": {"risk_score": 12, "risk_factors": [{"reasoning": "leak"}]},
            "analysis_only_complete": True,
            "report_generated": True,
        },
    )
    row.status = EventStatus.CLOSED.value
    service = _service_with_row(
        row,
        store_values={
            "analysis_only_complete": True,
            "report_generated": True,
        },
        persisted_report_quality=None,
    )

    event = await service.get_event(event_id)

    assert event is not None
    snap = event.event_context_snapshot or {}
    assert snap.get("collection_status") == "failed"
    assert snap.get("evidence_gaps")
    assert snap["storyline"]["grounding_status"] == "ungrounded"
    assert "phases" not in snap["storyline"]
    assert "evidence_output" not in snap
    assert "report" not in snap
    assert "leak" not in str(snap.get("risk_assessment"))
    # No DB report row → do not claim readable report despite freeze blob.
    assert snap.get("report_generated") is False


@pytest.mark.asyncio
async def test_get_event_backfills_evidence_when_orm_has_only_risk() -> None:
    """ISSUE-254: partial ORM snapshot still hydrates evidence summary from WM."""
    from app.models.context import EventContext

    event_id = "evt-overlay-254-backfill"
    row = _reporting_row(event_id, snapshot={"risk_assessment": {"risk_score": 55}})
    service = _service_with_row(row, store_values={"analysis_only_complete": True})
    service._store.get_full_context = AsyncMock(
        return_value=EventContext(
            evidence_output={
                "evidence_list": [],
                "gaps": [{"missing_source": "endpoint", "reason": "empty"}],
                "conflicts": [],
                "success_sources": [],
                "failed_sources": ["endpoint"],
                "overall_confidence": 0.0,
                "collection_status": "failed",
            },
            analysis_only_complete=True,
        )
    )

    event = await service.get_event(event_id)

    assert event is not None
    snap = event.event_context_snapshot or {}
    assert snap.get("risk_assessment", {}).get("risk_score") == 55
    assert snap.get("collection_status") == "failed"
    assert snap.get("evidence_count") == 0
    assert snap.get("analysis_only_complete") is True


@pytest.mark.asyncio
async def test_get_event_overlays_bounded_triage_severity_from_wm() -> None:
    """ISSUE-330: GET hydrates triage_severity without copying the triage payload."""
    event_id = "evt-overlay-330-triage"
    row = _reporting_row(
        event_id,
        snapshot={"risk_assessment": {"risk_score": 77, "severity": "high"}},
    )
    service = _service_with_row(
        row,
        store_values={
            "triage_result": {
                "severity": "medium",
                "decision_summary": "event_type=data_exfiltration, severity=medium",
                "reasoning": "CoT must not leak",
            }
        },
    )

    event = await service.get_event(event_id)

    assert event is not None
    snap = event.event_context_snapshot or {}
    assert snap.get("triage_severity") == "medium"
    assert "triage_result" not in snap
    assert "CoT must not leak" not in str(snap)
    service._store.get.assert_any_await(event_id, "triage_result")


@pytest.mark.asyncio
async def test_get_event_overlays_bounded_triage_event_type_from_wm() -> None:
    event_id = "evt-overlay-triage-event-type"
    row = _reporting_row(
        event_id,
        snapshot={"risk_assessment": {"risk_score": 77, "severity": "high"}},
    )
    service = _service_with_row(
        row,
        store_values={
            "triage_result": {
                "event_type": "data_exfiltration",
                "severity": "high",
                "decision_summary": "event_type=data_exfiltration, severity=high",
                "reasoning": "CoT must not leak",
            }
        },
    )

    event = await service.get_event(event_id)

    assert event is not None
    snap = event.event_context_snapshot or {}
    assert event.event_type == EventType.MALICIOUS_PROCESS
    assert snap.get("triage_event_type") == "data_exfiltration"
    assert "triage_result" not in snap
    assert "CoT must not leak" not in str(snap)
