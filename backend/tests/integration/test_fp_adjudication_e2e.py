"""ISSUE-114 disposition policy tests for post-evidence FP adjudication."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from httpx import ASGITransport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.db import models as orm
from app.models.enums import (
    ActionExecutionPhase,
    ActionStatus,
    EventStatus,
    FinalVerdict,
    SourceDisposition,
    SourceObjectKind,
)
from app.services.evidence_projection import bind_evidence_projection

pytestmark = pytest.mark.e2e_basic


def _journal_scalar(value: object) -> object:
    if isinstance(value, dict) and set(value) == {"_scalar"}:
        return value["_scalar"]
    return value


ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_not_required_post_evidence_fp_closes_without_scenario_dependency(
    session_factory: async_sessionmaker[AsyncSession],
    source_ingester: Any,
    build_analysis_pipeline: Any,
    working_memory: Any,
) -> None:
    """account_anomaly_fp closes only after evidence + org baseline, not fixture names."""
    from app.data_generators.scenarios import build_scenario
    from app.data_generators.scenarios.account_anomaly_fp import SCENARIO_ID
    from app.mock_xdr.api import create_app
    from app.mock_xdr.state import MockXDRState

    state = MockXDRState()
    state.load_scenario(build_scenario(SCENARIO_ID, seed=42))
    transport = ASGITransport(app=create_app(state=state))

    async with httpx.AsyncClient(
        transport=transport, base_url="http://mock-xdr", timeout=30.0
    ) as client:
        adapter = MockXDRSourceAdapter(
            base_url="http://mock-xdr",
            read_token="mock-read-token",
            write_token="mock-write-token",
            client=client,
            max_retries=0,
        )
        summary = await source_ingester.poll(adapter, ALL_SOURCE_KINDS, batch_size=10)
        assert summary.accepted >= 1

    async with session_factory() as session:
        row = (
            await session.scalars(
                select(orm.SecurityEvent).where(
                    orm.SecurityEvent.title == "Bulk login by ops account during change window"
                )
            )
        ).first()
    assert row is not None
    event_id = row.event_id

    pipeline, projection = build_analysis_pipeline(scenario_id=SCENARIO_ID)
    with bind_evidence_projection(projection):
        result = await pipeline.run(event_id)

    assert result is not None
    assert result.short_circuit is False
    assert result.evidence_output is not None
    assert len(result.evidence_output.evidence_list) > 0

    fp_wm = working_memory.for_writer("FalsePositiveMatcher")
    pre_fp = await fp_wm.read(event_id, "false_positive_match")
    if isinstance(pre_fp, dict):
        assert pre_fp.get("recommendation") != "close_as_fp"

    fp_adj_wm = working_memory.for_writer("PostEvidenceFpAdjudicator")
    adjudication = await fp_adj_wm.read(event_id, "fp_adjudication")
    assert isinstance(adjudication, dict)
    assert adjudication.get("recommendation") == "close_as_fp"
    assert adjudication.get("supporting_evidence_ids")
    assert "baseline_window_match" in (adjudication.get("matched_conditions") or [])

    assert result.status == EventStatus.CLOSED
    assert result.final_verdict == FinalVerdict.FALSE_POSITIVE

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        close_logs = (
            await session.scalars(
                select(orm.EventAuditLog)
                .where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.to_status == EventStatus.CLOSED.value,
                )
                .order_by(orm.EventAuditLog.created_at.desc())
            )
        ).all()
    assert row is not None
    assert row.status == EventStatus.CLOSED
    assert close_logs
    assert "post_evidence" in (close_logs[0].reason or "")
    assert "account_anomaly_fp" not in (close_logs[0].reason or "")
    assert "ops_change_window_bulk_login" not in (close_logs[0].reason or "")


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_required_pre_evidence_fp_advisory_does_not_force_verdict_or_close(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: Any,
    session_factory: async_sessionmaker[AsyncSession],
    build_analysis_pipeline: Any,
    working_memory: Any,
) -> None:
    """REQUIRED disposition ignores pre-evidence close_as_fp; stays at REPORTING."""
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.accepted >= 1

    async with session_factory() as session:
        row = (
            await session.scalars(
                select(orm.SecurityEvent).order_by(orm.SecurityEvent.created_at.desc()).limit(1)
            )
        ).first()
    assert row is not None
    event_id = row.event_id

    fp_wm = working_memory.for_writer("FalsePositiveMatcher")
    await fp_wm.write(
        event_id,
        "false_positive_match",
        {
            "matched": True,
            "max_score": 0.96,
            "recommendation": "close_as_fp",
            "phase": "pre_evidence",
            "source": "FalsePositiveMatcher",
        },
    )

    pipeline, projection = build_analysis_pipeline()
    with bind_evidence_projection(projection):
        result = await pipeline.run(event_id)

    assert result.short_circuit is False
    assert result.evidence_output is not None
    assert len(result.evidence_output.evidence_list) > 0
    assert result.final_verdict != FinalVerdict.FALSE_POSITIVE
    assert result.status == EventStatus.REPORTING

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
    assert row is not None
    assert row.status == EventStatus.REPORTING


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_required_post_evidence_fp_adjudication_from_pipeline_without_journal_seed(
    session_factory: async_sessionmaker[AsyncSession],
    source_ingester: Any,
    build_analysis_pipeline: Any,
    working_memory: Any,
    event_service: Any,
) -> None:
    """REQUIRED policy: pipeline produces fp_adjudication naturally and stays at REPORTING."""
    from app.data_generators.scenarios import build_scenario
    from app.data_generators.scenarios.account_anomaly_fp import SCENARIO_ID
    from app.mock_xdr.api import create_app
    from app.mock_xdr.state import MockXDRState
    from app.models.enums import DispositionPolicy, WritebackReadiness
    from app.orchestration.workflow_runtime import WorkflowRuntimeService

    state = MockXDRState()
    state.load_scenario(build_scenario(SCENARIO_ID, seed=42))
    transport = ASGITransport(app=create_app(state=state))

    async with httpx.AsyncClient(
        transport=transport, base_url="http://mock-xdr", timeout=30.0
    ) as client:
        adapter = MockXDRSourceAdapter(
            base_url="http://mock-xdr",
            read_token="mock-read-token",
            write_token="mock-write-token",
            client=client,
            max_retries=0,
        )
        summary = await source_ingester.poll(adapter, ALL_SOURCE_KINDS, batch_size=10)
        assert summary.accepted >= 1

    async with session_factory() as session:
        row = (
            await session.scalars(
                select(orm.SecurityEvent).where(
                    orm.SecurityEvent.title == "Bulk login by ops account during change window"
                )
            )
        ).first()
    assert row is not None
    event_id = row.event_id

    async with session_factory() as session:
        async with session.begin():
            db_row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert db_row is not None
            db_row.disposition_policy = DispositionPolicy.REQUIRED.value

    pipeline, projection = build_analysis_pipeline(scenario_id=SCENARIO_ID)
    with bind_evidence_projection(projection):
        result = await pipeline.run(event_id)

    assert result.short_circuit is False
    assert result.evidence_output is not None
    assert len(result.evidence_output.evidence_list) > 0
    assert result.status == EventStatus.REPORTING
    assert result.disposition_policy == "required"

    fp_adj_wm = working_memory.for_writer("PostEvidenceFpAdjudicator")
    adjudication = await fp_adj_wm.read(event_id, "fp_adjudication")
    assert isinstance(adjudication, dict)
    assert adjudication.get("recommendation") == "close_as_fp"
    assert adjudication.get("supporting_evidence_ids")
    assert float(adjudication.get("max_score") or 0.0) >= 0.88
    assert "baseline_window_match" in (adjudication.get("matched_conditions") or [])

    async with session_factory() as session:
        async with session.begin():
            db_row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert db_row is not None
            db_row.status = EventStatus.TRIAGING.value

    async def _ready(_event_id: str) -> WritebackReadiness:
        return WritebackReadiness.READY

    runtime = WorkflowRuntimeService(
        session_factory,
        event_service=event_service,
        readiness_resolver=_ready,
    )
    await runtime.begin_disposition_only(event_id)

    async with session_factory() as session:
        db_row = await session.get(orm.SecurityEvent, event_id)
        assert db_row is not None
        assert float(db_row.confidence or 0.0) >= 0.88
        assert db_row.final_verdict == FinalVerdict.FALSE_POSITIVE.value
        deferred_row = await session.scalar(
            select(orm.Action).where(
                orm.Action.event_id == event_id,
                orm.Action.execution_phase == ActionExecutionPhase.POST_VERIFY.value,
                orm.Action.tool_name == "update_source_event_disposition",
            )
        )
        assert deferred_row is not None
        assert deferred_row.status == ActionStatus.APPROVED.value
        assert deferred_row.approved_terminal_dispositions == [SourceDisposition.IGNORED.value]
        intent = await session.scalar(
            select(orm.EventContextJournal).where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "disposition_only_intent",
            )
        )
        assert intent is not None
        assert _journal_scalar(intent.value) is True
