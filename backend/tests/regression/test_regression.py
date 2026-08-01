"""Regression golden-path integration tests (ISSUE-087)."""

from __future__ import annotations

import warnings

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.services.context_service import EventContextStore
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService
from tests.regression.helpers import ingest_and_run_golden_chain
from tests.regression.scenarios import DEMO_SCENARIOS, REGRESSION_SCENARIOS
from tests.regression.snapshot import (
    SnapshotDiffer,
    SnapshotRecorder,
    baseline_path,
    format_drifts,
    load_baseline,
)

pytestmark = [pytest.mark.regression, pytest.mark.integration]


@pytest.mark.usefixtures("clean_state")
@pytest.mark.parametrize("scenario_id", REGRESSION_SCENARIOS)
@pytest.mark.asyncio
async def test_regression_scenario_matches_baseline(
    scenario_id: str,
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    state_machine_service: StateMachineService,
) -> None:
    baseline = load_baseline(scenario_id)
    if baseline is None:
        pytest.skip(
            f"missing baseline for {scenario_id!r}; run `make update-baseline` first "
            f"(expected {baseline_path(scenario_id)})"
        )

    event_id = await ingest_and_run_golden_chain(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
        run_graph_investigation=run_graph_investigation,
        context_store=context_store,
        event_disposition_service=event_disposition_service,
        disposition_sync_service=disposition_sync_service,
        state_machine_service=state_machine_service,
    )

    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    current = await recorder.record(event_id, scenario_id)
    drifts = SnapshotDiffer().diff(baseline, current)
    blocking = SnapshotDiffer.blocking_drifts(drifts)
    warns = SnapshotDiffer.warn_drifts(drifts)
    if warns:
        warnings.warn(
            "regression warn drift detected:\n" + format_drifts(warns),
            UserWarning,
            stacklevel=1,
        )
    assert not blocking, format_drifts(blocking)


def test_demo_scenarios_are_subset_of_regression_registry() -> None:
    assert set(DEMO_SCENARIOS).issubset(set(REGRESSION_SCENARIOS))


def test_missing_baseline_skip_message_template() -> None:
    scenario_id = "__missing_scenario__"
    assert load_baseline(scenario_id) is None
    path = baseline_path(scenario_id)
    message = (
        f"missing baseline for {scenario_id!r}; run `make update-baseline` first (expected {path})"
    )
    assert "make update-baseline" in message
    assert str(path) in message


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_regression_detects_verdict_drift(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
) -> None:
    scenario_id = "account_anomaly_fp"
    baseline = load_baseline(scenario_id)
    assert baseline is not None

    event_id = await ingest_and_run_golden_chain(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
        run_graph_investigation=run_graph_investigation,
    )
    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    current = await recorder.record(event_id, scenario_id)
    # Force a deliberate mismatch against the ISSUE-099/114 baseline verdict.
    current["final_verdict"] = "false_positive"

    drifts = SnapshotDiffer().diff(baseline, current)
    blocking = SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "final_verdict" for item in blocking)
    assert format_drifts(blocking)


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_regression_detects_risk_score_drift(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
) -> None:
    scenario_id = "account_anomaly_fp"
    baseline = load_baseline(scenario_id)
    assert baseline is not None

    event_id = await ingest_and_run_golden_chain(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
        run_graph_investigation=run_graph_investigation,
    )
    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    current = await recorder.record(event_id, scenario_id)
    current["risk_score"] = int(baseline["risk_score"]) + 10

    drifts = SnapshotDiffer().diff(baseline, current)
    blocking = SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "risk_score" for item in blocking)
    assert format_drifts(blocking)


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_regression_detects_executed_actions_drift(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    state_machine_service: StateMachineService,
) -> None:
    scenario_id = "insider_data_exfiltration"
    baseline = load_baseline(scenario_id)
    assert baseline is not None
    assert baseline["executed_actions"], "baseline must include response actions"

    event_id = await ingest_and_run_golden_chain(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
        run_graph_investigation=run_graph_investigation,
        context_store=context_store,
        event_disposition_service=event_disposition_service,
        disposition_sync_service=disposition_sync_service,
        state_machine_service=state_machine_service,
    )
    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    current = await recorder.record(event_id, scenario_id)
    current["executed_actions"] = ["create_ticket"]

    drifts = SnapshotDiffer().diff(baseline, current)
    blocking = SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "executed_actions" for item in blocking)
    assert format_drifts(blocking)


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_regression_detects_dispositions_drift(
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    state_machine_service: StateMachineService,
) -> None:
    scenario_id = "insider_data_exfiltration"
    baseline = load_baseline(scenario_id)
    assert baseline is not None
    assert baseline["dispositions"], "baseline must include disposition rows"

    event_id = await ingest_and_run_golden_chain(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
        run_graph_investigation=run_graph_investigation,
        context_store=context_store,
        event_disposition_service=event_disposition_service,
        disposition_sync_service=disposition_sync_service,
        state_machine_service=state_machine_service,
    )
    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    current = await recorder.record(event_id, scenario_id)
    current["dispositions"] = [
        {
            "operation": "set_event_disposition",
            "execution_owner": "xdr_managed",
            "writeback_status": "failed",
        }
    ]

    drifts = SnapshotDiffer().diff(baseline, current)
    blocking = SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "dispositions" for item in blocking)
    assert format_drifts(blocking)


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_regression_fails_when_agent_verdict_changes(
    monkeypatch: pytest.MonkeyPatch,
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
) -> None:
    from app.agents.verdict_resolver import VerdictResolver
    from app.models.enums import FinalVerdict

    def _force_false_positive(
        self: VerdictResolver,
        *args: object,
        **kwargs: object,
    ) -> FinalVerdict:
        del self, args, kwargs
        return FinalVerdict.FALSE_POSITIVE

    monkeypatch.setattr(VerdictResolver, "resolve", _force_false_positive)

    scenario_id = "account_anomaly_fp"
    baseline = load_baseline(scenario_id)
    assert baseline is not None
    # ISSUE-099/114 golden path: source enrichment + advisory FP → confirmed_threat.
    assert baseline["final_verdict"] == "confirmed_threat"

    event_id = await ingest_and_run_golden_chain(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
        run_graph_investigation=run_graph_investigation,
    )
    recorder = SnapshotRecorder(session_factory, context_store=context_store)
    current = await recorder.record(event_id, scenario_id)
    assert current["final_verdict"] != baseline["final_verdict"]

    drifts = SnapshotDiffer().diff(baseline, current)
    blocking = SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "final_verdict" for item in blocking)
    assert format_drifts(blocking)
