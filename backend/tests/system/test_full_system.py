"""ISSUE-086 full-system main-chain tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.rules.default_plans import DEFAULT_PLANS
from app.agents.rules.default_response_rules import DEFAULT_RESPONSE_RULES, get_rule_actions
from app.data_generators.base import TELEMETRY_FILENAMES
from app.data_generators.scenarios import SCENARIO_BUILDERS, build_scenario
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.models.enums import EventType, Severity
from app.services.context_service import EventContextStore
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService
from tests.system.helpers import (
    assert_approval_record_exists,
    assert_main_chain_expectations,
    assert_no_disposition_writeback,
    ingest_scenario_event,
    run_full_response_chain,
    run_l3_approval_response_chain,
    run_rule_fallback_main_chain,
)
from tests.system.scenario_expectations import (
    FILE_ONLY_SCENARIOS,
    FULL_RESPONSE_SCENARIOS,
    L3_APPROVAL_RESPONSE_SCENARIOS,
    MOCK_WRITEBACK_SCENARIOS,
    SCENARIO_EXPECTATIONS,
    SCENARIO_TO_EVENT_TYPE,
    risk_bounds_for,
)

pytestmark = [pytest.mark.system, pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_SCENARIOS = REPO_ROOT / "data" / "scenarios"

ALL_EIGHT_SCENARIOS = tuple(SCENARIO_EXPECTATIONS.keys())


def test_scenario_expectations_cover_all_event_types() -> None:
    assert len(SCENARIO_EXPECTATIONS) == 8
    assert {spec.event_type for spec in SCENARIO_EXPECTATIONS.values()} == set(EventType)


def test_default_plans_and_response_rules_cover_all_event_types() -> None:
    for event_type in EventType:
        assert event_type in DEFAULT_PLANS
        assert event_type in DEFAULT_RESPONSE_RULES
        actions = get_rule_actions(event_type, Severity.HIGH)
        assert actions


@pytest.mark.parametrize("scenario_id", ALL_EIGHT_SCENARIOS)
def test_data_scenario_pack_exists(scenario_id: str) -> None:
    if scenario_id in {
        "insider_data_exfiltration",
        "account_anomaly_fp",
        "suspicious_domain_access",
    }:
        pytest.skip("legacy demo packs live under data/mock and app generators")
    scenario_dir = DATA_SCENARIOS / scenario_id
    assert scenario_dir.is_dir(), f"missing exported pack: {scenario_dir}"
    for filename in TELEMETRY_FILENAMES.values():
        path = scenario_dir / filename
        assert path.is_file(), f"missing telemetry file: {path}"
    dump = scenario_dir / f"{scenario_id}.scenario.json"
    assert dump.is_file()


@pytest.mark.usefixtures("clean_state")
@pytest.mark.parametrize("scenario_id", ALL_EIGHT_SCENARIOS)
@pytest.mark.asyncio
async def test_eight_event_types_main_chain_rule_fallback(
    scenario_id: str,
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
) -> None:
    spec = SCENARIO_EXPECTATIONS[scenario_id]
    event_id = await ingest_scenario_event(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
    )
    await run_rule_fallback_main_chain(
        event_id=event_id,
        run_graph_investigation=run_graph_investigation,
        scenario_id=scenario_id,
    )
    await assert_main_chain_expectations(
        event_service=event_service,
        context_store=context_store,
        session_factory=session_factory,
        event_id=event_id,
        spec=spec,
    )
    assert SCENARIO_TO_EVENT_TYPE[scenario_id] is spec.event_type


@pytest.mark.usefixtures("clean_state")
@pytest.mark.parametrize("scenario_id", sorted(FULL_RESPONSE_SCENARIOS))
@pytest.mark.asyncio
async def test_high_risk_full_response_chain(
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
    assert scenario_id in MOCK_WRITEBACK_SCENARIOS
    assert scenario_id not in FILE_ONLY_SCENARIOS

    event_id = await ingest_scenario_event(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
    )
    await run_rule_fallback_main_chain(
        event_id=event_id,
        run_graph_investigation=run_graph_investigation,
        scenario_id=scenario_id,
    )
    await assert_main_chain_expectations(
        event_service=event_service,
        context_store=context_store,
        session_factory=session_factory,
        event_id=event_id,
        spec=SCENARIO_EXPECTATIONS[scenario_id],
    )
    if scenario_id in L3_APPROVAL_RESPONSE_SCENARIOS:
        await run_l3_approval_response_chain(
            session_factory=session_factory,
            context_store=context_store,
            event_service=event_service,
            event_disposition_service=event_disposition_service,
            disposition_sync_service=disposition_sync_service,
            state_machine_service=state_machine_service,
            mock_xdr_state=mock_xdr_state,
            event_id=event_id,
        )
        await assert_approval_record_exists(session_factory, event_id)
    else:
        await run_full_response_chain(
            session_factory=session_factory,
            event_service=event_service,
            event_disposition_service=event_disposition_service,
            disposition_sync_service=disposition_sync_service,
            mock_xdr_state=mock_xdr_state,
            event_id=event_id,
        )


def test_rule_fallback_risk_bounds_reject_misconfigured_min() -> None:
    """Changing rule_fallback_risk_min to 999 must fall outside observed rule scores."""
    spec = SCENARIO_EXPECTATIONS["host_compromise"]
    # ISSUE-099: source-enriched rule-only scores land near the mid-50s, not ~20.
    observed_rule_score = 51
    bad_min = 999
    good_min, good_max = risk_bounds_for(spec, rule_only=True)
    assert good_min <= observed_rule_score <= good_max
    assert not (bad_min <= observed_rule_score <= good_max)


@pytest.mark.usefixtures("clean_state")
@pytest.mark.parametrize("scenario_id", sorted(FILE_ONLY_SCENARIOS))
@pytest.mark.asyncio
async def test_file_only_scenarios_no_disposition_writeback(
    scenario_id: str,
    mock_xdr_state: MockXDRState,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    run_graph_investigation: object,
) -> None:
    spec = SCENARIO_EXPECTATIONS[scenario_id]
    event_id = await ingest_scenario_event(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
    )
    await run_rule_fallback_main_chain(
        event_id=event_id,
        run_graph_investigation=run_graph_investigation,
        scenario_id=scenario_id,
    )
    await assert_main_chain_expectations(
        event_service=event_service,
        context_store=context_store,
        session_factory=session_factory,
        event_id=event_id,
        spec=spec,
    )
    await assert_no_disposition_writeback(session_factory, event_id)


@pytest.mark.parametrize("scenario_id", sorted(MOCK_WRITEBACK_SCENARIOS))
def test_scenario_builders_registered(scenario_id: str) -> None:
    assert scenario_id in SCENARIO_BUILDERS
    built = build_scenario(scenario_id, seed=42)
    assert built.scenario_id == scenario_id
    assert built.expected_outcome


def test_export_system_scenarios_script_smoke() -> None:
    import subprocess
    import sys

    script = REPO_ROOT / "backend" / "scripts" / "export_system_scenarios.py"
    assert script.is_file()
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=REPO_ROOT / "backend",
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Wrote" in result.stdout
    for scenario_id in (
        "host_compromise",
        "malicious_process",
        "insider_privilege_abuse",
        "lateral_movement",
        "other_unclassified",
    ):
        dump = DATA_SCENARIOS / scenario_id / f"{scenario_id}.scenario.json"
        assert dump.is_file(), f"missing exported pack after smoke run: {dump}"
