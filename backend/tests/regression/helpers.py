"""Shared helpers for ISSUE-087 regression tests.

Regression scope (Mock-only):
- Ingest scenario telemetry, then run SuperAgent analysis under deterministic
  MockLLM golden responses (``run_graph_investigation`` default client). This is
  the repo's practical equivalent of the Issue's ``MOCK_DETERMINISTIC=1`` intent
  (that env var is not defined; determinism comes from MockLLMClient + golden).
- For ``FULL_RESPONSE_SCENARIOS`` (from ``tests.system.scenario_expectations``),
  also run the ISSUE-086 L3 approval response chain so ``executed_actions`` /
  ``dispositions`` baselines are non-empty.
- Snapshots capture verdict, risk, trajectory metrics, quality scores, and any
  response actions/dispositions present after these chains.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.redis_client import RedisClient
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.services.context_service import EventContextStore
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService
from tests.test_support.db_isolation import (
    clear_shadowtrace_redis_keys,
    truncate_business_tables,
)
from tests.system.helpers import (
    ingest_scenario_event,
    run_l3_approval_response_chain,
)
from tests.system.scenario_expectations import (
    FULL_RESPONSE_SCENARIOS,
    L3_APPROVAL_RESPONSE_SCENARIOS,
)


async def reset_regression_state(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> None:
    """Clear business tables and Redis keys between baseline refresh scenarios."""
    await truncate_business_tables(session_factory)
    await clear_shadowtrace_redis_keys(redis_client)


async def run_golden_main_chain(
    *,
    event_id: str,
    run_graph_investigation: Any,
    scenario_id: str,
    llm_client: Any | None = None,
) -> None:
    """Run the deterministic MockLLM golden investigation path (not rule-fallback)."""
    await run_graph_investigation(
        event_id,
        scenario_id=scenario_id,
        llm_client=llm_client,
    )


async def run_regression_response_chain_if_applicable(
    *,
    scenario_id: str,
    event_id: str,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    state_machine_service: StateMachineService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Run ISSUE-086 response chain for high-risk scenarios that require writeback."""
    if scenario_id not in FULL_RESPONSE_SCENARIOS:
        return

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


async def ingest_and_run_golden_chain(
    *,
    scenario_id: str,
    source_adapter: object,
    source_ingester: SourceIngester,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
    session_factory: async_sessionmaker[AsyncSession],
    run_graph_investigation: Any,
    context_store: EventContextStore | None = None,
    event_disposition_service: EventDispositionService | None = None,
    disposition_sync_service: DispositionSyncService | None = None,
    state_machine_service: StateMachineService | None = None,
    llm_client: Any | None = None,
) -> str:
    event_id = await ingest_scenario_event(
        scenario_id=scenario_id,
        source_adapter=source_adapter,
        source_ingester=source_ingester,
        event_service=event_service,
        mock_xdr_state=mock_xdr_state,
        session_factory=session_factory,
    )
    await run_golden_main_chain(
        event_id=event_id,
        run_graph_investigation=run_graph_investigation,
        scenario_id=scenario_id,
        llm_client=llm_client,
    )
    if (
        scenario_id in FULL_RESPONSE_SCENARIOS
        and context_store is not None
        and event_disposition_service is not None
        and disposition_sync_service is not None
        and state_machine_service is not None
    ):
        await run_regression_response_chain_if_applicable(
            scenario_id=scenario_id,
            event_id=event_id,
            session_factory=session_factory,
            context_store=context_store,
            event_service=event_service,
            event_disposition_service=event_disposition_service,
            disposition_sync_service=disposition_sync_service,
            state_machine_service=state_machine_service,
            mock_xdr_state=mock_xdr_state,
        )
    return event_id
