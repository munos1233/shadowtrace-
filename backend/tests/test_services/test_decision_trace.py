"""DecisionTraceService persistence and ordering tests (ISSUE-063).

Verifies the 8-source aggregation, timestamp ordering, summary computation,
and graceful handling of empty events.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.models.decision_trace import DecisionTrace
from app.models.enums import DecisionTraceEntryType
from app.services.decision_trace_service import (
    _ENTRY_TYPE_ORDER,
    DecisionTraceService,
)

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="module")
def migrated_database() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            # Clean in FK-safe order: children first
            await session.execute(delete(orm.DispositionReceipt))
            await session.execute(delete(orm.DispositionOutbox))
            await session.execute(delete(orm.ActionExecutionJob))
            await session.execute(delete(orm.ToolCallLog))
            await session.execute(delete(orm.LLMCallLog))
            await session.execute(delete(orm.EventAuditLog))
            await session.execute(delete(orm.DecisionRecord))
            await session.execute(delete(orm.AgentTrace))
            await session.execute(delete(ApprovalRecordORM))
            await session.execute(delete(orm.Action))
            await session.execute(delete(orm.Report))
            await session.execute(delete(orm.Evidence))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.SourceConnector))
            await session.execute(delete(orm.SecurityEvent))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.DispositionReceipt))
            await session.execute(delete(orm.DispositionOutbox))
            await session.execute(delete(orm.ActionExecutionJob))
            await session.execute(delete(orm.ToolCallLog))
            await session.execute(delete(orm.LLMCallLog))
            await session.execute(delete(orm.EventAuditLog))
            await session.execute(delete(orm.DecisionRecord))
            await session.execute(delete(orm.AgentTrace))
            await session.execute(delete(ApprovalRecordORM))
            await session.execute(delete(orm.Action))
            await session.execute(delete(orm.Report))
            await session.execute(delete(orm.Evidence))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.SourceConnector))
            await session.execute(delete(orm.SecurityEvent))


@pytest.fixture
def service(
    session_factory: async_sessionmaker[AsyncSession],
) -> DecisionTraceService:
    return DecisionTraceService(session_factory)


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# --------------------------------------------------------------------------- #
# Seed helpers
# --------------------------------------------------------------------------- #

_SEED_NOW = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)


async def _seed_security_event(
    session: AsyncSession,
    event_id: str,
    *,
    approval_records: list[dict[str, object]] | None = None,
) -> None:
    row = orm.SecurityEvent(
        event_id=event_id,
        event_type="alert",
        title=f"Test Event {event_id}",
        description="Seeded for ISSUE-063 tests",
        status="analyzing",
        severity="high",
        risk_score=85,
        confidence=0.9,
        creation_source_ref={"source": "test", "source_record_id": "src-1"},
        event_context_snapshot=(
            {"approval_records": approval_records} if approval_records else None
        ),
    )
    session.add(row)
    await session.flush()


async def _seed_source_connector(
    session: AsyncSession,
    connector_id: str = "conn-test-1",
) -> str:
    row = orm.SourceConnector(
        connector_id=connector_id,
        source_product="mock_xdr",
        display_name="Test Connector",
        status="active",
        capabilities={},
        disposition_policy_default="not_required",
        schema_version="1",
    )
    session.add(row)
    await session.flush()
    return connector_id


async def _seed_source_object(
    session: AsyncSession,
    source_record_id: str = "src-1",
    connector_id: str = "conn-test-1",
) -> str:
    row = orm.SourceObject(
        source_record_id=source_record_id,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id=connector_id,
        source_kind="incident",
        source_object_id="INC-1001",
    )
    session.add(row)
    await session.flush()
    return source_record_id


async def _seed_agent_trace(
    session: AsyncSession,
    event_id: str,
    agent_name: str = "TriageAgent",
    status: str = "completed",
    started_at: datetime = _SEED_NOW,
    duration_ms: int = 1200,
    llm_tokens_used: int = 450,
    output_data: dict[str, object] | None = None,
) -> str:
    trace_id = _id("trc")
    row = orm.AgentTrace(
        trace_id=trace_id,
        event_id=event_id,
        agent_name=agent_name,
        status=status,
        started_at=started_at,
        completed_at=started_at + timedelta(milliseconds=duration_ms),
        duration_ms=duration_ms,
        llm_model="gpt-4o",
        llm_tokens_used=llm_tokens_used,
        output_data=output_data or {},
    )
    session.add(row)
    return trace_id


async def _seed_tool_call(
    session: AsyncSession,
    event_id: str,
    tool_name: str = "query_asset_info",
    started_at: datetime = _SEED_NOW + timedelta(seconds=1),
) -> str:
    call_id = _id("call")
    row = orm.ToolCallLog(
        call_id=call_id,
        event_id=event_id,
        tool_name=tool_name,
        tool_category="query",
        status="success",
        started_at=started_at,
        completed_at=started_at + timedelta(milliseconds=300),
        duration_ms=300,
    )
    session.add(row)
    return call_id


async def _seed_llm_call(
    session: AsyncSession,
    event_id: str,
    agent_name: str = "TriageAgent",
    created_at: datetime = _SEED_NOW + timedelta(seconds=2),
) -> int:
    row = orm.LLMCallLog(
        event_id=event_id,
        agent_name=agent_name,
        prompt_key="triage_prompt",
        model_name="gpt-4o",
        prompt_tokens=500,
        completion_tokens=200,
        total_tokens=700,
        latency_ms=800,
        status="success",
        created_at=created_at,
    )
    session.add(row)
    await session.flush()
    return row.id


async def _seed_audit_log(
    session: AsyncSession,
    event_id: str,
    from_status: str = "triaging",
    to_status: str = "analyzing",
    created_at: datetime = _SEED_NOW + timedelta(seconds=3),
) -> int:
    row = orm.EventAuditLog(
        event_id=event_id,
        from_status=from_status,
        to_status=to_status,
        operator="system",
        reason="test transition",
        created_at=created_at,
    )
    session.add(row)
    await session.flush()
    return row.id


async def _seed_action(
    session: AsyncSession,
    event_id: str,
    action_id: str | None = None,
) -> str:
    aid = action_id or _id("act")
    row = orm.Action(
        action_id=aid,
        event_id=event_id,
        plan_revision=1,
        action_fingerprint=f"fp-{aid}",
        action_category="response",
        action_name="block_ip",
        tool_name="block_ip",
        action_level="L3",
        execution_phase="immediate",
        status="success",
    )
    session.add(row)
    return aid


async def _seed_approval_record(
    session: AsyncSession,
    event_id: str,
    action_id: str,
    *,
    decision: str = "approved",
    operator: str = "analyst-1",
    comment: str = "valid threat",
    requested_at: datetime = _SEED_NOW + timedelta(seconds=6),
    decided_at: datetime | None = None,
    plan_revision: int = 1,
) -> str:
    approval_id = _id("appr")
    decision_id = _id("dec")
    row = ApprovalRecordORM(
        approval_id=approval_id,
        action_id=action_id,
        event_id=event_id,
        plan_revision=plan_revision,
        approval_cycle=0,
        decision_id=decision_id,
        required_level="L4",
        decision=decision,
        operator=operator,
        comment=comment,
        requested_at=requested_at,
        decided_at=decided_at if decided_at is not None else requested_at,
    )
    session.add(row)
    return decision_id


async def _seed_action_job(
    session: AsyncSession,
    event_id: str,
    action_id: str,
    created_at: datetime = _SEED_NOW + timedelta(seconds=7),
) -> str:
    job_id = _id("job")
    row = orm.ActionExecutionJob(
        job_id=job_id,
        event_id=event_id,
        action_id=action_id,
        provider_name="mock_xdr",
        idempotency_key=f"idem-{job_id}",
        status="success",
        created_at=created_at,
    )
    session.add(row)
    return job_id


async def _seed_disposition_outbox(
    session: AsyncSession,
    event_id: str,
    action_id: str,
    intent_kind: str = "entity_action_submit",
    created_at: datetime = _SEED_NOW + timedelta(seconds=8),
) -> tuple[str, str]:
    outbox_id = _id("obx")
    disposition_id = _id("disp")
    writeback_id = _id("wb")
    row = orm.DispositionOutbox(
        outbox_id=outbox_id,
        writeback_id=writeback_id,
        disposition_id=disposition_id,
        action_id=action_id,
        event_id=event_id,
        closure_cycle=1,
        source_record_id="src-1",
        source_locator_hash="hash-1",
        source_sequence=1,
        intent_kind=intent_kind,
        logical_slot="slot-1",
        idempotency_key=f"idem-{outbox_id}",
        command_payload={"op": "block_ip"},
        command_payload_sha256="sha256-1",
        delivery_status="delivered",
        created_at=created_at,
    )
    session.add(row)
    return outbox_id, disposition_id


async def _seed_writeback_receipt(
    session: AsyncSession,
    writeback_id: str,
    disposition_id: str,
    action_id: str,
    source_record_id: str = "src-1",
    confirmed_at: datetime = _SEED_NOW + timedelta(seconds=9),
) -> None:
    row = orm.DispositionReceipt(
        writeback_id=writeback_id,
        sequence=1,
        disposition_id=disposition_id,
        action_id=action_id,
        source_record_id=source_record_id,
        status="confirmed",
        confirmation_evidence="readback_verified",
        simulated=True,
        confirmed_at=confirmed_at,
    )
    session.add(row)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


class TestDecisionTraceFullTimeline:
    """Tests with all 8 source types seeded."""

    @pytest.mark.asyncio
    async def test_all_eight_entry_types_present_and_ordered(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_source_connector(session)
                await _seed_source_object(session)
                await _seed_agent_trace(session, event_id)  # ~0s
                await _seed_tool_call(session, event_id)  # ~1s
                await _seed_llm_call(session, event_id)  # ~2s
                await _seed_audit_log(session, event_id)  # ~3s
                await _seed_audit_log(
                    session,
                    event_id,
                    "analyzing",
                    "scoring",
                    _SEED_NOW + timedelta(seconds=4),
                )  # ~4s
                action_id = await _seed_action(session, event_id)
                await _seed_approval_record(
                    session,
                    event_id,
                    action_id,
                    operator="analyst-1",
                    comment="valid threat",
                    requested_at=_SEED_NOW + timedelta(seconds=6),
                )  # ~6s
                await _seed_action_job(session, event_id, action_id)  # ~7s
                outbox_id, disposition_id = await _seed_disposition_outbox(
                    session, event_id, action_id
                )  # ~8s
                await _seed_writeback_receipt(
                    session, "wb-receipt-1", disposition_id, action_id
                )  # ~9s

        trace = await service.get_decision_trace(event_id)

        # 1 agent + 1 tool + 1 LLM + 2 audit + 1 approval + 1 job + 1 disposition + 1 receipt = 9
        assert len(trace.entries) == 9
        assert trace.missing_sources == []

        entry_types = [e.entry_type for e in trace.entries]
        assert entry_types == [
            DecisionTraceEntryType.AGENT_EXECUTION,
            DecisionTraceEntryType.TOOL_CALL,
            DecisionTraceEntryType.LLM_CALL,
            DecisionTraceEntryType.STATE_TRANSITION,
            DecisionTraceEntryType.STATE_TRANSITION,
            DecisionTraceEntryType.APPROVAL,
            DecisionTraceEntryType.ACTION_EXECUTION,
            DecisionTraceEntryType.DISPOSITION,
            DecisionTraceEntryType.WRITEBACK,
        ]

    @pytest.mark.asyncio
    async def test_entries_sorted_by_timestamp_ascending(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                # Create entries with deliberately out-of-order insertion
                await _seed_llm_call(
                    session, event_id, created_at=_SEED_NOW + timedelta(seconds=10)
                )
                await _seed_agent_trace(
                    session, event_id, started_at=_SEED_NOW + timedelta(seconds=1)
                )
                await _seed_audit_log(
                    session,
                    event_id,
                    created_at=_SEED_NOW + timedelta(seconds=20),
                )

        trace = await service.get_decision_trace(event_id)
        timestamps = [e.timestamp for e in trace.entries]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_same_timestamp_ordered_by_entry_type_priority(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")
        shared_ts = _SEED_NOW + timedelta(seconds=5)

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                # Seed multiple entry types at the same timestamp
                action_id = await _seed_action(session, event_id)
                await _seed_agent_trace(session, event_id, started_at=shared_ts)
                await _seed_tool_call(session, event_id, started_at=shared_ts)
                await _seed_audit_log(
                    session,
                    event_id,
                    from_status="scoring",
                    to_status="planning_response",
                    created_at=shared_ts,
                )
                await _seed_action_job(session, event_id, action_id, created_at=shared_ts)

        trace = await service.get_decision_trace(event_id)
        shared_entries = [e for e in trace.entries if e.timestamp == shared_ts]
        type_order = [e.entry_type for e in shared_entries]

        # Verify relative order follows _ENTRY_TYPE_ORDER priority
        for i in range(len(type_order) - 1):
            assert _ENTRY_TYPE_ORDER[type_order[i]] <= _ENTRY_TYPE_ORDER[type_order[i + 1]]

    @pytest.mark.asyncio
    async def test_summary_counts_match_entry_counts(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_source_connector(session)
                await _seed_source_object(session)
                await _seed_agent_trace(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    agent_name="RiskAgent",
                    started_at=_SEED_NOW + timedelta(seconds=1),
                )
                await _seed_tool_call(session, event_id)
                await _seed_tool_call(
                    session,
                    event_id,
                    tool_name="query_domain",
                    started_at=_SEED_NOW + timedelta(seconds=2),
                )
                await _seed_tool_call(
                    session,
                    event_id,
                    tool_name="query_process",
                    started_at=_SEED_NOW + timedelta(seconds=3),
                )
                await _seed_llm_call(session, event_id)
                await _seed_llm_call(
                    session,
                    event_id,
                    agent_name="RiskAgent",
                    created_at=_SEED_NOW + timedelta(seconds=4),
                )
                await _seed_audit_log(session, event_id)
                action_id = await _seed_action(session, event_id)
                await _seed_approval_record(
                    session,
                    event_id,
                    action_id,
                    operator="admin",
                    comment="approved",
                    requested_at=_SEED_NOW,
                )
                await _seed_action_job(session, event_id, action_id)
                await _seed_disposition_outbox(session, event_id, action_id)

        trace = await service.get_decision_trace(event_id)
        s = trace.summary

        assert s.agent_count == 2
        assert s.tool_call_count == 3
        assert s.llm_call_count == 2
        assert s.state_transition_count == 1
        assert s.approval_count == 1
        assert s.action_execution_count == 1
        assert s.disposition_count == 1
        # No writeback receipt seeded => 0
        assert s.writeback_count == 0
        # 2 LLM calls with 700 tokens each = 1400
        assert s.total_tokens == 1400
        # Duration should span from first to last entry
        assert s.total_duration_ms is not None
        assert s.total_duration_ms > 0


class TestDecisionTraceEmptyAndMissing:
    """Tests for empty events and missing data sources."""

    @pytest.mark.asyncio
    async def test_empty_event_returns_empty_trace(self, service: DecisionTraceService) -> None:
        trace = await service.get_decision_trace("evt-nonexistent")
        assert isinstance(trace, DecisionTrace)
        assert trace.event_id == "evt-nonexistent"
        assert trace.entries == []
        assert trace.summary.agent_count == 0
        assert trace.summary.tool_call_count == 0

    @pytest.mark.asyncio
    async def test_entries_have_expected_detail_fields(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(session, event_id, agent_name="TriageAgent")
                await _seed_tool_call(session, event_id, tool_name="query_asset_info")
                await _seed_llm_call(session, event_id)

        trace = await service.get_decision_trace(event_id)

        agent_e = next(
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        )
        assert agent_e.detail["agent_name"] == "TriageAgent"
        assert agent_e.detail["status"] == "completed"
        assert agent_e.detail["duration_ms"] == 1200
        assert agent_e.ref_id is not None

        tool_e = next(e for e in trace.entries if e.entry_type == DecisionTraceEntryType.TOOL_CALL)
        assert tool_e.detail["tool_name"] == "query_asset_info"
        assert tool_e.detail["tool_category"] == "query"
        assert tool_e.ref_id is not None

        llm_e = next(e for e in trace.entries if e.entry_type == DecisionTraceEntryType.LLM_CALL)
        assert llm_e.detail["total_tokens"] == 700
        assert llm_e.detail["model_name"] == "gpt-4o"

    @pytest.mark.asyncio
    async def test_total_duration_covers_full_span(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(session, event_id, started_at=_SEED_NOW)
                # Last entry 30 seconds later
                await _seed_audit_log(
                    session,
                    event_id,
                    created_at=_SEED_NOW + timedelta(seconds=30),
                )

        trace = await service.get_decision_trace(event_id)
        assert trace.summary.total_duration_ms is not None
        assert 29_000 <= trace.summary.total_duration_ms <= 31_000


class TestDecisionTraceService:
    """Unit-level tests for internal helpers."""

    def test_sort_key_entry_type_ordering(self) -> None:
        """Verify _ENTRY_TYPE_ORDER covers all 8 types."""
        expected = {
            DecisionTraceEntryType.AGENT_EXECUTION,
            DecisionTraceEntryType.TOOL_CALL,
            DecisionTraceEntryType.LLM_CALL,
            DecisionTraceEntryType.STATE_TRANSITION,
            DecisionTraceEntryType.APPROVAL,
            DecisionTraceEntryType.ACTION_EXECUTION,
            DecisionTraceEntryType.DISPOSITION,
            DecisionTraceEntryType.WRITEBACK,
        }
        assert set(_ENTRY_TYPE_ORDER.keys()) == expected
        # All values are distinct and in [0, 7]
        assert sorted(_ENTRY_TYPE_ORDER.values()) == list(range(8))

    def test_entry_type_order_values_match_spec(self) -> None:
        """Verify the fixed ordering: agent → tool → llm → state → approval
        → action → disposition → writeback."""
        order = _ENTRY_TYPE_ORDER
        assert order[DecisionTraceEntryType.AGENT_EXECUTION] == 0
        assert order[DecisionTraceEntryType.TOOL_CALL] == 1
        assert order[DecisionTraceEntryType.LLM_CALL] == 2
        assert order[DecisionTraceEntryType.STATE_TRANSITION] == 3
        assert order[DecisionTraceEntryType.APPROVAL] == 4
        assert order[DecisionTraceEntryType.ACTION_EXECUTION] == 5
        assert order[DecisionTraceEntryType.DISPOSITION] == 6
        assert order[DecisionTraceEntryType.WRITEBACK] == 7

    @pytest.mark.asyncio
    async def test_entry_id_format(self) -> None:
        from app.services.decision_trace_service import _new_entry_id

        eid = _new_entry_id()
        assert eid.startswith("dte-")
        assert len(eid) == 12  # "dte-" + 8 hex

    @pytest.mark.asyncio
    async def test_approval_records_from_approval_table_without_snapshot(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")
        decided_at = _SEED_NOW + timedelta(seconds=5)

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                action_id = await _seed_action(session, event_id)
                decision_id = await _seed_approval_record(
                    session,
                    event_id,
                    action_id,
                    operator="soc-analyst",
                    comment="confirmed threat",
                    requested_at=decided_at,
                    decided_at=decided_at,
                    plan_revision=2,
                )

        trace = await service.get_decision_trace(event_id)
        assert trace.summary.approval_count == 1

        approval_entries = [
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.APPROVAL
        ]
        assert len(approval_entries) == 1
        a = approval_entries[0]
        assert a.actor == "soc-analyst"
        assert a.detail["decision"] == "approved"
        assert a.detail["reason"] == "confirmed threat"
        assert a.detail["action_id"] == action_id
        assert a.ref_id == decision_id

    @pytest.mark.asyncio
    async def test_writeback_receipts_require_action_rows(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Writeback receipts are queried via Action FK; verify they appear
        only when the corresponding Action row exists."""
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_source_connector(session)
                await _seed_source_object(session)
                action_id = await _seed_action(session, event_id)
                # Create a disposition outbox entry
                _, disp_id = await _seed_disposition_outbox(
                    session, event_id, action_id, created_at=_SEED_NOW
                )
                # Create a writeback receipt linked to the action
                row = orm.DispositionReceipt(
                    writeback_id="wb-test-1",
                    sequence=1,
                    disposition_id=disp_id,
                    action_id=action_id,
                    source_record_id="src-1",
                    status="confirmed",
                    confirmation_evidence="verified",
                    simulated=False,
                    confirmed_at=_SEED_NOW + timedelta(seconds=1),
                )
                session.add(row)

        trace = await service.get_decision_trace(event_id)
        wb_entries = [e for e in trace.entries if e.entry_type == DecisionTraceEntryType.WRITEBACK]
        assert len(wb_entries) == 1
        assert wb_entries[0].ref_id == "wb-test-1"
        assert wb_entries[0].detail["status"] == "confirmed"


class TestDecisionTraceDegradationAndEdgeCases:
    @pytest.mark.asyncio
    async def test_pending_approval_summary_matches_entry_count(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")
        requested_at = _SEED_NOW + timedelta(seconds=2)

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                action_id = await _seed_action(session, event_id)
                await _seed_approval_record(
                    session,
                    event_id,
                    action_id,
                    decision="require_approval",
                    operator=None,
                    comment=None,
                    requested_at=requested_at,
                    decided_at=None,
                )

        trace = await service.get_decision_trace(event_id)
        approval_entries = [
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.APPROVAL
        ]
        assert len(approval_entries) == 1
        assert trace.summary.approval_count == 1
        assert approval_entries[0].timestamp == requested_at

    @pytest.mark.asyncio
    async def test_missing_source_agent_trace_failure(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_tool_call(session, event_id)

        async def _boom(_session: AsyncSession, _event_id: str) -> list[orm.AgentTrace]:
            raise RuntimeError("agent trace query failed")

        monkeypatch.setattr(service, "_fetch_agent_traces", _boom)

        trace = await service.get_decision_trace(event_id)
        assert "agent_trace" in trace.missing_sources
        assert any(e.entry_type == DecisionTraceEntryType.TOOL_CALL for e in trace.entries)

    @pytest.mark.asyncio
    async def test_agent_trace_without_timestamp_still_emits_entry(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                session.add(
                    orm.AgentTrace(
                        trace_id=_id("trc"),
                        event_id=event_id,
                        agent_name="TriageAgent",
                        status="running",
                        started_at=None,
                        completed_at=None,
                    )
                )

        trace = await service.get_decision_trace(event_id)
        agent_entries = [
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        ]
        assert len(agent_entries) == 1
        assert agent_entries[0].detail.get("timestamp_inferred") is True
        assert trace.summary.agent_count == 1

    @pytest.mark.asyncio
    async def test_agent_trace_includes_decision_basis_and_severity_title(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    output_data={
                        "severity": "high",
                        "event_type": "data_exfiltration",
                        "decision_summary": "critical exfiltration detected",
                        "_decision_basis": {
                            "structured_conclusion": "legacy CoT must not leak",
                            "confidence": 0.95,
                            "evidence_refs": ["evd-1"],
                        },
                    },
                )

        trace = await service.get_decision_trace(event_id)
        agent = next(
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        )
        assert agent.title == "TriageAgent 完成分诊：severity=high"
        assert agent.detail["severity"] == "high"
        assert agent.detail["structured_conclusion"] == "critical exfiltration detected"
        assert agent.detail["confidence"] == 0.95

    @pytest.mark.asyncio
    async def test_triage_agent_production_name_severity_title(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    agent_name="triage_agent",
                    output_data={
                        "severity": "high",
                        "event_type": "data_exfiltration",
                        "decision_summary": "critical exfiltration detected",
                    },
                )

        trace = await service.get_decision_trace(event_id)
        agent = next(
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        )
        assert agent.title == "triage_agent 完成分诊：severity=high"

    @pytest.mark.asyncio
    async def test_legacy_react_trace_decision_basis_does_not_leak_cot(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """ISSUE-131: legacy _decision_basis CoT must not surface in decision trace."""
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    agent_name="react_engine",
                    output_data={
                        "decision_summary": "bounded react summary",
                        "confidence": 0.72,
                        "_decision_basis": {
                            "structured_conclusion": "hidden chain-of-thought reasoning",
                            "input_summary": "legacy input",
                        },
                    },
                )

        trace = await service.get_decision_trace(event_id)
        agent = next(
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        )
        assert agent.detail["structured_conclusion"] == "bounded react summary"
        assert "hidden chain-of-thought" not in str(agent.detail)
        assert agent.detail.get("input_summary") == "legacy input"

    @pytest.mark.asyncio
    async def test_legacy_react_trace_exposes_not_retained_compat_keys(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """ISSUE-131: legacy CoT keys surface as [NOT_RETAINED] on read path."""
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    agent_name="react_engine",
                    output_data={
                        "decision_summary": "bounded react summary",
                        "thought": "hidden chain-of-thought",
                        "reflection": "also hidden",
                        "reasoning": "free text reasoning",
                    },
                )

        trace = await service.get_decision_trace(event_id)
        agent = next(
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        )
        assert agent.detail["thought"] == "[NOT_RETAINED]"
        assert agent.detail["reflection"] == "[NOT_RETAINED]"
        assert agent.detail["reasoning"] == "[NOT_RETAINED]"
        assert "hidden chain-of-thought" not in str(agent.detail)

    @pytest.mark.asyncio
    async def test_agent_execution_synthesizes_brief_when_decision_summary_missing(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """ISSUE-243: read path fills structured brief for typed agent outputs."""
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    agent_name="risk_agent",
                    output_data={
                        "risk_score": 72,
                        "severity": "high",
                        "scoring_mode": "heuristic",
                        "confidence": 0.8,
                    },
                )

        trace = await service.get_decision_trace(event_id)
        agent = next(
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        )
        assert "risk_score=72" in agent.detail["structured_conclusion"]
        assert agent.detail["brief"] == agent.detail["structured_conclusion"]
        assert "status=completed" not in agent.title
        assert "risk_score=72" in agent.title

    @pytest.mark.asyncio
    async def test_empty_agent_output_exposes_summary_unavailable(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    agent_name="memory_agent",
                    output_data={},
                )

        trace = await service.get_decision_trace(event_id)
        agent = next(
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        )
        assert agent.detail["summary_unavailable"] == "empty_output"
        assert "summary_unavailable=empty_output" in agent.title
        assert "status=completed" not in agent.title

    @pytest.mark.asyncio
    async def test_running_agent_title_uses_in_progress_wording(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(session, event_id, status="running")

        trace = await service.get_decision_trace(event_id)
        agent = next(
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        )
        assert "执行中分诊" in agent.title

    @pytest.mark.asyncio
    async def test_tool_call_detail_includes_records_count_from_evidence_trace(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """ISSUE-101: merge evidence_agent query_timings into tool_call detail."""
        event_id = _id("evt")

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    agent_name="evidence_agent",
                    output_data={
                        "query_timings": [
                            {
                                "tool_name": "query_dns",
                                "source": "dns",
                                "status": "success",
                                "execution_time_ms": 12,
                                "records_count": 0,
                                "gap_reason": "no_records",
                            }
                        ],
                        "gaps": [],
                        "collection_status": "degraded",
                    },
                )
                await _seed_tool_call(session, event_id, tool_name="query_dns")

        trace = await service.get_decision_trace(event_id)
        tool_e = next(e for e in trace.entries if e.entry_type == DecisionTraceEntryType.TOOL_CALL)
        assert tool_e.detail["records_count"] == 0
        assert tool_e.detail["gap_reason"] == "no_records"

        agent_e = next(
            e
            for e in trace.entries
            if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
            and e.detail.get("agent_name") == "evidence_agent"
        )
        assert "query_timings" in agent_e.detail
        assert agent_e.detail["collection_status"] == "degraded"


class TestDecisionRecordRef:
    @pytest.mark.asyncio
    async def test_agent_execution_entry_includes_decision_record_ref(
        self,
        service: DecisionTraceService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = _id("evt")
        record_ref = "dec-abc123456789"

        async with session_factory() as session:
            async with session.begin():
                await _seed_security_event(session, event_id)
                await _seed_agent_trace(
                    session,
                    event_id,
                    agent_name="react_engine",
                    output_data={
                        "decision_summary": "bounded summary",
                        "decision_record_ref": record_ref,
                        "_decision_basis": {
                            "structured_conclusion": "bounded summary",
                            "confidence": 0.5,
                        },
                    },
                )

        trace = await service.get_decision_trace(event_id)
        agent_entries = [
            e for e in trace.entries if e.entry_type == DecisionTraceEntryType.AGENT_EXECUTION
        ]
        assert len(agent_entries) == 1
        assert agent_entries[0].decision_record_ref == record_ref
        assert agent_entries[0].detail["decision_record_ref"] == record_ref
