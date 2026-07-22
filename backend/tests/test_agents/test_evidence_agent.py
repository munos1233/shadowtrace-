"""EvidenceAgent sequential collection tests (ISSUE-033)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from app.agents.evidence_agent import (
    EVIDENCE_QUERY_ORDER,
    EvidenceAgent,
    InMemoryEvidenceRepository,
    SqlAlchemyEvidenceRepository,
    time_range_around_occurred_at,
)
from app.agents.evidence_parser import TOOL_SOURCE_MAP, EvidenceParser
from app.models.agent_io import (
    CollectionStatus,
    EvidenceAgentInput,
    EvidenceOutput,
    TriageResult,
)
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    HostEntity,
    IPEntity,
)
from app.models.enums import EventType, EvidenceSource, Severity
from app.models.evidence import Evidence
from app.models.ids import new_evidence_id
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.services.evidence_projection import (
    EvidenceProjection,
    bind_evidence_projection,
    bind_evidence_query_scope,
)
from tests.test_tools.tool_system_fixtures import (
    DEFAULT_SCOPE,
    WINDOW,
    new_sfx,
)

pytestmark = pytest.mark.asyncio


class _EventScopeService:
    def __init__(self, scope: Any = DEFAULT_SCOPE) -> None:
        self.scope = scope

    async def get_evidence_query_scope(self, event_id: str) -> Any:
        return self.scope


class _FakeWorkingMemory:
    """Minimal BoundWorkingMemory stand-in (write/read signatures must match)."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}
        self.scratchpad: dict[str, list[str]] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        self.scratchpad.setdefault(event_id, []).append(note)


class _RecordingTraceService:
    def __init__(self) -> None:
        self.traces: list[dict[str, Any]] = []

    async def log_trace(self, **kwargs: Any) -> str:
        self.traces.append(kwargs)
        return f"trace-{uuid4().hex[:8]}"


class _FlakyExecutor:
    """Delegates to a real executor but forces selected tools to fail."""

    def __init__(self, inner: Any, fail_tools: set[str]) -> None:
        self._inner = inner
        self._fail_tools = fail_tools

    async def call(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        **kwargs: Any,
    ) -> ToolResult:
        if tool_name in self._fail_tools:
            return ToolResult(
                call_id=f"call-fail-{new_sfx()}",
                tool_name=tool_name,
                provider_name="test",
                status=ToolResultStatus.FAILED,
                error_detail=f"forced failure for {tool_name}",
                execution_time_ms=3,
            )
        return await self._inner.call(tool_name, params, event_id, **kwargs)


def _main_scenario_triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            accounts=[
                AccountEntity(entity_id="ent-acc-1", username="zhangsan"),
            ],
            hosts=[
                HostEntity(
                    entity_id="ent-host-1",
                    hostname="PC-FIN-023",
                    ip="10.20.30.23",
                ),
            ],
            ips=[
                IPEntity(
                    entity_id="ent-ip-int",
                    address="10.20.30.23",
                    scope="internal",
                ),
                IPEntity(
                    entity_id="ent-ip-ext",
                    address="203.0.113.88",
                    scope="external",
                ),
            ],
            domains=[
                DomainEntity(
                    entity_id="ent-dom-1",
                    fqdn="unknown-upload-example.com",
                ),
            ],
        ),
        ioc_list=["203.0.113.88", "unknown-upload-example.com"],
        reasoning="insider data exfiltration main scenario",
    )


def _make_evidence(
    *,
    source: EvidenceSource,
    evidence_type: str,
    confidence: float,
    timestamp: datetime,
    event_id: str = "evt-dedup",
) -> Evidence:
    return Evidence(
        evidence_id=new_evidence_id(),
        event_id=event_id,
        source=source,
        evidence_type=evidence_type,
        description="test",
        confidence=confidence,
        timestamp=timestamp,
    )


@pytest.fixture
def wm() -> _FakeWorkingMemory:
    return _FakeWorkingMemory()


@pytest.fixture
def evidence_repo() -> InMemoryEvidenceRepository:
    return InMemoryEvidenceRepository()


@pytest.fixture
def trace_service() -> _RecordingTraceService:
    return _RecordingTraceService()


def _build_agent(
    *,
    tool_executor: Any,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
    trace_service: _RecordingTraceService | None = None,
    event_service: Any | None = None,
) -> EvidenceAgent:
    return EvidenceAgent(
        tool_executor=tool_executor,
        working_memory=wm,
        evidence_repository=evidence_repo,
        event_service=event_service if event_service is not None else _EventScopeService(),
        trace_service=trace_service,
        default_time_range=dict(WINDOW),
        evidence_mode="sequential",
    )


async def _seed_event_context(
    wm: _FakeWorkingMemory,
    event_id: str,
    *,
    occurred_at: str = "2024-06-15T09:00:00Z",
) -> None:
    """Seed EventContext.event so EvidenceAgent derives the query window."""
    await wm.write(
        event_id,
        "event",
        {
            "event_id": event_id,
            "occurred_at": occurred_at,
        },
    )


async def test_all_seven_sources_completed_timeline_and_persistence(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
    trace_service: _RecordingTraceService,
) -> None:
    """Main scenario: >=5 success sources, monotonic timeline, persist + WM."""
    event_id = f"evt-evd-all-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = _build_agent(
        tool_executor=tool_executor,
        wm=wm,
        evidence_repo=evidence_repo,
        trace_service=trace_service,
    )
    agent_input = EvidenceAgentInput(
        event_id=event_id,
        triage_result=_main_scenario_triage(),
    )

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(agent_input)

    assert isinstance(output, EvidenceOutput)
    assert output.collection_status is CollectionStatus.COMPLETED
    assert len(output.success_sources) >= 5
    assert len(output.evidence_list) >= 5

    timestamps = [item.timestamp for item in output.evidence_list if item.timestamp is not None]
    assert timestamps == sorted(timestamps)
    assert all(ts.microsecond == 0 for ts in timestamps)

    stored = await evidence_repo.list_by_event(event_id)
    assert {row.evidence_id for row in stored} == {
        item.evidence_id for item in output.evidence_list
    }
    assert len(stored) == len(output.evidence_list)

    ctx = await wm.read(event_id, "evidence_output")
    assert ctx is not None
    assert ctx["collection_status"] == CollectionStatus.COMPLETED.value
    assert len(ctx["evidence_list"]) == len(output.evidence_list)

    # Per-query timings for agent_trace / scratchpad acceptance.
    assert len(agent.last_query_timings) == len(EVIDENCE_QUERY_ORDER)
    assert {row["tool_name"] for row in agent.last_query_timings} == set(EVIDENCE_QUERY_ORDER)
    notes = wm.scratchpad.get(event_id, [])
    assert len(notes) == len(EVIDENCE_QUERY_ORDER)
    assert all("execution_time_ms=" in note for note in notes)

    assert len(trace_service.traces) == 1
    assert trace_service.traces[0]["agent_name"] == "evidence_agent"
    assert trace_service.traces[0]["status"] == "completed"
    trace_out = trace_service.traces[0]["output_data"]
    assert isinstance(trace_out, dict)
    assert "query_timings" in trace_out
    assert len(trace_out["query_timings"]) == len(EVIDENCE_QUERY_ORDER)
    assert {row["tool_name"] for row in trace_out["query_timings"]} == set(EVIDENCE_QUERY_ORDER)
    assert all("execution_time_ms" in row for row in trace_out["query_timings"])
    assert trace_out.get("persist_ok") is True


async def test_three_tool_failures_partial_done_penalty(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """Partial failure: success sources 3–4 → partial_done, penalty 0.10.

    Issue prose says "2 failures", but 统一命名 requires success count 3–4 for
    partial_done. Force-fail 3 of 7 tools (leave 4 successful) to match the rule.
    """
    event_id = f"evt-evd-partial-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    fail_tools = {
        "query_dns",
        "query_asset_info",
        "query_threat_intel",
    }
    flaky = _FlakyExecutor(tool_executor, fail_tools)
    agent = _build_agent(
        tool_executor=flaky,
        wm=wm,
        evidence_repo=evidence_repo,
    )
    agent_input = EvidenceAgentInput(
        event_id=event_id,
        triage_result=_main_scenario_triage(),
    )

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(agent_input)

    assert output.collection_status is CollectionStatus.PARTIAL_DONE
    assert 3 <= len(output.success_sources) <= 4
    assert set(output.failed_sources) >= {TOOL_SOURCE_MAP[name].value for name in fail_tools}

    unpenalized = EvidenceAgent._overall_confidence(
        output.evidence_list,
        CollectionStatus.COMPLETED,
    )
    expected = max(0.0, min(1.0, unpenalized - 0.10))
    assert abs(output.overall_confidence - expected) < 1e-9


async def test_all_tools_failed_returns_failed_without_raise(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """All failures: collection_status=failed, no exception."""
    event_id = f"evt-evd-fail-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    flaky = _FlakyExecutor(tool_executor, set(EVIDENCE_QUERY_ORDER))
    agent = _build_agent(
        tool_executor=flaky,
        wm=wm,
        evidence_repo=evidence_repo,
    )
    agent_input = EvidenceAgentInput(
        event_id=event_id,
        triage_result=_main_scenario_triage(),
    )

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(agent_input)

    assert output.collection_status is CollectionStatus.FAILED
    assert output.evidence_list == []
    assert output.overall_confidence == 0.0
    assert len(output.failed_sources) == len(EVIDENCE_QUERY_ORDER)
    ctx = await wm.read(event_id, "evidence_output")
    assert ctx["collection_status"] == "failed"


async def test_dedup_keeps_higher_confidence_and_sorts_by_timestamp() -> None:
    """Dedup key (source, evidence_type, timestamp) keeps higher confidence."""
    base = datetime(2024, 6, 15, 9, 1, 0, tzinfo=UTC)
    low = _make_evidence(
        source=EvidenceSource.ENDPOINT,
        evidence_type="process_create",
        confidence=0.40,
        timestamp=base + timedelta(milliseconds=500),
    )
    high = _make_evidence(
        source=EvidenceSource.ENDPOINT,
        evidence_type="process_create",
        confidence=0.90,
        timestamp=base + timedelta(milliseconds=800),
    )
    earlier = _make_evidence(
        source=EvidenceSource.DNS,
        evidence_type="dns_query",
        confidence=0.70,
        timestamp=base - timedelta(minutes=1),
    )
    later = _make_evidence(
        source=EvidenceSource.NETWORK_FLOW,
        evidence_type="network_flow",
        confidence=0.70,
        timestamp=base + timedelta(minutes=2),
    )

    result = EvidenceAgent._dedup_and_sort([low, high, earlier, later])
    assert len(result) == 3
    endpoint_rows = [row for row in result if row.source is EvidenceSource.ENDPOINT]
    assert len(endpoint_rows) == 1
    assert endpoint_rows[0].confidence == 0.90
    assert endpoint_rows[0].timestamp == base  # truncated to seconds

    stamps = [row.timestamp for row in result]
    assert stamps == sorted(stamps)


async def test_parser_source_mapping_and_login_template() -> None:
    """EvidenceParser source mapping and description template."""
    parser = EvidenceParser()
    tool_result = ToolResult(
        call_id="call-1",
        tool_name="query_account_login",
        provider_name="evidence_projection",
        status=ToolResultStatus.SUCCESS,
        confidence=0.8,
        data={
            "records": [
                {
                    "record_id": "id-1",
                    "account": "zhangsan",
                    "src_ip": "10.20.30.23",
                    "logged_at": "2024-06-15T09:01:00Z",
                    "event_type": "login",
                    "result": "success",
                }
            ],
            "source_references": [],
        },
        execution_time_ms=5,
    )
    rows = parser.parse("query_account_login", tool_result, event_id="evt-1")
    assert len(rows) == 1
    assert rows[0].source is EvidenceSource.IDENTITY
    assert "账号 zhangsan" in rows[0].description
    assert "10.20.30.23" in rows[0].description
    assert rows[0].confidence == 0.8


async def test_evidence_table_count_matches_list_after_upsert(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """Evidence repository row count matches evidence_list."""
    event_id = f"evt-evd-count-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = _build_agent(
        tool_executor=tool_executor,
        wm=wm,
        evidence_repo=evidence_repo,
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(
                    event_id=event_id,
                    triage_result=_main_scenario_triage(),
                )
            )
    stored = await evidence_repo.list_by_event(event_id)
    assert len(stored) == len(output.evidence_list)
    assert {s.evidence_id for s in stored} == {e.evidence_id for e in output.evidence_list}


class _FailingEvidenceRepository(InMemoryEvidenceRepository):
    async def upsert_batch(self, evidence_list: list[Evidence]) -> None:
        raise RuntimeError("simulated upsert failure")


async def test_agent_trace_payload_includes_query_timings(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
    trace_service: _RecordingTraceService,
) -> None:
    """Acceptance: agent_trace output_data carries per-query timings."""
    event_id = f"evt-evd-trace-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = _build_agent(
        tool_executor=tool_executor,
        wm=wm,
        evidence_repo=evidence_repo,
        trace_service=trace_service,
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            await agent.execute(
                EvidenceAgentInput(
                    event_id=event_id,
                    triage_result=_main_scenario_triage(),
                )
            )
    payload = trace_service.traces[0]["output_data"]
    timings = payload["query_timings"]
    assert len(timings) == 7
    assert all(isinstance(row["execution_time_ms"], int) for row in timings)
    assert payload["collection_status"] == CollectionStatus.COMPLETED.value
    assert payload["persist_ok"] is True


async def test_persist_failure_is_visible_in_trace_and_agent_state(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    trace_service: _RecordingTraceService,
) -> None:
    """DB upsert failure must not be silent: last_persist_error + trace persist_ok=false."""
    event_id = f"evt-evd-persist-fail-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = _build_agent(
        tool_executor=tool_executor,
        wm=wm,
        evidence_repo=_FailingEvidenceRepository(),
        trace_service=trace_service,
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(
                    event_id=event_id,
                    triage_result=_main_scenario_triage(),
                )
            )
    # Collection still returns evidence (tool path succeeded).
    assert len(output.evidence_list) >= 5
    assert agent.last_persist_error is not None
    assert "simulated upsert failure" in agent.last_persist_error
    payload = trace_service.traces[0]["output_data"]
    assert payload["persist_ok"] is False
    assert "simulated upsert failure" in str(payload.get("persist_error"))
    assert any(row.get("status") == "persist_failed" for row in payload["query_timings"])
    notes = wm.scratchpad.get(event_id, [])
    assert any("persist_failed" in note for note in notes)


async def test_time_range_derived_from_event_occurred_at(wm: _FakeWorkingMemory) -> None:
    """Query window is centered on EventContext.event.occurred_at."""
    event_id = f"evt-evd-window-{new_sfx()}"
    await _seed_event_context(wm, event_id, occurred_at="2024-06-15T09:30:00Z")
    agent = EvidenceAgent(working_memory=wm, tool_executor=object())
    resolved = await agent._resolve_time_range(
        EvidenceAgentInput(event_id=event_id, triage_result=_main_scenario_triage())
    )
    expected = time_range_around_occurred_at(datetime(2024, 6, 15, 9, 30, tzinfo=UTC))
    assert resolved == expected
    assert resolved != dict(WINDOW)


async def test_five_tool_failures_degraded_penalty(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """Success sources 1–2 → degraded with 0.25 penalty."""
    event_id = f"evt-evd-degraded-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    fail_tools = {
        "query_file_access",
        "query_network_flow",
        "query_dns",
        "query_asset_info",
        "query_threat_intel",
    }
    flaky = _FlakyExecutor(tool_executor, fail_tools)
    agent = _build_agent(tool_executor=flaky, wm=wm, evidence_repo=evidence_repo)
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(event_id=event_id, triage_result=_main_scenario_triage())
            )

    assert output.collection_status is CollectionStatus.DEGRADED
    assert 1 <= len(output.success_sources) <= 2
    unpenalized = EvidenceAgent._overall_confidence(
        output.evidence_list,
        CollectionStatus.COMPLETED,
    )
    expected = max(0.0, min(1.0, unpenalized - 0.25))
    assert abs(output.overall_confidence - expected) < 1e-9


async def test_missing_event_service_marks_missing_scope_gaps(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """Without event_service every query gap uses reason=missing_scope."""
    event_id = f"evt-evd-noscope-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = EvidenceAgent(
        tool_executor=tool_executor,
        working_memory=wm,
        evidence_repository=evidence_repo,
        event_service=None,
        default_time_range=dict(WINDOW),
    )
    with bind_evidence_projection(evidence_projection):
        output = await agent.execute(
            EvidenceAgentInput(event_id=event_id, triage_result=_main_scenario_triage())
        )

    assert output.collection_status is CollectionStatus.FAILED
    assert len(output.gaps) == len(EVIDENCE_QUERY_ORDER)
    assert all(gap.reason == "missing_scope" for gap in output.gaps)
    assert len(output.failed_sources) == len(EVIDENCE_QUERY_ORDER)


class _EmptyDnsExecutor:
    """Return SUCCESS with empty records for DNS to exercise no_records gaps."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def call(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        **kwargs: Any,
    ) -> ToolResult:
        if tool_name == "query_dns":
            return ToolResult(
                call_id=f"call-empty-{new_sfx()}",
                tool_name=tool_name,
                provider_name="test",
                status=ToolResultStatus.SUCCESS,
                confidence=0.8,
                data={"records": [], "source_references": []},
                execution_time_ms=2,
            )
        return await self._inner.call(tool_name, params, event_id, **kwargs)


async def test_empty_records_counts_as_gap_not_success_source(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """Tool SUCCESS with zero parsed rows is a no_records gap, not a success source."""
    event_id = f"evt-evd-empty-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    executor = _EmptyDnsExecutor(tool_executor)
    agent = _build_agent(tool_executor=executor, wm=wm, evidence_repo=evidence_repo)
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(event_id=event_id, triage_result=_main_scenario_triage())
            )

    dns = EvidenceSource.DNS.value
    assert dns not in output.success_sources
    assert dns not in output.failed_sources
    dns_gaps = [gap for gap in output.gaps if gap.missing_source is EvidenceSource.DNS]
    assert len(dns_gaps) == 1
    assert dns_gaps[0].reason == "no_records"


@pytest.mark.integration
async def test_sqlalchemy_evidence_upsert_keeps_higher_confidence() -> None:
    """Postgres upsert retains the higher-confidence row on evidence_id conflict."""
    import os
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import delete, text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    from app.db import models as orm
    from app.models.enums import (
        DispositionPolicy,
        EventStatus,
        EventType,
        FinalVerdict,
        Severity,
        SourceObjectKind,
    )
    from tests.test_services.test_state_machine_service import _ref

    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
    )
    backend_dir = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "migrations"))

    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        await engine.dispose()
        pytest.skip("PostgreSQL not reachable; start Compose postgres first")

    await asyncio.to_thread(command.upgrade, cfg, "head")
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    repo = SqlAlchemyEvidenceRepository(session_factory)
    event_id = f"evt-evd-sql-{new_sfx()}"
    evidence_id = new_evidence_id()
    now = datetime.now(UTC)
    ref = _ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{new_sfx()}")

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.OTHER.value,
                    title="evidence-upsert-test",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.LOW.value,
                    risk_score=1,
                    confidence=0.5,
                    final_verdict=FinalVerdict.NONE.value,
                    creation_source_ref=ref.model_dump(mode="json"),
                    source_reference_snapshots=[ref.model_dump(mode="json")],
                    disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
                    occurred_at=now,
                )
            )

    low = Evidence(
        evidence_id=evidence_id,
        event_id=event_id,
        source=EvidenceSource.IDENTITY,
        evidence_type="login",
        description="low confidence",
        confidence=0.30,
        timestamp=now,
    )
    high = Evidence(
        evidence_id=evidence_id,
        event_id=event_id,
        source=EvidenceSource.IDENTITY,
        evidence_type="login",
        description="high confidence",
        confidence=0.90,
        timestamp=now,
    )
    try:
        await repo.upsert_batch([low])
        await repo.upsert_batch([high])
        rows = await repo.list_by_event(event_id)
        assert len(rows) == 1
        assert rows[0].evidence_id == evidence_id
        assert rows[0].confidence == 0.90
        assert rows[0].description == "high confidence"
    finally:
        async with session_factory() as session:
            async with session.begin():
                await session.execute(delete(orm.Evidence).where(orm.Evidence.event_id == event_id))
                await session.execute(
                    delete(orm.SecurityEvent).where(orm.SecurityEvent.event_id == event_id)
                )
        await engine.dispose()
