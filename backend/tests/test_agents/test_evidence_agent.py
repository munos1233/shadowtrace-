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
    resolve_tool_outcome,
    time_range_around_occurred_at,
)
from app.agents.evidence_parser import TOOL_SOURCE_MAP, EvidenceParser
from app.models.agent_io import (
    CollectionStatus,
    EntityProvenanceRecord,
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
from app.models.enums import EventType, EvidenceSource, Severity, SourceObjectKind
from app.models.evidence import Evidence
from app.models.ids import new_evidence_id
from app.models.source import SourceReference
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.services.evidence_projection import (
    EvidenceProjection,
    bind_evidence_projection,
    bind_evidence_query_scope,
)
from app.services.evidence_query_plan_service import build_query_dedupe_key
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


async def test_evidence_collect_skips_edr_when_no_valid_host(
    tool_executor: Any,
) -> None:
    """ISSUE-100: empty triage entities must not invoke query_edr_process."""

    class _EdrCallRecorder:
        def __init__(self, inner: object) -> None:
            self.inner = inner
            self.edr_calls: list[dict[str, object]] = []

        async def call(self, tool_name: str, params: dict[str, object], **kwargs: object) -> object:
            if tool_name == "query_edr_process":
                self.edr_calls.append(params)
            return await self.inner.call(tool_name, params, **kwargs)

    event_id = f"evt-100-edr-skip-{new_sfx()}"
    wm = _FakeWorkingMemory()
    await _seed_event_context(wm, event_id)
    recorder = _EdrCallRecorder(tool_executor)
    agent = _build_agent(
        tool_executor=recorder,
        wm=wm,
        evidence_repo=InMemoryEvidenceRepository(),
    )
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(),
    )
    with bind_evidence_query_scope(DEFAULT_SCOPE):
        output = await agent.execute(EvidenceAgentInput(event_id=event_id, triage_result=triage))

    assert recorder.edr_calls == []
    assert any(gap.reason == "source_skipped" for gap in output.gaps)
    edr_timing = next(
        row for row in agent.last_query_timings if row["tool_name"] == "query_edr_process"
    )
    assert edr_timing["tool_outcome"] == "source_skipped"


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


@pytest.mark.asyncio(loop_scope="function")
async def test_resolve_tool_outcome_distinguishes_empty_failed_and_skipped() -> None:
    """ISSUE-249: tool_ok_empty / tool_failed / source_skipped are mutually exclusive."""
    assert resolve_tool_outcome(success=True, failed=False, gap_reason=None) == "tool_ok"
    assert (
        resolve_tool_outcome(success=False, failed=False, gap_reason="no_records")
        == "tool_ok_empty"
    )
    assert (
        resolve_tool_outcome(success=False, failed=True, gap_reason="tool_failed") == "tool_failed"
    )
    assert (
        resolve_tool_outcome(success=False, failed=True, gap_reason="source_skipped")
        == "source_skipped"
    )
    assert (
        resolve_tool_outcome(success=False, failed=True, gap_reason="invalid_entity")
        == "source_skipped"
    )


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


class _FailingDnsExecutor:
    """Force DNS tool failure to contrast with tool_ok_empty."""

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
                call_id=f"call-fail-{new_sfx()}",
                tool_name=tool_name,
                provider_name="test",
                status=ToolResultStatus.FAILED,
                confidence=0.0,
                data={},
                execution_time_ms=2,
                error_detail="dns provider unavailable",
            )
        return await self._inner.call(tool_name, params, event_id, **kwargs)


async def test_empty_records_counts_as_gap_not_success_source(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """Tool SUCCESS with zero parsed rows is tool_ok_empty, not a success source."""
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

    dns_timing = next(row for row in agent.last_query_timings if row["tool_name"] == "query_dns")
    assert dns_timing["tool_outcome"] == "tool_ok_empty"
    assert dns_timing["status"] == "tool_ok_empty"
    assert dns_timing["provider_status"] == "success"
    assert dns_timing["records_count"] == 0
    assert dns_timing["gap_reason"] == "no_records"
    # ISSUE-101: collection_status is derived only from parser-success source count.
    assert output.collection_status is EvidenceAgent._collection_status(len(output.success_sources))


async def test_empty_records_tool_outcome_differs_from_tool_failed(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """ISSUE-249 acceptance: empty SUCCESS vs FAILED are distinguishable in timings."""
    empty_event = f"evt-evd-empty-ok-{new_sfx()}"
    await _seed_event_context(wm, empty_event)
    empty_agent = _build_agent(
        tool_executor=_EmptyDnsExecutor(tool_executor),
        wm=wm,
        evidence_repo=evidence_repo,
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            await empty_agent.execute(
                EvidenceAgentInput(event_id=empty_event, triage_result=_main_scenario_triage())
            )
    empty_timing = next(
        row for row in empty_agent.last_query_timings if row["tool_name"] == "query_dns"
    )

    fail_event = f"evt-evd-tool-fail-{new_sfx()}"
    await _seed_event_context(wm, fail_event)
    fail_agent = _build_agent(
        tool_executor=_FailingDnsExecutor(tool_executor),
        wm=wm,
        evidence_repo=InMemoryEvidenceRepository(),
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            fail_output = await fail_agent.execute(
                EvidenceAgentInput(event_id=fail_event, triage_result=_main_scenario_triage())
            )
    fail_timing = next(
        row for row in fail_agent.last_query_timings if row["tool_name"] == "query_dns"
    )

    assert empty_timing["tool_outcome"] == "tool_ok_empty"
    assert fail_timing["tool_outcome"] == "tool_failed"
    assert empty_timing["tool_outcome"] != fail_timing["tool_outcome"]
    assert EvidenceSource.DNS.value in fail_output.failed_sources
    assert EvidenceSource.DNS.value not in fail_output.success_sources


def _source_ref() -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-mock",
        source_object_id="INC-101",
        ingested_at=datetime.now(UTC),
    )


async def test_invalid_hostname_produces_invalid_entity_gap_without_tool_call(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """ISSUE-101: alert-jargon hostname must not invoke EDR; gap=invalid_entity."""

    class _EdrCallRecorder:
        def __init__(self, inner: object) -> None:
            self.inner = inner
            self.edr_calls: list[dict[str, object]] = []

        async def call(self, tool_name: str, params: dict[str, object], **kwargs: object) -> object:
            if tool_name == "query_edr_process":
                self.edr_calls.append(params)
            return await self.inner.call(tool_name, params, **kwargs)

    event_id = f"evt-101-invalid-host-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    recorder = _EdrCallRecorder(tool_executor)
    agent = _build_agent(tool_executor=recorder, wm=wm, evidence_repo=evidence_repo)
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            hosts=[HostEntity(entity_id="ent-bad-host", hostname="stage3")],
        ),
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(event_id=event_id, triage_result=triage)
            )

    assert recorder.edr_calls == []
    endpoint_gaps = [gap for gap in output.gaps if gap.missing_source is EvidenceSource.ENDPOINT]
    assert len(endpoint_gaps) == 1
    assert endpoint_gaps[0].reason == "invalid_entity"


async def test_threat_intel_skips_invalid_ioc_in_list_without_tool_call(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """ISSUE-101: invalid ioc_list entries must not invoke threat_intel; gap=invalid_entity."""

    class _ThreatIntelCallRecorder:
        def __init__(self, inner: object) -> None:
            self.inner = inner
            self.threat_intel_calls: list[dict[str, object]] = []

        async def call(self, tool_name: str, params: dict[str, object], **kwargs: object) -> object:
            if tool_name == "query_threat_intel":
                self.threat_intel_calls.append(params)
            return await self.inner.call(tool_name, params, **kwargs)

    event_id = f"evt-101-invalid-ioc-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    recorder = _ThreatIntelCallRecorder(tool_executor)
    agent = _build_agent(tool_executor=recorder, wm=wm, evidence_repo=evidence_repo)
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(),
        ioc_list=["stage3", "not-a-valid-indicator"],
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(event_id=event_id, triage_result=triage)
            )

    assert recorder.threat_intel_calls == []
    intel_gaps = [gap for gap in output.gaps if gap.missing_source is EvidenceSource.THREAT_INTEL]
    assert len(intel_gaps) == 1
    assert intel_gaps[0].reason == "invalid_entity"


async def test_triage_degraded_without_source_entities_skips_all_queries(
    tool_executor: Any,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """ISSUE-101: degraded triage without source entities fail-closes all seven queries."""

    class _CallRecorder:
        def __init__(self, inner: object) -> None:
            self.inner = inner
            self.calls: list[str] = []

        async def call(self, tool_name: str, params: dict[str, object], **kwargs: object) -> object:
            self.calls.append(tool_name)
            return await self.inner.call(tool_name, params, **kwargs)

    event_id = f"evt-101-degraded-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    recorder = _CallRecorder(tool_executor)
    agent = _build_agent(tool_executor=recorder, wm=wm, evidence_repo=evidence_repo)
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        degraded=True,
        degradation_reasons=["llm_timeout"],
        entities=EntitySet(),
    )
    with bind_evidence_query_scope(DEFAULT_SCOPE):
        output = await agent.execute(EvidenceAgentInput(event_id=event_id, triage_result=triage))

    assert recorder.calls == []
    assert len(output.gaps) == len(EVIDENCE_QUERY_ORDER)
    assert all(gap.reason == "triage_degraded" for gap in output.gaps)
    assert output.collection_status is CollectionStatus.FAILED


async def test_triage_degraded_with_source_entities_still_collects(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """Degraded triage with source-enriched entities must not global-skip."""
    event_id = f"evt-101-degraded-src-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = _build_agent(tool_executor=tool_executor, wm=wm, evidence_repo=evidence_repo)
    ref = _source_ref()
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        degraded=True,
        entities=EntitySet(
            hosts=[
                HostEntity(
                    entity_id="ent-host-src",
                    hostname="PC-FIN-023",
                    ip="10.20.30.23",
                    source_refs=[ref],
                ),
            ],
            accounts=[AccountEntity(entity_id="ent-acc", username="svc-backup", source_refs=[ref])],
            ips=[
                IPEntity(
                    entity_id="ent-ip-int",
                    address="10.20.30.23",
                    scope="internal",
                    source_refs=[ref],
                ),
            ],
            domains=[
                DomainEntity(
                    entity_id="ent-dom",
                    fqdn="unknown-upload-example.com",
                    source_refs=[ref],
                ),
            ],
        ),
        ioc_list=["203.0.113.88"],
        entity_provenance_summary=[
            EntityProvenanceRecord(
                source_kind="incident",
                source_object_id="INC-101",
                connector_id="conn-mock",
            )
        ],
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(event_id=event_id, triage_result=triage)
            )

    assert not any(gap.reason == "triage_degraded" for gap in output.gaps)
    assert len(output.success_sources) >= 1


async def test_query_timings_include_records_count_and_gap_reason(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """ISSUE-101: agent trace timings expose records_count and gap_reason."""
    event_id = f"evt-101-timings-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    executor = _EmptyDnsExecutor(tool_executor)
    agent = _build_agent(tool_executor=executor, wm=wm, evidence_repo=evidence_repo)
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            await agent.execute(
                EvidenceAgentInput(event_id=event_id, triage_result=_main_scenario_triage())
            )

    dns_timing = next(row for row in agent.last_query_timings if row["tool_name"] == "query_dns")
    assert dns_timing["records_count"] == 0
    assert dns_timing["gap_reason"] == "no_records"
    assert dns_timing["tool_outcome"] == "tool_ok_empty"
    assert dns_timing["status"] == "tool_ok_empty"
    assert dns_timing["provider_status"] == "success"
    success_timing = next(
        row
        for row in agent.last_query_timings
        if row["tool_name"] != "query_dns" and row.get("records_count", 0) > 0
    )
    assert success_timing["gap_reason"] is None
    assert success_timing["tool_outcome"] == "tool_ok"


async def test_malicious_process_with_source_entities_produces_evidence(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """ISSUE-101 acceptance: malicious_process + source entities yields evidence."""
    event_id = f"evt-101-malproc-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = _build_agent(tool_executor=tool_executor, wm=wm, evidence_repo=evidence_repo)
    ref = _source_ref()
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            hosts=[
                HostEntity(
                    entity_id="ent-host-mp",
                    hostname="PC-FIN-023",
                    ip="10.20.30.23",
                    source_refs=[ref],
                ),
            ],
            accounts=[
                AccountEntity(entity_id="ent-acc-mp", username="svc-backup", source_refs=[ref])
            ],
            ips=[
                IPEntity(
                    entity_id="ent-ip-mp",
                    address="10.20.30.23",
                    scope="internal",
                    source_refs=[ref],
                ),
            ],
            domains=[
                DomainEntity(
                    entity_id="ent-dom-mp",
                    fqdn="unknown-upload-example.com",
                    source_refs=[ref],
                ),
            ],
        ),
        ioc_list=["203.0.113.88"],
    )
    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(
                EvidenceAgentInput(event_id=event_id, triage_result=triage)
            )

    assert len(output.evidence_list) >= 1
    assert output.collection_status in {
        CollectionStatus.DEGRADED,
        CollectionStatus.PARTIAL_DONE,
        CollectionStatus.COMPLETED,
    }


async def test_degraded_summary_only_still_global_skips(
    tool_executor: Any,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """Provenance summary alone must not bypass triage_degraded global skip."""

    class _CallRecorder:
        def __init__(self, inner: object) -> None:
            self.inner = inner
            self.calls: list[str] = []

        async def call(self, tool_name: str, params: dict[str, object], **kwargs: object) -> object:
            self.calls.append(tool_name)
            return await self.inner.call(tool_name, params, **kwargs)

    event_id = f"evt-101-summary-only-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    recorder = _CallRecorder(tool_executor)
    agent = _build_agent(tool_executor=recorder, wm=wm, evidence_repo=evidence_repo)
    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        need_investigation=True,
        degraded=True,
        degradation_reasons=["llm_timeout"],
        entities=EntitySet(),
        entity_provenance_summary=[
            EntityProvenanceRecord(
                source_kind="incident",
                source_object_id="INC-orphan",
                connector_id="conn-mock",
            )
        ],
    )
    with bind_evidence_query_scope(DEFAULT_SCOPE):
        output = await agent.execute(EvidenceAgentInput(event_id=event_id, triage_result=triage))

    assert recorder.calls == []
    assert all(gap.reason == "triage_degraded" for gap in output.gaps)


async def test_evidence_respects_alert_context_for_validator() -> None:
    """Evidence-stage validator must align with triage alert context (ISSUE-101)."""
    from app.agents.evidence_agent import _validate_entities_for_evidence

    alert_text = "Suspicious activity detected on host myserver during lateral scan"
    entities = EntitySet(
        hosts=[HostEntity(entity_id="ent-myserver", hostname="myserver")],
    )

    without_alert = _validate_entities_for_evidence(entities, alert_text="")
    assert without_alert.entity_set.hosts == []

    with_alert = _validate_entities_for_evidence(entities, alert_text=alert_text)
    assert len(with_alert.entity_set.hosts) == 1
    assert with_alert.entity_set.hosts[0].hostname == "myserver"


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


def test_build_params_query_dns_from_ioc_when_no_domain_entity() -> None:
    """ISSUE-332: FQDN IOCs backfill query_dns when EntitySet.domains is empty."""
    agent = EvidenceAgent(llm_client=None, tool_executor=None)
    time_range = {"start": "2024-01-01T00:00:00Z", "end": "2024-01-02T00:00:00Z"}
    params = agent._build_params(
        "query_dns",
        EntitySet(),
        time_range,
        ioc_list=["storage-sync-cdn.example"],
    )
    assert params == {"domain": "storage-sync-cdn.example", "time_range": time_range}


def test_build_params_query_dns_skips_ip_only_ioc() -> None:
    """ISSUE-332: IP-only IOCs must not be sent as DNS domain queries."""
    agent = EvidenceAgent(llm_client=None, tool_executor=None)
    time_range = {"start": "2024-01-01T00:00:00Z", "end": "2024-01-02T00:00:00Z"}
    params = agent._build_params(
        "query_dns",
        EntitySet(),
        time_range,
        ioc_list=["203.0.113.10"],
    )
    assert params is None


def test_build_params_query_dns_prefers_entity_domain_over_ioc() -> None:
    agent = EvidenceAgent(llm_client=None, tool_executor=None)
    time_range = {"start": "2024-01-01T00:00:00Z", "end": "2024-01-02T00:00:00Z"}
    entities = EntitySet(domains=[DomainEntity(entity_id="d1", fqdn="entity.example")])
    params = agent._build_params(
        "query_dns",
        entities,
        time_range,
        ioc_list=["ioc.example"],
    )
    assert params == {"domain": "entity.example", "time_range": time_range}


async def test_plan_driven_required_tools_limits_queries(
    tool_executor: Any,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
    evidence_projection: EvidenceProjection,
) -> None:
    """ISSUE-115: validated required_tools subset is honored (+ mandatory merge)."""
    event_id = f"evt-evd-plan-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = _build_agent(tool_executor=tool_executor, wm=wm, evidence_repo=evidence_repo)
    triage = TriageResult(
        event_type=EventType.SUSPICIOUS_DOMAIN,
        severity=Severity.MEDIUM,
        need_investigation=True,
        entities=EntitySet(
            domains=[DomainEntity(entity_id="ent-dom-plan", fqdn="plan-only.example")],
        ),
        reasoning="plan-driven dns lookup",
    )
    agent_input = EvidenceAgentInput(
        event_id=event_id,
        triage_result=triage,
        required_tools=["query_dns"],
    )

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            output = await agent.execute(agent_input)

    assert agent.last_query_plan is not None
    assert "query_dns" in agent.last_query_plan.tools
    queried = {row["tool_name"] for row in agent.last_query_timings}
    assert queried == set(agent.last_query_plan.tools)
    assert len(queried) <= 3
    assert "query_account_login" not in queried
    assert isinstance(output, EvidenceOutput)


async def test_run_one_query_deduped_reuses_cached_outcome(
    tool_executor: Any,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    """ISSUE-115: identical query signature reuses prior outcome within one run."""
    event_id = f"evt-evd-dedupe-{new_sfx()}"
    agent = _build_agent(tool_executor=tool_executor, wm=wm, evidence_repo=evidence_repo)
    triage = _main_scenario_triage()
    time_range = dict(WINDOW)
    scope = DEFAULT_SCOPE
    params = agent._build_params(
        "query_threat_intel",
        triage.entities,
        time_range,
        ioc_list=triage.ioc_list,
    )
    assert params is not None
    cache: dict[str, dict[str, Any]] = {}
    first = await agent._run_one_query_deduped(
        "query_threat_intel",
        params,
        event_id,
        scope=scope,
        time_range=time_range,
        dedupe_cache=cache,
    )
    second = await agent._run_one_query_deduped(
        "query_threat_intel",
        params,
        event_id,
        scope=scope,
        time_range=time_range,
        dedupe_cache=cache,
    )
    assert first.get("dedupe_reused") is not True
    assert second.get("dedupe_reused") is True
    assert first.get("dedupe_key") == second.get("dedupe_key")


async def test_agent_honors_budget_from_execution_plan_input(
    tool_executor: Any,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
    evidence_projection: EvidenceProjection,
) -> None:
    """ISSUE-115: budget cap applies when execution_plan is passed via input."""
    from app.models.agent_io import ExecutionPlan, PlanBudget, PlanStep

    event_id = f"evt-evd-budget-{new_sfx()}"
    await _seed_event_context(wm, event_id)
    agent = _build_agent(tool_executor=tool_executor, wm=wm, evidence_repo=evidence_repo)
    triage = _main_scenario_triage()
    execution_plan = ExecutionPlan(
        plan_id="pln-budget",
        event_id=event_id,
        steps=[
            PlanStep(
                step_order=1,
                step_goal="collect all",
                assigned_agent="evidence_agent",
                required_tools=list(EVIDENCE_QUERY_ORDER),
                success_criteria="ok",
            )
        ],
        budget=PlanBudget(max_tool_calls=3),
        revision=0,
    )
    agent_input = EvidenceAgentInput(
        event_id=event_id,
        triage_result=triage,
        execution_plan=execution_plan.model_dump(mode="json"),
    )

    with bind_evidence_projection(evidence_projection):
        with bind_evidence_query_scope(DEFAULT_SCOPE):
            await agent.execute(agent_input)

    assert agent.last_query_plan is not None
    assert set(agent.last_query_plan.mandatory_tools).issubset(set(agent.last_query_plan.tools))
    assert len(agent.last_query_plan.tools) >= len(agent.last_query_plan.mandatory_tools)
    assert "budget_exceeded_mandatory_preserved" in agent.last_query_plan.degraded_reasons


async def test_dedupe_key_uses_source_snapshot_cutoff(
    tool_executor: Any,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
) -> None:
    event_id = f"evt-evd-snap-{new_sfx()}"
    await wm.write(event_id, "source_snapshot", {"snapshot_id": "snap-test-001"})
    agent = _build_agent(tool_executor=tool_executor, wm=wm, evidence_repo=evidence_repo)
    triage = _main_scenario_triage()
    time_range = dict(WINDOW)
    scope = DEFAULT_SCOPE
    params = agent._build_params(
        "query_threat_intel",
        triage.entities,
        time_range,
        ioc_list=triage.ioc_list,
    )
    assert params is not None
    await agent._resolve_snapshot_cutoff(event_id)
    agent.last_snapshot_cutoff = await agent._resolve_snapshot_cutoff(event_id)
    key = build_query_dedupe_key(
        "query_threat_intel",
        params,
        time_range,
        scope,
        snapshot_cutoff=agent.last_snapshot_cutoff,
    )
    key_without = build_query_dedupe_key(
        "query_threat_intel",
        params,
        time_range,
        scope,
    )
    assert agent.last_snapshot_cutoff == "snap-test-001"
    assert key != key_without


async def test_agent_trace_payload_includes_query_plan(
    tool_executor: Any,
    evidence_projection: EvidenceProjection,
    wm: _FakeWorkingMemory,
    evidence_repo: InMemoryEvidenceRepository,
    trace_service: _RecordingTraceService,
) -> None:
    event_id = f"evt-evd-plan-trace-{new_sfx()}"
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
                    plan_step_goal="collect baseline evidence",
                )
            )
    payload = trace_service.traces[0]["output_data"]
    assert "query_plan" in payload
    assert payload["query_plan"]["tools"]
    assert payload.get("plan_step_goal") == "collect baseline evidence"
