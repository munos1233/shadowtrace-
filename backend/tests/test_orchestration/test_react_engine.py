"""ReActEngine loop, safety, and audit tests (ISSUE-053).

Covers the acceptance criteria:
1. Mock mode main scenario converges in 3 rounds with stop_reason=confidence_met.
2. Every ReActRound is fully populated and the per-round trace carries an
   auditable decision_basis (via the real ISSUE-028 TraceProjection).
3. Budget / max_rounds / ConvergenceGuard bound the loop in finite time.

Safety: malicious or mistaken LLM choices (block_ip / isolate_host /
ResponseAgent / unknown targets) are denied *before* execution with zero
tool calls and zero external side effects.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from app.core.llm.base import (
    InMemoryLLMCallAuditRecorder,
    LLMMessage,
    LLMResponse,
    LLMTimeoutError,
)
from app.core.llm.mock_client import MockLLMClient
from app.models.react import (
    ReActAction,
    ReActActionType,
    ReActReflectOutput,
    ReActStopReason,
    ReActThinkOutput,
)
from app.models.workflow import CONFIDENCE_THRESHOLD, GLOBAL_MAX_STEPS
from app.orchestration.convergence_guard import ConvergenceGuard, StopReason
from app.orchestration.react_engine import (
    REACT_ACTION_DENIED,
    ReActEngine,
    ReadOnlyReActExecutor,
)
from app.providers.tools.mock_provider import MockToolProvider, bind_mock_tool_provider
from app.services.agent_trace_service import TraceProjection
from app.services.evidence_projection import (
    EvidenceProjection,
    bind_evidence_projection,
    bind_evidence_query_scope,
)
from app.tools.executor import InMemoryExecutionJobStore, ToolExecutor
from app.tools.registry import ToolRegistry
from tests.test_tools.tool_system_fixtures import (
    DEFAULT_SCOPE,
    RecordingAuditService,
)

EVENT_ID = "evt-react-0001"
GOAL = "补全证据缺口并确认外泄路径"
MAIN_CONTEXT = {
    "event_id": EVENT_ID,
    "scenario_id": "react_main",
    "observation": "alert: host 10.20.30.23 uploaded 2.3GB to unknown-upload-example.com",
    "gaps": "exfiltration path not yet corroborated",
}


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #


class ScriptedLLM:
    """Deterministic LLM stub serving queued think/reflect payloads."""

    def __init__(self) -> None:
        self.think_queue: list[ReActThinkOutput | Exception] = []
        self.reflect_queue: list[ReActReflectOutput | Exception] = []
        self.calls: list[dict[str, Any]] = []

    def add_round(self, think: ReActThinkOutput, reflect: ReActReflectOutput) -> None:
        self.think_queue.append(think)
        self.reflect_queue.append(reflect)

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        event_id: str,
        agent_name: str,
        prompt_key: str,
        scenario_id: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        json_mode: bool = False,
        response_model: type | None = None,
    ) -> LLMResponse:
        self.calls.append(
            {"prompt_key": prompt_key, "scenario_id": scenario_id, "event_id": event_id}
        )
        queue = self.think_queue if prompt_key == "react_think" else self.reflect_queue
        item: ReActThinkOutput | ReActReflectOutput | Exception
        if queue:
            item = queue.pop(0)
        elif prompt_key == "react_think":
            item = ReActThinkOutput(
                thought="default scripted finish",
                action=ReActAction(action_type=ReActActionType.FINISH, rationale="default"),
            )
        else:
            item = ReActReflectOutput(reflection="default", confidence=0.0)
        if isinstance(item, Exception):
            raise item
        return LLMResponse(
            content=item.model_dump_json(),
            parsed=item,
            model_name="scripted-model",
        )


class RecordingTraceSink:
    """In-memory ReActTraceSink capturing per-round trace payloads."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def log_trace(
        self,
        event_id: str,
        agent_name: str,
        input_data: Any,
        output_data: Any | None,
        status: str,
        started_at: Any,
        completed_at: Any | None,
        **kwargs: Any,
    ) -> str:
        self.entries.append(
            {
                "event_id": event_id,
                "agent_name": agent_name,
                "input_data": input_data,
                "output_data": output_data,
                "status": status,
            }
        )
        return f"trc-test-{len(self.entries):04d}"


def think_tool(tool_name: str, params: dict[str, Any] | None = None) -> ReActThinkOutput:
    return ReActThinkOutput(
        thought=f"need {tool_name}",
        action=ReActAction(
            action_type=ReActActionType.CALL_TOOL,
            target_name=tool_name,
            params=params or {"indicator": "203.0.113.88"},
            rationale="scripted",
        ),
        candidates=[tool_name],
    )


def think_agent(agent_name: str, params: dict[str, Any] | None = None) -> ReActThinkOutput:
    return ReActThinkOutput(
        thought=f"need agent {agent_name}",
        action=ReActAction(
            action_type=ReActActionType.CALL_AGENT,
            target_name=agent_name,
            params=params or {},
            rationale="scripted",
        ),
        candidates=[agent_name],
    )


def reflect(confidence: float, gap: str = "more") -> ReActReflectOutput:
    return ReActReflectOutput(
        reflection="scripted reflection",
        confidence=confidence,
        gap=gap,
        evidence_refs=["ev-x"],
    )


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@contextmanager
def bound_evidence_scope(projection: EvidenceProjection) -> Iterator[None]:
    """Bind the trusted event scope the orchestrator would bind in production.

    Query tools fail closed without it (GuardrailViolationError); the caller
    of the engine — not the engine — owns this binding.
    """
    with bind_evidence_projection(projection), bind_evidence_query_scope(DEFAULT_SCOPE):
        yield


@pytest.fixture
def trace_sink() -> RecordingTraceSink:
    return RecordingTraceSink()


@pytest.fixture
def mock_llm() -> MockLLMClient:
    return MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder())


@pytest.fixture
async def guarded_tool_executor(
    tool_registry: ToolRegistry,
    mock_provider: MockToolProvider,
    audit: RecordingAuditService,
    job_store: InMemoryExecutionJobStore,
) -> AsyncIterator[tuple[ToolExecutor, ConvergenceGuard]]:
    """ToolExecutor wired to a shared ConvergenceGuard (engine+executor counting)."""
    guard = ConvergenceGuard()

    async def instant_sleep(_delay: float) -> None:
        return None

    executor = ToolExecutor(
        registry=tool_registry,
        audit_service=audit,
        job_store=job_store,
        convergence_guard=guard,
        sleep=instant_sleep,
        provider_context=lambda: bind_mock_tool_provider(mock_provider),
    )
    yield executor, guard


# --------------------------------------------------------------------------- #
# Acceptance 1: mock main scenario converges in 3 rounds
# --------------------------------------------------------------------------- #


async def test_main_scenario_three_round_convergence(
    mock_llm: MockLLMClient,
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
    trace_sink: RecordingTraceSink,
    evidence_projection: EvidenceProjection,
) -> None:
    guard = ConvergenceGuard()
    engine = ReActEngine(mock_llm, convergence_guard=guard, trace_sink=trace_sink)
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    with bound_evidence_scope(evidence_projection):
        result = await engine.run(GOAL, dict(MAIN_CONTEXT), executor)

    assert result.stop_reason is ReActStopReason.CONFIDENCE_MET
    assert len(result.rounds) == 3
    assert result.final_confidence == pytest.approx(0.85)
    assert result.final_confidence >= CONFIDENCE_THRESHOLD

    # Golden design: threat intel → DNS → network flow.
    assert [r.action.target_name for r in result.rounds if r.action] == [
        "query_threat_intel",
        "query_dns",
        "query_network_flow",
    ]
    # Acceptance 2: every round fully populated.
    for round_ in result.rounds:
        assert round_.observation
        assert round_.thought
        assert round_.action is not None
        assert round_.action_result is not None
        assert round_.action_result["status"] == "success"
        assert round_.reflection
        assert 0.0 <= round_.confidence <= 1.0
    assert [r.round_index for r in result.rounds] == [1, 2, 3]
    assert len(result.outputs["action_results"]) == 3

    # Real tool dispatches happened, all query category, zero failures.
    assert audit.starts == 3
    assert all(row["tool_category"] == "query" for row in audit.rows.values())
    assert all(row["status"] == "success" for row in audit.rows.values())

    # Convergence guard counted the rounds but did not fire.
    state = guard.get_state(EVENT_ID)
    assert state.react_rounds == 3
    decision = await guard.should_stop(EVENT_ID)
    assert not decision.stop

    # Per-round traces carry an auditable decision_basis (ISSUE-028 projection).
    assert len(trace_sink.entries) == 3
    for entry in trace_sink.entries:
        assert entry["agent_name"] == "react_engine"
        assert entry["input_data"]["goal"] == GOAL
        assert entry["input_data"]["observation_summary"]
        basis = TraceProjection.decision_basis(entry["output_data"])
        assert basis["selected_action"]
        assert basis["confidence"] is not None
    last_basis = TraceProjection.decision_basis(trace_sink.entries[-1]["output_data"])
    assert last_basis["evidence_refs"] == ["ev-ti-001", "ev-dns-002", "ev-flow-003"]
    assert "query_network_flow" in last_basis["selected_action"]
    assert last_basis["confidence"] == pytest.approx(0.85)


# --------------------------------------------------------------------------- #
# Stop conditions
# --------------------------------------------------------------------------- #


async def test_max_rounds_truncation(
    tool_executor: ToolExecutor,
    evidence_projection: EvidenceProjection,
) -> None:
    llm = ScriptedLLM()
    for _ in range(5):
        llm.add_round(think_tool("query_threat_intel"), reflect(0.4))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    with bound_evidence_scope(evidence_projection):
        result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor, max_rounds=2)

    assert result.stop_reason is ReActStopReason.MAX_ROUNDS
    assert len(result.rounds) == 2
    assert result.final_confidence == pytest.approx(0.4)


async def test_finish_stops_early_with_mock_default_golden(
    mock_llm: MockLLMClient,
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
) -> None:
    # No scenario_id → default.json → LLM returns finish on round 1.
    engine = ReActEngine(mock_llm)
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.FINISHED
    assert len(result.rounds) == 1
    assert result.rounds[0].action is not None
    assert result.rounds[0].action.action_type is ReActActionType.FINISH
    assert result.rounds[0].action_result is None
    assert audit.starts == 0


async def test_null_action_stops_as_finished(tool_executor: ToolExecutor) -> None:
    llm = ScriptedLLM()
    llm.think_queue.append(ReActThinkOutput(thought="nothing to do", action=None))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.FINISHED
    assert len(result.rounds) == 1
    assert result.rounds[0].action is None
    assert result.rounds[0].action_result is None


async def test_budget_exhausted_stops_before_dispatch(
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
    evidence_projection: EvidenceProjection,
) -> None:
    llm = ScriptedLLM()
    for _ in range(4):
        llm.add_round(think_tool("query_threat_intel"), reflect(0.4))
    engine = ReActEngine(llm, tool_call_budget=1)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    with bound_evidence_scope(evidence_projection):
        result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor, max_rounds=5)

    assert result.stop_reason is ReActStopReason.BUDGET_EXHAUSTED
    assert len(result.rounds) == 2
    # Round 1 consumed the single allowed tool call; round 2 was gated pre-dispatch.
    assert result.rounds[0].action_result is not None
    assert result.rounds[1].action_result is None
    assert audit.starts == 1


async def test_convergence_guard_duplicate_tool_calls_forces_stop(
    guarded_tool_executor: tuple[ToolExecutor, ConvergenceGuard],
    audit: RecordingAuditService,
    evidence_projection: EvidenceProjection,
) -> None:
    executor, guard = guarded_tool_executor
    llm = ScriptedLLM()
    # LLM stubbornly repeats the same query with low confidence — without the
    # guard this would burn all max_rounds.
    for _ in range(10):
        llm.add_round(think_tool("query_threat_intel"), reflect(0.4))
    engine = ReActEngine(llm, convergence_guard=guard)  # type: ignore[arg-type]
    react_executor = ReadOnlyReActExecutor(executor, event_id=EVENT_ID)

    with bound_evidence_scope(evidence_projection):
        result = await engine.run(GOAL, {"event_id": EVENT_ID}, react_executor, max_rounds=10)

    assert result.stop_reason is ReActStopReason.CONVERGED
    assert result.outputs["convergence_reason"] == StopReason.DUPLICATE_TOOL_CALLS.value
    assert result.outputs["convergence_state"]["tool_call_signatures"]["query_threat_intel"] > 3
    assert len(result.rounds) < 10
    assert audit.starts == len(result.rounds)


async def test_convergence_guard_prefilled_global_steps_stop_immediately(
    tool_executor: ToolExecutor,
) -> None:
    guard = ConvergenceGuard()
    for _ in range(GLOBAL_MAX_STEPS - 1):
        await guard.record_step(EVENT_ID, "agent_retry")
    llm = ScriptedLLM()  # would finish on round 1 — but never gets there
    engine = ReActEngine(llm, convergence_guard=guard)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.CONVERGED
    assert result.outputs["convergence_reason"] == StopReason.GLOBAL_MAX_STEPS.value
    assert result.rounds == []
    assert llm.calls == []


# --------------------------------------------------------------------------- #
# LLM degradation (降级策略)
# --------------------------------------------------------------------------- #


async def test_llm_unavailable_returns_error_empty_result(
    tmp_path: Path,
    tool_executor: ToolExecutor,
) -> None:
    # Empty golden root → MockLLM raises LLMProviderError on the think call.
    client = MockLLMClient(
        golden_root=tmp_path,
        audit_recorder=InMemoryLLMCallAuditRecorder(),
    )
    engine = ReActEngine(client)
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.ERROR
    assert result.rounds == []
    assert result.final_confidence == 0.0
    assert "react_think" in result.outputs["stop_detail"]


async def test_reflect_failure_returns_error_after_round(
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
    evidence_projection: EvidenceProjection,
    trace_sink: RecordingTraceSink,
) -> None:
    llm = ScriptedLLM()
    llm.think_queue.append(think_tool("query_threat_intel"))
    llm.reflect_queue.append(LLMTimeoutError("reflect timed out"))
    engine = ReActEngine(llm, trace_sink=trace_sink)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    with bound_evidence_scope(evidence_projection):
        result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.ERROR
    assert "react_reflect" in result.outputs["stop_detail"]
    assert len(result.rounds) == 1
    # The action executed (and was audited) before the reflect step failed.
    assert audit.starts == 1
    assert result.rounds[0].action_result is not None
    # Even the reflect-failed round leaves an auditable trace (每轮写 agent_trace).
    assert len(trace_sink.entries) == 1
    assert "react_reflect_failed" in trace_sink.entries[0]["output_data"]["warnings"]


async def test_tool_failed_status_counts_toward_consecutive_failures(
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
) -> None:
    # Query tools fail closed without a bound event scope (GuardrailViolationError
    # → ToolExecutor FAILED result) — the engine must count those rounds as failed.
    llm = ScriptedLLM()
    for _ in range(3):
        llm.add_round(think_tool("query_threat_intel"), reflect(0.9))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    # Deliberately no bound_evidence_scope: dispatches happen but return FAILED.
    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor, max_rounds=5)

    assert result.stop_reason is ReActStopReason.ERROR
    assert len(result.rounds) == 2
    assert all(
        r.action_result is not None and r.action_result["status"] == "failed" for r in result.rounds
    )
    # Dispatches really happened (unlike the denial path) — failure was post-execution.
    assert audit.starts == 2


async def test_consecutive_failures_reset_on_success(
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
    evidence_projection: EvidenceProjection,
) -> None:
    llm = ScriptedLLM()
    # denied, success (low confidence), denied, denied → error only after the
    # second *consecutive* failure pair; a lone failure must not stop the loop.
    llm.add_round(think_tool("no_such_tool"), reflect(0.4))
    llm.add_round(think_tool("query_threat_intel"), reflect(0.5))
    llm.add_round(think_tool("block_ip"), reflect(0.4))
    llm.add_round(think_tool("isolate_host"), reflect(0.4))
    llm.add_round(think_tool("query_threat_intel"), reflect(0.9))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    with bound_evidence_scope(evidence_projection):
        result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor, max_rounds=5)

    assert result.stop_reason is ReActStopReason.ERROR
    assert len(result.rounds) == 4
    statuses = [r.action_result["status"] for r in result.rounds if r.action_result]
    assert statuses == [
        REACT_ACTION_DENIED,
        "success",
        REACT_ACTION_DENIED,
        REACT_ACTION_DENIED,
    ]
    # Only the single successful round dispatched a tool call.
    assert audit.starts == 1


# --------------------------------------------------------------------------- #
# Safety: illegal actions denied before any side effect
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", ["block_ip", "isolate_host"])
async def test_side_effect_tools_denied_with_zero_effects(
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
    target: str,
) -> None:
    llm = ScriptedLLM()
    for _ in range(3):
        llm.add_round(think_tool(target, {"ip": "10.20.30.23"}), reflect(0.9))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor, max_rounds=5)

    # Two consecutive denied rounds → early error stop (never confidence_met).
    assert result.stop_reason is ReActStopReason.ERROR
    assert len(result.rounds) == 2
    for round_ in result.rounds:
        assert round_.action_result is not None
        assert round_.action_result["status"] == REACT_ACTION_DENIED
    # Zero tool dispatches, zero external side effects.
    assert audit.starts == 0
    assert audit.rows == {}


async def test_response_agent_and_unlisted_agents_denied(
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
) -> None:
    llm = ScriptedLLM()
    for _ in range(3):
        llm.add_round(think_agent("ResponseAgent"), reflect(0.9))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.ERROR
    assert len(result.rounds) == 2
    assert all(
        r.action_result is not None and r.action_result["status"] == REACT_ACTION_DENIED
        for r in result.rounds
    )
    assert audit.starts == 0


async def test_unknown_tool_denied(
    tool_executor: ToolExecutor,
    audit: RecordingAuditService,
) -> None:
    llm = ScriptedLLM()
    for _ in range(3):
        llm.add_round(think_tool("no_such_tool"), reflect(0.5))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.ERROR
    assert result.rounds[0].action_result is not None
    assert result.rounds[0].action_result["status"] == REACT_ACTION_DENIED
    assert audit.starts == 0


async def test_executor_exception_counts_as_failed_round() -> None:
    class ExplodingExecutor:
        def __init__(self) -> None:
            self.calls = 0

        async def execute(self, action: ReActAction) -> dict[str, Any]:
            self.calls += 1
            raise RuntimeError("boom")

    llm = ScriptedLLM()
    for _ in range(3):
        llm.add_round(think_tool("query_threat_intel"), reflect(0.9))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ExplodingExecutor()

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)  # type: ignore[arg-type]

    assert result.stop_reason is ReActStopReason.ERROR
    assert len(result.rounds) == 2
    assert executor.calls == 2
    assert all(
        r.action_result is not None and r.action_result["status"] == "error" for r in result.rounds
    )


# --------------------------------------------------------------------------- #
# Whitelisted read-only agents
# --------------------------------------------------------------------------- #


async def test_whitelisted_read_only_agent_executes(
    tool_executor: ToolExecutor,
) -> None:
    invoked: list[dict[str, Any]] = []

    async def evidence_gap_probe(params: dict[str, Any]) -> dict[str, Any]:
        invoked.append(params)
        return {"status": "success", "agent_name": "evidence_gap_probe", "data": {"gaps": []}}

    llm = ScriptedLLM()
    llm.add_round(think_agent("evidence_gap_probe", {"focus": "dns"}), reflect(0.9, gap=""))
    engine = ReActEngine(llm)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(
        tool_executor,
        event_id=EVENT_ID,
        allowed_agents={"evidence_gap_probe": evidence_gap_probe},
    )

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.CONFIDENCE_MET
    assert invoked == [{"focus": "dns"}]
    assert result.rounds[0].action_result is not None
    assert result.rounds[0].action_result["status"] == "success"
    # describe_targets surfaces the whitelist for the think prompt.
    targets = executor.describe_targets()
    assert targets["read_only_agents"] == ["evidence_gap_probe"]
    assert "query_threat_intel" in targets["query_tools"]
    assert "block_ip" not in targets["query_tools"]


# --------------------------------------------------------------------------- #
# Trace audit detail
# --------------------------------------------------------------------------- #


async def test_finish_round_trace_has_no_evidence_refs(
    tool_executor: ToolExecutor,
    trace_sink: RecordingTraceSink,
) -> None:
    llm = ScriptedLLM()
    llm.think_queue.append(
        ReActThinkOutput(
            thought="done",
            action=ReActAction(action_type=ReActActionType.FINISH, rationale="enough"),
            candidates=["query_dns"],
        )
    )
    engine = ReActEngine(llm, trace_sink=trace_sink)  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)

    result = await engine.run(GOAL, {"event_id": EVENT_ID}, executor)

    assert result.stop_reason is ReActStopReason.FINISHED
    assert len(trace_sink.entries) == 1
    output = trace_sink.entries[0]["output_data"]
    assert output["selected_action"] == "finish:"
    assert output["candidate_actions"] == ["query_dns"]
    assert "evidence_refs" not in output
    # No hidden chain-of-thought / prompt material in the trace payload.
    assert "prompt" not in str(output).lower()


async def test_run_rejects_invalid_max_rounds(tool_executor: ToolExecutor) -> None:
    engine = ReActEngine(ScriptedLLM())  # type: ignore[arg-type]
    executor = ReadOnlyReActExecutor(tool_executor, event_id=EVENT_ID)
    with pytest.raises(ValueError, match="max_rounds"):
        await engine.run(GOAL, {"event_id": EVENT_ID}, executor, max_rounds=0)
