"""ISSUE-048 StateGraph unit and recovery tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest
from langgraph.checkpoint.memory import MemorySaver

from app.agents.planner_agent import PlannerAgent
from app.core.errors import InvalidStateTransitionError, ValidationError
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import (
    CollectionStatus,
    EffectStatus,
    EvidenceAgentInput,
    EvidenceOutput,
    ExecutionPlan,
    GraphAgentInput,
    GraphOutput,
    GraphSummary,
    GraphSummaryFeature,
    PlanBudget,
    PlanStep,
    ReportAgentInput,
    ReportPhaseStatus,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    RiskAssessment,
    ScoringMode,
    TriageResult,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
)
from app.models.context import EventContext
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionOwner,
    ExecutionSubstate,
    FinalVerdict,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.security_event import EventSummary
from app.models.workflow import TransitionContext, validate_transition
from app.orchestration.checkpointer import (
    CHECKPOINT_TTL_SECONDS,
    RedisCheckpointer,
    checkpoint_key_for_event,
)
from app.orchestration.graph_state import InvestigationState
from app.orchestration.replan_handler import MAX_REPLAN_COUNT
from app.orchestration.workflow_graph import (
    GRAPH_EXECUTABLE_AGENTS,
    NODE_APPROVAL,
    NODE_APPROVAL_WAIT,
    NODE_CLOSE,
    NODE_EXECUTE,
    NODE_FP_ADJUDICATION,
    NODE_GRAPH,
    NODE_HALT,
    NODE_MANUAL_HOLD,
    NODE_PLANNER,
    NODE_RAG,
    NODE_REPLAN,
    NODE_REPORT,
    NODE_RESPONSE,
    NODE_RISK,
    NODE_VERIFY,
    P0_GRAPH_NODE_TO_AGENT,
    P0_NODE_SEQUENCE,
    ROUTE_CLOSE,
    ROUTE_CONTINUE,
    ROUTE_EVIDENCE,
    ROUTE_EXECUTE,
    ROUTE_HALT,
    ROUTE_INVESTIGATE,
    ROUTE_MANUAL,
    ROUTE_REPLAN,
    ROUTE_REPORT,
    ROUTE_RESPONSE,
    ROUTE_TO_VERIFY,
    ROUTE_WAIT,
    ROUTE_WRITEBACK,
    _resolve_verify_writeback_status,
    _resolve_verify_writeback_statuses,
    build_investigation_graph,
    invoke_investigation_graph,
    route_after_approval,
    route_after_fp_adjudication,
    route_after_planner,
    route_after_report,
    route_after_risk,
    route_after_triage,
    route_after_verify,
    route_after_writeback_recovery,
)


def _base_state(**overrides: Any) -> InvestigationState:
    state: InvestigationState = {
        "event_id": "evt-graph-001",
        "event_status": EventStatus.TRIAGING.value,
        "disposition_policy": DispositionPolicy.NOT_REQUIRED.value,
        "severity": Severity.HIGH.value,
        "final_verdict": None,
        "confidence": 0.0,
        "need_investigation": True,
        "execution_substate": ExecutionSubstate.NONE.value,
        "event_status_update_readiness": WritebackReadiness.NOT_REQUIRED.value,
        "degraded_flags": [],
        "node_trace": [],
        "halted": False,
        "disposition_only_intent": False,
        "report_generated": False,
        "needs_approval_wait": False,
        "generate_report": True,
        "defer_response_execution": False,
    }
    state.update(overrides)
    return state


class StubAgent:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[Any] = []

    async def execute(self, input: Any) -> Any:
        self.calls.append(input)
        return self.result


class CapturingGraphAgent:
    """Returns distinct graph outputs per invocation (ISSUE-116 replan coverage)."""

    def __init__(self) -> None:
        self.calls: list[GraphAgentInput] = []

    async def execute(self, input: GraphAgentInput) -> GraphOutput:
        self.calls.append(input)
        call_no = len(self.calls)
        return GraphOutput(
            summary=GraphSummary(
                features=[
                    GraphSummaryFeature(
                        feature_id=f"graph_call_{call_no}",
                        feature_kind="attack_stage",
                        score_hint=40.0 + (10.0 * call_no),
                        evidence_ids=[f"evd-call-{call_no:02d}"],
                        provenance="graph_edge",
                    )
                ]
            )
        )


class FixedEvidencePlanPlanner:
    """Planner stub that returns a deterministic evidence subset plan."""

    async def execute(self, input: Any) -> ExecutionPlan:
        event_id = getattr(input, "event_id", "evt-graph-001")
        return ExecutionPlan(
            plan_id="pln-graph-evidence",
            event_id=event_id,
            steps=[
                PlanStep(
                    step_order=1,
                    step_goal="dns only",
                    assigned_agent="evidence_agent",
                    required_tools=["query_dns"],
                    success_criteria="ok",
                ),
                PlanStep(
                    step_order=2,
                    step_goal="risk",
                    assigned_agent="risk_agent",
                    required_tools=[],
                    success_criteria="ok",
                ),
                PlanStep(
                    step_order=3,
                    step_goal="response",
                    assigned_agent="response_agent",
                    required_tools=[],
                    success_criteria="ok",
                ),
                PlanStep(
                    step_order=4,
                    step_goal="report",
                    assigned_agent="report_agent",
                    required_tools=[],
                    success_criteria="ok",
                ),
            ],
            budget=PlanBudget(max_tool_calls=30),
            revision=0,
        )

    async def plan_disposition_only(self, event_context: EventContext) -> ExecutionPlan:
        event_id = event_context.event.event_id if event_context.event else "evt-graph-001"
        return ExecutionPlan(
            plan_id="pln-disposition-only",
            event_id=event_id,
            steps=[],
            revision=0,
        )


class CapturingEvidenceAgent:
    def __init__(self) -> None:
        self.calls: list[EvidenceAgentInput] = []

    async def execute(self, input: EvidenceAgentInput) -> EvidenceOutput:
        self.calls.append(input)
        return EvidenceOutput(collection_status=CollectionStatus.COMPLETED)


class ReplanOnceVerifyAgent:
    """First verify pass requests replan; second pass succeeds (ISSUE-062 e2e)."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    async def execute(self, input: Any) -> VerificationResult:
        self.calls.append(input)
        if len(self.calls) == 1:
            return VerificationResult(
                overall_status=VerificationOverallStatus.FAILED,
                verification_phase=VerificationPhase.EFFECT,
                need_action_replan=True,
                failed_actions=["act-failed-001"],
            )
        return VerificationResult(
            overall_status=VerificationOverallStatus.SUCCESS,
            verification_phase=VerificationPhase.EFFECT,
        )


class AlwaysFailVerifyAgent:
    """Every verify pass requests action replan (ISSUE-062 exhaustion e2e)."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    async def execute(self, input: Any) -> VerificationResult:
        self.calls.append(input)
        return VerificationResult(
            overall_status=VerificationOverallStatus.FAILED,
            verification_phase=VerificationPhase.EFFECT,
            need_action_replan=True,
            failed_actions=[f"act-failed-{len(self.calls):03d}"],
        )


class CapturingReportAgent:
    """Records ReportAgentInput for escalation assertions."""

    def __init__(self) -> None:
        self.calls: list[ReportAgentInput] = []

    async def execute(self, input: ReportAgentInput) -> SimpleNamespace:
        self.calls.append(input)
        return SimpleNamespace(report_id="rpt-capture")


def _agents_with_verify(verify_agent: Any, *, triage: TriageResult | None = None) -> dict[str, Any]:
    agents = _agents(triage=triage)
    agents["verify_agent"] = verify_agent
    return agents


def _agents_with_verify_and_report(
    verify_agent: Any,
    report_agent: Any,
    *,
    triage: TriageResult | None = None,
) -> dict[str, Any]:
    agents = _agents_with_verify(verify_agent, triage=triage)
    agents["report_agent"] = report_agent
    return agents


@dataclass
class FakeStateMachine:
    status: EventStatus = EventStatus.TRIAGING
    transitions: list[tuple[str, EventStatus, str | None]] = field(default_factory=list)
    statuses: dict[str, EventStatus] = field(default_factory=dict)

    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: Any = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> Any:
        current = self.statuses.get(event_id, EventStatus.TRIAGING)
        validate_transition(current, target, context or TransitionContext())
        self.transitions.append((event_id, target, reason))
        self.statuses[event_id] = target
        self.status = target
        return SimpleNamespace(event_id=event_id, status=target)

    async def get_current_status(self, event_id: str) -> EventStatus:
        return self.statuses.get(event_id, self.status)


class FakeEventService:
    def __init__(self) -> None:
        self.verdicts: list[FinalVerdict] = []
        self.context_snapshots: dict[str, dict[str, Any]] = {}

    async def set_final_verdict(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
    ) -> Any:
        self.verdicts.append(verdict)
        return SimpleNamespace(event_id=event_id, final_verdict=verdict)

    async def merge_report_generated_context_snapshot(
        self,
        event_id: str,
        generated: bool,
    ) -> None:
        self.context_snapshots.setdefault(event_id, {})["report_generated"] = generated

    async def merge_report_quality_context_snapshot(
        self,
        event_id: str,
        report_quality: str,
    ) -> None:
        self.context_snapshots.setdefault(event_id, {})["report_quality"] = report_quality

    async def merge_analysis_only_complete_context_snapshot(
        self,
        event_id: str,
        complete: bool,
    ) -> None:
        self.context_snapshots.setdefault(event_id, {})["analysis_only_complete"] = complete


class FakeRuntime:
    def __init__(
        self,
        readiness: WritebackReadiness = WritebackReadiness.NOT_REQUIRED,
    ) -> None:
        self.intent = False
        self.readiness = readiness
        self.begun: list[str] = []
        self.substates: list[ExecutionSubstate] = []

    async def get_event_status_update_readiness(
        self,
        event_id: str,
    ) -> WritebackReadiness:
        return self.readiness

    async def begin_disposition_only(self, event_id: str) -> None:
        self.begun.append(event_id)
        self.intent = True

    async def read_disposition_only_intent(self, event_id: str) -> bool:
        return self.intent

    async def set_execution_substate(
        self,
        event_id: str,
        substate: ExecutionSubstate,
        *,
        event_status: EventStatus,
    ) -> None:
        self.substates.append(substate)

    async def assert_disposition_only_transition_allowed(
        self,
        event_id: str,
        *,
        current: EventStatus,
        target: EventStatus,
    ) -> None:
        assert self.intent is True


class FakeDegradedFlags:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any, str]] = []

    async def set_flag(
        self,
        event_id: str,
        flag_name: str,
        value: Any,
        writer: str,
    ) -> list[str]:
        self.calls.append((event_id, flag_name, value, writer))
        return [f"{flag_name}={value}"]


class FakeContextStore:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], Any] = {}

    async def get_full_context(self, event_id: str) -> EventContext:
        return EventContext()

    async def get(self, event_id: str, key: str) -> Any:
        return self.data.get((event_id, key))

    async def set(self, event_id: str, key: str, value: Any, **_kwargs: Any) -> None:
        self.data[(event_id, key)] = value


class FakeRedisStore:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str) -> bytes | None:
        return self.values.get(key)

    async def set(self, key: str, value: bytes, *, ex: int | None = None) -> None:
        self.values[key] = value
        if ex is not None:
            self.ttls[key] = ex

    async def incr(self, key: str) -> int:
        generation = int(self.values.get(key, b"0")) + 1
        self.values[key] = str(generation).encode()
        return generation

    async def expire(self, key: str, seconds: int) -> bool:
        self.ttls[key] = seconds
        return True

    async def eval(self, script: str, numkeys: int, *args: object) -> int:
        del numkeys
        if "checkpoint-reserve-generation-v3" in script:
            sequence_key, generation_key, ttl, expected = args
            assert isinstance(sequence_key, str)
            assert isinstance(generation_key, str)
            assert isinstance(ttl, int)
            assert isinstance(expected, int)
            current = int(self.values.get(generation_key, b"0"))
            if expected >= 0 and current != expected:
                return -1
            generation = int(self.values.get(sequence_key, b"0")) + 1
            self.values[sequence_key] = str(generation).encode()
            await self.set(generation_key, str(generation).encode(), ex=ttl)
            return generation
        if "checkpoint-reserve-generation-v2" in script:
            sequence_key, generation_key, _ttl = args
            assert isinstance(sequence_key, str)
            assert isinstance(generation_key, str)
            generation = int(self.values.get(sequence_key, b"0")) + 1
            self.values[sequence_key] = str(generation).encode()
            self.values[generation_key] = str(generation).encode()
            return generation
        assert "checkpoint-publish-v2" in script
        checkpoint_key, generation_key, generation, value, ttl = args
        assert isinstance(checkpoint_key, str)
        assert isinstance(generation_key, str)
        assert isinstance(generation, int)
        assert isinstance(value, bytes)
        assert isinstance(ttl, int)
        if int(self.values.get(generation_key, b"0")) != generation:
            return 0
        await self.set(checkpoint_key, value, ex=ttl)
        return 1

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)


class FakeRedisClient:
    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.store = FakeRedisStore()

    async def ping(self) -> bool:
        return self.available

    def get_client(self) -> FakeRedisStore:
        return self.store


def _agents(*, triage: TriageResult | None = None) -> dict[str, Any]:
    triage_result = triage or TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="investigate",
    )
    return {
        "triage_agent": StubAgent(triage_result),
        "planner_agent": PlannerAgent(),
        "evidence_agent": StubAgent(EvidenceOutput(collection_status=CollectionStatus.COMPLETED)),
        "risk_agent": StubAgent(
            RiskAssessment(
                risk_score=80,
                severity=Severity.HIGH,
                confidence=0.9,
                scoring_mode=ScoringMode.RULE_ONLY,
            )
        ),
        "report_agent": StubAgent(SimpleNamespace(report_id="rpt-stub")),
        "verify_agent": StubAgent(
            VerificationResult(
                overall_status=VerificationOverallStatus.SUCCESS,
                verification_phase=VerificationPhase.EFFECT,
            )
        ),
        # ISSUE-218: default to a fully wired DI so golden-path tests exercise
        # the real closed loop instead of the (now fail-closed) stub nodes.
        "response_agent": StubAgent(
            ResponsePlan(
                plan_id="plan-default",
                actions=[],
                strategy_summary="stub",
                generated_by=ResponsePlanGeneratedBy.TEMPLATE,
            )
        ),
    }


def _agents_without_response_agent(*, triage: TriageResult | None = None) -> dict[str, Any]:
    """Full agent set minus response_agent — for ISSUE-218 fail-closed tests."""
    agents = _agents(triage=triage)
    agents.pop("response_agent", None)
    return agents


def _services(
    state_machine: FakeStateMachine | None = None,
    *,
    runtime: FakeRuntime | None = None,
) -> dict[str, Any]:
    return {
        "state_machine": state_machine or FakeStateMachine(),
        "event_service": FakeEventService(),
        "workflow_runtime": runtime or FakeRuntime(),
        "degraded_flags": FakeDegradedFlags(),
        "context_store": FakeContextStore(),
        # ISSUE-218: default to a fully wired DI so golden-path tests exercise
        # the real closed loop instead of the (now fail-closed) stub nodes.
        "approval_engine": FakeApprovalEngine(needs_wait=False, evaluated_count=0),
        "action_execution": FakeActionExecution(),
    }


class TestResolveVerifyWritebackStatus:
    def _result(
        self,
        *,
        failed_writebacks: list[str],
        results: list[VerificationActionResult],
    ) -> VerificationResult:
        return VerificationResult(
            overall_status=VerificationOverallStatus.FAILED,
            verification_phase=VerificationPhase.EFFECT,
            failed_writebacks=failed_writebacks,
            results=results,
        )

    def _action(
        self,
        *,
        writeback_ids: list[str],
        writeback_status: WritebackStatus | None,
    ) -> VerificationActionResult:
        return VerificationActionResult(
            action_id="act-001",
            effect_status=EffectStatus.FAILED,
            writeback_required=writeback_status is not None,
            writeback_readiness=(
                WritebackReadiness.READY
                if writeback_status is not None
                else WritebackReadiness.NOT_REQUIRED
            ),
            writeback_status=writeback_status,
            writeback_ids=writeback_ids,
        )

    def test_matches_failed_writeback_id(self) -> None:
        result = self._result(
            failed_writebacks=["wbk-target"],
            results=[
                self._action(
                    writeback_ids=["wbk-target"],
                    writeback_status=WritebackStatus.PENDING,
                )
            ],
        )
        assert _resolve_verify_writeback_status(result) == "pending"

    def test_no_fallback_when_id_mismatch(self) -> None:
        """ISSUE-062: do not borrow another writeback's status on ID mismatch."""
        result = self._result(
            failed_writebacks=["wbk-target"],
            results=[
                self._action(
                    writeback_ids=["wbk-other"],
                    writeback_status=WritebackStatus.CONFLICT,
                )
            ],
        )
        assert _resolve_verify_writeback_status(result) is None

    def test_status_map_covers_each_heterogeneous_writeback(self) -> None:
        """ISSUE-170: every failed writeback gets its OWN status in the map."""
        result = self._result(
            failed_writebacks=["wbk-001", "wbk-002"],
            results=[
                self._action(
                    writeback_ids=["wbk-001"],
                    writeback_status=WritebackStatus.UNKNOWN,
                ),
                self._action(
                    writeback_ids=["wbk-002"],
                    writeback_status=WritebackStatus.CONFLICT,
                ),
            ],
        )
        statuses = _resolve_verify_writeback_statuses(result)
        assert statuses == {"wbk-001": "unknown", "wbk-002": "conflict"}

    def test_status_map_none_without_failed_writebacks(self) -> None:
        result = self._result(
            failed_writebacks=[],
            results=[
                self._action(
                    writeback_ids=["wbk-001"],
                    writeback_status=WritebackStatus.CONFLICT,
                )
            ],
        )
        assert _resolve_verify_writeback_statuses(result) is None

    def test_status_map_skips_writebacks_without_status(self) -> None:
        """Writebacks without a reported status are left out of the map."""
        result = self._result(
            failed_writebacks=["wbk-001"],
            results=[
                self._action(
                    writeback_ids=["wbk-001"],
                    writeback_status=None,
                )
            ],
        )
        assert _resolve_verify_writeback_statuses(result) is None

    def test_status_map_uses_latest_status_on_duplicate_writeback_id(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Duplicate writeback_id entries keep the latest status and log a warning."""
        import logging

        result = self._result(
            failed_writebacks=["wbk-dup"],
            results=[
                self._action(
                    writeback_ids=["wbk-dup"],
                    writeback_status=WritebackStatus.UNKNOWN,
                ),
                self._action(
                    writeback_ids=["wbk-dup"],
                    writeback_status=WritebackStatus.CONFLICT,
                ),
            ],
        )
        graph_logger = logging.getLogger("app.orchestration.workflow_graph")
        graph_logger.disabled = False
        graph_logger.propagate = True
        with caplog.at_level(
            logging.WARNING,
            logger="app.orchestration.workflow_graph",
        ):
            statuses = _resolve_verify_writeback_statuses(result)
        assert statuses == {"wbk-dup": "conflict"}
        assert "conflicting status for wbk-dup" in caplog.text


class TestRouteAfterTriage:
    def test_not_required_no_investigation_closes(self) -> None:
        assert route_after_triage(_base_state(need_investigation=False)) == ROUTE_CLOSE

    def test_not_required_no_investigation_routes_report_when_generate_report_false(
        self,
    ) -> None:
        assert (
            route_after_triage(_base_state(need_investigation=False, generate_report=False))
            == ROUTE_REPORT
        )

    def test_pre_evidence_fp_does_not_close_at_triage(self) -> None:
        state = _base_state(
            false_positive_match={"recommendation": "close_as_fp", "phase": "pre_evidence"}
        )
        assert route_after_triage(state) == ROUTE_INVESTIGATE

    @pytest.mark.parametrize(
        "state",
        [
            _base_state(need_investigation=True),
            _base_state(
                disposition_policy=DispositionPolicy.REQUIRED.value,
                need_investigation=False,
            ),
        ],
    )
    def test_other_paths_investigate(self, state: InvestigationState) -> None:
        assert route_after_triage(state) == ROUTE_INVESTIGATE


class TestRouteAfterFpAdjudication:
    def test_always_continues_investigation(self) -> None:
        assert route_after_fp_adjudication(_base_state()) == ROUTE_CONTINUE
        assert (
            route_after_fp_adjudication(
                _base_state(
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    fp_adjudication={"recommendation": "close_as_fp"},
                )
            )
            == ROUTE_CONTINUE
        )


def test_remaining_route_truth_tables() -> None:
    assert route_after_planner(_base_state(disposition_only_intent=True)) == ROUTE_RESPONSE
    assert route_after_planner(_base_state()) == ROUTE_EVIDENCE
    assert route_after_risk(_base_state()) == ROUTE_RESPONSE
    assert route_after_risk(_base_state(defer_response_execution=True)) == ROUTE_REPORT
    assert (
        route_after_risk(
            _base_state(
                defer_response_execution=True,
                disposition_only_intent=True,
            )
        )
        == ROUTE_RESPONSE
    )
    assert (
        route_after_report(_base_state(disposition_policy=DispositionPolicy.REQUIRED.value))
        == ROUTE_HALT
    )
    assert (
        route_after_report(
            _base_state(
                disposition_policy=DispositionPolicy.REQUIRED.value,
                verify_overall_status=VerificationOverallStatus.SUCCESS.value,
            )
        )
        == ROUTE_CLOSE
    )
    assert route_after_report(_base_state()) == ROUTE_CLOSE
    assert route_after_report(_base_state(generate_report=False)) == ROUTE_HALT
    assert (
        route_after_approval(
            _base_state(execution_substate=ExecutionSubstate.WAITING_APPROVAL.value)
        )
        == ROUTE_WAIT
    )
    assert route_after_approval(_base_state()) == ROUTE_EXECUTE
    assert (
        route_after_approval(_base_state(event_status=EventStatus.REPORTING.value)) == ROUTE_REPORT
    )
    assert route_after_verify(_base_state(verify_need_manual_resolution=True)) == ROUTE_MANUAL
    assert route_after_verify(_base_state(verify_need_writeback_recovery=True)) == ROUTE_WRITEBACK
    assert route_after_verify(_base_state(verify_need_action_replan=True)) == ROUTE_REPLAN
    # ISSUE-062 truth table: disposition_only / required with all three flags
    # false → overall success → REPORT (not HALT).  Deferred writeback waiting
    # is handled via verify_need_writeback_recovery.
    assert route_after_verify(_base_state(disposition_only_intent=True)) == ROUTE_REPORT
    assert (
        route_after_verify(_base_state(disposition_policy=DispositionPolicy.REQUIRED.value))
        == ROUTE_REPORT
    )
    assert route_after_verify(_base_state()) == ROUTE_REPORT
    assert route_after_verify(_base_state(halted=True)) == ROUTE_HALT
    assert (
        route_after_writeback_recovery(_base_state(verify_need_writeback_recovery=True))
        == ROUTE_WRITEBACK
    )
    assert route_after_writeback_recovery(_base_state()) == ROUTE_TO_VERIFY


@pytest.mark.asyncio
async def test_graph_compiles_and_golden_path_order() -> None:
    """not_required full investigation path runs P0 sequence and closes."""
    machine = FakeStateMachine()
    services = _services(machine)
    graph = build_investigation_graph(_agents(), services)
    assert NODE_RAG not in graph.get_graph().nodes

    final = await graph.ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-graph-001"}},
    )
    trace = final["node_trace"]
    assert tuple(trace) == P0_NODE_SEQUENCE
    assert machine.status is EventStatus.CLOSED
    assert services["event_service"].verdicts == []


@pytest.mark.asyncio
async def test_graph_node_passes_graph_output_to_risk() -> None:
    """ISSUE-116: pre-risk graph output is typed into RiskAgentInput."""
    graph_output = GraphOutput(
        summary=GraphSummary(
            features=[
                GraphSummaryFeature(
                    feature_id="attack_path_0",
                    feature_kind="attack_path",
                    score_hint=60.0,
                    evidence_ids=["evd-00000001"],
                    provenance="graph_path",
                )
            ]
        )
    )
    graph_stub = StubAgent(graph_output)
    risk_stub = StubAgent(
        RiskAssessment(
            risk_score=80,
            severity=Severity.HIGH,
            confidence=0.9,
            scoring_mode=ScoringMode.RULE_ONLY,
        )
    )
    agents = _agents()
    agents["graph_agent"] = graph_stub
    agents["risk_agent"] = risk_stub
    graph = build_investigation_graph(agents, _services(FakeStateMachine()))
    await graph.ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-graph-002"}},
    )
    assert len(graph_stub.calls) == 1
    assert len(risk_stub.calls) == 1
    assert risk_stub.calls[0].graph_output is not None
    assert NODE_GRAPH in graph.get_graph().nodes


@pytest.mark.asyncio
async def test_graph_replan_one_cycle_then_success() -> None:
    """ISSUE-062: effect verification failure triggers one replan cycle then CLOSED."""
    verify_agent = ReplanOnceVerifyAgent()
    machine = FakeStateMachine()
    services = _services(machine)
    final = await build_investigation_graph(
        _agents_with_verify(verify_agent),
        services,
    ).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-replan-once"}},
    )
    trace = final["node_trace"]

    assert NODE_REPLAN in trace
    assert trace.count(NODE_VERIFY) == 2
    assert final["replan_count"] == 1
    assert final["escalated"] is False
    assert NODE_CLOSE in trace
    assert len(verify_agent.calls) == 2
    assert machine.status is EventStatus.CLOSED


@pytest.mark.asyncio
async def test_graph_node_recomputes_on_replan_cycle() -> None:
    """ISSUE-116: replan loops back through graph_node instead of skipping stale graph."""
    graph_agent = CapturingGraphAgent()
    verify_agent = ReplanOnceVerifyAgent()
    machine = FakeStateMachine()
    services = _services(machine)
    agents = _agents_with_verify(verify_agent)
    agents["graph_agent"] = graph_agent
    final = await build_investigation_graph(agents, services).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-graph-replan"}},
    )

    assert NODE_REPLAN in final["node_trace"]
    assert len(graph_agent.calls) == 2
    assert graph_agent.calls[0].event_id == "evt-graph-001"
    assert graph_agent.calls[1].event_id == "evt-graph-001"


@pytest.mark.asyncio
async def test_graph_replan_exhaustion_escalates() -> None:
    """ISSUE-062: three replan cycles then escalation → report with human note."""
    verify_agent = AlwaysFailVerifyAgent()
    report_agent = CapturingReportAgent()
    machine = FakeStateMachine()
    services = _services(machine)
    final = await build_investigation_graph(
        _agents_with_verify_and_report(verify_agent, report_agent),
        services,
    ).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-replan-exhaust"}},
    )
    trace = final["node_trace"]

    assert trace.count(NODE_VERIFY) == MAX_REPLAN_COUNT + 1
    assert trace.count(NODE_REPLAN) == MAX_REPLAN_COUNT + 1
    assert final["replan_count"] == MAX_REPLAN_COUNT
    assert final["escalated"] is True
    assert NODE_REPORT in trace
    assert NODE_CLOSE in trace
    assert len(report_agent.calls) == 1
    assert report_agent.calls[0].escalated is True
    assert report_agent.calls[0].replan_count == MAX_REPLAN_COUNT
    failed_transitions = [
        target for _event_id, target, _reason in machine.transitions if target is EventStatus.FAILED
    ]
    assert failed_transitions, "escalation must transition through FAILED before report"
    assert machine.status is EventStatus.CLOSED


@pytest.mark.asyncio
async def test_optional_rag_is_between_evidence_and_risk() -> None:
    agents = _agents()
    agents["rag_agent"] = StubAgent(None)
    graph = build_investigation_graph(agents, _services())
    graph_view = graph.get_graph()
    assert NODE_RAG in graph_view.nodes
    edges = {(edge.source, edge.target) for edge in graph_view.edges}
    assert ("evidence_node", NODE_FP_ADJUDICATION) in edges
    assert (NODE_FP_ADJUDICATION, NODE_RAG) in edges
    assert (NODE_RAG, NODE_GRAPH) in edges
    assert (NODE_GRAPH, NODE_RISK) in edges


@pytest.mark.asyncio
async def test_not_required_short_circuit_generates_report_and_closes() -> None:
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="no investigation",
    )
    agents = _agents(triage=triage)
    services = _services()
    final = await build_investigation_graph(agents, services).ainvoke(
        _base_state(need_investigation=False, severity=Severity.LOW.value),
        {"configurable": {"thread_id": "evt-short"}},
    )
    assert final["node_trace"] == ["triage_node", NODE_CLOSE]
    assert final["report_generated"] is True
    assert services["event_service"].verdicts == [FinalVerdict.NONE]


@pytest.mark.asyncio
async def test_not_required_short_circuit_from_new_reaches_closed() -> None:
    """Investigate HTTP path starts at NEW; triage must reach TRIAGING then CLOSED."""
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="no investigation",
    )
    machine = FakeStateMachine()
    event_id = "evt-short-new"
    machine.statuses[event_id] = EventStatus.NEW
    machine.status = EventStatus.NEW
    services = _services(machine)
    final = await build_investigation_graph(_agents(triage=triage), services).ainvoke(
        _base_state(
            event_id=event_id,
            event_status=EventStatus.NEW.value,
            need_investigation=False,
            severity=Severity.LOW.value,
        ),
        {"configurable": {"thread_id": event_id}},
    )
    assert final["node_trace"] == ["triage_node", NODE_CLOSE]
    assert machine.status is EventStatus.CLOSED
    assert (event_id, EventStatus.TRIAGING, "investigation:triage_start") in machine.transitions


@pytest.mark.asyncio
async def test_evidence_node_passes_execution_plan_required_tools() -> None:
    """ISSUE-115: workflow evidence_node wires plan tools into EvidenceAgentInput."""
    capturing = CapturingEvidenceAgent()
    triage = TriageResult(
        event_type=EventType.SUSPICIOUS_DOMAIN,
        severity=Severity.MEDIUM,
        need_investigation=True,
        reasoning="workflow plan wiring",
    )
    agents = _agents(triage=triage)
    agents["planner_agent"] = FixedEvidencePlanPlanner()
    agents["evidence_agent"] = capturing
    final = await build_investigation_graph(agents, _services()).ainvoke(
        _base_state(
            triage_result=triage.model_dump(mode="json"),
            defer_response_execution=True,
        ),
        {"configurable": {"thread_id": "evt-graph-evidence-plan"}},
    )
    assert "evidence_node" in final["node_trace"]
    assert capturing.calls
    call = capturing.calls[0]
    assert "query_dns" in call.required_tools
    assert call.plan_step_goal == "dns only"
    assert isinstance(call.execution_plan, dict)
    assert call.execution_plan.get("plan_id") == "pln-graph-evidence"


@pytest.mark.asyncio
async def test_defer_path_skips_report_agent_when_generate_report_false() -> None:
    """ISSUE-204: defer investigate with generate_report=false must not call ReportAgent."""
    machine = FakeStateMachine()
    services = _services(machine)
    agents = _agents()
    report_agent = agents["report_agent"]
    final = await build_investigation_graph(agents, services).ainvoke(
        _base_state(
            defer_response_execution=True,
            generate_report=False,
        ),
        {"configurable": {"thread_id": "evt-defer-no-report"}},
    )
    assert NODE_REPORT in final["node_trace"]
    assert report_agent.calls == []
    assert final["report_generated"] is False
    assert final["halted"] is True
    assert machine.status is EventStatus.REPORTING


@pytest.mark.asyncio
async def test_deferred_response_not_required_reaches_closed() -> None:
    """ISSUE-566: HTTP investigate defers response execution and closes."""
    machine = FakeStateMachine()
    services = _services(machine)
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(defer_response_execution=True),
        {"configurable": {"thread_id": "evt-defer-not-required"}},
    )
    assert final["node_trace"] == [
        "triage_node",
        NODE_PLANNER,
        "evidence_node",
        NODE_FP_ADJUDICATION,
        NODE_GRAPH,
        NODE_RISK,
        NODE_REPORT,
        NODE_CLOSE,
    ]
    assert machine.status is EventStatus.CLOSED


@pytest.mark.asyncio
async def test_deferred_response_required_stays_reporting() -> None:
    """ISSUE-566: required-policy HTTP investigate halts at REPORTING."""
    machine = FakeStateMachine()
    services = _services(machine)
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            defer_response_execution=True,
        ),
        {"configurable": {"thread_id": "evt-defer-required"}},
    )
    assert final["node_trace"] == [
        "triage_node",
        NODE_PLANNER,
        "evidence_node",
        NODE_FP_ADJUDICATION,
        NODE_GRAPH,
        NODE_RISK,
        NODE_REPORT,
        NODE_HALT,
    ]
    assert machine.status is EventStatus.REPORTING
    assert final["halted"] is True


@pytest.mark.asyncio
async def test_required_threat_never_enters_disposition_only() -> None:
    """REQUIRED non-FP threat without a response_agent fails closed.

    ISSUE-218: a missing response agent must not fabricate progress.  A
    required-policy event without a response_agent previously advanced to
    WAITING_APPROVAL (and later escalated at verify_node); now it halts
    immediately at response_node with FAILED + a response_agent_miswired
    degraded flag.  The disposition-only shortcut is never taken.
    """
    runtime = FakeRuntime(WritebackReadiness.READY)
    services = _services(runtime=runtime)
    final = await build_investigation_graph(
        _agents_without_response_agent(),
        services,
    ).ainvoke(
        _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            event_status_update_readiness=WritebackReadiness.READY.value,
        ),
        {"configurable": {"thread_id": "evt-threat"}},
    )
    assert runtime.begun == []
    assert final["halted"] is True
    assert final["event_status"] == EventStatus.FAILED.value
    assert final["node_trace"][-1] == NODE_HALT
    assert any("response_agent_miswired" in f for f in final.get("degraded_flags", []))
    degraded = services["degraded_flags"]
    assert any(call[3] == "InvestigationGraph" for call in getattr(degraded, "calls", []))


@pytest.mark.asyncio
async def test_required_golden_path_order_halts_at_verify() -> None:
    """P0 main-chain order through response, then fail-closed on missing agent.

    ISSUE-218: without a response_agent the graph must not silently advance
    past response.  It transitions to FAILED and halts (previously it
    continued to WAITING_APPROVAL and verify_node escalated to
    MANUAL_RESOLUTION only because no response_plan existed).
    """
    final = await build_investigation_graph(
        _agents_without_response_agent(),
        _services(runtime=FakeRuntime(WritebackReadiness.READY)),
    ).ainvoke(
        _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            event_status_update_readiness=WritebackReadiness.READY.value,
        ),
        {"configurable": {"thread_id": "evt-required-golden"}},
    )
    assert final["halted"] is True
    assert final["event_status"] == EventStatus.FAILED.value
    assert final["node_trace"][-1] == NODE_HALT
    assert any("response_agent_miswired" in f for f in final.get("degraded_flags", []))


@pytest.mark.asyncio
async def test_required_post_evidence_fp_stays_reporting_without_auto_close() -> None:
    """REQUIRED + post-evidence FP continues through analysis and halts at REPORTING."""
    first_graph = build_investigation_graph(_agents(), _services())
    second_graph = build_investigation_graph(_agents(), _services())
    initial = _base_state(
        disposition_policy=DispositionPolicy.REQUIRED.value,
        fp_adjudication={"recommendation": "close_as_fp", "matched_window_id": "cw-test"},
        defer_response_execution=True,
        evidence_output={
            "evidence_list": [],
            "conflicts": [],
            "gaps": [],
            "success_sources": [],
            "failed_sources": [],
            "overall_confidence": 0.0,
            "collection_status": CollectionStatus.COMPLETED.value,
        },
        triage_result=TriageResult(
            event_type=EventType.ACCOUNT_ANOMALY,
            severity=Severity.MEDIUM,
            need_investigation=True,
            reasoning="fp after evidence",
        ).model_dump(mode="json"),
    )
    first = await first_graph.ainvoke(
        initial,
        {"configurable": {"thread_id": "evt-fp-a"}},
    )
    second = await second_graph.ainvoke(
        initial,
        {"configurable": {"thread_id": "evt-fp-b"}},
    )

    assert first["node_trace"] == second["node_trace"]
    assert NODE_FP_ADJUDICATION in first["node_trace"]
    assert "begin_disposition_only_node" not in first["node_trace"]
    assert NODE_CLOSE not in first["node_trace"]
    assert first["node_trace"][-2:] == [NODE_REPORT, NODE_HALT]
    assert first["event_status"] == EventStatus.REPORTING.value
    assert first["halted"] is True


@pytest.mark.asyncio
async def test_required_post_evidence_fp_does_not_shortcut_to_manual_hold() -> None:
    """Post-evidence FP no longer routes to manual_hold before analysis completes."""
    degraded = FakeDegradedFlags()
    services = _services(runtime=FakeRuntime(WritebackReadiness.CAPABILITY_UNSUPPORTED))
    services["degraded_flags"] = degraded
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            fp_adjudication={"recommendation": "close_as_fp"},
            defer_response_execution=True,
            event_status_update_readiness=WritebackReadiness.CAPABILITY_UNSUPPORTED.value,
            evidence_output={
                "evidence_list": [],
                "conflicts": [],
                "gaps": [],
                "success_sources": [],
                "failed_sources": [],
                "overall_confidence": 0.0,
                "collection_status": CollectionStatus.COMPLETED.value,
            },
            triage_result=TriageResult(
                event_type=EventType.ACCOUNT_ANOMALY,
                severity=Severity.MEDIUM,
                need_investigation=True,
                reasoning="fp after evidence",
            ).model_dump(mode="json"),
        ),
        {"configurable": {"thread_id": "evt-blocked"}},
    )
    assert NODE_MANUAL_HOLD not in final["node_trace"]
    assert final["node_trace"][-2:] == [NODE_REPORT, NODE_HALT]
    assert final["event_status"] == EventStatus.REPORTING.value


@pytest.mark.asyncio
async def test_forged_disposition_only_intent_is_rejected() -> None:
    runtime = FakeRuntime()
    graph = build_investigation_graph(_agents(), _services(runtime=runtime))
    with pytest.raises(InvalidStateTransitionError):
        await graph.ainvoke(
            _base_state(disposition_only_intent=True),
            {"configurable": {"thread_id": "evt-forged"}},
        )


@pytest.mark.asyncio
async def test_disposition_only_prebuilt_plan_routes_through_execute_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-288: disposition_only skips ResponseAgent but continues the graph."""
    prebuilt_action = Action.model_validate(
        {
            "action_id": "act-disp-only-prebuilt",
            "event_id": "evt-disp-only-graph",
            "plan_revision": 1,
            "action_fingerprint": "fp-disp-only-prebuilt",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "update_source_event_disposition",
            "tool_name": TERMINAL_DISPOSITION_TOOL,
            "action_level": ActionLevel.L2,
            "execution_phase": ActionExecutionPhase.POST_VERIFY,
            "activation_condition": "after_effect_resolution",
            "approved_operation_template_hash": "hash-ignored",
            "approved_terminal_dispositions": ["ignored"],
            "status": ActionStatus.APPROVED,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "reason": "disposition_only prebuilt",
        }
    )

    async def _fake_load(_session_factory: object, event_id: str) -> tuple[ResponsePlan, int]:
        plan = ResponsePlan(
            plan_id="plan-disp-only",
            actions=[prebuilt_action.model_copy(update={"event_id": event_id})],
            strategy_summary="prebuilt deferred terminal writeback",
            generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        )
        return plan, 1

    monkeypatch.setattr(
        "app.orchestration.workflow_graph._load_prebuilt_disposition_response_plan",
        _fake_load,
    )

    runtime = FakeRuntime(WritebackReadiness.READY)
    runtime.intent = True
    action_execution = FakeActionExecution()
    machine = FakeStateMachine(
        status=EventStatus.PLANNING_RESPONSE,
        statuses={"evt-disp-only-graph": EventStatus.PLANNING_RESPONSE},
    )
    services = _services(machine, runtime=runtime)
    services["session_factory"] = object()
    services["approval_engine"] = FakeApprovalEngine(needs_wait=False, evaluated_count=1)
    services["action_execution"] = action_execution

    redis = MemorySaver()
    graph = build_investigation_graph(
        _agents_without_response_agent(),
        services,
        checkpointer=redis,
        interrupt_after=[NODE_VERIFY],
    )
    config = {"configurable": {"thread_id": "evt-disp-only-graph"}}
    initial = _base_state(
        event_id="evt-disp-only-graph",
        disposition_policy=DispositionPolicy.REQUIRED.value,
        disposition_only_intent=True,
        final_verdict=FinalVerdict.FALSE_POSITIVE.value,
        event_status=EventStatus.PLANNING_RESPONSE.value,
        event_status_update_readiness=WritebackReadiness.READY.value,
        execution_plan={
            "plan_id": "pln-disp-only",
            "event_id": "evt-disp-only-graph",
            "steps": [],
            "revision": 0,
        },
    )
    await graph.aupdate_state(config, initial, as_node=NODE_PLANNER)
    final = await invoke_investigation_graph(graph, None, config)

    trace = final["node_trace"]
    assert NODE_RESPONSE in trace
    assert trace.index(NODE_RESPONSE) < trace.index(NODE_APPROVAL)
    assert NODE_EXECUTE in trace
    assert NODE_VERIFY in trace
    assert trace.index(NODE_EXECUTE) < trace.index(NODE_VERIFY)
    assert final.get("halted") is not True
    assert action_execution.calls == [("evt-disp-only-graph", 1)]
    assert final.get("response_plan") is not None


@pytest.mark.asyncio
async def test_disposition_only_missing_prebuilt_action_halts_at_response() -> None:
    """ISSUE-288: disposition_only without a trusted prebuilt Action fails closed."""
    runtime = FakeRuntime(WritebackReadiness.READY)
    runtime.intent = True
    machine = FakeStateMachine(
        status=EventStatus.PLANNING_RESPONSE,
        statuses={"evt-disp-only-missing": EventStatus.PLANNING_RESPONSE},
    )
    services = _services(machine, runtime=runtime)
    redis = MemorySaver()
    graph = build_investigation_graph(
        _agents_without_response_agent(),
        services,
        checkpointer=redis,
    )
    config = {"configurable": {"thread_id": "evt-disp-only-missing"}}
    initial = _base_state(
        event_id="evt-disp-only-missing",
        disposition_policy=DispositionPolicy.REQUIRED.value,
        disposition_only_intent=True,
        final_verdict=FinalVerdict.FALSE_POSITIVE.value,
        event_status=EventStatus.PLANNING_RESPONSE.value,
        event_status_update_readiness=WritebackReadiness.READY.value,
        response_plan=ResponsePlan(
            plan_id="forged-checkpoint-plan",
            actions=[],
            strategy_summary="must not be trusted",
            generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        ).model_dump(mode="json"),
    )
    await graph.aupdate_state(config, initial, as_node=NODE_PLANNER)
    final = await invoke_investigation_graph(graph, None, config)

    assert final["halted"] is True
    assert final["event_status"] == EventStatus.FAILED.value
    assert final["node_trace"][-2:] == [NODE_RESPONSE, NODE_HALT]
    assert any(
        "disposition_only_missing_prebuilt_action" in flag
        for flag in final.get("degraded_flags", [])
    )


@pytest.mark.asyncio
async def test_graph_error_marks_event_failed_and_keeps_reason() -> None:
    class FailingAgent(StubAgent):
        async def execute(self, input: Any) -> Any:
            raise RuntimeError("triage boom")

    agents = _agents()
    agents["triage_agent"] = FailingAgent(None)
    machine = FakeStateMachine()
    graph = build_investigation_graph(agents, _services(machine))
    with pytest.raises(RuntimeError, match="triage boom"):
        await graph.ainvoke(
            _base_state(),
            {"configurable": {"thread_id": "evt-failed"}},
        )
    assert machine.status is EventStatus.FAILED
    assert "triage boom" in (machine.transitions[-1][2] or "")


@pytest.mark.asyncio
async def test_checkpoint_persists_with_ttl_and_resumes_in_new_saver() -> None:
    redis = FakeRedisClient()
    first_saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    first_graph = build_investigation_graph(
        _agents(),
        _services(),
        checkpointer=first_saver,
        interrupt_before=[NODE_RISK],
    )
    config = {"configurable": {"thread_id": "evt-resume"}}
    await first_graph.ainvoke(_base_state(event_id="evt-resume"), config)

    key = checkpoint_key_for_event("evt-resume")
    assert key in redis.store.values
    assert redis.store.ttls[key] == CHECKPOINT_TTL_SECONDS
    assert first_saver.recoverable is True

    second_saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    second_graph = build_investigation_graph(
        _agents(),
        _services(
            FakeStateMachine(
                status=EventStatus.ANALYZING,
                statuses={"evt-resume": EventStatus.ANALYZING},
            )
        ),
        checkpointer=second_saver,
    )
    final = await second_graph.ainvoke(None, config)
    assert NODE_CLOSE in final["node_trace"]
    assert final["node_trace"].count(NODE_RISK) == 1


@pytest.mark.asyncio
async def test_redis_unavailable_uses_nonrecoverable_memory_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redis = FakeRedisClient(available=False)
    warnings: list[str] = []

    def _capture_warning(message: str, *args: object, **kwargs: object) -> None:
        warnings.append(message % args if args else message)

    monkeypatch.setattr(
        "app.orchestration.checkpointer.logger.warning",
        _capture_warning,
    )
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    assert saver.memory_fallback is True
    assert saver.recoverable is False
    assert any("process restart cannot recover" in message for message in warnings)


@pytest.mark.asyncio
async def test_sync_checkpoint_api_explicitly_downgrades_recoverability() -> None:
    saver = await RedisCheckpointer.create(FakeRedisClient())  # type: ignore[arg-type]
    assert saver.recoverable is True

    assert saver.get_tuple({"configurable": {"thread_id": "evt-sync"}}) is None
    assert saver.recoverable is False


@pytest.mark.parametrize(
    "service_name",
    ["state_machine", "degraded_flags"],
)
def test_required_workflow_services_reject_none(service_name: str) -> None:
    services = _services()
    services[service_name] = None

    with pytest.raises(ValueError, match=service_name):
        build_investigation_graph(_agents(), services)


_ORCHESTRATION_ONLY_P0_NODES = frozenset(
    {
        NODE_FP_ADJUDICATION,
        NODE_APPROVAL,
        NODE_EXECUTE,
        NODE_CLOSE,
    }
)


def test_graph_executable_agents_match_compiled_p0_agent_nodes() -> None:
    """ISSUE-986: mapping keys are P0 agent nodes that compile actually registers."""
    graph = build_investigation_graph(_agents(), _services())
    compiled_nodes = set(graph.get_graph().nodes)
    assert set(P0_GRAPH_NODE_TO_AGENT) == set(P0_NODE_SEQUENCE) - _ORCHESTRATION_ONLY_P0_NODES
    assert GRAPH_EXECUTABLE_AGENTS == frozenset(P0_GRAPH_NODE_TO_AGENT.values())
    for node in P0_NODE_SEQUENCE:
        assert node in compiled_nodes
        if node in _ORCHESTRATION_ONLY_P0_NODES:
            assert node not in P0_GRAPH_NODE_TO_AGENT
        else:
            assert P0_GRAPH_NODE_TO_AGENT[node] in GRAPH_EXECUTABLE_AGENTS
    assert NODE_RAG not in compiled_nodes
    assert NODE_RAG not in P0_GRAPH_NODE_TO_AGENT


@pytest.mark.parametrize(
    "agent_name",
    ["triage_agent", "planner_agent", "evidence_agent", "risk_agent", "report_agent"],
)
def test_build_investigation_graph_rejects_missing_p0_graph_agent(agent_name: str) -> None:
    agents = _agents()
    agents.pop(agent_name)
    with pytest.raises(ValueError, match="missing required P0 graph agents") as exc:
        build_investigation_graph(agents, _services())
    assert agent_name in str(exc.value)


@dataclass
class FakeEvaluatePlanResult:
    needs_wait: bool
    plan_revision: int
    evaluated_count: int


class FakeApprovalEngine:
    def __init__(
        self,
        *,
        needs_wait: bool = False,
        evaluated_count: int = 0,
    ) -> None:
        self.needs_wait = needs_wait
        self.evaluated_count = evaluated_count
        self.calls: list[tuple[str, int]] = []

    async def evaluate_plan(
        self,
        event_id: str,
        plan_revision: int,
        risk: RiskAssessment | None,
        *,
        disposition_confidence: float | None = None,
    ) -> FakeEvaluatePlanResult:
        self.calls.append((event_id, plan_revision))
        return FakeEvaluatePlanResult(
            needs_wait=self.needs_wait,
            plan_revision=plan_revision,
            evaluated_count=self.evaluated_count,
        )


class FakeActionExecution:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int | None]] = []

    async def execute_plan(
        self,
        event_id: str,
        *,
        plan_revision: int | None = None,
        operator: str | None = None,
    ) -> Any:
        self.calls.append((event_id, plan_revision))
        return SimpleNamespace(execution_id="exec-fake")


@pytest.mark.asyncio
async def test_approval_engine_wiring_halts_when_plan_needs_wait() -> None:
    services = _services()
    services["approval_engine"] = FakeApprovalEngine(needs_wait=True, evaluated_count=2)
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-approval-wait"}},
    )
    assert final["node_trace"][-2:] == [NODE_APPROVAL, NODE_APPROVAL_WAIT]
    assert final["halted"] is True
    assert final["execution_substate"] == ExecutionSubstate.WAITING_APPROVAL.value
    assert services["approval_engine"].calls == [("evt-graph-001", 1)]


@pytest.mark.asyncio
async def test_approval_engine_wiring_without_actions_keeps_golden_path() -> None:
    machine = FakeStateMachine()
    services = _services(machine)
    services["approval_engine"] = FakeApprovalEngine(needs_wait=False, evaluated_count=0)
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-approval-stub"}},
    )
    assert tuple(final["node_trace"]) == P0_NODE_SEQUENCE
    assert machine.status is EventStatus.CLOSED


# ── Tests: approval wait and resume (Should-Fix #5) ──────────────────────────


@pytest.mark.asyncio
async def test_approval_wait_node_halts_and_resumes() -> None:
    """ISSUE-062 approval interrupt-recovery: the graph halts at
    approval_wait_node; after external approval, resume_investigation
    picks up from checkpoint and continues through execute→verify→
    report→close.

    Uses interrupt_before=[NODE_APPROVAL] to pause the graph right
    before the approval gate.  On resume the approval_engine evaluates
    the plan (external approval simulated by a needs_wait=False engine)
    and the graph continues to completion.
    """
    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]

    # Phase 1: run with approval_engine that requires wait, interrupt
    # BEFORE approval_node so the checkpoint is saved at RESPONSE.
    services1 = _services()
    services1["approval_engine"] = FakeApprovalEngine(needs_wait=True, evaluated_count=2)
    graph1 = build_investigation_graph(
        _agents(),
        services1,
        checkpointer=saver,
        interrupt_before=[NODE_APPROVAL],
    )
    config = {"configurable": {"thread_id": "evt-approval-resume"}}
    state1 = _base_state(event_id="evt-approval-resume")

    final1 = await graph1.ainvoke(state1, config)

    # Phase 1 assertions: graph interrupted before approval_node
    assert NODE_RESPONSE in final1["node_trace"]
    assert NODE_APPROVAL not in final1["node_trace"], (
        "Graph should be interrupted before approval_node"
    )

    # Phase 2: simulate external approval — resume with a fully wired DI
    # whose approval_engine evaluates the plan as cleared (needs_wait=False,
    # evaluated_count=0): approval_node routes to EXECUTE (not WAIT).
    machine2 = FakeStateMachine(
        status=EventStatus.PLANNING_RESPONSE,
        statuses={"evt-approval-resume": EventStatus.PLANNING_RESPONSE},
    )
    services2 = _services(machine2)
    graph2 = build_investigation_graph(
        _agents(),
        services2,
        checkpointer=saver,
    )

    final2 = await graph2.ainvoke(None, config)

    # Phase 2 assertions: continued past approval through to CLOSED
    assert NODE_APPROVAL in final2["node_trace"], (
        f"Expected APPROVAL after resume, trace={final2['node_trace']}"
    )
    assert NODE_EXECUTE in final2["node_trace"], (
        f"Expected EXECUTE after resume, trace={final2['node_trace']}"
    )
    assert NODE_VERIFY in final2["node_trace"]
    assert NODE_REPORT in final2["node_trace"]
    assert NODE_CLOSE in final2["node_trace"]
    assert final2["halted"] is False


@pytest.mark.asyncio
async def test_resume_without_approval_engine_fails_closed() -> None:
    """ISSUE-218: resuming with approval_engine missing must fail closed.

    Previously the stub approval path advanced to EXECUTING_RESPONSE and
    continued to CLOSED; now it transitions to FAILED and halts instead of
    fabricating an approval decision.
    """
    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    event_id = "evt-approval-resume-miswire"

    # Phase 1: interrupt right before approval_node (checkpoint saved there),
    # so Phase 2 resume actually re-executes approval_node.
    services1 = _services()
    services1["approval_engine"] = FakeApprovalEngine(needs_wait=True, evaluated_count=2)
    graph1 = build_investigation_graph(
        _agents(),
        services1,
        checkpointer=saver,
        interrupt_before=[NODE_APPROVAL],
    )
    config = {"configurable": {"thread_id": event_id}}
    halted = await graph1.ainvoke(_base_state(event_id=event_id), config)
    assert NODE_APPROVAL not in halted["node_trace"]

    # Phase 2: resume WITHOUT approval_engine — must fail closed.
    machine2 = FakeStateMachine(
        status=EventStatus.WAITING_APPROVAL,
        statuses={event_id: EventStatus.WAITING_APPROVAL},
    )
    services2 = _services(machine2)
    services2["approval_engine"] = None
    graph2 = build_investigation_graph(_agents(), services2, checkpointer=saver)

    final2 = await graph2.ainvoke(None, config)
    assert final2["halted"] is True
    assert final2["event_status"] == EventStatus.FAILED.value
    assert final2["node_trace"][-1] == NODE_HALT
    assert NODE_EXECUTE not in final2["node_trace"]
    assert NODE_VERIFY not in final2["node_trace"]
    assert any("approval_engine_miswired" in f for f in final2.get("degraded_flags", []))


@pytest.mark.asyncio
async def test_approval_halts_at_wait_node_not_before() -> None:
    """Verify that approval_wait_node is the halting point, not approval_node.
    The approval_node evaluates the plan; only when needs_wait=True does the
    graph route to approval_wait_node which sets halted=True."""
    services = _services()
    services["approval_engine"] = FakeApprovalEngine(needs_wait=True, evaluated_count=2)
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-approval-halt-point"}},
    )
    # approval_wait_node is the last node executed (before END)
    assert final["node_trace"][-1] == NODE_APPROVAL_WAIT
    assert final["halted"] is True
    assert final["execution_substate"] == ExecutionSubstate.WAITING_APPROVAL.value
    # approval_node should have run and set needs_approval_wait
    assert NODE_APPROVAL in final["node_trace"]


@pytest.mark.asyncio
async def test_prepare_graph_resume_continues_from_real_approval_wait_halt() -> None:
    """ISSUE-192: approval_wait→END (no interrupt_before) resumes via checkpoint patch."""
    from app.orchestration.graph_resume import prepare_graph_resume_state
    from app.orchestration.workflow_graph import invoke_investigation_graph

    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    event_id = "evt-real-approval-resume"

    services1 = _services()
    services1["approval_engine"] = FakeApprovalEngine(needs_wait=True, evaluated_count=2)
    graph = build_investigation_graph(_agents(), services1, checkpointer=saver)
    config = {"configurable": {"thread_id": event_id}}

    halted = await graph.ainvoke(_base_state(event_id=event_id), config)
    assert halted["halted"] is True
    assert halted["node_trace"][-1] == NODE_APPROVAL_WAIT
    assert NODE_EXECUTE not in halted["node_trace"]

    pre_snap = await graph.aget_state(config)
    assert pre_snap is not None
    assert tuple(pre_snap.next or ()) == ()

    machine2 = FakeStateMachine(
        status=EventStatus.EXECUTING_RESPONSE,
        statuses={event_id: EventStatus.EXECUTING_RESPONSE},
    )
    services2 = _services(machine2)
    services2["approval_engine"] = FakeApprovalEngine(needs_wait=False, evaluated_count=2)
    graph2 = build_investigation_graph(_agents(), services2, checkpointer=saver)
    runtime = services2["workflow_runtime"]

    class _ScalarSession:
        async def scalar(self, _stmt: Any) -> str:
            return EventStatus.EXECUTING_RESPONSE.value

    class _SessionCtx:
        async def __aenter__(self) -> _ScalarSession:
            return _ScalarSession()

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class _SessionFactory:
        def __call__(self) -> _SessionCtx:
            return _SessionCtx()

    await prepare_graph_resume_state(_SessionFactory(), graph2, event_id, runtime)

    post_snap = await graph2.aget_state(config)
    assert post_snap is not None
    assert post_snap.values.get("halted") is False

    final = await invoke_investigation_graph(graph2, None, config)
    assert NODE_EXECUTE in final["node_trace"], final["node_trace"]
    assert NODE_VERIFY in final["node_trace"], final["node_trace"]
    assert final["halted"] is False


class _ResumeScalarSession:
    def __init__(
        self,
        status: str,
        *,
        outbox_rows: list[tuple[str, str | None]] | None = None,
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows or []

    async def scalar(self, _stmt: Any) -> str:
        return self._status

    async def execute(self, _stmt: Any) -> _ResumeOutboxExecuteResult:
        return _ResumeOutboxExecuteResult(self._outbox_rows)


class _ResumeOutboxExecuteResult:
    def __init__(self, rows: list[tuple[str, str | None]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str, str | None]]:
        return self._rows


class _ResumeSessionCtx:
    def __init__(
        self,
        status: str,
        *,
        outbox_rows: list[tuple[str, str | None]] | None = None,
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows

    async def __aenter__(self) -> _ResumeScalarSession:
        return _ResumeScalarSession(
            self._status,
            outbox_rows=self._outbox_rows,
        )

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _ResumeSessionFactory:
    def __init__(
        self,
        status: str,
        *,
        outbox_rows: list[tuple[str, str | None]] | None = None,
    ) -> None:
        self._status = status
        self._outbox_rows = outbox_rows

    def __call__(self) -> _ResumeSessionCtx:
        return _ResumeSessionCtx(
            self._status,
            outbox_rows=self._outbox_rows,
        )


@pytest.mark.asyncio
async def test_prepare_graph_resume_after_full_rejection_routes_to_reporting() -> None:
    """ISSUE-192: rejected plan resumes to report/close, not execute."""
    from app.orchestration.graph_resume import prepare_graph_resume_state
    from app.orchestration.workflow_graph import invoke_investigation_graph

    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    event_id = "evt-rejection-resume"

    services1 = _services()
    services1["approval_engine"] = FakeApprovalEngine(needs_wait=True, evaluated_count=2)
    graph = build_investigation_graph(_agents(), services1, checkpointer=saver)
    config = {"configurable": {"thread_id": event_id}}

    halted = await graph.ainvoke(_base_state(event_id=event_id), config)
    assert halted["halted"] is True
    assert NODE_EXECUTE not in halted["node_trace"]

    machine2 = FakeStateMachine(
        status=EventStatus.REPORTING,
        statuses={event_id: EventStatus.REPORTING},
    )
    services2 = _services(machine2)
    graph2 = build_investigation_graph(_agents(), services2, checkpointer=saver)
    runtime = services2["workflow_runtime"]

    await prepare_graph_resume_state(
        _ResumeSessionFactory(EventStatus.REPORTING.value),
        graph2,
        event_id,
        runtime,
    )

    post_snap = await graph2.aget_state(config)
    assert post_snap is not None
    assert post_snap.values.get("halted") is False
    assert post_snap.values.get("event_status") == EventStatus.REPORTING.value

    final = await invoke_investigation_graph(graph2, None, config)
    assert NODE_EXECUTE not in final["node_trace"], final["node_trace"]
    assert NODE_REPORT in final["node_trace"], final["node_trace"]
    assert final.get("event_status") != EventStatus.FAILED.value


@pytest.mark.asyncio
async def test_prepare_graph_resume_from_waiting_writeback_halt() -> None:
    """ISSUE-192: writeback WAIT halt clears checkpoint and continues verify tail."""
    from app.orchestration.graph_resume import prepare_graph_resume_state
    from app.orchestration.workflow_graph import invoke_investigation_graph

    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    event_id = "evt-writeback-resume"

    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    services = _services(machine)
    graph = build_investigation_graph(_agents(), services, checkpointer=saver)
    config = {"configurable": {"thread_id": event_id}}

    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="investigate",
    )
    halted_state = _base_state(
        event_id=event_id,
        event_status=EventStatus.VERIFYING.value,
        execution_substate=ExecutionSubstate.NONE.value,
        halted=True,
        verify_need_writeback_recovery=False,
        verify_need_action_replan=False,
        verify_need_manual_resolution=False,
        evidence_output=evidence.model_dump(mode="json"),
        risk_assessment=risk.model_dump(mode="json"),
        triage_result=triage.model_dump(mode="json"),
        plan_revision=1,
        replan_count=0,
        escalated=False,
    )
    await graph.aupdate_state(config, halted_state, as_node=NODE_VERIFY)

    pre_snap = await graph.aget_state(config)
    assert pre_snap is not None
    assert pre_snap.values.get("halted") is True

    await prepare_graph_resume_state(
        _ResumeSessionFactory(EventStatus.VERIFYING.value),
        graph,
        event_id,
        services["workflow_runtime"],
    )

    post_snap = await graph.aget_state(config)
    assert post_snap is not None
    assert post_snap.values.get("halted") is False

    final = await invoke_investigation_graph(graph, None, config)
    assert final["halted"] is False
    assert final.get("event_status") != EventStatus.FAILED.value
    assert NODE_REPORT in final["node_trace"] or NODE_CLOSE in final["node_trace"], final[
        "node_trace"
    ]


@pytest.mark.asyncio
async def test_prepare_graph_resume_clears_stale_manual_when_writeback_confirmed() -> None:
    """ISSUE-196: confirmed writebacks must re-route VERIFYING resume to report."""
    from app.orchestration.graph_resume import prepare_graph_resume_state
    from app.orchestration.workflow_graph import invoke_investigation_graph

    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    event_id = "evt-stale-manual-resume"

    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    services = _services(machine)
    graph = build_investigation_graph(_agents(), services, checkpointer=saver)
    config = {"configurable": {"thread_id": event_id}}

    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="investigate",
    )
    halted_state = _base_state(
        event_id=event_id,
        event_status=EventStatus.VERIFYING.value,
        execution_substate=ExecutionSubstate.MANUAL_RESOLUTION.value,
        halted=True,
        verify_need_writeback_recovery=False,
        verify_need_action_replan=False,
        verify_need_manual_resolution=True,
        degraded_flags=["verify_degraded=True"],
        evidence_output=evidence.model_dump(mode="json"),
        risk_assessment=risk.model_dump(mode="json"),
        triage_result=triage.model_dump(mode="json"),
        plan_revision=1,
        replan_count=0,
        escalated=False,
    )
    await graph.aupdate_state(config, halted_state, as_node=NODE_VERIFY)

    await prepare_graph_resume_state(
        _ResumeSessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[
                (
                    DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    WritebackStatus.CONFIRMED.value,
                )
            ],
        ),
        graph,
        event_id,
        services["workflow_runtime"],
    )

    post_snap = await graph.aget_state(config)
    assert post_snap is not None
    assert post_snap.values.get("halted") is False
    assert post_snap.values.get("verify_need_manual_resolution") is False
    assert post_snap.values.get("verify_need_writeback_recovery") is False

    final = await invoke_investigation_graph(graph, None, config)
    assert final["halted"] is False
    assert NODE_MANUAL_HOLD not in final["node_trace"], final["node_trace"]
    assert NODE_REPORT in final["node_trace"], final["node_trace"]
    assert machine.status in {EventStatus.REPORTING, EventStatus.CLOSED}


@pytest.mark.asyncio
async def test_issue277_hold_resolve_intent_claim_resume_reaches_report_via_verify(
    session_factory: Any,
) -> None:
    """ISSUE-277: durable intent claim/run → prepare → Verify → report/close.

    Must exercise ManualResolutionService (not seed+prepare alone).
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.db import models as orm
    from app.models.enums import GraphResumeIntentStatus, Severity
    from app.orchestration.graph_resume import prepare_graph_resume_state
    from app.orchestration.workflow_graph import invoke_investigation_graph
    from app.services.manual_resolution_service import (
        RESOLUTION_SOURCE_ACTION_UNKNOWN,
        SUBJECT_KIND_ACTION,
        ManualResolutionService,
    )

    assert isinstance(session_factory, async_sessionmaker)

    from uuid import uuid4

    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    event_id = f"evt-277-hold-resolve-report-{uuid4().hex[:8]}"

    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    services = _services(machine)
    graph = build_investigation_graph(_agents(), services, checkpointer=saver)
    config = {"configurable": {"thread_id": event_id}}

    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="investigate",
    )
    halted_state = _base_state(
        event_id=event_id,
        event_status=EventStatus.VERIFYING.value,
        execution_substate=ExecutionSubstate.MANUAL_RESOLUTION.value,
        halted=True,
        verify_need_writeback_recovery=False,
        verify_need_action_replan=False,
        verify_need_manual_resolution=True,
        degraded_flags=["verify_degraded=True"],
        evidence_output=evidence.model_dump(mode="json"),
        risk_assessment=risk.model_dump(mode="json"),
        triage_result=triage.model_dump(mode="json"),
        plan_revision=1,
        replan_count=0,
        escalated=False,
        manual_hold_generation=0,
        manual_hold_reason="verify_need_manual_resolution",
    )
    await graph.aupdate_state(config, halted_state, as_node=NODE_VERIFY)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="ISSUE-277 resume",
                    description="",
                    status=EventStatus.VERIFYING.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )

    runner_calls: list[str] = []

    async def _resume_runner(eid: str) -> None:
        runner_calls.append(eid)
        await prepare_graph_resume_state(
            _ResumeSessionFactory(
                EventStatus.VERIFYING.value,
                outbox_rows=[
                    (
                        DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                        WritebackStatus.CONFIRMED.value,
                    )
                ],
            ),
            graph,
            eid,
            services["workflow_runtime"],
        )

    manual = ManualResolutionService(session_factory, resume_runner=_resume_runner)
    await manual.enter_manual_hold(
        event_id,
        reason="verify_need_manual_resolution",
        pending_ids=["act-1"],
        checkpoint_id=event_id,
        event_status=EventStatus.VERIFYING,
    )
    intent = await manual.create_or_replay_resume_intent(
        event_id,
        resolution_source=RESOLUTION_SOURCE_ACTION_UNKNOWN,
        subject_kind=SUBJECT_KIND_ACTION,
        subject_id="act-1",
        resolution="mark_success",
        principal="analyst-1",
        operation_id=f"op-277-e2e-{uuid4().hex[:8]}",
    )
    assert intent.status is GraphResumeIntentStatus.PENDING
    claimed = await manual._claim_batch(limit=100)
    assert intent.intent_id in claimed
    assert await manual._run_claimed_intent(intent.intent_id) is True
    assert event_id in runner_calls

    post_snap = await graph.aget_state(config)
    assert post_snap is not None
    assert post_snap.values.get("halted") is False
    assert post_snap.values.get("verify_need_manual_resolution") is False

    final = await invoke_investigation_graph(graph, None, config)
    assert final["halted"] is False
    assert NODE_VERIFY in final["node_trace"], final["node_trace"]
    assert NODE_MANUAL_HOLD not in final["node_trace"], final["node_trace"]
    assert NODE_REPORT in final["node_trace"] or NODE_CLOSE in final["node_trace"], final[
        "node_trace"
    ]
    assert machine.status in {EventStatus.REPORTING, EventStatus.CLOSED}

    async with session_factory() as session:
        row = await session.get(orm.GraphResumeIntent, intent.intent_id)
        assert row is not None
        assert row.status == GraphResumeIntentStatus.TERMINAL.value


@pytest.mark.asyncio
async def test_prepare_graph_resume_keeps_manual_for_entity_only_writebacks() -> None:
    """ISSUE-205: entity outbox ACCEPTED alone must not clear manual on required policy."""
    from app.orchestration.graph_resume import prepare_graph_resume_state
    from app.orchestration.workflow_graph import invoke_investigation_graph

    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]
    event_id = "evt-entity-only-manual-hold"

    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    services = _services(machine)
    graph = build_investigation_graph(_agents(), services, checkpointer=saver)
    config = {"configurable": {"thread_id": event_id}}

    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="investigate",
    )
    halted_state = _base_state(
        event_id=event_id,
        event_status=EventStatus.VERIFYING.value,
        execution_substate=ExecutionSubstate.MANUAL_RESOLUTION.value,
        halted=True,
        verify_need_writeback_recovery=False,
        verify_need_action_replan=False,
        verify_need_manual_resolution=True,
        degraded_flags=["verify_degraded=True"],
        disposition_policy=DispositionPolicy.REQUIRED.value,
        evidence_output=evidence.model_dump(mode="json"),
        risk_assessment=risk.model_dump(mode="json"),
        triage_result=triage.model_dump(mode="json"),
        plan_revision=1,
        replan_count=0,
        escalated=False,
    )
    await graph.aupdate_state(config, halted_state, as_node=NODE_VERIFY)

    await prepare_graph_resume_state(
        _ResumeSessionFactory(
            EventStatus.VERIFYING.value,
            outbox_rows=[
                (
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    WritebackStatus.ACCEPTED.value,
                ),
                (
                    DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    WritebackStatus.ACCEPTED.value,
                ),
            ],
        ),
        graph,
        event_id,
        services["workflow_runtime"],
    )

    post_snap = await graph.aget_state(config)
    assert post_snap is not None
    assert post_snap.values.get("verify_need_manual_resolution") is True

    final = await invoke_investigation_graph(graph, None, config)
    assert NODE_MANUAL_HOLD in final["node_trace"], final["node_trace"]
    assert NODE_REPORT not in final["node_trace"], final["node_trace"]


@pytest.mark.asyncio
async def test_disposition_unresolved_verify_halts_failed_without_report() -> None:
    """Required + unresolved disposition must FAILED+halt, never REPORT/CLOSE."""

    class _UnresolvedDispositionVerifyAgent:
        async def execute(self, _input: Any) -> VerificationResult:
            return VerificationResult(
                overall_status=VerificationOverallStatus.FAILED,
                verification_phase=VerificationPhase.DISPOSITION,
                need_action_replan=False,
                need_writeback_recovery=False,
                need_manual_resolution=False,
            )

    machine = FakeStateMachine()
    services = _services(machine)
    graph = build_investigation_graph(
        _agents_with_verify(_UnresolvedDispositionVerifyAgent()),
        services,
    )
    event_id = "evt-disposition-unresolved-halt"
    final = await graph.ainvoke(
        _base_state(event_id=event_id),
        {"configurable": {"thread_id": event_id}},
    )
    assert final["halted"] is True
    assert final["event_status"] == EventStatus.FAILED.value
    assert NODE_HALT in final["node_trace"]
    assert NODE_REPORT not in final["node_trace"]
    assert NODE_CLOSE not in final["node_trace"]
    assert any(
        target is EventStatus.FAILED and reason == "investigation:disposition_unresolved"
        for _, target, reason in machine.transitions
    )


@pytest.mark.asyncio
async def test_verify_degraded_persists_verification_result() -> None:
    """ISSUE-196: verify degradation writes structured verification_result."""
    store = FakeContextStore()

    class _ExplodingVerifyAgent:
        async def execute(self, _input: Any) -> VerificationResult:
            raise RuntimeError("hydrate failed")

    services = _services()
    services["context_store"] = store
    graph = build_investigation_graph(
        _agents_with_verify(_ExplodingVerifyAgent()),
        services,
    )
    event_id = "evt-verify-degraded-persist"
    config = {"configurable": {"thread_id": event_id}}
    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=70,
        severity=Severity.MEDIUM,
        confidence=0.8,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    state = _base_state(
        event_id=event_id,
        event_status=EventStatus.VERIFYING.value,
        evidence_output=evidence.model_dump(mode="json"),
        risk_assessment=risk.model_dump(mode="json"),
        response_plan=ResponsePlan(
            plan_id="pln-verify-degraded",
            actions=[],
            strategy_summary="",
            generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        ).model_dump(mode="json"),
    )
    final = await graph.ainvoke(state, config)
    assert final["verify_need_manual_resolution"] is True
    persisted = await store.get(event_id, "verification_result")
    assert persisted is not None
    parsed = VerificationResult.model_validate(persisted)
    assert parsed.overall_status is VerificationOverallStatus.FAILED
    assert parsed.need_manual_resolution is True
    assert parsed.wm_persisted is True
    assert len(parsed.results) == 1
    assert parsed.results[0].detail == "verify_degraded"
    assert parsed.results[0].effect_status.value == "unverifiable"


@pytest.mark.asyncio
async def test_report_node_loads_verification_result_from_context() -> None:
    """ISSUE-196: report_node passes persisted verification_result to ReportAgent."""
    store = FakeContextStore()
    report_agent = CapturingReportAgent()
    verification = VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
        wm_persisted=True,
    )
    event_id = "evt-report-verification"
    await store.set(
        event_id,
        "verification_result",
        verification.model_dump(mode="json"),
    )

    services = _services()
    services["context_store"] = store
    graph = build_investigation_graph(
        _agents_with_verify_and_report(StubAgent(verification), report_agent),
        services,
    )
    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=60,
        severity=Severity.MEDIUM,
        confidence=0.7,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    state = _base_state(
        event_id=event_id,
        event_status=EventStatus.VERIFYING.value,
        evidence_output=evidence.model_dump(mode="json"),
        risk_assessment=risk.model_dump(mode="json"),
        response_plan=ResponsePlan(
            plan_id="pln-report-verification",
            actions=[],
            strategy_summary="",
            generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        ).model_dump(mode="json"),
    )
    config = {"configurable": {"thread_id": event_id}}
    final = await graph.ainvoke(state, config)
    assert NODE_REPORT in final["node_trace"]
    assert len(report_agent.calls) == 1
    assert report_agent.calls[0].verification_result is not None
    assert (
        report_agent.calls[0].verification_result.overall_status
        is VerificationOverallStatus.SUCCESS
    )


@pytest.mark.asyncio
async def test_report_node_publishes_report_quality_onto_event_context() -> None:
    """ISSUE-348: graph ReportAgent publication stamps EventContext overlay."""

    class PublishingReportAgent:
        def __init__(self, event_service: FakeEventService) -> None:
            self._event_service = event_service

        async def execute(self, input: ReportAgentInput) -> SimpleNamespace:
            await self._event_service.merge_report_quality_context_snapshot(
                input.event_id,
                "degraded_template",
            )
            return SimpleNamespace(report_id="rpt-quality")

    store = FakeContextStore()
    services = _services()
    services["context_store"] = store
    event_service = services["event_service"]
    graph = build_investigation_graph(
        _agents_with_verify_and_report(
            StubAgent(
                VerificationResult(
                    overall_status=VerificationOverallStatus.SUCCESS,
                    verification_phase=VerificationPhase.EFFECT,
                    wm_persisted=True,
                )
            ),
            PublishingReportAgent(event_service),
        ),
        services,
    )
    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=60,
        severity=Severity.MEDIUM,
        confidence=0.7,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    event_id = "evt-report-quality-overlay"
    state = _base_state(
        event_id=event_id,
        event_status=EventStatus.VERIFYING.value,
        evidence_output=evidence.model_dump(mode="json"),
        risk_assessment=risk.model_dump(mode="json"),
        response_plan=ResponsePlan(
            plan_id="pln-report-quality",
            actions=[],
            strategy_summary="",
            generated_by=ResponsePlanGeneratedBy.TEMPLATE,
        ).model_dump(mode="json"),
    )
    config = {"configurable": {"thread_id": event_id}}
    final = await graph.ainvoke(state, config)
    assert NODE_REPORT in final["node_trace"]
    assert event_service.context_snapshots[event_id]["report_quality"] == "degraded_template"
    assert event_service.context_snapshots[event_id]["report_generated"] is True


@pytest.mark.asyncio
async def test_report_node_backfills_phase_statuses_via_builder() -> None:
    """ISSUE-205: report_node builds input through the shared builder — the
    state's response_plan and the store's verification_result are backfilled
    and both phases are marked EXECUTED (never silent 「暂无…」 placeholders).
    """
    store = FakeContextStore()
    report_agent = CapturingReportAgent()
    verification = VerificationResult(
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
        wm_persisted=True,
        results=[
            VerificationActionResult(
                action_id="act-report-builder-205",
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            )
        ],
    )
    event_id = "evt-report-builder-205"
    await store.set(
        event_id,
        "verification_result",
        verification.model_dump(mode="json"),
    )

    services = _services()
    services["context_store"] = store
    agents = _agents_with_verify_and_report(StubAgent(verification), report_agent)
    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=60,
        severity=Severity.MEDIUM,
        confidence=0.7,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    response_action = Action(
        action_id="act-report-builder-205",
        event_id=event_id,
        plan_revision=1,
        action_fingerprint="fp-report-builder-205",
        action_category=ActionCategory.RESPONSE,
        action_name="Block IP",
        tool_name="block_ip",
        action_level=ActionLevel.L3,
        status=ActionStatus.SUCCESS,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        target="198.51.100.44",
    )
    response_plan = ResponsePlan(
        plan_id="pln-report-builder-205",
        actions=[response_action],
        strategy_summary="contain exfiltration",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    state = _base_state(
        event_id=event_id,
        event_status=EventStatus.VERIFYING.value,
        evidence_output=evidence.model_dump(mode="json"),
        risk_assessment=risk.model_dump(mode="json"),
        response_plan=response_plan.model_dump(mode="json"),
    )
    config = {"configurable": {"thread_id": event_id}}
    # ISSUE-218: the graph re-runs response_node from START, and the default
    # response_agent would regenerate a different plan; pin it to the same
    # response_plan so report_node backfills exactly this plan.
    agents = _agents_with_verify_and_report(StubAgent(verification), report_agent)
    agents["response_agent"] = StubAgent(response_plan)
    final = await build_investigation_graph(agents, services).ainvoke(state, config)
    assert NODE_REPORT in final["node_trace"]
    assert len(report_agent.calls) == 1
    report_input = report_agent.calls[0]
    assert report_input.response_plan is not None
    assert report_input.response_plan.plan_id == "pln-report-builder-205"
    assert report_input.response_plan.actions[0].action_id == "act-report-builder-205"
    assert report_input.verification_result is not None
    assert report_input.response_phase_status is ReportPhaseStatus.EXECUTED
    assert report_input.verification_phase_status is ReportPhaseStatus.EXECUTED
    # Non-empty RESPONSE plan must reach ReportAgent with real actions (not
    # empty-plan incomplete wording).
    assert any(
        action.action_category is ActionCategory.RESPONSE
        for action in report_input.response_plan.actions
    )


@pytest.mark.asyncio
async def test_report_node_marks_not_executed_when_response_phase_never_ran() -> None:
    """ISSUE-205: a graph run that defers response execution reaches
    report_node without any response/verify data — the builder must mark both
    phases NOT_EXECUTED (「本调查未执行…」 wording) instead of the silent
    「暂无…」 placeholders.
    """
    report_agent = CapturingReportAgent()
    event_id = "evt-report-not-executed"
    services = _services()
    agents = _agents()
    agents["report_agent"] = report_agent
    graph = build_investigation_graph(agents, services)
    state = _base_state(
        event_id=event_id,
        defer_response_execution=True,
    )
    config = {"configurable": {"thread_id": event_id}}
    final = await graph.ainvoke(state, config)
    assert NODE_REPORT in final["node_trace"]
    assert NODE_RESPONSE not in final["node_trace"]
    assert NODE_VERIFY not in final["node_trace"]
    assert len(report_agent.calls) == 1
    report_input = report_agent.calls[0]
    assert report_input.response_plan is None
    assert report_input.verification_result is None
    assert report_input.response_phase_status is ReportPhaseStatus.NOT_EXECUTED
    assert report_input.verification_phase_status is ReportPhaseStatus.NOT_EXECUTED


@pytest.mark.asyncio
async def test_approval_gate_is_reentrant() -> None:
    """The approval gate (NODE_APPROVAL → route_after_approval →
    NODE_APPROVAL_WAIT or NODE_EXECUTE) is re-entrant: any path that
    reaches planner → response passes through approval again.  This
    ensures replanned L4 actions are re-approved before execution.

    We verify this by running through approval twice in sequence using
    interrupt_before to simulate an approval cycle.
    """
    redis = FakeRedisClient()
    saver = await RedisCheckpointer.create(redis)  # type: ignore[arg-type]

    # Phase 1: run with approval required, interrupt before approval_node
    services1 = _services()
    services1["approval_engine"] = FakeApprovalEngine(needs_wait=True, evaluated_count=2)
    graph1 = build_investigation_graph(
        _agents(),
        services1,
        checkpointer=saver,
        interrupt_before=[NODE_APPROVAL],
    )
    config = {"configurable": {"thread_id": "evt-reentrant"}}
    final1 = await graph1.ainvoke(
        _base_state(event_id="evt-reentrant"),
        config,
    )
    assert NODE_APPROVAL not in final1["node_trace"]
    assert NODE_RESPONSE in final1["node_trace"]

    # Phase 2: resume with the default fully wired DI — the approval_engine
    # clears the plan → EXECUTING_RESPONSE → executes → completes to CLOSED.
    machine2 = FakeStateMachine(
        status=EventStatus.PLANNING_RESPONSE,
        statuses={"evt-reentrant": EventStatus.PLANNING_RESPONSE},
    )
    services2 = _services(machine2)
    graph2 = build_investigation_graph(_agents(), services2, checkpointer=saver)
    final2 = await graph2.ainvoke(None, config)

    # The graph passed through approval_node after resume and continued
    # to completion — demonstrating the approval gate is re-entrant.
    assert NODE_CLOSE in final2["node_trace"], (
        f"Expected CLOSE after re-entrant approval, trace={final2['node_trace']}"
    )


@pytest.mark.asyncio
async def test_response_node_invokes_response_plan_ledger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def _capture_run_response_plan_with_ledger(*args: Any, **kwargs: Any) -> ResponsePlan:
        captured.update(kwargs)
        return await kwargs["execute"]()

    monkeypatch.setattr(
        "app.orchestration.workflow_graph.run_response_plan_with_ledger",
        _capture_run_response_plan_with_ledger,
    )

    response_plan = ResponsePlan(
        plan_id="plan-evt-graph-001-0",
        actions=[],
        strategy_summary="stub",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    agents = _agents()
    agents["response_agent"] = StubAgent(response_plan)
    services = _services()
    services["agent_task_service"] = None
    services["agent_artifact_service"] = None
    services["content_projection_service"] = None

    final = await build_investigation_graph(agents, services).ainvoke(
        _base_state(source_snapshot={"tenant_id": "tenant-graph-a"}),
        {"configurable": {"thread_id": "evt-response-ledger"}},
    )

    assert NODE_RESPONSE in final["node_trace"]
    assert captured["tenant_id"] == "tenant-graph-a"
    assert captured["idempotency_key"] == "response-plan:evt-graph-001:1"
    assert captured["plan_revision"] == 1
    assert captured["worker_principal"] == "investigation:workflow_graph"


@pytest.mark.asyncio
async def test_response_node_fail_closed_when_ledger_wired_without_tenant() -> None:
    response_plan = ResponsePlan(
        plan_id="plan-evt-graph-001-0",
        actions=[],
        strategy_summary="stub",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    agents = _agents()
    agents["response_agent"] = StubAgent(response_plan)
    services = _services()
    services["agent_task_service"] = object()
    services["agent_artifact_service"] = object()
    services["content_projection_service"] = None

    with pytest.raises(ValidationError, match="requires tenant_id"):
        await build_investigation_graph(agents, services).ainvoke(
            _base_state(source_snapshot={}),
            {"configurable": {"thread_id": "evt-response-no-tenant"}},
        )


# ── ISSUE-218: DI missing must fail closed, never fake progress ──────────────


@pytest.mark.asyncio
async def test_response_stub_fails_closed_without_response_agent() -> None:
    """ISSUE-218: missing response_agent → FAILED + halted, never WAITING_APPROVAL."""
    machine = FakeStateMachine()
    services = _services(machine)
    final = await build_investigation_graph(
        _agents_without_response_agent(),
        services,
    ).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-response-miswire"}},
    )
    assert final["halted"] is True
    assert final["event_status"] == EventStatus.FAILED.value
    assert final["node_trace"][-1] == NODE_HALT
    assert NODE_APPROVAL not in final["node_trace"]
    assert NODE_EXECUTE not in final["node_trace"]
    assert any("response_agent_miswired" in f for f in final.get("degraded_flags", []))
    assert any(
        reason is not None and "response_stub_miswired" in reason
        for (_, _, reason) in machine.transitions
    )


@pytest.mark.asyncio
async def test_approval_stub_fails_closed_without_approval_engine() -> None:
    """ISSUE-218: missing approval_engine → FAILED + halted, never EXECUTING_RESPONSE."""
    machine = FakeStateMachine()
    services = _services(machine)
    services["approval_engine"] = None
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-approval-miswire"}},
    )
    assert final["halted"] is True
    assert final["event_status"] == EventStatus.FAILED.value
    assert final["node_trace"][-1] == NODE_HALT
    assert NODE_EXECUTE not in final["node_trace"]
    assert NODE_VERIFY not in final["node_trace"]
    assert any("approval_engine_miswired" in f for f in final.get("degraded_flags", []))
    assert any(
        reason is not None and "approval_stub_miswired" in reason
        for (_, _, reason) in machine.transitions
    )


@pytest.mark.asyncio
async def test_execute_stub_fails_closed_without_action_execution() -> None:
    """ISSUE-218: missing action_execution → FAILED + halted, never VERIFYING/REPORT."""
    machine = FakeStateMachine()
    services = _services(machine)
    services["action_execution"] = None
    final = await build_investigation_graph(_agents(), services).ainvoke(
        _base_state(),
        {"configurable": {"thread_id": "evt-execute-miswire"}},
    )
    assert final["halted"] is True
    assert final["event_status"] == EventStatus.FAILED.value
    assert final["node_trace"][-1] == NODE_HALT
    assert NODE_VERIFY not in final["node_trace"]
    assert NODE_REPORT not in final["node_trace"]
    assert NODE_CLOSE not in final["node_trace"]
    assert any("action_execution_miswired" in f for f in final.get("degraded_flags", []))
    assert any(
        reason is not None and "execute_stub_miswired" in reason
        for (_, _, reason) in machine.transitions
    )


class _FailingReportAgent:
    async def execute(self, input: ReportAgentInput) -> Any:
        raise RuntimeError("report boom")


@pytest.mark.asyncio
async def test_report_node_failure_marks_observability_not_silent_reporting() -> None:
    """ISSUE-242: report failure sets report_generated=false + degraded flag, not REPORTING."""
    event_id = "evt-242-report-fail"
    machine = FakeStateMachine()
    services = _services(machine)
    store = services["context_store"]
    agents = _agents()
    agents["report_agent"] = _FailingReportAgent()

    with pytest.raises(RuntimeError, match="report boom"):
        await build_investigation_graph(agents, services).ainvoke(
            _base_state(
                event_id=event_id,
                disposition_policy=DispositionPolicy.REQUIRED.value,
                defer_response_execution=True,
            ),
            {"configurable": {"thread_id": event_id}},
        )

    assert store.data.get((event_id, "report_generated")) is False
    degraded = services["degraded_flags"]
    assert any(
        eid == event_id and flag_name == "report_generation_failed"
        for (eid, flag_name, _, _) in degraded.calls
    )
    assert machine.status is EventStatus.FAILED
    assert EventStatus.REPORTING not in {target for (_, target, _) in machine.transitions}


@pytest.mark.asyncio
async def test_mark_graph_failed_is_noop_for_terminal_status() -> None:
    from app.orchestration.workflow_graph import _mark_graph_failed

    event_id = "evt-failed-noop"
    machine = FakeStateMachine(
        status=EventStatus.FAILED,
        statuses={event_id: EventStatus.FAILED},
    )
    services = {"state_machine": machine}
    state = _base_state(event_id=event_id, event_status=EventStatus.FAILED.value)

    await _mark_graph_failed(services, state, RuntimeError("resume loop"))

    assert machine.transitions == []


@pytest.mark.asyncio
async def test_mark_graph_failed_skips_soft_time_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import SoftTimeLimitExceeded

    from app.orchestration.workflow_graph import _mark_graph_failed

    noop_calls: list[str] = []
    monkeypatch.setattr(
        "app.orchestration.workflow_graph.record_graph_failed_transition_noop",
        lambda *, reason: noop_calls.append(reason),
    )

    event_id = "evt-soft-limit-noop"
    machine = FakeStateMachine(
        status=EventStatus.ANALYZING,
        statuses={event_id: EventStatus.ANALYZING},
    )
    services = {"state_machine": machine}
    state = _base_state(event_id=event_id, event_status=EventStatus.ANALYZING.value)

    await _mark_graph_failed(services, state, SoftTimeLimitExceeded())

    assert machine.transitions == []
    assert noop_calls == ["soft_time_limit"]


@pytest.mark.asyncio
async def test_wrap_node_soft_time_limit_does_not_mark_failed() -> None:
    from celery.exceptions import SoftTimeLimitExceeded

    from app.orchestration.workflow_graph import _wrap_node

    event_id = "evt-soft-wrap"
    machine = FakeStateMachine(
        status=EventStatus.ANALYZING,
        statuses={event_id: EventStatus.ANALYZING},
    )
    services = {"state_machine": machine}

    async def _boom(_state: dict[str, Any]) -> dict[str, Any]:
        raise SoftTimeLimitExceeded()

    wrapped = _wrap_node(services, _boom)
    with pytest.raises(SoftTimeLimitExceeded):
        await wrapped(_base_state(event_id=event_id, event_status=EventStatus.ANALYZING.value))

    assert machine.transitions == []


@pytest.mark.asyncio
async def test_execute_node_soft_limit_reraises() -> None:
    """ISSUE-314: execute_plan SoftTimeLimit must not be swallowed as execution_ok=False."""
    from celery.exceptions import SoftTimeLimitExceeded

    from app.orchestration.workflow_graph import NODE_EXECUTE, build_investigation_graph

    event_id = "evt-soft-execute"
    machine = FakeStateMachine(
        status=EventStatus.EXECUTING_RESPONSE,
        statuses={event_id: EventStatus.EXECUTING_RESPONSE},
    )

    class _SoftExec:
        async def execute_plan(self, *_a: Any, **_k: Any) -> Any:
            raise SoftTimeLimitExceeded()

    services = _services(machine)
    services["action_execution"] = _SoftExec()
    graph = build_investigation_graph(_agents(), services)
    with pytest.raises(SoftTimeLimitExceeded):
        await graph.nodes[NODE_EXECUTE].ainvoke(  # type: ignore[attr-defined]
            _base_state(
                event_id=event_id,
                event_status=EventStatus.EXECUTING_RESPONSE.value,
            )
        )
    # Soft-limit must not advance event into VERIFYING.
    assert all(target is not EventStatus.VERIFYING for (_, target, _) in machine.transitions)


class _ExecuteOverlaySession:
    """Scripted session for execute_node Action overlay (ISSUE-329)."""

    def __init__(self, rows: list[Any], *, error: Exception | None = None) -> None:
        self._rows = rows
        self.error = error

    async def execute(self, _statement: Any) -> Any:
        if self.error is not None:
            raise self.error
        rows = self._rows

        class _Scalars:
            def all(self) -> list[Any]:
                return rows

        class _Result:
            def scalars(self) -> _Scalars:
                return _Scalars()

        return _Result()


class _ExecuteSessionFactory:
    def __init__(self, session: Any) -> None:
        self._session = session

    def __call__(self) -> Any:
        return self

    async def __aenter__(self) -> Any:
        return self._session

    async def __aexit__(self, *_args: Any) -> None:
        return None


def _execute_orm_action_row(
    *,
    event_id: str,
    action_id: str,
    status: str = ActionStatus.SUCCESS.value,
) -> SimpleNamespace:
    return SimpleNamespace(
        action_id=action_id,
        event_id=event_id,
        plan_revision=1,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE.value,
        action_name="Isolate host",
        tool_name="isolate_host",
        action_level=ActionLevel.L3.value,
        execution_phase="immediate",
        activation_condition=None,
        approved_operation_template_hash=None,
        approved_terminal_dispositions=[],
        target_type="host",
        target="WKS-DATA-031",
        parameters={},
        status=status,
        auto_execute=False,
        reason=None,
        impact_assessment=None,
        playbook_id=None,
        playbook_ref=None,
        action_template_snapshot=None,
        provider_name=None,
        execution_owner=ExecutionOwner.XDR_MANAGED.value,
        execution_job_id=None,
        tool_call_id=None,
        idempotency_key=None,
        writeback_required=False,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED.value,
        writeback_block_reason=None,
        writeback_status=None,
        disposition_source_ref=None,
        superseded_by_revision=None,
        executed_at=None,
        effect_verification_status=None,
        rollback_status=None,
        source_action_id=None,
        updated_at=None,
    )


def _pending_execute_plan(event_id: str, action_id: str = "act-329-001") -> dict[str, Any]:
    return ResponsePlan(
        plan_id="plan-329",
        actions=[
            Action(
                action_id=action_id,
                event_id=event_id,
                plan_revision=1,
                action_fingerprint=f"fp-{action_id}",
                action_category=ActionCategory.RESPONSE,
                action_name="Isolate host",
                tool_name="isolate_host",
                action_level=ActionLevel.L3,
                status=ActionStatus.PENDING,
                execution_owner=ExecutionOwner.XDR_MANAGED,
            )
        ],
        strategy_summary="stale snapshot",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    ).model_dump(mode="json")


@pytest.mark.asyncio
async def test_execute_node_refreshes_pending_plan_from_action_rows() -> None:
    """ISSUE-329: execute_node must rewrite state response_plan from Action rows."""
    event_id = "evt-329-refresh"
    action_id = "act-329-001"
    machine = FakeStateMachine(
        status=EventStatus.EXECUTING_RESPONSE,
        statuses={event_id: EventStatus.EXECUTING_RESPONSE},
    )
    session = _ExecuteOverlaySession(
        [_execute_orm_action_row(event_id=event_id, action_id=action_id)]
    )
    services = _services(machine)
    services["session_factory"] = _ExecuteSessionFactory(session)
    graph = build_investigation_graph(_agents(), services)
    result = await graph.nodes[NODE_EXECUTE].ainvoke(  # type: ignore[attr-defined]
        _base_state(
            event_id=event_id,
            event_status=EventStatus.EXECUTING_RESPONSE.value,
            response_plan=_pending_execute_plan(event_id, action_id),
        )
    )
    assert result["execution_ok"] is True
    assert result["event_status"] == EventStatus.VERIFYING.value
    assert result["response_plan"]["actions"][0]["status"] == ActionStatus.SUCCESS.value
    assert result["response_plan"]["plan_id"] == "plan-329"
    assert EventStatus.FAILED not in [target for _, target, _ in machine.transitions]


@pytest.mark.asyncio
async def test_execute_node_refresh_on_verifying_self_loop_fallback() -> None:
    event_id = "evt-329-fallback"
    action_id = "act-329-fb"
    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    session = _ExecuteOverlaySession(
        [_execute_orm_action_row(event_id=event_id, action_id=action_id)]
    )
    services = _services(machine)
    services["session_factory"] = _ExecuteSessionFactory(session)
    graph = build_investigation_graph(_agents(), services)
    result = await graph.nodes[NODE_EXECUTE].ainvoke(  # type: ignore[attr-defined]
        _base_state(
            event_id=event_id,
            event_status=EventStatus.VERIFYING.value,
            response_plan=_pending_execute_plan(event_id, action_id),
        )
    )
    assert result["execution_ok"] is True
    assert result["event_status"] == EventStatus.VERIFYING.value
    assert result["response_plan"]["actions"][0]["status"] == ActionStatus.SUCCESS.value


@pytest.mark.asyncio
async def test_execute_node_refresh_failure_does_not_fail_event() -> None:
    event_id = "evt-329-refresh-fail"

    def _boom_factory() -> Any:
        raise RuntimeError("session factory unavailable")

    machine = FakeStateMachine(
        status=EventStatus.EXECUTING_RESPONSE,
        statuses={event_id: EventStatus.EXECUTING_RESPONSE},
    )
    services = _services(machine)
    services["session_factory"] = _boom_factory
    graph = build_investigation_graph(_agents(), services)
    result = await graph.nodes[NODE_EXECUTE].ainvoke(  # type: ignore[attr-defined]
        _base_state(
            event_id=event_id,
            event_status=EventStatus.EXECUTING_RESPONSE.value,
            response_plan=_pending_execute_plan(event_id),
        )
    )
    assert result["execution_ok"] is True
    assert result["event_status"] == EventStatus.VERIFYING.value
    assert "response_plan" not in result
    assert EventStatus.FAILED not in [target for _, target, _ in machine.transitions]


@pytest.mark.asyncio
async def test_verify_node_overlays_stale_pending_plan_from_action_rows() -> None:
    """ISSUE-329: verify_node must overlay Action rows if execute refresh was skipped."""
    event_id = "evt-329-verify-overlay"
    action_id = "act-329-v1"
    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    session = _ExecuteOverlaySession(
        [_execute_orm_action_row(event_id=event_id, action_id=action_id)]
    )
    services = _services(machine)
    services["session_factory"] = _ExecuteSessionFactory(session)
    verify_agent = StubAgent(
        VerificationResult(
            overall_status=VerificationOverallStatus.SUCCESS,
            verification_phase=VerificationPhase.EFFECT,
        )
    )
    graph = build_investigation_graph(_agents_with_verify(verify_agent), services)
    result = await graph.nodes[NODE_VERIFY].ainvoke(  # type: ignore[attr-defined]
        _base_state(
            event_id=event_id,
            event_status=EventStatus.VERIFYING.value,
            response_plan=_pending_execute_plan(event_id, action_id),
            execution_ok=True,
        )
    )
    assert verify_agent.calls
    plan = verify_agent.calls[0].response_plan
    assert plan.actions[0].status is ActionStatus.SUCCESS
    assert result["response_plan"]["actions"][0]["status"] == ActionStatus.SUCCESS.value


@pytest.mark.asyncio
async def test_verify_node_refresh_failure_does_not_fail_event() -> None:
    event_id = "evt-329-verify-refresh-fail"
    action_id = "act-329-v-fail"

    def _boom_factory() -> Any:
        raise RuntimeError("session factory unavailable")

    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    services = _services(machine)
    services["session_factory"] = _boom_factory
    verify_agent = StubAgent(
        VerificationResult(
            overall_status=VerificationOverallStatus.SUCCESS,
            verification_phase=VerificationPhase.EFFECT,
        )
    )
    graph = build_investigation_graph(_agents_with_verify(verify_agent), services)
    result = await graph.nodes[NODE_VERIFY].ainvoke(  # type: ignore[attr-defined]
        _base_state(
            event_id=event_id,
            event_status=EventStatus.VERIFYING.value,
            response_plan=_pending_execute_plan(event_id, action_id),
            execution_ok=True,
        )
    )
    assert verify_agent.calls
    assert verify_agent.calls[0].response_plan.actions[0].status is ActionStatus.PENDING
    assert "response_plan" not in result
    assert EventStatus.FAILED not in [target for _, target, _ in machine.transitions]


@pytest.mark.asyncio
async def test_execute_node_skips_plan_refresh_when_execution_ok_false() -> None:
    event_id = "evt-329-skip-refresh"

    class _FailingExec:
        async def execute_plan(self, *_a: Any, **_k: Any) -> Any:
            raise RuntimeError("execute_plan failed")

    machine = FakeStateMachine(
        status=EventStatus.EXECUTING_RESPONSE,
        statuses={event_id: EventStatus.EXECUTING_RESPONSE},
    )
    session = _ExecuteOverlaySession(
        [_execute_orm_action_row(event_id=event_id, action_id="act-329-001")]
    )
    services = _services(machine)
    services["action_execution"] = _FailingExec()
    services["session_factory"] = _ExecuteSessionFactory(session)
    graph = build_investigation_graph(_agents(), services)
    result = await graph.nodes[NODE_EXECUTE].ainvoke(  # type: ignore[attr-defined]
        _base_state(
            event_id=event_id,
            event_status=EventStatus.EXECUTING_RESPONSE.value,
            response_plan=_pending_execute_plan(event_id),
        )
    )
    assert result["execution_ok"] is False
    assert "response_plan" not in result
    assert result["event_status"] == EventStatus.VERIFYING.value


@pytest.mark.asyncio
async def test_verify_node_soft_limit_reraises() -> None:
    """ISSUE-314: verify_agent SoftTimeLimit must not degrade and continue."""
    from celery.exceptions import SoftTimeLimitExceeded

    from app.orchestration.workflow_graph import NODE_VERIFY, build_investigation_graph

    event_id = "evt-soft-verify"
    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )

    class _SoftVerify:
        async def execute(self, *_a: Any, **_k: Any) -> Any:
            raise SoftTimeLimitExceeded()

    agents = _agents_with_verify(_SoftVerify())
    services = _services(machine)
    graph = build_investigation_graph(agents, services)
    with pytest.raises(SoftTimeLimitExceeded):
        await graph.nodes[NODE_VERIFY].ainvoke(  # type: ignore[attr-defined]
            _base_state(
                event_id=event_id,
                event_status=EventStatus.VERIFYING.value,
            )
        )


@pytest.mark.asyncio
async def test_mark_graph_failed_skips_failed_self_loop() -> None:
    from app.orchestration.workflow_graph import _mark_graph_failed

    event_id = "evt-failed-self-loop"

    class _RejectFailedSelfLoop(FakeStateMachine):
        async def transition(self, event_id: str, target: EventStatus, **kwargs: Any) -> Any:
            current = self.statuses.get(event_id, EventStatus.TRIAGING)
            if current is EventStatus.FAILED and target is EventStatus.FAILED:
                raise InvalidStateTransitionError(
                    "illegal transition",
                    current=EventStatus.FAILED,
                    target=EventStatus.FAILED,
                )
            return await super().transition(event_id, target, **kwargs)

    machine = _RejectFailedSelfLoop(
        status=EventStatus.FAILED,
        statuses={event_id: EventStatus.FAILED},
    )
    services = {"state_machine": machine}
    state = _base_state(event_id=event_id, event_status=EventStatus.FAILED.value)

    await _mark_graph_failed(services, state, RuntimeError("stale resume"))

    assert machine.transitions == []


@pytest.mark.asyncio
async def test_mark_graph_failed_swallows_failed_to_failed_transition_error() -> None:
    from app.orchestration.workflow_graph import _mark_graph_failed

    event_id = "evt-failed-race"

    class _StaleReadMachine(FakeStateMachine):
        async def get_current_status(self, event_id: str) -> EventStatus:
            return EventStatus.VERIFYING

        async def transition(self, event_id: str, target: EventStatus, **kwargs: Any) -> Any:
            raise InvalidStateTransitionError(
                "illegal transition",
                current=EventStatus.FAILED,
                target=EventStatus.FAILED,
            )

    machine = _StaleReadMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    services = {"state_machine": machine}
    state = _base_state(event_id=event_id, event_status=EventStatus.VERIFYING.value)

    await _mark_graph_failed(services, state, RuntimeError("stale resume"))

    assert machine.transitions == []


@pytest.mark.asyncio
async def test_mark_graph_failed_is_noop_for_closed_status() -> None:
    from app.orchestration.workflow_graph import _mark_graph_failed

    event_id = "evt-closed-noop"
    machine = FakeStateMachine(
        status=EventStatus.CLOSED,
        statuses={event_id: EventStatus.CLOSED},
    )
    services = {"state_machine": machine}
    state = _base_state(event_id=event_id, event_status=EventStatus.CLOSED.value)

    await _mark_graph_failed(services, state, RuntimeError("resume loop"))

    assert machine.transitions == []


@pytest.mark.asyncio
async def test_mark_graph_failed_skips_on_state_mismatch_validation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.orchestration.workflow_graph import _mark_graph_failed

    noop_calls: list[str] = []
    monkeypatch.setattr(
        "app.orchestration.workflow_graph.record_graph_failed_transition_noop",
        lambda *, reason: noop_calls.append(reason),
    )

    event_id = "evt-mismatch-noop"
    machine = FakeStateMachine(
        status=EventStatus.VERIFYING,
        statuses={event_id: EventStatus.VERIFYING},
    )
    services = {"state_machine": machine}
    state = _base_state(event_id=event_id, event_status=EventStatus.VERIFYING.value)
    mismatch = ValidationError(
        "caller EventStatus does not match authoritative state",
        details={
            "caller_status": EventStatus.EXECUTING_RESPONSE.value,
            "authoritative_status": EventStatus.FAILED.value,
        },
    )

    await _mark_graph_failed(services, state, mismatch)

    assert machine.transitions == []
    assert noop_calls == ["state_mismatch"]


@pytest.mark.asyncio
async def test_planner_revise_soft_limit_not_fresh_plan() -> None:
    """ISSUE-314: SoftTimeLimit in planner.revise must not fall back to fresh plan."""
    from celery.exceptions import SoftTimeLimitExceeded

    from app.orchestration.workflow_graph import planner_node

    class SoftPlanner:
        async def revise(self, *_a: Any, **_k: Any) -> Any:
            raise SoftTimeLimitExceeded()

        async def execute(self, *_a: Any, **_k: Any) -> Any:
            raise AssertionError("fresh plan must not run after soft-limit")

        async def plan_disposition_only(self, *_a: Any, **_k: Any) -> Any:
            raise AssertionError("disposition-only must not run")

    triage = TriageResult(
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.MEDIUM,
        need_investigation=True,
        decision_summary="soft-limit replan",
    )
    plan = ExecutionPlan(
        plan_id="pln-soft-replan",
        event_id="evt-soft-replan",
        steps=[
            PlanStep(
                step_order=1,
                step_goal="risk",
                assigned_agent="risk_agent",
                required_tools=[],
                success_criteria="ok",
            )
        ],
        budget=PlanBudget(max_tool_calls=10),
        revision=0,
    )
    event_context = EventContext(
        event=EventSummary(
            event_id="evt-soft-replan",
            event_type=EventType.MALICIOUS_PROCESS,
            title="soft replan",
            status=EventStatus.ANALYZING,
            severity=Severity.MEDIUM,
            risk_score=0,
            final_verdict=FinalVerdict.NONE,
            writeback_required=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
        ),
        triage_result=triage.model_dump(mode="json"),
        execution_plan=plan.model_dump(mode="json"),
        replan_count=1,
    )
    with pytest.raises(SoftTimeLimitExceeded):
        await planner_node(event_context, SoftPlanner())  # type: ignore[arg-type]
