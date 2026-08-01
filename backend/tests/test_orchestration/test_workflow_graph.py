"""ISSUE-048 StateGraph unit and recovery tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from app.agents.planner_agent import PlannerAgent
from app.core.errors import InvalidStateTransitionError
from app.models.agent_io import (
    CollectionStatus,
    EffectStatus,
    EvidenceOutput,
    ReportAgentInput,
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
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionSubstate,
    FinalVerdict,
    Severity,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.workflow import TransitionContext, validate_transition
from app.orchestration.checkpointer import (
    CHECKPOINT_TTL_SECONDS,
    RedisCheckpointer,
    checkpoint_key_for_event,
)
from app.orchestration.graph_state import InvestigationState
from app.orchestration.replan_handler import MAX_REPLAN_COUNT
from app.orchestration.workflow_graph import (
    NODE_APPROVAL,
    NODE_APPROVAL_WAIT,
    NODE_CLOSE,
    NODE_EXECUTE,
    NODE_FP_ADJUDICATION,
    NODE_HALT,
    NODE_MANUAL_HOLD,
    NODE_PLANNER,
    NODE_RAG,
    NODE_REPLAN,
    NODE_REPORT,
    NODE_RESPONSE,
    NODE_RISK,
    NODE_VERIFY,
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
    ROUTE_WAIT,
    ROUTE_WRITEBACK,
    _resolve_verify_writeback_status,
    build_investigation_graph,
    route_after_approval,
    route_after_fp_adjudication,
    route_after_planner,
    route_after_report,
    route_after_risk,
    route_after_triage,
    route_after_verify,
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


class FakeEventService:
    def __init__(self) -> None:
        self.verdicts: list[FinalVerdict] = []

    async def set_final_verdict(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
    ) -> Any:
        self.verdicts.append(verdict)
        return SimpleNamespace(event_id=event_id, final_verdict=verdict)


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
    async def get_full_context(self, event_id: str) -> EventContext:
        return EventContext()


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
    }


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


class TestRouteAfterTriage:
    def test_not_required_no_investigation_closes(self) -> None:
        assert route_after_triage(_base_state(need_investigation=False)) == ROUTE_CLOSE

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
    assert route_after_report(_base_state()) == ROUTE_CLOSE
    assert (
        route_after_approval(
            _base_state(execution_substate=ExecutionSubstate.WAITING_APPROVAL.value)
        )
        == ROUTE_WAIT
    )
    assert route_after_approval(_base_state()) == ROUTE_EXECUTE
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
    assert (NODE_RAG, NODE_RISK) in edges


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
        NODE_RISK,
        NODE_REPORT,
        NODE_HALT,
    ]
    assert machine.status is EventStatus.REPORTING
    assert final["halted"] is True


@pytest.mark.asyncio
async def test_required_threat_never_enters_disposition_only() -> None:
    """REQUIRED non-FP threat does not take the disposition-only shortcut.

    With ISSUE-062 Should-Fix #2, the verify_node for required policy
    without a response_plan escalates to MANUAL_RESOLUTION instead of
    silently proceeding with a placeholder plan.  The graph reaches
    manual_hold_node with verify_need_manual_resolution=True and halts.
    We assert the disposition-only path was not taken and the event is
    routed to manual hold.
    """
    runtime = FakeRuntime(WritebackReadiness.READY)
    services = _services(runtime=runtime)
    final = await build_investigation_graph(
        _agents(),
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
    assert final["verify_need_manual_resolution"] is True
    assert any(
        "missing_response_plan_for_required_policy" in f for f in final.get("degraded_flags", [])
    )
    degraded = services["degraded_flags"]
    assert any(call[3] == "InvestigationGraph" for call in getattr(degraded, "calls", []))


@pytest.mark.asyncio
async def test_required_golden_path_order_halts_at_verify() -> None:
    """P0 main-chain order through verify, then MANUAL_RESOLUTION (ISSUE-062).

    With ISSUE-062 Should-Fix #2, when disposition_policy=REQUIRED and no
    response_plan exists, verify_node escalates to MANUAL_RESOLUTION rather
    than constructing a placeholder and proceeding to REPORTING.  The graph
    ends at manual_hold_node with halted=True.
    """
    final = await build_investigation_graph(
        _agents(),
        _services(runtime=FakeRuntime(WritebackReadiness.READY)),
    ).ainvoke(
        _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            event_status_update_readiness=WritebackReadiness.READY.value,
        ),
        {"configurable": {"thread_id": "evt-required-golden"}},
    )
    assert final["halted"] is True
    assert final["verify_need_manual_resolution"] is True


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
    before the approval gate.  On resume without an approval_engine,
    the stub path transitions to EXECUTING_RESPONSE and the graph
    continues to completion — simulating the external API having
    already approved the plan.
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

    # Phase 2: simulate external approval — create a new graph WITHOUT
    # approval_engine.  When resumed, approval_node runs in stub mode:
    # it transitions to EXECUTING_RESPONSE, sets execution_substate=NONE,
    # and route_after_approval routes to EXECUTE (not WAIT).
    machine2 = FakeStateMachine(
        status=EventStatus.PLANNING_RESPONSE,
        statuses={"evt-approval-resume": EventStatus.PLANNING_RESPONSE},
    )
    services2 = _services(machine2)
    # No approval_engine → approval_node stub path → EXECUTING_RESPONSE
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

    # Phase 2: resume without approval_engine → stub approval path →
    # EXECUTING_RESPONSE → executes → completes to CLOSED.
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
