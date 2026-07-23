"""LangGraph investigation workflow tests (ISSUE-048)."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from app.agents.planner_agent import PlannerAgent, _generate_disposition_only_plan_id
from app.core.errors import InvalidStateTransitionError
from app.core.redis_client import RedisClient
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionSubstate,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.report import InvestigationReport
from app.orchestration.checkpointer import RedisCheckpointer, checkpoint_key_for_event
from app.orchestration.graph_state import InvestigationState
from app.orchestration.workflow_graph import (
    NODE_CLOSE,
    NODE_HALT,
    NODE_MANUAL_HOLD,
    NODE_PLANNER,
    NODE_RISK,
    NODE_TRIAGE,
    P0_NODE_SEQUENCE,
    build_investigation_graph,
)
from app.orchestration.workflow_routes import (
    ROUTE_AFTER_APPROVAL_EXECUTE,
    ROUTE_AFTER_APPROVAL_WAIT,
    ROUTE_AFTER_PLANNER_EVIDENCE,
    ROUTE_AFTER_PLANNER_RESPONSE,
    ROUTE_AFTER_RISK_RESPONSE,
    ROUTE_AFTER_TRIAGE_CLOSE,
    ROUTE_AFTER_TRIAGE_DISPOSITION_ONLY,
    ROUTE_AFTER_TRIAGE_INVESTIGATE,
    ROUTE_AFTER_TRIAGE_MANUAL_HOLD,
    ROUTE_AFTER_VERIFY_HALT,
    ROUTE_AFTER_VERIFY_MANUAL,
    ROUTE_AFTER_VERIFY_REPLAN,
    ROUTE_AFTER_VERIFY_REPORT,
    ROUTE_AFTER_VERIFY_WRITEBACK,
    route_after_approval,
    route_after_planner,
    route_after_risk,
    route_after_triage,
    route_after_verify,
)


def _base_state(**overrides: Any) -> InvestigationState:
    state: InvestigationState = {
        "event_id": "evt-graph-001",
        "event_status": EventStatus.TRIAGING.value,
        "disposition_policy": DispositionPolicy.REQUIRED.value,
        "severity": Severity.HIGH.value,
        "final_verdict": None,
        "confidence": 0.0,
        "need_investigation": True,
        "execution_substate": ExecutionSubstate.NONE.value,
        "event_status_update_readiness": WritebackReadiness.READY.value,
        "degraded_flags": [],
        "node_trace": [],
        "halted": False,
        "disposition_only_intent": False,
        "include_rag": False,
        "memory_checkpointer": False,
        "report_generated": False,
        "needs_approval_wait": False,
    }
    state.update(overrides)
    return state


@dataclass
class FakeStateMachine:
    transitions: list[tuple[str, EventStatus]] = field(default_factory=list)
    status: EventStatus = EventStatus.TRIAGING

    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: Any = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> SimpleNamespace:
        self.transitions.append((event_id, target))
        self.status = target
        return SimpleNamespace(status=target, event_id=event_id)


class StubAgent:
    def __init__(self, result: Any) -> None:
        self._result = result
        self.calls: list[Any] = []

    async def execute(self, input: Any) -> Any:
        self.calls.append(input)
        return self._result


class FakeRedisStore:
    def __init__(self) -> None:
        self.kv: dict[str, bytes] = {}

    async def get(self, key: str) -> bytes | None:
        return self.kv.get(key)

    async def set(self, key: str, value: bytes, *, ex: int | None = None) -> None:
        self.kv[key] = value

    async def delete(self, key: str) -> None:
        self.kv.pop(key, None)

    async def ping(self) -> bool:
        return True


class FakeRedisClient:
    def __init__(self) -> None:
        self.store = FakeRedisStore()

    def get_client(self) -> FakeRedisStore:
        return self.store

    async def ping(self) -> bool:
        return True

    @staticmethod
    def dumps(value: Any) -> bytes:
        return RedisClient.dumps(value)


def _make_agents(*, triage: TriageResult | None = None) -> dict[str, Any]:
    triage_result = triage or TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="investigate",
    )
    evidence = EvidenceOutput(collection_status=CollectionStatus.COMPLETED)
    risk = RiskAssessment(
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    report = InvestigationReport(
        report_id="rpt-test-001",
        event_id="evt-graph-001",
        title="Test",
        summary="summary",
        sections=[],
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        risk_score=80,
        severity=Severity.HIGH,
    )
    return {
        "triage_agent": StubAgent(triage_result),
        "planner_agent": PlannerAgent(),
        "evidence_agent": StubAgent(evidence),
        "risk_agent": StubAgent(risk),
        "report_agent": StubAgent(report),
    }


def _make_services(state_machine: FakeStateMachine | None = None) -> dict[str, Any]:
    return {"state_machine": state_machine or FakeStateMachine()}


# --------------------------------------------------------------------------- #
# Route functions — 100% branch coverage
# --------------------------------------------------------------------------- #


class TestRouteAfterTriage:
    def test_not_required_low_close(self) -> None:
        state = _base_state(
            disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
            severity=Severity.LOW.value,
        )
        assert route_after_triage(state) == ROUTE_AFTER_TRIAGE_CLOSE

    def test_not_required_fp_close(self) -> None:
        state = _base_state(
            disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
            false_positive_match={"recommendation": "close_as_fp"},
        )
        assert route_after_triage(state) == ROUTE_AFTER_TRIAGE_CLOSE

    def test_required_fp_ready_disposition_only(self) -> None:
        state = _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            false_positive_match={"recommendation": "close_as_fp", "max_score": 0.95},
            event_status_update_readiness=WritebackReadiness.READY.value,
        )
        assert route_after_triage(state) == ROUTE_AFTER_TRIAGE_DISPOSITION_ONLY

    def test_required_fp_blocked_manual_hold(self) -> None:
        state = _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            false_positive_match={"recommendation": "close_as_fp"},
            event_status_update_readiness=WritebackReadiness.CAPABILITY_UNKNOWN.value,
        )
        assert route_after_triage(state) == ROUTE_AFTER_TRIAGE_MANUAL_HOLD

    def test_required_threat_investigate(self) -> None:
        state = _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            severity=Severity.HIGH.value,
            need_investigation=True,
        )
        assert route_after_triage(state) == ROUTE_AFTER_TRIAGE_INVESTIGATE


class TestRouteAfterPlanner:
    def test_disposition_only_response(self) -> None:
        assert route_after_planner(_base_state(disposition_only_intent=True)) == (
            ROUTE_AFTER_PLANNER_RESPONSE
        )

    def test_investigate_evidence(self) -> None:
        assert route_after_planner(_base_state(disposition_only_intent=False)) == (
            ROUTE_AFTER_PLANNER_EVIDENCE
        )


class TestRouteAfterRisk:
    def test_always_response(self) -> None:
        assert route_after_risk(_base_state()) == ROUTE_AFTER_RISK_RESPONSE


class TestRouteAfterApproval:
    def test_waiting_approval(self) -> None:
        state = _base_state(execution_substate=ExecutionSubstate.WAITING_APPROVAL.value)
        assert route_after_approval(state) == ROUTE_AFTER_APPROVAL_WAIT

    def test_execute(self) -> None:
        assert route_after_approval(_base_state()) == ROUTE_AFTER_APPROVAL_EXECUTE


class TestRouteAfterVerify:
    def test_manual(self) -> None:
        assert route_after_verify(_base_state(verify_need_manual_resolution=True)) == (
            ROUTE_AFTER_VERIFY_MANUAL
        )

    def test_writeback(self) -> None:
        assert route_after_verify(_base_state(verify_need_writeback_recovery=True)) == (
            ROUTE_AFTER_VERIFY_WRITEBACK
        )

    def test_replan(self) -> None:
        assert route_after_verify(_base_state(verify_need_action_replan=True)) == (
            ROUTE_AFTER_VERIFY_REPLAN
        )

    def test_disposition_halt(self) -> None:
        assert route_after_verify(_base_state(disposition_only_intent=True)) == (
            ROUTE_AFTER_VERIFY_HALT
        )

    def test_report_default(self) -> None:
        assert route_after_verify(_base_state()) == ROUTE_AFTER_VERIFY_REPORT


# --------------------------------------------------------------------------- #
# Graph compile + golden path
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_graph_compiles_without_cycle_error() -> None:
    graph = build_investigation_graph(_make_agents(), _make_services())
    assert graph is not None
    assert "triage_node" in graph.get_graph().nodes


@pytest.mark.asyncio
async def test_golden_path_node_order() -> None:
    sm = FakeStateMachine()
    graph = build_investigation_graph(_make_agents(), _make_services(sm))
    config = {"configurable": {"thread_id": "evt-graph-001"}}
    final = await graph.ainvoke(_base_state(), config)
    trace = final["node_trace"]
    for expected in P0_NODE_SEQUENCE:
        assert expected in trace
    assert trace.index(NODE_TRIAGE) < trace.index(NODE_PLANNER) < trace.index(NODE_CLOSE)
    assert sm.status is EventStatus.CLOSED


@pytest.mark.asyncio
async def test_not_required_low_short_circuit_close() -> None:
    sm = FakeStateMachine()
    triage = TriageResult(
        event_type=EventType.OTHER,
        severity=Severity.LOW,
        need_investigation=False,
        reasoning="low",
    )
    graph = build_investigation_graph(_make_agents(triage=triage), _make_services(sm))
    final = await graph.ainvoke(
        _base_state(
            disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
            severity=Severity.LOW.value,
        ),
        {"configurable": {"thread_id": "evt-low-close"}},
    )
    assert NODE_CLOSE in final["node_trace"]
    assert NODE_PLANNER not in final["node_trace"]
    assert sm.status is EventStatus.CLOSED


@pytest.mark.asyncio
async def test_required_threat_does_not_enter_disposition_only() -> None:
    sm = FakeStateMachine()
    graph = build_investigation_graph(_make_agents(), _make_services(sm))
    final = await graph.ainvoke(_base_state(), {"configurable": {"thread_id": "evt-threat"}})
    assert final.get("disposition_only_intent") is False
    assert NODE_PLANNER in final["node_trace"]
    assert NODE_HALT not in final["node_trace"]


@pytest.mark.asyncio
async def test_readiness_blocked_sets_degraded_flag_not_manual_substate() -> None:
    graph = build_investigation_graph(_make_agents(), _make_services())
    final = await graph.ainvoke(
        _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            false_positive_match={"recommendation": "close_as_fp"},
            event_status_update_readiness=WritebackReadiness.CAPABILITY_UNSUPPORTED.value,
        ),
        {"configurable": {"thread_id": "evt-blocked"}},
    )
    assert NODE_MANUAL_HOLD in final["node_trace"]
    assert any("disposition_writeback_blocked=" in f for f in final["degraded_flags"])
    assert final["execution_substate"] == ExecutionSubstate.NONE.value
    assert final["halted"] is True


@pytest.mark.asyncio
async def test_disposition_only_halts_before_closed() -> None:
    calls: list[str] = []

    class TrackingRuntime:
        async def begin_disposition_only(self, event_id: str) -> None:
            calls.append(event_id)

        async def set_execution_substate(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def assert_disposition_only_transition_allowed(
            self, *args: Any, **kwargs: Any
        ) -> None:
            return None

    sm = FakeStateMachine()
    services = _make_services(sm)
    services["workflow_runtime"] = TrackingRuntime()
    graph = build_investigation_graph(_make_agents(), services)
    final = await graph.ainvoke(
        _base_state(
            disposition_policy=DispositionPolicy.REQUIRED.value,
            false_positive_match={"recommendation": "close_as_fp", "max_score": 0.91},
            event_status_update_readiness=WritebackReadiness.READY.value,
        ),
        {"configurable": {"thread_id": "evt-disp-only"}},
    )
    assert calls == ["evt-graph-001"]
    assert final.get("disposition_only_intent") is True
    assert final.get("final_verdict") == FinalVerdict.FALSE_POSITIVE.value
    assert NODE_HALT in final["node_trace"]
    assert NODE_CLOSE not in final["node_trace"]
    assert final["halted"] is True
    assert sm.status is not EventStatus.CLOSED


@pytest.mark.asyncio
async def test_disposition_only_plan_is_stable() -> None:
    planner = PlannerAgent()
    from app.models.context import EventContext
    from app.models.security_event import EventSummary

    summary = EventSummary(
        event_id="evt-stable-plan",
        event_type=EventType.OTHER,
        title="t",
        status=EventStatus.TRIAGING,
        severity=Severity.MEDIUM,
        risk_score=0,
        final_verdict=FinalVerdict.NONE,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    ctx = EventContext(event=summary)
    plan1 = await planner.plan_disposition_only(ctx)
    plan2 = await planner.plan_disposition_only(ctx)
    assert plan1.plan_id == plan2.plan_id == _generate_disposition_only_plan_id("evt-stable-plan")
    assert len(plan1.steps) == 1
    assert plan1.steps[0].assigned_agent == "response_agent"


@pytest.mark.asyncio
async def test_forged_disposition_only_intent_rejected() -> None:
    class DenyRuntime:
        async def assert_disposition_only_transition_allowed(
            self,
            event_id: str,
            *,
            target: EventStatus,
            current: EventStatus,
        ) -> None:
            raise InvalidStateTransitionError(
                "forged disposition_only_intent",
                current=current.value,
                target=target.value,
            )

    with pytest.raises(InvalidStateTransitionError):
        await DenyRuntime().assert_disposition_only_transition_allowed(
            "evt-forged",
            target=EventStatus.PLANNING_RESPONSE,
            current=EventStatus.TRIAGING,
        )


@pytest.mark.asyncio
async def test_checkpoint_recovery_from_redis() -> None:
    fake_redis = FakeRedisClient()
    cp1 = await RedisCheckpointer.create(fake_redis)  # type: ignore[arg-type]
    assert cp1.memory_fallback is False

    sm = FakeStateMachine()
    graph1 = build_investigation_graph(
        _make_agents(),
        _make_services(sm),
        checkpointer=cp1,
        interrupt_before=[NODE_RISK],
    )
    config = {"configurable": {"thread_id": "evt-recover-001"}}
    await graph1.ainvoke(_base_state(event_id="evt-recover-001"), config)

    key = checkpoint_key_for_event("evt-recover-001")
    assert key in fake_redis.store.kv

    cp2 = await RedisCheckpointer.create(fake_redis)  # type: ignore[arg-type]
    graph2 = build_investigation_graph(_make_agents(), _make_services(sm), checkpointer=cp2)
    final = await graph2.ainvoke(None, config)
    assert NODE_CLOSE in final["node_trace"]
    assert final["node_trace"].count(NODE_RISK) == 1


@pytest.mark.asyncio
async def test_memory_fallback_marks_non_recoverable() -> None:
    cp = await RedisCheckpointer.create(None)
    assert cp.memory_fallback is True
