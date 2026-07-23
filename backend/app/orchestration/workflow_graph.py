"""Workflow graph nodes (ISSUE-048/ISSUE-049).

Provides ``planner_node`` / ``rag_node`` helpers and ``build_investigation_graph``
for the LangGraph investigation StateGraph (ISSUE-048).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine, Mapping
from typing import Any, Protocol, cast

from langchain_core.runnables.config import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.agents.planner_agent import PlannerAgent
from app.agents.rag_agent import RAGAgent
from app.core.errors import InvalidStateTransitionError
from app.models.agent_io import (
    EvidenceAgentInput,
    EvidenceOutput,
    ExecutionPlan,
    PlannerAgentInput,
    RAGOutput,
    ReportAgentInput,
    RiskAgentInput,
    RiskAssessment,
    TriageAgentInput,
    TriageResult,
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
)
from app.models.security_event import EventSummary
from app.models.workflow import TransitionContext
from app.orchestration.graph_state import InvestigationState
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
from app.services.analysis_only_pipeline import run_rag_stage
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import format_degraded_flag
from app.services.state_machine_service import StateMachineService

logger = logging.getLogger(__name__)

CompiledInvestigationGraph = CompiledStateGraph[
    InvestigationState, None, InvestigationState, InvestigationState
]

_GRAPH_OPERATOR = "InvestigationGraph"

# Node names (locked for downstream issues)
NODE_TRIAGE = "triage_node"
NODE_BEGIN_DISPOSITION_ONLY = "begin_disposition_only_node"
NODE_MANUAL_HOLD = "manual_hold_node"
NODE_CLOSE = "close_node"
NODE_PLANNER = "planner_node"
NODE_EVIDENCE = "evidence_node"
NODE_RAG = "rag_node"
NODE_RISK = "risk_node"
NODE_RESPONSE = "response_node"
NODE_APPROVAL = "approval_node"
NODE_APPROVAL_WAIT = "approval_wait_node"
NODE_EXECUTE = "execute_node"
NODE_VERIFY = "verify_node"
NODE_REPLAN = "replan_node"
NODE_REPORT = "report_node"
NODE_HALT = "halt_node"

P0_NODE_SEQUENCE = (
    NODE_TRIAGE,
    NODE_PLANNER,
    NODE_EVIDENCE,
    NODE_RISK,
    NODE_RESPONSE,
    NODE_APPROVAL,
    NODE_EXECUTE,
    NODE_VERIFY,
    NODE_REPORT,
    NODE_CLOSE,
)


class _AgentLike(Protocol):
    async def execute(self, input: Any) -> Any: ...


class _WorkflowRuntimeLike(Protocol):
    async def begin_disposition_only(self, event_id: str) -> None: ...
    async def read_disposition_only_intent(self, event_id: str) -> bool: ...
    async def set_execution_substate(
        self,
        event_id: str,
        substate: ExecutionSubstate,
        *,
        event_status: EventStatus,
    ) -> None: ...
    async def assert_disposition_only_transition_allowed(
        self,
        event_id: str,
        *,
        target: EventStatus,
        current: EventStatus,
    ) -> None: ...


class _DegradedFlagLike(Protocol):
    async def set_flag(
        self,
        event_id: str,
        flag_name: str,
        value: Any,
        writer: str,
    ) -> list[str]: ...


class _EventServiceLike(Protocol):
    async def set_final_verdict(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
    ) -> Any: ...


def _trace(node_name: str) -> dict[str, list[str]]:
    return {"node_trace": [node_name]}


def _patch_state(*parts: Mapping[str, Any]) -> InvestigationState:
    merged: dict[str, Any] = {}
    for part in parts:
        merged.update(part)
    return cast(InvestigationState, merged)


async def _read_persisted_disposition_only_intent(
    services: dict[str, Any],
    event_id: str,
) -> bool:
    runtime = services.get("workflow_runtime")
    if runtime is not None and hasattr(runtime, "read_disposition_only_intent"):
        return bool(await runtime.read_disposition_only_intent(event_id))
    store = cast(EventContextStore | None, services.get("context_store"))
    if store is not None:
        value = await store.get(event_id, "disposition_only_intent")
        return bool(value)
    return False


async def _hydrate_context_fields(
    services: dict[str, Any],
    event_id: str,
    target: dict[str, Any],
) -> None:
    store = cast(EventContextStore | None, services.get("context_store"))
    if store is None:
        return
    ctx = await store.get_full_context(event_id)
    if ctx.false_positive_match is not None:
        target["false_positive_match"] = ctx.false_positive_match
    if ctx.source_snapshot is not None:
        target["source_snapshot"] = ctx.source_snapshot
    if ctx.event is not None:
        target.setdefault("disposition_policy", ctx.event.disposition_policy.value)
        target.setdefault("severity", ctx.event.severity.value)
        if ctx.event.writeback_readiness is not None:
            target.setdefault(
                "event_status_update_readiness",
                ctx.event.writeback_readiness.value,
            )


async def _mark_graph_failed(services: dict[str, Any], state: InvestigationState) -> None:
    state_machine = services.get("state_machine")
    if state_machine is None:
        return
    try:
        await cast(StateMachineService, state_machine).transition(
            state["event_id"],
            EventStatus.FAILED,
            operator=_GRAPH_OPERATOR,
            reason="investigation_graph:error",
        )
    except Exception:
        logger.exception(
            "failed to transition event=%s to FAILED after graph error",
            state.get("event_id"),
        )


def _wrap_node(
    services: dict[str, Any],
    fn: Callable[[InvestigationState], Coroutine[Any, Any, InvestigationState]],
) -> Callable[[InvestigationState], Coroutine[Any, Any, InvestigationState]]:
    async def wrapped(state: InvestigationState) -> InvestigationState:
        try:
            return await fn(state)
        except Exception:
            await _mark_graph_failed(services, state)
            raise

    return wrapped


async def invoke_investigation_graph(
    graph: CompiledInvestigationGraph,
    state: InvestigationState,
    config: RunnableConfig,
    services: dict[str, Any],
) -> InvestigationState:
    """Run the compiled graph; on failure mark FAILED then re-raise."""
    try:
        result = await graph.ainvoke(state, config)
        return cast(InvestigationState, result)
    except Exception as exc:
        await _mark_graph_failed(services, state)
        raise exc


def _event_summary_from_state(state: InvestigationState) -> EventSummary:
    return EventSummary(
        event_id=state["event_id"],
        event_type=EventType.OTHER,
        title="investigation",
        status=EventStatus(state.get("event_status", EventStatus.TRIAGING.value)),
        severity=Severity(state.get("severity", Severity.MEDIUM.value)),
        risk_score=0,
        final_verdict=FinalVerdict(state.get("final_verdict") or FinalVerdict.NONE.value),
        writeback_required=False,
        writeback_readiness=WritebackReadiness(
            state.get("event_status_update_readiness", WritebackReadiness.NOT_REQUIRED.value)
        ),
        disposition_policy=DispositionPolicy(
            state.get("disposition_policy", DispositionPolicy.NOT_REQUIRED.value)
        ),
    )


def _event_context_from_state(state: InvestigationState) -> EventContext:
    summary = _event_summary_from_state(state)
    return EventContext(
        event=summary,
        triage_result=state.get("triage_result"),
        false_positive_match=state.get("false_positive_match"),
        source_snapshot=state.get("source_snapshot"),
        disposition_only_intent=bool(state.get("disposition_only_intent")),
        execution_substate=ExecutionSubstate(state.get("execution_substate", "none")),
        execution_plan=state.get("execution_plan"),
    )


async def _transition_status(
    services: dict[str, Any],
    state: InvestigationState,
    target: EventStatus,
    *,
    context: TransitionContext | None = None,
    reason: str,
) -> dict[str, str]:
    state_machine = services.get("state_machine")
    event_id = state["event_id"]
    if state_machine is not None:
        await cast(StateMachineService, state_machine).transition(
            event_id,
            target,
            context=context,
            operator=_GRAPH_OPERATOR,
            reason=reason,
        )
    return {"event_status": target.value}


def build_investigation_graph(
    agents: dict[str, Any],
    services: dict[str, Any],
    *,
    checkpointer: Any | None = None,
    interrupt_before: list[str] | None = None,
    interrupt_after: list[str] | None = None,
) -> CompiledInvestigationGraph:
    """Build and compile the investigation LangGraph (dependency injection only)."""
    triage_agent = cast(_AgentLike, agents["triage_agent"])
    planner_agent = cast(PlannerAgent, agents["planner_agent"])
    evidence_agent = cast(_AgentLike, agents["evidence_agent"])
    risk_agent = cast(_AgentLike, agents["risk_agent"])
    report_agent = cast(_AgentLike, agents["report_agent"])
    rag_agent = agents.get("rag_agent")
    workflow_runtime = cast(_WorkflowRuntimeLike | None, services.get("workflow_runtime"))
    degraded_flags = cast(_DegradedFlagLike | None, services.get("degraded_flags"))
    event_service = cast(_EventServiceLike | None, services.get("event_service"))

    async def triage_node(state: InvestigationState) -> InvestigationState:
        triage_input = TriageAgentInput(
            event_id=state["event_id"],
            raw_event_summary="",
        )
        result = await triage_agent.execute(triage_input)
        if not isinstance(result, TriageResult):
            raise TypeError("triage_agent must return TriageResult")
        update: dict[str, Any] = {
            **_trace(NODE_TRIAGE),
            "triage_result": result.model_dump(mode="json"),
            "need_investigation": result.need_investigation,
            "severity": result.severity.value,
        }
        await _hydrate_context_fields(services, state["event_id"], update)
        return _patch_state(update)

    async def begin_disposition_only_node(state: InvestigationState) -> InvestigationState:
        if workflow_runtime is None:
            raise RuntimeError("workflow_runtime is required for disposition-only path")
        await workflow_runtime.begin_disposition_only(state["event_id"])
        if workflow_runtime is not None:
            await workflow_runtime.assert_disposition_only_transition_allowed(
                state["event_id"],
                target=EventStatus.PLANNING_RESPONSE,
                current=EventStatus(state.get("event_status", EventStatus.TRIAGING.value)),
            )
        status_update = await _transition_status(
            services,
            state,
            EventStatus.PLANNING_RESPONSE,
            context=TransitionContext(
                final_verdict=FinalVerdict.FALSE_POSITIVE,
                disposition_only_intent=True,
                disposition_policy=DispositionPolicy(state["disposition_policy"]),
                recommendation="close_as_fp",
            ),
            reason="disposition_only:begin",
        )
        return _patch_state(
            _trace(NODE_BEGIN_DISPOSITION_ONLY),
            status_update,
            {
                "disposition_only_intent": True,
                "disposition_only_active": True,
                "final_verdict": FinalVerdict.FALSE_POSITIVE.value,
            },
        )

    async def manual_hold_node(state: InvestigationState) -> InvestigationState:
        readiness = state.get(
            "event_status_update_readiness",
            WritebackReadiness.CAPABILITY_UNKNOWN.value,
        )
        flag_entry = format_degraded_flag("disposition_writeback_blocked", readiness)
        flags = list(state.get("degraded_flags") or [])
        if flag_entry and flag_entry not in flags:
            flags.append(flag_entry)
        if degraded_flags is not None:
            await degraded_flags.set_flag(
                state["event_id"],
                "disposition_writeback_blocked",
                readiness,
                writer="StateMachineService",
            )
        return _patch_state(
            _trace(NODE_MANUAL_HOLD),
            {
                "degraded_flags": flags,
                "halted": True,
                "execution_substate": ExecutionSubstate.NONE.value,
            },
        )

    async def close_node(state: InvestigationState) -> InvestigationState:
        policy = DispositionPolicy(state.get("disposition_policy", "not_required"))
        severity = Severity(state.get("severity", Severity.MEDIUM.value))
        is_fp = (state.get("false_positive_match") or {}).get("recommendation") == "close_as_fp"
        if (
            event_service is not None
            and policy is DispositionPolicy.NOT_REQUIRED
            and (severity is Severity.LOW or is_fp)
            and is_fp
        ):
            await event_service.set_final_verdict(
                state["event_id"],
                FinalVerdict.FALSE_POSITIVE,
                operator=_GRAPH_OPERATOR,
            )
        ctx = TransitionContext(
            disposition_policy=DispositionPolicy(state.get("disposition_policy", "not_required")),
            severity=Severity(state.get("severity", Severity.MEDIUM.value)),
            recommendation=(state.get("false_positive_match") or {}).get("recommendation"),
            final_verdict=(
                FinalVerdict(fv) if (fv := state.get("final_verdict")) is not None else None
            ),
            report_exists=bool(state.get("report_generated")),
        )
        status_update = await _transition_status(
            services,
            state,
            EventStatus.CLOSED,
            context=ctx,
            reason="investigation:close",
        )
        return _patch_state(_trace(NODE_CLOSE), status_update, {"halted": False})

    async def planner_graph_node(state: InvestigationState) -> InvestigationState:
        persisted = await _read_persisted_disposition_only_intent(services, state["event_id"])
        if state.get("disposition_only_intent") and not persisted:
            if workflow_runtime is not None:
                await workflow_runtime.assert_disposition_only_transition_allowed(
                    state["event_id"],
                    target=EventStatus.PLANNING_RESPONSE,
                    current=EventStatus(state.get("event_status", EventStatus.TRIAGING.value)),
                )
            raise InvalidStateTransitionError(
                "forged disposition_only_intent without server persistence",
                current=state.get("event_status", EventStatus.TRIAGING.value),
                target=EventStatus.PLANNING_RESPONSE.value,
                details={"event_id": state["event_id"]},
            )
        disposition_only = persisted
        event_context = _event_context_from_state(
            _patch_state(state, {"disposition_only_intent": persisted})
        )
        plan = await planner_node(event_context, planner_agent, disposition_only=disposition_only)
        update: dict[str, Any] = {
            **_trace(NODE_PLANNER),
            "execution_plan": plan.model_dump(mode="json"),
            "disposition_only_active": persisted,
            "disposition_only_intent": persisted,
        }
        if disposition_only:
            status_update = await _transition_status(
                services,
                state,
                EventStatus.PLANNING_RESPONSE,
                context=TransitionContext(
                    final_verdict=FinalVerdict.FALSE_POSITIVE,
                    disposition_only_intent=True,
                    disposition_policy=DispositionPolicy(state["disposition_policy"]),
                    recommendation="close_as_fp",
                ),
                reason="disposition_only:plan",
            )
            update.update(status_update)
        return _patch_state(update)

    async def evidence_node(state: InvestigationState) -> InvestigationState:
        triage = TriageResult.model_validate(state["triage_result"])
        status_update = await _transition_status(
            services,
            state,
            EventStatus.COLLECTING_EVIDENCE,
            context=TransitionContext(need_investigation=True),
            reason="investigation:evidence",
        )
        evidence = await evidence_agent.execute(
            EvidenceAgentInput(event_id=state["event_id"], triage_result=triage)
        )
        if not isinstance(evidence, EvidenceOutput):
            raise TypeError("evidence_agent must return EvidenceOutput")
        await _transition_status(
            services,
            _patch_state(state, status_update),
            EventStatus.ANALYZING,
            reason="investigation:analyze",
        )
        return _patch_state(
            _trace(NODE_EVIDENCE),
            status_update,
            {
                "event_status": EventStatus.ANALYZING.value,
                "evidence_output": evidence.model_dump(mode="json"),
            },
        )

    async def rag_graph_node(state: InvestigationState) -> InvestigationState:
        if rag_agent is None or not state.get("include_rag"):
            return _patch_state(_trace(NODE_RAG))
        triage = TriageResult.model_validate(state["triage_result"])
        evidence = EvidenceOutput.model_validate(state["evidence_output"])
        event_context = _event_context_from_state(state)
        output = await rag_node(
            event_context,
            cast(RAGAgent, rag_agent),
            triage_result=triage,
            evidence_output=evidence,
        )
        rag_update: dict[str, Any] = {**_trace(NODE_RAG)}
        if output is not None:
            rag_update["rag_output"] = output.model_dump(mode="json")
        return _patch_state(rag_update)

    async def risk_node(state: InvestigationState) -> InvestigationState:
        triage = TriageResult.model_validate(state["triage_result"])
        evidence = EvidenceOutput.model_validate(state["evidence_output"])
        rag_output = None
        if state.get("rag_output") is not None:
            rag_output = RAGOutput.model_validate(state["rag_output"])
        await _transition_status(
            services,
            state,
            EventStatus.SCORING,
            reason="investigation:score",
        )
        assessment = await risk_agent.execute(
            RiskAgentInput(
                event_id=state["event_id"],
                triage_result=triage,
                evidence_output=evidence,
                rag_output=rag_output,
            )
        )
        if not isinstance(assessment, RiskAssessment):
            raise TypeError("risk_agent must return RiskAssessment")
        await _transition_status(
            services,
            state,
            EventStatus.PLANNING_RESPONSE,
            reason="investigation:plan_response",
        )
        return _patch_state(
            _trace(NODE_RISK),
            {
                "event_status": EventStatus.PLANNING_RESPONSE.value,
                "risk_assessment": assessment.model_dump(mode="json"),
                "severity": assessment.severity.value,
            },
        )

    async def response_node(state: InvestigationState) -> InvestigationState:
        verdict_raw = state.get("final_verdict")
        verdict = FinalVerdict(verdict_raw) if verdict_raw else None
        await _transition_status(
            services,
            state,
            EventStatus.WAITING_APPROVAL,
            context=TransitionContext(
                disposition_only_intent=bool(state.get("disposition_only_active")),
                final_verdict=verdict,
            ),
            reason="investigation:response_stub",
        )
        return _patch_state(
            _trace(NODE_RESPONSE),
            {"event_status": EventStatus.WAITING_APPROVAL.value},
        )

    async def approval_node(state: InvestigationState) -> InvestigationState:
        if state.get("needs_approval_wait"):
            if workflow_runtime is not None:
                await workflow_runtime.set_execution_substate(
                    state["event_id"],
                    ExecutionSubstate.WAITING_APPROVAL,
                    event_status=EventStatus.WAITING_APPROVAL,
                )
            return _patch_state(
                _trace(NODE_APPROVAL),
                {
                    "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
                    "event_status": EventStatus.WAITING_APPROVAL.value,
                },
            )
        if workflow_runtime is not None:
            await workflow_runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.NONE,
                event_status=EventStatus.WAITING_APPROVAL,
            )
        await _transition_status(
            services,
            state,
            EventStatus.EXECUTING_RESPONSE,
            reason="investigation:approval_stub",
        )
        return _patch_state(
            _trace(NODE_APPROVAL),
            {
                "event_status": EventStatus.EXECUTING_RESPONSE.value,
                "execution_substate": ExecutionSubstate.NONE.value,
            },
        )

    async def approval_wait_node(state: InvestigationState) -> InvestigationState:
        if workflow_runtime is not None:
            await workflow_runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.WAITING_APPROVAL,
                event_status=EventStatus.WAITING_APPROVAL,
            )
        return _patch_state(
            _trace(NODE_APPROVAL_WAIT),
            {
                "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
                "halted": True,
            },
        )

    async def execute_node(state: InvestigationState) -> InvestigationState:
        await _transition_status(
            services,
            state,
            EventStatus.VERIFYING,
            reason="investigation:execute_stub",
        )
        return _patch_state(
            _trace(NODE_EXECUTE),
            {"event_status": EventStatus.VERIFYING.value},
        )

    async def verify_node(state: InvestigationState) -> InvestigationState:
        update: dict[str, Any] = {**_trace(NODE_VERIFY)}
        if state.get("disposition_only_active"):
            update.update(
                {
                    "verify_need_manual_resolution": False,
                    "verify_need_writeback_recovery": False,
                    "verify_need_action_replan": False,
                }
            )
            return _patch_state(update)
        await _transition_status(
            services,
            state,
            EventStatus.REPORTING,
            reason="investigation:verify_stub",
        )
        update["event_status"] = EventStatus.REPORTING.value
        return _patch_state(update)

    async def replan_node(state: InvestigationState) -> InvestigationState:
        await _transition_status(
            services,
            state,
            EventStatus.REPLANNING,
            reason="investigation:replan_stub",
        )
        return _patch_state(
            _trace(NODE_REPLAN),
            {"event_status": EventStatus.REPLANNING.value},
        )

    async def report_node(state: InvestigationState) -> InvestigationState:
        evidence = EvidenceOutput.model_validate(state["evidence_output"])
        assessment = RiskAssessment.model_validate(state["risk_assessment"])
        await _transition_status(
            services,
            state,
            EventStatus.REPORTING,
            reason="investigation:report",
        )
        report = await report_agent.execute(
            ReportAgentInput(
                event_id=state["event_id"],
                evidence_output=evidence,
                risk_assessment=assessment,
            )
        )
        return _patch_state(
            _trace(NODE_REPORT),
            {
                "event_status": EventStatus.REPORTING.value,
                "report_generated": report is not None,
            },
        )

    async def halt_node(state: InvestigationState) -> InvestigationState:
        return _patch_state(_trace(NODE_HALT), {"halted": True})

    def _register(
        name: str, fn: Callable[[InvestigationState], Coroutine[Any, Any, InvestigationState]]
    ) -> None:
        graph.add_node(name, cast(Any, _wrap_node(services, fn)))

    graph: StateGraph[InvestigationState] = StateGraph(InvestigationState)
    _register(NODE_TRIAGE, triage_node)
    _register(NODE_BEGIN_DISPOSITION_ONLY, begin_disposition_only_node)
    _register(NODE_MANUAL_HOLD, manual_hold_node)
    _register(NODE_CLOSE, close_node)
    _register(NODE_PLANNER, planner_graph_node)
    _register(NODE_EVIDENCE, evidence_node)
    _register(NODE_RISK, risk_node)
    _register(NODE_RESPONSE, response_node)
    _register(NODE_APPROVAL, approval_node)
    _register(NODE_APPROVAL_WAIT, approval_wait_node)
    _register(NODE_EXECUTE, execute_node)
    _register(NODE_VERIFY, verify_node)
    _register(NODE_REPLAN, replan_node)
    _register(NODE_REPORT, report_node)
    _register(NODE_HALT, halt_node)

    if rag_agent is not None:
        _register(NODE_RAG, rag_graph_node)

    graph.add_edge(START, NODE_TRIAGE)
    graph.add_conditional_edges(
        NODE_TRIAGE,
        route_after_triage,
        {
            ROUTE_AFTER_TRIAGE_CLOSE: NODE_CLOSE,
            ROUTE_AFTER_TRIAGE_DISPOSITION_ONLY: NODE_BEGIN_DISPOSITION_ONLY,
            ROUTE_AFTER_TRIAGE_MANUAL_HOLD: NODE_MANUAL_HOLD,
            ROUTE_AFTER_TRIAGE_INVESTIGATE: NODE_PLANNER,
        },
    )
    graph.add_edge(NODE_BEGIN_DISPOSITION_ONLY, NODE_PLANNER)
    graph.add_edge(NODE_MANUAL_HOLD, END)
    graph.add_conditional_edges(
        NODE_PLANNER,
        route_after_planner,
        {
            ROUTE_AFTER_PLANNER_RESPONSE: NODE_RESPONSE,
            ROUTE_AFTER_PLANNER_EVIDENCE: NODE_EVIDENCE,
        },
    )

    if rag_agent is not None:
        graph.add_edge(NODE_EVIDENCE, NODE_RAG)
        graph.add_edge(NODE_RAG, NODE_RISK)
    else:
        graph.add_edge(NODE_EVIDENCE, NODE_RISK)

    graph.add_conditional_edges(
        NODE_RISK,
        route_after_risk,
        {ROUTE_AFTER_RISK_RESPONSE: NODE_RESPONSE},
    )
    graph.add_edge(NODE_RESPONSE, NODE_APPROVAL)
    graph.add_conditional_edges(
        NODE_APPROVAL,
        route_after_approval,
        {
            ROUTE_AFTER_APPROVAL_EXECUTE: NODE_EXECUTE,
            ROUTE_AFTER_APPROVAL_WAIT: NODE_APPROVAL_WAIT,
        },
    )
    graph.add_edge(NODE_APPROVAL_WAIT, END)
    graph.add_edge(NODE_EXECUTE, NODE_VERIFY)
    graph.add_conditional_edges(
        NODE_VERIFY,
        route_after_verify,
        {
            ROUTE_AFTER_VERIFY_REPORT: NODE_REPORT,
            ROUTE_AFTER_VERIFY_REPLAN: NODE_REPLAN,
            ROUTE_AFTER_VERIFY_MANUAL: NODE_MANUAL_HOLD,
            ROUTE_AFTER_VERIFY_WRITEBACK: NODE_MANUAL_HOLD,
            ROUTE_AFTER_VERIFY_HALT: NODE_HALT,
        },
    )
    graph.add_edge(NODE_REPLAN, NODE_PLANNER)
    graph.add_edge(NODE_REPORT, NODE_CLOSE)
    graph.add_edge(NODE_CLOSE, END)
    graph.add_edge(NODE_HALT, END)

    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=interrupt_before,
        interrupt_after=interrupt_after,
    )


def _synthesized_fallback_triage(
    event_context: EventContext,
    *,
    reasoning: str,
) -> TriageResult:
    return TriageResult(
        event_type=EventType.OTHER,
        severity=event_context.event.severity if event_context.event else Severity.MEDIUM,
        need_investigation=True,
        reasoning=reasoning,
        degraded=True,
    )


async def planner_node(
    event_context: EventContext,
    planner: PlannerAgent,
    *,
    disposition_only: bool = False,
) -> ExecutionPlan:
    """Generate or revise an investigation plan for the given event context.

    This is the canonical entry point for the ``planner_node`` in the
    LangGraph investigation workflow (ISSUE-048 / ISSUE-054).

    Args:
        event_context: The current ``EventContext``, which must carry at least
            a valid ``event_id`` and, for normal paths, a ``triage_result``.
        planner: A configured ``PlannerAgent`` instance (LLM client + working
            memory already injected).
        disposition_only: When ``True``, produce the deterministic single-step
            disposition-only plan instead of a full investigation plan.

    Returns:
        The generated ``ExecutionPlan`` (already persisted to
        ``EventContext.execution_plan`` via working memory).
    """
    event_id = event_context.event.event_id if event_context.event else "unknown"

    if disposition_only:
        logger.info(
            "planner_node: generating disposition-only plan for event=%s",
            event_id,
        )
        return await planner.plan_disposition_only(event_context)

    triage_data = event_context.triage_result
    triage_result: TriageResult | None = None
    if triage_data is not None:
        try:
            triage_result = TriageResult.model_validate(triage_data)
        except Exception:
            logger.warning(
                "planner_node: corrupt triage_result in EventContext for event=%s, "
                "falling back to DEFAULT_PLANS (EventType.OTHER)",
                event_id,
                exc_info=True,
            )
            triage_result = _synthesized_fallback_triage(
                event_context,
                reasoning="triage data corrupt — using conservative rule-based plan",
            )
    else:
        logger.warning(
            "planner_node: missing triage_result for event=%s, "
            "using conservative DEFAULT_PLANS path",
            event_id,
        )
        triage_result = _synthesized_fallback_triage(
            event_context,
            reasoning="triage unavailable — using conservative rule-based plan",
        )

    if event_context.replan_count > 0:
        existing_plan_data = event_context.execution_plan
        if existing_plan_data is not None:
            try:
                previous_plan = ExecutionPlan.model_validate(existing_plan_data)
                logger.info(
                    "planner_node: revising plan for event=%s replan_count=%d",
                    event_id,
                    event_context.replan_count,
                )
                return await planner.revise(
                    event_context,
                    failure_reason=(f"replan triggered (count={event_context.replan_count})"),
                    previous_plan=previous_plan,
                )
            except Exception:
                logger.warning(
                    "planner_node: failed to parse existing plan for revision, "
                    "falling back to fresh plan for event=%s",
                    event_id,
                    exc_info=True,
                )

    input = PlannerAgentInput(
        event_id=event_id,
        triage_result=triage_result,
    )
    return await planner.execute(input)


async def rag_node(
    event_context: EventContext,
    rag_agent: RAGAgent,
    *,
    triage_result: TriageResult,
    evidence_output: EvidenceOutput,
) -> RAGOutput | None:
    """LangGraph node: RAG retrieval after evidence, before risk (ISSUE-047).

    Failures degrade to ``None`` so RiskAgent can continue without enhancement.
    """
    event_id = event_context.event.event_id if event_context.event else "unknown"
    output, _degraded = await run_rag_stage(
        rag_agent,
        event_id=event_id,
        triage_result=triage_result,
        evidence_output=evidence_output,
    )
    return output


__all__ = [
    "NODE_APPROVAL",
    "NODE_CLOSE",
    "NODE_EVIDENCE",
    "NODE_EXECUTE",
    "NODE_HALT",
    "NODE_MANUAL_HOLD",
    "NODE_PLANNER",
    "NODE_REPORT",
    "NODE_RESPONSE",
    "NODE_RISK",
    "NODE_TRIAGE",
    "NODE_VERIFY",
    "P0_NODE_SEQUENCE",
    "build_investigation_graph",
    "invoke_investigation_graph",
    "planner_node",
    "rag_node",
]
