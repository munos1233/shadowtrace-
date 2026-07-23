"""Workflow graph nodes (ISSUE-048/ISSUE-049).

Provides ``planner_node`` / ``rag_node`` helpers and ``build_investigation_graph``
for the LangGraph investigation StateGraph (ISSUE-048).
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, cast

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.agents.planner_agent import PlannerAgent
from app.agents.rag_agent import RAGAgent
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
from app.services.degraded_flag_service import format_degraded_flag
from app.services.state_machine_service import StateMachineService

logger = logging.getLogger(__name__)

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


def _trace(node_name: str) -> dict[str, list[str]]:
    return {"node_trace": [node_name]}


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
) -> CompiledStateGraph:
    """Build and compile the investigation LangGraph (dependency injection only)."""
    triage_agent = cast(_AgentLike, agents["triage_agent"])
    planner_agent = cast(PlannerAgent, agents["planner_agent"])
    evidence_agent = cast(_AgentLike, agents["evidence_agent"])
    risk_agent = cast(_AgentLike, agents["risk_agent"])
    report_agent = cast(_AgentLike, agents["report_agent"])
    rag_agent = agents.get("rag_agent")
    workflow_runtime = cast(_WorkflowRuntimeLike | None, services.get("workflow_runtime"))
    degraded_flags = cast(_DegradedFlagLike | None, services.get("degraded_flags"))

    async def triage_node(state: InvestigationState) -> InvestigationState:
        triage_input = TriageAgentInput(
            event_id=state["event_id"],
            raw_event_summary="",
        )
        result = await triage_agent.execute(triage_input)
        if not isinstance(result, TriageResult):
            raise TypeError("triage_agent must return TriageResult")
        update: InvestigationState = {
            **_trace(NODE_TRIAGE),
            "triage_result": result.model_dump(mode="json"),
            "need_investigation": result.need_investigation,
            "severity": result.severity.value,
        }
        return update

    async def begin_disposition_only_node(state: InvestigationState) -> InvestigationState:
        if workflow_runtime is None:
            raise RuntimeError("workflow_runtime is required for disposition-only path")
        await workflow_runtime.begin_disposition_only(state["event_id"])
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
        return {
            **_trace(NODE_BEGIN_DISPOSITION_ONLY),
            **status_update,
            "disposition_only_intent": True,
            "final_verdict": FinalVerdict.FALSE_POSITIVE.value,
        }

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
        return {
            **_trace(NODE_MANUAL_HOLD),
            "degraded_flags": flags,
            "halted": True,
            "execution_substate": ExecutionSubstate.NONE.value,
        }

    async def close_node(state: InvestigationState) -> InvestigationState:
        ctx = TransitionContext(
            disposition_policy=DispositionPolicy(state.get("disposition_policy", "not_required")),
            severity=Severity(state.get("severity", Severity.MEDIUM.value)),
            recommendation=(state.get("false_positive_match") or {}).get("recommendation"),
            final_verdict=FinalVerdict(state["final_verdict"])
            if state.get("final_verdict")
            else None,
            report_exists=bool(state.get("report_generated")),
        )
        status_update = await _transition_status(
            services,
            state,
            EventStatus.CLOSED,
            context=ctx,
            reason="investigation:close",
        )
        return {**_trace(NODE_CLOSE), **status_update, "halted": False}

    async def planner_graph_node(state: InvestigationState) -> InvestigationState:
        disposition_only = bool(state.get("disposition_only_intent"))
        event_context = _event_context_from_state(state)
        plan = await planner_node(event_context, planner_agent, disposition_only=disposition_only)
        update: InvestigationState = {
            **_trace(NODE_PLANNER),
            "execution_plan": plan.model_dump(mode="json"),
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
        return update

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
            {**state, **status_update},
            EventStatus.ANALYZING,
            reason="investigation:analyze",
        )
        return {
            **_trace(NODE_EVIDENCE),
            **status_update,
            "event_status": EventStatus.ANALYZING.value,
            "evidence_output": evidence.model_dump(mode="json"),
        }

    async def rag_graph_node(state: InvestigationState) -> InvestigationState:
        if rag_agent is None or not state.get("include_rag"):
            return _trace(NODE_RAG)
        triage = TriageResult.model_validate(state["triage_result"])
        evidence = EvidenceOutput.model_validate(state["evidence_output"])
        event_context = _event_context_from_state(state)
        output = await rag_node(
            event_context,
            cast(RAGAgent, rag_agent),
            triage_result=triage,
            evidence_output=evidence,
        )
        update: InvestigationState = _trace(NODE_RAG)
        if output is not None:
            update["rag_output"] = output.model_dump(mode="json")
        return update

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
        return {
            **_trace(NODE_RISK),
            "event_status": EventStatus.PLANNING_RESPONSE.value,
            "risk_assessment": assessment.model_dump(mode="json"),
            "severity": assessment.severity.value,
        }

    async def response_node(state: InvestigationState) -> InvestigationState:
        await _transition_status(
            services,
            state,
            EventStatus.WAITING_APPROVAL,
            context=TransitionContext(
                disposition_only_intent=bool(state.get("disposition_only_intent")),
                final_verdict=FinalVerdict(state["final_verdict"])
                if state.get("final_verdict")
                else None,
            ),
            reason="investigation:response_stub",
        )
        return {
            **_trace(NODE_RESPONSE),
            "event_status": EventStatus.WAITING_APPROVAL.value,
        }

    async def approval_node(state: InvestigationState) -> InvestigationState:
        if state.get("needs_approval_wait"):
            if workflow_runtime is not None:
                await workflow_runtime.set_execution_substate(
                    state["event_id"],
                    ExecutionSubstate.WAITING_APPROVAL,
                    event_status=EventStatus.WAITING_APPROVAL,
                )
            return {
                **_trace(NODE_APPROVAL),
                "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
                "event_status": EventStatus.WAITING_APPROVAL.value,
            }
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
        return {
            **_trace(NODE_APPROVAL),
            "event_status": EventStatus.EXECUTING_RESPONSE.value,
            "execution_substate": ExecutionSubstate.NONE.value,
        }

    async def approval_wait_node(state: InvestigationState) -> InvestigationState:
        if workflow_runtime is not None:
            await workflow_runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.WAITING_APPROVAL,
                event_status=EventStatus.WAITING_APPROVAL,
            )
        return {
            **_trace(NODE_APPROVAL_WAIT),
            "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
            "halted": True,
        }

    async def execute_node(state: InvestigationState) -> InvestigationState:
        await _transition_status(
            services,
            state,
            EventStatus.VERIFYING,
            reason="investigation:execute_stub",
        )
        return {
            **_trace(NODE_EXECUTE),
            "event_status": EventStatus.VERIFYING.value,
        }

    async def verify_node(state: InvestigationState) -> InvestigationState:
        update: InvestigationState = _trace(NODE_VERIFY)
        if state.get("disposition_only_intent"):
            update["verify_need_manual_resolution"] = False
            update["verify_need_writeback_recovery"] = False
            update["verify_need_action_replan"] = False
        else:
            await _transition_status(
                services,
                state,
                EventStatus.REPORTING,
                reason="investigation:verify_stub",
            )
            update["event_status"] = EventStatus.REPORTING.value
        return update

    async def replan_node(state: InvestigationState) -> InvestigationState:
        await _transition_status(
            services,
            state,
            EventStatus.REPLANNING,
            reason="investigation:replan_stub",
        )
        return {
            **_trace(NODE_REPLAN),
            "event_status": EventStatus.REPLANNING.value,
        }

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
        return {
            **_trace(NODE_REPORT),
            "event_status": EventStatus.REPORTING.value,
            "report_generated": report is not None,
        }

    async def halt_node(state: InvestigationState) -> InvestigationState:
        return {
            **_trace(NODE_HALT),
            "halted": True,
        }

    graph: StateGraph = StateGraph(InvestigationState)
    graph.add_node(NODE_TRIAGE, triage_node)
    graph.add_node(NODE_BEGIN_DISPOSITION_ONLY, begin_disposition_only_node)
    graph.add_node(NODE_MANUAL_HOLD, manual_hold_node)
    graph.add_node(NODE_CLOSE, close_node)
    graph.add_node(NODE_PLANNER, planner_graph_node)
    graph.add_node(NODE_EVIDENCE, evidence_node)
    graph.add_node(NODE_RISK, risk_node)
    graph.add_node(NODE_RESPONSE, response_node)
    graph.add_node(NODE_APPROVAL, approval_node)
    graph.add_node(NODE_APPROVAL_WAIT, approval_wait_node)
    graph.add_node(NODE_EXECUTE, execute_node)
    graph.add_node(NODE_VERIFY, verify_node)
    graph.add_node(NODE_REPLAN, replan_node)
    graph.add_node(NODE_REPORT, report_node)
    graph.add_node(NODE_HALT, halt_node)

    if rag_agent is not None:
        graph.add_node(NODE_RAG, rag_graph_node)

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
    "planner_node",
    "rag_node",
]
