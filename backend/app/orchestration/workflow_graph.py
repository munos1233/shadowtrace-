"""LangGraph investigation workflow (ISSUE-048/ISSUE-049/ISSUE-062)."""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine, Mapping
from typing import Any, Protocol, cast

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.agents.planner_agent import PlannerAgent
from app.agents.rag_agent import RAGAgent
from app.core.config import get_settings
from app.core.errors import InvalidStateTransitionError, ValidationError
from app.models.agent_io import (
    CollectionStatus,
    EffectStatus,
    EvidenceAgentInput,
    EvidenceOutput,
    ExecutionPlan,
    GraphAgentInput,
    GraphOutput,
    PlannerAgentInput,
    RAGOutput,
    ResponseAgentInput,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    RiskAgentInput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
    VerifyAgentInput,
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
from app.orchestration.event_status_transition_retry import transition_with_bounded_retry
from app.orchestration.graph_state import InvestigationState
from app.orchestration.replan_handler import (
    ReplanHandler,
    replan_graph_node,
)
from app.orchestration.triage_input_builder import build_triage_agent_input
from app.orchestration.writeback_recovery_handler import (
    WritebackRecoveryHandler,
    writeback_recovery_graph_node,
)
from app.services.agent_task_coordinator import (
    run_response_plan_with_ledger,
    run_risk_score_with_ledger,
)
from app.services.analysis_only_pipeline import run_rag_stage
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService, apply_flag_to_list
from app.services.evidence_query_plan_service import extract_evidence_plan_inputs
from app.services.false_positive_matcher import build_fp_close_reason
from app.services.fp_adjudication_runner import run_post_evidence_fp_adjudication
from app.services.report_input_builder import build_report_agent_input
from app.services.state_machine_service import StateMachineService
from app.services.tenant_resolution import resolve_tenant_id
from app.services.working_memory import WorkingMemory

logger = logging.getLogger(__name__)


async def _persist_degraded_flag(
    state: InvestigationState,
    flag_name: str,
    *,
    event_id: str,
    degraded_flags: DegradedFlagService,
) -> list[str]:
    """Persist a verify-node degraded flag to DB + EventContext and graph state."""
    try:
        return await degraded_flags.set_flag(
            event_id,
            flag_name,
            True,
            writer=_GRAPH_OPERATOR,
        )
    except Exception:
        logger.exception(
            "degraded_flag persistence failed: flag=%s event=%s — falling back to graph state",
            flag_name,
            event_id,
        )
        return apply_flag_to_list(
            list(state.get("degraded_flags") or []),
            flag_name,
            True,
        )


CompiledInvestigationGraph = CompiledStateGraph[
    InvestigationState, None, InvestigationState, InvestigationState
]

_GRAPH_OPERATOR = "InvestigationGraph"

NODE_TRIAGE = "triage_node"
NODE_BEGIN_DISPOSITION_ONLY = "begin_disposition_only_node"
NODE_MANUAL_HOLD = "manual_hold_node"
NODE_CLOSE = "close_node"
NODE_PLANNER = "planner_node"
NODE_EVIDENCE = "evidence_node"
NODE_FP_ADJUDICATION = "fp_adjudication_node"
NODE_GRAPH = "graph_node"
NODE_RAG = "rag_node"
NODE_RISK = "risk_node"
NODE_RESPONSE = "response_node"
NODE_APPROVAL = "approval_node"
NODE_APPROVAL_WAIT = "approval_wait_node"
NODE_EXECUTE = "execute_node"
NODE_VERIFY = "verify_node"
NODE_REPLAN = "replan_node"
NODE_WRITEBACK_RECOVERY = "writeback_recovery_node"
NODE_REPORT = "report_node"
NODE_HALT = "halt_node"

P0_NODE_SEQUENCE = (
    NODE_TRIAGE,
    NODE_PLANNER,
    NODE_EVIDENCE,
    NODE_FP_ADJUDICATION,
    NODE_GRAPH,
    NODE_RISK,
    NODE_RESPONSE,
    NODE_APPROVAL,
    NODE_EXECUTE,
    NODE_VERIFY,
    NODE_REPORT,
    NODE_CLOSE,
)

ROUTE_CLOSE = "close"
ROUTE_MANUAL_HOLD = "manual_hold"
ROUTE_INVESTIGATE = "investigate"
ROUTE_RESPONSE = "response"
ROUTE_EVIDENCE = "evidence"
ROUTE_CONTINUE = "continue"
ROUTE_EXECUTE = "execute"
ROUTE_TO_APPROVAL = "approval"
ROUTE_TO_VERIFY = "verify"
ROUTE_WAIT = "wait"
ROUTE_REPORT = "report"
ROUTE_REPLAN = "replan"
ROUTE_MANUAL = "manual"
ROUTE_WRITEBACK = "writeback"
ROUTE_HALT = "halt"


class _AgentLike(Protocol):
    async def execute(self, input: Any) -> Any: ...


class _StateMachinePort(Protocol):
    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: TransitionContext | None = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> Any: ...

    async def get_current_status(self, event_id: str) -> EventStatus: ...


class _DispositionSyncPort(Protocol):
    async def retry_writeback(
        self,
        writeback_id: str,
        operator: str,
    ) -> Any: ...

    async def resolve_writeback(
        self,
        writeback_id: str,
        resolution: str,
        principal: str,
        comment: str,
    ) -> Any: ...

    async def lookup_writeback_status(
        self,
        writeback_id: str,
    ) -> Any: ...

    async def activate_deferred_disposition(
        self,
        event_id: str,
        *,
        operator: str,
    ) -> Any: ...


class _WorkflowRuntimeLike(Protocol):
    async def get_event_status_update_readiness(
        self,
        event_id: str,
    ) -> WritebackReadiness: ...

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
        current: EventStatus,
        target: EventStatus,
    ) -> None: ...


class _EventServiceLike(Protocol):
    async def set_final_verdict(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
    ) -> Any: ...


def route_after_triage(state: InvestigationState) -> str:
    """Mirror the locked TRIAGING gates without broadening them.

    ISSUE-204: when ``generate_report`` is False, do not fast-path into
    ``close_node`` (CLOSED still requires a report). Route to ``report_node``
    so the skip path can persist ``report_generated=false`` and halt at
    REPORTING.
    """
    policy = DispositionPolicy(
        state.get("disposition_policy", DispositionPolicy.NOT_REQUIRED.value)
    )
    if policy is DispositionPolicy.NOT_REQUIRED and state.get("need_investigation") is False:
        if not state.get("generate_report", True):
            return ROUTE_REPORT
        return ROUTE_CLOSE
    return ROUTE_INVESTIGATE


def route_after_fp_adjudication(state: InvestigationState) -> str:
    """Post-evidence adjudication never short-circuits investigation (ISSUE-114)."""
    _ = state
    return ROUTE_CONTINUE


def route_after_planner(state: InvestigationState) -> str:
    """Use only the trusted intent hydrated by planner_graph_node."""
    return ROUTE_RESPONSE if state.get("disposition_only_intent") else ROUTE_EVIDENCE


def route_after_risk(state: InvestigationState) -> str:
    """Route to response execution or analysis-completion report."""
    if state.get("disposition_only_intent"):
        return ROUTE_RESPONSE
    if state.get("defer_response_execution"):
        return ROUTE_REPORT
    return ROUTE_RESPONSE


def route_after_report(state: InvestigationState) -> str:
    """End analysis at REPORTING for required policy; close when not required.

    ISSUE-204: REPORTING means the report phase is reachable, not that report
    bytes exist. When ``generate_report`` is False, halt at REPORTING regardless
    of disposition policy.
    """
    if not state.get("generate_report", True):
        return ROUTE_HALT
    policy = DispositionPolicy(
        state.get("disposition_policy", DispositionPolicy.NOT_REQUIRED.value)
    )
    if policy is DispositionPolicy.REQUIRED:
        return ROUTE_HALT
    return ROUTE_CLOSE


def route_after_approval(state: InvestigationState) -> str:
    # ISSUE-218: a halted approval (e.g. approval_engine missing → FAILED)
    # must stop the graph instead of continuing to execute.
    if state.get("halted"):
        return ROUTE_HALT
    if state.get("execution_substate") == ExecutionSubstate.WAITING_APPROVAL.value:
        return ROUTE_WAIT
    event_status = EventStatus(state.get("event_status", EventStatus.WAITING_APPROVAL.value))
    if event_status is EventStatus.REPORTING:
        return ROUTE_REPORT
    return ROUTE_EXECUTE


def route_after_verify(state: InvestigationState) -> str:
    if state.get("halted"):
        return ROUTE_HALT
    if state.get("verify_need_manual_resolution"):
        return ROUTE_MANUAL
    if state.get("verify_need_writeback_recovery"):
        return ROUTE_WRITEBACK
    if state.get("verify_need_action_replan"):
        return ROUTE_REPLAN
    # ISSUE-062 truth table: when all three flags are false → overall success → REPORT.
    # Disposition-only / required policy events use the same REPORTING path;
    # any deferred writeback that still needs waiting is handled via
    # verify_need_writeback_recovery (checked above), not via HALT.
    return ROUTE_REPORT


def route_after_replan(state: InvestigationState) -> str:
    """After replan_node: if escalated, go to report; otherwise loop to planner."""
    if state.get("escalated"):
        return ROUTE_REPORT
    return ROUTE_INVESTIGATE  # goes back to planner_node


def _route_after_response(state: InvestigationState) -> str:
    return ROUTE_HALT if state.get("halted") else ROUTE_TO_APPROVAL


def _route_after_execute(state: InvestigationState) -> str:
    # ISSUE-218: execute_node fail-closed sets halted — skip verify_node so
    # the trace does not imply verification ran after a miswire failure.
    return ROUTE_HALT if state.get("halted") else ROUTE_TO_VERIFY


def _trace(node_name: str) -> InvestigationState:
    return cast(InvestigationState, {"node_trace": [node_name]})


def _patch_state(*parts: Mapping[str, Any]) -> InvestigationState:
    merged: dict[str, Any] = {}
    for part in parts:
        merged.update(part)
    return cast(InvestigationState, merged)


async def _mark_graph_failed(
    services: dict[str, Any],
    state: InvestigationState,
    error: Exception,
) -> None:
    state_machine = cast(StateMachineService, services["state_machine"])
    reason = f"investigation_graph:error:{type(error).__name__}:{error}"[:500]
    try:
        await state_machine.transition(
            state["event_id"],
            EventStatus.FAILED,
            operator=_GRAPH_OPERATOR,
            reason=reason,
        )
    except Exception:
        logger.exception("failed to mark event=%s FAILED", state.get("event_id"))


def _wrap_node(
    services: dict[str, Any],
    fn: Callable[[InvestigationState], Coroutine[Any, Any, InvestigationState]],
) -> Callable[[InvestigationState], Coroutine[Any, Any, InvestigationState]]:
    async def wrapped(state: InvestigationState) -> InvestigationState:
        try:
            return await fn(state)
        except Exception as exc:
            await _mark_graph_failed(services, state, exc)
            raise

    return wrapped


async def invoke_investigation_graph(
    graph: CompiledInvestigationGraph,
    state: InvestigationState | None,
    config: RunnableConfig,
) -> InvestigationState:
    """Invoke or resume a graph with its configured checkpoint saver."""
    result = await graph.ainvoke(state, config)
    return cast(InvestigationState, result)


def alert_text_from_snapshot(snapshot: object) -> str:
    """Build alert text from a frozen ``source_snapshot`` dict.

    Shared by the production ``workflow_graph`` and the SuperAgent internal
    graph so both derive alert text from the same immutable source fields
    (ISSUE-143). Returns an empty string when no usable snapshot is present.
    """
    if not isinstance(snapshot, dict):
        return ""
    parts = [
        str(snapshot[key]).strip()
        for key in ("title", "description", "summary", "raw_alert")
        if isinstance(snapshot.get(key), str) and str(snapshot[key]).strip()
    ]
    return ". ".join(parts)


def _alert_text_from_state(state: InvestigationState) -> str:
    return alert_text_from_snapshot(state.get("source_snapshot"))


def _event_context_from_state(state: InvestigationState) -> EventContext:
    policy = DispositionPolicy(
        state.get("disposition_policy", DispositionPolicy.NOT_REQUIRED.value)
    )
    summary = EventSummary(
        event_id=state["event_id"],
        event_type=EventType.OTHER,
        title="investigation",
        status=EventStatus(state.get("event_status", EventStatus.TRIAGING.value)),
        severity=Severity(state.get("severity", Severity.MEDIUM.value)),
        risk_score=0,
        final_verdict=FinalVerdict(state.get("final_verdict") or FinalVerdict.NONE.value),
        writeback_required=policy is DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness(
            state.get(
                "event_status_update_readiness",
                WritebackReadiness.NOT_REQUIRED.value,
            )
        ),
        disposition_policy=policy,
        escalated=bool(state.get("escalated", False)),
    )
    return EventContext(
        event=summary,
        triage_result=state.get("triage_result"),
        false_positive_match=state.get("false_positive_match"),
        fp_adjudication=state.get("fp_adjudication"),
        source_snapshot=state.get("source_snapshot"),
        disposition_only_intent=bool(state.get("disposition_only_intent")),
        execution_substate=ExecutionSubstate(
            state.get("execution_substate", ExecutionSubstate.NONE.value)
        ),
        execution_plan=state.get("execution_plan"),
        replan_count=int(state.get("replan_count", 0)),
    )


async def _transition_status(
    services: dict[str, Any],
    state: InvestigationState,
    target: EventStatus,
    *,
    context: TransitionContext | None = None,
    reason: str,
) -> InvestigationState:
    settings = get_settings()
    state_machine = cast(StateMachineService, services["state_machine"])

    async def _call_transition() -> None:
        await state_machine.transition(
            state["event_id"],
            target,
            context=context,
            operator=_GRAPH_OPERATOR,
            reason=reason,
        )

    await transition_with_bounded_retry(
        _call_transition,
        event_id=state["event_id"],
        target=target,
        max_retries=settings.super_agent_transition_max_retries,
        backoff_seconds=settings.super_agent_transition_retry_backoff_seconds,
        log_prefix="InvestigationGraph",
    )
    return cast(InvestigationState, {"event_status": target.value})


async def build_initial_investigation_state(
    event_id: str,
    *,
    context_store: EventContextStore,
    defer_response_execution: bool = True,
    generate_report: bool = True,
) -> InvestigationState:
    """Build LangGraph initial state from persisted EventContext + event row."""
    context = await context_store.get_full_context(event_id)
    event = context.event
    policy = event.disposition_policy if event is not None else DispositionPolicy.NOT_REQUIRED
    report_was_generated = context.report is not None or bool(context.report_generated)
    state: InvestigationState = {
        "event_id": event_id,
        "node_trace": [],
        "degraded_flags": list(context.degraded_flags or []),
        "halted": False,
        "disposition_only_intent": bool(context.disposition_only_intent),
        "execution_substate": context.execution_substate.value,
        "replan_count": int(context.replan_count or 0),
        "escalated": bool(event.escalated if event is not None else False),
        "disposition_policy": policy.value,
        "event_status": (event.status.value if event is not None else EventStatus.NEW.value),
        "severity": (event.severity.value if event is not None else Severity.MEDIUM.value),
        "final_verdict": (
            event.final_verdict.value
            if event is not None and event.final_verdict is not None
            else None
        ),
        "event_status_update_readiness": (
            event.writeback_readiness.value
            if event is not None
            else WritebackReadiness.NOT_REQUIRED.value
        ),
        "report_generated": report_was_generated,
        "generate_report": generate_report,
        "needs_approval_wait": False,
        # ISSUE-566: initial HTTP investigate completes analysis at report;
        # response/approval/execute/verify resume via approval_engine hooks.
        # ISSUE-077 may set defer_response_execution=False to reach L4 approval.
        "defer_response_execution": defer_response_execution,
    }
    if context.triage_result is not None:
        state["triage_result"] = context.triage_result
    if context.false_positive_match is not None:
        state["false_positive_match"] = context.false_positive_match
    if context.fp_adjudication is not None:
        state["fp_adjudication"] = context.fp_adjudication
    if context.source_snapshot is not None:
        state["source_snapshot"] = context.source_snapshot
    if context.execution_plan is not None:
        state["execution_plan"] = context.execution_plan
    if context.evidence_output is not None:
        state["evidence_output"] = context.evidence_output
    if context.rag_output is not None:
        state["rag_output"] = context.rag_output
    if context.risk_assessment is not None:
        state["risk_assessment"] = context.risk_assessment
    if context.response_plan is not None:
        state["response_plan"] = context.response_plan
    return state


async def _hydrate_context(
    services: dict[str, Any],
    event_id: str,
    target: dict[str, Any],
) -> None:
    store = cast(EventContextStore, services["context_store"])
    context = await store.get_full_context(event_id)
    if context.false_positive_match is not None:
        target["false_positive_match"] = context.false_positive_match
    if context.fp_adjudication is not None:
        target["fp_adjudication"] = context.fp_adjudication
    if context.source_snapshot is not None:
        target["source_snapshot"] = context.source_snapshot
    if context.event is not None:
        target["disposition_policy"] = context.event.disposition_policy.value
        target["severity"] = context.event.severity.value
        target["event_status"] = context.event.status.value
        target["final_verdict"] = context.event.final_verdict.value


async def _persist_verify_degraded_result(
    services: dict[str, Any],
    event_id: str,
    *,
    detail: str,
) -> None:
    """Persist structured verification failure before routing to manual (ISSUE-196)."""
    store = services.get("context_store")
    if store is None:
        return
    result = VerificationResult(
        overall_status=VerificationOverallStatus.FAILED,
        verification_phase=VerificationPhase.EFFECT,
        need_manual_resolution=True,
        results=[
            VerificationActionResult(
                action_id="__verify_node_degraded__",
                effect_status=EffectStatus.UNVERIFIABLE,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                detail=detail,
                verification_phase=VerificationPhase.EFFECT,
            )
        ],
        wm_persisted=True,
    )
    try:
        await store.set(event_id, "verification_result", result.model_dump(mode="json"))
    except Exception:
        logger.warning(
            "verify_node: failed to persist degraded verification_result for event=%s (%s)",
            event_id,
            detail,
        )


def _resolve_verify_writeback_status(
    verification_result: VerificationResult,
) -> str | None:
    """Pick the writeback status for the first failed writeback in verify output.

    ``WritebackRecoveryHandler`` reads ``verify_writeback_status`` from graph
    state; when VerifyAgent reports ``failed_writebacks`` we mirror the matching
    ``VerificationActionResult.writeback_status`` so recovery routes correctly
    instead of falling back to LOOKUP.
    """
    failed = verification_result.failed_writebacks
    if not failed:
        return None
    target = failed[0]
    for item in verification_result.results:
        if target in item.writeback_ids and item.writeback_status is not None:
            return item.writeback_status.value
    return None


def _resolve_verify_writeback_statuses(
    verification_result: VerificationResult,
) -> dict[str, str] | None:
    """Build a per-writeback status map for all failed writebacks (ISSUE-170).

    Replaces the per-cycle scalar for routing purposes: heterogeneous failures
    (e.g. wbk-001 UNKNOWN + wbk-002 CONFLICT) must be recovered by their own
    status instead of inheriting the first writeback's scalar value.

    Only the verify graph node writes this map; recovery nodes read it and
    must not mutate it across LOOKUP/RETRY cycles.
    """
    failed = verification_result.failed_writebacks
    if not failed:
        return None
    failed_set = set(failed)
    statuses: dict[str, str] = {}
    for item in verification_result.results:
        if item.writeback_status is None:
            continue
        for wb_id in item.writeback_ids:
            if wb_id not in failed_set:
                continue
            new_status = item.writeback_status.value
            prior = statuses.get(wb_id)
            if prior is not None and prior != new_status:
                logger.warning(
                    "verify_writeback_status_map: conflicting status for %s "
                    "(%s vs %s) — using latest result entry",
                    wb_id,
                    prior,
                    new_status,
                )
            statuses[wb_id] = new_status
    return statuses or None


def _plan_revision_from_state(state: InvestigationState) -> int:
    execution_plan = state.get("execution_plan") or {}
    revision = execution_plan.get("revision")
    if revision is not None and int(revision) > 0:
        return int(revision)
    if state.get("plan_revision") is not None:
        return int(state["plan_revision"])
    return 1


def build_investigation_graph(
    agents: dict[str, Any],
    services: dict[str, Any],
    *,
    checkpointer: Any | None = None,
    interrupt_before: list[str] | None = None,
    interrupt_after: list[str] | None = None,
) -> CompiledInvestigationGraph:
    """Build the investigation graph exclusively from injected dependencies."""
    required_services = (
        "state_machine",
        "event_service",
        "workflow_runtime",
        "degraded_flags",
        "context_store",
    )
    missing_services = [name for name in required_services if services.get(name) is None]
    if missing_services:
        raise ValueError(f"missing required workflow services: {', '.join(missing_services)}")

    triage_agent = cast(_AgentLike, agents["triage_agent"])
    planner_agent = cast(PlannerAgent, agents["planner_agent"])
    evidence_agent = cast(_AgentLike, agents["evidence_agent"])
    risk_agent = cast(_AgentLike, agents["risk_agent"])
    report_agent = cast(_AgentLike, agents["report_agent"])
    response_agent = cast(_AgentLike | None, agents.get("response_agent"))
    rag_agent = cast(RAGAgent | None, agents.get("rag_agent"))
    graph_agent = cast(_AgentLike | None, agents.get("graph_agent"))
    runtime = cast(_WorkflowRuntimeLike, services["workflow_runtime"])
    event_service = cast(_EventServiceLike, services["event_service"])
    degraded_flags = cast(DegradedFlagService, services["degraded_flags"])

    # Hoist handler creation to closure — ReplanHandler and
    # WritebackRecoveryHandler are stateless (no accumulated state between
    # calls), so sharing a single instance per graph invocation avoids
    # unnecessary allocations on every node execution.
    _state_machine_port = cast(_StateMachinePort, services["state_machine"])
    _replan_handler = ReplanHandler(
        state_machine=_state_machine_port,
        runtime=runtime,
    )
    _wb_handler = WritebackRecoveryHandler(
        state_machine=_state_machine_port,
        runtime=runtime,
        disposition_sync=services.get("disposition_sync"),
        lookup_poll_interval_s=get_settings().writeback_lookup_poll_interval_s,
    )
    _convergence_guard = services.get("convergence_guard")

    async def triage_graph_node(state: InvestigationState) -> InvestigationState:
        current = EventStatus(state.get("event_status", EventStatus.NEW.value))
        status_patch: InvestigationState = cast(InvestigationState, {})
        if current is EventStatus.NEW:
            status_patch = await _transition_status(
                services,
                state,
                EventStatus.TRIAGING,
                reason="investigation:triage_start",
            )
        event_context: EventContext | None = None
        context_store = services.get("context_store")
        if context_store is not None:
            try:
                event_context = await context_store.get_full_context(state["event_id"])
            except Exception:
                logger.debug(
                    "triage input: context lookup failed for event=%s",
                    state["event_id"],
                    exc_info=True,
                )
        triage_input = await build_triage_agent_input(
            state["event_id"],
            event_context=event_context,
            event_service=services.get("event_service"),
        )
        result = await triage_agent.execute(triage_input)
        if not isinstance(result, TriageResult):
            raise TypeError("triage_agent must return TriageResult")
        update: dict[str, Any] = {
            "triage_result": result.model_dump(mode="json"),
            "need_investigation": result.need_investigation,
            "severity": result.severity.value,
        }
        await _hydrate_context(services, state["event_id"], update)
        update["event_status_update_readiness"] = (
            await runtime.get_event_status_update_readiness(state["event_id"])
        ).value
        return _patch_state(_trace(NODE_TRIAGE), {**status_patch, **update})

    async def begin_disposition_only_node(
        state: InvestigationState,
    ) -> InvestigationState:
        await runtime.begin_disposition_only(state["event_id"])
        current = EventStatus(state.get("event_status", EventStatus.TRIAGING.value))
        await runtime.assert_disposition_only_transition_allowed(
            state["event_id"],
            current=current,
            target=EventStatus.PLANNING_RESPONSE,
        )
        status = await _transition_status(
            services,
            state,
            EventStatus.PLANNING_RESPONSE,
            context=TransitionContext(
                final_verdict=FinalVerdict.FALSE_POSITIVE,
                disposition_only_intent=True,
                disposition_policy=DispositionPolicy.REQUIRED,
                recommendation="close_as_fp",
            ),
            reason="disposition_only:begin",
        )
        return _patch_state(
            _trace(NODE_BEGIN_DISPOSITION_ONLY),
            status,
            {
                "disposition_only_intent": True,
                "final_verdict": FinalVerdict.FALSE_POSITIVE.value,
            },
        )

    async def manual_hold_node(state: InvestigationState) -> InvestigationState:
        readiness = state.get(
            "event_status_update_readiness",
            WritebackReadiness.CAPABILITY_UNKNOWN.value,
        )
        flags = list(state.get("degraded_flags") or [])
        entry = f"disposition_writeback_blocked={readiness}"
        if entry not in flags:
            flags.append(entry)
        flags = await degraded_flags.set_flag(
            state["event_id"],
            "disposition_writeback_blocked",
            readiness,
            writer="DegradedFlagService",
        )
        return _patch_state(
            _trace(NODE_MANUAL_HOLD),
            {
                "degraded_flags": flags,
                "execution_substate": ExecutionSubstate.NONE.value,
                "halted": True,
            },
        )

    async def close_node(state: InvestigationState) -> InvestigationState:
        triage = TriageResult.model_validate(state["triage_result"])
        final_verdict = state.get("final_verdict")
        short_circuit = state.get("risk_assessment") is None
        if short_circuit and not final_verdict:
            await event_service.set_final_verdict(
                state["event_id"],
                FinalVerdict.NONE,
                operator=_GRAPH_OPERATOR,
            )
            final_verdict = FinalVerdict.NONE.value

        report_generated = bool(state.get("report_generated"))
        generate_report = bool(state.get("generate_report", True))
        if not report_generated and generate_report:
            evidence = EvidenceOutput(
                evidence_list=[],
                conflicts=[],
                gaps=[],
                success_sources=[],
                failed_sources=[],
                overall_confidence=0.0,
                collection_status=CollectionStatus.COMPLETED,
            )
            assessment = RiskAssessment(
                risk_score=0,
                severity=triage.severity,
                confidence=0.9,
                risk_factors=[],
                possible_false_positive=True,
                scoring_mode=ScoringMode.RULE_ONLY,
            )
            # ISSUE-205: escalated events can reach close_node after the
            # response/verify phases ran — backfill any existing plan and
            # verification result through the shared builder instead of
            # rendering silent placeholders.
            report_input = await build_report_agent_input(
                state["event_id"],
                evidence_output=evidence,
                risk_assessment=assessment,
                escalated=bool(state.get("escalated", False)),
                replan_count=int(state.get("replan_count", 0)),
                state=state,
                context_store=services.get("context_store"),
                session_factory=services.get("session_factory"),
            )
            report = await report_agent.execute(report_input)
            report_generated = report is not None

        # ISSUE-204: never attempt CLOSED without report bytes when the caller
        # opted out of generation — halt at REPORTING instead of failing the gate.
        if not report_generated and not generate_report:
            store = services.get("context_store")
            if store is not None:
                try:
                    await store.set(state["event_id"], "report_generated", False)
                except Exception:
                    logger.warning(
                        "failed to persist report_generated=false event=%s",
                        state["event_id"],
                        exc_info=True,
                    )
            current_event_status = EventStatus(
                state.get("event_status", EventStatus.TRIAGING.value)
            )
            if current_event_status is not EventStatus.REPORTING:
                status = await _transition_status(
                    services,
                    state,
                    EventStatus.REPORTING,
                    reason="investigation:close_skipped_no_report",
                )
            else:
                status = cast(InvestigationState, {})
            return _patch_state(
                _trace(NODE_CLOSE),
                status,
                {
                    "report_generated": False,
                    "halted": True,
                    "final_verdict": final_verdict,
                },
            )

        # ISSUE-062 Blocker: escalated events arrive at close_node with
        # CONTAINED/FAILED status in the DB (set by ReplanHandler.escalate()).
        # STATE_TRANSITIONS has CONTAINED→{REPORTING, FAILED} and
        # FAILED→{REPORTING} — no direct edge to CLOSED.  We must first
        # transition through REPORTING to satisfy the state machine.
        current_event_status = EventStatus(state.get("event_status", EventStatus.REPORTING.value))
        if current_event_status in (EventStatus.CONTAINED, EventStatus.FAILED):
            report_status = await _transition_status(
                services,
                state,
                EventStatus.REPORTING,
                reason="investigation:escalated_to_reporting",
            )
            state = _patch_state(state, report_status)

        escalated = bool(state.get("escalated", False))
        status = await _transition_status(
            services,
            state,
            EventStatus.CLOSED,
            context=TransitionContext(
                need_investigation=triage.need_investigation,
                disposition_policy=DispositionPolicy(
                    state.get(
                        "disposition_policy",
                        DispositionPolicy.NOT_REQUIRED.value,
                    )
                ),
                severity=triage.severity,
                recommendation=((state.get("fp_adjudication") or {}).get("recommendation")),
                final_verdict=FinalVerdict(final_verdict) if final_verdict else None,
                report_exists=report_generated,
                escalated=escalated,
            ),
            reason=build_fp_close_reason(
                state.get("false_positive_match"),
                fp_adjudication=state.get("fp_adjudication"),
            ),
        )
        return _patch_state(
            _trace(NODE_CLOSE),
            status,
            {
                "final_verdict": final_verdict,
                "report_generated": report_generated,
                "halted": False,
            },
        )

    async def planner_graph_node(state: InvestigationState) -> InvestigationState:
        persisted = await runtime.read_disposition_only_intent(state["event_id"])
        if state.get("disposition_only_intent") and not persisted:
            raise InvalidStateTransitionError(
                "forged disposition_only_intent without server persistence",
                current=state.get("event_status", EventStatus.TRIAGING.value),
                target=EventStatus.PLANNING_RESPONSE.value,
                details={"event_id": state["event_id"]},
            )
        context = _event_context_from_state(
            _patch_state(state, {"disposition_only_intent": persisted})
        )
        plan = await planner_node(
            context,
            planner_agent,
            disposition_only=persisted,
        )
        return _patch_state(
            _trace(NODE_PLANNER),
            {
                "execution_plan": plan.model_dump(mode="json"),
                "disposition_only_intent": persisted,
            },
        )

    async def evidence_node(state: InvestigationState) -> InvestigationState:
        triage = TriageResult.model_validate(state["triage_result"])
        status = await _transition_status(
            services,
            state,
            EventStatus.COLLECTING_EVIDENCE,
            context=TransitionContext(need_investigation=True),
            reason="investigation:evidence",
        )
        planned_tools, _step_orders, _budget, _invalid = extract_evidence_plan_inputs(
            state.get("execution_plan")
        )
        plan_step_goal = ""
        execution_plan_data = state.get("execution_plan")
        if isinstance(execution_plan_data, dict):
            for step in execution_plan_data.get("steps") or []:
                if isinstance(step, dict) and step.get("assigned_agent") == "evidence_agent":
                    plan_step_goal = str(step.get("step_goal") or "")
                    break
        result = await evidence_agent.execute(
            EvidenceAgentInput(
                event_id=state["event_id"],
                triage_result=triage,
                alert_text=_alert_text_from_state(state),
                required_tools=planned_tools,
                plan_step_goal=plan_step_goal,
                execution_plan=(
                    execution_plan_data if isinstance(execution_plan_data, dict) else None
                ),
            )
        )
        if not isinstance(result, EvidenceOutput):
            raise TypeError("evidence_agent must return EvidenceOutput")
        await _transition_status(
            services,
            _patch_state(state, status),
            EventStatus.ANALYZING,
            reason="investigation:analyze",
        )
        return _patch_state(
            _trace(NODE_EVIDENCE),
            {
                "event_status": EventStatus.ANALYZING.value,
                "evidence_output": result.model_dump(mode="json"),
            },
        )

    async def fp_adjudication_node(state: InvestigationState) -> InvestigationState:
        triage = TriageResult.model_validate(state["triage_result"])
        evidence = EvidenceOutput.model_validate(state["evidence_output"])
        store = cast(EventContextStore, services["context_store"])
        context = await store.get_full_context(state["event_id"])
        occurred_at = context.event.occurred_at if context.event is not None else None
        wm_root = services.get("working_memory")
        fp_wm = (
            cast(WorkingMemory, wm_root).for_writer("PostEvidenceFpAdjudicator")
            if wm_root is not None
            else None
        )
        result = await run_post_evidence_fp_adjudication(
            event_id=state["event_id"],
            evidence_output=evidence,
            triage_result=triage,
            source_snapshot=state.get("source_snapshot"),
            occurred_at=occurred_at,
            working_memory=fp_wm,
        )
        return _patch_state(
            _trace(NODE_FP_ADJUDICATION),
            {"fp_adjudication": result.model_dump(mode="json")},
        )

    async def rag_graph_node(state: InvestigationState) -> InvestigationState:
        if rag_agent is None:
            return _trace(NODE_RAG)
        output = await rag_node(
            _event_context_from_state(state),
            rag_agent,
            triage_result=TriageResult.model_validate(state["triage_result"]),
            evidence_output=EvidenceOutput.model_validate(state["evidence_output"]),
        )
        update: dict[str, Any] = {}
        if output is not None:
            update["rag_output"] = output.model_dump(mode="json")
        return _patch_state(_trace(NODE_RAG), update)

    async def graph_node(state: InvestigationState) -> InvestigationState:
        if graph_agent is None:
            return _trace(NODE_GRAPH)
        evidence = EvidenceOutput.model_validate(state["evidence_output"])
        result = await graph_agent.execute(
            GraphAgentInput(
                event_id=state["event_id"],
                evidence_output=evidence,
            )
        )
        if not isinstance(result, GraphOutput):
            raise TypeError("graph_agent must return GraphOutput")
        update: dict[str, Any] = {"graph_output": result.model_dump(mode="json")}
        if result.degraded:
            flags = list(state.get("degraded_flags") or [])
            if "graph_degraded" not in flags:
                flags.append("graph_degraded")
            update["degraded_flags"] = flags
        return _patch_state(_trace(NODE_GRAPH), update)

    async def risk_node(state: InvestigationState) -> InvestigationState:
        rag_output = (
            RAGOutput.model_validate(state["rag_output"])
            if state.get("rag_output") is not None
            else None
        )
        graph_output = (
            GraphOutput.model_validate(state["graph_output"])
            if state.get("graph_output") is not None
            else None
        )
        await _transition_status(
            services,
            state,
            EventStatus.SCORING,
            reason="investigation:score",
        )
        tenant_id = resolve_tenant_id(state.get("source_snapshot"))
        if tenant_id is None:
            context_store = services.get("context_store")
            if context_store is not None:
                try:
                    source_snapshot = await context_store.get(state["event_id"], "source_snapshot")
                    tenant_id = resolve_tenant_id(source_snapshot)
                except Exception:
                    logger.debug(
                        "risk_node tenant resolution failed for event=%s",
                        state["event_id"],
                        exc_info=True,
                    )

        async def _execute_risk() -> RiskAssessment:
            result = await risk_agent.execute(
                RiskAgentInput(
                    event_id=state["event_id"],
                    triage_result=TriageResult.model_validate(state["triage_result"]),
                    evidence_output=EvidenceOutput.model_validate(state["evidence_output"]),
                    graph_output=graph_output,
                    rag_output=rag_output,
                )
            )
            if not isinstance(result, RiskAssessment):
                raise TypeError("risk_agent must return RiskAssessment")
            return result

        if tenant_id:
            projection_fields: dict[str, Any] = {
                "triage_result": state["triage_result"],
                "evidence_output": state["evidence_output"],
            }
            if state.get("rag_output") is not None:
                projection_fields["rag_output"] = state["rag_output"]
            if state.get("graph_output") is not None:
                projection_fields["graph_output"] = state["graph_output"]
            result = await run_risk_score_with_ledger(
                services.get("agent_task_service"),
                services.get("agent_artifact_service"),
                event_id=state["event_id"],
                tenant_id=tenant_id,
                worker_principal="investigation:workflow_graph",
                idempotency_key=f"risk-score:{state['event_id']}",
                content_projection_service=services.get("content_projection_service"),
                projection_fields=projection_fields,
                execute=_execute_risk,
            )
        else:
            result = await _execute_risk()
        defer_response = bool(state.get("defer_response_execution"))
        if defer_response:
            risk_status = EventStatus.SCORING
            status_patch: InvestigationState = cast(InvestigationState, {})
        else:
            status_patch = await _transition_status(
                services,
                state,
                EventStatus.PLANNING_RESPONSE,
                reason="investigation:plan_response",
            )
            risk_status = EventStatus.PLANNING_RESPONSE
        update: dict[str, Any] = {
            "event_status": risk_status.value,
            "risk_assessment": result.model_dump(mode="json"),
            "severity": result.severity.value,
        }
        await _hydrate_context(services, state["event_id"], update)
        update["event_status"] = risk_status.value
        return _patch_state(
            _trace(NODE_RISK),
            status_patch,
            update,
        )

    async def response_node(state: InvestigationState) -> InvestigationState:
        if state.get("disposition_only_intent"):
            return _patch_state(
                _trace(NODE_RESPONSE),
                {"halted": True},
            )
        plan_revision = _plan_revision_from_state(state)
        response_update: dict[str, Any] = {"plan_revision": plan_revision}
        if response_agent is not None:
            risk = RiskAssessment.model_validate(state["risk_assessment"])
            evidence = (
                EvidenceOutput.model_validate(state["evidence_output"])
                if state.get("evidence_output") is not None
                else None
            )

            async def _execute_response() -> ResponsePlan:
                result = await response_agent.execute(
                    ResponseAgentInput(
                        event_id=state["event_id"],
                        risk_assessment=risk,
                        evidence_output=evidence,
                    )
                )
                if not isinstance(result, ResponsePlan):
                    raise TypeError("response_agent must return ResponsePlan")
                return result

            tenant_id = resolve_tenant_id(state.get("source_snapshot"))
            if tenant_id is None:
                context_store = services.get("context_store")
                if context_store is not None:
                    try:
                        source_snapshot = await context_store.get(
                            state["event_id"], "source_snapshot"
                        )
                        tenant_id = resolve_tenant_id(source_snapshot)
                    except Exception:
                        logger.debug(
                            "response_node tenant resolution failed for event=%s",
                            state["event_id"],
                            exc_info=True,
                        )

            if tenant_id:
                projection_fields: dict[str, Any] = {
                    "risk_assessment": state["risk_assessment"],
                }
                if state.get("evidence_output") is not None:
                    projection_fields["evidence_output"] = state["evidence_output"]
                result = await run_response_plan_with_ledger(
                    services.get("agent_task_service"),
                    services.get("agent_artifact_service"),
                    event_id=state["event_id"],
                    tenant_id=tenant_id,
                    worker_principal="investigation:workflow_graph",
                    idempotency_key=f"response-plan:{state['event_id']}:{plan_revision}",
                    plan_revision=plan_revision,
                    content_projection_service=services.get("content_projection_service"),
                    projection_fields=projection_fields,
                    execute=_execute_response,
                )
            elif services.get("agent_task_service") is not None:
                # Ledger is wired: refuse unscoped execute that would skip immutable refs.
                raise ValidationError(
                    "response_plan ledger requires tenant_id",
                    error_code="validation_error",
                    details={
                        "event_id": state["event_id"],
                        "reason": "tenant_missing",
                    },
                )
            else:
                result = await _execute_response()
            response_update["response_plan"] = result.model_dump(mode="json")
        verdict_raw = state.get("final_verdict")
        transition_context = TransitionContext(
            disposition_only_intent=bool(state.get("disposition_only_intent")),
            final_verdict=FinalVerdict(verdict_raw) if verdict_raw else None,
        )
        if response_agent is None:
            # ISSUE-218: DI missing — fail closed instead of advancing to
            # WAITING_APPROVAL on a stub.  Persist a degraded flag, transition
            # to FAILED (legal edge) and halt the graph.
            flags = await _persist_degraded_flag(
                state,
                "response_agent_miswired",
                event_id=state["event_id"],
                degraded_flags=degraded_flags,
            )
            status = await _transition_status(
                services,
                state,
                EventStatus.FAILED,
                context=transition_context,
                reason="investigation:response_stub_miswired",
            )
            return _patch_state(
                _trace(NODE_RESPONSE),
                status,
                {"halted": True, "degraded_flags": flags, **response_update},
            )
        status = await _transition_status(
            services,
            state,
            EventStatus.WAITING_APPROVAL,
            context=transition_context,
            reason="investigation:response_plan",
        )
        return _patch_state(_trace(NODE_RESPONSE), status, response_update)

    async def approval_node(state: InvestigationState) -> InvestigationState:
        approval_engine = services.get("approval_engine")
        if approval_engine is not None:
            plan_revision = _plan_revision_from_state(state)
            risk = (
                RiskAssessment.model_validate(state["risk_assessment"])
                if state.get("risk_assessment") is not None
                else None
            )
            result = await approval_engine.evaluate_plan(
                state["event_id"],
                plan_revision,
                risk,
                disposition_confidence=state.get("confidence"),
            )
            if result.needs_wait:
                await runtime.set_execution_substate(
                    state["event_id"],
                    ExecutionSubstate.WAITING_APPROVAL,
                    event_status=EventStatus.WAITING_APPROVAL,
                )
                return _patch_state(
                    _trace(NODE_APPROVAL),
                    {
                        "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
                        "needs_approval_wait": True,
                        "plan_revision": plan_revision,
                    },
                )
            if result.evaluated_count > 0:
                await runtime.set_execution_substate(
                    state["event_id"],
                    ExecutionSubstate.NONE,
                    event_status=EventStatus.EXECUTING_RESPONSE,
                )
                current = EventStatus(state.get("event_status", EventStatus.WAITING_APPROVAL.value))
                update: dict[str, Any] = {
                    "execution_substate": ExecutionSubstate.NONE.value,
                    "plan_revision": plan_revision,
                }
                if current is not EventStatus.EXECUTING_RESPONSE:
                    status = await _transition_status(
                        services,
                        state,
                        EventStatus.EXECUTING_RESPONSE,
                        reason="investigation:approval_decided",
                    )
                    update.update(status)
                return _patch_state(_trace(NODE_APPROVAL), update)
        else:
            # ISSUE-218: approval_engine missing — fail closed instead of
            # faking an approval decision.  Persist a degraded flag, transition
            # to FAILED (legal edge) and halt the graph.
            flags = await _persist_degraded_flag(
                state,
                "approval_engine_miswired",
                event_id=state["event_id"],
                degraded_flags=degraded_flags,
            )
            status = await _transition_status(
                services,
                state,
                EventStatus.FAILED,
                reason="investigation:approval_stub_miswired",
            )
            return _patch_state(
                _trace(NODE_APPROVAL),
                status,
                {
                    "halted": True,
                    "degraded_flags": flags,
                    "execution_substate": ExecutionSubstate.NONE.value,
                },
            )
        if state.get("needs_approval_wait"):
            await runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.WAITING_APPROVAL,
                event_status=EventStatus.WAITING_APPROVAL,
            )
            return _patch_state(
                _trace(NODE_APPROVAL),
                {"execution_substate": ExecutionSubstate.WAITING_APPROVAL.value},
            )
        await runtime.set_execution_substate(
            state["event_id"],
            ExecutionSubstate.NONE,
            event_status=EventStatus.WAITING_APPROVAL,
        )
        status = await _transition_status(
            services,
            state,
            EventStatus.EXECUTING_RESPONSE,
            reason="investigation:approval_cleared",
        )
        return _patch_state(
            _trace(NODE_APPROVAL),
            status,
            {"execution_substate": ExecutionSubstate.NONE.value},
        )

    async def approval_wait_node(state: InvestigationState) -> InvestigationState:
        # Persist WAITING_APPROVAL substate and pause graph execution.
        # The graph halts here; resume_investigation() is called after
        # approve/reject API endpoints complete their decision cycle.
        await runtime.set_execution_substate(
            state["event_id"],
            ExecutionSubstate.WAITING_APPROVAL,
            event_status=EventStatus.WAITING_APPROVAL,
        )
        logger.info(
            "approval_wait: event=%s paused for human approval",
            state["event_id"],
        )
        return _patch_state(
            _trace(NODE_APPROVAL_WAIT),
            {
                "halted": True,
                "execution_substate": ExecutionSubstate.WAITING_APPROVAL.value,
            },
        )

    async def execute_node(state: InvestigationState) -> InvestigationState:
        action_execution = services.get("action_execution")
        if action_execution is None:
            # ISSUE-218: DI missing — fail closed instead of advancing to
            # VERIFYING on a stub.  Persist a degraded flag, transition to
            # FAILED (legal edge) and halt the graph.
            flags = await _persist_degraded_flag(
                state,
                "action_execution_miswired",
                event_id=state["event_id"],
                degraded_flags=degraded_flags,
            )
            status = await _transition_status(
                services,
                state,
                EventStatus.FAILED,
                reason="investigation:execute_stub_miswired",
            )
            return _patch_state(
                _trace(NODE_EXECUTE),
                status,
                {"halted": True, "degraded_flags": flags},
            )
        plan_revision = _plan_revision_from_state(state)
        execution_ok = True
        try:
            summary = await action_execution.execute_plan(
                state["event_id"],
                plan_revision=plan_revision,
            )
            # Track whether any IMMEDIATE actions were executed.
            execution_ok = summary is not None
        except Exception:
            logger.exception(
                "execute_plan failed for event=%s revision=%d",
                state["event_id"],
                plan_revision,
            )
            execution_ok = False

        status = await _transition_status(
            services,
            state,
            EventStatus.VERIFYING,
            reason="investigation:execute_plan",
        )
        return _patch_state(
            _trace(NODE_EXECUTE),
            status,
            {"execution_ok": execution_ok},
        )

    async def verify_node(state: InvestigationState) -> InvestigationState:
        if state.get("halted"):
            # ISSUE-218: a previous node halted (e.g. execute_node failed
            # closed on a missing action_execution) — do not run verification
            # or advance state past FAILED; route_after_verify sends us to HALT.
            return _patch_state(_trace(NODE_VERIFY), {"halted": True})
        verify_agent = cast(_AgentLike | None, agents.get("verify_agent"))
        disposition_sync = services.get("disposition_sync")
        event_disposition = services.get("event_disposition")
        disposition_only = bool(state.get("disposition_only_intent"))
        policy_required = state.get("disposition_policy") == DispositionPolicy.REQUIRED.value

        # Should-Fix: when disposition_policy=required and no response_plan
        # exists, escalate to MANUAL_RESOLUTION instead of constructing a
        # placeholder that would silently swallow the missing plan.  A
        # required-policy event must have a concrete response plan before
        # verification can proceed.
        if policy_required and state.get("response_plan") is None:
            flags = await _persist_degraded_flag(
                state,
                "missing_response_plan_for_required_policy",
                event_id=state["event_id"],
                degraded_flags=degraded_flags,
            )
            await runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.MANUAL_RESOLUTION,
                event_status=EventStatus.VERIFYING,
            )
            return _patch_state(
                _trace(NODE_VERIFY),
                {
                    "degraded_flags": flags,
                    "execution_substate": ExecutionSubstate.MANUAL_RESOLUTION.value,
                    "verify_need_action_replan": False,
                    "verify_need_writeback_recovery": False,
                    "verify_need_manual_resolution": True,
                },
            )

        # Build ResponsePlan from state for VerifyAgent input.
        # The fallback placeholder (plan_id="") is only reached for
        # non-required-policy events where the planner didn't produce a
        # response_plan — the empty plan is acceptable here because
        # VerifyAgent only uses it for context; the policy won't enforce
        # disposition writeback.
        response_plan = (
            ResponsePlan.model_validate(state["response_plan"])
            if state.get("response_plan") is not None
            else ResponsePlan(
                plan_id="",
                actions=[],
                strategy_summary="",
                generated_by=ResponsePlanGeneratedBy.TEMPLATE,
            )
        )

        verification_result: VerificationResult | None = None
        degraded = False

        if verify_agent is not None:
            try:
                result = await verify_agent.execute(
                    VerifyAgentInput(
                        event_id=state["event_id"],
                        response_plan=response_plan,
                        verification_phase=VerificationPhase.EFFECT,
                    )
                )
                if isinstance(result, VerificationResult):
                    verification_result = result
                else:
                    degraded = True
                    logger.warning(
                        "verify_agent returned non-VerificationResult for event=%s",
                        state["event_id"],
                    )
            except Exception:
                degraded = True
                logger.exception("verify_agent failed for event=%s", state["event_id"])
        elif disposition_only or policy_required:
            # Disposition-only path without verify_agent: activate phase 2
            # disposition writeback.  Prefer EventDispositionService (ISSUE-059A)
            # which routes through TerminalDispositionResolver and the
            # after_effect_resolution_ready gate; fall back to direct
            # disposition_sync.activate_deferred_disposition when EDS is
            # not wired.  When neither is available, flag writeback recovery
            # so the writeback recovery handler can pick it up.
            disposition_activation_failed = False
            if event_disposition is not None:
                try:
                    logger.info(
                        "verify_node: activating deferred disposition via "
                        "EventDispositionService for event=%s",
                        state["event_id"],
                    )
                    plan_revision = _plan_revision_from_state(state)
                    await event_disposition.activate_and_submit(
                        state["event_id"],
                        plan_revision,
                        principal_or_system="verify_node:disposition_activation",
                    )
                except Exception:
                    logger.exception(
                        "verify_node: EventDispositionService activation failed for event=%s",
                        state["event_id"],
                    )
                    degraded = True
                    disposition_activation_failed = True
            elif disposition_sync is not None:
                try:
                    logger.info(
                        "verify_node: activating deferred disposition via "
                        "disposition_sync for event=%s",
                        state["event_id"],
                    )
                    await disposition_sync.activate_deferred_disposition(
                        state["event_id"],
                        operator="verify_node:disposition_activation",
                    )
                except Exception:
                    logger.exception(
                        "verify_node: disposition activation failed for event=%s",
                        state["event_id"],
                    )
                    degraded = True
                    disposition_activation_failed = True
            else:
                degraded = True

            # When disposition activation itself fails the writeback was
            # never created (the activation is what creates the outbox
            # record), so there is nothing for WritebackRecoveryHandler to
            # recover.  Route to MANUAL_RESOLUTION so an operator can
            # decide whether to retry activation or close the event.
            # We write the flag directly into state rather than through
            # DegradedFlagService.set_flag to avoid the ISSUE-014 guardrail
            # (verify_node is not a trusted caller and
            # disposition_activation_failed is not in the allowlist).
            if degraded and disposition_activation_failed:
                flags = await _persist_degraded_flag(
                    state,
                    "disposition_activation_failed",
                    event_id=state["event_id"],
                    degraded_flags=degraded_flags,
                )
                await runtime.set_execution_substate(
                    state["event_id"],
                    ExecutionSubstate.MANUAL_RESOLUTION,
                    event_status=EventStatus.VERIFYING,
                )
                return _patch_state(
                    _trace(NODE_VERIFY),
                    {
                        "degraded_flags": flags,
                        "execution_substate": ExecutionSubstate.MANUAL_RESOLUTION.value,
                        "verify_need_action_replan": False,
                        "verify_need_writeback_recovery": False,
                        "verify_need_manual_resolution": True,
                    },
                )
        else:
            degraded = True

        if degraded or verification_result is None:
            # Degradation: verification could not complete.  Route to
            # MANUAL_RESOLUTION so an operator can triage rather than
            # silently assuming success and proceeding to REPORTING.
            # We write the flag directly into state rather than through
            # DegradedFlagService.set_flag to avoid the ISSUE-014 guardrail
            # (verify_node is not a trusted caller and verify_degraded is
            # not in the allowlist).
            flags = await _persist_degraded_flag(
                state,
                "verify_degraded",
                event_id=state["event_id"],
                degraded_flags=degraded_flags,
            )
            await _persist_verify_degraded_result(
                services,
                state["event_id"],
                detail="verify_degraded",
            )
            await runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.MANUAL_RESOLUTION,
                event_status=EventStatus.VERIFYING,
            )
            return _patch_state(
                _trace(NODE_VERIFY),
                {
                    "degraded_flags": flags,
                    "execution_substate": ExecutionSubstate.MANUAL_RESOLUTION.value,
                    "verify_need_action_replan": False,
                    "verify_need_writeback_recovery": False,
                    "verify_need_manual_resolution": True,
                },
            )

        # Extract routing flags from VerificationResult.
        update: dict[str, Any] = {
            "verify_need_action_replan": verification_result.need_action_replan,
            "verify_need_writeback_recovery": verification_result.need_writeback_recovery,
            "verify_need_manual_resolution": verification_result.need_manual_resolution,
            "verify_failed_actions": verification_result.failed_actions,
            "verify_failed_writebacks": verification_result.failed_writebacks,
            "verify_writeback_status": _resolve_verify_writeback_status(verification_result),
            "verify_writeback_status_map": _resolve_verify_writeback_statuses(verification_result),
            "verify_has_partial_success": verification_result.overall_status.value == "partial",
        }

        # Should-Fix: when execution_ok is False but VerifyAgent didn't report
        # any specific failures, the execution layer itself failed without a
        # corresponding verification signal.  This is an anomalous state —
        # route to MANUAL_RESOLUTION instead of silently proceeding to
        # REPORTING with a false sense of success.
        if (
            not state.get("execution_ok", True)
            and not verification_result.need_action_replan
            and not verification_result.need_writeback_recovery
            and not verification_result.need_manual_resolution
        ):
            flags = await _persist_degraded_flag(
                state,
                "execution_failed_unverified",
                event_id=state["event_id"],
                degraded_flags=degraded_flags,
            )
            await runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.MANUAL_RESOLUTION,
                event_status=EventStatus.VERIFYING,
            )
            return _patch_state(
                _trace(NODE_VERIFY),
                {
                    **update,
                    "degraded_flags": flags,
                    "execution_substate": ExecutionSubstate.MANUAL_RESOLUTION.value,
                    "verify_need_action_replan": False,
                    "verify_need_writeback_recovery": False,
                    "verify_need_manual_resolution": True,
                },
            )

        # Transition to the appropriate status based on verification outcome.
        # ISSUE-242: overall success stays in VERIFYING; report_node owns the
        # VERIFYING→REPORTING transition *after* ReportAgent upserts so
        # status=reporting never races a missing GET /report row.
        if verification_result.need_action_replan:
            # Don't transition here — replan_node handles REPLANNING transition.
            pass
        elif verification_result.need_writeback_recovery:
            # Stay in VERIFYING with WAITING_WRITEBACK substate.
            await runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.WAITING_WRITEBACK,
                event_status=EventStatus.VERIFYING,
            )
            update["execution_substate"] = ExecutionSubstate.WAITING_WRITEBACK.value
        elif verification_result.need_manual_resolution:
            await runtime.set_execution_substate(
                state["event_id"],
                ExecutionSubstate.MANUAL_RESOLUTION,
                event_status=EventStatus.VERIFYING,
            )
            update["execution_substate"] = ExecutionSubstate.MANUAL_RESOLUTION.value

        return _patch_state(_trace(NODE_VERIFY), update)

    async def replan_node(state: InvestigationState) -> InvestigationState:
        patches = await replan_graph_node(
            state,
            handler=_replan_handler,
            convergence_guard=_convergence_guard,
        )
        return _patch_state(_trace(NODE_REPLAN), patches)

    async def writeback_recovery_node(state: InvestigationState) -> InvestigationState:
        return await writeback_recovery_graph_node(
            state,
            handler=_wb_handler,
        )

    async def report_node(state: InvestigationState) -> InvestigationState:
        store = services.get("context_store")
        event_id = state["event_id"]

        async def _persist_report_generated_flag(generated: bool) -> None:
            if store is None:
                return
            try:
                await store.set(event_id, "report_generated", generated)
            except Exception:
                logger.warning(
                    "failed to persist report_generated=%s event=%s",
                    generated,
                    event_id,
                    exc_info=True,
                )

        if not state.get("generate_report", True):
            await _persist_report_generated_flag(False)
            current = EventStatus(state.get("event_status", EventStatus.VERIFYING.value))
            if current is not EventStatus.REPORTING:
                status = await _transition_status(
                    services,
                    state,
                    EventStatus.REPORTING,
                    reason="investigation:report_skipped",
                )
            else:
                status = cast(InvestigationState, {})
            return _patch_state(
                _trace(NODE_REPORT),
                status,
                {"report_generated": False},
            )
        # ISSUE-205: single builder backfills response_plan + verification_result
        # (state → context_store); the prior hand-written verify-only injection
        # is retired so no parallel construction path remains.
        report_input = await build_report_agent_input(
            event_id,
            evidence_output=EvidenceOutput.model_validate(state["evidence_output"]),
            risk_assessment=RiskAssessment.model_validate(state["risk_assessment"]),
            escalated=bool(state.get("escalated", False)),
            replan_count=int(state.get("replan_count", 0)),
            state=state,
            context_store=store,
            session_factory=services.get("session_factory"),
        )
        try:
            report = await report_agent.execute(report_input)
            if report is None:
                raise ValidationError(
                    "ReportAgent returned no report while generate_report=true",
                    error_code="report_generation_failed",
                    details={"event_id": event_id},
                )
        except Exception as exc:
            # ISSUE-242: never leave REPORTING with a silent missing row —
            # persist explicit failure markers before _wrap_node marks FAILED.
            await _persist_report_generated_flag(False)
            try:
                await _persist_degraded_flag(
                    state,
                    "report_generation_failed",
                    event_id=event_id,
                    degraded_flags=degraded_flags,
                )
            except Exception:
                logger.warning(
                    "failed to persist report_generation_failed flag event=%s",
                    event_id,
                    exc_info=True,
                )
            raise

        await _persist_report_generated_flag(True)
        # ISSUE-062 B2 / ISSUE-242: report_node owns VERIFYING→REPORTING after
        # upsert. Without this transition, close_node would attempt
        # VERIFYING→CLOSED which is illegal. When already at REPORTING (e.g.
        # resume), skip the redundant DB write.
        current = EventStatus(state.get("event_status", EventStatus.VERIFYING.value))
        if current is not EventStatus.REPORTING:
            status = await _transition_status(
                services,
                state,
                EventStatus.REPORTING,
                reason="investigation:report",
            )
        else:
            status = cast(InvestigationState, {})
        return _patch_state(
            _trace(NODE_REPORT),
            status,
            {"report_generated": True},
        )

    async def halt_node(state: InvestigationState) -> InvestigationState:
        return _patch_state(_trace(NODE_HALT), {"halted": True})

    graph: StateGraph[InvestigationState] = StateGraph(InvestigationState)

    def register(
        name: str,
        node: Callable[
            [InvestigationState],
            Coroutine[Any, Any, InvestigationState],
        ],
    ) -> None:
        graph.add_node(name, cast(Any, _wrap_node(services, node)))

    register(NODE_TRIAGE, triage_graph_node)
    # ISSUE-114: disposition-only is API-triggered via WorkflowRuntimeService.
    # This node has no graph incoming edges; tests/resume hooks invoke it directly.
    register(NODE_BEGIN_DISPOSITION_ONLY, begin_disposition_only_node)
    register(NODE_MANUAL_HOLD, manual_hold_node)
    register(NODE_CLOSE, close_node)
    register(NODE_PLANNER, planner_graph_node)
    register(NODE_EVIDENCE, evidence_node)
    register(NODE_FP_ADJUDICATION, fp_adjudication_node)
    register(NODE_GRAPH, graph_node)
    register(NODE_RISK, risk_node)
    register(NODE_RESPONSE, response_node)
    register(NODE_APPROVAL, approval_node)
    register(NODE_APPROVAL_WAIT, approval_wait_node)
    register(NODE_EXECUTE, execute_node)
    register(NODE_VERIFY, verify_node)
    register(NODE_REPLAN, replan_node)
    register(NODE_WRITEBACK_RECOVERY, writeback_recovery_node)
    register(NODE_REPORT, report_node)
    register(NODE_HALT, halt_node)
    if rag_agent is not None:
        register(NODE_RAG, rag_graph_node)

    graph.add_edge(START, NODE_TRIAGE)
    graph.add_conditional_edges(
        NODE_TRIAGE,
        route_after_triage,
        {
            ROUTE_CLOSE: NODE_CLOSE,
            ROUTE_REPORT: NODE_REPORT,
            ROUTE_MANUAL_HOLD: NODE_MANUAL_HOLD,
            ROUTE_INVESTIGATE: NODE_PLANNER,
        },
    )
    graph.add_edge(NODE_BEGIN_DISPOSITION_ONLY, NODE_PLANNER)
    graph.add_edge(NODE_MANUAL_HOLD, END)
    graph.add_conditional_edges(
        NODE_PLANNER,
        route_after_planner,
        {
            ROUTE_RESPONSE: NODE_RESPONSE,
            ROUTE_EVIDENCE: NODE_EVIDENCE,
        },
    )
    graph.add_edge(NODE_EVIDENCE, NODE_FP_ADJUDICATION)
    graph.add_conditional_edges(
        NODE_FP_ADJUDICATION,
        route_after_fp_adjudication,
        {ROUTE_CONTINUE: NODE_RAG if rag_agent is not None else NODE_GRAPH},
    )
    if rag_agent is not None:
        graph.add_edge(NODE_RAG, NODE_GRAPH)
    graph.add_edge(NODE_GRAPH, NODE_RISK)
    graph.add_conditional_edges(
        NODE_RISK,
        route_after_risk,
        {
            ROUTE_RESPONSE: NODE_RESPONSE,
            ROUTE_REPORT: NODE_REPORT,
        },
    )
    graph.add_conditional_edges(
        NODE_RESPONSE,
        _route_after_response,
        {
            ROUTE_HALT: NODE_HALT,
            ROUTE_TO_APPROVAL: NODE_APPROVAL,
        },
    )
    graph.add_conditional_edges(
        NODE_APPROVAL,
        route_after_approval,
        {
            ROUTE_EXECUTE: NODE_EXECUTE,
            ROUTE_WAIT: NODE_APPROVAL_WAIT,
            ROUTE_REPORT: NODE_REPORT,
            ROUTE_HALT: NODE_HALT,
        },
    )
    graph.add_edge(NODE_APPROVAL_WAIT, END)
    graph.add_conditional_edges(
        NODE_EXECUTE,
        _route_after_execute,
        {
            ROUTE_HALT: NODE_HALT,
            ROUTE_TO_VERIFY: NODE_VERIFY,
        },
    )
    graph.add_conditional_edges(
        NODE_VERIFY,
        route_after_verify,
        {
            ROUTE_REPORT: NODE_REPORT,
            ROUTE_REPLAN: NODE_REPLAN,
            ROUTE_MANUAL: NODE_MANUAL_HOLD,
            ROUTE_WRITEBACK: NODE_WRITEBACK_RECOVERY,
            ROUTE_HALT: NODE_HALT,
        },
    )
    # Writeback recovery routing (ISSUE-062 S2):
    #
    # NODE_WRITEBACK_RECOVERY deliberately reuses ``route_after_verify`` because
    # its state output produces the same routing flags (verify_need_* / halted)
    # that the verify→{report, replan, manual, writeback, halt} truth table
    # consumes.  This is an intentional contract — not an oversight:
    #
    #   writeback_recovery_graph_node sets:
    #     verify_need_writeback_recovery → ROUTE_WRITEBACK (loop back here)
    #     verify_need_manual_resolution    → ROUTE_MANUAL  (manual_hold_node)
    #     (neither flag)                   → ROUTE_REPORT  (report_node)
    #     halted                           → ROUTE_HALT    (halt_node)
    #
    # If writeback recovery ever needs to send a signal beyond this set (e.g.
    # "waiting but don't halt the graph"), define a dedicated route function
    # rather than adding a new flag that route_after_verify must also handle.
    graph.add_conditional_edges(
        NODE_WRITEBACK_RECOVERY,
        route_after_verify,
        {
            ROUTE_REPORT: NODE_REPORT,
            ROUTE_REPLAN: NODE_REPLAN,
            ROUTE_MANUAL: NODE_MANUAL_HOLD,
            ROUTE_WRITEBACK: NODE_WRITEBACK_RECOVERY,
            ROUTE_HALT: NODE_HALT,
        },
    )
    # Replan: escalate→report, continue→back to planner for revise.
    graph.add_conditional_edges(
        NODE_REPLAN,
        route_after_replan,
        {
            ROUTE_REPORT: NODE_REPORT,
            ROUTE_INVESTIGATE: NODE_PLANNER,
        },
    )
    graph.add_conditional_edges(
        NODE_REPORT,
        route_after_report,
        {
            ROUTE_CLOSE: NODE_CLOSE,
            ROUTE_HALT: NODE_HALT,
        },
    )
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
        source_snapshot=event_context.source_snapshot,
        principal="investigation:workflow_graph",
    )
    return output


__all__ = [
    "NODE_APPROVAL",
    "NODE_APPROVAL_WAIT",
    "NODE_BEGIN_DISPOSITION_ONLY",
    "NODE_CLOSE",
    "NODE_EVIDENCE",
    "NODE_EXECUTE",
    "NODE_GRAPH",
    "NODE_HALT",
    "NODE_MANUAL_HOLD",
    "NODE_PLANNER",
    "NODE_RAG",
    "NODE_REPLAN",
    "NODE_REPORT",
    "NODE_RESPONSE",
    "NODE_RISK",
    "NODE_TRIAGE",
    "NODE_VERIFY",
    "NODE_WRITEBACK_RECOVERY",
    "P0_NODE_SEQUENCE",
    "build_investigation_graph",
    "build_initial_investigation_state",
    "invoke_investigation_graph",
    "planner_node",
    "rag_node",
    "route_after_approval",
    "route_after_planner",
    "route_after_replan",
    "route_after_report",
    "route_after_risk",
    "route_after_fp_adjudication",
    "route_after_triage",
    "route_after_verify",
]
