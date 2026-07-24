"""SuperAgent — LangGraph-backed orchestration driver (ISSUE-054).

Wires the full investigation graph with conditional routing::

    START → triage ─┬→ planner → execute_plan_steps → report → END
                    └→ close_node → END

When triage determines ``need_investigation=false`` and
``disposition_policy=not_required`` the graph routes to ``close_node``
(ISSUE-048 fast-close path).  Otherwise it proceeds through the full
analysis pipeline.

Each node wraps an Agent call, managing state transitions, lease renewal and
error handling.  RAG, Graph, Storyline and ReAct are injected as capability
switches (hooks) — they do not break the main pipeline when unavailable.

Uses a lightweight dict-based graph runner that mirrors the langgraph
``StateGraph`` pattern without requiring the external package at runtime.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Protocol, runtime_checkable

from app.agents.base import AgentOutput, BaseAgent
from app.agents.planner_agent import PlannerAgent
from app.agents.rag_agent import RAGAgent
from app.core.errors import InvestigationInProgressError, ShadowTraceError
from app.models.agent_io import (
    CollectionStatus,
    EvidenceAgentInput,
    EvidenceOutput,
    ExecutionPlan,
    GraphOutput,
    PlanStep,
    RAGOutput,
    ReportAgentInput,
    RiskAgentInput,
    RiskAssessment,
    ScoringMode,
    SuperAgentInput,
    TriageAgentInput,
    TriageResult,
)
from app.models.context import EventContext
from app.models.entities import EntitySet
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SuperAgentStatus,
    WritebackReadiness,
)
from app.models.ids import report_id_for_event
from app.models.report import InvestigationReport
from app.models.security_event import EventSummary
from app.models.workflow import TransitionContext
from app.orchestration.lease import EventLease, generate_owner_id
from app.orchestration.workflow_graph import planner_node, rag_node
from app.services.working_memory import BoundWorkingMemory

logger = logging.getLogger(__name__)

_SUPER_AGENT_OPERATOR = "SuperAgent"

# Plan steps handled outside execute_plan_steps (ISSUE-054 / ISSUE-062 boundary).
_DEFERRED_PLAN_AGENTS = frozenset({"report_agent", "response_agent"})

# --------------------------------------------------------------------------- #
# Agent protocol for type-safe dependency injection
# --------------------------------------------------------------------------- #


@runtime_checkable
class _AgentProtocol(Protocol):
    async def execute(self, input: Any) -> Any: ...


# --------------------------------------------------------------------------- #
# Lightweight graph runner (langgraph-compatible API subset)
# --------------------------------------------------------------------------- #


class _CompiledGraph:
    """Runs a compiled graph sequentially from the entry point.

    Nodes are ``async def node(state: dict) -> dict`` callables that
    receive the current state and return a partial update.  Edges are
    traversed depth-first from the entry point.  Conditional edges (from
    ``add_conditional_edges``) are evaluated before unconditional edges.
    """

    def __init__(
        self,
        nodes: dict[str, Any],
        edges: list[tuple[str, str]],
        entry_point: str,
        cond_edges: dict[str, tuple[Any, dict[Any, str]]] | None = None,
    ) -> None:
        self._nodes = nodes
        self._adj: dict[str, str | None] = {}
        for src, dst in edges:
            self._adj[src] = dst
        # Ensure every node has an entry in _adj so we never KeyError.
        for name in nodes:
            self._adj.setdefault(name, None)
        self._entry_point = entry_point
        self._cond_edges: dict[str, tuple[Any, dict[Any, str]]] = cond_edges or {}

    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
        """Run the graph.  Each node receives a snapshot and returns an update."""
        current: str | None = self._entry_point
        while current is not None:
            if current not in self._nodes:
                logger.error("Graph node %r not found; stopping", current)
                break
            node_fn = self._nodes[current]
            update = await node_fn(state)
            if update:
                state.update(update)
            # Conditional routing takes precedence over unconditional edges.
            if current in self._cond_edges:
                path_fn, path_map = self._cond_edges[current]
                key = path_fn(state)
                current = path_map.get(key)
            else:
                current = self._adj.get(current)
        return state


class _StateGraph:
    """Minimal ``StateGraph``-alike builder with conditional-edge support."""

    def __init__(self, schema: type) -> None:
        self._nodes: dict[str, Any] = {}
        self._edges: list[tuple[str, str]] = []
        self._cond_edges: dict[str, tuple[Any, dict[Any, str]]] = {}
        self._entry_point: str | None = None

    def add_node(self, name: str, func: Any) -> None:
        self._nodes[name] = func

    def add_edge(self, from_node: str, to_node: str) -> None:
        self._edges.append((from_node, to_node))

    def add_conditional_edges(
        self,
        source: str,
        path_fn: Any,
        path_map: dict[Any, str],
    ) -> None:
        """Route *source* → ``path_map[path_fn(state)]`` after execution."""
        self._cond_edges[source] = (path_fn, path_map)

    def set_entry_point(self, name: str) -> None:
        self._entry_point = name

    def compile(self) -> _CompiledGraph:
        if self._entry_point is None:
            raise ValueError("entry_point must be set before compile()")
        return _CompiledGraph(
            self._nodes,
            self._edges,
            self._entry_point,
            self._cond_edges if self._cond_edges else None,
        )


# --------------------------------------------------------------------------- #
# SuperAgent
# --------------------------------------------------------------------------- #


class SuperAgent(BaseAgent[SuperAgentInput, AgentOutput]):
    """Orchestration agent that drives the full investigation lifecycle.

    Parameters
    ----------
    triage_agent, evidence_agent, planner_agent, risk_agent, report_agent:
        Required P0 agents — the graph will not execute without them.
    rag_agent, graph_agent, storyline_service:
        Optional P1 capability switches; missing → simply skipped.
    react_executor:
        ``ReadOnlyReActExecutor`` (ISSUE-053); only activated when
        ``REACT_ENABLED=true`` AND the executor is injected.
    event_service:
        Used for status transitions (``transition_status``).
    lease:
        ``EventLease``; may be ``None`` in dev/test (degraded path rejects
        duplicates through other means).
    working_memory:
        ``BoundWorkingMemory`` for persisting agent outputs.
    convergence_guard:
        ``ConvergenceGuard`` for global step counting (ISSUE-052).
    event_bus:
        ``EventBus`` for WS progress notifications.
    """

    agent_name: str = "super_agent"

    def __init__(
        self,
        *,
        triage_agent: _AgentProtocol | None = None,
        evidence_agent: _AgentProtocol | None = None,
        planner_agent: PlannerAgent | None = None,
        rag_agent: RAGAgent | None = None,
        risk_agent: _AgentProtocol | None = None,
        report_agent: _AgentProtocol | None = None,
        graph_agent: _AgentProtocol | None = None,
        storyline_service: Any | None = None,  # StorylineService (has .generate not .execute)
        react_executor: Any | None = None,
        event_service: Any | None = None,
        context_store: Any | None = None,
        lease: EventLease | None = None,
        working_memory: BoundWorkingMemory | None = None,
        convergence_guard: Any | None = None,
        event_bus: Any | None = None,
        react_enabled: bool = False,
        trace_service: Any | None = None,
    ) -> None:
        super().__init__(
            working_memory=working_memory,
            trace_service=trace_service,
            event_bus=event_bus,
        )
        self.triage_agent = triage_agent
        self.evidence_agent = evidence_agent
        self.planner_agent = planner_agent
        self.rag_agent = rag_agent
        self.risk_agent = risk_agent
        self.report_agent = report_agent
        self.graph_agent = graph_agent
        self.storyline_service = storyline_service
        self.react_executor = react_executor
        self.event_service = event_service
        self.context_store = context_store
        self.lease = lease
        self.convergence_guard = convergence_guard
        self.react_enabled = react_enabled
        self._transition_failures: dict[str, list[dict[str, Any]]] = {}

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    async def investigate(
        self,
        event_id: str,
        *,
        owner_id: str | None = None,
        lease_acquired: bool = False,
    ) -> None:
        """Run the full investigation graph for *event_id*.

        Acquires a distributed lease (unless *lease_acquired* is True),
        freezes the source snapshot, executes the LangGraph pipeline,
        persists the final context, and releases the lease on completion.
        """
        if self.planner_agent is None:
            raise RuntimeError("SuperAgent requires a PlannerAgent")
        if self.triage_agent is None or self.evidence_agent is None:
            raise RuntimeError("SuperAgent requires TriageAgent and EvidenceAgent")
        if self.risk_agent is None or self.report_agent is None:
            raise RuntimeError("SuperAgent requires RiskAgent and ReportAgent")

        resolved_owner = owner_id or generate_owner_id()
        acquired = lease_acquired
        renewal_task: asyncio.Task[None] | None = None
        event_context: EventContext | None = None
        guard_reset_needed = True  # cleared only when another worker owns the lease

        try:
            # 1. Acquire lease
            if self.lease is not None:
                if not lease_acquired:
                    acquired = await self.lease.acquire(event_id, resolved_owner)
                    if not acquired:
                        raise InvestigationInProgressError(
                            message="investigation already in progress for this event",
                            error_code="investigation_in_progress",
                            details={"event_id": event_id},
                        )
                renewal_task = await self.lease.start_renewal(event_id, resolved_owner)

            # 2. Load / build initial state
            event_context = await self._load_event_context(event_id)

            # 3. Freeze source snapshot for this investigation run
            await self._freeze_source_snapshot(event_context)

            # 4. Build and run graph
            graph = self._build_graph()
            state: dict[str, Any] = {
                "event_context": event_context,
                "super_agent_status": SuperAgentStatus.PLANNING,
                "error": None,
            }
            final_state = await graph.ainvoke(state)

            # 5. Fail closed when state-machine transitions did not persist.
            failures = self._transition_failures.pop(event_id, [])
            if failures:
                raise ShadowTraceError(
                    message=(
                        f"SuperAgent state transitions failed for event={event_id}"
                    ),
                    error_code="internal_error",
                    details={"failures": failures},
                )

            # 6. Persist final EventContext state so downstream consumers
            #    (API response, frontend, ReportAgent fallback) see latest data.
            ec: EventContext = final_state.get("event_context", event_context)
            await self._persist_event_context(ec)
            await self._persist_analysis_only_complete(event_id)

        except InvestigationInProgressError:
            # Concurrent trigger — another worker already owns this event.
            # Do NOT transition to FAILED; the active worker is still
            # processing.  Also skip guard reset — the owning worker will
            # handle its own counters.
            guard_reset_needed = False
            raise
        except Exception:
            await self._transition(
                event_id, EventStatus.FAILED, reason="exception", ec=event_context
            )
            failures = self._transition_failures.pop(event_id, [])
            if failures:
                logger.warning(
                    "SuperAgent: %d transition failure(s) before FAILED for event=%s: %s",
                    len(failures),
                    event_id,
                    failures,
                )
            raise
        finally:
            if renewal_task is not None:
                renewal_task.cancel()
                try:
                    await renewal_task
                except asyncio.CancelledError:
                    pass
            # Reset guard counters BEFORE releasing the lease.  If release()
            # raises (Redis connectivity loss) we must still prevent unbounded
            # memory growth in the ConvergenceGuard in-process store.
            if guard_reset_needed:
                self._reset_convergence_guard(event_id)
            if acquired and self.lease is not None:
                await self.lease.release(event_id, resolved_owner)

    # ------------------------------------------------------------------ #
    # _run — BaseAgent template integration
    # ------------------------------------------------------------------ #

    async def _run(self, input: SuperAgentInput) -> AgentOutput:
        """Delegates to ``investigate`` so BaseAgent.execute() applies."""
        await self.investigate(input.event_id)
        return AgentOutput(agent_name="super_agent", success=True)

    # ------------------------------------------------------------------ #
    # Graph construction
    # ------------------------------------------------------------------ #

    def _build_graph(self) -> _CompiledGraph:
        """Assemble the investigation state graph.

        Nodes
        -----
        triage → [conditional] → planner → execute_plan_steps → report
        triage → [conditional] → close_node (fast-close when
        need_investigation=false + disposition_policy=not_required)
        """
        builder: _StateGraph = _StateGraph(dict)
        builder.add_node("triage", self._triage_node)
        builder.add_node("close_node", self._close_node)
        builder.add_node("planner", self._planner_node)
        builder.add_node("execute_plan_steps", self._execute_plan_steps_node)
        builder.add_node("report", self._report_node)

        builder.set_entry_point("triage")
        builder.add_conditional_edges(
            "triage",
            _route_after_triage,
            {True: "close_node", False: "planner"},
        )
        builder.add_edge("planner", "execute_plan_steps")
        builder.add_edge("execute_plan_steps", "report")

        return builder.compile()

    # ------------------------------------------------------------------ #
    # Graph nodes
    # ------------------------------------------------------------------ #

    async def _triage_node(self, state: dict[str, Any]) -> dict[str, Any]:
        """Run TriageAgent and persist the result."""
        ec: EventContext = state["event_context"]
        event_id = _event_id_from_context(ec)

        await self._transition(event_id, EventStatus.TRIAGING, ec=ec)
        state["super_agent_status"] = SuperAgentStatus.EXECUTING
        await self._record_agent_step(event_id, "triage_agent")

        triage_input = await self._build_triage_input(event_id, ec)

        triage_result: TriageResult = await self.triage_agent.execute(triage_input)  # type: ignore[union-attr]
        if not isinstance(triage_result, TriageResult):
            raise TypeError("TriageAgent must return TriageResult")

        ec.triage_result = triage_result.model_dump(mode="json")

        if not triage_result.need_investigation:
            # Per ISSUE-048 routing: fast-close requires BOTH
            # need_investigation=false AND disposition_policy=not_required.
            # When disposition is still required the event stays on the main
            # pipeline so writeback/external sync can proceed.
            policy = _disposition_policy_from_context(ec)
            if policy == DispositionPolicy.NOT_REQUIRED:
                logger.info(
                    "SuperAgent: triage says no investigation needed for event=%s "
                    "(policy=%s) — fast-closing",
                    event_id,
                    policy.value,
                )
                state["_investigation_skipped"] = True
            else:
                logger.warning(
                    "SuperAgent: triage says no investigation needed for event=%s "
                    "but disposition_policy=%s — cannot fast-close; "
                    "keeping on main pipeline",
                    event_id,
                    policy.value,
                )

        await self._check_convergence_stop(event_id, "triage_agent")

        state["event_context"] = ec
        return state

    async def _close_node(self, state: dict[str, Any]) -> dict[str, Any]:
        """Fast-close path: report then CLOSED when no investigation is needed."""
        ec: EventContext = state["event_context"]
        event_id = _event_id_from_context(ec)

        triage_data = ec.triage_result
        triage = (
            TriageResult.model_validate(triage_data)
            if triage_data is not None
            else TriageResult(
                event_type="other",  # type: ignore[arg-type]
                severity="low",  # type: ignore[arg-type]
                need_investigation=False,
                reasoning="triage unavailable",
                degraded=True,
            )
        )

        placeholder_evidence = EvidenceOutput(
            evidence_list=[],
            conflicts=[],
            gaps=[],
            success_sources=[],
            failed_sources=[],
            overall_confidence=0.0,
            collection_status=CollectionStatus.COMPLETED,
        )
        placeholder_risk = RiskAssessment(
            risk_score=0,
            severity=triage.severity,
            confidence=0.9,
            risk_factors=[],
            possible_false_positive=True,
            scoring_mode=ScoringMode.RULE_ONLY,
        )
        report_input = ReportAgentInput(
            event_id=event_id,
            evidence_output=placeholder_evidence,
            risk_assessment=placeholder_risk,
        )
        report: InvestigationReport | None = await self.report_agent.execute(report_input)  # type: ignore[union-attr]
        if report is not None:
            if not isinstance(report, InvestigationReport):
                raise TypeError("ReportAgent must return InvestigationReport or None")
            ec.report = report
            if not report.report_id:
                report.report_id = report_id_for_event(event_id)

        await self._transition(
            event_id,
            EventStatus.CLOSED,
            reason="super_agent:short_circuit_closed",
            ec=ec,
            context=TransitionContext(
                need_investigation=False,
                recommendation="close_as_fp",
            ),
        )
        state["super_agent_status"] = SuperAgentStatus.FINISHED
        state["event_context"] = ec
        logger.info(
            "SuperAgent: fast-close for event=%s (need_investigation=false)",
            event_id,
        )
        return state

    async def _planner_node(self, state: dict[str, Any]) -> dict[str, Any]:
        """Generate execution plan via PlannerAgent.

        Does **not** advance ``EventStatus`` — that is the responsibility of
        each plan-step executor (evidence → COLLECTING_EVIDENCE → ANALYZING,
        risk → SCORING, report → REPORTING).

        Skipped when triage determined no investigation is needed.
        """
        if state.get("_investigation_skipped"):
            return state

        ec: EventContext = state["event_context"]
        event_id = _event_id_from_context(ec)

        await self._record_agent_step(event_id, "planner_agent")

        plan: ExecutionPlan = await planner_node(ec, self.planner_agent)  # type: ignore[arg-type]
        ec.execution_plan = plan.model_dump(mode="json")

        await self._check_convergence_stop(event_id, "planner_agent")

        state["event_context"] = ec
        return state

    async def _execute_plan_steps_node(self, state: dict[str, Any]) -> dict[str, Any]:
        """Walk through ``ExecutionPlan.steps`` and execute each one in order."""
        ec: EventContext = state["event_context"]
        event_id = _event_id_from_context(ec)

        # When triage determines no investigation is needed, skip all plan steps.
        if state.get("_investigation_skipped"):
            logger.info(
                "SuperAgent: investigation skipped for event=%s (need_investigation=false)",
                event_id,
            )
            state["event_context"] = ec
            return state

        plan_data = ec.execution_plan
        if plan_data is None:
            logger.warning("SuperAgent: no execution plan found for event=%s", event_id)
            state["event_context"] = ec
            return state

        plan = ExecutionPlan.model_validate(plan_data)

        evidence_executed = False
        for step in plan.steps:
            if step.assigned_agent in _DEFERRED_PLAN_AGENTS:
                continue
            if step.assigned_agent == "evidence_agent":
                if evidence_executed:
                    continue
                evidence_executed = True
            await self._execute_single_step(ec, step)

        state["event_context"] = ec
        return state

    async def _report_node(self, state: dict[str, Any]) -> dict[str, Any]:
        """Generate investigation report via ReportAgent.

        Defence-in-depth: when the investigation was skipped by triage AND
        the graph somehow reached this node (e.g. future conditional-edge
        reconfiguration), produce a minimal report rather than crashing on
        missing evidence / risk data.
        """
        if state.get("_investigation_skipped"):
            logger.info(
                "SuperAgent: _report_node reached with _investigation_skipped "
                "set — generating minimal report"
            )

        ec: EventContext = state["event_context"]
        event_id = _event_id_from_context(ec)

        current_status = _current_status_from_context(ec)
        if current_status not in (EventStatus.REPORTING, EventStatus.CLOSED, EventStatus.FAILED):
            await self._transition(event_id, EventStatus.REPORTING, ec=ec)
        await self._record_agent_step(event_id, "report_agent")

        evidence_data = ec.evidence_output
        evidence_output = (
            EvidenceOutput.model_validate(evidence_data)
            if evidence_data is not None
            else EvidenceOutput(
                evidence_list=[],
                conflicts=[],
                gaps=[],
                success_sources=[],
                failed_sources=[],
                overall_confidence=0.0,
                collection_status="degraded",  # type: ignore[arg-type]
            )
        )

        risk_data = ec.risk_assessment
        risk_assessment = (
            RiskAssessment.model_validate(risk_data)
            if risk_data is not None
            else RiskAssessment(
                risk_score=0,
                severity="low",  # type: ignore[arg-type]
                confidence=0.0,
                scoring_mode="rule_only",  # type: ignore[arg-type]
            )
        )

        report_input = ReportAgentInput(
            event_id=event_id,
            evidence_output=evidence_output,
            risk_assessment=risk_assessment,
        )

        report: InvestigationReport | None = await self.report_agent.execute(report_input)  # type: ignore[union-attr]
        if report is not None:
            if not isinstance(report, InvestigationReport):
                raise TypeError("ReportAgent must return InvestigationReport or None")
            ec.report = report
            if not report.report_id:
                report.report_id = report_id_for_event(event_id)

        # P1 post-hook: generate storyline for frontend timeline consumption.
        # Per ISSUE-051, StorylineService runs after report_node so the
        # ReportAgent attack_storyline chapter always uses evidence-timeline
        # fallback; the generated storyline is for the frontend timeline tab.
        await self._run_storyline_step(ec)

        await self._check_convergence_stop(event_id, "report_agent")

        policy = _disposition_policy_from_context(ec)
        if ec.event is not None and policy == DispositionPolicy.NOT_REQUIRED:
            triage_data = ec.triage_result
            need_inv: bool | None = None
            if triage_data is not None:
                need_inv = TriageResult.model_validate(triage_data).need_investigation
            await self._transition(
                event_id,
                EventStatus.CLOSED,
                reason="super_agent:complete_not_required",
                ec=ec,
                context=TransitionContext(need_investigation=need_inv),
            )

        state["event_context"] = ec
        state["super_agent_status"] = SuperAgentStatus.FINISHED
        return state

    # ------------------------------------------------------------------ #
    # Plan-step dispatch
    # ------------------------------------------------------------------ #

    async def _execute_single_step(self, ec: EventContext, step: PlanStep) -> None:
        """Dispatch a single PlanStep to the assigned agent.

        ConvergenceGuard integration (ISSUE-052): each agent step records a
        ``"agent_retry"`` step and checks ``should_stop`` afterwards.
        """
        event_id = _event_id_from_context(ec)
        agent_name = step.assigned_agent
        logger.info(
            "SuperAgent: executing step %d agent=%s for event=%s",
            step.step_order,
            agent_name,
            event_id,
        )

        await self._record_agent_step(event_id, agent_name)

        match agent_name:
            case "evidence_agent":
                await self._run_evidence_step(ec, step)
            case "rag_agent":
                await self._run_rag_step(ec)
            case "risk_agent":
                await self._run_risk_step(ec)
            case "report_agent":
                pass  # handled by dedicated report_node
            case "graph_agent":
                await self._run_graph_step(ec, step)
            case "storyline_service":
                await self._run_storyline_step(ec)
            case "react":
                await self._run_react_step(ec, step)
            case _:
                logger.warning(
                    "SuperAgent: unknown agent %r in plan step %d for event=%s",
                    agent_name,
                    step.step_order,
                    event_id,
                )

        await self._check_convergence_stop(event_id, agent_name)

    async def _run_evidence_step(self, ec: EventContext, step: PlanStep) -> None:
        event_id = _event_id_from_context(ec)
        # Transition to COLLECTING_EVIDENCE only once (first evidence step in plan).
        current_status = _current_status_from_context(ec)
        if current_status in (EventStatus.NEW, EventStatus.TRIAGING):
            await self._transition(event_id, EventStatus.COLLECTING_EVIDENCE, ec=ec)

        triage_data = ec.triage_result
        triage = (
            TriageResult.model_validate(triage_data)
            if triage_data is not None
            else TriageResult(
                event_type="other",  # type: ignore[arg-type]
                severity="medium",  # type: ignore[arg-type]
                need_investigation=True,
                reasoning="triage unavailable",
                degraded=True,
            )
        )

        evidence_input = EvidenceAgentInput(
            event_id=event_id,
            triage_result=triage,
            plan_step_goal=step.step_goal,
            required_tools=step.required_tools,
        )
        evidence_output = await self.evidence_agent.execute(evidence_input)  # type: ignore[union-attr]
        if not isinstance(evidence_output, EvidenceOutput):
            raise TypeError("EvidenceAgent must return EvidenceOutput")
        ec.evidence_output = evidence_output.model_dump(mode="json")
        current_status = _current_status_from_context(ec)
        if current_status not in (
            EventStatus.ANALYZING,
            EventStatus.SCORING,
            EventStatus.REPORTING,
            EventStatus.CLOSED,
            EventStatus.FAILED,
        ):
            await self._transition(event_id, EventStatus.ANALYZING, ec=ec)

    async def _run_rag_step(self, ec: EventContext) -> None:
        """RAG enhancement — failure is non-blocking (降级策略)."""
        if self.rag_agent is None:
            return
        event_id = _event_id_from_context(ec)
        triage_data = ec.triage_result
        evidence_data = ec.evidence_output
        if triage_data is None or evidence_data is None:
            logger.warning(
                "SuperAgent: skipping RAG for event=%s — missing triage or evidence",
                event_id,
            )
            return
        try:
            triage = TriageResult.model_validate(triage_data)
            evidence = EvidenceOutput.model_validate(evidence_data)
            rag_out: RAGOutput | None = await rag_node(
                ec,
                self.rag_agent,
                triage_result=triage,
                evidence_output=evidence,
            )
            if rag_out is not None:
                ec.rag_output = rag_out.model_dump(mode="json")
        except Exception:
            logger.warning(
                "SuperAgent: RAG failed for event=%s — continuing without RAG",
                event_id,
                exc_info=True,
            )

    async def _run_risk_step(self, ec: EventContext) -> None:
        event_id = _event_id_from_context(ec)
        current_status = _current_status_from_context(ec)
        if current_status not in (
            EventStatus.SCORING,
            EventStatus.REPORTING,
            EventStatus.CLOSED,
            EventStatus.FAILED,
        ):
            await self._transition(event_id, EventStatus.SCORING, ec=ec)

        triage_data = ec.triage_result
        evidence_data = ec.evidence_output
        rag_data = ec.rag_output
        graph_data = ec.graph_output

        triage = (
            TriageResult.model_validate(triage_data)
            if triage_data is not None
            else TriageResult(
                event_type="other",  # type: ignore[arg-type]
                severity="medium",  # type: ignore[arg-type]
                need_investigation=True,
                reasoning="triage unavailable",
                degraded=True,
            )
        )
        evidence = (
            EvidenceOutput.model_validate(evidence_data)
            if evidence_data is not None
            else EvidenceOutput(
                evidence_list=[],
                conflicts=[],
                gaps=[],
                success_sources=[],
                failed_sources=[],
                overall_confidence=0.0,
                collection_status="degraded",  # type: ignore[arg-type]
            )
        )
        rag = RAGOutput.model_validate(rag_data) if rag_data is not None else None
        graph = GraphOutput.model_validate(graph_data) if graph_data is not None else None

        risk_input = RiskAgentInput(
            event_id=event_id,
            triage_result=triage,
            evidence_output=evidence,
            rag_output=rag,
            graph_output=graph,
        )
        risk_assessment: RiskAssessment = await self.risk_agent.execute(risk_input)  # type: ignore[union-attr]
        if not isinstance(risk_assessment, RiskAssessment):
            raise TypeError("RiskAgent must return RiskAssessment")
        ec.risk_assessment = risk_assessment.model_dump(mode="json")

    async def _run_graph_step(self, ec: EventContext, step: PlanStep) -> None:
        """Optional GraphAgent step (P1 capability switch)."""
        if self.graph_agent is None:
            return
        event_id = _event_id_from_context(ec)
        evidence_data = ec.evidence_output
        if evidence_data is None:
            return
        try:
            from app.models.agent_io import GraphAgentInput

            evidence = EvidenceOutput.model_validate(evidence_data)
            graph_input = GraphAgentInput(
                event_id=event_id,
                evidence_output=evidence,
            )
            graph_output = await self.graph_agent.execute(graph_input)
            if graph_output is not None:
                ec.graph_output = (
                    graph_output.model_dump(mode="json")
                    if hasattr(graph_output, "model_dump")
                    else graph_output
                )
        except Exception:
            logger.warning(
                "SuperAgent: GraphAgent failed for event=%s — continuing",
                event_id,
                exc_info=True,
            )

    async def _run_storyline_step(self, ec: EventContext) -> None:
        """Optional StorylineService step (P1 capability switch).

        Calls ``StorylineService.generate`` which persists the result via
        WorkingMemory (writer identity fixed as ``StorylineService`` per
        ISSUE-051) AND returns the ``AttackStoryline``.  We write it to
        ``ec.storyline`` so the in-memory EventContext stays in sync with
        the persistence layer.  Failure is non-blocking (降级策略).

        Idempotent: skips when ``ec.storyline`` is already populated so
        the post-report hook and any explicit plan step never duplicate work.
        """
        if self.storyline_service is None:
            return
        if ec.storyline is not None:
            return  # already generated (by post-hook or prior plan step)
        event_id = _event_id_from_context(ec)
        try:
            storyline = await self.storyline_service.generate(ec.model_dump(mode="json"))
            if storyline is not None:
                # Persist to in-memory EventContext so downstream consumers
                # (persist, frontend polling) see the latest storyline.
                ec.storyline = (
                    storyline.model_dump(mode="json")
                    if hasattr(storyline, "model_dump")
                    else storyline
                )
        except Exception:
            logger.warning(
                "SuperAgent: StorylineService failed for event=%s — continuing",
                event_id,
                exc_info=True,
            )

    async def _run_react_step(self, ec: EventContext, step: PlanStep) -> None:
        """Optional ReAct iteration step (P1 capability switch, ISSUE-053).

        Only active when ``react_enabled`` is ``True`` AND a
        ``ReadOnlyReActExecutor`` has been injected.  The plan-step goal
        becomes the ReAct goal.

        In ISSUE-054 scope the concrete ReAct loop wiring is a hook point;
        ISSUE-053/ISSUE-055 deliver the full observe→think→act→reflect loop.
        """
        if not self.react_enabled or self.react_executor is None:
            return
        event_id = _event_id_from_context(ec)
        # _record_agent_step is called by _execute_single_step before
        # dispatching here — do NOT double-count.
        logger.info(
            "SuperAgent: ReAct step for event=%s goal=%r "
            "(ISSUE-053 executor wiring deferred to ISSUE-055)",
            event_id,
            step.step_goal,
        )
        # ISSUE-053/ISSUE-055: replace with ReActEngine.run(goal=step.step_goal, ...)
        # The executor is a ReadOnlyReActExecutor that requires per-event
        # init params (tool_executor, event_id); the factory in events.py
        # guards against REACT_ENABLED=true without a valid executor.

    # ------------------------------------------------------------------ #
    # ConvergenceGuard helpers (ISSUE-052)
    # ------------------------------------------------------------------ #

    async def _record_agent_step(self, event_id: str, agent_name: str) -> None:
        """Record an agent step with the ConvergenceGuard, if configured."""
        if self.convergence_guard is None:
            return
        try:
            await self.convergence_guard.record_step(
                event_id,
                "agent_retry",
                tool_name=agent_name,
            )
        except Exception:
            logger.debug(
                "SuperAgent: convergence_guard.record_step failed for event=%s agent=%s",
                event_id,
                agent_name,
                exc_info=True,
            )

    def _reset_convergence_guard(self, event_id: str) -> None:
        """Release convergence counters for *event_id* to prevent memory leaks.

        Per ISSUE-052: the orchestrator MUST reset when an event reaches a
        terminal status (CLOSED or FAILED).  Without this the in-process
        ``_states`` dict grows unboundedly in long-running processes.
        """
        if self.convergence_guard is not None:
            try:
                self.convergence_guard.reset(event_id)
            except Exception:
                logger.debug(
                    "SuperAgent: convergence_guard.reset failed for event=%s",
                    event_id,
                    exc_info=True,
                )

    async def _check_convergence_stop(self, event_id: str, agent_name: str) -> None:
        """Check whether ConvergenceGuard demands a stop.  Raises on stop."""
        if self.convergence_guard is None:
            return
        try:
            decision = await self.convergence_guard.should_stop(event_id)
            if decision:
                logger.warning(
                    "SuperAgent: ConvergenceGuard stop agent=%s event=%s reason=%s",
                    agent_name,
                    event_id,
                    decision.reason.value,
                )
                # Map stop reason → appropriate error_code so callers can
                # distinguish budget caps (global_max_steps, max_llm_calls)
                # from guardrail triggers (oscillation, duplicate_tool_calls).
                _REASON_ERROR_CODE: dict[str, str] = {
                    "global_max_steps": "budget_exceeded",
                    "max_llm_calls": "budget_exceeded",
                    "oscillation": "guardrail_failed",
                    "duplicate_tool_calls": "guardrail_failed",
                }
                error_code = _REASON_ERROR_CODE.get(decision.reason.value, "budget_exceeded")

                raise ShadowTraceError(
                    message=f"ConvergenceGuard stop: {decision.reason.value}",
                    error_code=error_code,
                    details={
                        "event_id": event_id,
                        "stop_reason": decision.reason.value,
                        "stop_detail": decision.detail,
                    },
                )
        except ShadowTraceError:
            raise
        except Exception:
            logger.debug(
                "SuperAgent: convergence_guard.should_stop failed for event=%s",
                event_id,
                exc_info=True,
            )

    # ------------------------------------------------------------------ #
    # State machine helpers
    # ------------------------------------------------------------------ #

    async def _transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        reason: str | None = None,
        ec: EventContext | None = None,
        context: TransitionContext | None = None,
    ) -> None:
        if self.event_service is None:
            return
        transition = getattr(self.event_service, "transition_status", None)
        if transition is None:
            return
        try:
            transition_kwargs: dict[str, Any] = {
                "operator": _SUPER_AGENT_OPERATOR,
                "reason": reason or f"super_agent:{target.value}",
            }
            if context is not None:
                transition_kwargs["context"] = context
            await transition(event_id, target, **transition_kwargs)
            # Refresh the in-memory status so subsequent _current_status_from_context
            # checks see the latest state.
            if self.event_service is not None and ec is not None and ec.event is not None:
                try:
                    event = await self.event_service.get_event(event_id)
                    if event is not None and hasattr(event, "status"):
                        ec.event.status = event.status
                except Exception:
                    logger.debug(
                        "SuperAgent: failed to refresh event status for event=%s",
                        event_id,
                        exc_info=True,
                    )
        except Exception as exc:
            from app.core.errors import InvalidStateTransitionError

            # Invalid-state transitions are logic bugs — they must surface.
            if isinstance(exc, InvalidStateTransitionError):
                logger.error(
                    "SuperAgent: illegal state transition for event=%s → %s",
                    event_id,
                    target.value,
                    exc_info=True,
                )
                raise
            # Transient failures (DB, network) are logged but not re-raised
            # because the graph may still complete its analysis nodes.
            # Accumulate per-event_id so concurrent investigations on the
            # same SuperAgent singleton never mix up failures.
            self._transition_failures.setdefault(event_id, []).append(
                {
                    "event_id": event_id,
                    "target": target.value,
                    "error": str(exc),
                }
            )
            logger.warning(
                "SuperAgent: transition to %s failed for event=%s (%d total)",
                target.value,
                event_id,
                len(self._transition_failures.get(event_id, [])),
                exc_info=True,
            )

    async def _load_event_context(self, event_id: str) -> EventContext:
        """Load or create an EventContext for the given event.

        Uses ``EventContextStore.get_full_context`` when available, falling
        back to an empty ``EventContext`` for test / degraded paths.
        """
        if self.context_store is not None:
            try:
                get_full = getattr(self.context_store, "get_full_context", None)
                if get_full is not None:
                    ec = await get_full(event_id)
                    if ec is not None:
                        return ec
            except Exception:
                logger.debug(
                    "SuperAgent: failed to load EventContext for event=%s",
                    event_id,
                    exc_info=True,
                )
        # Fallback: build a minimal context through the event service
        if self.event_service is not None:
            try:
                get_event = getattr(self.event_service, "get_event", None)
                if get_event is not None:
                    event = await get_event(event_id)
                    if event is not None:
                        ec = EventContext()
                        ec.event = _event_summary_from_record(event_id, event)
                        return ec
            except Exception:
                logger.debug(
                    "SuperAgent: failed to load event for context, event=%s",
                    event_id,
                    exc_info=True,
                )
        # Last-resort fallback: minimal EventContext with synthetic EventSummary
        ec = EventContext()
        ec.event = EventSummary(
            event_id=event_id,
            event_type=EventType.OTHER,
            title=f"Investigation {event_id}",
            status=EventStatus.NEW,
            severity=Severity.MEDIUM,
            risk_score=0,
            final_verdict=FinalVerdict.NONE,
            writeback_required=True,
            writeback_readiness=WritebackReadiness.CAPABILITY_UNKNOWN,
            disposition_policy=DispositionPolicy.REQUIRED,
        )
        return ec

    async def _freeze_source_snapshot(self, ec: EventContext) -> None:
        """Capture the current source state as an immutable snapshot.

        In ISSUE-054 scope this is a best-effort placeholder; the full
        snapshot freeze lands with SourceIngester integration (ISSUE-017).
        """
        if ec.source_snapshot is None and ec.event is not None:
            ec.source_snapshot = {"frozen_at_event_id": ec.event.event_id}

    async def _persist_event_context(self, ec: EventContext) -> None:
        """Persist the final EventContext state after graph completion.

        Writes back to the context store when available so that downstream
        consumers (API response status, frontend polling, ReportAgent
        fallback) see the latest field values.
        """
        if self.context_store is None:
            return
        event_id = _event_id_from_context(ec)
        try:
            set_ctx = getattr(self.context_store, "set_full_context", None)
            if set_ctx is not None:
                await set_ctx(event_id, ec)
        except Exception:
            logger.debug(
                "SuperAgent: failed to persist EventContext for event=%s",
                event_id,
                exc_info=True,
            )

    async def _build_triage_input(self, event_id: str, ec: EventContext) -> TriageAgentInput:
        """Build triage input aligned with ``AnalysisOnlyPipeline._run_triage``."""
        raw_summary = _build_raw_summary(ec)
        hint_entities = EntitySet()
        if self.event_service is not None:
            try:
                event = await self.event_service.get_event(event_id)
            except Exception:
                event = None
            if event is not None:
                if isinstance(event, dict):
                    title = str(event.get("title") or (ec.event.title if ec.event else event_id))
                    description = str(event.get("description") or "")
                    raw_summary = f"{title}. {description}".strip(". ")
                else:
                    description = str(getattr(event, "description", "") or "").strip()
                    raw_summary = f"{event.title}. {description}".strip(". ")
                    entities = getattr(event, "entities", None)
                    if entities is not None:
                        hint_entities = entities
        return TriageAgentInput(
            event_id=event_id,
            raw_event_summary=raw_summary,
            hint_entities=hint_entities,
        )

    async def _persist_analysis_only_complete(self, event_id: str) -> None:
        if self.context_store is None:
            return
        try:
            await self.context_store.set(event_id, "analysis_only_complete", True)
        except Exception:
            logger.warning(
                "SuperAgent: failed to persist analysis_only_complete for event=%s",
                event_id,
                exc_info=True,
            )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _coerce_disposition_policy(value: object) -> DispositionPolicy:
    if isinstance(value, DispositionPolicy):
        return value
    if value is None:
        return DispositionPolicy.REQUIRED
    return DispositionPolicy(str(value))


def _event_summary_from_record(event_id: str, event: Any) -> EventSummary:
    """Build ``EventSummary`` from an ORM row or test dict."""
    if isinstance(event, dict):
        policy = _coerce_disposition_policy(event.get("disposition_policy"))
        writeback_required = policy is DispositionPolicy.REQUIRED
        status_raw = event.get("status", EventStatus.NEW)
        status = status_raw if isinstance(status_raw, EventStatus) else EventStatus(str(status_raw))
        type_raw = event.get("event_type", EventType.OTHER)
        event_type = type_raw if isinstance(type_raw, EventType) else EventType(str(type_raw))
        sev_raw = event.get("severity", Severity.MEDIUM)
        severity = sev_raw if isinstance(sev_raw, Severity) else Severity(str(sev_raw))
        verdict_raw = event.get("final_verdict", FinalVerdict.NONE)
        final_verdict = (
            verdict_raw if isinstance(verdict_raw, FinalVerdict) else FinalVerdict(str(verdict_raw))
        )
        return EventSummary(
            event_id=event_id,
            event_type=event_type,
            title=str(event.get("title") or event_id),
            status=status,
            severity=severity,
            risk_score=int(event.get("risk_score") or 0),
            final_verdict=final_verdict,
            writeback_required=writeback_required,
            writeback_readiness=(
                WritebackReadiness.NOT_REQUIRED
                if not writeback_required
                else WritebackReadiness.CAPABILITY_UNKNOWN
            ),
            disposition_policy=policy,
        )

    from app.services.context_service import event_summary_from_security_event

    return event_summary_from_security_event(event)


def _event_id_from_context(ec: EventContext) -> str:
    if ec.event is not None:
        return ec.event.event_id
    return "unknown"


def _current_status_from_context(ec: EventContext) -> EventStatus | None:
    """Infer the current ``EventStatus`` from the context, if available."""
    if ec.event is not None:
        return ec.event.status
    return None


def _build_raw_summary(ec: EventContext) -> str:
    """Build a textual summary of the event for TriageAgent input."""
    if ec.event is not None:
        parts = [
            f"title={ec.event.title}",
            f"type={ec.event.event_type.value}",
            f"severity={ec.event.severity.value}",
        ]
        return " | ".join(parts)
    return ""


def _disposition_policy_from_context(ec: EventContext) -> DispositionPolicy:
    """Extract the disposition policy from the EventContext.

    Returns ``NOT_REQUIRED`` as a safe default when the event summary is
    unavailable (e.g. degraded fallback path).
    """
    if ec.event is not None:
        return ec.event.disposition_policy
    return DispositionPolicy.NOT_REQUIRED


def _route_after_triage(state: dict[str, Any]) -> bool:
    """Conditional routing predicate for ``_build_graph``.

    Returns ``True`` when the event should fast-close (``close_node``),
    ``False`` to proceed with the full analysis pipeline (``planner``).

    The ``_investigation_skipped`` flag is only set by ``_triage_node``
    after verifying that **both** ``need_investigation=false`` AND
    ``disposition_policy=not_required`` per ISSUE-048 routing rules.
    """
    return bool(state.get("_investigation_skipped", False))


__all__ = ["SuperAgent"]
