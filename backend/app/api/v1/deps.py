"""FastAPI dependency injection for services (ISSUE-038 / ISSUE-058).

Lazily creates singleton service instances from settings. Tests override
via ``app.dependency_overrides``.

IMPORTANT: All service imports are lazy (inside function bodies) to avoid
circular imports with ``app.api.v1.schemas`` → ``app.services.context_service``.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.core.redis_client import RedisClient

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Lazy singletons
# --------------------------------------------------------------------------- #

_session_factory: async_sessionmaker[AsyncSession] | None = None
_redis_client: RedisClient | None = None
_context_store: Any = None  # EventContextStore
_degraded_flags: Any = None  # DegradedFlagService
_audit_log: Any = None  # EventAuditLogService
_event_service: Any = None  # EventService
_state_machine: Any = None  # StateMachineService
_event_bus: Any = None  # EventBus
_pipeline: Any = None  # AnalysisOnlyPipeline
_super_agent: Any = None  # SuperAgent
_event_lease: Any = None  # EventLease
_investigation_stack: dict[str, Any] | None = None
_approval_engine: Any = None  # ApprovalEngine
_impact_assessment_service: Any = None  # ImpactAssessmentService
_disposition_sync: Any = None  # DispositionSyncService
_action_execution: Any = None  # ActionExecutionService
_rollback_service: Any = None  # RollbackService
_adapter_registry: Any = None  # DispositionAdapterRegistry
_workflow_runtime: Any = None  # WorkflowRuntimeService
_event_disposition: Any = None  # EventDispositionService
_graph_sync_service: Any = None  # GraphSyncService (ISSUE-082)
_neo4j_client: Any = None  # Neo4jClient (ISSUE-082)


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        settings = get_settings()
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        _session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    return _session_factory


def _get_redis() -> RedisClient:
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = RedisClient(url=settings.redis_url)
    return _redis_client


def _get_context_store() -> Any:
    global _context_store
    if _context_store is None:
        from app.services.context_service import EventContextStore

        _context_store = EventContextStore(_get_redis(), _get_session_factory())
    return _context_store


def _get_degraded_flags() -> Any:
    global _degraded_flags
    if _degraded_flags is None:
        from app.services.degraded_flag_service import DegradedFlagService

        _degraded_flags = DegradedFlagService(_get_context_store(), _get_session_factory())
    return _degraded_flags


def _get_audit_log() -> Any:
    global _audit_log
    if _audit_log is None:
        from app.services.event_audit_log_service import EventAuditLogService

        _audit_log = EventAuditLogService(_get_session_factory())
    return _audit_log


def _get_event_bus() -> Any:
    global _event_bus
    if _event_bus is None:
        from app.core.event_bus import EventBus

        _event_bus = EventBus(_get_redis())
    return _event_bus


async def get_event_service() -> Any:
    global _event_service
    if _event_service is None:
        from app.services.event_service import EventService

        state_machine = await get_state_machine()
        _event_service = EventService(
            _get_session_factory(),
            _get_context_store(),
            degraded_flags=_get_degraded_flags(),
            state_machine=state_machine,
            event_bus=_get_event_bus(),
        )
    return _event_service


async def get_state_machine() -> Any:
    global _state_machine
    if _state_machine is None:
        from app.services.state_machine_service import StateMachineService

        _state_machine = StateMachineService(
            _get_session_factory(),
            _get_context_store(),
            audit_log=_get_audit_log(),
            degraded_flags=_get_degraded_flags(),
        )
    return _state_machine


def _get_impact_assessment_service() -> Any:
    """Return the ImpactAssessmentService singleton (ISSUE-079)."""
    global _impact_assessment_service
    if _impact_assessment_service is None:
        from app.services.impact_assessment_service import (
            ImpactAssessmentService,
            create_default_asset_provider,
        )

        _impact_assessment_service = ImpactAssessmentService(
            asset_info_provider=create_default_asset_provider(),
        )
    return _impact_assessment_service


async def get_approval_engine() -> Any:
    """Return the tiered approval engine singleton (ISSUE-058)."""
    global _approval_engine
    if _approval_engine is None:
        from app.services.approval_engine import ApprovalEngine

        state_machine = await get_state_machine()
        _approval_engine = ApprovalEngine(
            _get_session_factory(),
            event_bus=_get_event_bus(),
            state_machine=state_machine,
            context_store=_get_context_store(),
            resume_investigation=_resume_investigation,
            impact_assessment_service=_get_impact_assessment_service(),
        )
    return _approval_engine


ApprovalEngineDep = Annotated[Any, Depends(get_approval_engine)]


def _get_adapter_registry() -> Any:
    global _adapter_registry
    if _adapter_registry is None:
        from app.adapters.mock_xdr import MockXDRDispositionAdapter
        from app.adapters.registry import DispositionAdapterRegistry

        settings = get_settings()
        registry = DispositionAdapterRegistry()
        base_url = settings.disposition_base_url or "http://mock-xdr"
        adapter = MockXDRDispositionAdapter(
            base_url=base_url,
            read_token="mock-read-token",
            write_token="mock-write-token",
        )
        registry.register("mock_xdr", adapter)
        _adapter_registry = registry
    return _adapter_registry


async def _get_workflow_runtime() -> Any:
    global _workflow_runtime
    if _workflow_runtime is None:
        from app.orchestration.workflow_runtime import WorkflowRuntimeService

        _workflow_runtime = WorkflowRuntimeService(
            _get_session_factory(),
            event_service=await get_event_service(),
        )
    return _workflow_runtime


async def _resume_investigation(event_id: str) -> None:
    """Resume graph orchestration after terminal writeback (ISSUE-059 P0 hook)."""
    settings = get_settings()
    mode = (settings.orchestration_mode or "graph").strip().lower()
    if mode != "graph":
        return
    try:
        agent = await get_super_agent()
        await agent.investigate(event_id)
    except Exception:
        logger.exception("resume_investigation failed event=%s", event_id)


async def get_disposition_sync() -> Any:
    global _disposition_sync
    if _disposition_sync is None:
        from app.core.guardrails import OutboundDispositionGuard
        from app.services.disposition_sync_service import DispositionSyncService

        _disposition_sync = DispositionSyncService(
            _get_session_factory(),
            context_store=_get_context_store(),
            adapter_registry=_get_adapter_registry(),
            outbound_guard=OutboundDispositionGuard(),
            event_bus=_get_event_bus(),
            resume_investigation=_resume_investigation,
        )
    return _disposition_sync


async def get_event_disposition_service() -> Any:
    """Return EventDispositionService for phase-2 terminal writeback activation."""
    global _event_disposition
    if _event_disposition is None:
        from app.services.event_disposition_service import EventDispositionService

        _event_disposition = EventDispositionService(
            _get_session_factory(),
            disposition_sync=await get_disposition_sync(),
            context_store=_get_context_store(),
            event_bus=_get_event_bus(),
        )
    return _event_disposition


async def _build_production_investigation_graph(
    *,
    planner_agent: Any,
    convergence_guard: Any,
) -> Any:
    """Wire ISSUE-048/062 LangGraph for production SuperAgent orchestration."""
    from app.agents.response_agent import ResponseAgent
    from app.agents.verify_agent import VerifyAgent
    from app.orchestration.checkpointer import build_checkpointer
    from app.orchestration.workflow_graph import build_investigation_graph

    stack = await _get_investigation_stack()
    wm = stack["wm"]
    event_bus = _get_event_bus()
    response_agent = ResponseAgent(
        llm_client=stack["llm_client"],
        working_memory=wm.for_writer("ResponseAgent"),
        budget_service=stack["budget_service"],
        output_guard=stack["output_guard"],
        trace_service=stack["trace_service"],
        event_bus=event_bus,
        event_service=stack["event_service"],
        session_factory=stack["session_factory"],
        scenario_id="insider_data_exfiltration",
    )
    verify_agent = VerifyAgent(
        tool_executor=stack["tool_executor"],
        working_memory=wm.for_writer("VerifyAgent"),
        trace_service=stack["trace_service"],
        event_bus=event_bus,
        session_factory=stack["session_factory"],
        event_disposition_service=await get_event_disposition_service(),
        disposition_sync_service=await get_disposition_sync(),
    )
    agents = {
        "triage_agent": stack["triage"],
        "planner_agent": planner_agent,
        "evidence_agent": stack["evidence"],
        "risk_agent": stack["risk"],
        "report_agent": stack["report"],
        "response_agent": response_agent,
        "verify_agent": verify_agent,
        "rag_agent": stack["rag"],
    }
    services = {
        "state_machine": stack["state_machine"],
        "event_service": stack["event_service"],
        "workflow_runtime": await _get_workflow_runtime(),
        "degraded_flags": stack["degraded_flags"],
        "context_store": stack["context_store"],
        "approval_engine": await get_approval_engine(),
        "action_execution": await get_action_execution(),
        "disposition_sync": await get_disposition_sync(),
        "event_disposition": await get_event_disposition_service(),
        "convergence_guard": convergence_guard,
    }
    checkpointer = await build_checkpointer(_get_redis())
    return build_investigation_graph(agents, services, checkpointer=checkpointer)


async def get_action_execution() -> Any:
    global _action_execution
    if _action_execution is None:
        from app.services.action_execution_service import ActionExecutionService

        stack = await _get_investigation_stack()
        _action_execution = ActionExecutionService(
            _get_session_factory(),
            disposition_sync=await get_disposition_sync(),
            tool_executor=stack["tool_executor"],
            state_machine=stack["state_machine"],
            context_store=_get_context_store(),
            event_bus=_get_event_bus(),
            workflow_runtime=await _get_workflow_runtime(),
        )
    return _action_execution


async def get_rollback_service() -> Any:
    global _rollback_service
    if _rollback_service is None:
        from app.services.event_audit_log_service import EventAuditLogService
        from app.services.rollback_service import RollbackService, build_execute_rollback_hook

        action_execution = await get_action_execution()
        _rollback_service = RollbackService(
            _get_session_factory(),
            audit=EventAuditLogService(_get_session_factory()),
            execute_rollback=build_execute_rollback_hook(action_execution),
            disposition_sync=await get_disposition_sync(),
            event_bus=_get_event_bus(),
            adapter_registry=_get_adapter_registry(),
        )
    return _rollback_service


async def get_graph_sync_service() -> Any:
    """Return GraphSyncService when NEO4J_ENABLED=true; None otherwise.

    ISSUE-082 §实现步骤 point 3: GraphAgent 输出后异步触发 Neo4j 同步。
    Wiring: inject into GraphAgent(graph_sync_service=...) when GraphAgent
    is integrated into the production orchestration stack (ISSUE-050/P1).
    """
    global _graph_sync_service, _neo4j_client
    settings = get_settings()
    if not settings.neo4j_enabled:
        return None
    if _graph_sync_service is None:
        from app.core.neo4j_client import Neo4jClient
        from app.services.graph_sync_service import GraphSyncService

        _neo4j_client = Neo4jClient()
        _graph_sync_service = GraphSyncService(
            _get_session_factory(),
            client=_neo4j_client,
        )
    return _graph_sync_service


DispositionSyncDep = Annotated[Any, Depends(get_disposition_sync)]
ActionExecutionDep = Annotated[Any, Depends(get_action_execution)]
RollbackServiceDep = Annotated[Any, Depends(get_rollback_service)]


async def _get_wm() -> Any:
    """Return a shared WorkingMemory instance."""
    from app.services.working_memory import WorkingMemory

    return WorkingMemory(
        store=_get_context_store(),
        redis=_get_redis(),
        degraded_flags=_get_degraded_flags(),
    )


async def _build_investigation_agents() -> dict[str, Any]:
    """Wire shared P0 agents and services for pipeline / SuperAgent."""
    from app.agents.evidence_agent import EvidenceAgent
    from app.agents.rag_agent import RAGAgent
    from app.agents.report_agent import ReportAgent
    from app.agents.risk_agent import RiskAgent
    from app.agents.triage_agent import TriageAgent
    from app.core.embedding.service import EmbeddingService
    from app.core.guardrails import OutputGuard
    from app.core.llm.factory import get_llm_client
    from app.services.agent_trace_service import AgentTraceService
    from app.services.budget_service import BudgetService
    from app.services.case_kb_service import CaseKBService
    from app.services.false_positive_matcher import FalsePositiveMatcher
    from app.services.knowledge_store import KnowledgeStore
    from app.tools.executor import get_tool_executor

    settings = get_settings()
    event_service = await get_event_service()
    state_machine = await get_state_machine()
    wm = await _get_wm()
    session_factory = _get_session_factory()
    budget_service = BudgetService(redis=_get_redis(), settings=settings)
    output_guard = OutputGuard()
    trace_service = AgentTraceService(session_factory)
    llm_client = get_llm_client(settings=settings, budget_service=budget_service)
    tool_executor = get_tool_executor()
    tool_executor.budget_service = budget_service

    # ISSUE-078: wire FalsePositiveMatcher for vector-based FP pre-filter.
    embed_service = EmbeddingService(settings)
    knowledge_store = KnowledgeStore(session_factory, embed_service)
    case_kb_service = CaseKBService(knowledge_store, session_factory)
    fp_matcher = FalsePositiveMatcher(case_kb_service)

    # ISSUE-075: every stage Agent must receive EventBus so BaseAgent.execute
    # emits schema-valid agent_progress / agent_completed / agent_failed.
    event_bus = _get_event_bus()

    triage = TriageAgent(
        llm_client=llm_client,
        working_memory=wm.for_writer("TriageAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_bus=event_bus,
        fp_matcher=fp_matcher,
    )
    evidence = EvidenceAgent(
        llm_client=llm_client,
        tool_executor=tool_executor,
        working_memory=wm.for_writer("EvidenceAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_bus=event_bus,
        event_service=event_service,
        session_factory=session_factory,
    )
    rag = RAGAgent(
        working_memory=wm.for_writer("RAGAgent"),
        pipeline=None,
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_bus=event_bus,
    )
    risk = RiskAgent(
        llm_client=llm_client,
        working_memory=wm.for_writer("RiskAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_bus=event_bus,
        event_service=event_service,
        scenario_id="insider_data_exfiltration",
    )
    report = ReportAgent(
        llm_client=llm_client,
        working_memory=wm.for_writer("ReportAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_service=event_service,
        event_bus=event_bus,
        scenario_id="insider_data_exfiltration",
    )

    return {
        "settings": settings,
        "event_service": event_service,
        "state_machine": state_machine,
        "wm": wm,
        "session_factory": session_factory,
        "trace_service": trace_service,
        "triage": triage,
        "evidence": evidence,
        "rag": rag,
        "risk": risk,
        "report": report,
        "context_store": _get_context_store(),
        "degraded_flags": _get_degraded_flags(),
        "budget_service": budget_service,
        "output_guard": output_guard,
        "llm_client": llm_client,
        "tool_executor": tool_executor,
    }


async def _get_investigation_stack() -> dict[str, Any]:
    """Return shared agent wiring for pipeline and SuperAgent."""
    global _investigation_stack
    if _investigation_stack is None:
        _investigation_stack = await _build_investigation_agents()
    return _investigation_stack


async def get_pipeline() -> Any:
    """Return AnalysisOnlyPipeline (lazy import)."""
    global _pipeline
    if _pipeline is None:
        from app.services.analysis_only_pipeline import AnalysisOnlyPipeline

        stack = await _get_investigation_stack()
        _pipeline = AnalysisOnlyPipeline(
            event_service=stack["event_service"],
            state_machine=stack["state_machine"],
            triage_agent=stack["triage"],
            evidence_agent=stack["evidence"],
            rag_agent=stack["rag"],
            risk_agent=stack["risk"],
            report_agent=stack["report"],
            context_store=stack["context_store"],
            degraded_flags=stack["degraded_flags"],
            settings=stack["settings"],
        )
    return _pipeline


def get_event_lease() -> Any:
    """Return the shared EventLease singleton (ISSUE-054)."""
    global _event_lease
    if _event_lease is None:
        from app.orchestration.lease import EventLease

        _event_lease = EventLease(_get_redis())
    return _event_lease


async def get_super_agent() -> Any:
    """Return SuperAgent for graph-mode orchestration (ISSUE-054)."""
    global _super_agent
    if _super_agent is None:
        from app.agents.planner_agent import PlannerAgent
        from app.agents.super_agent import SuperAgent
        from app.orchestration.convergence_guard import ConvergenceGuard

        stack = await _get_investigation_stack()
        settings = stack["settings"]
        wm = stack["wm"]

        planner = PlannerAgent(
            llm_client=stack["llm_client"],
            working_memory=wm.for_writer("PlannerAgent"),
            budget_service=stack["budget_service"],
            output_guard=stack["output_guard"],
            trace_service=stack["trace_service"],
            event_bus=_get_event_bus(),
        )
        convergence_guard = ConvergenceGuard(
            working_memory=wm.for_writer("ConvergenceGuard"),
        )
        investigation_graph = await _build_production_investigation_graph(
            planner_agent=planner,
            convergence_guard=convergence_guard,
        )

        _super_agent = SuperAgent(
            triage_agent=stack["triage"],
            evidence_agent=stack["evidence"],
            planner_agent=planner,
            rag_agent=stack["rag"],
            risk_agent=stack["risk"],
            report_agent=stack["report"],
            event_service=stack["event_service"],
            context_store=stack["context_store"],
            lease=get_event_lease(),
            convergence_guard=convergence_guard,
            event_bus=_get_event_bus(),
            trace_service=stack["trace_service"],
            react_enabled=settings.react_enabled,
            investigation_graph=investigation_graph,
        )
    return _super_agent


def reset_deps() -> None:
    """Reset all lazy singletons (for tests)."""
    global _session_factory, _redis_client, _context_store, _degraded_flags
    global _audit_log, _event_service, _state_machine, _event_bus, _pipeline, _approval_engine
    global _super_agent, _event_lease, _investigation_stack
    global _disposition_sync, _action_execution, _rollback_service
    global _adapter_registry, _workflow_runtime, _event_disposition
    global _impact_assessment_service
    global _graph_sync_service, _neo4j_client
    _session_factory = None
    _redis_client = None
    _context_store = None
    _degraded_flags = None
    _audit_log = None
    _event_service = None
    _state_machine = None
    _event_bus = None
    _pipeline = None
    _super_agent = None
    _event_lease = None
    _investigation_stack = None
    _approval_engine = None
    _impact_assessment_service = None
    _disposition_sync = None
    _action_execution = None
    _rollback_service = None
    _adapter_registry = None
    _workflow_runtime = None
    _event_disposition = None
    _graph_sync_service = None
    _neo4j_client = None
