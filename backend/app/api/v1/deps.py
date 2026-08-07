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
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.redis_client import RedisClient
from app.db.session_provider import get_session_provider, reset_session_provider

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Lazy singletons (session factory owned by SessionProvider — ISSUE-118)
# --------------------------------------------------------------------------- #

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
_investigation_intent_service: Any = None  # InvestigationIntentService
_behavior_observation_service: Any = None  # BehaviorObservationService
_approval_engine: Any = None  # ApprovalEngine
_impact_assessment_service: Any = None  # ImpactAssessmentService
_disposition_sync: Any = None  # DispositionSyncService
_action_execution: Any = None  # ActionExecutionService
_rollback_service: Any = None  # RollbackService
_adapter_registry: Any = None  # DispositionAdapterRegistry
_workflow_runtime: Any = None  # WorkflowRuntimeService
_event_disposition: Any = None  # EventDispositionService
_opensearch_client: Any = None  # OpenSearchClient
_search_service: Any = None  # SearchService
_tool_call_log: Any = None  # ToolCallLogService
_graph_sync_service: Any = None  # GraphSyncService (ISSUE-082)
_neo4j_client: Any = None  # Neo4jClient (ISSUE-082)
_memory_governance: Any = None  # MemoryGovernance (ISSUE-081)
_detection_governance: Any = None  # DetectionGovernanceService (ISSUE-125)
_detection_promotion: Any = None  # DetectionPromotionService (ISSUE-124)
_detection_context_projector: Any = None  # DetectionContextProjector (ISSUE-127)
_detection_context_service: Any = None  # DetectionContextService (ISSUE-127)
_decision_record_service: Any = None  # DecisionRecordService (ISSUE-131)
_tool_call_grant_service: Any = None  # ToolCallGrantService (ISSUE-134)
_agent_task_service: Any = None  # AgentTaskService (ISSUE-133)
_agent_artifact_service: Any = None  # AgentArtifactService (ISSUE-133)
_content_projection_service: Any = None  # ContentProjectionService (ISSUE-133)


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    return get_session_provider().session_factory()


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
        from app.services.degraded_flag_service import (
            DegradedFlagService,
            wire_redis_context_recovery,
        )

        store = _get_context_store()
        _degraded_flags = DegradedFlagService(store, _get_session_factory())
        wire_redis_context_recovery(store, _degraded_flags)
    return _degraded_flags


def _get_decision_record_service() -> Any:
    global _decision_record_service
    if _decision_record_service is None:
        from app.services.decision_record_service import DecisionRecordService

        _decision_record_service = DecisionRecordService(
            _get_session_factory(),
            degraded_flag_service=_get_degraded_flags(),
        )
    return _decision_record_service


def _get_tool_call_grant_service() -> Any:
    global _tool_call_grant_service
    if _tool_call_grant_service is None:
        from app.services.tool_call_budget_reservation import ToolCallBudgetReservationService
        from app.services.tool_call_grant_service import ToolCallGrantService

        _tool_call_grant_service = ToolCallGrantService(
            _get_session_factory(),
            budget_reservation=ToolCallBudgetReservationService(
                _get_redis(),
                attempt_redis_recovery=get_settings().budget_attempt_redis_recovery,
                recovery_interval_seconds=get_settings().budget_redis_recovery_interval_seconds,
            ),
        )
    return _tool_call_grant_service


def _get_agent_task_service() -> Any:
    global _agent_task_service
    if _agent_task_service is None:
        from app.services.agent_task_service import AgentTaskService

        _agent_task_service = AgentTaskService(
            _get_session_factory(),
            grant_service=_get_tool_call_grant_service(),
        )
    return _agent_task_service


def _get_agent_artifact_service() -> Any:
    global _agent_artifact_service
    if _agent_artifact_service is None:
        from app.services.agent_artifact_service import AgentArtifactService

        _agent_artifact_service = AgentArtifactService(_get_session_factory())
    return _agent_artifact_service


def _get_content_projection_service() -> Any:
    global _content_projection_service
    if _content_projection_service is None:
        from app.services.content_projection_service import ContentProjectionService

        _content_projection_service = ContentProjectionService()
    return _content_projection_service


def _get_audit_log() -> Any:
    global _audit_log
    if _audit_log is None:
        from app.services.event_audit_log_service import EventAuditLogService

        _audit_log = EventAuditLogService(
            _get_session_factory(),
            opensearch=_get_opensearch_client(),
        )
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
        from app.services.auto_investigate_policy import AutoInvestigatePolicyService
        from app.services.event_service import EventService
        from app.services.investigation_intent_service import InvestigationIntentService

        state_machine = await get_state_machine()
        intent_service = InvestigationIntentService(
            _get_session_factory(),
            policy=AutoInvestigatePolicyService(),
            degraded_flags=_get_degraded_flags(),
        )
        _event_service = EventService(
            _get_session_factory(),
            _get_context_store(),
            degraded_flags=_get_degraded_flags(),
            state_machine=state_machine,
            event_bus=_get_event_bus(),
            investigation_intent=intent_service,
        )
    return _event_service


async def get_investigation_intent_service() -> Any:
    global _investigation_intent_service
    if _investigation_intent_service is None:
        from app.services.auto_investigate_policy import AutoInvestigatePolicyService
        from app.services.investigation_intent_service import InvestigationIntentService

        _investigation_intent_service = InvestigationIntentService(
            _get_session_factory(),
            policy=AutoInvestigatePolicyService(),
            degraded_flags=_get_degraded_flags(),
        )
    return _investigation_intent_service


async def get_behavior_observation_service() -> Any:
    global _behavior_observation_service
    if _behavior_observation_service is None:
        from app.services.behavior_observation_service import BehaviorObservationService

        _behavior_observation_service = BehaviorObservationService(_get_session_factory())
    return _behavior_observation_service


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


def get_memory_governance() -> Any:
    """Return the shared memory review and promotion service."""
    global _memory_governance
    if _memory_governance is None:
        from app.core.embedding.factory import get_embedding_client
        from app.services.case_kb_service import CaseKBService
        from app.services.knowledge_store import KnowledgeStore
        from app.services.memory_governance import MemoryGovernance
        from app.services.profile_service import ProfileService

        session_factory = _get_session_factory()
        knowledge_store = KnowledgeStore(session_factory, get_embedding_client())
        _memory_governance = MemoryGovernance(
            session_factory,
            case_kb_service=CaseKBService(knowledge_store, session_factory),
            profile_service=ProfileService(session_factory),
        )
    return _memory_governance


MemoryGovernanceDep = Annotated[Any, Depends(get_memory_governance)]


def get_detection_governance_service() -> Any:
    """Return the shared detection governance decision service."""
    global _detection_governance
    if _detection_governance is None:
        from app.services.detection_governance_service import DetectionGovernanceService

        _detection_governance = DetectionGovernanceService(_get_session_factory())
    return _detection_governance


DetectionGovernanceDep = Annotated[Any, Depends(get_detection_governance_service)]


def get_detection_context_projector() -> Any:
    """Return the shared detection context projector (ISSUE-127)."""
    global _detection_context_projector
    if _detection_context_projector is None:
        from app.services.detection_context_projector import DetectionContextProjector

        _detection_context_projector = DetectionContextProjector(
            _get_session_factory(),
            governance=get_detection_governance_service(),
        )
    return _detection_context_projector


def get_detection_context_service() -> Any:
    """Return the shared detection context snapshot store (ISSUE-127)."""
    global _detection_context_service
    if _detection_context_service is None:
        from app.services.detection_context_service import DetectionContextService

        _detection_context_service = DetectionContextService(_get_session_factory())
    return _detection_context_service


async def get_detection_promotion_service() -> Any:
    """Return the shared detection promotion saga service (ISSUE-124)."""
    global _detection_promotion
    if _detection_promotion is None:
        from app.ingestion.source_ingester import SourceIngester
        from app.services.detection_promotion_service import DetectionPromotionService

        settings = get_settings()
        session_factory = _get_session_factory()
        event_service = await get_event_service()
        ingester = SourceIngester(
            event_service,
            session_factory,
            source_mode=settings.source_mode,
        )
        _detection_promotion = DetectionPromotionService(
            session_factory,
            governance=get_detection_governance_service(),
            event_service=event_service,
            source_ingester=ingester,
            context_projector=get_detection_context_projector(),
        )
    return _detection_promotion


DetectionPromotionDep = Annotated[Any, Depends(get_detection_promotion_service)]


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
            decision_record_service=_get_decision_record_service(),
        )
    return _workflow_runtime


async def _resume_investigation(event_id: str) -> None:
    """Resume graph orchestration after approval or writeback (ISSUE-059 / #613)."""
    settings = get_settings()
    mode = (settings.orchestration_mode or "graph").strip().lower()
    if mode != "graph":
        return
    from app.orchestration.graph_resume_observability import execute_graph_resume_with_retry

    await execute_graph_resume_with_retry(
        event_id,
        session_factory=_get_session_factory(),
        get_super_agent=get_super_agent,
        get_workflow_runtime=_get_workflow_runtime,
        degraded_flags=_get_degraded_flags(),
    )


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
            decision_record_service=_get_decision_record_service(),
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
        playbook_kb_service=stack.get("playbook_kb_service"),
        playbook_release_service=stack.get("playbook_release_service"),
    )
    verify_agent = VerifyAgent(
        tool_executor=stack["tool_executor"],
        working_memory=wm.for_writer("VerifyAgent"),
        trace_service=stack["trace_service"],
        event_bus=event_bus,
        session_factory=stack["session_factory"],
        event_disposition_service=await get_event_disposition_service(),
        disposition_sync_service=await get_disposition_sync(),
        # ISSUE-169: align with ResponseAgent and the other production agents —
        # verification structured output must run through the same OutputGuard.
        output_guard=stack["output_guard"],
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
        "graph_agent": stack["graph_agent"],
    }
    services = {
        "state_machine": stack["state_machine"],
        "event_service": stack["event_service"],
        "workflow_runtime": await _get_workflow_runtime(),
        "degraded_flags": stack["degraded_flags"],
        "context_store": stack["context_store"],
        "session_factory": stack["session_factory"],
        "working_memory": stack["wm"],
        "approval_engine": await get_approval_engine(),
        "action_execution": await get_action_execution(),
        "disposition_sync": await get_disposition_sync(),
        "event_disposition": await get_event_disposition_service(),
        "convergence_guard": convergence_guard,
        "agent_task_service": _get_agent_task_service(),
        "agent_artifact_service": _get_agent_artifact_service(),
        "content_projection_service": _get_content_projection_service(),
    }
    # ISSUE-218: fail fast on production miswiring — if a key service/agent
    # is missing the graph would previously "succeed" through stub nodes
    # (fake progress).  A production deployment must fail explicitly instead.
    missing_di = [
        name
        for name, dep in (
            ("response_agent", response_agent),
            ("verify_agent", verify_agent),
            ("approval_engine", services["approval_engine"]),
            ("action_execution", services["action_execution"]),
            ("disposition_sync", services["disposition_sync"]),
            ("event_disposition", services["event_disposition"]),
        )
        if dep is None
    ]
    if missing_di:
        raise RuntimeError(
            "production investigation graph miswired — missing dependencies: "
            + ", ".join(missing_di)
        )
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
        from app.services.rollback_service import RollbackService, build_execute_rollback_hook

        action_execution = await get_action_execution()
        _rollback_service = RollbackService(
            _get_session_factory(),
            audit=_get_audit_log(),
            execute_rollback=build_execute_rollback_hook(action_execution),
            disposition_sync=await get_disposition_sync(),
            event_bus=_get_event_bus(),
            adapter_registry=_get_adapter_registry(),
        )
    return _rollback_service


def _get_opensearch_client() -> Any:
    """Return the OpenSearchClient singleton (ISSUE-084)."""
    global _opensearch_client
    if _opensearch_client is None:
        from app.core.opensearch_client import OpenSearchClient

        _opensearch_client = OpenSearchClient(get_settings())
    return _opensearch_client


def _get_tool_call_log_service() -> Any:
    """Return ToolCallLogService with optional OpenSearch dual-write (ISSUE-084)."""
    global _tool_call_log
    if _tool_call_log is None:
        from app.services.tool_call_log_service import ToolCallLogService

        _tool_call_log = ToolCallLogService(
            _get_session_factory(),
            opensearch=_get_opensearch_client(),
        )
    return _tool_call_log


def get_search_service() -> Any:
    """Return the SearchService singleton (ISSUE-084)."""
    global _search_service
    if _search_service is None:
        from app.services.search_service import SearchService

        _search_service = SearchService(
            _get_session_factory(),
            opensearch=_get_opensearch_client(),
        )
    return _search_service


async def get_graph_sync_service() -> Any:
    """Return GraphSyncService when NEO4J_ENABLED=true; None otherwise.

    ISSUE-082 §实现步骤 point 3: GraphAgent 输出后异步触发 Neo4j 同步。
    """
    global _graph_sync_service, _neo4j_client
    settings = get_settings()
    if not settings.neo4j_enabled:
        return None
    if _graph_sync_service is None:
        from app.services.graph_sync_service import GraphSyncService

        client = _ensure_neo4j_client()
        _graph_sync_service = GraphSyncService(
            _get_session_factory(),
            client=client,
        )
    return _graph_sync_service


def _ensure_neo4j_client() -> Any:
    """Lazily construct the shared Neo4jClient when NEO4J_ENABLED."""
    global _neo4j_client
    settings = get_settings()
    if not settings.neo4j_enabled:
        return None
    if _neo4j_client is None:
        from app.core.neo4j_client import Neo4jClient

        _neo4j_client = Neo4jClient()
    return _neo4j_client


async def get_attack_path_service() -> Any:
    """Return AttackPathService (ISSUE-083).

    When NEO4J_ENABLED=false the service is constructed without a client and
    always returns empty cross_event_paths.
    """
    from app.services.attack_path_service import AttackPathService

    settings = get_settings()
    session_factory = _get_session_factory() if settings.neo4j_enabled else None
    return AttackPathService(
        client=_ensure_neo4j_client(),
        session_factory=session_factory,
    )


async def shutdown_neo4j_client() -> None:
    """Close the lazy Neo4j driver on application shutdown (ISSUE-082)."""
    global _neo4j_client, _graph_sync_service
    if _neo4j_client is not None:
        await _neo4j_client.aclose()
        _neo4j_client = None
        _graph_sync_service = None


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
    from app.agents.graph_agent import GraphAgent
    from app.agents.memory_agent import MemoryAgent
    from app.agents.rag_agent import RAGAgent
    from app.agents.report_agent import ReportAgent
    from app.agents.risk_agent import RiskAgent
    from app.agents.triage_agent import TriageAgent
    from app.core.embedding.factory import get_embedding_client
    from app.core.guardrails import OutputGuard
    from app.core.llm.factory import get_llm_client
    from app.orchestration.convergence_guard import ConvergenceGuard
    from app.services.agent_trace_service import AgentTraceService
    from app.services.budget_service import BudgetService
    from app.services.case_kb_service import CaseKBService
    from app.services.false_positive_matcher import FalsePositiveMatcher
    from app.services.knowledge_store import KnowledgeStore
    from app.services.memory_governance import MemoryGovernance
    from app.services.profile_service import ProfileService
    from app.services.storyline_service import StorylineService
    from app.tools.executor import NullAuditService, get_tool_executor

    settings = get_settings()
    event_service = await get_event_service()
    state_machine = await get_state_machine()
    wm = await _get_wm()
    session_factory = _get_session_factory()
    budget_service = BudgetService(
        redis=_get_redis(),
        settings=settings,
        attempt_redis_recovery=settings.budget_attempt_redis_recovery,
        recovery_interval_seconds=settings.budget_redis_recovery_interval_seconds,
    )
    output_guard = OutputGuard()
    trace_service = AgentTraceService(
        session_factory,
        decision_record_service=_get_decision_record_service(),
        degraded_flag_service=_get_degraded_flags(),
    )
    # ISSUE-168: construct ONE ConvergenceGuard for the whole investigation
    # stack and share it across the SuperAgent graph, the LLM client and the
    # ToolExecutor so MAX_* / stop conditions apply to tool and LLM traffic
    # uniformly (production DI must not leave NoopConvergenceGuard in place).
    convergence_guard = ConvergenceGuard(
        working_memory=wm.for_writer("ConvergenceGuard"),
    )
    llm_client = get_llm_client(
        settings=settings,
        budget_service=budget_service,
        # ConvergenceGuardHook declares a sync record_step while ConvergenceGuard
        # is async — BaseLLMClient._check_convergence dispatches via
        # _is_async_callable, so the mismatch is runtime-compatible.
        convergence_guard=convergence_guard,  # type: ignore[arg-type]
    )
    tool_executor = get_tool_executor()
    tool_executor.budget_service = budget_service
    # Same instance on the executor singleton (replacing the default
    # NoopConvergenceGuard), mirroring the budget_service swap above.
    # ConvergenceGuard.should_stop returns StopDecision (bool-like via
    # __bool__) while ConvergenceGuardPort declares bool — structurally
    # compatible at runtime, so silence the static mismatch here.
    tool_executor.convergence_guard = convergence_guard  # type: ignore[assignment]
    if isinstance(tool_executor.audit_service, NullAuditService):
        tool_executor.audit_service = _get_tool_call_log_service()

    from app.services.safe_tool_projection import SafeToolProjectionService
    from app.tools.tool_call_runtime import (
        ReactToolExecutorFactory,
        build_evidence_query_executor,
    )

    evidence_tool_executor = build_evidence_query_executor(
        tool_executor,
        settings=settings,
    )
    react_executor_factory = ReactToolExecutorFactory(
        inner_executor=tool_executor,
        grant_service=_get_tool_call_grant_service(),
        settings=settings,
        projection_service=SafeToolProjectionService(tool_executor.registry),
    )

    # ISSUE-078: wire FalsePositiveMatcher for vector-based FP pre-filter.
    embed_service = get_embedding_client(settings=settings)
    knowledge_store = KnowledgeStore(session_factory, embed_service)
    case_kb_service = CaseKBService(knowledge_store, session_factory)
    fp_matcher = FalsePositiveMatcher(case_kb_service)
    profile_service = ProfileService(session_factory)
    memory_governance = MemoryGovernance(
        session_factory,
        case_kb_service=case_kb_service,
        profile_service=profile_service,
    )
    memory = MemoryAgent(
        case_kb_service=case_kb_service,
        profile_service=profile_service,
        memory_governance=memory_governance,
        context_store=_get_context_store(),
        llm_client=llm_client,
        working_memory=wm.for_writer("MemoryAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        audit_service=_get_audit_log(),
        event_bus=_get_event_bus(),
        degraded_flags=_get_degraded_flags(),
        early_enqueue_enabled=settings.memory_enqueue_after_analysis,
    )

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
        degraded_flags=_get_degraded_flags(),
        event_service=event_service,
    )
    evidence = EvidenceAgent(
        llm_client=llm_client,
        tool_executor=evidence_tool_executor,
        working_memory=wm.for_writer("EvidenceAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_bus=event_bus,
        event_service=event_service,
        session_factory=session_factory,
    )
    from app.playbook.resources import get_loaded_playbook_resources, probe_playbook_resources
    from app.rag.resources import get_loaded_retrieval_resources
    from app.services.knowledge_release_service import KnowledgeReleaseService

    retrieval_resources = get_loaded_retrieval_resources(
        settings=settings,
        session_factory=session_factory,
        llm_client=llm_client,
        embed_service=embed_service,
    )
    if retrieval_resources.status != "ready":
        logger.warning(
            "Retrieval resources not ready during investigation stack build",
            extra={
                "status": retrieval_resources.status,
                "reasons": list(retrieval_resources.reasons),
                "mode": retrieval_resources.mode,
            },
        )
    playbook_resources = get_loaded_playbook_resources(
        settings=settings,
        session_factory=session_factory,
        embed_service=embed_service,
    )
    playbook_resources = await probe_playbook_resources(playbook_resources, settings=settings)
    if playbook_resources.status != "ready":
        logger.warning(
            "Playbook resources not ready during investigation stack build",
            extra={
                "status": playbook_resources.status,
                "reasons": list(playbook_resources.reasons),
                "mode": playbook_resources.mode,
                "active_release_id": playbook_resources.active_release_id,
            },
        )
    knowledge_release_service = KnowledgeReleaseService(
        session_factory,
        store=knowledge_store,
        settings=settings,
    )
    rag = RAGAgent(
        working_memory=wm.for_writer("RAGAgent"),
        pipeline=retrieval_resources.pipeline,
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_bus=event_bus,
        knowledge_release_service=knowledge_release_service,
        playbook_release_service=playbook_resources.playbook_release_service,
        settings=settings,
    )
    risk = RiskAgent(
        llm_client=llm_client,
        working_memory=wm.for_writer("RiskAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_bus=event_bus,
        event_service=event_service,
        degraded_flags=_get_degraded_flags(),
    )
    report = ReportAgent(
        llm_client=llm_client,
        working_memory=wm.for_writer("ReportAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_service=event_service,
        detection_context_service=get_detection_context_service(),
        event_bus=event_bus,
    )
    graph_sync = await get_graph_sync_service()
    graph_agent = GraphAgent(
        working_memory=wm.for_writer("GraphAgent"),
        budget_service=budget_service,
        output_guard=output_guard,
        trace_service=trace_service,
        event_bus=event_bus,
        session_factory=session_factory,
        graph_sync_service=graph_sync,
    )
    storyline_service = StorylineService(
        llm_client=llm_client,
        working_memory=wm.for_writer("StorylineService"),
        event_service=event_service,
    )
    from app.services.output_quality_evaluator import build_output_quality_evaluator

    output_quality_evaluator = build_output_quality_evaluator(
        working_memory=wm,
        llm_client=llm_client,
        judge_enabled=settings.quality_judge_enabled,
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
        "playbook_kb_service": playbook_resources.playbook_kb_service,
        "playbook_release_service": playbook_resources.playbook_release_service,
        "risk": risk,
        "report": report,
        "graph_agent": graph_agent,
        "storyline_service": storyline_service,
        "output_quality_evaluator": output_quality_evaluator,
        "memory": memory,
        "context_store": _get_context_store(),
        "degraded_flags": _get_degraded_flags(),
        "budget_service": budget_service,
        "output_guard": output_guard,
        "convergence_guard": convergence_guard,
        "llm_client": llm_client,
        "tool_executor": tool_executor,
        "evidence_tool_executor": evidence_tool_executor,
        "react_executor_factory": react_executor_factory,
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
            graph_agent=stack["graph_agent"],
            risk_agent=stack["risk"],
            report_agent=stack["report"],
            context_store=stack["context_store"],
            session_factory=stack["session_factory"],
            working_memory=stack["wm"],
            degraded_flags=stack["degraded_flags"],
            settings=stack["settings"],
            memory_agent=stack["memory"],
            agent_task_service=_get_agent_task_service(),
            agent_artifact_service=_get_agent_artifact_service(),
            content_projection_service=_get_content_projection_service(),
            # ISSUE-168: the pipeline runs the same LLM client / ToolExecutor
            # as the investigation stack, so it must own the shared guard's
            # lifecycle (reset after each run) instead of leaving counters
            # behind for re-investigations of the same event.
            convergence_guard=stack["convergence_guard"],
            output_quality_evaluator=stack["output_quality_evaluator"],
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
        # ISSUE-168: reuse the single guard wired during stack assembly so the
        # LLM client / ToolExecutor / investigation graph all share one counter
        # set instead of a second, disconnected instance.
        convergence_guard = stack["convergence_guard"]
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
            session_factory=stack["session_factory"],
            lease=get_event_lease(),
            convergence_guard=convergence_guard,
            event_bus=_get_event_bus(),
            trace_service=stack["trace_service"],
            react_enabled=settings.react_enabled,
            react_executor_factory=stack["react_executor_factory"],
            react_llm_client=stack["llm_client"],
            investigation_graph=investigation_graph,
            memory_agent=stack["memory"],
            audit_service=_get_audit_log(),
            graph_agent=stack["graph_agent"],
            storyline_service=stack["storyline_service"],
            output_quality_evaluator=stack["output_quality_evaluator"],
        )
    return _super_agent


def reset_investigation_stack_cache() -> None:
    """Drop cached investigation wiring without tearing down infrastructure."""
    global _pipeline, _super_agent, _investigation_stack
    _pipeline = None
    _super_agent = None
    _investigation_stack = None


def reset_loop_bound_redis_resources() -> None:
    """Drop Redis and redis-backed singletons after Celery ``asyncio.run`` (ISSUE-252).

    Strategy B: redis.asyncio clients are loop-bound. Each worker task must discard
    the process-cached Redis client (and anything holding it) so the next
    ``asyncio.run`` binds fresh clients. SessionProvider is intentionally kept —
    worker NullPool engines are already loop-safe across consecutive runs.
    """
    import asyncio

    global _redis_client, _context_store, _degraded_flags
    global _event_service, _state_machine, _event_bus, _pipeline, _approval_engine
    global _super_agent, _event_lease, _investigation_stack, _investigation_intent_service
    global _behavior_observation_service
    global _disposition_sync, _action_execution, _rollback_service
    global _adapter_registry, _workflow_runtime, _event_disposition
    global _impact_assessment_service
    global _tool_call_grant_service, _agent_task_service
    global _memory_governance, _detection_governance, _detection_promotion
    global _detection_context_projector, _detection_context_service
    global _decision_record_service

    client = _redis_client
    _redis_client = None
    _context_store = None
    _degraded_flags = None
    _decision_record_service = None
    _event_service = None
    _state_machine = None
    _event_bus = None
    _pipeline = None
    _super_agent = None
    _event_lease = None
    _investigation_stack = None
    _investigation_intent_service = None
    _behavior_observation_service = None
    _approval_engine = None
    _impact_assessment_service = None
    _disposition_sync = None
    _action_execution = None
    _rollback_service = None
    _adapter_registry = None
    _workflow_runtime = None
    _event_disposition = None
    _tool_call_grant_service = None
    _agent_task_service = None
    _memory_governance = None
    _detection_governance = None
    _detection_promotion = None
    _detection_context_projector = None
    _detection_context_service = None

    if client is None:
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop (Celery Strategy B after asyncio.run) — close cleanly.
        try:
            asyncio.run(client.aclose())
        except Exception:
            logger.debug("Redis aclose after Celery task failed", exc_info=True)
        return
    # Called from inside a running loop (tests / reset_deps): drop references only.
    # Closing via asyncio.run would nest loops; RedisClient rebind handles reuse.


def reset_deps() -> None:
    """Reset all lazy singletons (for tests)."""
    global _redis_client, _context_store, _degraded_flags
    global _audit_log, _event_service, _state_machine, _event_bus, _pipeline, _approval_engine
    global _super_agent, _event_lease, _investigation_stack, _investigation_intent_service
    global _behavior_observation_service
    global _disposition_sync, _action_execution, _rollback_service
    global _adapter_registry, _workflow_runtime, _event_disposition
    global _impact_assessment_service
    global _opensearch_client, _search_service, _tool_call_log
    global _graph_sync_service, _neo4j_client
    global \
        _memory_governance, \
        _detection_governance, \
        _detection_promotion, \
        _detection_context_projector, \
        _detection_context_service, \
        _decision_record_service, \
        _tool_call_grant_service, \
        _agent_task_service, \
        _agent_artifact_service, \
        _content_projection_service
    reset_session_provider()
    from app.core.embedding.factory import reset_embedding_client
    from app.playbook.resources import reset_playbook_resources_cache
    from app.rag.resources import reset_loaded_retrieval_resources
    from app.services.evidence_projection import reset_evidence_projection_default

    reset_embedding_client()
    reset_loaded_retrieval_resources()
    reset_playbook_resources_cache()
    reset_evidence_projection_default()
    reset_loop_bound_redis_resources()
    _audit_log = None
    _opensearch_client = None
    _search_service = None
    _tool_call_log = None
    _graph_sync_service = None
    _neo4j_client = None
    _decision_record_service = None
    _agent_artifact_service = None
    _content_projection_service = None
