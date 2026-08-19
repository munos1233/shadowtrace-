"""Orchestration package — ReAct engine, ConvergenceGuard, EventLease, SuperAgent, etc."""

from app.core.errors import (
    ReplanCountExceededError,
    WritebackManualResolutionRequiredError,
    WritebackRecoveryExhaustedError,
)
from app.orchestration.convergence_guard import (
    ConvergenceGuard,
    ConvergenceState,
    StopDecision,
    StopReason,
    make_tool_call_signature,
)
from app.orchestration.lease import (
    DEFAULT_LEASE_TTL_S,
    RENEW_INTERVAL_S,
    EventLease,
    generate_owner_id,
)
from app.orchestration.react_engine import (
    ReActActionDenied,
    ReActActionExecutor,
    ReActEngine,
    ReActTraceSink,
    ReadOnlyReActExecutor,
)
from app.orchestration.replan_handler import (
    EscalationResult,
    ReplanDecision,
    ReplanHandler,
    ReplanResult,
    replan_graph_node,
)
from app.orchestration.writeback_recovery_handler import (
    VERIFY_UNKNOWN_MAX_LOOKUPS,
    WritebackRecoveryAction,
    WritebackRecoveryHandler,
    WritebackRecoveryResult,
    WritebackState,
    writeback_recovery_graph_node,
)

__all__ = [
    "ConvergenceGuard",
    "ConvergenceState",
    "DEFAULT_LEASE_TTL_S",
    "EscalationResult",
    "EventLease",
    "RENEW_INTERVAL_S",
    "ReadOnlyReActExecutor",
    "ReActActionDenied",
    "ReActActionExecutor",
    "ReActEngine",
    "ReActTraceSink",
    "ReplanCountExceededError",
    "ReplanDecision",
    "ReplanHandler",
    "ReplanResult",
    "StopDecision",
    "StopReason",
    "VERIFY_UNKNOWN_MAX_LOOKUPS",
    "WritebackManualResolutionRequiredError",
    "WritebackRecoveryAction",
    "WritebackRecoveryExhaustedError",
    "WritebackRecoveryHandler",
    "WritebackRecoveryResult",
    "WritebackState",
    "generate_owner_id",
    "make_tool_call_signature",
    "planner_node",
    "rag_node",
    "replan_graph_node",
    "writeback_recovery_graph_node",
]


def __getattr__(name: str) -> object:
    """Lazy-export graph nodes to avoid analysis_only_pipeline ↔ workflow_graph import cycle."""
    if name in {"planner_node", "rag_node"}:
        from app.orchestration.workflow_graph import planner_node, rag_node

        return planner_node if name == "planner_node" else rag_node
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
