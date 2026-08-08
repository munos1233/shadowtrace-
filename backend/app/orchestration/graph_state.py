"""LangGraph investigation state (ISSUE-048)."""

from __future__ import annotations

from typing import Annotated, Any

from typing_extensions import TypedDict


def _merge_trace(left: list[str] | None, right: list[str] | None) -> list[str]:
    """Append node names while preserving execution order."""
    return [*(left or []), *(right or [])]


def _merge_flags(left: list[str] | None, right: list[str] | None) -> list[str]:
    """Merge degraded flags without duplicating entries during replay."""
    return list(dict.fromkeys([*(left or []), *(right or [])]))


class InvestigationState(TypedDict, total=False):
    """Checkpoint-safe state for one investigation workflow."""

    event_id: str
    event_status: str
    disposition_policy: str
    severity: str
    final_verdict: str | None
    confidence: float
    need_investigation: bool | None
    triage_result: dict[str, Any] | None
    false_positive_match: dict[str, Any] | None
    fp_adjudication: dict[str, Any] | None
    source_snapshot: dict[str, Any] | None
    disposition_only_intent: bool
    execution_substate: str
    execution_plan: dict[str, Any] | None
    event_status_update_readiness: str
    degraded_flags: Annotated[list[str], _merge_flags]
    node_trace: Annotated[list[str], _merge_trace]
    halted: bool
    error: str | None
    verify_need_manual_resolution: bool
    verify_need_writeback_recovery: bool
    verify_need_action_replan: bool
    verify_failed_actions: list[str] | None
    verify_failed_writebacks: list[str] | None
    verify_writeback_status: str | None
    # ISSUE-170: per-writeback status map keyed by writeback_id.  The scalar
    # ``verify_writeback_status`` above is kept for back-compat (single
    # writeback projection); recovery routing MUST prefer the map entry for
    # the current writeback_id so heterogeneous failures (e.g. UNKNOWN +
    # CONFLICT) are not misrouted through a stale scalar.
    verify_writeback_status_map: dict[str, str] | None
    writeback_lookup_count: int
    writeback_retry_count: int
    verify_has_partial_success: bool
    # When False and no verify_failed_actions → MANUAL_RESOLUTION
    execution_ok: bool
    include_rag: bool
    evidence_output: dict[str, Any] | None
    graph_output: dict[str, Any] | None
    rag_output: dict[str, Any] | None
    risk_assessment: dict[str, Any] | None
    response_plan: dict[str, Any] | None
    plan_revision: int
    replan_count: int
    escalated: bool
    report_generated: bool
    # ISSUE-204: when False, report_node skips ReportAgent and persists report_generated=false.
    generate_report: bool
    needs_approval_wait: bool
    # ISSUE-566: initial HTTP investigate (via build_initial_investigation_state)
    # defers response/approval/execute/verify; analysis completes at report
    # (REQUIRED→REPORTING, NOT_REQUIRED→CLOSED). Full P0 response execution
    # resumes via approval_engine / resume_investigation. Workflow unit tests
    # pass defer_response_execution=False via _base_state().
    defer_response_execution: bool
    # ISSUE-277: incremented on each manual_hold_node entry; paired with journal CAS.
    manual_hold_generation: int | None
