"""Pure conditional routing functions for the investigation graph (ISSUE-048)."""

from __future__ import annotations

from app.models.enums import DispositionPolicy, Severity, WritebackReadiness
from app.orchestration.graph_state import InvestigationState

ROUTE_AFTER_TRIAGE_CLOSE = "close"
ROUTE_AFTER_TRIAGE_DISPOSITION_ONLY = "disposition_only"
ROUTE_AFTER_TRIAGE_MANUAL_HOLD = "manual_hold"
ROUTE_AFTER_TRIAGE_INVESTIGATE = "investigate"

ROUTE_AFTER_PLANNER_RESPONSE = "response"
ROUTE_AFTER_PLANNER_EVIDENCE = "evidence"

ROUTE_AFTER_RISK_RESPONSE = "response"

ROUTE_AFTER_APPROVAL_EXECUTE = "execute"
ROUTE_AFTER_APPROVAL_WAIT = "wait"

ROUTE_AFTER_VERIFY_REPORT = "report"
ROUTE_AFTER_VERIFY_REPLAN = "replan"
ROUTE_AFTER_VERIFY_MANUAL = "manual"
ROUTE_AFTER_VERIFY_WRITEBACK = "writeback"
ROUTE_AFTER_VERIFY_HALT = "halt"


def _is_close_as_fp(state: InvestigationState) -> bool:
    fp = state.get("false_positive_match") or {}
    return fp.get("recommendation") == "close_as_fp"


def route_after_triage(state: InvestigationState) -> str:
    """Route after triage_node — mirrors ISSUE-007 TRIAGING gates (no wider paths)."""
    policy_raw = state.get("disposition_policy", DispositionPolicy.NOT_REQUIRED.value)
    policy = DispositionPolicy(policy_raw)
    severity = Severity(state.get("severity", Severity.MEDIUM.value))
    is_fp = _is_close_as_fp(state)

    if policy is DispositionPolicy.NOT_REQUIRED and (severity is Severity.LOW or is_fp):
        return ROUTE_AFTER_TRIAGE_CLOSE

    if is_fp and policy is DispositionPolicy.REQUIRED:
        readiness = WritebackReadiness(
            state.get("event_status_update_readiness", WritebackReadiness.CAPABILITY_UNKNOWN.value)
        )
        if readiness is WritebackReadiness.READY:
            return ROUTE_AFTER_TRIAGE_DISPOSITION_ONLY
        return ROUTE_AFTER_TRIAGE_MANUAL_HOLD

    return ROUTE_AFTER_TRIAGE_INVESTIGATE


def route_after_planner(state: InvestigationState) -> str:
    """Route using server-persisted intent reflected in ``disposition_only_active``."""
    if state.get("disposition_only_active"):
        return ROUTE_AFTER_PLANNER_RESPONSE
    return ROUTE_AFTER_PLANNER_EVIDENCE


def route_after_risk(state: InvestigationState) -> str:
    """P0 always continues to response planning after risk."""
    return ROUTE_AFTER_RISK_RESPONSE


def route_after_approval(state: InvestigationState) -> str:
    """Pause while execution_substate indicates human approval pending."""
    substate = state.get("execution_substate", "none")
    if substate == "waiting_approval":
        return ROUTE_AFTER_APPROVAL_WAIT
    return ROUTE_AFTER_APPROVAL_EXECUTE


def route_after_verify(state: InvestigationState) -> str:
    """Fixed verify routing — do not infer from overall_status alone."""
    if state.get("verify_need_manual_resolution"):
        return ROUTE_AFTER_VERIFY_MANUAL
    if state.get("verify_need_writeback_recovery"):
        return ROUTE_AFTER_VERIFY_WRITEBACK
    if state.get("verify_need_action_replan"):
        return ROUTE_AFTER_VERIFY_REPLAN
    if state.get("disposition_only_active"):
        return ROUTE_AFTER_VERIFY_HALT
    return ROUTE_AFTER_VERIFY_REPORT
