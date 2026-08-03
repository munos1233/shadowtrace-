"""Evidence query plan resolution for ISSUE-115.

Server-owned mandatory baseline, planner ``required_tools`` merge/sanitize,
budget trimming, and deterministic dedupe keys for EvidenceAgent.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.agents.evidence_tools import EVIDENCE_QUERY_ORDER, SEVEN_EVIDENCE_TOOLS
from app.models.agent_io import ExecutionPlan, PlanBudget, TriageResult
from app.models.enums import EventType, ToolCategory
from app.services.evidence_projection import EvidenceQueryScope
from app.tools.specs import baseline_tool_index

logger = logging.getLogger(__name__)

_ALLOWED_EVIDENCE_QUERY_TOOLS: frozenset[str] = frozenset(SEVEN_EVIDENCE_TOOLS)

_FORBIDDEN_EVIDENCE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "update_source_event_disposition",
    }
)

_EVENT_TYPE_MANDATORY_FLOOR: dict[EventType, frozenset[str]] = {
    EventType.DATA_EXFILTRATION: frozenset(
        {"query_network_flow", "query_file_access", "query_threat_intel"}
    ),
    EventType.INSIDER_THREAT: frozenset({"query_file_access", "query_account_login"}),
    EventType.ACCOUNT_ANOMALY: frozenset({"query_account_login", "query_file_access"}),
    EventType.HOST_COMPROMISE: frozenset({"query_edr_process", "query_network_flow"}),
    EventType.MALICIOUS_PROCESS: frozenset({"query_edr_process", "query_threat_intel"}),
    EventType.SUSPICIOUS_DOMAIN: frozenset({"query_dns", "query_threat_intel"}),
    EventType.LATERAL_MOVEMENT: frozenset({"query_network_flow", "query_edr_process"}),
}


class EvidenceQueryPlan(BaseModel):
    """Resolved, deterministic evidence query set for one EvidenceAgent run."""

    model_config = ConfigDict(extra="forbid")

    tools: list[str] = Field(default_factory=list)
    mandatory_tools: list[str] = Field(default_factory=list)
    planned_tools: list[str] = Field(default_factory=list)
    plan_step_orders: list[int] = Field(default_factory=list)
    degraded_reasons: list[str] = Field(default_factory=list)
    rejected_tools: list[str] = Field(default_factory=list)
    budget_trimmed_tools: list[str] = Field(default_factory=list)
    used_safety_baseline: bool = False


def allowlisted_query_tools_from_manifest(
    allowed_operations: frozenset[str] | set[str] | None = None,
) -> frozenset[str]:
    """Return query tools allowed for evidence collection."""
    if allowed_operations is not None:
        return frozenset(
            name for name in allowed_operations if name in _ALLOWED_EVIDENCE_QUERY_TOOLS
        )
    index = baseline_tool_index()
    return frozenset(
        name
        for name, meta in index.items()
        if meta.tool_category is ToolCategory.QUERY and name in _ALLOWED_EVIDENCE_QUERY_TOOLS
    )


def resolve_event_type_floor(triage: TriageResult) -> frozenset[str]:
    """Event-type mandatory floor independent of entity extraction."""
    floor = _EVENT_TYPE_MANDATORY_FLOOR.get(triage.event_type)
    if floor is None:
        return frozenset()
    return frozenset(floor & _ALLOWED_EVIDENCE_QUERY_TOOLS)


def resolve_mandatory_baseline(triage: TriageResult) -> frozenset[str]:
    """Server-owned mandatory tools from triage entities and event type."""
    mandatory: set[str] = set()
    entities = triage.entities

    if any(account.username for account in entities.accounts):
        mandatory.update({"query_account_login", "query_file_access"})
    if any(host.hostname or host.ip for host in entities.hosts):
        mandatory.update({"query_edr_process", "query_asset_info"})
    if any(ip.address for ip in entities.ips):
        mandatory.add("query_network_flow")
    if any(domain.fqdn for domain in entities.domains) or any(
        item.strip() for item in triage.ioc_list
    ):
        mandatory.update({"query_dns", "query_threat_intel"})

    mandatory.update(resolve_event_type_floor(triage))
    return frozenset(mandatory & _ALLOWED_EVIDENCE_QUERY_TOOLS)


def sanitize_planned_tools(
    raw_tools: list[str],
    *,
    allowlisted: frozenset[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Reject non-query / response / disposition tools; preserve first-seen order."""
    allowed = allowlisted or _ALLOWED_EVIDENCE_QUERY_TOOLS
    index = baseline_tool_index()
    clean: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()

    for raw in raw_tools:
        name = raw.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        meta = index.get(name)
        if name in _FORBIDDEN_EVIDENCE_TOOL_NAMES:
            rejected.append(name)
            continue
        if meta is not None and meta.tool_category is not ToolCategory.QUERY:
            rejected.append(name)
            continue
        if name not in allowed:
            rejected.append(name)
            continue
        clean.append(name)

    return clean, rejected


def extract_evidence_plan_inputs(
    execution_plan: ExecutionPlan | dict[str, Any] | None,
) -> tuple[list[str], list[int], PlanBudget | None, bool]:
    """Collect evidence_agent required_tools and budget from an execution plan."""
    if execution_plan is None:
        return [], [], None, False

    plan: ExecutionPlan | None
    if isinstance(execution_plan, ExecutionPlan):
        plan = execution_plan
    else:
        try:
            plan = ExecutionPlan.model_validate(execution_plan)
        except Exception:
            return [], [], None, True

    tools: list[str] = []
    step_orders: list[int] = []
    seen: set[str] = set()
    for step in plan.steps:
        if step.assigned_agent != "evidence_agent":
            continue
        step_orders.append(step.step_order)
        for tool in step.required_tools:
            if tool not in seen:
                seen.add(tool)
                tools.append(tool)
    return tools, step_orders, plan.budget, False


def apply_query_budget(
    ordered_tools: list[str],
    *,
    mandatory_tools: frozenset[str],
    floor_tools: frozenset[str] | None = None,
    max_tool_calls: int | None,
) -> tuple[list[str], list[str], bool]:
    """Trim optional tools only; mandatory/floor tools are never dropped."""
    _ = floor_tools  # floor is a subset of mandatory; ordering follows ordered_tools
    if max_tool_calls is None or max_tool_calls <= 0 or len(ordered_tools) <= max_tool_calls:
        return ordered_tools, [], False

    mandatory_in_order = [tool for tool in ordered_tools if tool in mandatory_tools]
    optional_in_order = [tool for tool in ordered_tools if tool not in mandatory_tools]
    budget_exceeded = len(mandatory_in_order) > max_tool_calls

    if budget_exceeded:
        kept_set = set(mandatory_in_order)
    else:
        optional_slots = max_tool_calls - len(mandatory_in_order)
        kept_set = set(mandatory_in_order) | set(optional_in_order[:optional_slots])

    kept = [tool for tool in ordered_tools if tool in kept_set]
    trimmed = [tool for tool in ordered_tools if tool not in kept_set]
    return kept, trimmed, budget_exceeded


def order_tools(tools: frozenset[str]) -> list[str]:
    """Stable canonical order for evidence queries."""
    return [tool for tool in EVIDENCE_QUERY_ORDER if tool in tools]


def snapshot_cutoff_from_source(source_snapshot: dict[str, Any] | None) -> str:
    """Stable snapshot/cutoff token for dedupe keys from frozen source_snapshot."""
    if not isinstance(source_snapshot, dict):
        return ""
    for key in ("snapshot_id", "data_cutoff", "cutoff_at", "frozen_at_event_id"):
        value = source_snapshot.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def build_query_dedupe_key(
    tool_name: str,
    params: dict[str, Any],
    time_range: dict[str, str],
    scope: EvidenceQueryScope | None,
    *,
    snapshot_cutoff: str = "",
) -> str:
    """Normalized dedupe key across tool, params, window, tenant scope, snapshot."""
    scope_part = ""
    if scope is not None:
        scope_part = f"{scope.source_tenant_id}|{','.join(sorted(scope.connector_ids))}"
    canonical_params = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
    window = f"{time_range.get('start', '')}|{time_range.get('end', '')}"
    material = f"{tool_name}|{canonical_params}|{window}|{scope_part}|{snapshot_cutoff.strip()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def resolve_evidence_query_plan(
    triage: TriageResult,
    *,
    planned_tools: list[str] | None = None,
    execution_plan: ExecutionPlan | dict[str, Any] | None = None,
    max_tool_calls: int | None = None,
    allowlisted: frozenset[str] | None = None,
) -> EvidenceQueryPlan:
    """Merge mandatory baseline with validated planner tools; fail-safe to seven-source baseline."""
    mandatory = resolve_mandatory_baseline(triage)
    floor_tools = resolve_event_type_floor(triage)
    allowset = allowlisted or _ALLOWED_EVIDENCE_QUERY_TOOLS

    extracted_tools: list[str] = []
    step_orders: list[int] = []
    plan_budget: PlanBudget | None = None
    plan_invalid = False
    if execution_plan is not None:
        extracted_tools, step_orders, plan_budget, plan_invalid = extract_evidence_plan_inputs(
            execution_plan
        )
    raw_planned = list(planned_tools or extracted_tools)
    clean_planned, rejected = sanitize_planned_tools(raw_planned, allowlisted=allowset)

    degraded: list[str] = []
    used_baseline = False

    all_rejected = bool(raw_planned) and not clean_planned
    plan_missing = (
        plan_invalid
        or all_rejected
        or (execution_plan is not None and not step_orders and not raw_planned)
    )
    no_planner_input = execution_plan is None and planned_tools is not None and not planned_tools

    if plan_missing or no_planner_input:
        merged = frozenset(SEVEN_EVIDENCE_TOOLS) | mandatory
        used_baseline = True
        degraded.append("plan_missing_or_invalid")
        if rejected:
            degraded.append("rejected_non_query_tools")
    else:
        merged = mandatory | frozenset(clean_planned)
        if rejected:
            degraded.append("rejected_non_query_tools")

    ordered = order_tools(merged)
    manifest_disabled = [tool for tool in ordered if tool not in allowset]
    if manifest_disabled:
        degraded.append("manifest_disabled_tools")
        rejected.extend(manifest_disabled)
        ordered = [tool for tool in ordered if tool in allowset]

    budget_cap = max_tool_calls
    if budget_cap is None and plan_budget is not None:
        budget_cap = plan_budget.max_tool_calls

    final_tools, trimmed, budget_exceeded = apply_query_budget(
        ordered,
        mandatory_tools=mandatory,
        floor_tools=floor_tools,
        max_tool_calls=budget_cap,
    )
    if trimmed:
        optional_trimmed = [tool for tool in trimmed if tool not in mandatory]
        if optional_trimmed:
            degraded.append("budget_trimmed_optional_queries")
    if budget_exceeded:
        degraded.append("budget_exceeded_mandatory_preserved")

    return EvidenceQueryPlan(
        tools=final_tools,
        mandatory_tools=sorted(mandatory),
        planned_tools=clean_planned,
        plan_step_orders=step_orders,
        degraded_reasons=degraded,
        rejected_tools=rejected,
        budget_trimmed_tools=trimmed,
        used_safety_baseline=used_baseline,
    )


__all__ = [
    "EvidenceQueryPlan",
    "SEVEN_EVIDENCE_TOOLS",
    "allowlisted_query_tools_from_manifest",
    "apply_query_budget",
    "build_query_dedupe_key",
    "extract_evidence_plan_inputs",
    "order_tools",
    "resolve_event_type_floor",
    "resolve_evidence_query_plan",
    "resolve_mandatory_baseline",
    "sanitize_planned_tools",
    "snapshot_cutoff_from_source",
]
