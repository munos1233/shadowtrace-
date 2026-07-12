"""Baseline query ToolMeta definitions (intro §4.5.1)."""

from __future__ import annotations

from app.models.enums import ToolCategory
from app.models.tool_meta import RoutingKind, SideEffectLevel, ToolMeta
from app.tools.inputs import TOOL_INPUT_MODELS

_QUERY_NAMES = (
    "query_account_login",
    "query_edr_process",
    "query_file_access",
    "query_network_flow",
    "query_dns",
    "query_asset_info",
    "query_vuln_info",
    "query_threat_intel",
    "query_history_cases",
)


def _query_meta(name: str, *, description: str) -> ToolMeta:
    input_model = TOOL_INPUT_MODELS[name]
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.QUERY,
        description=description,
        action_category=None,
        routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
        supported_execution_owners=[],
        required_disposition_intent_by_owner={},
        side_effect_level=SideEffectLevel.NONE,
        idempotency=True,
        async_mode=False,
        rollback_supported=False,
        executable=True,
        input_schema=input_model.model_json_schema(),
    )


QUERY_TOOL_METAS: list[ToolMeta] = [
    _query_meta("query_account_login", description="Query account login history."),
    _query_meta("query_edr_process", description="Query EDR process activity on a host."),
    _query_meta("query_file_access", description="Query file access events for an account."),
    _query_meta("query_network_flow", description="Query network flows by src/dst IP."),
    _query_meta("query_dns", description="Query DNS resolution history for a domain."),
    _query_meta("query_asset_info", description="Query asset inventory by IP or hostname."),
    _query_meta("query_vuln_info", description="Query vulnerability findings for an asset."),
    _query_meta("query_threat_intel", description="Query threat intelligence for an indicator."),
    _query_meta("query_history_cases", description="Query similar historical cases."),
]

assert {m.tool_name for m in QUERY_TOOL_METAS} == set(_QUERY_NAMES)
