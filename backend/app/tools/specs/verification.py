"""Baseline verification ToolMeta definitions (intro §4.5.3)."""

from __future__ import annotations

from app.models.enums import ActionCategory, ActionLevel, ToolCategory
from app.models.tool_meta import RoutingKind, SideEffectLevel, ToolMeta
from app.tools.inputs import TOOL_INPUT_MODELS

_VERIFY_SPECS: tuple[tuple[str, str, list[str]], ...] = (
    ("check_ip_block_status", "Verify IP block effect.", ["ip"]),
    ("check_domain_block_status", "Verify domain block effect.", ["domain"]),
    ("check_host_isolation_status", "Verify host isolation effect.", ["host"]),
    ("check_file_quarantine_status", "Verify file quarantine effect.", ["file"]),
    ("check_process_block_status", "Verify process block effect.", ["process"]),
    ("check_virus_scan_status", "Verify virus scan completion.", ["host"]),
    ("check_account_status", "Verify account disable/logout/reset effect.", ["account"]),
    ("check_new_alerts", "Check for new related alerts after response.", ["event"]),
    ("check_traffic_drop", "Verify traffic drop after network containment.", ["ip", "host"]),
)


def _verify_meta(name: str, description: str, target_types: list[str]) -> ToolMeta:
    input_model = TOOL_INPUT_MODELS[name]
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.VERIFICATION,
        description=description,
        action_category=ActionCategory.VERIFICATION,
        routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
        supported_execution_owners=[],
        required_disposition_intent_by_owner={},
        side_effect_level=SideEffectLevel.NONE,
        action_level=ActionLevel.L0,
        idempotency=True,
        async_mode=False,
        rollback_supported=False,
        executable=True,
        target_types=target_types,
        input_schema=input_model.model_json_schema(),
    )


VERIFICATION_TOOL_METAS: list[ToolMeta] = [
    _verify_meta(name, desc, targets) for name, desc, targets in _VERIFY_SPECS
]
