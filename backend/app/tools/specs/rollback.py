"""Baseline rollback ToolMeta definitions (intro §4.5.4)."""

from __future__ import annotations

from app.models.enums import ActionCategory, ActionLevel, ExecutionOwner, ToolCategory
from app.models.tool_meta import (
    RoutingKind,
    SideEffectLevel,
    ToolMeta,
    default_rollback_intents,
)
from app.tools.inputs import TOOL_INPUT_MODELS
from app.tools.specs.response import RESPONSE_ROLLBACK_MAP

# Inverse of RESPONSE_ROLLBACK_MAP — kept in sync by tests.
ROLLBACK_SOURCE_MAP: dict[str, str] = {v: k for k, v in RESPONSE_ROLLBACK_MAP.items()}

_ROLLBACK_SPECS: tuple[tuple[str, str, ActionLevel, SideEffectLevel, list[str]], ...] = (
    ("unblock_ip", "Undo an IP block.", ActionLevel.L2, SideEffectLevel.MEDIUM, ["ip"]),
    (
        "unblock_domain",
        "Undo a domain block.",
        ActionLevel.L2,
        SideEffectLevel.MEDIUM,
        ["domain"],
    ),
    (
        "cancel_host_isolation",
        "Cancel host isolation.",
        ActionLevel.L3,
        SideEffectLevel.HIGH,
        ["host"],
    ),
    (
        "restore_file",
        "Restore a quarantined file.",
        ActionLevel.L3,
        SideEffectLevel.HIGH,
        ["file"],
    ),
    (
        "restore_account",
        "Re-enable a disabled account.",
        ActionLevel.L3,
        SideEffectLevel.HIGH,
        ["account"],
    ),
    (
        "close_false_positive_ticket",
        "Close a false-positive ticket created earlier.",
        ActionLevel.L1,
        SideEffectLevel.LOW,
        ["ticket"],
    ),
)


def _rollback_meta(
    name: str,
    description: str,
    action_level: ActionLevel,
    side_effect_level: SideEffectLevel,
    target_types: list[str],
) -> ToolMeta:
    input_model = TOOL_INPUT_MODELS[name]
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.ROLLBACK,
        description=description,
        action_category=ActionCategory.ROLLBACK,
        routing_kind=RoutingKind.OWNER_ROUTED,
        supported_execution_owners=[
            ExecutionOwner.XDR_MANAGED,
            ExecutionOwner.DIRECT_TOOL,
        ],
        required_disposition_intent_by_owner=default_rollback_intents(),
        required_capabilities=["entity_response"],
        side_effect_level=side_effect_level,
        action_level=action_level,
        idempotency=True,
        async_mode=True,
        rollback_supported=False,
        executable=True,
        target_types=target_types,
        input_schema=input_model.model_json_schema(),
        output_schema={"$ref": "ActionExecutionJob"},
    )


ROLLBACK_TOOL_METAS: list[ToolMeta] = [
    _rollback_meta(name, desc, level, se, targets)
    for name, desc, level, se, targets in _ROLLBACK_SPECS
]
