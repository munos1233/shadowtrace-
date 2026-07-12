"""Baseline response ToolMeta definitions (intro §4.5.2) including virtual disposition."""

from __future__ import annotations

from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    DispositionIntentKind,
    ExecutionOwner,
    ToolCategory,
)
from app.models.tool_meta import (
    TERMINAL_DISPOSITION_TOOL,
    RoutingKind,
    SideEffectLevel,
    ToolMeta,
    default_response_intents,
)
from app.tools.inputs import TOOL_INPUT_MODELS

# Canonical rollback mapping (intro §4.5 / ISSUE-061). Tools not listed here
# default to rollback_supported=False — never invent a similar-name substitute.
RESPONSE_ROLLBACK_MAP: dict[str, str] = {
    "block_ip": "unblock_ip",
    "block_domain": "unblock_domain",
    "isolate_host": "cancel_host_isolation",
    "quarantine_file": "restore_file",
    "disable_account": "restore_account",
    "create_ticket": "close_false_positive_ticket",
}


def _response_meta(
    name: str,
    *,
    description: str,
    action_level: ActionLevel,
    side_effect_level: SideEffectLevel,
    target_types: list[str],
    async_mode: bool = True,
    rollback_tool_name: str | None = None,
) -> ToolMeta:
    input_model = TOOL_INPUT_MODELS[name]
    rollback = rollback_tool_name if rollback_tool_name is not None else RESPONSE_ROLLBACK_MAP.get(
        name
    )
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.RESPONSE,
        description=description,
        action_category=ActionCategory.RESPONSE,
        routing_kind=RoutingKind.OWNER_ROUTED,
        supported_execution_owners=[
            ExecutionOwner.XDR_MANAGED,
            ExecutionOwner.DIRECT_TOOL,
        ],
        required_disposition_intent_by_owner=default_response_intents(),
        required_capabilities=["entity_response"],
        side_effect_level=side_effect_level,
        action_level=action_level,
        idempotency=True,
        async_mode=async_mode,
        rollback_supported=rollback is not None,
        rollback_tool_name=rollback,
        executable=True,
        target_types=target_types,
        input_schema=input_model.model_json_schema(),
        # Only async tools surface ActionExecutionJob on the job path;
        # sync tools keep the immediate ToolResult envelope only.
        output_schema={"$ref": "ActionExecutionJob"} if async_mode else {},
    )


def _virtual_disposition_meta() -> ToolMeta:
    input_model = TOOL_INPUT_MODELS[TERMINAL_DISPOSITION_TOOL]
    return ToolMeta(
        tool_name=TERMINAL_DISPOSITION_TOOL,
        tool_category=ToolCategory.RESPONSE,
        description=(
            "Deferred disposition-only virtual meta. Catalog/approval only; "
            "executed solely by DispositionAdapter as EVENT_STATUS_UPDATE."
        ),
        action_category=ActionCategory.RESPONSE,
        routing_kind=RoutingKind.DISPOSITION_ONLY,
        supported_execution_owners=[ExecutionOwner.XDR_MANAGED],
        required_disposition_intent_by_owner={
            ExecutionOwner.XDR_MANAGED: DispositionIntentKind.EVENT_STATUS_UPDATE
        },
        required_capabilities=["event_disposition"],
        side_effect_level=SideEffectLevel.MEDIUM,
        action_level=ActionLevel.L2,
        idempotency=True,
        async_mode=False,
        rollback_supported=False,
        executable=False,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        activation_condition="after_effect_resolution",
        target_types=["source_object"],
        input_schema=input_model.model_json_schema(),
    )


RESPONSE_TOOL_METAS: list[ToolMeta] = [
    # L1 — notify / ticket
    _response_meta(
        "notify_security_team",
        description="Notify the security team (low blast radius).",
        action_level=ActionLevel.L1,
        side_effect_level=SideEffectLevel.LOW,
        target_types=["channel"],
        async_mode=False,
        rollback_tool_name=None,
    ),
    _response_meta(
        "create_ticket",
        description="Create a security ticket / work order.",
        action_level=ActionLevel.L1,
        side_effect_level=SideEffectLevel.LOW,
        target_types=["ticket"],
        async_mode=False,
    ),
    # L2 — network blocks
    _response_meta(
        "block_ip",
        description="Block an IP address.",
        action_level=ActionLevel.L2,
        side_effect_level=SideEffectLevel.MEDIUM,
        target_types=["ip"],
    ),
    _response_meta(
        "block_domain",
        description="Block a domain.",
        action_level=ActionLevel.L2,
        side_effect_level=SideEffectLevel.MEDIUM,
        target_types=["domain"],
    ),
    # L3 — host / file / process / account disable
    _response_meta(
        "isolate_host",
        description="Isolate a host from the network.",
        action_level=ActionLevel.L3,
        side_effect_level=SideEffectLevel.HIGH,
        target_types=["host"],
    ),
    _response_meta(
        "quarantine_file",
        description="Quarantine a suspicious file.",
        action_level=ActionLevel.L3,
        side_effect_level=SideEffectLevel.HIGH,
        target_types=["file"],
    ),
    _response_meta(
        "block_process",
        description="Block a process hash/name. Rollback only if Provider declares it.",
        action_level=ActionLevel.L3,
        side_effect_level=SideEffectLevel.HIGH,
        target_types=["process"],
        rollback_tool_name=None,  # not in baseline rollback map
    ),
    _response_meta(
        "scan_host_for_virus",
        description="Trigger a host virus scan. Rollback only if Provider declares it.",
        action_level=ActionLevel.L3,
        side_effect_level=SideEffectLevel.MEDIUM,
        target_types=["host"],
        rollback_tool_name=None,
    ),
    _response_meta(
        "disable_account",
        description="Disable an account.",
        action_level=ActionLevel.L3,
        side_effect_level=SideEffectLevel.HIGH,
        target_types=["account"],
    ),
    _response_meta(
        "force_logout",
        description="Force logout of an account session.",
        action_level=ActionLevel.L3,
        side_effect_level=SideEffectLevel.MEDIUM,
        target_types=["account"],
        rollback_tool_name=None,
    ),
    # L4 — credential / token
    _response_meta(
        "reset_password",
        description="Reset an account password.",
        action_level=ActionLevel.L4,
        side_effect_level=SideEffectLevel.HIGH,
        target_types=["account"],
        rollback_tool_name=None,
    ),
    _response_meta(
        "revoke_token",
        description="Revoke an account token / session credential.",
        action_level=ActionLevel.L4,
        side_effect_level=SideEffectLevel.HIGH,
        target_types=["account"],
        rollback_tool_name=None,
    ),
    # Virtual disposition-only (not ToolProvider-executable)
    _virtual_disposition_meta(),
]
