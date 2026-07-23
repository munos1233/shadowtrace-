"""Conservative rule-based response actions per EventType (ISSUE-057).

Used when playbook KB and LLM are unavailable. Each EventType maps severity bands
to a ordered list of tool names (non-destructive defaults for ``other``).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import EventType, Severity

# Response tools only — query tools never appear here.
RESPONSE_ONLY_TOOLS = frozenset(
    {
        "notify_security_team",
        "create_ticket",
        "block_ip",
        "block_domain",
        "isolate_host",
        "quarantine_file",
        "block_process",
        "scan_host_for_virus",
        "disable_account",
        "force_logout",
        "reset_password",
        "revoke_token",
    }
)


@dataclass(frozen=True)
class ResponseRuleAction:
    """One rule-suggested response tool with stable ordering metadata."""

    tool_name: str
    step_order: int = 0


def _ticket(step: int = 99) -> ResponseRuleAction:
    return ResponseRuleAction("create_ticket", step_order=step)


def _notify(step: int = 100) -> ResponseRuleAction:
    return ResponseRuleAction("notify_security_team", step_order=step)


def _actions(*items: ResponseRuleAction) -> list[ResponseRuleAction]:
    for item in items:
        if item.tool_name not in RESPONSE_ONLY_TOOLS:
            raise ValueError(f"invalid response tool in DEFAULT_RESPONSE_RULES: {item.tool_name}")
    return list(items)


# Severity → ordered conservative tool list (action_level resolved from ToolMeta).
DEFAULT_RESPONSE_RULES: dict[EventType, dict[Severity, list[ResponseRuleAction]]] = {
    EventType.ACCOUNT_ANOMALY: {
        Severity.LOW: _actions(_ticket()),
        Severity.MEDIUM: _actions(
            ResponseRuleAction("disable_account", 1),
            _ticket(2),
            _notify(3),
        ),
        Severity.HIGH: _actions(
            ResponseRuleAction("disable_account", 1),
            ResponseRuleAction("force_logout", 2),
            ResponseRuleAction("block_ip", 3),
            _ticket(4),
            _notify(5),
        ),
        Severity.CRITICAL: _actions(
            ResponseRuleAction("disable_account", 1),
            ResponseRuleAction("force_logout", 2),
            ResponseRuleAction("revoke_token", 3),
            ResponseRuleAction("block_ip", 4),
            _ticket(5),
            _notify(6),
        ),
    },
    EventType.HOST_COMPROMISE: {
        Severity.LOW: _actions(_ticket()),
        Severity.MEDIUM: _actions(
            ResponseRuleAction("isolate_host", 1),
            ResponseRuleAction("scan_host_for_virus", 2),
            _ticket(3),
        ),
        Severity.HIGH: _actions(
            ResponseRuleAction("isolate_host", 1),
            ResponseRuleAction("block_ip", 2),
            ResponseRuleAction("quarantine_file", 3),
            _ticket(4),
            _notify(5),
        ),
        Severity.CRITICAL: _actions(
            ResponseRuleAction("isolate_host", 1),
            ResponseRuleAction("block_ip", 2),
            ResponseRuleAction("quarantine_file", 3),
            ResponseRuleAction("block_process", 4),
            _ticket(5),
            _notify(6),
        ),
    },
    EventType.DATA_EXFILTRATION: {
        Severity.LOW: _actions(_ticket()),
        Severity.MEDIUM: _actions(
            ResponseRuleAction("block_ip", 1),
            ResponseRuleAction("block_domain", 2),
            _ticket(3),
        ),
        Severity.HIGH: _actions(
            ResponseRuleAction("disable_account", 1),
            ResponseRuleAction("block_ip", 2),
            _ticket(3),
            _notify(4),
        ),
        Severity.CRITICAL: _actions(
            ResponseRuleAction("disable_account", 1),
            ResponseRuleAction("block_ip", 2),
            ResponseRuleAction("block_domain", 3),
            _ticket(4),
            _notify(5),
        ),
    },
    EventType.INSIDER_THREAT: {
        Severity.LOW: _actions(_ticket()),
        Severity.MEDIUM: _actions(
            ResponseRuleAction("disable_account", 1),
            _ticket(2),
        ),
        Severity.HIGH: _actions(
            ResponseRuleAction("disable_account", 1),
            ResponseRuleAction("revoke_token", 2),
            ResponseRuleAction("block_ip", 3),
            _ticket(4),
            _notify(5),
        ),
        Severity.CRITICAL: _actions(
            ResponseRuleAction("disable_account", 1),
            ResponseRuleAction("revoke_token", 2),
            ResponseRuleAction("force_logout", 3),
            ResponseRuleAction("block_ip", 4),
            _ticket(5),
            _notify(6),
        ),
    },
    EventType.MALICIOUS_PROCESS: {
        Severity.LOW: _actions(_ticket()),
        Severity.MEDIUM: _actions(
            ResponseRuleAction("block_process", 1),
            ResponseRuleAction("isolate_host", 2),
            _ticket(3),
        ),
        Severity.HIGH: _actions(
            ResponseRuleAction("block_process", 1),
            ResponseRuleAction("isolate_host", 2),
            ResponseRuleAction("quarantine_file", 3),
            _ticket(4),
            _notify(5),
        ),
        Severity.CRITICAL: _actions(
            ResponseRuleAction("block_process", 1),
            ResponseRuleAction("isolate_host", 2),
            ResponseRuleAction("quarantine_file", 3),
            ResponseRuleAction("block_ip", 4),
            _ticket(5),
            _notify(6),
        ),
    },
    EventType.SUSPICIOUS_DOMAIN: {
        Severity.LOW: _actions(_ticket()),
        Severity.MEDIUM: _actions(
            ResponseRuleAction("block_domain", 1),
            _ticket(2),
        ),
        Severity.HIGH: _actions(
            ResponseRuleAction("block_domain", 1),
            ResponseRuleAction("block_ip", 2),
            _ticket(3),
            _notify(4),
        ),
        Severity.CRITICAL: _actions(
            ResponseRuleAction("block_domain", 1),
            ResponseRuleAction("block_ip", 2),
            ResponseRuleAction("isolate_host", 3),
            _ticket(4),
            _notify(5),
        ),
    },
    EventType.LATERAL_MOVEMENT: {
        Severity.LOW: _actions(_ticket()),
        Severity.MEDIUM: _actions(
            ResponseRuleAction("isolate_host", 1),
            ResponseRuleAction("block_ip", 2),
            _ticket(3),
        ),
        Severity.HIGH: _actions(
            ResponseRuleAction("isolate_host", 1),
            ResponseRuleAction("block_ip", 2),
            ResponseRuleAction("disable_account", 3),
            _ticket(4),
            _notify(5),
        ),
        Severity.CRITICAL: _actions(
            ResponseRuleAction("isolate_host", 1),
            ResponseRuleAction("block_ip", 2),
            ResponseRuleAction("disable_account", 3),
            ResponseRuleAction("quarantine_file", 4),
            _ticket(5),
            _notify(6),
        ),
    },
    EventType.OTHER: {
        Severity.LOW: _actions(_ticket()),
        Severity.MEDIUM: _actions(_ticket(), _notify()),
        Severity.HIGH: _actions(_ticket(), _notify()),
        Severity.CRITICAL: _actions(_ticket(), _notify()),
    },
}

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def get_rule_actions(event_type: EventType, severity: Severity) -> list[ResponseRuleAction]:
    """Return the conservative rule action set for *event_type* at *severity*.

    Falls back to the nearest lower severity band when an exact band is missing.
    """
    table = DEFAULT_RESPONSE_RULES.get(event_type) or DEFAULT_RESPONSE_RULES[EventType.OTHER]
    idx = _SEVERITY_ORDER.index(severity)
    for band in reversed(_SEVERITY_ORDER[: idx + 1]):
        actions = table.get(band)
        if actions:
            return list(actions)
    return list(table.get(Severity.LOW, [_ticket()]))


__all__ = [
    "DEFAULT_RESPONSE_RULES",
    "RESPONSE_ONLY_TOOLS",
    "ResponseRuleAction",
    "get_rule_actions",
]
