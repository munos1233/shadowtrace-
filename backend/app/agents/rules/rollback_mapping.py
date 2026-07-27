"""Canonical response→rollback tool mapping (ISSUE-061).

Re-exports ``RESPONSE_ROLLBACK_MAP`` from the tool spec layer so that
the RollbackService has a single, stable import point.

Non-rollbackable actions (issue spec §4.5):
    force_logout, reset_password, revoke_token, notify_security_team
These are NOT in the mapping and will return ``rollback_supported=False``
at the ToolMeta level.
"""

from __future__ import annotations

from app.tools.specs.response import RESPONSE_ROLLBACK_MAP

ROLLBACK_MAPPING: dict[str, str] = dict(RESPONSE_ROLLBACK_MAP)
"""Maps response tool names to their canonical rollback counterparts."""

# Actions explicitly listed as non-rollbackable in the spec.
_NON_ROLLBACKABLE: frozenset[str] = frozenset(
    {
        "force_logout",
        "reset_password",
        "revoke_token",
        "notify_security_team",
    }
)


def is_rollbackable(tool_name: str) -> bool:
    """Return True if *tool_name* has a defined rollback counterpart.

    Explicitly short-circuits on the spec-mandated non-rollbackable set so
    that a tool accidentally added to the mapping is still blocked
    (defence-in-depth, ISSUE-061 §输入上下文).
    """
    if tool_name in _NON_ROLLBACKABLE:
        return False
    return tool_name in ROLLBACK_MAPPING


def get_rollback_tool(tool_name: str) -> str | None:
    """Return the rollback tool name for *tool_name*, or None.

    Also checks ``_NON_ROLLBACKABLE`` for defence-in-depth; a tool in
    that set will never return a mapping even if accidentally added to
    ``RESPONSE_ROLLBACK_MAP``.
    """
    if tool_name in _NON_ROLLBACKABLE:
        return None
    return ROLLBACK_MAPPING.get(tool_name)


def get_source_tool(rollback_tool_name: str) -> str | None:
    """Inverse lookup: return the response tool for a given rollback tool name."""
    for response_tool, rb_tool in ROLLBACK_MAPPING.items():
        if rb_tool == rollback_tool_name:
            return response_tool
    return None


# Independent readback tools used to confirm a rollback reversed the original
# effect (ISSUE-061 §统一命名 point 4).  ``None`` means no readback surface
# exists — callers may treat a successful rollback execution as ``skipped``.
ROLLBACK_VERIFY_MAP: dict[str, str | None] = {
    "unblock_ip": "check_ip_block_status",
    "unblock_domain": "check_domain_block_status",
    "cancel_host_isolation": "check_host_isolation_status",
    "restore_file": "check_file_quarantine_status",
    "restore_account": "check_account_status",
    "close_false_positive_ticket": None,
}


def get_rollback_verify_tool(rollback_tool_name: str) -> str | None:
    """Return the readback verification tool for *rollback_tool_name*, or None."""
    return ROLLBACK_VERIFY_MAP.get(rollback_tool_name)


__all__ = [
    "ROLLBACK_MAPPING",
    "ROLLBACK_VERIFY_MAP",
    "get_rollback_tool",
    "get_rollback_verify_tool",
    "get_source_tool",
    "is_rollbackable",
]
