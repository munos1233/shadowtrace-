"""Shared live/XDR writeback side-effect fence (ISSUE-222)."""

from __future__ import annotations

from app.core.config import Settings, get_settings, is_mock_disposition_mode
from app.core.errors import ValidationError
from app.models.enums import ExecutionOwner

WRITEBACK_FENCE_BLOCKED_ERROR_CODE = "writeback_fence_blocked"


def assert_live_side_effects_allowed(
    *,
    settings: Settings | None = None,
    action_id: str | None = None,
) -> None:
    """Block when ``BLOCK_LIVE_ACTION_EXECUTION`` is enabled (ISSUE-059 P0 freeze).

    Not to be confused with ``ALLOW_LIVE_SIDE_EFFECTS``, which only gates live
    ToolProvider adapter registration (``configure_tool_registry``).
    """
    resolved = settings or get_settings()
    if resolved.block_live_action_execution:
        details: dict[str, object] = {"block_live_action_execution": True}
        if action_id is not None:
            details["action_id"] = action_id
        raise ValidationError(
            "live action execution is frozen (ISSUE-059 P0); "
            "set BLOCK_LIVE_ACTION_EXECUTION=false to allow execute_plan",
            details=details,
        )


def assert_xdr_writeback_allowed(
    *,
    settings: Settings | None = None,
    action_id: str | None = None,
    execution_owner: ExecutionOwner,
) -> None:
    """Block live disposition writeback unless ALLOW_XDR_WRITEBACK is enabled."""
    if execution_owner is not ExecutionOwner.XDR_MANAGED:
        return
    resolved = settings or get_settings()
    if not is_mock_disposition_mode(resolved.disposition_mode) and not resolved.allow_xdr_writeback:
        details: dict[str, object] = {"disposition_mode": resolved.disposition_mode}
        if action_id is not None:
            details["action_id"] = action_id
        raise ValidationError(
            "xdr writeback is not enabled for live disposition mode",
            details=details,
        )


def assert_writeback_side_effects_allowed(
    *,
    settings: Settings | None = None,
    action_id: str | None = None,
    execution_owner: ExecutionOwner | None,
) -> None:
    """Combined claim/delivery fence: live side effects + XDR writeback.

    ``execution_owner=None`` (system/verification actions) skips the XDR gate;
    live side-effect fence still applies.
    """
    assert_live_side_effects_allowed(settings=settings, action_id=action_id)
    if execution_owner is None:
        return
    assert_xdr_writeback_allowed(
        settings=settings,
        action_id=action_id,
        execution_owner=execution_owner,
    )


__all__ = [
    "WRITEBACK_FENCE_BLOCKED_ERROR_CODE",
    "assert_live_side_effects_allowed",
    "assert_writeback_side_effects_allowed",
    "assert_xdr_writeback_allowed",
]
