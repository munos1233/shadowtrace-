"""Shared helpers for caller vs authoritative EventStatus mismatch (ISSUE-376)."""

from __future__ import annotations

from app.core.errors import ValidationError

EVENT_STATUS_MISMATCH_MSG = "caller EventStatus does not match authoritative state"


def is_event_status_mismatch_error(exc: BaseException) -> bool:
    """Return True when *exc* is a fail-closed ValidationError status mismatch."""
    return isinstance(exc, ValidationError) and EVENT_STATUS_MISMATCH_MSG in str(exc)


__all__ = ["EVENT_STATUS_MISMATCH_MSG", "is_event_status_mismatch_error"]
