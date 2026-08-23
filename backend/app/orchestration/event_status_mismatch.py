"""Shared EventStatus caller/DB mismatch detection (ISSUE-376).

``WorkflowRuntime.set_execution_substate`` fail-closes when the caller passes a
stale EventStatus. Graph nodes, resume, and SuperAgent must classify that
error the same way — never copy the message string.
"""

from __future__ import annotations

from app.core.errors import ValidationError

EVENT_STATUS_MISMATCH_MSG = "caller EventStatus does not match authoritative state"


def is_event_status_mismatch(exc: BaseException) -> bool:
    """True when substate CAS rejected a stale caller EventStatus."""
    return isinstance(exc, ValidationError) and EVENT_STATUS_MISMATCH_MSG in str(exc)
