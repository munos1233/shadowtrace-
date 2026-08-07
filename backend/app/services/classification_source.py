"""Derived ``classification_source`` + triage ORM rewrite helpers (ISSUE-209/211).

``classification_source`` is a **read-only derived** field. Machine provenance
continues to use only the existing ``event_type_from_*`` degraded_flags
(ISSUE-197). Human overrides are persisted separately as
``EventContext.classification_override`` (mirrored into
``security_event.event_context_snapshot``).

ISSUE-211 adds list consistency: after triage persists ``triage_result``,
``SecurityEvent.event_type`` may be rewritten to match — unless the event is in
an active disposition stage (skip + audit/degraded, never 409 the background
path).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from app.models.enums import ClassificationSource, EventStatus

CLASSIFICATION_OVERRIDE_KEY = "classification_override"
TRIAGE_RESULT_KEY = "triage_result"

_LLM_FALLBACK_FLAG = "event_type_from_llm_fallback"
_HEURISTIC_FLAG = "event_type_from_heuristic"

# ISSUE-211 — ORM rewrite skip / failure observability (not machine provenance).
EVENT_TYPE_ORM_REWRITE_SKIPPED_FLAG = "event_type_orm_rewrite_skipped"
EVENT_TYPE_ORM_REWRITE_FAILED_FLAG = "event_type_orm_rewrite_failed"
ORM_REWRITE_SKIP_HINT = "列表类型未回写：活跃处置中"
ORM_REWRITE_SKIP_HUMAN_HINT = "列表类型未回写：存在人工分类覆盖"

# Same lock set as human PATCH (ISSUE-209); machine path skips instead of 409.
CLASSIFICATION_LOCKED_STATUSES: frozenset[EventStatus] = frozenset(
    {
        EventStatus.EXECUTING_RESPONSE,
        EventStatus.VERIFYING,
    }
)


class OrmEventTypeRewriteOutcome(StrEnum):
    """Result of ``EventService.rewrite_event_type_from_triage``."""

    APPLIED = "applied"
    NOOP = "noop"
    SKIPPED_GATE = "skipped_gate"
    SKIPPED_LOCKED = "skipped_locked"
    SKIPPED_HUMAN = "skipped_human"
    SKIPPED_MISSING = "skipped_missing"
    FAILED = "failed"


def _flag_present(flags: list[str], flag_name: str) -> bool:
    prefix = f"{flag_name}="
    return any(f == flag_name or str(f).startswith(prefix) for f in flags)


def classification_override_from_snapshot(
    snapshot: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Extract durable human override payload from event_context_snapshot."""
    if not isinstance(snapshot, dict):
        return None
    raw = snapshot.get(CLASSIFICATION_OVERRIDE_KEY)
    return dict(raw) if isinstance(raw, dict) else None


def derive_classification_source(
    *,
    classification_override: dict[str, Any] | None = None,
    degraded_flags: list[str] | None = None,
    event_context_snapshot: dict[str, Any] | None = None,
) -> ClassificationSource:
    """Derive ``classification_source`` per ISSUE-209 / ISSUE-211 mapping table.

    Priority (top → bottom):
    1. Latest human PATCH marker → ``human``
    2. ``event_type_from_llm_fallback`` flag → ``llm_fallback``
    3. ``event_type_from_heuristic`` flag → ``heuristic``
    4. else → ``source``
    """
    override = classification_override
    if override is None:
        override = classification_override_from_snapshot(event_context_snapshot)
    if isinstance(override, dict) and str(override.get("source") or "") == "human":
        return ClassificationSource.HUMAN
    flags = [str(f) for f in (degraded_flags or [])]
    if _flag_present(flags, _LLM_FALLBACK_FLAG):
        return ClassificationSource.LLM_FALLBACK
    if _flag_present(flags, _HEURISTIC_FLAG):
        return ClassificationSource.HEURISTIC
    return ClassificationSource.SOURCE


def should_skip_orm_event_type_rewrite(status: EventStatus | str) -> bool:
    """True when triage must not rewrite list ``event_type`` (active disposition)."""
    if isinstance(status, EventStatus):
        return status in CLASSIFICATION_LOCKED_STATUSES
    try:
        return EventStatus(str(status)) in CLASSIFICATION_LOCKED_STATUSES
    except ValueError:
        return False


def snapshot_has_human_classification_override(
    snapshot: dict[str, Any] | None,
) -> bool:
    """True when ORM snapshot mirrors a durable human PATCH marker (ISSUE-209)."""
    override = classification_override_from_snapshot(snapshot)
    return isinstance(override, dict) and str(override.get("source") or "") == "human"
