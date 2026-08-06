"""Event classification_source derivation + human override helpers (ISSUE-209).

``classification_source`` is a **read-only derived** field. Machine provenance
continues to use only the existing ``event_type_from_*`` degraded_flags
(ISSUE-197). Human overrides are persisted separately as
``EventContext.classification_override`` (and mirrored into
``security_event.event_context_snapshot`` for list/detail without Redis).
"""

from __future__ import annotations

from typing import Any

from app.models.enums import ClassificationSource

CLASSIFICATION_OVERRIDE_KEY = "classification_override"
TRIAGE_RESULT_KEY = "triage_result"
_LLM_FALLBACK_FLAG = "event_type_from_llm_fallback"
_HEURISTIC_FLAG = "event_type_from_heuristic"


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


def apply_event_type_to_triage_payload(
    triage: Any,
    event_type: str,
) -> tuple[Any, bool]:
    """Copy triage payload with ``event_type`` synced; return ``(payload, changed)``.

    Used so human classification overrides keep ResponseAgent rule selection
    aligned with ``SecurityEvent.event_type`` when reinvestigate is skipped.
    """
    if triage is None:
        return None, False

    if isinstance(triage, dict):
        current = str(triage.get("event_type") or "")
        if current == event_type:
            return triage, False
        updated = dict(triage)
        updated["event_type"] = event_type
        return updated, True

    dump = getattr(triage, "model_dump", None)
    if callable(dump):
        try:
            data = dump(mode="json")
        except TypeError:
            data = dump()
        if not isinstance(data, dict):
            return triage, False
        current = str(data.get("event_type") or "")
        if current == event_type:
            return triage, False
        data["event_type"] = event_type
        return data, True

    return triage, False


def build_human_classification_override(
    *,
    event_type: str,
    reason: str,
    operator: str,
    previous_event_type: str,
    updated_at: str,
    reinvestigate: bool = False,
) -> dict[str, Any]:
    """Build the durable human override payload stored in context / snapshot."""
    return {
        "source": "human",
        "event_type": event_type,
        "previous_event_type": previous_event_type,
        "reason": reason,
        "operator": operator,
        "updated_at": updated_at,
        "reinvestigate": bool(reinvestigate),
    }


def human_override_event_type(
    classification_override: dict[str, Any] | None,
) -> str | None:
    """Return the human-overridden event_type value, or None if not applicable."""
    if not isinstance(classification_override, dict):
        return None
    if str(classification_override.get("source") or "") != "human":
        return None
    raw = classification_override.get("event_type")
    if raw is None:
        return None
    value = str(raw).strip()
    return value or None
