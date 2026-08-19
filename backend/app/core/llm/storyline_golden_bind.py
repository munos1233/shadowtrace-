"""Bind storyline_generate Mock goldens to the current prompt evidence catalog.

Production MockLLM must not emit timeline entries without input ``evidence_id``
values. Tests must not be the only place this binding happens.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from app.core.llm.base import LLMMessage

_CONTEXT_MARKER = "Context:\n"


def parse_storyline_timestamp(value: Any) -> datetime | None:
    """Parse golden/catalog timestamps (Z or offset) into aware UTC datetimes."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def extract_evidence_catalog(messages: list[LLMMessage]) -> list[dict[str, Any]]:
    """Read the evidence list from a storyline_generate user prompt."""
    for msg in messages:
        if msg.role != "user":
            continue
        content = msg.content or ""
        if _CONTEXT_MARKER not in content:
            continue
        try:
            payload = json.loads(content.split(_CONTEXT_MARKER, 1)[1])
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        evidence = payload.get("evidence")
        if isinstance(evidence, list):
            return [item for item in evidence if isinstance(item, dict)]
    return []


def bind_storyline_evidence_ids(
    content: dict[str, Any],
    evidence_list: list[dict[str, Any]],
) -> dict[str, Any]:
    """Fill golden timeline ``evidence_id`` slots from the prompt catalog.

    Matching prefers an already-valid catalog id, then the closest timestamp.
    Entries that cannot be grounded keep an empty ``evidence_id`` so the
    StorylineService drops them instead of stamping ``generated_by=llm``.
    """
    catalog_ids = {
        str(item.get("evidence_id") or "").strip()
        for item in evidence_list
        if str(item.get("evidence_id") or "").strip()
    }
    used: set[str] = set()
    phases = content.get("phases")
    if not isinstance(phases, list):
        return content
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        entries = phase.get("entries")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            existing = str(entry.get("evidence_id") or "").strip()
            if existing and existing in catalog_ids and existing not in used:
                entry["evidence_id"] = existing
                used.add(existing)
                continue
            entry["evidence_id"] = _closest_unused_evidence_id(
                entry.get("timestamp"),
                evidence_list,
                used=used,
            )
            if entry["evidence_id"]:
                used.add(entry["evidence_id"])
    return content


def _closest_unused_evidence_id(
    timestamp: Any,
    evidence_list: list[dict[str, Any]],
    *,
    used: set[str],
) -> str:
    entry_ts = parse_storyline_timestamp(timestamp)
    if entry_ts is None or not evidence_list:
        return ""
    best_id = ""
    best_delta: float | None = None
    for item in evidence_list:
        eid = str(item.get("evidence_id") or "").strip()
        if not eid or eid in used:
            continue
        ev_ts = parse_storyline_timestamp(item.get("timestamp"))
        if ev_ts is None:
            continue
        delta = abs((ev_ts - entry_ts).total_seconds())
        if best_delta is None or delta < best_delta:
            best_delta = delta
            best_id = eid
    return best_id


def bind_storyline_golden(content_value: Any, messages: list[LLMMessage]) -> Any:
    """Bind a loaded golden ``content`` value (dict or JSON string) in place."""
    payload = content_value
    if isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            return content_value
        payload = decoded
    if not isinstance(payload, dict):
        return content_value
    catalog = extract_evidence_catalog(messages)
    return bind_storyline_evidence_ids(payload, catalog)


__all__ = [
    "bind_storyline_evidence_ids",
    "bind_storyline_golden",
    "extract_evidence_catalog",
    "parse_storyline_timestamp",
]
