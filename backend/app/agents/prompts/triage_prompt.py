"""TriageAgent LLM prompt templates (ISSUE-032 / ISSUE-251).

Provides a compact JSON-only system prompt plus a helper to build the message
list. ``TriageLLMResponse`` accepts a tolerant wire shape (optional
``entity_id``, ignore unknown keys, coerce unknown ``event_type``) and
materializes a domain ``EntitySet`` for downstream validation.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.llm.base import LLMMessage
from app.models.entities import EntitySet
from app.models.enums import EventType

_MAX_TRIAGE_SUMMARY_CHARS = 512
_ENTITY_ID_RE = re.compile(r"[^a-z0-9]+")
_IP_SCOPES = frozenset({"external", "internal", "unknown"})


def _slug_entity_id(prefix: str, value: str) -> str:
    """Stable id from natural key; hash suffix prevents punctuation collisions."""

    raw = (value or "").strip().lower()
    cleaned = _ENTITY_ID_RE.sub("", raw)[:24] or "unknown"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{cleaned}-{digest}"


_ENTITY_ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "accounts": frozenset(
        {
            "entity_id",
            "entity_type",
            "username",
            "domain",
            "display_name",
            "source_refs",
            "attributes",
        }
    ),
    "hosts": frozenset(
        {"entity_id", "entity_type", "hostname", "ip", "os", "source_refs", "attributes"}
    ),
    "ips": frozenset({"entity_id", "entity_type", "address", "scope", "source_refs", "attributes"}),
    "domains": frozenset({"entity_id", "entity_type", "fqdn", "source_refs", "attributes"}),
    "processes": frozenset(
        {
            "entity_id",
            "entity_type",
            "name",
            "pid",
            "command_line",
            "hash",
            "source_refs",
            "attributes",
        }
    ),
    "files": frozenset(
        {"entity_id", "entity_type", "path", "name", "hash", "source_refs", "attributes"}
    ),
}


def _fill_entity_id(item: dict[str, Any], *, prefix: str, natural_key: str) -> dict[str, Any]:
    entity_id = item.get("entity_id")
    if isinstance(entity_id, str) and entity_id.strip():
        return item
    natural = item.get(natural_key)
    if not isinstance(natural, str) or not natural.strip():
        for key in ("name", "address", "hostname", "fqdn", "username", "path"):
            candidate = item.get(key)
            if isinstance(candidate, str) and candidate.strip():
                natural = candidate
                break
        else:
            natural = "unknown"
    item["entity_id"] = _slug_entity_id(prefix, str(natural))
    return item


def _coerce_entity_list(
    raw: Any,
    *,
    category: str,
    prefix: str,
    natural_key: str,
    default_entity_type: str,
) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    allowed = _ENTITY_ALLOWED_FIELDS[category]
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cleaned = {key: value for key, value in item.items() if key in allowed}
        cleaned.setdefault("entity_type", default_entity_type)
        if "source_refs" in cleaned and not isinstance(cleaned["source_refs"], list):
            cleaned.pop("source_refs", None)
        if "attributes" in cleaned and not isinstance(cleaned["attributes"], dict):
            cleaned.pop("attributes", None)
        if category == "ips" and "scope" in cleaned:
            scope = str(cleaned.get("scope") or "").strip().lower()
            cleaned["scope"] = scope if scope in _IP_SCOPES else "unknown"
        out.append(_fill_entity_id(cleaned, prefix=prefix, natural_key=natural_key))
    return out


def coerce_entities_payload(entities: Any) -> Any:
    """Normalize LLM entity payload: keep known fields, fill missing entity_id."""

    if isinstance(entities, EntitySet):
        return entities
    if not isinstance(entities, dict):
        return {
            "accounts": [],
            "hosts": [],
            "ips": [],
            "domains": [],
            "processes": [],
            "files": [],
        }
    return {
        "accounts": _coerce_entity_list(
            entities.get("accounts"),
            category="accounts",
            prefix="acct",
            natural_key="username",
            default_entity_type="account",
        ),
        "hosts": _coerce_entity_list(
            entities.get("hosts"),
            category="hosts",
            prefix="host",
            natural_key="hostname",
            default_entity_type="host",
        ),
        "ips": _coerce_entity_list(
            entities.get("ips"),
            category="ips",
            prefix="ip",
            natural_key="address",
            default_entity_type="ip",
        ),
        "domains": _coerce_entity_list(
            entities.get("domains"),
            category="domains",
            prefix="dom",
            natural_key="fqdn",
            default_entity_type="domain",
        ),
        "processes": _coerce_entity_list(
            entities.get("processes"),
            category="processes",
            prefix="proc",
            natural_key="name",
            default_entity_type="process",
        ),
        "files": _coerce_entity_list(
            entities.get("files"),
            category="files",
            prefix="file",
            natural_key="name",
            default_entity_type="file",
        ),
    }


class TriageLLMResponse(BaseModel):
    """Wire model for ``triage_extract`` structured output (ISSUE-251).

    Tolerant on purpose: real models often omit ``entity_id``, add commentary
    keys, or invent unknown event types. Domain ``EntitySet`` remains strict;
    this wrapper coerces then re-validates into entity models.
    """

    model_config = ConfigDict(extra="ignore")

    event_type: EventType = EventType.OTHER
    entities: EntitySet = Field(default_factory=EntitySet)
    decision_summary: str = Field(default="", max_length=_MAX_TRIAGE_SUMMARY_CHARS)
    # Deprecated ISSUE-131: legacy key retained for parse compatibility only.
    reasoning: str = Field(default="", deprecated=True)

    @model_validator(mode="before")
    @classmethod
    def _coerce_wire_payload(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        data["entities"] = coerce_entities_payload(data.get("entities"))
        if "decision_summary" not in data or data.get("decision_summary") is None:
            data["decision_summary"] = ""
        return data

    @field_validator("event_type", mode="before")
    @classmethod
    def _coerce_event_type(cls, value: Any) -> Any:
        if isinstance(value, EventType):
            return value
        if isinstance(value, str):
            try:
                return EventType(value)
            except ValueError:
                return EventType.OTHER
        return EventType.OTHER

    @field_validator("decision_summary")
    @classmethod
    def _bound_summary(cls, value: str) -> str:
        return (value or "")[:_MAX_TRIAGE_SUMMARY_CHARS]

    @field_validator("reasoning")
    @classmethod
    def _reject_legacy_reasoning(cls, value: str) -> str:
        return ""


# Compact contract: one short shape example (not multi-entity few-shots).
# entity_id is optional — server fills it when omitted (ISSUE-251).
TRIAGE_SYSTEM_PROMPT: str = (
    "You are a security triage specialist. Return a single JSON object only "
    "(no markdown fences, no commentary) with shape:\n"
    '{"event_type":"<enum>","entities":{"accounts":[],"hosts":[],"ips":[],'
    '"domains":[],"processes":[],"files":[]},"decision_summary":"<short>"}\n\n'
    "event_type must be exactly one of: data_exfiltration, insider_threat, "
    "malicious_process, suspicious_domain, lateral_movement, host_compromise, "
    "account_anomaly, other.\n\n"
    "Entity object fields (omit entity_id if unsure — server will assign):\n"
    '- accounts: {"username":"..."}\n'
    '- hosts: {"hostname":"..."}\n'
    '- ips: {"address":"...","scope":"external|internal|unknown"}\n'
    '- domains: {"fqdn":"..."}\n'
    '- processes: {"name":"..."}\n'
    '- files: {"name":"..."}\n'
    "Use empty lists for absent categories. decision_summary max 512 chars; "
    "never include chain-of-thought.\n\n"
    "Minimal example:\n"
    '{"event_type":"account_anomaly","entities":{"accounts":[{"username":'
    '"svc-backup"}],"hosts":[{"hostname":"PC-OPS-01"}],"ips":[{"address":'
    '"10.50.1.10","scope":"internal"}],"domains":[],"processes":[],"files":[]},'
    '"decision_summary":"Single failed login from internal IP."}'
)


def build_triage_messages(alert_text: str) -> list[LLMMessage]:
    """Return ``[system, user]`` messages for the LLM entity-extraction call.

    Args:
        alert_text: The raw alert text / summary to parse.  Must be a non-empty
            string.  Callers are responsible for truncating excessively long
            inputs before calling this function.

    Returns:
        A two-element message list ready for ``BaseLLMClient.chat``.

    Raises:
        ValueError: If *alert_text* is None or an empty string.
    """
    if not alert_text or not isinstance(alert_text, str):
        raise ValueError(
            f"alert_text must be a non-empty string, got {type(alert_text).__name__!r}"
        )
    return [
        LLMMessage(role="system", content=TRIAGE_SYSTEM_PROMPT),
        LLMMessage(
            role="user",
            content=f"Parse this alert and respond with JSON only:\n{alert_text}",
        ),
    ]


__all__ = [
    "TriageLLMResponse",
    "TRIAGE_SYSTEM_PROMPT",
    "build_triage_messages",
    "coerce_entities_payload",
]
