"""Storyline prompt builder (ISSUE-051 / ISSUE-251)."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.llm.base import LLMMessage


class StorylineEntryLLM(BaseModel):
    """Wire entry — timestamp stays a string; service parses/filters later."""

    model_config = ConfigDict(extra="ignore")

    timestamp: str | None = None
    description: str = ""
    evidence_id: str = ""
    technique_id: str | None = None
    severity_hint: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_timestamp(cls, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @field_validator("description", "evidence_id", mode="before")
    @classmethod
    def _coerce_text(cls, value: Any) -> str:
        return "" if value is None else str(value)

    @field_validator("technique_id", "severity_hint", mode="before")
    @classmethod
    def _coerce_optional(cls, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class StorylinePhaseLLM(BaseModel):
    model_config = ConfigDict(extra="ignore")

    phase_order: int = 1
    phase_name: str = ""
    tactic: str | None = None
    narrative: str = ""
    entries: list[StorylineEntryLLM] = Field(default_factory=list)

    @field_validator("phase_name", "narrative", mode="before")
    @classmethod
    def _coerce_text(cls, value: Any) -> str:
        return "" if value is None else str(value)

    @field_validator("entries", mode="before")
    @classmethod
    def _coerce_entries(cls, value: Any) -> list[Any]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]


class StorylineLLMResponse(BaseModel):
    """Slim wire model for storyline_generate (ISSUE-251).

    Intentionally omits storyline_id / event_id / generated_by — server owns
    those. Nested TimelineEntry datetime validation is deferred to the service.
    """

    model_config = ConfigDict(extra="ignore")

    narrative_summary: str = ""
    phases: list[StorylinePhaseLLM] = Field(default_factory=list)

    @field_validator("narrative_summary", mode="before")
    @classmethod
    def _coerce_summary(cls, value: Any) -> str:
        return "" if value is None else str(value)

    @field_validator("phases", mode="before")
    @classmethod
    def _coerce_phases(cls, value: Any) -> list[Any]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @model_validator(mode="after")
    def _require_content(self) -> StorylineLLMResponse:
        if str(self.narrative_summary or "").strip():
            return self
        if any(str(phase.phase_name or "").strip() or phase.entries for phase in self.phases):
            return self
        raise ValueError("storyline requires narrative_summary or at least one phase")


def build_storyline_messages(
    *,
    evidence_entries: list[dict[str, Any]],
    technique_matches: list[dict[str, Any]],
    graph_paths: list[list[str]],
    entity_names: list[str],
    evidence_conflicts: list[dict[str, Any]] | None = None,
) -> list[LLMMessage]:
    """Build JSON-mode messages for attack storyline generation."""
    system = (
        "You are ShadowTrace StorylineService. Reconstruct the attack timeline "
        "from evidence, ATT&CK matches, and graph paths. Return a single JSON "
        "object only (no markdown fences, no commentary) with shape:\n"
        '{"narrative_summary":"<short>","phases":[{"phase_order":1,'
        '"phase_name":"initial_access|collection|staging|exfiltration|post_action",'
        '"tactic":null,"narrative":"...","entries":[{"timestamp":"ISO-8601",'
        '"description":"...","evidence_id":"evd-...","technique_id":null,'
        '"severity_hint":"low|medium|high|critical"}]}]}\n'
        "Use only evidence_id values present in the context. Omit entries you "
        "cannot ground. Do not invent storyline_id or event_id. No chain-of-thought."
    )
    compact_conflicts = [
        item
        for item in (evidence_conflicts or [])
        if isinstance(item, dict) and item.get("rule_name")
    ]
    if any(item.get("rule_name") == "iam_absent_but_edr_active" for item in compact_conflicts):
        system += (
            " evidence_conflicts includes iam_absent_but_edr_active: name that "
            "identity/endpoint conflict in the narrative. Do not reduce it to a "
            "conflict count."
        )
    # Keep context compact: do not re-embed the schema inside the payload.
    context = {
        "evidence": evidence_entries,
        "attack_techniques": technique_matches,
        "graph_attack_paths": graph_paths,
        "key_entity_names": entity_names,
        "evidence_conflicts": compact_conflicts,
    }
    user = (
        "Generate the attack storyline and respond with JSON only.\n"
        f"Context:\n{json.dumps(context, ensure_ascii=False)}"
    )
    return [
        LLMMessage(role="system", content=system),
        LLMMessage(role="user", content=user),
    ]


__all__ = [
    "StorylineEntryLLM",
    "StorylineLLMResponse",
    "StorylinePhaseLLM",
    "build_storyline_messages",
]
