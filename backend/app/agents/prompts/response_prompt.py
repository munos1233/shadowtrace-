"""Response plan LLM prompt builder (ISSUE-057 / ISSUE-251)."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.llm.base import LLMMessage
from app.models.agent_io import EvidenceOutput, RiskAssessment, TriageResult


class ResponseActionLLM(BaseModel):
    """One candidate action from response_plan structured output."""

    model_config = ConfigDict(extra="ignore")

    tool_name: str = ""
    target_type: str | None = None
    target: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""

    @field_validator("tool_name", "reason", mode="before")
    @classmethod
    def _coerce_text(cls, value: Any) -> str:
        return "" if value is None else str(value)

    @field_validator("target_type", "target", mode="before")
    @classmethod
    def _coerce_optional(cls, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @field_validator("parameters", mode="before")
    @classmethod
    def _coerce_parameters(cls, value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}


class ResponsePlanLLMResponse(BaseModel):
    """Slim wire model for response_plan (ISSUE-251)."""

    model_config = ConfigDict(extra="ignore")

    actions: list[ResponseActionLLM] = Field(default_factory=list)
    strategy_summary: str = ""

    @field_validator("actions", mode="before")
    @classmethod
    def _coerce_actions(cls, value: Any) -> list[Any]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @field_validator("strategy_summary", mode="before")
    @classmethod
    def _coerce_summary(cls, value: Any) -> str:
        return "" if value is None else str(value)

    @model_validator(mode="after")
    def _require_actions(self) -> ResponsePlanLLMResponse:
        usable = [action for action in self.actions if str(action.tool_name or "").strip()]
        if not usable:
            raise ValueError("response_plan requires at least one action with tool_name")
        self.actions = usable
        return self


def build_response_plan_messages(
    *,
    triage_result: TriageResult,
    risk_assessment: RiskAssessment,
    evidence_output: EvidenceOutput | None,
    available_tools: list[str],
    entities_summary: dict[str, Any],
) -> list[LLMMessage]:
    """Build JSON-mode messages requesting candidate response actions only."""
    system = (
        "You are ShadowTrace ResponseAgent. Propose a conservative disposition "
        "plan. Return a single JSON object only (no markdown fences, no commentary) "
        "with shape:\n"
        '{"actions":[{"tool_name":"...","target_type":"...","target":"...",'
        '"parameters":{},"reason":"..."}],"strategy_summary":"..."}\n'
        "Each action must use a tool_name from available_tools, include "
        "target_type and target when the tool requires an entity target, and must "
        "not invent tools or targets. Do not include "
        "update_source_event_disposition — the server appends deferred writeback "
        "actions when required. Prefer lower-risk actions first."
    )
    evidence_block: dict[str, Any] = {}
    if evidence_output is not None:
        evidence_block = {
            "overall_confidence": evidence_output.overall_confidence,
            "collection_status": evidence_output.collection_status.value,
            "evidence_count": len(evidence_output.evidence_list),
        }
    user_payload = {
        "event_type": triage_result.event_type.value,
        "severity": triage_result.severity.value,
        "risk_score": risk_assessment.risk_score,
        "risk_severity": risk_assessment.severity.value,
        "entities": entities_summary,
        "available_tools": sorted(available_tools),
        "evidence": evidence_block,
        "triage_reasoning": triage_result.reasoning[:500],
    }
    return [
        LLMMessage(role="system", content=system),
        LLMMessage(
            role="user",
            content=(
                "Propose the response plan and respond with JSON only.\n"
                f"Context:\n{json.dumps(user_payload, ensure_ascii=False)}"
            ),
        ),
    ]


__all__ = [
    "ResponseActionLLM",
    "ResponsePlanLLMResponse",
    "build_response_plan_messages",
]
