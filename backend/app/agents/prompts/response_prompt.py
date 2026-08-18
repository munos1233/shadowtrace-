"""Response plan LLM prompt builder (ISSUE-057 / ISSUE-251)."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.agents.prompts.prompt_blocks import (
    bounded_decision_summary,
    bounded_triage_reasoning,
    evidence_prompt_block,
)
from app.agents.triage_risk_consistency import (
    TRIAGE_RISK_INCONSISTENCY_FLAG,
    should_flag_triage_risk_inconsistency,
)
from app.core.llm.base import LLMMessage
from app.models.agent_io import EvidenceOutput, RiskAssessment, TriageResult
from app.models.enums import FinalVerdict


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
    final_verdict: FinalVerdict | str | None = None,
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
        "actions when required. Prefer lower-risk actions first. "
        "When risk_severity is high or risk_score >= 65, plan containment for "
        "EntitySet hosts/accounts even if triage severity is medium. "
        "Coverage contract (ISSUE-328, not domain): for each EntitySet account "
        "propose disable_account; for each host propose isolate_host; for each "
        "external destination IP propose block_ip. Do not omit a covered entity "
        "and do not wait for the server to merge rule fallback.\n"
        "block_ip policy (ISSUE-361): use block_ip only for external exfiltration "
        "or C2 destination IPs (entities whose attributes.normalized_field is "
        "dst_ip). Do not block VPN egress or other source IPs (src_ip, source_ip) — "
        "blocking egress can lock legitimate VPN paths and has higher blast radius "
        "than blocking a remote destination. For compromised identity or account "
        "paths prefer disable_account. The server drops default source block_ip; "
        "do not set explicit_source_block (analyst/playbook only). Still block "
        "external exfil/C2 destinations and malicious domains.\n"
        "For the same account, do not stack disable_account with force_logout, "
        "reset_password, or revoke_token — pick disable_account. The server "
        "collapses redundant identity tools on the same account."
    )
    verdict: FinalVerdict | None = None
    if final_verdict is not None:
        try:
            verdict = (
                final_verdict
                if isinstance(final_verdict, FinalVerdict)
                else FinalVerdict(str(final_verdict))
            )
        except ValueError:
            verdict = None
    if verdict is FinalVerdict.CONFIRMED_THREAT:
        system += (
            " For confirmed threats, plan isolate_host for every host listed in "
            "entities.hosts (EntitySet hosts only — not asset inventory or decoys). "
            "You may sequence lower-risk actions first, but do not omit identified "
            "compromised hosts from isolation. strategy_summary must reflect the "
            "final containment actions and must not claim a host remains online if "
            "you isolate it."
        )
    evidence_block: dict[str, Any] = {}
    if evidence_output is not None:
        evidence_block = evidence_prompt_block(evidence_output)
    user_payload = {
        "event_type": triage_result.event_type.value,
        "severity": triage_result.severity.value,
        "risk_score": risk_assessment.risk_score,
        "risk_severity": risk_assessment.severity.value,
        "final_verdict": verdict.value if verdict is not None else None,
        "entities": entities_summary,
        "available_tools": sorted(available_tools),
        "evidence": evidence_block,
        "decision_summary": bounded_decision_summary(triage_result),
        "triage_reasoning": bounded_triage_reasoning(triage_result),
    }
    if verdict is not None and should_flag_triage_risk_inconsistency(
        triage=triage_result,
        risk_score=int(risk_assessment.risk_score),
        final_verdict=verdict,
    ):
        user_payload[TRIAGE_RISK_INCONSISTENCY_FLAG] = True
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
