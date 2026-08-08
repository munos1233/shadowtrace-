"""Risk scoring prompt builders (ISSUE-035 / ISSUE-251)."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.llm.base import LLMMessage
from app.models.agent_io import EvidenceOutput, TriageResult

FACTOR_NAMES: tuple[str, ...] = (
    "asset_impact",
    "behavior_anomaly",
    "evidence_confidence",
    "attack_stage",
    "data_sensitivity",
    "threat_intel",
)


class RiskFactorLLM(BaseModel):
    """One dimension score from risk_score structured output."""

    model_config = ConfigDict(extra="ignore")

    score: float | None = None
    reason: str = ""

    @model_validator(mode="before")
    @classmethod
    def _accept_reasoning_alias(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if not data.get("reason") and data.get("reasoning") is not None:
            data["reason"] = data.get("reasoning")
        return data

    @field_validator("score", mode="before")
    @classmethod
    def _coerce_score(cls, value: Any) -> float | None:
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @field_validator("reason", mode="before")
    @classmethod
    def _coerce_reason(cls, value: Any) -> str:
        return "" if value is None else str(value)


class RiskScoreLLMResponse(BaseModel):
    """Slim wire model so JSON repair embeds a real schema (ISSUE-251)."""

    model_config = ConfigDict(extra="ignore")

    factors: dict[str, RiskFactorLLM] = Field(default_factory=dict)
    raw_confidence: float = 0.75
    evidence_limited: bool = False

    @field_validator("factors", mode="before")
    @classmethod
    def _coerce_factors(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        out: dict[str, Any] = {}
        for key, entry in value.items():
            if not isinstance(entry, dict):
                continue
            try:
                parsed = RiskFactorLLM.model_validate(entry)
            except Exception:
                continue
            if parsed.score is None:
                continue
            out[str(key)] = parsed
        return out

    @field_validator("raw_confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.75

    @field_validator("evidence_limited", mode="before")
    @classmethod
    def _coerce_limited(cls, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes"}
        return bool(value)

    @model_validator(mode="after")
    def _require_all_factors(self) -> RiskScoreLLMResponse:
        missing = [name for name in FACTOR_NAMES if name not in self.factors]
        if missing:
            raise ValueError(f"risk_score missing required factors: {missing}")
        return self


def build_risk_messages(
    *,
    triage_result: TriageResult,
    evidence_output: EvidenceOutput,
    rag_summary: dict[str, Any] | None = None,
    graph_summary: dict[str, Any] | None = None,
    source_snapshot: dict[str, Any] | None = None,
) -> list[LLMMessage]:
    """Build JSON-mode messages that request per-dimension scores only (no CoT)."""
    system = (
        "You are ShadowTrace RiskAgent. Score residual cyber risk for one security "
        "event across six fixed dimensions. Return a single JSON object only "
        "(no markdown fences, no commentary) with shape:\n"
        '{"factors":{"asset_impact":{"score":0,"reason":"..."},'
        '"behavior_anomaly":{"score":0,"reason":"..."},'
        '"evidence_confidence":{"score":0,"reason":"..."},'
        '"attack_stage":{"score":0,"reason":"..."},'
        '"data_sensitivity":{"score":0,"reason":"..."},'
        '"threat_intel":{"score":0,"reason":"..."}},'
        '"raw_confidence":0.0,"evidence_limited":false}\n'
        "Each score is 0-100 with a one-sentence evidence-based reason. "
        "Do not include chain-of-thought. Missing or failed evidence collection "
        "does NOT mean low threat — preserve source alert severity when evidence "
        "is sparse and set evidence_limited=true."
    )
    source_context: dict[str, Any] = {}
    if isinstance(source_snapshot, dict):
        normalized = source_snapshot.get("normalized")
        if isinstance(normalized, dict):
            source_context["normalized"] = normalized
        if source_snapshot.get("severity"):
            source_context["severity"] = source_snapshot.get("severity")
    payload = {
        "triage": {
            "event_type": triage_result.event_type.value,
            "severity": triage_result.severity.value,
            "ioc_list": list(triage_result.ioc_list),
            "reasoning": triage_result.reasoning,
        },
        "source_snapshot": source_context,
        "evidence": {
            "overall_confidence": evidence_output.overall_confidence,
            "collection_status": evidence_output.collection_status.value,
            "success_sources": list(evidence_output.success_sources),
            "failed_sources": list(evidence_output.failed_sources),
            "evidence_count": len(evidence_output.evidence_list),
            "sample": [
                {
                    "source": item.source.value,
                    "evidence_type": item.evidence_type,
                    "description": item.description[:200],
                    "confidence": item.confidence,
                    "mitre_technique": item.mitre_technique,
                    "is_conflicting": item.is_conflicting,
                }
                for item in evidence_output.evidence_list[:12]
            ],
        },
        "rag": rag_summary or {},
        "graph_summary": graph_summary or {},
        "required_factors": list(FACTOR_NAMES),
    }
    user = (
        "Score the event and respond with JSON only.\n"
        f"Context:\n{json.dumps(payload, ensure_ascii=False)}"
    )
    return [
        LLMMessage(role="system", content=system),
        LLMMessage(role="user", content=user),
    ]


__all__ = [
    "FACTOR_NAMES",
    "RiskFactorLLM",
    "RiskScoreLLMResponse",
    "build_risk_messages",
]
