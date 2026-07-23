"""Response plan LLM prompt builder (ISSUE-057)."""

from __future__ import annotations

import json
from typing import Any

from app.core.llm.base import LLMMessage
from app.models.agent_io import EvidenceOutput, RiskAssessment, TriageResult


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
        "You are ShadowTrace ResponseAgent. Propose a conservative disposition plan "
        "as JSON only. Each action must use a tool_name from available_tools, include "
        "target_type and target when the tool requires an entity target, and must not "
        "invent tools or targets. Do not include update_source_event_disposition — "
        "the server appends deferred writeback actions when required. Sort mentally by "
        "ascending risk (L0 first). Reply with JSON object: "
        '{"actions":[{"tool_name":"...","target_type":"...","target":"...",'
        '"parameters":{},"reason":"..."}],"strategy_summary":"..."}'
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
        LLMMessage(role="user", content=json.dumps(user_payload, ensure_ascii=False)),
    ]
