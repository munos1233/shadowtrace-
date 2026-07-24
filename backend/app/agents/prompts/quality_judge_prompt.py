"""LLM judge prompt for agent output quality evaluation (ISSUE-065)."""

from __future__ import annotations

import json
from typing import Any

from app.core.llm.base import LLMMessage


def build_quality_judge_messages(
    *,
    agent_name: str,
    output_summary: dict[str, Any],
    rule_score: float,
    rule_verdict: str,
    rule_reasons: list[str],
) -> list[LLMMessage]:
    """Build JSON-mode messages for the LLM quality judge.

    The LLM receives the rule-based score + reasons and the output itself,
    then returns a calibrated score as JSON.
    """
    system = (
        "You are ShadowTrace OutputQualityEvaluator judge. Calibrate the "
        "rule-based quality score for a security agent's output. Consider: "
        "completeness (are required fields present?), grounding (are claims "
        "backed by evidence?), consistency (is the reasoning coherent?), "
        "and specificity (are concrete entities named rather than vague "
        "descriptions?).\n\n"
        "Return a JSON object with:\n"
        '- "calibrated_score": float 0-1\n'
        '- "verdict": "pass" | "warn" | "fail"\n'
        '- "reasons": list of strings\n'
        '- "disagreement_note": string (non-empty only when you disagree '
        "with the rule score by more than 0.15)\n\n"
        "Rules:\n"
        "1. If the rule score seems reasonable, keep calibrated_score close.\n"
        "2. If you find the rule score too harsh or too lenient, adjust it.\n"
        "3. verdict must align with calibrated_score: >=0.75 pass, "
        ">=0.5 warn, <0.5 fail.\n"
        "4. Do NOT include hidden reasoning — only the JSON object."
    )

    user = (
        f"Agent: {agent_name}\n\n"
        f"Rule score: {rule_score:.3f} (verdict={rule_verdict})\n"
        f"Rule reasons: {json.dumps(rule_reasons, ensure_ascii=False)}\n\n"
        f"Agent output:\n{json.dumps(output_summary, ensure_ascii=False, indent=2)}"
    )

    return [
        LLMMessage(role="system", content=system),
        LLMMessage(role="user", content=user),
    ]


__all__ = ["build_quality_judge_messages"]
