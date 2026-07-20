"""Report generation prompt builders (ISSUE-036)."""

from __future__ import annotations

import json
from typing import Any

from app.agents.report_section_builder import SECTION_KEYS
from app.core.llm.base import LLMMessage


def build_report_messages(
    *,
    event_id: str,
    context_summary: dict[str, Any],
    draft_sections: dict[str, str],
) -> list[LLMMessage]:
    """Ask the LLM to refine a 15-section investigation report (JSON only)."""
    system = (
        "You are ShadowTrace ReportAgent, a senior SOC investigator. "
        "Produce a structured investigation report. Reply with JSON only. "
        "Do not invent entities, IPs, hosts, or scores that are absent from the "
        "provided facts. recommendations must contain 3 to 5 concrete next steps. "
        "Keep each section concise and evidence-grounded."
    )
    payload = {
        "event_id": event_id,
        "facts": context_summary,
        "draft_sections": draft_sections,
        "required_section_keys": list(SECTION_KEYS),
        "response_schema": {
            "title": "string",
            "summary": "string",
            "sections": {key: "markdown string" for key in SECTION_KEYS},
        },
    }
    user = (
        "Refine the investigation report. Return JSON shaped like:\n"
        '{"title":"...","summary":"...","sections":{'
        + ",".join(f'"{k}":"..."' for k in SECTION_KEYS)
        + "}}\n"
        "Use every required_section_keys entry. Prefer the draft text when facts "
        "are already complete; improve narrative quality for overview, "
        "attack_storyline, and recommendations.\n"
        f"Context:\n{json.dumps(payload, ensure_ascii=False)}"
    )
    return [
        LLMMessage(role="system", content=system),
        LLMMessage(role="user", content=user),
    ]
