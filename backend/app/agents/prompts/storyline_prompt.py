"""Storyline prompt builder (ISSUE-051)."""

from __future__ import annotations

import json
from typing import Any

from app.core.llm.base import LLMMessage


def build_storyline_messages(
    *,
    evidence_entries: list[dict[str, Any]],
    technique_matches: list[dict[str, Any]],
    graph_paths: list[list[str]],
    entity_names: list[str],
) -> list[LLMMessage]:
    """Build JSON-mode messages for attack storyline generation.

    The LLM receives pre-sorted evidence, ATT&CK technique matches, graph
    attack-path candidates, and key entity names, and must return a
    structured ``AttackStoryline`` as JSON.
    """
    system = (
        "You are ShadowTrace StorylineService. Reconstruct the attack "
        "timeline from evidence records, ATT&CK technique mappings, and "
        "entity-relationship graph paths. Your output must be a valid JSON "
        "object with the exact schema below. Do not include hidden "
        "chain-of-thought."
    )
    user_payload = {
        "evidence": evidence_entries,
        "attack_techniques": technique_matches,
        "graph_attack_paths": graph_paths,
        "key_entity_names": entity_names,
        "response_schema": {
            "narrative_summary": "不超过 300 字的中文叙事总结",
            "phases": [
                {
                    "phase_order": 1,
                    "phase_name": "initial_access|collection|staging|exfiltration|post_action",
                    "tactic": "关联 ATT&CK 战术 (可空)",
                    "narrative": "阶段中文叙事",
                    "entries": [
                        {
                            "timestamp": "ISO 8601",
                            "description": "事件描述",
                            "evidence_id": "evd-xxxxxxxx",
                            "technique_id": "Txxxx (可空)",
                            "severity_hint": "low|medium|high|critical (可空)",
                        }
                    ],
                }
            ],
        },
    }
    user = (
        "Generate the attack storyline. Return JSON matching:\n"
        f"{json.dumps(user_payload['response_schema'], ensure_ascii=False, indent=2)}\n"
        f"Context:\n{json.dumps(user_payload, ensure_ascii=False)}"
    )
    return [
        LLMMessage(role="system", content=system),
        LLMMessage(role="user", content=user),
    ]
