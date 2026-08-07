"""Prompt templates for PlannerAgent (ISSUE-049 / ISSUE-251).

Wire model asks only for steps (+ optional budget). Server owns plan_id,
event_id, revision, and revise_reason — shrinking required LLM fields and
avoiding AgentName/enum schema_validation failures on the full ExecutionPlan.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.agents.evidence_agent import EVIDENCE_QUERY_ORDER
from app.models.agent_io import ExecutionPlan, PlanBudget, TriageResult

_CANONICAL_EVIDENCE_TOOLS = ", ".join(EVIDENCE_QUERY_ORDER)


class PlanStepLLM(BaseModel):
    """Tolerant step wire shape for plan_generate / plan_revise."""

    model_config = ConfigDict(extra="ignore")

    step_order: int = 0
    step_goal: str = ""
    assigned_agent: str
    required_tools: list[str] = Field(default_factory=list)
    success_criteria: str = ""

    @field_validator("assigned_agent", mode="before")
    @classmethod
    def _coerce_agent(cls, value: Any) -> str:
        return str(value or "").strip()

    @field_validator("required_tools", mode="before")
    @classmethod
    def _coerce_tools(cls, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]

    @field_validator("step_goal", "success_criteria", mode="before")
    @classmethod
    def _coerce_text(cls, value: Any) -> str:
        return str(value or "")


class PlanGenerateLLMResponse(BaseModel):
    """Slim structured output for planner LLM calls (ISSUE-251)."""

    model_config = ConfigDict(extra="ignore")

    steps: list[PlanStepLLM] = Field(default_factory=list)
    budget: PlanBudget | None = None

    @field_validator("steps", mode="before")
    @classmethod
    def _coerce_steps(cls, value: Any) -> list[Any]:
        if not isinstance(value, list):
            return []
        out: list[PlanStepLLM] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            try:
                out.append(PlanStepLLM.model_validate(item))
            except Exception:
                continue
        return out

    @field_validator("budget", mode="before")
    @classmethod
    def _coerce_budget(cls, value: Any) -> Any:
        if value is None or isinstance(value, PlanBudget):
            return value
        if not isinstance(value, dict):
            return None
        try:
            return PlanBudget.model_validate(value)
        except Exception:
            return None


# --------------------------------------------------------------------------- #
# Plan generation prompt
# --------------------------------------------------------------------------- #

PLAN_GENERATE_SYSTEM = f"""\
You are a security investigation planner. Return a single JSON object only \
(no markdown fences, no commentary) with shape:
{{"steps":[{{"step_order":1,"step_goal":"...","assigned_agent":"evidence_agent",\
"required_tools":["query_threat_intel"],"success_criteria":"..."}}],\
"budget":{{"max_tool_calls":30,"max_llm_calls":20,"max_duration_s":300}}}}

Do NOT emit plan_id, event_id, revision, revise_reason, or degraded — the \
server owns those fields.

Available agents and tools:
- evidence_agent: {_CANONICAL_EVIDENCE_TOOLS}
- risk_agent: (no tools)
- response_agent: (no tools)
- rag_agent: (no tools; only if ATT&CK mapping is clearly needed)
- graph_agent: (no tools; only if entity relationship analysis is needed)

Rules:
1. Include evidence_agent steps first.
2. Always include a risk_agent step and a response_agent step.
3. assigned_agent must be one of the agent names above.
4. evidence_agent required_tools must use canonical names from the list.
5. Emit at least 4 steps.
6. budget is optional; omit it to use defaults.
"""

PLAN_GENERATE_USER = """\
Event ID: {event_id}

Triage result:
{triage_json}

Generate the investigation plan steps as JSON only (no extra text)."""


def build_plan_generate_messages(
    event_id: str,
    triage_result: TriageResult | None,
) -> list[dict[str, str]]:
    triage_json = json.dumps(
        triage_result.model_dump(mode="json") if triage_result else {},
        ensure_ascii=False,
        indent=2,
    )
    return [
        {"role": "system", "content": PLAN_GENERATE_SYSTEM},
        {
            "role": "user",
            "content": PLAN_GENERATE_USER.format(
                event_id=event_id,
                triage_json=triage_json,
            ),
        },
    ]


# --------------------------------------------------------------------------- #
# Plan revise prompt
# --------------------------------------------------------------------------- #

PLAN_REVISE_SYSTEM = """\
You are a security investigation planner. A previous plan failed or produced \
insufficient results. Return a single JSON object only (no markdown fences) \
with shape:
{"steps":[{"step_order":1,"step_goal":"...","assigned_agent":"evidence_agent",\
"required_tools":[],"success_criteria":"..."}],\
"budget":{"max_tool_calls":30,"max_llm_calls":20,"max_duration_s":300}}

Do NOT emit plan_id, event_id, revision, revise_reason, or degraded — the \
server owns those fields.

Rules:
1. Keep useful steps; replace or augment failed ones.
2. Steps must not be identical to the previous plan.
3. When assigned_agent is evidence_agent, required_tools must use canonical \
query tool names.
"""

PLAN_REVISE_USER = """\
Event ID: {event_id}

Failure reason: {failure_reason}

Previous plan:
{previous_plan_json}

Generate the revised plan steps as JSON only (no extra text)."""


def build_plan_revise_messages(
    event_id: str,
    failure_reason: str,
    previous_plan: ExecutionPlan,
) -> list[dict[str, str]]:
    previous_plan_json = json.dumps(
        previous_plan.model_dump(mode="json"),
        ensure_ascii=False,
        indent=2,
    )
    return [
        {"role": "system", "content": PLAN_REVISE_SYSTEM},
        {
            "role": "user",
            "content": PLAN_REVISE_USER.format(
                event_id=event_id,
                failure_reason=failure_reason,
                previous_plan_json=previous_plan_json,
            ),
        },
    ]


__all__ = [
    "PLAN_GENERATE_SYSTEM",
    "PLAN_GENERATE_USER",
    "PLAN_REVISE_SYSTEM",
    "PLAN_REVISE_USER",
    "PlanGenerateLLMResponse",
    "PlanStepLLM",
    "build_plan_generate_messages",
    "build_plan_revise_messages",
]
