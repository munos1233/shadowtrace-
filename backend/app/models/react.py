"""ReAct loop engine domain models (ISSUE-053).

The engine iterates observe → think → act → reflect rounds and stops on the
first of: confidence ≥ ``CONFIDENCE_THRESHOLD``, ``max_rounds`` reached, the
LLM returning ``finish`` (or a null action), the per-run tool-call budget
being exhausted, the ConvergenceGuard forcing convergence, or an error.

These models are the *auditable* surface of the loop: ``ReActRound`` keeps the
observation summary, selected action, action result, reflection and confidence
— never a hidden chain-of-thought prompt/response transcript.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReActActionType(StrEnum):
    """What the engine may do next (ISSUE-053 统一命名 §3)."""

    CALL_TOOL = "call_tool"
    CALL_AGENT = "call_agent"
    FINISH = "finish"


class ReActStopReason(StrEnum):
    """Why the loop stopped (ISSUE-053 统一命名 §5)."""

    CONFIDENCE_MET = "confidence_met"
    MAX_ROUNDS = "max_rounds"
    FINISHED = "finished"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CONVERGED = "converged"
    ERROR = "error"


class ReActAction(BaseModel):
    """One action chosen by the think step.

    ``action_type=finish`` (or a null ``ReActRound.action``) means the LLM
    decided to stop iterating. For ``call_tool`` / ``call_agent`` the
    ``target_name`` must resolve through the injected executor — the engine
    itself never touches tools or agents directly.
    """

    model_config = ConfigDict(extra="forbid")

    action_type: ReActActionType
    target_name: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""


class ReActRound(BaseModel):
    """Auditable record of one observe → think → act → reflect cycle.

    ``action=None`` marks the stop round (LLM returned no action).
    ``action_result=None`` means the action was not executed (stop round or
    budget stop); denied/failed executions carry a result dict whose
    ``status`` is ``react_action_denied`` / ``error`` instead.
    """

    model_config = ConfigDict(extra="forbid")

    round_index: int = Field(ge=1)
    observation: str = ""
    thought: str = ""
    action: ReActAction | None = None
    action_result: dict[str, Any] | None = None
    reflection: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ReActResult(BaseModel):
    """Aggregate outcome of ``ReActEngine.run`` (ISSUE-053 统一命名 §5).

    ``outputs`` is a free-form dict for callers; the engine fills
    ``outputs["action_results"]`` (per-round execution summaries) and, when
    useful for the caller's audit, ``outputs["stop_detail"]``.
    """

    model_config = ConfigDict(extra="forbid")

    rounds: list[ReActRound] = Field(default_factory=list)
    final_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    stop_reason: ReActStopReason
    outputs: dict[str, Any] = Field(default_factory=dict)


class ReActThinkOutput(BaseModel):
    """Structured payload expected from the ``react_think`` LLM call.

    ``action=None`` is the explicit stop signal (the round is recorded with a
    null action). ``candidates`` lists the target names the model considered
    so the per-round trace can show candidate → selected without storing the
    hidden chain-of-thought.
    """

    model_config = ConfigDict(extra="forbid")

    thought: str = ""
    action: ReActAction | None = None
    candidates: list[str] = Field(default_factory=list)


class ReActReflectOutput(BaseModel):
    """Structured payload expected from the ``react_reflect`` LLM call.

    ``confidence`` is clamped to [0, 1]; a missing/invalid confidence parses
    to 0.0 so a malformed reflection can never fabricate convergence.
    """

    model_config = ConfigDict(extra="forbid")

    reflection: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    gap: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


__all__ = [
    "ReActAction",
    "ReActActionType",
    "ReActReflectOutput",
    "ReActResult",
    "ReActRound",
    "ReActStopReason",
    "ReActThinkOutput",
]
