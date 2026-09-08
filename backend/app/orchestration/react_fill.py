"""Read-only ReAct evidence fill shared by PlannerAgent and graph react_node."""

from __future__ import annotations

import logging
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded

from app.core.config import get_settings
from app.core.errors import ToolCallGrantUnavailableError
from app.models.agent_io import PlanStep
from app.models.react import ReActResult, ReActStopReason
from app.orchestration.react_engine import ReActEngine
from app.services.tenant_resolution import resolve_tenant_id

logger = logging.getLogger(__name__)

REACT_FILL_GOAL = "只读补证：查询缺口证据，不生成处置动作"
REACT_FILL_SCRATCHPAD_PREFIX = "react_fill:"


def summarize_react_fill(result: ReActResult) -> str:
    """Compact reason fragment for PlannerAgent.revise."""
    gap_bits: list[str] = []
    for rnd in result.rounds:
        code = getattr(rnd.gap_code, "value", None) or str(rnd.gap_code or "")
        if code and code != "none":
            gap_bits.append(code)
        summary = (rnd.decision_summary or "").strip()
        if summary:
            gap_bits.append(summary[:80])
    gap_text = "; ".join(gap_bits)[:240]
    stop = (
        result.stop_reason.value
        if hasattr(result.stop_reason, "value")
        else str(result.stop_reason)
    )
    return f"react_stop={stop}; confidence={result.final_confidence:.2f}; gaps={gap_text}"


def execution_plan_has_react_step(execution_plan: Any) -> bool:
    steps: list[Any]
    if execution_plan is None:
        return False
    if isinstance(execution_plan, dict):
        steps = list(execution_plan.get("steps") or [])
    else:
        steps = list(getattr(execution_plan, "steps", None) or [])
    for step in steps:
        agent = (
            step.get("assigned_agent")
            if isinstance(step, dict)
            else getattr(step, "assigned_agent", None)
        )
        if agent == "react":
            return True
    return False


def react_step_from_plan(execution_plan: Any) -> PlanStep | None:
    if execution_plan is None:
        return None
    raw_steps = (
        execution_plan.get("steps")
        if isinstance(execution_plan, dict)
        else getattr(execution_plan, "steps", None)
    )
    for raw in raw_steps or []:
        payload = (
            raw
            if isinstance(raw, dict)
            else (raw.model_dump(mode="json") if hasattr(raw, "model_dump") else None)
        )
        if not isinstance(payload, dict) or payload.get("assigned_agent") != "react":
            continue
        try:
            return PlanStep.model_validate(payload)
        except Exception:
            return PlanStep.model_construct(
                step_order=int(payload.get("step_order") or 0),
                step_goal=str(payload.get("step_goal") or REACT_FILL_GOAL),
                assigned_agent="react",
                required_tools=list(payload.get("required_tools") or []),
                success_criteria=str(payload.get("success_criteria") or ""),
            )
    return None


async def _append_scratchpad(working_memory: Any | None, event_id: str, note: str) -> None:
    if working_memory is None:
        return
    writer = working_memory
    for_writer = getattr(working_memory, "for_writer", None)
    if callable(for_writer):
        try:
            writer = for_writer("WorkingMemory")
        except Exception:
            logger.warning(
                "react_fill: failed to bind WorkingMemory writer event=%s",
                event_id,
                exc_info=True,
            )
            return
    append = getattr(writer, "append_scratchpad", None)
    if not callable(append):
        return
    try:
        await append(event_id, note)
    except Exception:
        logger.warning(
            "react_fill: failed to append scratchpad event=%s",
            event_id,
            exc_info=True,
        )


async def run_readonly_react_fill(
    event_id: str,
    context: dict[str, Any],
    *,
    llm_client: Any | None,
    executor: Any | None = None,
    executor_factory: Any | None = None,
    plan_step: PlanStep | None = None,
    working_memory: Any | None = None,
    convergence_guard: Any | None = None,
    trace_sink: Any | None = None,
    source_snapshot: dict[str, Any] | None = None,
    react_enabled: bool | None = None,
) -> ReActResult | None:
    """Run a bounded read-only ReAct loop. Never creates disposition actions.

    Returns ``None`` when disabled, unwired, or the loop cannot start.
    SoftTimeLimitExceeded always propagates.
    """
    enabled = get_settings().react_enabled if react_enabled is None else react_enabled
    if not enabled:
        return None
    if llm_client is None:
        logger.warning("react_fill skipped — llm_client not wired event=%s", event_id)
        return None
    if executor_factory is None and executor is None:
        logger.warning("react_fill skipped — no executor event=%s", event_id)
        return None

    goal = str(context.get("gaps") or (plan_step.step_goal if plan_step else "") or REACT_FILL_GOAL)
    payload = dict(context)
    payload["event_id"] = event_id
    payload.setdefault("gaps", goal)

    react_exec = executor
    if executor_factory is not None:
        try:
            react_exec = await executor_factory.for_event(
                event_id,
                tenant_id=resolve_tenant_id(source_snapshot or payload.get("source_snapshot")),
                source_snapshot=source_snapshot or payload.get("source_snapshot"),
                plan_step=plan_step,
            )
        except ToolCallGrantUnavailableError:
            logger.warning("react_fill skipped — tool call grant unavailable event=%s", event_id)
            await _append_scratchpad(
                working_memory,
                event_id,
                f"{REACT_FILL_SCRATCHPAD_PREFIX}grant_unavailable",
            )
            return None
        except SoftTimeLimitExceeded:
            raise
        except Exception:
            logger.exception("react_fill executor mint failed event=%s", event_id)
            return None
    if react_exec is None:
        return None

    engine = ReActEngine(
        llm_client,
        convergence_guard=convergence_guard,
        trace_sink=trace_sink,
    )
    try:
        result = await engine.run(goal, payload, react_exec)
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        logger.exception("react_fill run failed event=%s", event_id)
        await _append_scratchpad(
            working_memory,
            event_id,
            f"{REACT_FILL_SCRATCHPAD_PREFIX}error",
        )
        return None

    note = f"{REACT_FILL_SCRATCHPAD_PREFIX}{summarize_react_fill(result)}"
    await _append_scratchpad(working_memory, event_id, note)
    if result.stop_reason is ReActStopReason.ERROR:
        logger.warning("react_fill stopped with error event=%s", event_id)
    return result


__all__ = [
    "REACT_FILL_GOAL",
    "execution_plan_has_react_step",
    "react_step_from_plan",
    "run_readonly_react_fill",
    "summarize_react_fill",
]
