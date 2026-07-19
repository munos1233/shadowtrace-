"""Generic ReAct loop engine — observe, think, act, reflect (ISSUE-053).

The engine runs a bounded multi-round loop:

1. **Observe** — assemble the observation from the caller context plus a
   summary of the previous round's result.
2. **Think** — LLM (``prompt_key=react_think``, JSON mode) chooses the next
   ``ReActAction`` (or ``finish`` / null to stop).
3. **Act** — the injected ``ReActActionExecutor`` executes the action. The
   engine itself never touches tools or agents directly.
4. **Reflect** — LLM (``prompt_key=react_reflect``, JSON mode) returns a
   confidence in [0, 1] and a gap description.

Stop conditions (first match wins, per round): ConvergenceGuard forced stop
(``converged``), LLM ``finish`` / null action (``finished``), tool-call budget
exhausted (``budget_exhausted``), confidence ≥ ``CONFIDENCE_THRESHOLD``
(``confidence_met``), ``max_rounds`` reached (``max_rounds``), or ``error``.

Safety contract (ISSUE-053 §3 / 硬约束 A):
* ReAct can **never** create / approve / execute response Actions. All
  disposition still flows only through
  ResponseAgent → PolicyFilter → ApprovalEngine → ActionExecutionService.
* P1 ships only ``ReadOnlyReActExecutor``: ``ToolCategory.QUERY`` tools plus
  an explicit whitelist of read-only investigation agents. response /
  verification / rollback tools, ApprovalEngine, ActionExecutionService and
  any side-effect target are refused *before* execution and recorded as
  ``react_action_denied``; two consecutive failed rounds stop the loop with
  ``stop_reason=error``.

Degradation (降级策略): any LLM failure stops the loop immediately with
``stop_reason=error`` so the caller (SuperAgent) can fall back to the fixed
plan sequence — the main pipeline is never blocked by ReAct.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from app.core.errors import LLMError
from app.core.llm.base import BaseLLMClient, LLMMessage, LLMProviderError
from app.models.enums import ToolCategory
from app.models.react import (
    ReActAction,
    ReActActionType,
    ReActReflectOutput,
    ReActResult,
    ReActRound,
    ReActStopReason,
    ReActThinkOutput,
)
from app.models.tool_meta import ToolResultStatus
from app.models.workflow import CONFIDENCE_THRESHOLD
from app.orchestration.convergence_guard import ConvergenceGuard
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolNotFoundError

logger = logging.getLogger(__name__)

REACT_THINK_PROMPT_KEY = "react_think"
REACT_REFLECT_PROMPT_KEY = "react_reflect"
REACT_ACTION_DENIED = "react_action_denied"

#: Cumulative per-run cap on executed ``call_tool`` actions (预算耗尽停止条件).
#: Bounds total tool traffic of one ``run`` even when the LLM never converges.
DEFAULT_TOOL_CALL_BUDGET = 10

#: Consecutive failed rounds (denied / executor error / failed tool result)
#: that trigger an early ``error`` stop (ISSUE-053 实现步骤 §3).
MAX_CONSECUTIVE_ROUND_FAILURES = 2

#: Observation / reflection text bound for trace and prompt payloads.
_MAX_TEXT_CHARS = 2_000

# Tool-result / executor statuses that count the round as failed.
_FAILURE_STATUSES: frozenset[str] = frozenset(
    {
        REACT_ACTION_DENIED,
        "error",
        ToolResultStatus.FAILED.value,
        ToolResultStatus.UNKNOWN.value,
        ToolResultStatus.TIMEOUT.value,
        ToolResultStatus.REMOTE_ERROR.value,
        ToolResultStatus.RATE_LIMITED.value,
        ToolResultStatus.AUTH_ERROR.value,
        ToolResultStatus.VALIDATION_ERROR.value,
        ToolResultStatus.CIRCUIT_OPEN.value,
        ToolResultStatus.UNSUPPORTED.value,
    }
)


class ReActActionDenied(Exception):
    """The executor refused an illegal action *before* any side effect.

    Plain exception with a stable ``error_code`` (same pattern as
    ``WrongExecutionChannelError``); the engine records it as the round's
    ``action_result`` and counts the round as failed.
    """

    error_code = REACT_ACTION_DENIED

    def __init__(self, message: str, *, action_type: str, target_name: str) -> None:
        self.action_type = action_type
        self.target_name = target_name
        super().__init__(message)


@runtime_checkable
class ReActActionExecutor(Protocol):
    """Execution surface injected by the caller (ISSUE-053 统一命名 §6).

    The engine depends only on this protocol — never on concrete agents,
    ToolExecutor internals, or any response/approval service.
    """

    async def execute(self, action: ReActAction) -> dict[str, Any]:
        """Run *action* and return a JSON-safe result dict.

        Implementations must raise ``ReActActionDenied`` for illegal targets
        *before* producing any side effect.
        """
        ...


@runtime_checkable
class ReActTraceSink(Protocol):
    """Minimal trace surface satisfied by ``AgentTraceService`` (ISSUE-028)."""

    async def log_trace(
        self,
        event_id: str,
        agent_name: str,
        input_data: Any,
        output_data: Any | None,
        status: str,
        started_at: datetime,
        completed_at: datetime | None,
        **kwargs: Any,
    ) -> str: ...


#: Whitelisted read-only investigation agent callable: params in, dict out.
ReadOnlyAgentCallable = Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]]


class ReadOnlyReActExecutor:
    """P1 executor: query-category tools + explicit read-only agent whitelist.

    * ``call_tool`` resolves the tool through the bound ``ToolExecutor``'s
      registry and refuses anything whose ``tool_category`` is not
      ``ToolCategory.QUERY`` (response / verification / rollback / virtual
      disposition-only metas are all rejected before any dispatch).
    * ``call_agent`` only invokes callables explicitly whitelisted by the
      caller (e.g. a read-only evidence/RAG query adapter). Unknown or
      unlisted names — including ResponseAgent, ApprovalEngine and
      ActionExecutionService — are refused.
    """

    def __init__(
        self,
        tool_executor: ToolExecutor,
        *,
        event_id: str,
        allowed_agents: Mapping[str, ReadOnlyAgentCallable] | None = None,
        agent_name: str = "react_engine",
    ) -> None:
        if not event_id.strip():
            raise ValueError("event_id must not be empty")
        self._tool_executor = tool_executor
        self._event_id = event_id
        self._allowed_agents: dict[str, ReadOnlyAgentCallable] = dict(allowed_agents or {})
        self._agent_name = agent_name

    async def execute(self, action: ReActAction) -> dict[str, Any]:
        if action.action_type is ReActActionType.FINISH:
            # The engine intercepts finish before dispatch; keep this benign.
            return {"status": "finished"}
        if action.action_type is ReActActionType.CALL_TOOL:
            return await self._execute_tool(action)
        if action.action_type is ReActActionType.CALL_AGENT:
            return await self._execute_agent(action)
        raise ReActActionDenied(
            f"unsupported action_type={action.action_type!r}",
            action_type=str(action.action_type),
            target_name=action.target_name,
        )

    def describe_targets(self) -> dict[str, Any]:
        """Catalog of legal targets for the think prompt (query tools + agents)."""
        query_tools = sorted(
            meta.tool_name
            for meta in self._tool_executor.registry.list_tools(category=ToolCategory.QUERY)
        )
        return {
            "query_tools": query_tools,
            "read_only_agents": sorted(self._allowed_agents),
        }

    async def _execute_tool(self, action: ReActAction) -> dict[str, Any]:
        name = action.target_name
        try:
            registered = self._tool_executor.registry.get_tool(name)
        except ToolNotFoundError as exc:
            raise ReActActionDenied(
                f"unknown tool target_name={name!r}",
                action_type=action.action_type.value,
                target_name=name,
            ) from exc
        meta = registered.tool_meta
        if meta.tool_category is not ToolCategory.QUERY:
            raise ReActActionDenied(
                f"tool {name!r} has tool_category={meta.tool_category.value}; "
                "ReAct may only call query tools",
                action_type=action.action_type.value,
                target_name=name,
            )
        result = await self._tool_executor.call(
            name,
            dict(action.params),
            self._event_id,
            agent_name=self._agent_name,
        )
        return {
            "status": result.status.value,
            "tool_name": name,
            "provider_name": result.provider_name,
            "data": result.data,
            "error_detail": result.error_detail,
        }

    async def _execute_agent(self, action: ReActAction) -> dict[str, Any]:
        name = action.target_name
        fn = self._allowed_agents.get(name)
        if fn is None:
            raise ReActActionDenied(
                f"agent {name!r} is not in the read-only whitelist",
                action_type=action.action_type.value,
                target_name=name,
            )
        result = fn(dict(action.params))
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, dict):
            return {"status": "success", "agent_name": name, "data": {"result": result}}
        return result


class ReActEngine:
    """Bounded observe → think → act → reflect loop (ISSUE-053).

    Args:
        llm_client: Provider-independent LLM client (mock / openai_compatible /
            custom). Mock routing keys are ``react_think`` / ``react_reflect``.
        convergence_guard: Optional ISSUE-052 guard; when present every round
            first calls ``record_step(event_id, "react_round")`` then
            ``should_stop(event_id)`` and a forced stop yields
            ``stop_reason=converged``.
        trace_sink: Optional ISSUE-028-compatible trace sink; each round writes
            an auditable ``decision_basis`` (observation summary, evidence
            refs, candidate actions, selected action, confidence) — never the
            hidden chain-of-thought.
        confidence_threshold: Stop threshold (default ``CONFIDENCE_THRESHOLD``).
        tool_call_budget: Cumulative per-run cap on executed ``call_tool``
            actions; reaching it stops the run with ``budget_exhausted``.
        agent_name: Audit identity used for traces and LLM call logs.
    """

    def __init__(
        self,
        llm_client: BaseLLMClient,
        *,
        convergence_guard: ConvergenceGuard | None = None,
        trace_sink: ReActTraceSink | None = None,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
        tool_call_budget: int = DEFAULT_TOOL_CALL_BUDGET,
        agent_name: str = "react_engine",
    ) -> None:
        if tool_call_budget < 0:
            raise ValueError("tool_call_budget must be >= 0")
        self._llm = llm_client
        self._guard = convergence_guard
        self._trace_sink = trace_sink
        self._confidence_threshold = confidence_threshold
        self._tool_call_budget = tool_call_budget
        self._agent_name = agent_name

    async def run(
        self,
        goal: str,
        context: dict[str, Any],
        executor: ReActActionExecutor,
        max_rounds: int = 5,
    ) -> ReActResult:
        """Run the loop until a stop condition fires (never unbounded).

        Raises:
            ValueError: ``max_rounds`` < 1, or ``context["event_id"]`` is
                missing/blank — traces, guard counters and tool calls all key
                on event_id, so a missing one must fail fast instead of
                polluting the audit trail with an "unknown" event.
        """
        if max_rounds < 1:
            raise ValueError("max_rounds must be >= 1")
        event_id = str(context.get("event_id") or "").strip()
        if not event_id:
            raise ValueError("context['event_id'] is required")

        rounds: list[ReActRound] = []
        action_results: list[dict[str, Any]] = []
        tool_calls = 0
        consecutive_failures = 0
        last_confidence = 0.0
        previous_summary = ""

        def _result(stop: ReActStopReason, **extra: Any) -> ReActResult:
            outputs: dict[str, Any] = {"goal": goal, "action_results": action_results}
            outputs.update(extra)
            return ReActResult(
                rounds=rounds,
                final_confidence=last_confidence,
                stop_reason=stop,
                outputs=outputs,
            )

        for round_index in range(1, max_rounds + 1):
            # --- Convergence guard: record first, then check (ISSUE-052 §4) ---
            if self._guard is not None:
                await self._guard.record_step(
                    event_id, "react_round", signature=f"round:{round_index}"
                )
                decision = await self._guard.should_stop(event_id)
                if decision.stop:
                    logger.warning(
                        "ReAct run converged by guard event=%s reason=%s detail=%s",
                        event_id,
                        decision.reason.value,
                        decision.detail,
                    )
                    return _result(
                        ReActStopReason.CONVERGED,
                        stop_detail=decision.detail,
                        convergence_reason=decision.reason.value,
                        convergence_state=self._guard.get_state(event_id).model_dump(mode="json"),
                    )

            observation = self._build_observation(goal, context, previous_summary)

            # --- Think ---
            try:
                think = await self._think(
                    goal, context, executor, observation, round_index, event_id
                )
            except LLMError as exc:
                # Degradation contract: LLM unavailable → immediate error stop;
                # caller (SuperAgent) falls back to the fixed plan sequence.
                logger.warning("ReAct think failed event=%s: %s", event_id, exc)
                return _result(ReActStopReason.ERROR, stop_detail=f"react_think: {exc}")

            action = think.action
            if action is None or action.action_type is ReActActionType.FINISH:
                round_ = ReActRound(
                    round_index=round_index,
                    observation=observation,
                    thought=think.thought,
                    action=action,
                    action_result=None,
                    reflection="",
                    confidence=last_confidence,
                )
                rounds.append(round_)
                await self._trace_round(event_id, goal, context, think, round_, None)
                return _result(ReActStopReason.FINISHED)

            # --- Budget gate (before any tool dispatch) ---
            if (
                action.action_type is ReActActionType.CALL_TOOL
                and tool_calls >= self._tool_call_budget
            ):
                round_ = ReActRound(
                    round_index=round_index,
                    observation=observation,
                    thought=think.thought,
                    action=action,
                    action_result=None,
                    reflection="",
                    confidence=last_confidence,
                )
                rounds.append(round_)
                await self._trace_round(event_id, goal, context, think, round_, None)
                return _result(
                    ReActStopReason.BUDGET_EXHAUSTED,
                    stop_detail=(
                        f"tool-call budget {self._tool_call_budget} exhausted "
                        f"after {tool_calls} calls"
                    ),
                )

            # --- Act ---
            round_failed = False
            try:
                action_result: dict[str, Any] = await executor.execute(action)
                if action.action_type is ReActActionType.CALL_TOOL:
                    tool_calls += 1
                round_failed = self._is_failure(action_result)
            except ReActActionDenied as exc:
                logger.warning(
                    "react_action_denied event=%s target=%s: %s",
                    event_id,
                    action.target_name,
                    exc,
                )
                action_result = {
                    "status": REACT_ACTION_DENIED,
                    "target_name": action.target_name,
                    "detail": str(exc),
                }
                round_failed = True
            except Exception as exc:  # noqa: BLE001 - executor failure must not crash the loop
                logger.exception(
                    "ReAct action execution failed event=%s target=%s",
                    event_id,
                    action.target_name,
                )
                action_result = {
                    "status": "error",
                    "target_name": action.target_name,
                    "detail": str(exc)[:_MAX_TEXT_CHARS],
                }
                round_failed = True

            action_results.append(
                {
                    "round": round_index,
                    "action_type": action.action_type.value,
                    "target_name": action.target_name,
                    "status": action_result.get("status", "success"),
                }
            )

            # --- Reflect ---
            try:
                reflect = await self._reflect(
                    goal, observation, action, action_result, context, round_index, event_id
                )
            except LLMError as exc:
                logger.warning("ReAct reflect failed event=%s: %s", event_id, exc)
                round_ = ReActRound(
                    round_index=round_index,
                    observation=observation,
                    thought=think.thought,
                    action=action,
                    action_result=action_result,
                    reflection="",
                    confidence=last_confidence,
                )
                rounds.append(round_)
                # Every recorded round must leave an auditable trace, even when
                # the reflect step itself failed (实现步骤 §2: 每轮写 agent_trace).
                await self._trace_round(
                    event_id,
                    goal,
                    context,
                    think,
                    round_,
                    None,
                    extra_warnings=["react_reflect_failed"],
                )
                return _result(ReActStopReason.ERROR, stop_detail=f"react_reflect: {exc}")

            round_ = ReActRound(
                round_index=round_index,
                observation=observation,
                thought=think.thought,
                action=action,
                action_result=action_result,
                reflection=reflect.reflection,
                confidence=reflect.confidence,
            )
            rounds.append(round_)
            await self._trace_round(event_id, goal, context, think, round_, reflect)

            consecutive_failures = consecutive_failures + 1 if round_failed else 0
            last_confidence = reflect.confidence
            previous_summary = self._summarize_result(action, action_result, reflect)

            if consecutive_failures >= MAX_CONSECUTIVE_ROUND_FAILURES:
                return _result(
                    ReActStopReason.ERROR,
                    stop_detail=(
                        f"{consecutive_failures} consecutive failed rounds "
                        f"(last: {action_result.get('status')})"
                    ),
                )
            if not round_failed and reflect.confidence >= self._confidence_threshold:
                return _result(ReActStopReason.CONFIDENCE_MET)

        return _result(ReActStopReason.MAX_ROUNDS)

    # ------------------------------------------------------------------ #
    # LLM steps
    # ------------------------------------------------------------------ #

    async def _think(
        self,
        goal: str,
        context: dict[str, Any],
        executor: ReActActionExecutor,
        observation: str,
        round_index: int,
        event_id: str,
    ) -> ReActThinkOutput:
        targets = self._describe_targets(executor)
        messages = [
            LLMMessage(
                role="system",
                content=(
                    "You are the ShadowTrace ReAct investigation engine. Choose the next "
                    "read-only step toward the goal. Reply with JSON only: "
                    '{"thought": str, "action": {"action_type": "call_tool|call_agent|finish", '
                    '"target_name": str, "params": object, "rationale": str} | null, '
                    '"candidates": [str]}. Only call_tool targets from query_tools and '
                    "call_agent targets from read_only_agents are legal; anything else is "
                    "denied before execution. Use action=null or action_type=finish to stop.\n"
                    f"Legal targets: {targets}"
                ),
            ),
            LLMMessage(role="user", content=observation),
        ]
        response = await self._llm.chat(
            messages,
            event_id=event_id,
            agent_name=self._agent_name,
            prompt_key=REACT_THINK_PROMPT_KEY,
            scenario_id=self._round_scenario(context, round_index),
            json_mode=True,
            response_model=ReActThinkOutput,
        )
        parsed = response.parsed
        if not isinstance(parsed, ReActThinkOutput):
            # Contract violation by a (custom) client: treat as LLM failure so
            # the caller falls back per the degradation contract, rather than
            # crashing on an AttributeError outside the LLMError path.
            raise LLMProviderError(
                "react_think returned no structured ReActThinkOutput payload",
                retryable=False,
            )
        return parsed

    async def _reflect(
        self,
        goal: str,
        observation: str,
        action: ReActAction,
        action_result: dict[str, Any],
        context: dict[str, Any],
        round_index: int,
        event_id: str,
    ) -> ReActReflectOutput:
        result_brief = self._truncate(str(action_result)[:_MAX_TEXT_CHARS])
        messages = [
            LLMMessage(
                role="system",
                content=(
                    "You are the ShadowTrace ReAct reflection step. Assess progress toward "
                    "the goal from the last action result. Reply with JSON only: "
                    '{"reflection": str, "confidence": number (0..1), "gap": str, '
                    '"evidence_refs": [str]}. confidence is your calibrated estimate that '
                    "the goal is fully answered by the evidence gathered so far."
                ),
            ),
            LLMMessage(
                role="user",
                content=(
                    f"Goal: {goal}\nObservation: {observation}\n"
                    f"Action: {action.action_type.value} {action.target_name}\n"
                    f"Action result: {result_brief}"
                ),
            ),
        ]
        response = await self._llm.chat(
            messages,
            event_id=event_id,
            agent_name=self._agent_name,
            prompt_key=REACT_REFLECT_PROMPT_KEY,
            scenario_id=self._round_scenario(context, round_index),
            json_mode=True,
            response_model=ReActReflectOutput,
        )
        parsed = response.parsed
        if not isinstance(parsed, ReActReflectOutput):
            raise LLMProviderError(
                "react_reflect returned no structured ReActReflectOutput payload",
                retryable=False,
            )
        return parsed

    # ------------------------------------------------------------------ #
    # Observation / summary helpers
    # ------------------------------------------------------------------ #

    def _build_observation(self, goal: str, context: dict[str, Any], previous_summary: str) -> str:
        parts = [f"Goal: {goal}"]
        for key in ("event_id", "observation", "evidence_summary", "gaps"):
            value = context.get(key)
            if value:
                parts.append(f"{key}: {self._truncate(str(value))}")
        if not any(context.get(key) for key in ("observation", "evidence_summary")):
            parts.append(f"context_keys: {sorted(map(str, context))}")
        if previous_summary:
            parts.append(f"Previous round result: {previous_summary}")
        return self._truncate("\n".join(parts))

    @staticmethod
    def _summarize_result(
        action: ReActAction, action_result: dict[str, Any], reflect: ReActReflectOutput
    ) -> str:
        status = action_result.get("status", "success")
        gap = f"; gap: {reflect.gap}" if reflect.gap else ""
        return (
            f"{action.action_type.value} {action.target_name} -> {status} "
            f"(confidence={reflect.confidence:.2f}{gap})"
        )

    @staticmethod
    def _describe_targets(executor: ReActActionExecutor) -> dict[str, Any]:
        describe = getattr(executor, "describe_targets", None)
        if callable(describe):
            try:
                targets = describe()
                if isinstance(targets, dict):
                    return targets
            except Exception:  # noqa: BLE001 - prompt enrichment must not break the loop
                logger.exception("executor describe_targets failed")
        return {}

    @staticmethod
    def _round_scenario(context: dict[str, Any], round_index: int) -> str | None:
        """Per-round MockLLM routing key: ``{scenario_id}_round{n}``.

        Missing per-round golden files fall back to the prompt_key's
        ``default.json`` (ISSUE-027 routing), so scenarios only override the
        rounds they care about.
        """
        base = context.get("scenario_id")
        if not base:
            return None
        return f"{base}_round{round_index}"

    @staticmethod
    def _truncate(text: str, max_chars: int = _MAX_TEXT_CHARS) -> str:
        return text if len(text) <= max_chars else f"{text[:max_chars]}[TRUNCATED]"

    @staticmethod
    def _is_failure(action_result: dict[str, Any]) -> bool:
        status = str(action_result.get("status", "success"))
        return status in _FAILURE_STATUSES

    # ------------------------------------------------------------------ #
    # Trace
    # ------------------------------------------------------------------ #

    async def _trace_round(
        self,
        event_id: str,
        goal: str,
        context: dict[str, Any],
        think: ReActThinkOutput,
        round_: ReActRound,
        reflect: ReActReflectOutput | None,
        extra_warnings: list[str] | None = None,
    ) -> None:
        """Write the per-round auditable decision_basis (no chain-of-thought)."""
        if self._trace_sink is None:
            return
        try:
            action = round_.action
            selected_action = (
                f"{action.action_type.value}:{action.target_name}" if action is not None else "stop"
            )
            warnings: list[str] = list(extra_warnings or [])
            if round_.action_result and round_.action_result.get("status") == REACT_ACTION_DENIED:
                warnings.append(REACT_ACTION_DENIED)
            input_data = {
                "goal": goal,
                "round_index": round_.round_index,
                "observation_summary": self._truncate(round_.observation, 500),
                "context_keys": sorted(map(str, context)),
            }
            output_data: dict[str, Any] = {
                "summary": round_.reflection or round_.thought,
                "candidate_actions": think.candidates,
                "selected_action": selected_action,
                "confidence": round_.confidence,
                "warnings": warnings,
            }
            if reflect is not None:
                # Shaped as {"evidence_id": ...} mappings so the ISSUE-028
                # TraceProjection extracts them into decision_basis.evidence_refs.
                output_data["evidence_refs"] = [
                    {"evidence_id": ref} for ref in reflect.evidence_refs
                ]
                if reflect.gap:
                    output_data["gap"] = reflect.gap
            now = datetime.now(UTC)
            await self._trace_sink.log_trace(
                event_id,
                self._agent_name,
                input_data,
                output_data,
                "success",
                now,
                now,
            )
        except Exception:  # noqa: BLE001 - tracing must never break the loop
            logger.exception(
                "ReAct trace write failed event=%s round=%s", event_id, round_.round_index
            )


__all__ = [
    "DEFAULT_TOOL_CALL_BUDGET",
    "MAX_CONSECUTIVE_ROUND_FAILURES",
    "REACT_ACTION_DENIED",
    "REACT_REFLECT_PROMPT_KEY",
    "REACT_THINK_PROMPT_KEY",
    "ReadOnlyAgentCallable",
    "ReadOnlyReActExecutor",
    "ReActActionDenied",
    "ReActActionExecutor",
    "ReActEngine",
    "ReActTraceSink",
]
