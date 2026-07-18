"""BaseAgent and generic Agent I/O envelopes (ISSUE-005).

Concrete Agents implement ``_run``; the base class ``execute`` template method
wraps timing, trace recording, guardrails, budget checks, EventBus publication
and working-memory access. Real logic for those wrappers lands in later Issues:

- ``_record_trace`` → ISSUE-028 (wired)
- ``_apply_guardrails`` → ISSUE-030
- ``_check_budget`` → ISSUE-029
- WorkingMemory product field R/W → ISSUE-014
- EventBus agent_progress / agent_completed / agent_failed → ISSUE-028
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

from app.core.sanitization import redact_sensitive_text
from app.models.agent_io import AGENT_INPUT_BY_NAME, AgentInput, AgentName
from app.services.working_memory import BoundWorkingMemory

logger = logging.getLogger(__name__)

TIn = TypeVar("TIn", bound="AgentInput")
TOut = TypeVar("TOut", bound=BaseModel)


class AgentOutput(BaseModel):
    """Generic agent output envelope for agents without a dedicated stage model.

    Stage Agents normally return their dedicated model from ``agent_io``
    (``TriageResult``, ``EvidenceOutput``, …) rather than this envelope.
    """

    model_config = ConfigDict(extra="forbid")

    agent_name: str
    success: bool = True
    degraded: bool = False
    error_detail: str | None = None
    duration_ms: int | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class BaseAgent(ABC, Generic[TIn, TOut]):
    """Abstract base for all 12 Agents (intro §4.4).

    Subclasses must set ``agent_name`` and implement ``_run``. Optional
    dependencies are injected as placeholders until their Issues land.
    """

    agent_name: str = ""

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        tool_executor: Any | None = None,
        working_memory: BoundWorkingMemory | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.tool_executor = tool_executor
        self.context_store = None
        self.working_memory = working_memory
        self.budget_service = budget_service
        self.output_guard = output_guard
        self.trace_service = trace_service
        self.audit_service = audit_service
        self.event_bus = event_bus
        # Per-instance hook lists (default empty); subclasses may append.
        self.pre_hooks: list[Any] = []
        self.post_hooks: list[Any] = []

    async def execute(self, input: TIn) -> TOut:
        """budget → pre_hooks → progress → _run → guardrails → post_hooks → trace."""
        expected_input = AGENT_INPUT_BY_NAME.get(cast(AgentName, self.agent_name))
        if expected_input is None or type(input) is not expected_input:
            expected_name = (
                expected_input.__name__ if expected_input is not None else "<AgentName>Input"
            )
            raise TypeError(
                f"{self.agent_name or type(self).__name__} requires {expected_name}, "
                f"got {type(input).__name__}"
            )
        await self._check_budget(input)
        for hook in self.pre_hooks:
            await hook(self, input)

        await self._publish_agent_progress(input)

        started_at = datetime.now(UTC)
        status = "completed"
        error_detail: str | None = None
        output: TOut | None = None
        self._current_input: TIn | None = input
        try:
            output = await self._run(input)
            output = await self._apply_guardrails(output)
            for hook in self.post_hooks:
                await hook(self, input)
            await self._publish_agent_completed(input)
            return output
        except Exception as exc:
            status = "failed"
            error_detail = str(exc)
            await self._publish_agent_failed(input, error_detail)
            raise
        finally:
            self._current_input = None
            completed_at = datetime.now(UTC)
            await self._record_trace(
                input=input,
                output=output,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                error_detail=error_detail,
            )

    @abstractmethod
    async def _run(self, input: TIn) -> TOut:
        """Subclass-implemented agent body. Must return the stage output model."""

    async def _record_trace(
        self,
        *,
        input: TIn,
        output: TOut | None,
        status: str,
        started_at: datetime,
        completed_at: datetime | None,
        error_detail: str | None = None,
    ) -> None:
        """Write agent execution trace via AgentTraceService (ISSUE-028).

        Trace writes are best-effort: a failure here logs a warning and never
        interrupts the agent pipeline (降级策略).
        """
        if self.trace_service is None:
            return
        try:
            await self.trace_service.log_trace(
                event_id=input.event_id,
                agent_name=self.agent_name,
                input_data=input,
                output_data=output,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                error_detail=error_detail,
                llm_model=getattr(self.llm_client, "model_name", None) if self.llm_client else None,
                llm_tokens_used=None,
            )
        except Exception:
            logger.warning(
                "AgentTraceService write failed for event=%s agent=%s",
                input.event_id,
                self.agent_name,
                exc_info=True,
            )

    async def _publish_agent_progress(self, input: TIn) -> None:
        if self.event_bus is None:
            return
        try:
            await self.event_bus.publish_event(
                input.event_id,
                "agent_progress",
                {
                    "agent_name": self.agent_name,
                    "status": "processing",
                },
            )
        except Exception:
            logger.debug(
                "event_bus agent_progress failed event=%s agent=%s",
                input.event_id,
                self.agent_name,
                exc_info=True,
            )

    async def _publish_agent_completed(self, input: TIn) -> None:
        if self.event_bus is None:
            return
        try:
            await self.event_bus.publish_event(
                input.event_id,
                "agent_completed",
                {
                    "agent_name": self.agent_name,
                },
            )
        except Exception:
            logger.debug(
                "event_bus agent_completed failed event=%s agent=%s",
                input.event_id,
                self.agent_name,
                exc_info=True,
            )

    async def _publish_agent_failed(self, input: TIn, error_detail: str) -> None:
        if self.event_bus is None:
            return
        try:
            await self.event_bus.publish_event(
                input.event_id,
                "agent_failed",
                {
                    "agent_name": self.agent_name,
                    "error_detail": redact_sensitive_text(error_detail),
                },
            )
        except Exception:
            logger.debug(
                "event_bus agent_failed failed event=%s agent=%s",
                input.event_id,
                self.agent_name,
                exc_info=True,
            )

    async def _apply_guardrails(self, output: TOut) -> TOut:
        """Validate agent output via OutputGuard (ISSUE-030).

        Block violations raise ``GuardrailViolationError`` after the guard
        persists findings to ``EventContext.guard_violations``. The surrounding
        ``execute`` template then records the agent trace as ``failed``.
        """
        if self.output_guard is None:
            return output
        current = getattr(self, "_current_input", None)
        context = await self._build_guard_context(current)
        result = await self.output_guard.validate(self.agent_name, output, context)
        sanitized = result.sanitized_output
        if sanitized is None:
            return output
        if isinstance(sanitized, type(output)):
            return sanitized
        if isinstance(output, BaseModel) and isinstance(sanitized, dict):
            try:
                return type(output).model_validate(sanitized)
            except Exception:
                return output
        return output

    async def _build_guard_context(self, input: TIn | None) -> dict[str, Any]:
        context: dict[str, Any] = {}
        if input is None:
            return context
        context["event_id"] = input.event_id
        memory = self.working_memory
        if memory is None:
            return context
        for key in (
            "evidence_output",
            "triage_result",
            "rag_output",
            "response_plan",
            "approval_records",
        ):
            try:
                value = await memory.read(input.event_id, key)
            except Exception:
                continue
            if value is not None:
                context[key] = value
        triage = context.get("triage_result")
        if isinstance(triage, dict) and triage.get("entities") is not None:
            context.setdefault("entities", triage["entities"])
        return context

    async def _check_budget(self, input: TIn) -> None:
        """Enforce BudgetService.check before agent body (ISSUE-029)."""
        if self.budget_service is None:
            return
        await self.budget_service.check(input.event_id, self.agent_name)
