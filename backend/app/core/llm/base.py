"""Shared LLM contracts, fallback orchestration, hooks, and audit (ISSUE-027)."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, TypeAlias, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import LLMError, ShadowTraceError
from app.core.sanitization import redact_sensitive_text
from app.core.telemetry import traced_operation
from app.db import models as orm

logger = logging.getLogger(__name__)

# Bounded durable failure classes for llm_call_log.error_class (ISSUE-240).
LLM_CALL_ERROR_CLASSES: frozenset[str] = frozenset(
    {
        "empty_content",
        "invalid_json",
        "schema_validation",
        "timeout",
        "auth",
        "rate_limit",
        "provider",
        "config",
        "audit",
        "budget",
        "unknown",
    }
)
_LLM_ERROR_DETAIL_MAX_LEN = 256


def _is_async_callable(fn: object) -> bool:
    return inspect.iscoroutinefunction(fn)


class LLMMessage(BaseModel):
    """One vendor-neutral chat message."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    name: str | None = None


class LLMResponse(BaseModel):
    """Normalized response returned to every Agent."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    content: str
    parsed: BaseModel | None = None
    model_name: str
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    fallback_level: int = Field(default=0, ge=0, le=2)
    degraded_reason: str | None = None


class LLMTimeoutError(LLMError):
    default_error_code = "llm_timeout"


class LLMAuthError(LLMError):
    default_error_code = "llm_auth_error"
    default_retryable = False


class LLMRateLimitedError(LLMError):
    default_error_code = "llm_rate_limited"


class LLMInvalidJSONError(LLMError):
    default_error_code = "llm_invalid_json"
    default_retryable = False

    def __init__(
        self,
        message: str,
        *,
        invalid_content: str,
        validation_error: str,
        error_class: str = "invalid_json",
        finish_reason: str | None = None,
    ) -> None:
        self.invalid_content = invalid_content
        self.validation_error = validation_error
<<<<<<< HEAD
        self.error_class = error_class if error_class in LLM_CALL_ERROR_CLASSES else "invalid_json"
        super().__init__(
            message,
            details={
                "validation_error": validation_error,
                "error_class": self.error_class,
            },
        )
=======
        self.finish_reason = finish_reason
        self.error_class = error_class if error_class in LLM_CALL_ERROR_CLASSES else "invalid_json"
        details: dict[str, Any] = {
            "validation_error": validation_error,
            "error_class": self.error_class,
        }
        if finish_reason:
            details["finish_reason"] = finish_reason
        super().__init__(message, details=details)
>>>>>>> 1feb761 (fix(ISSUE-239): bounded empty/truncated JSON recovery for real LLM clients)


class LLMProviderError(LLMError):
    default_error_code = "llm_provider_error"


class LLMAuditError(LLMError):
    default_error_code = "llm_audit_error"
    default_retryable = False


def sanitize_llm_error_detail(value: str | None) -> str | None:
    """Redact secrets and truncate detail for durable audit (never full bodies)."""

    if value is None:
        return None
    cleaned = redact_sensitive_text(str(value)).strip()
    if not cleaned:
        return None
    if len(cleaned) > _LLM_ERROR_DETAIL_MAX_LEN:
        return cleaned[: _LLM_ERROR_DETAIL_MAX_LEN - 1] + "…"
    return cleaned


def classify_llm_call_failure(
    *,
    status: str,
    error: BaseException | None = None,
) -> tuple[str | None, str | None]:
    """Map one audit attempt to ``(error_class, error_detail)``.

    Success rows keep both null. Detail never includes prompt text, API keys,
    or full completion bodies — only short redacted validation/provider hints.
    """

    if status == "success":
        return None, None

    error_class: str | None = None
    detail: str | None = None

    if isinstance(error, LLMInvalidJSONError):
        error_class = (
            error.error_class if error.error_class in LLM_CALL_ERROR_CLASSES else "invalid_json"
        )
        detail = error.validation_error or error.message
    elif isinstance(error, LLMTimeoutError) or status == "llm_timeout":
        error_class = "timeout"
        detail = getattr(error, "message", None) or status
    elif isinstance(error, LLMAuthError) or status == "llm_auth_error":
        error_class = "auth"
        detail = getattr(error, "message", None) or status
    elif isinstance(error, LLMRateLimitedError) or status == "llm_rate_limited":
        error_class = "rate_limit"
        detail = getattr(error, "message", None) or status
    elif status == "llm_config_error":
        error_class = "config"
        detail = getattr(error, "message", None) or status
    elif status == "llm_audit_error" or isinstance(error, LLMAuditError):
        error_class = "audit"
        detail = getattr(error, "message", None) or status
    elif status == "budget_exceeded" or (
        error is not None and getattr(error, "error_code", None) == "budget_exceeded"
    ):
        error_class = "budget"
        detail = getattr(error, "message", None) or status
    elif isinstance(error, LLMProviderError) or status in {
        "llm_provider_error",
        "error",
    }:
        error_class = "provider"
        detail = getattr(error, "message", None) or status
    elif isinstance(error, LLMError):
        code = (error.error_code or status or "").strip().lower()
        if code == "llm_invalid_json":
            error_class = "invalid_json"
        elif code == "llm_timeout":
            error_class = "timeout"
        else:
            error_class = "provider"
        detail = getattr(error, "message", None) or code or status
    elif status == "llm_invalid_json":
        error_class = "invalid_json"
        detail = status
    else:
        error_class = "unknown"
        detail = getattr(error, "message", None) or status

    if error_class not in LLM_CALL_ERROR_CLASSES:
        error_class = "unknown"
    return error_class, sanitize_llm_error_detail(detail)


@dataclass(frozen=True)
class ProviderResponse:
    """Internal normalized result from one actual provider request."""

    content: str
    model_name: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str | None = None


class LLMCallAudit(BaseModel):
    """Minimal audit payload; prompt text and credentials are intentionally absent."""

    event_id: str
    agent_name: str
    prompt_key: str
    model_name: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int | None = None
    fallback_level: int = 0
    status: str
    error_class: str | None = None
    error_detail: str | None = None


@runtime_checkable
class LLMCallAuditRecorder(Protocol):
    async def record(self, entry: LLMCallAudit) -> None: ...


class InMemoryLLMCallAuditRecorder:
    """Deterministic audit recorder for unit tests and local adapters."""

    def __init__(self) -> None:
        self.entries: list[LLMCallAudit] = []

    async def record(self, entry: LLMCallAudit) -> None:
        self.entries.append(entry)


class SQLAlchemyLLMCallAuditRecorder:
    """Persist each request attempt in its own short transaction."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record(self, entry: LLMCallAudit) -> None:
        async with self._session_factory() as session:
            session.add(orm.LLMCallLog(**entry.model_dump()))
            await session.commit()


@runtime_checkable
class ConvergenceGuardHook(Protocol):
    def record_step(
        self, event_id: str, step_type: str, *, signature: str | None = None, **kwargs: Any
    ) -> None: ...

    def should_stop(self, event_id: str) -> Any: ...


@runtime_checkable
class MessageBudgeterHook(Protocol):
    def fit(self, messages: list[LLMMessage], max_input_tokens: int) -> list[LLMMessage]: ...


@runtime_checkable
class BudgetMeterHook(Protocol):
    """ISSUE-029 BudgetService surface used by LLMClient."""

    async def check(self, event_id: str, agent_name: str) -> None: ...

    async def charge_llm(
        self,
        event_id: str,
        agent_name: str,
        model_name: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> Any: ...


BudgetCallback: TypeAlias = Callable[..., Awaitable[None] | None]

# CJK Unified Ideographs + common CJK punctuation / compatibility blocks.
_CJK_RE = re.compile(
    r"[\u3000-\u303f\u3040-\u309f\u30a0-\u30ff\u3400-\u4dbf"
    r"\u4e00-\u9fff\uf900-\ufaff]"
)

_JSON_MODE_HINT = (
    "Respond with a single valid JSON object only. "
    "Do not wrap the object in markdown fences or add commentary."
)

_EMPTY_CONTENT_RETRY_HINT = LLMMessage(
    role="user",
    content=(
        "Previous response had empty content. Return one JSON object only that "
        "matches the required schema. No markdown fences and no commentary."
    ),
)

# Bounded recovery for empty/truncated structured outputs (ISSUE-239).
_STRUCTURED_OUTPUT_MAX_TOKEN_CAP = 8192
_EMPTY_CONTENT_RETRIES = 1
_LENGTH_TRUNCATION_RETRIES = 1


def estimate_tokens(text: str) -> int:
    """Deterministic heuristic token estimate (ISSUE-031).

    CJK characters count as 1 token each; remaining characters count as
    ``ceil(n / 4)`` tokens. Empty text is 0.
    """

    if not text:
        return 0
    cjk = 0
    other = 0
    for char in text:
        if _CJK_RE.fullmatch(char):
            cjk += 1
        else:
            other += 1
    return cjk + (other + 3) // 4


def _fallback_level(model_index: int) -> int:
    return 0 if model_index == 0 else 1


def bump_max_tokens(max_tokens: int, *, cap: int = _STRUCTURED_OUTPUT_MAX_TOKEN_CAP) -> int:
    """Increase generation budget once for empty/truncated structured output."""

    safe = max(1, int(max_tokens))
    bumped = max(safe * 2, safe + 512)
    return min(bumped, cap)


def ensure_json_mode_messages(messages: Sequence[LLMMessage]) -> list[LLMMessage]:
    """Ensure json_object requests also instruct the model to emit JSON.

    OpenAI-compatible providers (including Ark) often require the word ``JSON``
    in the prompt when ``response_format=json_object``; otherwise content may be
    empty despite a successful HTTP response.
    """

    copied = [message.model_copy(deep=True) for message in messages]
    if any("json" in message.content.lower() for message in copied):
        return copied
    system = next((message for message in copied if message.role == "system"), None)
    if system is not None:
        system.content = f"{system.content.rstrip()}\n\n{_JSON_MODE_HINT}"
        return copied
    return [LLMMessage(role="system", content=_JSON_MODE_HINT), *copied]


def _plain_truncate(messages: Sequence[LLMMessage], max_chars: int) -> list[LLMMessage]:
    """Keep the first system message and newest context within a deterministic cap."""

    if max_chars <= 0:
        return []
    copied = [message.model_copy(deep=True) for message in messages]
    if sum(len(message.content) for message in copied) <= max_chars:
        return copied

    system = next((message for message in copied if message.role == "system"), None)
    remaining = max_chars - (len(system.content) if system else 0)
    if remaining < 0 and system is not None:
        return [system.model_copy(update={"content": system.content[:max_chars]})]

    tail: list[LLMMessage] = []
    for message in reversed(copied):
        if message is system:
            continue
        if remaining <= 0:
            break
        content = message.content
        if len(content) > remaining:
            content = content[-remaining:]
        tail.append(message.model_copy(update={"content": content}))
        remaining -= len(content)
    tail.reverse()
    return ([system] if system is not None else []) + tail


class BaseLLMClient(ABC):
    """Provider-independent chat flow with repair, fallback, guard, and audit."""

    def __init__(
        self,
        *,
        primary_model: str,
        fallback_models: Sequence[str] = (),
        timeout_seconds: float = 30.0,
        audit_recorder: LLMCallAuditRecorder | None = None,
        convergence_guard: ConvergenceGuardHook | None = None,
        budget_callback: BudgetCallback | None = None,
        budget_service: BudgetMeterHook | None = None,
        message_budgeter: MessageBudgeterHook | None = None,
        max_input_tokens: int = 16_000,
    ) -> None:
        if not primary_model.strip():
            raise ValueError("primary_model must not be empty")
        self.primary_model = primary_model.strip()
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        deduplicated_fallbacks = dict.fromkeys(
            model.strip()
            for model in fallback_models
            if model.strip() and model.strip() != self.primary_model
        )
        self.fallback_models = tuple(deduplicated_fallbacks)
        self.timeout_seconds = timeout_seconds
        if audit_recorder is None:
            raise ValueError("audit_recorder is required")
        self.audit_recorder = audit_recorder
        self.convergence_guard = convergence_guard
        self.budget_callback = budget_callback
        self.budget_service = budget_service
        self.message_budgeter = message_budgeter
        self.max_input_tokens = max_input_tokens

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        event_id: str,
        agent_name: str,
        prompt_key: str,
        scenario_id: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        json_mode: bool = False,
        response_model: type[BaseModel] | None = None,
        timeout: float | None = None,
    ) -> LLMResponse:
        del scenario_id  # Used by MockLLMClient; never inferred from prompt content.
        chat_started = time.perf_counter()
        self._validate_context(event_id, agent_name, prompt_key, messages)
        require_json = json_mode or response_model is not None
        prepared_source = ensure_json_mode_messages(messages) if require_json else list(messages)
        prepared = self._fit_messages(prepared_source)
        last_error: LLMError | None = None

        with traced_operation(
            "llm.chat",
            event_id=event_id,
            agent_name=agent_name,
            prompt_key=prompt_key,
        ):
            for model_index, model_name in enumerate((self.primary_model, *self.fallback_models)):
                level = _fallback_level(model_index)
                try:
                    raw, parsed = await self._complete_structured(
                        prepared,
                        model_name=model_name,
                        event_id=event_id,
                        agent_name=agent_name,
                        prompt_key=prompt_key,
                        fallback_level=level,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        require_json=require_json,
                        response_model=response_model,
                        timeout=timeout,
                    )
                except LLMAuditError:
                    raise
                except LLMError as exc:
                    if not exc.retryable:
                        raise
                    last_error = exc
                    continue
                except ShadowTraceError:
                    raise

                response = LLMResponse(
                    content=raw.content,
                    parsed=parsed,
                    model_name=raw.model_name,
                    prompt_tokens=raw.prompt_tokens,
                    completion_tokens=raw.completion_tokens,
                    total_tokens=raw.total_tokens or raw.prompt_tokens + raw.completion_tokens,
                    latency_ms=max(0, round((time.perf_counter() - chat_started) * 1000)),
                    fallback_level=level,
                    degraded_reason=(
                        f"primary model unavailable: {type(last_error).__name__}" if level else None
                    ),
                )
                return response

            if last_error is not None:
                raise last_error
            raise LLMProviderError("no LLM models are configured")

    @abstractmethod
    async def _request(
        self,
        messages: list[LLMMessage],
        *,
        model_name: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> ProviderResponse:
        """Perform exactly one provider request."""

    async def aclose(self) -> None:
        """Release provider resources when the concrete client owns them."""

        return None

    def _fit_messages(self, messages: list[LLMMessage]) -> list[LLMMessage]:
        if self.message_budgeter is not None:
            return self.message_budgeter.fit(list(messages), self.max_input_tokens)
        # Conservative 2 chars/token estimate: safe for CJK (~1–2) and English (~4).
        # Over-provision via message_budgeter when precise token counts are needed.
        return _plain_truncate(messages, self.max_input_tokens * 2)

    async def _complete_structured(
        self,
        messages: list[LLMMessage],
        *,
        model_name: str,
        event_id: str,
        agent_name: str,
        prompt_key: str,
        fallback_level: int,
        temperature: float,
        max_tokens: int,
        require_json: bool,
        response_model: type[BaseModel] | None,
        timeout: float | None = None,
    ) -> tuple[ProviderResponse, BaseModel | None]:
        """One model lane: empty/truncation bump (bounded), then one JSON repair.

        Empty content is *not* sent through the JSON repair path (repairing an
        empty body wastes a call). Invalid JSON still gets exactly one repair.
        """

        attempt_messages = messages
        attempt_max_tokens = max_tokens
        empty_retries = _EMPTY_CONTENT_RETRIES if require_json else 0
        truncation_retries = _LENGTH_TRUNCATION_RETRIES if require_json else 0

        while True:
            try:
                return await self._attempt(
                    attempt_messages,
                    model_name=model_name,
                    event_id=event_id,
                    agent_name=agent_name,
                    prompt_key=prompt_key,
                    fallback_level=fallback_level,
                    temperature=temperature,
                    max_tokens=attempt_max_tokens,
                    json_mode=require_json,
                    response_model=response_model,
                    timeout=timeout,
                )
            except LLMInvalidJSONError as exc:
                if exc.error_class == "empty_content":
                    if empty_retries <= 0:
                        raise
                    empty_retries -= 1
                    attempt_max_tokens = bump_max_tokens(attempt_max_tokens)
                    attempt_messages = self._fit_messages([*messages, _EMPTY_CONTENT_RETRY_HINT])
                    continue
                if truncation_retries > 0 and (exc.finish_reason or "").lower() == "length":
                    truncation_retries -= 1
                    attempt_max_tokens = bump_max_tokens(attempt_max_tokens)
                    continue
                return await self._repair_json(
                    messages,
                    invalid_content=exc.invalid_content,
                    validation_error=exc.validation_error,
                    model_name=model_name,
                    event_id=event_id,
                    agent_name=agent_name,
                    prompt_key=prompt_key,
                    fallback_level=fallback_level,
                    temperature=temperature,
                    max_tokens=attempt_max_tokens,
                    response_model=response_model,
                    timeout=timeout,
                )

    async def _attempt(
        self,
        messages: list[LLMMessage],
        *,
        model_name: str,
        event_id: str,
        agent_name: str,
        prompt_key: str,
        fallback_level: int,
        temperature: float,
        max_tokens: int,
        json_mode: bool,
        response_model: type[BaseModel] | None,
        timeout: float | None = None,
    ) -> tuple[ProviderResponse, BaseModel | None]:
        await self._check_convergence(event_id, agent_name, prompt_key, model_name)
        started = time.perf_counter()
        raw: ProviderResponse | None = None
        status = "error"
        error: BaseException | None = None
        try:
            await self._check_budget(event_id=event_id, agent_name=agent_name)
            try:
                effective_timeout = timeout if timeout is not None else self.timeout_seconds
                async with asyncio.timeout(effective_timeout):
                    raw = await self._request(
                        messages,
                        model_name=model_name,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        json_mode=json_mode,
                    )
            except TimeoutError as exc:
                raise LLMTimeoutError(
                    "LLM request timed out",
                    details={"model_name": model_name},
                ) from exc
        except LLMError as exc:
            status = exc.error_code
            error = exc
        except ShadowTraceError as exc:
            status = exc.error_code
            error = exc
        except Exception as exc:
            status = "llm_provider_error"
            error = LLMProviderError("unexpected LLM provider failure")
            error.__cause__ = exc

        parsed: BaseModel | None = None
        if error is None:
            assert raw is not None
            try:
                await self._charge_budget(raw, event_id=event_id, agent_name=agent_name)
                parsed = (
                    self._parse(
                        raw.content,
                        response_model,
                        finish_reason=raw.finish_reason,
                    )
                    if json_mode
                    else None
                )
                status = "success"
            except ShadowTraceError as exc:
                status = exc.error_code
                error = exc
            except Exception as exc:
                status = "llm_provider_error"
                error = LLMProviderError("LLM post-processing failed")
                error.__cause__ = exc

        latency_ms = max(0, round((time.perf_counter() - started) * 1000))
        error_class, error_detail = classify_llm_call_failure(status=status, error=error)
        await self._record_audit(
            LLMCallAudit(
                event_id=event_id,
                agent_name=agent_name,
                prompt_key=prompt_key,
                model_name=model_name,
                prompt_tokens=raw.prompt_tokens if raw else 0,
                completion_tokens=raw.completion_tokens if raw else 0,
                total_tokens=(
                    raw.total_tokens or raw.prompt_tokens + raw.completion_tokens if raw else 0
                ),
                latency_ms=latency_ms,
                fallback_level=fallback_level,
                status=status,
                error_class=error_class,
                error_detail=error_detail,
            )
        )
        if error is not None:
            raise error
        assert raw is not None
        return raw, parsed

    async def _repair_json(
        self,
        messages: list[LLMMessage],
        *,
        invalid_content: str,
        validation_error: str,
        model_name: str,
        event_id: str,
        agent_name: str,
        prompt_key: str,
        fallback_level: int,
        temperature: float,
        max_tokens: int,
        response_model: type[BaseModel] | None,
        timeout: float | None = None,
    ) -> tuple[ProviderResponse, BaseModel | None]:
        schema = (
            response_model.model_json_schema() if response_model is not None else {"type": "object"}
        )
        repair = LLMMessage(
            role="user",
            content=(
                "Return corrected JSON only. The previous output was invalid.\n"
                f"Validation error: {validation_error}\n"
                f"Required schema: {json.dumps(schema, ensure_ascii=False, sort_keys=True)}\n"
                f"Invalid output: {invalid_content}"
            ),
        )
        repaired_messages = [
            *messages,
            LLMMessage(role="assistant", content=invalid_content),
            repair,
        ]
        return await self._attempt(
            self._fit_messages(repaired_messages),
            model_name=model_name,
            event_id=event_id,
            agent_name=agent_name,
            prompt_key=prompt_key,
            fallback_level=fallback_level,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=True,
            response_model=response_model,
            timeout=timeout,
        )

    @staticmethod
    def _parse(
        content: str,
        response_model: type[BaseModel] | None,
        *,
        finish_reason: str | None = None,
    ) -> BaseModel | None:
        if not content or not content.strip():
            raise LLMInvalidJSONError(
                "LLM returned empty structured output",
                invalid_content=content or "",
                validation_error="empty completion content",
                error_class="empty_content",
                finish_reason=finish_reason,
            )
        try:
            payload = json.loads(content)
            if not isinstance(payload, dict):
                raise ValueError("top-level JSON must be an object")
            return response_model.model_validate(payload) if response_model is not None else None
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            if isinstance(exc, ValidationError):
                error_class = "schema_validation"
                validation_error = json.dumps(
                    exc.errors(include_input=False, include_url=False),
                    ensure_ascii=False,
                )
            elif isinstance(exc, json.JSONDecodeError):
                error_class = "invalid_json"
                # Keep detail short and free of the offending body.
                validation_error = (
                    f"JSONDecodeError: {exc.msg} (line {exc.lineno} column {exc.colno})"
                )
            else:
                # Non-object top-level JSON is a structural/schema mismatch.
                error_class = "schema_validation"
                validation_error = str(exc)
            raise LLMInvalidJSONError(
                "LLM returned invalid structured output",
                invalid_content=content,
                validation_error=validation_error,
                error_class=error_class,
                finish_reason=finish_reason,
            ) from exc

    async def _check_convergence(
        self, event_id: str, agent_name: str, prompt_key: str, model_name: str
    ) -> None:
        guard = self.convergence_guard
        if guard is None:
            return
        signature = f"{agent_name}:{prompt_key}:{model_name}"
        record_step = guard.record_step
        if _is_async_callable(record_step):
            await guard.record_step(event_id, "llm_call", signature=signature)  # type: ignore[misc,func-returns-value]
        else:
            guard.record_step(event_id, "llm_call", signature=signature)

        should_stop = guard.should_stop
        if _is_async_callable(should_stop):
            decision = await guard.should_stop(event_id)
        else:
            decision = guard.should_stop(event_id)
        if bool(getattr(decision, "stop", False)):
            reason = str(getattr(decision, "reason", "convergence_guard"))
            raise LLMProviderError(
                "LLM request blocked by convergence guard",
                retryable=False,
                details={"reason": reason},
            )

    async def _check_budget(self, *, event_id: str, agent_name: str) -> None:
        if self.budget_service is None:
            return
        await self.budget_service.check(event_id, agent_name)

    async def _charge_budget(
        self, response: LLMResponse | ProviderResponse, *, event_id: str, agent_name: str
    ) -> None:
        if self.budget_service is not None:
            await self.budget_service.charge_llm(
                event_id,
                agent_name,
                response.model_name,
                response.prompt_tokens,
                response.completion_tokens,
            )
            return
        if self.budget_callback is None:
            return
        result = self.budget_callback(
            event_id=event_id,
            agent_name=agent_name,
            model_name=response.model_name,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
        )
        if inspect.isawaitable(result):
            await result

    async def _record_audit(self, entry: LLMCallAudit) -> None:
        try:
            await self.audit_recorder.record(entry)
        except Exception as exc:
            raise LLMAuditError(
                "failed to persist LLM call audit",
                details={"event_id": entry.event_id, "prompt_key": entry.prompt_key},
            ) from exc

    @staticmethod
    def _validate_context(
        event_id: str, agent_name: str, prompt_key: str, messages: list[LLMMessage]
    ) -> None:
        missing = [
            field
            for field, value in (
                ("event_id", event_id),
                ("agent_name", agent_name),
                ("prompt_key", prompt_key),
            )
            if not value.strip()
        ]
        if missing:
            raise ValueError(f"required LLM context is empty: {', '.join(missing)}")
        if not messages:
            raise ValueError("messages must not be empty")


def default_golden_root() -> Path:
    return Path(__file__).with_name("golden")


__all__ = [
    "BaseLLMClient",
    "BudgetCallback",
    "BudgetMeterHook",
    "ConvergenceGuardHook",
    "InMemoryLLMCallAuditRecorder",
    "LLMAuditError",
    "LLMAuthError",
    "LLM_CALL_ERROR_CLASSES",
    "LLMCallAudit",
    "LLMCallAuditRecorder",
    "LLMInvalidJSONError",
    "LLMMessage",
    "LLMProviderError",
    "LLMRateLimitedError",
    "LLMResponse",
    "LLMTimeoutError",
    "MessageBudgeterHook",
    "ProviderResponse",
    "SQLAlchemyLLMCallAuditRecorder",
    "bump_max_tokens",
    "classify_llm_call_failure",
    "default_golden_root",
    "ensure_json_mode_messages",
    "estimate_tokens",
    "sanitize_llm_error_detail",
]
