"""Asynchronous OpenAI-compatible chat completions provider."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.llm.base import (
    BaseLLMClient,
    LLMAuthError,
    LLMMessage,
    LLMProviderError,
    LLMRateLimitedError,
    LLMTimeoutError,
    ProviderResponse,
)
from app.core.llm.json_extract import JsonExtractError, extract_json_object
from app.core.llm.url_utils import normalize_llm_base_url

_REASONING_PART_TYPES = frozenset({"reasoning", "thinking", "reason"})
_ANSWER_PART_TYPES = frozenset({"text", "output_text", "json", "output_json"})


def _normalize_message_content(content: Any) -> str:
    """Normalize provider content to a string; null/parts become empty or joined text."""

    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        answer_parts: list[str] = []
        reasoning_parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                answer_parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            part_type = str(item.get("type") or "").strip().lower()
            text = item.get("text")
            if not isinstance(text, str):
                nested = item.get("content")
                text = nested if isinstance(nested, str) else ""
            if not text:
                continue
            if part_type in _REASONING_PART_TYPES:
                reasoning_parts.append(text)
            elif part_type in _ANSWER_PART_TYPES or not part_type:
                answer_parts.append(text)
            else:
                answer_parts.append(text)
        if answer_parts:
            return "".join(answer_parts)
        return "".join(reasoning_parts)
    raise TypeError("message content must be a string, null, or content parts")


def _reasoning_text(message: dict[str, Any]) -> str:
    for key in ("reasoning_content", "reasoning", "thinking"):
        alt = message.get(key)
        if isinstance(alt, str) and alt.strip():
            return alt
    return ""


def _extractable_json_text(*candidates: str) -> str | None:
    for candidate in candidates:
        if not (candidate or "").strip():
            continue
        try:
            extract_json_object(candidate)
        except JsonExtractError:
            continue
        return candidate
    return None


def _completion_text(message: dict[str, Any], *, prefer_json: bool = False) -> str:
    """Prefer visible content; fall back to reasoning fields used by glm thinking.

    In json_mode, only keep a channel that actually contains a JSON object so
    think-only dumps become empty_content (retry) instead of invalid_json.
    """

    content = _normalize_message_content(message.get("content"))
    reasoning = _reasoning_text(message)
    if prefer_json:
        extracted = _extractable_json_text(content, reasoning)
        if extracted is not None:
            return extracted
        if not content.strip():
            return ""
        try:
            extract_json_object(content)
        except JsonExtractError as exc:
            if exc.error_class == "empty_content":
                return ""
        return content
    if content.strip():
        return content
    return reasoning or content


def _should_disable_thinking(*, model_name: str, base_url: str) -> bool:
    model = model_name.strip().lower()
    host = urlparse(base_url).netloc.lower()
    return (
        model.startswith("glm")
        or "glm-" in model
        or "volces.com" in host
        or "volcengine" in host
        or host.startswith("ark.")
        or ".ark." in host
    )


class OpenAICompatibleLLMClient(BaseLLMClient):
    """Client for APIs implementing the public OpenAI chat-completions shape."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> None:
        if not base_url.strip():
            raise ValueError("base_url is required for openai_compatible mode")
        super().__init__(**kwargs)
        self._base_url = normalize_llm_base_url(base_url)
        self._api_key = api_key
        self._client = client
        self._owns_client = client is None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(self.timeout_seconds),
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        messages: list[LLMMessage],
        *,
        model_name: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> ProviderResponse:
        client = await self._http()
        payload: dict[str, Any] = {
            "model": model_name,
            "messages": [message.model_dump(exclude_none=True) for message in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
            if _should_disable_thinking(model_name=model_name, base_url=self._base_url):
                # glm-5.x thinking mode leaves content empty / non-JSON; structured
                # agents need the answer channel, not the chain-of-thought channel.
                payload["thinking"] = {"type": "disabled"}
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

        try:
            response = await self._post_chat(client, payload, headers)
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(
                "LLM request timed out", details={"model_name": model_name}
            ) from exc
        except httpx.TransportError as exc:
            raise LLMProviderError(
                "LLM transport failed", details={"model_name": model_name}
            ) from exc

        if (
            json_mode
            and response.status_code >= 400
            and "thinking" in payload
            and response.status_code not in {401, 403, 429}
        ):
            payload.pop("thinking", None)
            try:
                response = await self._post_chat(client, payload, headers)
            except httpx.TimeoutException as exc:
                raise LLMTimeoutError(
                    "LLM request timed out", details={"model_name": model_name}
                ) from exc
            except httpx.TransportError as exc:
                raise LLMProviderError(
                    "LLM transport failed", details={"model_name": model_name}
                ) from exc

        if response.status_code in {401, 403}:
            raise LLMAuthError(
                "LLM provider rejected credentials",
                details={"model_name": model_name, "status": response.status_code},
            )
        if response.status_code == 429:
            raise LLMRateLimitedError(
                "LLM provider rate limited the request",
                details={"model_name": model_name, "status": response.status_code},
            )
        if response.status_code >= 400:
            raise LLMProviderError(
                "LLM provider returned an error",
                details={"model_name": model_name, "status": response.status_code},
            )

        try:
            body = response.json()
            choice = body["choices"][0]
            message = choice["message"]
            content = _completion_text(message, prefer_json=json_mode)
            finish_reason = choice.get("finish_reason")
            if finish_reason is not None and not isinstance(finish_reason, str):
                finish_reason = str(finish_reason)
            usage = body.get("usage") or {}
            prompt_tokens = int(usage.get("prompt_tokens") or 0)
            completion_tokens = int(usage.get("completion_tokens") or 0)
            total_tokens = int(usage.get("total_tokens") or 0)
            response_model_name = str(body.get("model") or model_name)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMProviderError(
                "LLM provider returned a malformed response",
                retryable=False,
                details={"model_name": model_name},
            ) from exc

        return ProviderResponse(
            content=content,
            model_name=response_model_name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens or prompt_tokens + completion_tokens,
            finish_reason=finish_reason,
        )

    async def _post_chat(
        self,
        client: httpx.AsyncClient,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> httpx.Response:
        timeout_s = getattr(self, "_active_request_timeout", None)
        if timeout_s is None:
            timeout_s = self.timeout_seconds
        return await client.post(
            f"{self._base_url}/chat/completions",
            json=payload,
            headers=headers,
            timeout=httpx.Timeout(timeout_s),
        )

    async def probe_chat(self, *, model_name: str | None = None) -> ProviderResponse:
        """Minimal synthetic chat used by health/smoke probes (ISSUE-106)."""
        return await self._request(
            [LLMMessage(role="user", content="ping")],
            model_name=model_name or self.primary_model,
            temperature=0.0,
            max_tokens=1,
            json_mode=False,
        )

    async def probe_models(self) -> int:
        """Optional GET /models probe; returns HTTP status (not all providers support it)."""
        client = await self._http()
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        try:
            response = await client.get(f"{self._base_url}/models", headers=headers)
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(
                "LLM models probe timed out",
                details={"endpoint": "models"},
            ) from exc
        except httpx.TransportError as exc:
            raise LLMProviderError(
                "LLM models probe transport failed",
                details={"endpoint": "models"},
            ) from exc
        if response.status_code in {401, 403}:
            raise LLMAuthError(
                "LLM provider rejected credentials",
                details={"endpoint": "models", "status": response.status_code},
            )
        if response.status_code == 429:
            raise LLMRateLimitedError(
                "LLM provider rate limited the models probe",
                details={"endpoint": "models", "status": response.status_code},
            )
        if response.status_code >= 400:
            raise LLMProviderError(
                "LLM models probe returned an error",
                details={"endpoint": "models", "status": response.status_code},
            )
        return int(response.status_code)


__all__ = ["OpenAICompatibleLLMClient"]
