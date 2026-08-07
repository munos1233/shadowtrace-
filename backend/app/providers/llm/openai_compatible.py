"""Asynchronous OpenAI-compatible chat completions provider."""

from __future__ import annotations

from typing import Any

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
from app.core.llm.url_utils import normalize_llm_base_url


def _normalize_message_content(content: Any) -> str:
    """Normalize provider content to a string; null/parts become empty or joined text."""

    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
                elif item.get("type") == "text" and isinstance(item.get("content"), str):
                    parts.append(item["content"])
        return "".join(parts)
    raise TypeError("message content must be a string, null, or content parts")


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
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

        try:
            response = await client.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=headers,
            )
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
            content = _normalize_message_content(message.get("content"))
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
