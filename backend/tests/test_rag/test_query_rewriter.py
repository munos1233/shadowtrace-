"""QueryRewriter fail-soft and structured-output hardening (ISSUE-239)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.core.llm.base import InMemoryLLMCallAuditRecorder, LLMInvalidJSONError, bump_max_tokens
from app.providers.llm.openai_compatible import OpenAICompatibleLLMClient
from app.rag.context import RetrievalContext
from app.rag.query_rewriter import QueryRewriteError, QueryRewriter


def _ctx() -> RetrievalContext:
    return RetrievalContext(
        tenant_id="tenant-a",
        principal="analyst-a",
        event_id="evt-2026-qr",
        trace_id="trace-qr-001",
    )


def _response(content: str | None, *, completion_tokens: int = 8) -> dict[str, Any]:
    return {
        "model": "primary-model",
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": completion_tokens,
            "total_tokens": 12 + completion_tokens,
        },
    }


@pytest.mark.asyncio
async def test_query_rewrite_recovers_from_empty_content_and_keeps_json_contract() -> None:
    calls: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        if len(calls) == 1:
            return httpx.Response(200, json=_response("", completion_tokens=64))
        return httpx.Response(
            200,
            json=_response('{"rewrites":["lateral movement hunt","credential abuse keywords"]}'),
        )

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = OpenAICompatibleLLMClient(
            base_url="https://llm.example/v1",
            api_key="test-key",
            client=http_client,
            primary_model="primary-model",
            audit_recorder=audit,
        )
        rewriter = QueryRewriter(client, agent_name="RAGAgent")
        rewritten = await rewriter.rewrite("ransomware attack", context=_ctx())

    assert rewritten[0] == "ransomware attack"
    assert "lateral movement hunt" in rewritten
    assert calls[0]["max_tokens"] == 768
    assert calls[1]["max_tokens"] == bump_max_tokens(768)
    assert calls[0]["response_format"] == {"type": "json_object"}
    assert any("JSON" in message["content"] for message in calls[0]["messages"])
    assert [(entry.status, entry.error_class) for entry in audit.entries] == [
        ("llm_invalid_json", "empty_content"),
        ("success", None),
    ]


@pytest.mark.asyncio
async def test_query_rewrite_fail_soft_on_persistent_empty_content() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_response(None, completion_tokens=40))

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = OpenAICompatibleLLMClient(
            base_url="https://llm.example/v1",
            api_key="test-key",
            client=http_client,
            primary_model="primary-model",
            audit_recorder=audit,
        )
        rewriter = QueryRewriter(client, agent_name="RAGAgent")
        with pytest.raises(QueryRewriteError) as exc_info:
            await rewriter.rewrite("phishing campaign", context=_ctx())

    cause = exc_info.value.__cause__
    assert isinstance(cause, LLMInvalidJSONError)
    assert cause.error_class == "empty_content"
    assert [entry.error_class for entry in audit.entries] == ["empty_content", "empty_content"]
