"""Vendor-neutral LLM provider tests (ISSUE-027)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from pydantic import BaseModel

from app.agents.prompts.triage_prompt import TriageLLMResponse
from app.core.config import Settings
from app.core.errors import BudgetExceededError
from app.core.llm.base import (
    InMemoryLLMCallAuditRecorder,
    LLMAuditError,
    LLMInvalidJSONError,
    LLMMessage,
    LLMProviderError,
    LLMTimeoutError,
    SQLAlchemyLLMCallAuditRecorder,
    bump_max_tokens,
    classify_llm_call_failure,
    clear_event_llm_unavailable,
    ensure_json_mode_messages,
    event_llm_unavailable_reason,
    mark_event_llm_unavailable,
    sanitize_llm_error_detail,
)
from app.core.llm.factory import get_llm_client
from app.core.llm.mock_client import MockLLMClient
from app.db import models as orm
from app.providers.llm.openai_compatible import OpenAICompatibleLLMClient


class TriagePayload(BaseModel):
    event_type: str
    confidence: float


MESSAGES = [LLMMessage(role="user", content="Classify this event")]


def _response(
    content: str | None,
    *,
    model: str,
    prompt_tokens: int = 4,
    completion_tokens: int = 3,
    finish_reason: str | None = "stop",
) -> dict[str, Any]:
    choice: dict[str, Any] = {"message": {"content": content}}
    if finish_reason is not None:
        choice["finish_reason"] = finish_reason
    return {
        "model": model,
        "choices": [choice],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def _client(
    http_client: httpx.AsyncClient,
    *,
    audit: InMemoryLLMCallAuditRecorder | None = None,
    primary_model: str = "primary-model",
    fallback_models: tuple[str, ...] = (),
    **kwargs: Any,
) -> OpenAICompatibleLLMClient:
    clear_event_llm_unavailable()
    return OpenAICompatibleLLMClient(
        base_url="https://llm.example/v1",
        api_key="test-key",
        client=http_client,
        primary_model=primary_model,
        fallback_models=fallback_models,
        audit_recorder=audit,
        **kwargs,
    )


@pytest.mark.asyncio
async def test_mock_mode_is_deterministic_and_uses_scenario_then_default(
    tmp_path: Path,
) -> None:
    golden = tmp_path / "triage_extract"
    golden.mkdir()
    (golden / "default.json").write_text(
        json.dumps({"content": {"event_type": "other", "confidence": 0.4}}),
        encoding="utf-8",
    )
    (golden / "scenario-a.json").write_text(
        json.dumps({"content": {"event_type": "account_anomaly", "confidence": 0.9}}),
        encoding="utf-8",
    )
    audit = InMemoryLLMCallAuditRecorder()
    client = MockLLMClient(golden_root=tmp_path, audit_recorder=audit)

    first = await client.chat(
        MESSAGES,
        event_id="evt-2026-mock",
        agent_name="TriageAgent",
        prompt_key="triage_extract",
        scenario_id="scenario-a",
        response_model=TriagePayload,
    )
    second = await client.chat(
        MESSAGES,
        event_id="evt-2026-mock",
        agent_name="TriageAgent",
        prompt_key="triage_extract",
        scenario_id="missing-scenario",
        response_model=TriagePayload,
    )

    assert first.parsed == TriagePayload(event_type="account_anomaly", confidence=0.9)
    assert second.parsed == TriagePayload(event_type="other", confidence=0.4)
    assert first.fallback_level == second.fallback_level == 2
    assert [entry.status for entry in audit.entries] == ["success", "success"]


@pytest.mark.asyncio
async def test_mock_mode_never_constructs_or_calls_http(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_network(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("mock mode attempted network access")

    monkeypatch.setattr(httpx, "AsyncClient", fail_network)
    settings = Settings(
        LLM_MODE="mock",
        LLM_PRIMARY_MODEL="mock-model",
        APP_ENV="development",
    )
    client = get_llm_client(
        settings=settings,
        audit_recorder=InMemoryLLMCallAuditRecorder(),
    )

    response = await client.chat(
        MESSAGES,
        event_id="evt-2026-no-network",
        agent_name="TriageAgent",
        prompt_key="triage_extract",
        response_model=TriageLLMResponse,
    )
    assert response.model_name == "mock-model"


@pytest.mark.asyncio
async def test_json_mode_repairs_invalid_output_once_and_parses_model() -> None:
    calls: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        if len(calls) == 1:
            return httpx.Response(200, json=_response("not-json", model=payload["model"]))
        return httpx.Response(
            200,
            json=_response(
                '{"event_type":"host_compromise","confidence":0.87}',
                model=payload["model"],
            ),
        )

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        response = await _client(http_client, audit=audit).chat(
            MESSAGES,
            event_id="evt-2026-json",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
            json_mode=True,
            response_model=TriagePayload,
        )

    assert response.parsed == TriagePayload(event_type="host_compromise", confidence=0.87)
    assert len(calls) == 2
    assert calls[0]["response_format"] == {"type": "json_object"}
    assert any("JSON" in message["content"] for message in calls[0]["messages"])
    assert "Return corrected JSON only" in calls[1]["messages"][-1]["content"]
    assert [entry.status for entry in audit.entries] == ["llm_invalid_json", "success"]


@pytest.mark.asyncio
async def test_json_mode_raises_after_exactly_one_failed_repair() -> None:
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(200, json=_response("still-invalid", model="primary-model"))

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(LLMInvalidJSONError):
            await _client(http_client, audit=audit).chat(
                MESSAGES,
                event_id="evt-2026-bad-json",
                agent_name="TriageAgent",
                prompt_key="triage_extract",
                response_model=TriagePayload,
            )

    assert attempts == 2
    assert [entry.status for entry in audit.entries] == [
        "llm_invalid_json",
        "llm_invalid_json",
    ]
    assert all(entry.error_class == "invalid_json" for entry in audit.entries)
    assert all(entry.error_detail is not None for entry in audit.entries)
    assert all("still-invalid" not in (entry.error_detail or "") for entry in audit.entries)


async def _failing_structured_chat(
    content: str,
    *,
    event_id: str,
) -> tuple[InMemoryLLMCallAuditRecorder, LLMInvalidJSONError]:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_response(content, model="primary-model"))

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(LLMInvalidJSONError) as exc_info:
            await _client(http_client, audit=audit, fallback_models=()).chat(
                MESSAGES,
                event_id=event_id,
                agent_name="TriageAgent",
                prompt_key="triage_extract",
                response_model=TriagePayload,
            )
    return audit, exc_info.value


@pytest.mark.asyncio
async def test_audit_distinguishes_empty_content_and_invalid_json() -> None:
    """ISSUE-240: empty completion vs illegal JSON must be SQL-distinguishable."""

    empty_audit, empty_exc = await _failing_structured_chat(
        "",
        event_id="evt-2026-empty",
    )
    invalid_audit, invalid_exc = await _failing_structured_chat(
        "not-json{{{",
        event_id="evt-2026-invalid",
    )
    schema_audit, schema_exc = await _failing_structured_chat(
        '{"event_type":1,"confidence":"bad"}',
        event_id="evt-2026-schema",
    )

    assert empty_exc.error_class == "empty_content"
    assert invalid_exc.error_class == "invalid_json"
    assert schema_exc.error_class == "schema_validation"

    assert {entry.error_class for entry in empty_audit.entries} == {"empty_content"}
    assert {entry.error_class for entry in invalid_audit.entries} == {"invalid_json"}
    assert {entry.error_class for entry in schema_audit.entries} == {"schema_validation"}
    assert empty_audit.entries[0].error_class != invalid_audit.entries[0].error_class

    all_entries = empty_audit.entries + invalid_audit.entries + schema_audit.entries
    assert {entry.status for entry in all_entries} == {"llm_invalid_json"}
    assert all(entry.error_detail for entry in all_entries)
    assert all(entry.error_class is not None for entry in all_entries)
    assert all(len(entry.error_detail or "") <= 256 for entry in all_entries)

    joined = " ".join(entry.error_detail or "" for entry in all_entries)
    assert "sk-proj-" not in joined
    assert "api_key" not in joined.lower()
    assert "Classify this event" not in joined
    assert "not-json{{{" not in joined


def test_sanitize_llm_error_detail_redacts_and_truncates() -> None:
    detail = sanitize_llm_error_detail(
        "auth failed api_key=sk-proj-ABCDEFG1234567890 token=secret-value " + ("x" * 300)
    )
    assert detail is not None
    assert len(detail) <= 256
    assert "sk-proj-" not in detail
    assert "[REDACTED]" in detail


def test_classify_llm_call_failure_success_is_null() -> None:
    assert classify_llm_call_failure(status="success", error=None) == (None, None)


@pytest.mark.asyncio
async def test_empty_content_retries_once_with_higher_max_tokens() -> None:
    """ISSUE-239: empty content gets a bounded max_tokens bump, not blind model fallback."""

    calls: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        if len(calls) == 1:
            return httpx.Response(
                200,
                json=_response(
                    "",
                    model=payload["model"],
                    completion_tokens=48,
                    finish_reason="length",
                ),
            )
        return httpx.Response(
            200,
            json=_response(
                '{"event_type":"host_compromise","confidence":0.81}',
                model=payload["model"],
            ),
        )

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        response = await _client(http_client, audit=audit).chat(
            MESSAGES,
            event_id="evt-2026-empty-retry",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
            max_tokens=256,
            json_mode=True,
            response_model=TriagePayload,
        )

    assert response.parsed == TriagePayload(event_type="host_compromise", confidence=0.81)
    assert len(calls) == 2
    assert calls[0]["max_tokens"] == 256
    assert calls[1]["max_tokens"] == bump_max_tokens(256)
    assert "empty content" in calls[1]["messages"][-1]["content"].lower()
    assert [(entry.status, entry.error_class) for entry in audit.entries] == [
        ("llm_invalid_json", "empty_content"),
        ("success", None),
    ]


@pytest.mark.asyncio
async def test_empty_content_retry_charges_budget_only_on_success() -> None:
    charges: list[dict[str, Any]] = []

    async def charge(**kwargs: Any) -> None:
        charges.append(kwargs)

    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        payload = json.loads(request.content)
        if attempts == 1:
            return httpx.Response(
                200,
                json=_response("", model=payload["model"], completion_tokens=48),
            )
        return httpx.Response(
            200,
            json=_response(
                '{"event_type":"host_compromise","confidence":0.81}',
                model=payload["model"],
            ),
        )

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        await _client(http_client, audit=audit, budget_callback=charge).chat(
            MESSAGES,
            event_id="evt-2026-empty-budget",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
            max_tokens=256,
            json_mode=True,
            response_model=TriagePayload,
        )

    assert len(charges) == 1
    assert charges[0]["completion_tokens"] == 3


@pytest.mark.asyncio
async def test_empty_content_does_not_enter_json_repair_path() -> None:
    calls: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        return httpx.Response(
            200,
            json=_response(None, model="primary-model", completion_tokens=32),
        )

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(LLMInvalidJSONError) as exc_info:
            await _client(http_client, audit=audit).chat(
                MESSAGES,
                event_id="evt-2026-empty-fail",
                agent_name="TriageAgent",
                prompt_key="triage_extract",
                response_model=TriagePayload,
            )

    assert exc_info.value.error_class == "empty_content"
    assert len(calls) == 2
    assert [entry.error_class for entry in audit.entries] == ["empty_content", "empty_content"]
    # Second call is the empty-content bump hint, not the schema repair prompt.
    assert "empty content" in calls[1]["messages"][-1]["content"].lower()
    assert all("Return corrected JSON only" not in c["messages"][-1]["content"] for c in calls)


@pytest.mark.asyncio
async def test_length_truncated_invalid_json_bumps_tokens_before_repair() -> None:
    calls: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        if len(calls) == 1:
            return httpx.Response(
                200,
                json=_response(
                    '{"event_type":"host_compromise","confidence":',
                    model=payload["model"],
                    finish_reason="length",
                ),
            )
        return httpx.Response(
            200,
            json=_response(
                '{"event_type":"host_compromise","confidence":0.66}',
                model=payload["model"],
            ),
        )

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        response = await _client(http_client, audit=audit).chat(
            MESSAGES,
            event_id="evt-2026-trunc",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
            max_tokens=128,
            response_model=TriagePayload,
        )

    assert response.parsed == TriagePayload(event_type="host_compromise", confidence=0.66)
    assert len(calls) == 2
    assert calls[0]["max_tokens"] == 128
    assert calls[1]["max_tokens"] == bump_max_tokens(128)
    assert all("Return corrected JSON only" not in c["messages"][-1]["content"] for c in calls)
    assert [(entry.status, entry.error_class) for entry in audit.entries] == [
        ("llm_invalid_json", "invalid_json"),
        ("success", None),
    ]


def test_ensure_json_mode_messages_injects_hint_when_missing() -> None:
    ensured = ensure_json_mode_messages(MESSAGES)
    assert any("JSON" in message.content for message in ensured)
    already = [LLMMessage(role="user", content="Return JSON object")]
    assert ensure_json_mode_messages(already)[0].content == "Return JSON object"


@pytest.mark.asyncio
async def test_primary_timeout_does_not_retry_fallback() -> None:
    audit = InMemoryLLMCallAuditRecorder()

    with respx.mock(base_url="https://llm.example/v1") as router:
        route = router.post("/chat/completions")
        route.side_effect = [
            httpx.ReadTimeout("primary timed out"),
            httpx.Response(
                200,
                json=_response("fallback answer", model="fallback-model", prompt_tokens=7),
            ),
        ]
        async with httpx.AsyncClient(base_url="https://llm.example/v1") as http_client:
            with pytest.raises(LLMTimeoutError):
                await _client(
                    http_client,
                    audit=audit,
                    fallback_models=("fallback-model",),
                ).chat(
                    MESSAGES,
                    event_id="evt-2026-fallback",
                    agent_name="RiskAgent",
                    prompt_key="risk_score",
                )

    assert route.call_count == 1
    assert [(entry.model_name, entry.status, entry.fallback_level) for entry in audit.entries] == [
        ("primary-model", "llm_timeout", 0),
    ]


@pytest.mark.asyncio
async def test_event_timeout_short_circuits_later_prompts() -> None:
    audit = InMemoryLLMCallAuditRecorder()

    with respx.mock(base_url="https://llm.example/v1") as router:
        route = router.post("/chat/completions")
        route.side_effect = httpx.ReadTimeout("primary timed out")
        async with httpx.AsyncClient(base_url="https://llm.example/v1") as http_client:
            client = _client(http_client, audit=audit)
            with pytest.raises(LLMTimeoutError):
                await client.chat(
                    MESSAGES,
                    event_id="evt-2026-short-circuit",
                    agent_name="PlannerAgent",
                    prompt_key="plan_generate",
                )
            with pytest.raises(LLMTimeoutError) as second:
                await client.chat(
                    MESSAGES,
                    event_id="evt-2026-short-circuit",
                    agent_name="RiskAgent",
                    prompt_key="risk_score",
                )

    assert "short_circuit" in (second.value.details or {})
    assert route.call_count == 1
    assert [entry.prompt_key for entry in audit.entries] == ["plan_generate", "risk_score"]
    assert audit.entries[1].status == "llm_timeout"
    assert audit.entries[1].error_detail == "llm_unavailable_short_circuit"
    assert audit.entries[1].latency_ms == 0


def test_event_llm_unavailable_map_is_bounded_and_clearable() -> None:
    from app.core.llm.base import _MAX_EVENT_LLM_UNAVAILABLE  # noqa: SLF001

    clear_event_llm_unavailable()
    try:
        mark_event_llm_unavailable("evt-old")
        for index in range(_MAX_EVENT_LLM_UNAVAILABLE):
            mark_event_llm_unavailable(f"evt-bound-{index}")
        assert event_llm_unavailable_reason("evt-old") is None
        assert event_llm_unavailable_reason(f"evt-bound-{_MAX_EVENT_LLM_UNAVAILABLE - 1}") == (
            "llm_timeout"
        )
        clear_event_llm_unavailable("evt-bound-0")
        assert event_llm_unavailable_reason("evt-bound-0") is None
    finally:
        clear_event_llm_unavailable()


@pytest.mark.asyncio
async def test_clearing_event_timeout_allows_later_chat() -> None:
    audit = InMemoryLLMCallAuditRecorder()

    with respx.mock(base_url="https://llm.example/v1") as router:
        route = router.post("/chat/completions")
        route.side_effect = [
            httpx.ReadTimeout("primary timed out"),
            httpx.Response(
                200,
                json=_response("recovered answer", model="primary-model", prompt_tokens=4),
            ),
        ]
        async with httpx.AsyncClient(base_url="https://llm.example/v1") as http_client:
            client = _client(http_client, audit=audit)
            with pytest.raises(LLMTimeoutError):
                await client.chat(
                    MESSAGES,
                    event_id="evt-2026-retry-after-timeout",
                    agent_name="PlannerAgent",
                    prompt_key="plan_generate",
                )
            clear_event_llm_unavailable("evt-2026-retry-after-timeout")
            response = await client.chat(
                MESSAGES,
                event_id="evt-2026-retry-after-timeout",
                agent_name="RiskAgent",
                prompt_key="risk_score",
            )

    assert response.content == "recovered answer"
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_primary_provider_error_falls_back_and_marks_level_one() -> None:
    audit = InMemoryLLMCallAuditRecorder()

    with respx.mock(base_url="https://llm.example/v1") as router:
        route = router.post("/chat/completions")
        route.side_effect = [
            httpx.ConnectError("primary unavailable"),
            httpx.Response(
                200,
                json=_response("fallback answer", model="fallback-model", prompt_tokens=7),
            ),
        ]
        async with httpx.AsyncClient(base_url="https://llm.example/v1") as http_client:
            response = await _client(
                http_client,
                audit=audit,
                fallback_models=("fallback-model",),
            ).chat(
                MESSAGES,
                event_id="evt-2026-fallback",
                agent_name="RiskAgent",
                prompt_key="risk_score",
            )

    assert response.content == "fallback answer"
    assert response.model_name == "fallback-model"
    assert response.fallback_level == 1
    assert response.degraded_reason is not None
    assert [(entry.model_name, entry.status, entry.fallback_level) for entry in audit.entries] == [
        ("primary-model", "llm_provider_error", 0),
        ("fallback-model", "success", 1),
    ]


@pytest.mark.asyncio
async def test_exhausted_real_models_raise_without_mock_fallback() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unavailable", request=request)

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(LLMProviderError):
            await _client(
                http_client,
                audit=audit,
                fallback_models=("fallback-model",),
            ).chat(
                MESSAGES,
                event_id="evt-2026-exhausted",
                agent_name="ReportAgent",
                prompt_key="report_generate",
            )

    assert [entry.model_name for entry in audit.entries] == ["primary-model", "fallback-model"]
    assert all(entry.model_name != "mock-model" for entry in audit.entries)


@pytest.mark.asyncio
async def test_base_timeout_bounds_injected_or_custom_transport() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(1)
        return httpx.Response(
            200,
            json=_response("late", model="primary-model"),
            request=request,
        )

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(LLMTimeoutError):
            await _client(
                http_client,
                audit=audit,
                timeout_seconds=0.01,
            ).chat(
                MESSAGES,
                event_id="evt-2026-base-timeout",
                agent_name="RiskAgent",
                prompt_key="risk_score",
            )

    assert [(entry.status, entry.fallback_level) for entry in audit.entries] == [("llm_timeout", 0)]


def test_fallback_chain_deduplicates_primary_and_repeated_models() -> None:
    client = OpenAICompatibleLLMClient(
        base_url="https://llm.example/v1",
        api_key="test-key",
        primary_model="primary-model",
        fallback_models=("primary-model", "fallback-model", "fallback-model"),
        audit_recorder=InMemoryLLMCallAuditRecorder(),
    )
    assert client.fallback_models == ("fallback-model",)


@pytest.mark.asyncio
async def test_versioned_base_url_is_preserved_with_injected_client() -> None:
    requested_urls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(
            200,
            json=_response("ok", model="primary-model"),
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        await _client(http_client, audit=InMemoryLLMCallAuditRecorder()).chat(
            MESSAGES,
            event_id="evt-2026-url",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
        )

    assert requested_urls == ["https://llm.example/v1/chat/completions"]


@pytest.mark.asyncio
async def test_budget_exceeded_is_not_wrapped_or_retried() -> None:
    requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            json=_response("ok", model="primary-model"),
            request=request,
        )

    async def charge(**kwargs: Any) -> None:
        del kwargs
        raise BudgetExceededError("budget exhausted")

    audit = InMemoryLLMCallAuditRecorder()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(BudgetExceededError):
            await _client(
                http_client,
                audit=audit,
                fallback_models=("fallback-model",),
                budget_callback=charge,
            ).chat(
                MESSAGES,
                event_id="evt-2026-budget",
                agent_name="RiskAgent",
                prompt_key="risk_score",
            )

    assert requests == 1
    assert [(entry.model_name, entry.status) for entry in audit.entries] == [
        ("primary-model", "budget_exceeded")
    ]


@pytest.mark.asyncio
async def test_audit_failure_prevents_unaudited_success() -> None:
    class BrokenAudit:
        async def record(self, entry: object) -> None:
            del entry
            raise RuntimeError("database unavailable")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_response("ok", model="primary-model"),
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(LLMAuditError):
            await _client(http_client, audit=BrokenAudit()).chat(  # type: ignore[arg-type]
                MESSAGES,
                event_id="evt-2026-audit-down",
                agent_name="RiskAgent",
                prompt_key="risk_score",
            )


@pytest.mark.asyncio
async def test_guard_and_budget_hooks_run_for_each_actual_request() -> None:
    class Guard:
        def __init__(self) -> None:
            self.steps: list[tuple[str, str, str]] = []

        def record_step(
            self,
            event_id: str,
            step_type: str,
            signature: str = "",
            **_: Any,
        ) -> None:
            self.steps.append((event_id, step_type, signature))

        def should_stop(self, event_id: str) -> Any:
            return SimpleNamespace(stop=False, reason="none")

    charges: list[dict[str, Any]] = []

    async def charge(**kwargs: Any) -> None:
        charges.append(kwargs)

    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        content = "bad" if attempts == 1 else '{"event_type":"other","confidence":0.6}'
        return httpx.Response(200, json=_response(content, model="primary-model"))

    guard = Guard()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        await _client(
            http_client,
            audit=InMemoryLLMCallAuditRecorder(),
            convergence_guard=guard,
            budget_callback=charge,
        ).chat(
            MESSAGES,
            event_id="evt-2026-hooks",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
            response_model=TriagePayload,
        )

    assert len(guard.steps) == 2
    assert all(step[1] == "llm_call" for step in guard.steps)
    # First invalid-json attempt parses before charge; only the repair success bills budget.
    assert len(charges) == 1
    assert charges[0]["prompt_tokens"] == 4


@pytest.mark.asyncio
async def test_each_success_and_failure_attempt_is_persisted_as_orm_rows() -> None:
    class Session:
        def __init__(self, rows: list[orm.LLMCallLog]) -> None:
            self.rows = rows
            self.committed = False

        async def __aenter__(self) -> Session:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        def add(self, row: orm.LLMCallLog) -> None:
            self.rows.append(row)

        async def commit(self) -> None:
            self.committed = True

    rows: list[orm.LLMCallLog] = []
    sessions: list[Session] = []

    def session_factory() -> Session:
        session = Session(rows)
        sessions.append(session)
        return session

    event_id = "evt-2026-llm-audit"

    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("primary unavailable", request=request)
        return httpx.Response(200, json=_response("ok", model="fallback-model"))

    recorder = SQLAlchemyLLMCallAuditRecorder(session_factory)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        await _client(
            http_client,
            audit=recorder,
            fallback_models=("fallback-model",),
        ).chat(
            MESSAGES,
            event_id=event_id,
            agent_name="RiskAgent",
            prompt_key="risk_score",
        )

    assert [(row.prompt_key, row.status, row.fallback_level, row.error_class) for row in rows] == [
        ("risk_score", "llm_provider_error", 0, "provider"),
        ("risk_score", "success", 1, None),
    ]
    assert rows[0].error_detail is not None
    assert rows[1].error_detail is None
    assert all(session.committed for session in sessions)


@pytest.mark.asyncio
async def test_unknown_mock_prompt_fails_explicitly() -> None:
    audit = InMemoryLLMCallAuditRecorder()
    client = MockLLMClient(audit_recorder=audit)
    with pytest.raises(LLMProviderError) as exc:
        await client.chat(
            MESSAGES,
            event_id="evt-2026-unknown",
            agent_name="TriageAgent",
            prompt_key="unknown_prompt",
        )
    assert exc.value.retryable is False
    assert [(entry.status, entry.fallback_level) for entry in audit.entries] == [
        ("llm_provider_error", 2)
    ]


@pytest.mark.asyncio
async def test_mock_storyline_golden_binds_prompt_evidence_ids() -> None:
    from app.agents.prompts.storyline_prompt import build_storyline_messages

    audit = InMemoryLLMCallAuditRecorder()
    client = MockLLMClient(audit_recorder=audit)
    evidence = [
        {
            "evidence_id": "evd-bind-login",
            "source": "identity",
            "evidence_type": "login",
            "description": "账号 zhangsan 从 10.20.30.23 登录",
            "timestamp": "2024-06-15T09:00:00Z",
        },
        {
            "evidence_id": "evd-bind-rar",
            "source": "endpoint",
            "evidence_type": "process_create",
            "description": "主机 PC-FIN-023 上 rar.exe 进程启动",
            "timestamp": "2024-06-15T09:01:00Z",
        },
        {
            "evidence_id": "evd-bind-file",
            "source": "data_security",
            "evidence_type": "file_access",
            "description": "账号 zhangsan 访问文件 financial_data.zip",
            "timestamp": "2024-06-15T09:02:00Z",
        },
        {
            "evidence_id": "evd-bind-net",
            "source": "network_flow",
            "evidence_type": "outbound",
            "description": "PC-FIN-023 连接外部 IP 203.0.113.88",
            "timestamp": "2024-06-15T09:03:00Z",
        },
        {
            "evidence_id": "evd-bind-dns",
            "source": "dns",
            "evidence_type": "dns_query",
            "description": "DNS 解析 unknown-upload-example.com 到 203.0.113.88",
            "timestamp": "2024-06-15T09:04:00Z",
        },
    ]
    messages = build_storyline_messages(
        evidence_entries=evidence,
        technique_matches=[],
        graph_paths=[],
        entity_names=["zhangsan"],
    )
    response = await client.chat(
        messages,
        event_id="evt-storyline-bind",
        agent_name="storyline_service",
        prompt_key="storyline_generate",
        scenario_id="insider_data_exfiltration",
        json_mode=True,
    )
    payload = json.loads(response.content)
    bound_ids = {
        str(entry.get("evidence_id") or "")
        for phase in payload.get("phases") or []
        for entry in (phase.get("entries") or [])
        if isinstance(phase, dict)
    }
    catalog = {item["evidence_id"] for item in evidence}
    assert bound_ids <= catalog
    assert bound_ids, "production MockLLM must bind catalog evidence_id values"
    assert "" not in bound_ids


def test_mock_llm_client_requires_audit_recorder() -> None:
    with pytest.raises(ValueError, match="audit_recorder is required"):
        MockLLMClient()


def test_llm_timeout_is_not_retryable() -> None:
    assert LLMTimeoutError().retryable is False


@pytest.mark.asyncio
async def test_cancelled_after_timeout_classified_preserves_status() -> None:
    class _CancelOnFirstAudit(InMemoryLLMCallAuditRecorder):
        def __init__(self) -> None:
            super().__init__()
            self._cancelled_once = False

        async def record(self, entry: object) -> None:
            if not self._cancelled_once:
                self._cancelled_once = True
                raise asyncio.CancelledError()
            await super().record(entry)  # type: ignore[arg-type]

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(1)
        return httpx.Response(
            200,
            json=_response("late", model="primary-model"),
            request=request,
        )

    audit = _CancelOnFirstAudit()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(asyncio.CancelledError):
            await _client(
                http_client,
                audit=audit,
                fallback_models=("fallback-model",),
                timeout_seconds=0.05,
            ).chat(
                MESSAGES,
                event_id="evt-2026-cancel-after-timeout",
                agent_name="ReportAgent",
                prompt_key="report_generate",
            )

    assert len(audit.entries) == 1
    assert audit.entries[0].status == "llm_timeout"
    assert audit.entries[0].error_class == "timeout"
    assert audit.entries[0].error_detail is not None
    assert len(audit.entries[0].error_detail or "") <= 256


@pytest.mark.asyncio
async def test_cancelled_inflight_attempt_records_minimal_audit() -> None:
    audit = InMemoryLLMCallAuditRecorder()

    async def handler(request: httpx.Request) -> httpx.Response:
        try:
            while True:
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            raise

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = _client(http_client, audit=audit, timeout_seconds=30.0)
        task = asyncio.create_task(
            client.chat(
                MESSAGES,
                event_id="evt-2026-cancelled",
                agent_name="ReportAgent",
                prompt_key="report_generate",
            )
        )
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert len(audit.entries) == 1
    assert audit.entries[0].status == "llm_provider_error"
    assert audit.entries[0].error_class == "provider"


@pytest.mark.asyncio
async def test_llm_chat_reraises_soft_time_limit_without_wrapping_or_fallback() -> None:
    """ISSUE-314: SoftTimeLimitExceeded must not become retryable LLMProviderError."""
    from celery.exceptions import SoftTimeLimitExceeded

    from app.core.llm.base import BaseLLMClient, ProviderResponse

    class _SoftLimitClient(BaseLLMClient):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.request_calls = 0

        async def _request(self, *args: Any, **kwargs: Any) -> ProviderResponse:
            self.request_calls += 1
            raise SoftTimeLimitExceeded()

    audit = InMemoryLLMCallAuditRecorder()
    client = _SoftLimitClient(
        primary_model="primary-model",
        fallback_models=("fallback-model",),
        audit_recorder=audit,
        timeout_seconds=5.0,
    )
    with pytest.raises(SoftTimeLimitExceeded):
        await client.chat(
            MESSAGES,
            event_id="evt-314-soft-llm",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
        )
    # Soft-limit must not enter fallback model retry.
    assert client.request_calls == 1
    assert audit.entries == []


@pytest.mark.asyncio
async def test_mock_llm_chat_reraises_soft_time_limit() -> None:
    """ISSUE-314: MockLLMClient must not wrap SoftTimeLimitExceeded."""
    from celery.exceptions import SoftTimeLimitExceeded

    audit = InMemoryLLMCallAuditRecorder()
    client = MockLLMClient(golden_root=Path("/tmp/no-golden"), audit_recorder=audit)

    async def _raise_soft(*_a: Any, **_k: Any) -> None:
        raise SoftTimeLimitExceeded()

    client._check_budget = _raise_soft  # type: ignore[method-assign]
    with pytest.raises(SoftTimeLimitExceeded):
        await client.chat(
            MESSAGES,
            event_id="evt-314-mock-soft",
            agent_name="TriageAgent",
            prompt_key="triage_extract",
        )
    assert audit.entries == []
