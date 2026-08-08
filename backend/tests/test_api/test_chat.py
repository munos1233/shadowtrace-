"""Conversational event Q&A API and service tests (ISSUE-076)."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import create_api_router
from app.api.v1.chat import get_event_qa_service
from app.api.v1.deps import get_event_service
from app.core.auth import Principal, get_principal
from app.core.llm.base import InMemoryLLMCallAuditRecorder, LLMInvalidJSONError, LLMProviderError
from app.core.llm.mock_client import MockLLMClient
from app.main import app
from app.services.event_qa_service import (
    ChatAnswer,
    ChatHistoryItem,
    ChatReference,
    EventQAService,
)


class _EventService:
    def __init__(self, *, exists: bool = True) -> None:
        self.exists = exists

    async def get_event(self, event_id: str) -> object | None:
        return object() if self.exists else None


class _QAService:
    def __init__(
        self,
        answer: ChatAnswer | None = None,
        *,
        fail: bool = False,
        error: Exception | None = None,
    ) -> None:
        self.result = answer or ChatAnswer(answer="基于评分与证据，事件为高危。")
        self.fail = fail
        self.error = error or RuntimeError("provider unavailable")
        self.calls: list[tuple[str, str, list[ChatHistoryItem]]] = []

    async def answer(
        self,
        event_id: str,
        question: str,
        history: list[ChatHistoryItem],
    ) -> ChatAnswer:
        self.calls.append((event_id, question, history))
        if self.fail:
            raise self.error
        return self.result


class _ContextStore:
    def __init__(self, context: Any) -> None:
        self.context = context

    async def get_full_context(self, event_id: str) -> Any:
        return self.context


class _TraceService:
    def __init__(self, trace: Any) -> None:
        self.trace = trace

    async def get_decision_trace(self, event_id: str) -> Any:
        return self.trace


class _CapturingLLM:
    def __init__(self, answer: ChatAnswer) -> None:
        self.answer = answer
        self.messages: list[Any] = []
        self.kwargs: dict[str, Any] = {}

    async def chat(self, messages: list[Any], **kwargs: Any) -> Any:
        self.messages = messages
        self.kwargs = kwargs
        return SimpleNamespace(parsed=self.answer, content=self.answer.model_dump_json())


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _client(
    qa_service: _QAService,
    *,
    event_exists: bool = True,
) -> TestClient:
    async def _principal() -> Principal:
        return Principal(subject="analyst-1", roles=["analyst"])

    async def _event_service() -> _EventService:
        return _EventService(exists=event_exists)

    async def _qa_service() -> _QAService:
        return qa_service

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_event_service] = _event_service
    app.dependency_overrides[get_event_qa_service] = _qa_service
    return TestClient(app)


def _context() -> Any:
    return SimpleNamespace(
        event={
            "event_id": "evt-076",
            "event_type": "account_anomaly",
            "title": "异常管理员登录",
            "status": "analyzing",
            "severity": "high",
            "risk_score": 88,
            "final_verdict": "confirmed_threat",
        },
        risk_assessment={
            "risk_score": 88,
            "severity": "high",
            "confidence": 0.91,
            "risk_factors": [
                {
                    "factor_name": "behavior_anomaly",
                    "raw_score": 92,
                    "weighted_score": 18.4,
                    "reasoning": "异常位置登录并访问敏感资产",
                }
            ],
        },
        evidence_output={
            "evidence_list": [
                {
                    "evidence_id": "evd-event-qa-001",
                    "source": "identity",
                    "evidence_type": "login",
                    "description": "管理员从异常位置登录",
                    "confidence": 0.94,
                    "raw_data": {"token": "must-not-reach-prompt"},
                }
            ]
        },
        report=None,
    )


def _trace() -> Any:
    return SimpleNamespace(
        entries=[
            {
                "entry_id": "trace-risk-1",
                "entry_type": "agent_execution",
                "timestamp": "2026-07-28T08:00:00Z",
                "actor": "RiskAgent",
                "title": "完成高危评分",
                "detail": {
                    "structured_conclusion": "高危",
                    "confidence": 0.91,
                    "hidden_reasoning": "must-not-reach-prompt",
                },
                "ref_id": "agent-run-1",
            }
        ]
    )


def test_chat_endpoint_returns_answer_and_references() -> None:
    qa = _QAService(
        ChatAnswer(
            answer="风险评分和登录证据共同支持高危结论。",
            references=[
                ChatReference(ref_type="evidence", ref_id="evd-event-qa-001"),
            ],
        )
    )

    response = _client(qa).post(
        "/api/v1/events/evt-076/chat",
        json={
            "question": "为什么判定为高危",
            "history": [{"role": "user", "content": "先概括事件"}],
        },
    )

    assert response.status_code == 200
    assert response.json()["references"] == [{"ref_type": "evidence", "ref_id": "evd-event-qa-001"}]
    assert qa.calls[0][0:2] == ("evt-076", "为什么判定为高危")
    assert qa.calls[0][2][0].role == "user"


def test_chat_endpoint_returns_event_not_found_before_qa() -> None:
    qa = _QAService()

    response = _client(qa, event_exists=False).post(
        "/api/v1/events/missing/chat",
        json={"question": "为什么高危", "history": []},
    )

    assert response.status_code == 404
    assert response.json()["error_code"] == "event_not_found"
    assert qa.calls == []


def test_chat_endpoint_maps_optional_service_failure_to_503() -> None:
    response = _client(
        _QAService(fail=True, error=LLMProviderError("provider unavailable")),
    ).post(
        "/api/v1/events/evt-076/chat",
        json={"question": "为什么高危", "history": []},
    )

    assert response.status_code == 503
    assert response.json() == {
        "error_code": "qa_unavailable",
        "error_message": "event Q&A is temporarily unavailable",
        "details": {"event_id": "evt-076"},
    }


def test_chat_endpoint_returns_context_not_ready_when_context_missing() -> None:
    response = _client(_QAService(fail=True, error=KeyError("evt-076"))).post(
        "/api/v1/events/evt-076/chat",
        json={"question": "为什么高危", "history": []},
    )

    assert response.status_code == 404
    assert response.json() == {
        "error_code": "context_not_ready",
        "error_message": "context for event evt-076 is not ready",
        "details": {"event_id": "evt-076"},
    }


def test_chat_endpoint_maps_empty_question_to_validation_error() -> None:
    response = _client(
        _QAService(fail=True, error=ValueError("question must not be empty")),
    ).post(
        "/api/v1/events/evt-076/chat",
        json={"question": "为什么高危", "history": []},
    )

    assert response.status_code == 422
    assert response.json()["error_code"] == "validation_error"
    assert "question must not be empty" in response.json()["error_message"]


def test_chat_endpoint_maps_invalid_llm_json_to_503() -> None:
    response = _client(
        _QAService(
            fail=True,
            error=LLMInvalidJSONError(
                "invalid json from provider",
                invalid_content="{not-json",
                validation_error="Expecting value",
            ),
        ),
    ).post(
        "/api/v1/events/evt-076/chat",
        json={"question": "为什么高危", "history": []},
    )

    assert response.status_code == 503
    assert response.json()["error_code"] == "qa_unavailable"


def test_chat_endpoint_rejects_more_than_ten_history_items() -> None:
    response = _client(_QAService()).post(
        "/api/v1/events/evt-076/chat",
        json={
            "question": "为什么高危",
            "history": [{"role": "user", "content": str(index)} for index in range(11)],
        },
    )

    assert response.status_code == 422


async def test_mock_mode_is_deterministic_and_returns_grounded_reference() -> None:
    service = EventQAService(
        context_store=_ContextStore(_context()),
        decision_trace_service=_TraceService(_trace()),
        llm_client=MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
    )

    first = await service.answer("evt-076", "为什么判定为高危", [])
    second = await service.answer("evt-076", "为什么判定为高危", [])

    assert first == second
    assert "Mock" in first.answer
    assert first.references == []


async def test_service_filters_invalid_references_and_bounds_safe_context() -> None:
    context = _context()
    context.evidence_output["evidence_list"].extend(
        {
            "evidence_id": f"evd-extra-{index:02d}",
            "source": "endpoint",
            "evidence_type": "process",
            "description": f"证据 {index}",
            "confidence": 0.8,
        }
        for index in range(25)
    )
    llm = _CapturingLLM(
        ChatAnswer(
            answer="评分依据见引用。",
            references=[
                ChatReference(ref_type="evidence", ref_id="missing-evidence"),
                ChatReference(ref_type="trace", ref_id="trace-risk-1"),
                ChatReference(ref_type="trace", ref_id="trace-risk-1"),
            ],
        )
    )
    service = EventQAService(
        context_store=_ContextStore(context),
        decision_trace_service=_TraceService(_trace()),
        llm_client=llm,
    )

    answer = await service.answer(
        "evt-076",
        "Authorization: Bearer super-secret-token 为什么高危",
        [ChatHistoryItem(role="assistant", content="token=history-secret")],
    )

    assert answer.references == [ChatReference(ref_type="trace", ref_id="trace-risk-1")]
    assert llm.kwargs["prompt_key"] == "event_qa"
    assert llm.kwargs["json_mode"] is True
    context_message = llm.messages[1].content
    assert context_message.index("## 1. 事件概要") < context_message.index("## 2. 风险评分摘要")
    assert context_message.index("## 2. 风险评分摘要") < context_message.index("## 3. 证据摘要")
    assert context_message.index("## 3. 证据摘要") < context_message.index("## 4. 决策轨迹摘要")
    assert "evd-extra-19" not in context_message
    assert "must-not-reach-prompt" not in context_message
    assert "super-secret-token" not in llm.messages[-1].content
    assert "history-secret" not in llm.messages[2].content


def test_chat_router_can_be_disabled_without_removing_core_routes() -> None:
    disabled_app = FastAPI()
    disabled_app.include_router(create_api_router(include_chat=False))
    paths = set(disabled_app.openapi()["paths"])

    assert "/events/{event_id}/chat" not in paths
    assert "/events" in paths
    assert "/health" in paths


def test_chat_openapi_declares_request_and_response_models() -> None:
    operation = app.openapi()["paths"]["/api/v1/events/{event_id}/chat"]["post"]

    assert operation["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/ChatRequest"
    )
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/ChatAnswer"
    )
