"""Evidence collection API tests (ISSUE-101)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import _get_context_store, get_event_service
from app.core.auth import Principal, get_principal
from app.main import app
from app.models.agent_io import CollectionStatus
from app.models.context import EventContext
from app.models.enums import EvidenceSource


class _EventService:
    def __init__(self, *, exists: bool = True) -> None:
        self._exists = exists

    async def get_event(self, event_id: str) -> object | None:
        return object() if self._exists else None


class _ContextStore:
    def __init__(
        self,
        evidence_output: dict[str, Any] | None,
        *,
        context_exists: bool = True,
        triage_result: dict[str, Any] | None = None,
    ) -> None:
        self._evidence_output = evidence_output
        self._context_exists = context_exists
        self._triage_result = triage_result

    async def get_full_context(self, event_id: str) -> EventContext:
        if not self._context_exists:
            raise KeyError(f"security_event not found: {event_id}")
        return EventContext(
            evidence_output=self._evidence_output,
            triage_result=self._triage_result,
        )


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _client(
    evidence_output: dict[str, Any] | None,
    *,
    event_exists: bool = True,
    context_exists: bool = True,
    triage_result: dict[str, Any] | None = None,
) -> TestClient:
    async def _principal() -> Principal:
        return Principal(subject="analyst-1", roles=["analyst"])

    async def _event_service() -> _EventService:
        return _EventService(exists=event_exists)

    def _context_store() -> _ContextStore:
        return _ContextStore(
            evidence_output,
            context_exists=context_exists,
            triage_result=triage_result,
        )

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_event_service] = _event_service
    app.dependency_overrides[_get_context_store] = _context_store
    return TestClient(app)


def _evidence_output() -> dict[str, Any]:
    return {
        "evidence_list": [],
        "conflicts": [],
        "gaps": [
            {
                "event_id": "evt-api-101",
                "missing_source": EvidenceSource.ENDPOINT.value,
                "reason": "source_skipped",
                "detail": {
                    "tool_name": "query_edr_process",
                    "description": "required entity missing or invalid for query_edr_process",
                },
            }
        ],
        "success_sources": [],
        "failed_sources": [EvidenceSource.ENDPOINT.value],
        "overall_confidence": 0.0,
        "collection_status": CollectionStatus.FAILED.value,
    }


def test_get_event_evidence_returns_gaps_and_collection_status() -> None:
    response = _client(_evidence_output()).get("/api/v1/events/evt-api-101/evidence")

    assert response.status_code == 200
    payload = response.json()
    assert payload["event_id"] == "evt-api-101"
    assert payload["collection_status"] == CollectionStatus.FAILED.value
    assert payload["gaps"][0]["reason"] == "source_skipped"
    assert payload["gaps"][0]["missing_source"] == EvidenceSource.ENDPOINT.value
    assert payload["query_summary"] == []


def test_get_event_evidence_not_ready_when_missing_output() -> None:
    response = _client(None).get("/api/v1/events/evt-api-101/evidence")

    assert response.status_code == 404
    assert response.json()["error_code"] == "evidence_not_ready"


def test_get_event_evidence_event_not_found_first() -> None:
    response = _client(_evidence_output(), event_exists=False).get(
        "/api/v1/events/missing/evidence"
    )

    assert response.status_code == 404
    assert response.json()["error_code"] == "event_not_found"


def test_get_event_evidence_includes_triage_context_chain() -> None:
    triage_result = {
        "event_type": "malicious_process",
        "severity": "high",
        "need_investigation": True,
        "degraded": True,
        "degradation_reasons": ["llm_timeout"],
        "entity_rejection_summary": {
            "rejection_counts": {"phrase_without_host_context": 2},
            "total_rejected": 2,
        },
        "entities": {},
        "ioc_list": [],
        "reasoning": "",
    }
    response = _client(
        _evidence_output(),
        triage_result=triage_result,
    ).get("/api/v1/events/evt-api-101/evidence")

    assert response.status_code == 200
    triage_context = response.json()["triage_context"]
    assert triage_context["degraded"] is True
    assert triage_context["degradation_reasons"] == ["llm_timeout"]
    assert triage_context["entity_rejection_summary"]["total_rejected"] == 2


def test_build_query_summary_items_exposes_tool_ok_empty() -> None:
    """ISSUE-249: observability map keeps provider_status separate from tool_ok_empty."""
    from types import SimpleNamespace

    from app.services.evidence_observability import build_query_summary_items

    rows = [
        SimpleNamespace(
            agent_name="evidence_agent",
            output_data={
                "query_timings": [
                    {
                        "tool_name": "query_dns",
                        "source": EvidenceSource.DNS.value,
                        "status": "tool_ok_empty",
                        "provider_status": "success",
                        "tool_outcome": "tool_ok_empty",
                        "execution_time_ms": 3,
                        "records_count": 0,
                        "gap_reason": "no_records",
                    },
                    {
                        "tool_name": "query_edr_process",
                        "source": EvidenceSource.ENDPOINT.value,
                        "status": "failed",
                        "provider_status": "failed",
                        "tool_outcome": "tool_failed",
                        "execution_time_ms": 4,
                        "records_count": 0,
                        "gap_reason": "tool_failed",
                    },
                ]
            },
        )
    ]

    summary = build_query_summary_items(rows)  # type: ignore[arg-type]
    by_tool = {item["tool_name"]: item for item in summary}
    assert by_tool["query_dns"]["tool_outcome"] == "tool_ok_empty"
    assert by_tool["query_dns"]["provider_status"] == "success"
    assert by_tool["query_dns"]["status"] == "tool_ok_empty"
    assert by_tool["query_dns"]["gap_reason"] == "no_records"
    assert by_tool["query_edr_process"]["tool_outcome"] == "tool_failed"
    assert by_tool["query_dns"]["tool_outcome"] != by_tool["query_edr_process"]["tool_outcome"]


def test_get_event_evidence_query_summary_exposes_tool_ok_empty(monkeypatch: Any) -> None:
    """ISSUE-249 API contract: GET /evidence surfaces tool_ok_empty in query_summary."""
    from types import SimpleNamespace

    from app.api.v1 import events as events_mod

    fake_row = SimpleNamespace(
        agent_name="evidence_agent",
        output_data={
            "query_timings": [
                {
                    "tool_name": "query_dns",
                    "source": EvidenceSource.DNS.value,
                    "status": "tool_ok_empty",
                    "provider_status": "success",
                    "tool_outcome": "tool_ok_empty",
                    "execution_time_ms": 2,
                    "records_count": 0,
                    "gap_reason": "no_records",
                }
            ]
        },
    )

    monkeypatch.setattr(events_mod, "_try_get_session_factory", lambda: object())

    async def _fake_db_read(*_args: Any, **_kwargs: Any) -> tuple[list[Any], int]:
        return [fake_row], 1

    monkeypatch.setattr(events_mod, "_db_read", _fake_db_read)

    evidence_output = _evidence_output()
    evidence_output["gaps"] = [
        {
            "event_id": "evt-api-249",
            "missing_source": EvidenceSource.DNS.value,
            "reason": "no_records",
            "detail": {
                "tool_name": "query_dns",
                "description": "query query_dns returned no usable evidence",
            },
        }
    ]
    evidence_output["failed_sources"] = []

    response = _client(evidence_output).get("/api/v1/events/evt-api-249/evidence")
    assert response.status_code == 200
    payload = response.json()
    assert payload["collection_status"] == CollectionStatus.FAILED.value
    assert payload["gaps"][0]["reason"] == "no_records"
    assert len(payload["query_summary"]) == 1
    item = payload["query_summary"][0]
    assert item["tool_name"] == "query_dns"
    assert item["tool_outcome"] == "tool_ok_empty"
    assert item["provider_status"] == "success"
    assert item["status"] == "tool_ok_empty"
    assert item["records_count"] == 0
    assert item["gap_reason"] == "no_records"
