"""Attack-storyline timeline API tests (ISSUE-070)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import _get_context_store, get_event_service
from app.core.auth import Principal, get_principal
from app.main import app
from app.models.context import EventContext


class _EventService:
    def __init__(self, *, exists: bool = True) -> None:
        self._exists = exists

    async def get_event(self, event_id: str) -> object | None:
        return object() if self._exists else None


_JOURNAL_UNSET = object()


class _ContextStore:
    def __init__(
        self,
        storyline: dict[str, Any] | None,
        *,
        context_exists: bool = True,
        journal_storyline: Any = _JOURNAL_UNSET,
    ) -> None:
        self._storyline = storyline
        self._context_exists = context_exists
        self._journal_storyline = journal_storyline

    async def get_full_context(self, event_id: str) -> EventContext:
        if not self._context_exists:
            raise KeyError(f"security_event not found: {event_id}")
        return EventContext(storyline=self._storyline)

    async def get_versioned_field(self, event_id: str, key: str) -> tuple[Any, int]:
        if key != "storyline":
            return None, 0
        if self._journal_storyline is _JOURNAL_UNSET:
            return self._storyline, 1
        return self._journal_storyline, 1


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _client(
    storyline: dict[str, Any] | None,
    *,
    event_exists: bool = True,
    context_exists: bool = True,
    journal_storyline: Any = _JOURNAL_UNSET,
) -> TestClient:
    async def _principal() -> Principal:
        return Principal(subject="analyst-1", roles=["analyst"])

    async def _event_service() -> _EventService:
        return _EventService(exists=event_exists)

    def _context_store() -> _ContextStore:
        return _ContextStore(
            storyline,
            context_exists=context_exists,
            journal_storyline=journal_storyline,
        )

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_event_service] = _event_service
    app.dependency_overrides[_get_context_store] = _context_store
    return TestClient(app)


def _storyline() -> dict[str, Any]:
    return {
        "storyline_id": "sty-api-070",
        "event_id": "evt-api-070",
        "narrative_summary": "攻击者使用有效账户收集并外传数据。",
        "generated_by": "rule",
        "phases": [
            {
                "phase_order": 1,
                "phase_name": "initial_access",
                "tactic": "Initial Access",
                "narrative": "异常账户登录。",
                "entries": [
                    {
                        "timestamp": "2026-07-27T08:00:00Z",
                        "description": "攻击者使用有效账户登录。",
                        "evidence_id": "ev-api-070",
                        "technique_id": "T1078",
                        "severity_hint": "high",
                    }
                ],
            }
        ],
    }


def test_timeline_returns_event_context_storyline() -> None:
    response = _client(_storyline()).get("/api/v1/events/evt-api-070/timeline")

    assert response.status_code == 200
    payload = response.json()
    assert payload["storyline_id"] == "sty-api-070"
    assert payload["generated_by"] == "rule"
    assert payload["phases"][0]["entries"][0]["evidence_id"] == "ev-api-070"


def test_timeline_returns_storyline_not_ready() -> None:
    response = _client(None).get("/api/v1/events/evt-api-070/timeline")

    assert response.status_code == 404
    assert response.json() == {
        "error_code": "storyline_not_ready",
        "error_message": "storyline for event evt-api-070 is not ready",
        "details": {"event_id": "evt-api-070"},
    }


def test_timeline_returns_storyline_not_ready_when_context_is_absent() -> None:
    response = _client(_storyline(), context_exists=False).get(
        "/api/v1/events/evt-api-070/timeline"
    )

    assert response.status_code == 404
    assert response.json()["error_code"] == "storyline_not_ready"


def test_timeline_returns_event_not_found_first() -> None:
    response = _client(_storyline(), event_exists=False).get("/api/v1/events/missing/timeline")

    assert response.status_code == 404
    assert response.json()["error_code"] == "event_not_found"


def test_timeline_openapi_declares_attack_storyline_response() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/api/v1/events/{event_id}/timeline"]["get"]
    response_ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert response_ref.endswith("/AttackStoryline")


def _snapshot_summary() -> dict[str, Any]:
    """ISSUE-254 bounded blob: counters, no phases, no event_id."""
    return {
        "storyline_id": "sty-api-070",
        "grounding_status": "evidence_grounded",
        "generated_by": "llm",
        "phase_count": 5,
        "claim_ref_count": 2,
        "narrative_summary": "summary only",
        "schema_version": "1.0",
    }


def test_timeline_snapshot_summary_is_not_ready_not_500() -> None:
    """CLOSED rebuild may put the snapshot summary in EventContext.storyline."""
    response = _client(
        _snapshot_summary(),
        journal_storyline=None,
    ).get("/api/v1/events/evt-api-070/timeline")

    assert response.status_code == 404
    assert response.json()["error_code"] == "storyline_not_ready"


def test_timeline_loads_journal_when_context_only_has_snapshot_summary() -> None:
    response = _client(
        _snapshot_summary(),
        journal_storyline=_storyline(),
    ).get("/api/v1/events/evt-api-070/timeline")

    assert response.status_code == 200
    payload = response.json()
    assert payload["generated_by"] == "rule"
    assert payload["event_id"] == "evt-api-070"
    assert payload["phases"][0]["entries"][0]["evidence_id"] == "ev-api-070"
    assert "phase_count" not in payload


def test_timeline_rejects_journal_summary_the_same_way() -> None:
    response = _client(
        _snapshot_summary(),
        journal_storyline=_snapshot_summary(),
    ).get("/api/v1/events/evt-api-070/timeline")

    assert response.status_code == 404
    assert response.json()["error_code"] == "storyline_not_ready"
