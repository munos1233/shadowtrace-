"""Approval decision_id idempotency API projection (ISSUE-281 / ID-CTR-006)."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import get_approval_engine
from app.core.config import get_settings
from app.main import app
from app.models.enums import ActionStatus
from app.services.approval_engine import ApprovalOutcome

_DEV_TOKENS = json.dumps(
    {
        "approver-token": {"subject": "approver-1", "roles": ["approver"]},
    }
)


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer approver-token"}


@pytest.fixture
def client() -> TestClient:
    yield TestClient(app)


def test_reject_after_approve_same_decision_id_returns_409(
    client: TestClient,
) -> None:
    class _CrossOperationEngine:
        async def approve(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome(
                persisted_status=ActionStatus.APPROVED,
                decision_id="dec-shared",
            )

        async def reject(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            from app.core.errors import ApprovalDecisionConflictError

            raise ApprovalDecisionConflictError(
                "decision_id replay operation or payload mismatch",
                details={"decision_id": "dec-shared"},
            )

        async def scan_timeouts(self) -> list[str]:
            return []

    async def _engine() -> _CrossOperationEngine:
        return _CrossOperationEngine()

    app.dependency_overrides[get_approval_engine] = _engine
    try:
        approve_resp = client.post(
            "/api/v1/actions/act-cross/approve",
            headers=_hdr(),
            json={"comment": "ok", "decision_id": "dec-shared"},
        )
        reject_resp = client.post(
            "/api/v1/actions/act-cross/reject",
            headers=_hdr(),
            json={"comment": "no", "decision_id": "dec-shared"},
        )
    finally:
        app.dependency_overrides.pop(get_approval_engine, None)

    assert approve_resp.status_code == 200, approve_resp.text
    assert approve_resp.json()["status"] == "approved"
    assert reject_resp.status_code == 409, reject_resp.text


def test_idempotent_replay_projects_persisted_status(
    client: TestClient,
) -> None:
    class _ReplayEngine:
        async def approve(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome(
                persisted_status=ActionStatus.APPROVED,
                decision_id="dec-replay",
                idempotent_replay=True,
            )

        async def reject(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome(
                persisted_status=ActionStatus.REJECTED,
                decision_id="dec-replay",
                idempotent_replay=True,
            )

        async def scan_timeouts(self) -> list[str]:
            return []

    async def _engine() -> _ReplayEngine:
        return _ReplayEngine()

    app.dependency_overrides[get_approval_engine] = _engine
    try:
        approve_resp = client.post(
            "/api/v1/actions/act-replay/approve",
            headers=_hdr(),
            json={"comment": "ok", "decision_id": "dec-replay"},
        )
        reject_resp = client.post(
            "/api/v1/actions/act-replay/reject",
            headers=_hdr(),
            json={"comment": "no", "decision_id": "dec-replay"},
        )
    finally:
        app.dependency_overrides.pop(get_approval_engine, None)

    assert approve_resp.status_code == 200, approve_resp.text
    assert approve_resp.json()["status"] == "approved"
    assert reject_resp.status_code == 200, reject_resp.text
    assert reject_resp.json()["status"] == "rejected"
