"""Approve/reject API resume_status exposure (ISSUE-193)."""

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


def test_approve_response_includes_resume_failed_and_degraded(
    client: TestClient,
) -> None:
    class _ResumeFailedEngine:
        async def approve(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome(
                resume_status="failed",
                resume_degraded=True,
                persisted_status=ActionStatus.APPROVED,
            )

        async def reject(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome()

        async def scan_timeouts(self) -> list[str]:
            return []

    async def _engine() -> _ResumeFailedEngine:
        return _ResumeFailedEngine()

    app.dependency_overrides[get_approval_engine] = _engine
    try:
        resp = client.post(
            "/api/v1/actions/act-resume-fail/approve",
            headers=_hdr(),
            json={"comment": "approved despite resume failure"},
        )
    finally:
        app.dependency_overrides.pop(get_approval_engine, None)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "approved"
    assert body["resume_status"] == "failed"
    assert body["degraded"] is True


def test_approve_response_omits_degraded_when_resume_ok(
    client: TestClient,
) -> None:
    class _ResumeOkEngine:
        async def approve(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome(
                resume_status="ok",
                resume_degraded=False,
                persisted_status=ActionStatus.APPROVED,
            )

        async def reject(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome()

        async def scan_timeouts(self) -> list[str]:
            return []

    async def _engine() -> _ResumeOkEngine:
        return _ResumeOkEngine()

    app.dependency_overrides[get_approval_engine] = _engine
    try:
        resp = client.post(
            "/api/v1/actions/act-resume-ok/approve",
            headers=_hdr(),
            json={"comment": "ok"},
        )
    finally:
        app.dependency_overrides.pop(get_approval_engine, None)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resume_status"] == "ok"
    assert body.get("degraded") is None
