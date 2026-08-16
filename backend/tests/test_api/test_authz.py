"""AuthN / AuthZ tests (ISSUE-004 step 6)."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import schemas as s
from app.api.v1.deps import get_approval_engine
from app.core.config import get_settings
from app.main import app
from app.models.enums import ActionStatus
from app.services.approval_engine import ApprovalOutcome
from tests.test_support.production_settings import apply_production_env

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
        "approver-token": {"subject": "approver-1", "roles": ["approver"]},
        "operator-token": {"subject": "op-1", "roles": ["disposition_operator"]},
        "admin-token": {"subject": "admin-1", "roles": ["admin"]},
    }
)


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from app.api.v1.deps import get_disposition_sync as _real_get_disposition_sync
    from app.api.v1.deps import get_event_service as _real_get_event_service
    from app.api.v1.deps import get_execution_job_query_service as _real_get_execution_job_query
    from app.api.v1.deps import get_state_machine as _real_get_state_machine
    from tests.test_api.test_contracts import (
        _MockDispositionSyncService,
        _MockEventService,
        _MockExecutionJobQueryService,
        _MockStateMachine,
    )

    class _StubApprovalEngine:
        async def approve(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome(persisted_status=ActionStatus.APPROVED)

        async def reject(self, *args: object, **kwargs: object) -> ApprovalOutcome:
            return ApprovalOutcome(persisted_status=ActionStatus.REJECTED)

        async def scan_timeouts(self) -> list[str]:
            return []

    async def _mock_event_service() -> _MockEventService:
        return _MockEventService()

    async def _mock_state_machine() -> _MockStateMachine:
        return _MockStateMachine()

    async def _stub_engine() -> _StubApprovalEngine:
        return _StubApprovalEngine()

    async def _mock_disposition_sync() -> _MockDispositionSyncService:
        return _MockDispositionSyncService()

    async def _mock_execution_job_query() -> _MockExecutionJobQueryService:
        return _MockExecutionJobQueryService()

    app.dependency_overrides[get_approval_engine] = _stub_engine
    app.dependency_overrides[_real_get_event_service] = _mock_event_service
    app.dependency_overrides[_real_get_state_machine] = _mock_state_machine
    app.dependency_overrides[_real_get_disposition_sync] = _mock_disposition_sync
    app.dependency_overrides[_real_get_execution_job_query] = _mock_execution_job_query
    yield TestClient(app)
    app.dependency_overrides.pop(get_approval_engine, None)
    app.dependency_overrides.pop(_real_get_event_service, None)
    app.dependency_overrides.pop(_real_get_state_machine, None)
    app.dependency_overrides.pop(_real_get_disposition_sync, None)
    app.dependency_overrides.pop(_real_get_execution_job_query, None)


def _hdr(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {role}-token"}


def test_anonymous_is_rejected(client: TestClient) -> None:
    resp = client.get("/api/v1/events")
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "unauthorized"


def test_wrong_role_is_forbidden(client: TestClient) -> None:
    # analyst cannot approve (needs approver).
    resp = client.post(
        "/api/v1/actions/act-1/approve", headers=_hdr("analyst"), json={"comment": "ok"}
    )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "forbidden"


def test_approver_can_approve(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/actions/act-1/approve", headers=_hdr("approver"), json={"comment": "ok"}
    )
    assert resp.status_code == 200


def test_body_cannot_forge_operator(client: TestClient) -> None:
    # extra="forbid" on the request model rejects a client-supplied operator.
    resp = client.post(
        "/api/v1/actions/act-1/approve",
        headers=_hdr("approver"),
        json={"comment": "ok", "operator": "root"},
    )
    assert resp.status_code == 422
    assert resp.json()["error_code"] == "validation_error"


def test_retry_requires_disposition_operator(client: TestClient) -> None:
    forbidden = client.post("/api/v1/writebacks/wbk-0a1b2c3d/retry", headers=_hdr("analyst"))
    assert forbidden.status_code == 403
    ok = client.post("/api/v1/writebacks/wbk-0a1b2c3d/retry", headers=_hdr("operator"))
    assert ok.status_code == 200


def test_resolve_writeback_requires_admin(client: TestClient) -> None:
    body = {
        "resolution": "manual_confirmed",
        "comment": "verified",
        "evidence_ref": "evidence://verified",
    }
    forbidden = client.post(
        "/api/v1/writebacks/wbk-0a1b2c3d/resolve", headers=_hdr("operator"), json=body
    )
    assert forbidden.status_code == 403
    ok = client.post("/api/v1/writebacks/wbk-0a1b2c3d/resolve", headers=_hdr("admin"), json=body)
    assert ok.status_code == 200


def test_force_local_close_requires_admin(client: TestClient) -> None:
    body = {"reason": "manual", "force_local_close": True}
    forbidden = client.post(
        f"/api/v1/events/{s.EXAMPLE_EVENT_ID}/close", headers=_hdr("analyst"), json=body
    )
    assert forbidden.status_code == 403
    ok = client.post(f"/api/v1/events/{s.EXAMPLE_EVENT_ID}/close", headers=_hdr("admin"), json=body)
    assert ok.status_code == 200
    assert ok.json()["external_unsynced"] is True


def test_trusted_proxy_headers_only_honored_when_enabled(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = {"X-Auth-Subject": "proxied-user", "X-Auth-Roles": "analyst"}
    # Disabled proxy: identity headers are ignored -> anonymous -> 401.
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "false")
    get_settings.cache_clear()
    disabled = client.get("/api/v1/events", headers=headers)
    assert disabled.status_code == 401

    # Enabled + client host allowlisted: headers are honored.
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "true")
    monkeypatch.setenv("TRUSTED_PROXY_ALLOWLIST", "testclient")
    get_settings.cache_clear()
    enabled = client.get("/api/v1/events", headers=headers)
    assert enabled.status_code == 200

    # Enabled but client host NOT allowlisted: headers ignored -> 401.
    monkeypatch.setenv("TRUSTED_PROXY_ALLOWLIST", "10.0.0.1")
    get_settings.cache_clear()
    blocked = client.get("/api/v1/events", headers=headers)
    assert blocked.status_code == 401


def test_trusted_proxy_strips_unknown_roles(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "true")
    monkeypatch.setenv("TRUSTED_PROXY_ALLOWLIST", "testclient")
    get_settings.cache_clear()

    mixed = client.get(
        "/api/v1/events",
        headers={
            "X-Auth-Subject": "proxied-user",
            "X-Auth-Roles": "analyst,superuser",
        },
    )
    assert mixed.status_code == 200

    unknown_only = client.get(
        "/api/v1/events",
        headers={
            "X-Auth-Subject": "proxied-user",
            "X-Auth-Roles": "superuser,root",
        },
    )
    assert unknown_only.status_code == 403
    assert unknown_only.json()["error_code"] == "forbidden"

    unknown_only_post = client.post(
        "/api/v1/events",
        headers={
            "X-Auth-Subject": "proxied-user",
            "X-Auth-Roles": "superuser,root",
        },
        json={
            "title": "probe",
            "description": "probe",
            "event_type": "malicious_process",
            "severity": "high",
        },
    )
    assert unknown_only_post.status_code == 403
    assert unknown_only_post.json()["error_code"] == "forbidden"


def test_trusted_proxy_accepts_case_insensitive_roles(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "true")
    monkeypatch.setenv("TRUSTED_PROXY_ALLOWLIST", "testclient")
    get_settings.cache_clear()

    resp = client.get(
        "/api/v1/events",
        headers={
            "X-Auth-Subject": "proxied-user",
            "X-Auth-Roles": "Analyst,ADMIN",
        },
    )
    assert resp.status_code == 200


def test_dev_token_rejected_in_production(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    apply_production_env(monkeypatch)
    # ISSUE-217: a non-empty DEV_AUTH_TOKENS is itself a production
    # fail-closed violation, so clear it to exercise the auth-layer gate here.
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "false")
    monkeypatch.setenv("DEV_AUTH_TOKENS", "")
    get_settings.cache_clear()
    resp = client.get("/api/v1/events", headers=_hdr("admin"))
    assert resp.status_code == 401


def test_dev_token_rejected_when_app_env_has_surrounding_whitespace(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """APP_ENV with leading/trailing whitespace must still be treated as production.

    ISSUE-217: auth._is_production must apply the same strip() semantics as
    Settings.production_fail_closed_violations, so a padded APP_ENV cannot
    silently re-enable the DEV_AUTH_TOKENS path.
    """
    apply_production_env(monkeypatch, APP_ENV="  production  ")
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "false")
    monkeypatch.setenv("DEV_AUTH_TOKENS", "")
    get_settings.cache_clear()
    resp = client.get("/api/v1/events", headers=_hdr("admin"))
    assert resp.status_code == 401


def test_is_production_strips_surrounding_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-217: _is_production must share the config gate's strip() semantics.

    This is the direct regression guard for the bug: before the fix,
    ``APP_ENV=" production"`` made _is_production() return False while
    production_fail_closed_violations treated it as production.
    """
    from app.core import auth

    apply_production_env(monkeypatch)
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "false")
    # The autouse _dev_auth fixture sets DEV_AUTH_TOKENS, which is itself a
    # production fail-closed violation; clear it to reach the production cases.
    monkeypatch.setenv("DEV_AUTH_TOKENS", "")

    for env, expected in (
        ("production", True),
        (" production", True),
        ("production ", True),
        ("  production  ", True),
        ("Production", True),
        ("development", False),
        ("staging", False),
    ):
        monkeypatch.setenv("APP_ENV", env)
        get_settings.cache_clear()
        assert auth._is_production() is expected
    get_settings.cache_clear()
