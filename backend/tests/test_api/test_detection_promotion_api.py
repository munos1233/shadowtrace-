"""Detection promotion API tests (ISSUE-124 / #629)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.auth import Principal, get_principal
from app.core.errors import ResourceNotFoundError, ValidationError
from app.main import app
from app.models.detection_promotion import (
    DetectionPromotionRecord,
    DetectionPromotionResult,
    DetectionPromotionStatus,
)


def _record(**overrides: Any) -> DetectionPromotionRecord:
    now = datetime(2026, 8, 4, tzinfo=UTC)
    payload: dict[str, Any] = {
        "promotion_id": "dprom-test",
        "tenant_id": "tenant-a",
        "promotion_key": "pk-test",
        "status": DetectionPromotionStatus.COMPLETED,
        "decision_id": "dgov-test",
        "candidate_detection_id": "cdet-1",
        "candidate_content_hash": "c" * 64,
        "package_id": "drpkg-test",
        "package_version": 1,
        "package_content_hash": "p" * 64,
        "detection_scope_id": "dscope-test",
        "event_id": "evt-promoted",
        "created_at": now,
        "updated_at": now,
    }
    payload.update(overrides)
    return DetectionPromotionRecord(**payload)


class _FakePromotion:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.gate_closed = False
        self.record = _record()

    async def promote_candidate(self, artifact: Any, request: Any) -> DetectionPromotionResult:
        self.calls.append(("promote", request.candidate_detection_id, artifact.evaluation_id))
        if self.gate_closed:
            raise ValidationError(
                "promotion blocked: governance gate closed",
                details={"reason_codes": ["no_active_approval"]},
            )
        return DetectionPromotionResult(
            promotion_id=self.record.promotion_id,
            status=self.record.status,
            record=self.record,
            resumed=False,
        )

    async def get_promotion(self, promotion_id: str, *, tenant_id: str) -> DetectionPromotionRecord:
        self.calls.append(("get", promotion_id, tenant_id))
        if promotion_id != self.record.promotion_id or tenant_id != self.record.tenant_id:
            raise ResourceNotFoundError(
                "detection promotion not found",
                details={"promotion_id": promotion_id, "tenant_id": tenant_id},
            )
        return self.record

    async def list_promotions(self, **kwargs: Any) -> tuple[list[DetectionPromotionRecord], int]:
        self.calls.append(("list", kwargs))
        if kwargs.get("tenant_id") != self.record.tenant_id:
            return [], 0
        return [self.record], 1


@pytest.fixture
def promotion_client(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, _FakePromotion]:
    fake = _FakePromotion()
    from app.api.v1 import deps

    app.dependency_overrides[deps.get_detection_promotion_service] = lambda: fake

    async def _principal() -> Principal:
        return Principal(subject="api-approver", roles=["approver"], tenant_id="tenant-a")

    app.dependency_overrides[get_principal] = _principal
    client = TestClient(app)
    yield client, fake
    app.dependency_overrides.clear()


def _minimal_artifact_payload() -> dict[str, Any]:
    return {
        "evaluation_id": "deval-api-test",
        "tenant_id": "tenant-a",
        "dataset_id": "detection_shadow_v1",
        "dataset_version": "2026.08.02",
        "dataset_content_hash": "b" * 64,
        "code_sha": "abc1234",
        "config": {
            "seed": 42,
            "cutoff_at": "2026-08-01T15:30:00Z",
            "candidate_refs": {
                "package_id": "drpkg-test",
                "package_version": 1,
                "package_content_hash": "a" * 64,
                "feature_contract_version": "1.0",
                "detection_scope_id": "dscope-test",
            },
        },
        "started_at": "2026-08-01T15:00:00Z",
        "completed_at": "2026-08-01T15:05:00Z",
        "status": "completed",
        "aggregates": {
            "case_count": 1,
            "pass_count": 1,
            "fail_count": 0,
            "unevaluable_count": 0,
            "error_count": 0,
            "pass_rate": 1.0,
            "required_scorer_error_count": 0,
        },
        "artifact_hash": "f" * 64,
    }


def test_create_promotion_requires_approver(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, fake = promotion_client

    async def _analyst() -> Principal:
        return Principal(subject="analyst-only", roles=["analyst"], tenant_id="tenant-a")

    app.dependency_overrides[get_principal] = _analyst
    response = client.post(
        "/api/v1/detection/promotions",
        json={
            "tenant_id": "tenant-a",
            "candidate_detection_id": "cdet-1",
            "artifact": _minimal_artifact_payload(),
        },
    )
    assert response.status_code == 403
    assert fake.calls == []


def test_create_promotion_from_artifact(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, fake = promotion_client
    response = client.post(
        "/api/v1/detection/promotions",
        json={
            "tenant_id": "tenant-a",
            "candidate_detection_id": "cdet-1",
            "decision_id": "dgov-test",
            "artifact": _minimal_artifact_payload(),
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["promotion_id"] == "dprom-test"
    assert body["status"] == "completed"
    assert body["record"]["event_id"] == "evt-promoted"
    assert fake.calls[0][0] == "promote"


def test_create_promotion_from_path(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, fake = promotion_client
    app.dependency_overrides[get_principal] = lambda: Principal(
        subject="eval-approver", roles=["approver"], tenant_id="tenant-detection-eval"
    )
    response = client.post(
        "/api/v1/detection/promotions",
        json={
            "tenant_id": "tenant-detection-eval",
            "candidate_detection_id": "cdet-1",
            "artifact_path": "detection_shadow_v1/baseline_artifact.json",
        },
    )
    assert response.status_code == 200
    assert fake.calls[0][0] == "promote"
    assert fake.calls[0][2]


def test_create_promotion_path_escape_rejected(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, fake = promotion_client
    response = client.post(
        "/api/v1/detection/promotions",
        json={
            "tenant_id": "tenant-a",
            "candidate_detection_id": "cdet-1",
            "artifact_path": "../../../etc/passwd",
        },
    )
    assert response.status_code == 422
    assert fake.calls == []


def test_create_promotion_requires_artifact_or_path(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, _ = promotion_client
    response = client.post(
        "/api/v1/detection/promotions",
        json={"tenant_id": "tenant-a", "candidate_detection_id": "cdet-1"},
    )
    assert response.status_code == 422


def test_create_promotion_gate_closed(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, fake = promotion_client
    fake.gate_closed = True
    response = client.post(
        "/api/v1/detection/promotions",
        json={
            "tenant_id": "tenant-a",
            "candidate_detection_id": "cdet-1",
            "artifact": _minimal_artifact_payload(),
        },
    )
    assert response.status_code == 422
    assert response.json()["error_code"] == "validation_error"


def test_list_promotions(promotion_client: tuple[TestClient, _FakePromotion]) -> None:
    client, fake = promotion_client
    response = client.get(
        "/api/v1/detection/promotions",
        params={"tenant_id": "tenant-a", "candidate_detection_id": "cdet-1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["promotion_id"] == "dprom-test"
    assert fake.calls[0][0] == "list"


def test_list_promotions_requires_tenant_id(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, _ = promotion_client
    response = client.get("/api/v1/detection/promotions")
    assert response.status_code == 422


def test_get_promotion(promotion_client: tuple[TestClient, _FakePromotion]) -> None:
    client, _ = promotion_client
    response = client.get(
        "/api/v1/detection/promotions/dprom-test",
        params={"tenant_id": "tenant-a"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "completed"


def test_get_promotion_not_found(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, _ = promotion_client
    response = client.get(
        "/api/v1/detection/promotions/missing",
        params={"tenant_id": "tenant-a"},
    )
    assert response.status_code == 404


def test_list_promotions_allows_analyst(
    promotion_client: tuple[TestClient, _FakePromotion],
) -> None:
    client, _ = promotion_client

    async def _analyst() -> Principal:
        return Principal(subject="analyst-only", roles=["analyst"], tenant_id="tenant-a")

    app.dependency_overrides[get_principal] = _analyst
    response = client.get(
        "/api/v1/detection/promotions",
        params={"tenant_id": "tenant-a"},
    )
    assert response.status_code == 200


@pytest.mark.parametrize("role", ["approver", "analyst"])
@pytest.mark.parametrize("path", ["", "/dprom-test"])
def test_cross_tenant_promotion_reads_denied(promotion_client, role, path):
    client, fake = promotion_client
    app.dependency_overrides[get_principal] = lambda: Principal(
        subject="tenant-a-user", roles=[role], tenant_id="tenant-a"
    )
    fake.record = _record(tenant_id="tenant-b")
    response = client.get(f"/api/v1/detection/promotions{path}", params={"tenant_id": "tenant-b"})
    assert response.status_code == 404
    assert fake.calls == []


@pytest.mark.parametrize("from_path", [False, True])
def test_cross_tenant_promotion_denied_before_loading_or_execution(promotion_client, from_path):
    client, fake = promotion_client
    fake.record = _record(tenant_id="tenant-b")
    artifact = _minimal_artifact_payload() | {"tenant_id": "tenant-b"}
    source = {"artifact_path": "nonexistent.json"} if from_path else {"artifact": artifact}
    response = client.post(
        "/api/v1/detection/promotions",
        json={
            "tenant_id": "tenant-b",
            "candidate_detection_id": "cdet-1",
            **source,
        },
    )
    assert response.status_code == 404
    assert fake.calls == []


def test_foreign_artifact_with_own_tenant_denied(promotion_client):
    client, fake = promotion_client
    response = client.post(
        "/api/v1/detection/promotions",
        json={
            "tenant_id": "tenant-a",
            "candidate_detection_id": "cdet-1",
            "artifact": _minimal_artifact_payload() | {"tenant_id": "tenant-b"},
        },
    )
    assert response.status_code == 404
    assert fake.calls == []


def test_projection_error_survives_list_and_detail(promotion_client):
    client, fake = promotion_client
    fake.record = _record(
        context_projection_error={
            "reason": "context_projection_failed",
            "message": "projection unavailable",
        }
    )
    listed = client.get("/api/v1/detection/promotions", params={"tenant_id": "tenant-a"})
    detail = client.get("/api/v1/detection/promotions/dprom-test", params={"tenant_id": "tenant-a"})
    assert listed.status_code == detail.status_code == 200
    assert (
        listed.json()["items"][0]["context_projection_error"]["message"] == "projection unavailable"
    )
    assert detail.json()["context_projection_error"]["reason"] == "context_projection_failed"
