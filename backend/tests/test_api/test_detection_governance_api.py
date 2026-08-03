"""Detection governance API tests (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.auth import Principal, get_principal
from app.main import app


class _FakeGovernance:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    async def assess_eligibility(
        self, artifact: Any, *, threshold_manifest_path: Any = None, principal: Any = None
    ) -> Any:
        from app.models.detection_governance import DetectionGovernanceEligibilityAssessment

        self.calls.append(("assess", artifact.evaluation_id))
        return DetectionGovernanceEligibilityAssessment(eligible=True)

    async def record_decision(
        self, principal: Principal, artifact: Any, request: Any, **kwargs: Any
    ) -> Any:
        from app.models.detection_governance import (
            DetectionGovernanceCandidateBinding,
            DetectionGovernanceDecision,
            DetectionGovernanceDecisionKind,
            DetectionGovernanceEvaluationBinding,
            DetectionGovernanceThresholdBinding,
        )
        from app.services.detection_governance_binding import finalize_decision

        self.calls.append(("record", request.decision.value))
        decision = DetectionGovernanceDecision(
            decision_id="dgov-test",
            tenant_id=artifact.tenant_id,
            decision=DetectionGovernanceDecisionKind(request.decision),
            candidate_binding=DetectionGovernanceCandidateBinding(
                candidate_set_hash="c" * 64,
                candidate_refs=artifact.config.candidate_refs,
                feature_contract_version="1.0",
                detection_scope_id="dscope-test",
            ),
            evaluation_binding=DetectionGovernanceEvaluationBinding(
                evaluation_id=artifact.evaluation_id,
                dataset_id=artifact.dataset_id,
                dataset_version=artifact.dataset_version,
                dataset_content_hash=artifact.dataset_content_hash,
                artifact_hash=artifact.artifact_hash or ("a" * 64),
                code_sha=artifact.code_sha,
            ),
            threshold_binding=DetectionGovernanceThresholdBinding(manifest_version="2026.08.02"),
            binding_hash="e" * 64,
            policy_version="issue125_v1",
            reviewer_subject=principal.subject,
            reviewer_roles=list(principal.roles),
            decided_at=datetime.now(UTC),
        )
        return finalize_decision(decision)

    async def get_decision(self, decision_id: str, *, tenant_id: str | None = None) -> Any:
        raise AssertionError("not used in this test")

    async def list_decisions(self, **kwargs: Any) -> tuple[list[Any], int]:
        return [], 0

    async def revoke_decision(
        self,
        principal: Principal,
        decision_id: str,
        *,
        reason_note: str,
        tenant_id: str | None = None,
    ) -> Any:
        raise AssertionError("not used in this test")

    async def evaluate_promotion_gate(
        self, artifact: Any, *, binding_hash: str | None = None
    ) -> Any:
        from app.models.detection_governance import DetectionGovernancePromotionGateResult

        return DetectionGovernancePromotionGateResult(allowed=False)


@pytest.fixture
def governance_client(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, _FakeGovernance]:
    fake = _FakeGovernance()
    from app.api.v1 import deps

    app.dependency_overrides[deps.get_detection_governance_service] = lambda: fake

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


def test_record_decision_requires_approver_role(
    governance_client: tuple[TestClient, _FakeGovernance],
) -> None:
    client, _ = governance_client
    from app.core.auth import get_principal

    async def _analyst() -> Principal:
        return Principal(subject="analyst-only", roles=["analyst"])

    app.dependency_overrides[get_principal] = _analyst
    response = client.post(
        "/api/v1/detection/governance/decisions",
        json={"artifact": _minimal_artifact_payload(), "decision": "approve"},
    )
    assert response.status_code == 403


def test_record_decision_endpoint(governance_client: tuple[TestClient, _FakeGovernance]) -> None:
    client, fake = governance_client
    response = client.post(
        "/api/v1/detection/governance/decisions",
        json={
            "artifact": _minimal_artifact_payload(),
            "decision": "approve",
            "threshold_manifest_path": (
                "data/evaluation/detection_shadow_v1/threshold_manifest.json"
            ),
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision_id"] == "dgov-test"
    assert body["reviewer_subject"] == "api-approver"
    assert fake.calls[0][0] == "record"


def test_list_decisions_requires_tenant_id(
    governance_client: tuple[TestClient, _FakeGovernance],
) -> None:
    client, _ = governance_client
    response = client.get("/api/v1/detection/governance/decisions")
    assert response.status_code == 422


def test_get_decision_requires_tenant_id(
    governance_client: tuple[TestClient, _FakeGovernance],
) -> None:
    client, _ = governance_client
    response = client.get("/api/v1/detection/governance/decisions/dgov-test")
    assert response.status_code == 422


def test_record_approve_requires_threshold_manifest_path(
    governance_client: tuple[TestClient, _FakeGovernance],
) -> None:
    client, _ = governance_client
    response = client.post(
        "/api/v1/detection/governance/decisions",
        json={"artifact": _minimal_artifact_payload(), "decision": "approve"},
    )
    assert response.status_code == 422
