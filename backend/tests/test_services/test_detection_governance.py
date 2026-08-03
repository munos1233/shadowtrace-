"""Detection governance service tests (ISSUE-125 / #630 Phase A)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.auth import Principal
from app.core.errors import ValidationError
from app.db.orm.detection_governance import DetectionGovernanceDecisionORM
from app.evaluation.detection.artifact import finalize_detection_artifact
from app.models.detection_evaluation import (
    DetectionCandidateRefs,
    DetectionEvaluationArtifact,
    DetectionEvaluationConfig,
    DetectionResourceSummary,
    DetectionTenantSafetySummary,
)
from app.models.detection_governance import (
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
    DetectionGovernanceReasonCode,
)
from app.models.evaluation_quality import (
    EvaluationQualityReport,
    MetricDenominator,
    QualityMetricStatus,
    QualityMetricValue,
)
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationGateResult,
    EvaluationReleaseRefs,
    EvaluationRunStatus,
    GateVerdict,
)
from app.services.detection_governance_binding import validate_decision_artifact_binding
from app.services.detection_governance_policy import (
    assess_governance_eligibility,
    load_detection_governance_policy,
)
from app.services.detection_governance_service import DetectionGovernanceService

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
THRESHOLD_PATH = (
    REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1" / "threshold_manifest.json"
)
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _postgres_reachable() -> bool:
    import asyncio

    from app.db.session_provider import SessionProvider

    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    try:
        return asyncio.run(provider.ping_postgres())
    except Exception:
        return False
    finally:
        asyncio.run(provider.dispose())


requires_postgres = pytest.mark.skipif(
    not _postgres_reachable(),
    reason="PostgreSQL not reachable",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="module")
def migrated_database() -> None:
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_governance_rows(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(DetectionGovernanceDecisionORM))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(DetectionGovernanceDecisionORM))


def _candidate_refs() -> DetectionCandidateRefs:
    return DetectionCandidateRefs(
        package_id="drpkg-test-v1",
        package_version=1,
        package_content_hash="a" * 64,
        rule_ids=["rule-test"],
        feature_contract_version="1.0",
        detection_scope_id="dscope-test",
        scope_revision_id="dscope-rev-test",
    )


def _quality_report(*, blocking: bool = False) -> EvaluationQualityReport:
    status = QualityMetricStatus.FAIL_CLOSED if blocking else QualityMetricStatus.COMPUTED
    metrics = [
        QualityMetricValue(
            metric_id="threat_recall",
            value=1.0 if not blocking else None,
            status=status,
            denominator=MetricDenominator(numerator=1, denominator=1),
            reason="" if not blocking else "blocked",
        ),
        QualityMetricValue(
            metric_id="benign_specificity",
            value=1.0 if not blocking else None,
            status=status,
            denominator=MetricDenominator(numerator=1, denominator=1),
            reason="" if not blocking else "blocked",
        ),
    ]
    return EvaluationQualityReport(
        dataset_id="detection_shadow_v1",
        dataset_version="2026.08.02",
        dataset_content_hash="b" * 64,
        code_sha="abc1234",
        release_refs=EvaluationReleaseRefs(),
        sample_counts={"threat": 1, "benign": 1, "unevaluable": 0, "total": 2},
        metrics=metrics,
    )


def _artifact(*, eligible: bool = True) -> DetectionEvaluationArtifact:
    gate_verdict = GateVerdict.PASS if eligible else GateVerdict.FAIL_CLOSED
    status = EvaluationRunStatus.COMPLETED if eligible else EvaluationRunStatus.FAILED
    refs = _candidate_refs()
    artifact = DetectionEvaluationArtifact(
        evaluation_id="deval-test-001",
        tenant_id="tenant-detection-eval",
        dataset_id="detection_shadow_v1",
        dataset_version="2026.08.02",
        dataset_content_hash="b" * 64,
        code_sha="abc1234",
        config=DetectionEvaluationConfig(
            seed=42,
            cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
            candidate_refs=refs,
            candidate_refs_entries=[refs],
            candidate_set_hash="c" * 64,
            scorer_ids=["threat_detection", "benign_detection"],
        ),
        started_at=datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 1, 15, 5, 0, tzinfo=UTC),
        status=status,
        aggregates=EvaluationAggregateMetrics(
            case_count=2,
            pass_count=2 if eligible else 0,
            fail_count=0,
            unevaluable_count=0,
            error_count=0,
            pass_rate=1.0 if eligible else 0.0,
            required_scorer_error_count=0 if eligible else 1,
        ),
        gate=EvaluationGateResult(
            verdict=gate_verdict,
            manifest_version="2026.08.02",
            manifest_path=str(THRESHOLD_PATH),
            diffs=[],
        ),
        quality_report=_quality_report(blocking=not eligible),
        resource_summary=DetectionResourceSummary(total_runtime_errors=0 if eligible else 3),
        tenant_safety=DetectionTenantSafetySummary(probe_count=1, pass_count=1, fail_count=0),
    )
    return finalize_detection_artifact(artifact)


def _approver(*, tenant_id: str = "tenant-detection-eval") -> Principal:
    return Principal(subject="detection-approver-1", roles=["approver"], tenant_id=tenant_id)


def test_assert_governance_tenant_access_denies_missing_tenant_id() -> None:
    from app.core.errors import ResourceNotFoundError
    from app.services.detection_governance_service import assert_governance_tenant_access

    with pytest.raises(ResourceNotFoundError):
        assert_governance_tenant_access(
            Principal(subject="approver-no-tenant", roles=["approver"]),
            "tenant-detection-eval",
        )


def test_assert_governance_tenant_access_allows_admin_without_tenant_id() -> None:
    from app.services.detection_governance_service import assert_governance_tenant_access

    assert_governance_tenant_access(
        Principal(subject="admin-user", roles=["admin"]),
        "tenant-detection-eval",
    )


@pytest.mark.asyncio
async def test_eligibility_passes_for_clean_artifact() -> None:
    assessment = assess_governance_eligibility(
        _artifact(eligible=True),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    assert assessment.eligible is True
    assert assessment.reason_codes == []
    assert assessment.threshold_manifest_validated is True


@pytest.mark.asyncio
async def test_eligibility_fail_closed_on_stale_hash() -> None:
    artifact = _artifact(eligible=True)
    tampered = artifact.model_copy(update={"artifact_hash": "d" * 64})
    assessment = assess_governance_eligibility(tampered, threshold_manifest_path=THRESHOLD_PATH)
    assert assessment.eligible is False
    assert DetectionGovernanceReasonCode.ARTIFACT_HASH_MISMATCH in assessment.reason_codes


@pytest.mark.asyncio
@requires_postgres
async def test_record_approve_requires_human_reviewer(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    with pytest.raises(ValidationError, match="human reviewer"):
        await service.record_decision(
            Principal(
                subject="system:scheduler",
                roles=["approver"],
                tenant_id="tenant-detection-eval",
            ),
            _artifact(eligible=True),
            DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
            threshold_manifest_path=THRESHOLD_PATH,
        )


@pytest.mark.asyncio
@requires_postgres
async def test_record_approve_persists_immutable_decision(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    decision = await service.record_decision(
        _approver(),
        _artifact(eligible=True),
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            expires_at=datetime.now(UTC) + timedelta(days=7),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    assert decision.decision == DetectionGovernanceDecisionKind.APPROVE
    assert decision.decision_hash
    assert decision.reviewer_subject == "detection-approver-1"
    loaded = await service.get_decision(
        decision.decision_id,
        tenant_id=decision.tenant_id,
    )
    assert loaded.decision_hash == decision.decision_hash


@pytest.mark.asyncio
@requires_postgres
async def test_record_approve_blocked_when_ineligible(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    with pytest.raises(ValidationError, match="ineligible"):
        await service.record_decision(
            _approver(),
            _artifact(eligible=False),
            DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
            threshold_manifest_path=THRESHOLD_PATH,
        )


@pytest.mark.asyncio
@requires_postgres
async def test_revoke_supersedes_active_approval(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    approved = await service.record_decision(
        _approver(),
        _artifact(eligible=True),
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    revoked = await service.revoke_decision(
        _approver(),
        approved.decision_id,
        reason_note="post-review regression",
        tenant_id=approved.tenant_id,
    )
    assert revoked.decision == DetectionGovernanceDecisionKind.REVOKE
    gate = await service.evaluate_promotion_gate(_artifact(eligible=True))
    assert gate.allowed is False
    assert DetectionGovernanceReasonCode.NO_ACTIVE_APPROVAL in gate.reason_codes


@pytest.mark.asyncio
@requires_postgres
async def test_promotion_gate_allows_matching_artifact(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    artifact = _artifact(eligible=True)
    approved = await service.record_decision(
        _approver(),
        artifact,
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    gate = await service.evaluate_promotion_gate(artifact)
    assert gate.allowed is True
    assert gate.decision_id == approved.decision_id


@pytest.mark.asyncio
@requires_postgres
async def test_binding_validation_rejects_stale_artifact(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    artifact = _artifact(eligible=True)
    decision = await service.record_decision(
        _approver(),
        artifact,
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    tampered = artifact.model_copy(update={"code_sha": "deadbeef"})
    tampered = finalize_detection_artifact(tampered)
    with pytest.raises(ValidationError, match="artifact hash changed"):
        validate_decision_artifact_binding(decision, tampered)


@pytest.mark.asyncio
@requires_postgres
async def test_expire_active_approvals_appends_expire_record(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    now = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
    service = DetectionGovernanceService(session_factory, now=lambda: now)
    artifact = _artifact(eligible=True)
    approved = await service.record_decision(
        _approver(),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            expires_at=now - timedelta(minutes=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    expired_ids = await service.expire_active_approvals()
    assert expired_ids
    gate = await service.evaluate_promotion_gate(artifact)
    assert gate.allowed is False
    chain, _ = await service.list_decisions(binding_hash=approved.binding_hash)
    kinds = {item.decision for item in chain}
    assert DetectionGovernanceDecisionKind.EXPIRE in kinds


@pytest.mark.asyncio
async def test_eligibility_fail_closed_when_quality_report_missing() -> None:
    artifact = _artifact(eligible=True).model_copy(update={"quality_report": None})
    assessment = assess_governance_eligibility(artifact, threshold_manifest_path=THRESHOLD_PATH)
    assert assessment.eligible is False
    assert DetectionGovernanceReasonCode.ARTIFACT_INCOMPLETE in assessment.reason_codes


@pytest.mark.asyncio
async def test_eligibility_fail_closed_when_no_tenant_probes() -> None:
    artifact = _artifact(eligible=True).model_copy(
        update={"tenant_safety": DetectionTenantSafetySummary(probe_count=0)}
    )
    assessment = assess_governance_eligibility(artifact, threshold_manifest_path=THRESHOLD_PATH)
    assert assessment.eligible is False
    assert DetectionGovernanceReasonCode.TENANT_ISOLATION_FAILED in assessment.reason_codes


@pytest.mark.asyncio
async def test_eligibility_rejects_empty_candidate_set_hash() -> None:
    artifact = _artifact(eligible=True)
    tampered_config = artifact.config.model_copy(update={"candidate_set_hash": ""})
    artifact = artifact.model_copy(update={"config": tampered_config})
    assessment = assess_governance_eligibility(artifact, threshold_manifest_path=THRESHOLD_PATH)
    assert assessment.eligible is False
    assert DetectionGovernanceReasonCode.ARTIFACT_INCOMPLETE in assessment.reason_codes


@pytest.mark.asyncio
@requires_postgres
async def test_record_approve_rejects_agent_principal(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    with pytest.raises(ValidationError, match="human reviewer"):
        await service.record_decision(
            Principal(
                subject="agent:planner",
                roles=["approver"],
                tenant_id="tenant-detection-eval",
            ),
            _artifact(eligible=True),
            DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
            threshold_manifest_path=THRESHOLD_PATH,
        )


@pytest.mark.asyncio
@requires_postgres
async def test_list_decisions_pagination(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    artifact = _artifact(eligible=True)
    for _ in range(3):
        await service.record_decision(
            _approver(),
            artifact,
            DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.REJECT),
            threshold_manifest_path=THRESHOLD_PATH,
        )
    page1, total = await service.list_decisions(
        tenant_id=artifact.tenant_id,
        limit=2,
        offset=0,
    )
    page2, _ = await service.list_decisions(
        tenant_id=artifact.tenant_id,
        limit=2,
        offset=2,
    )
    assert total == 3
    assert len(page1) == 2
    assert len(page2) == 1


@pytest.mark.asyncio
@requires_postgres
async def test_get_decision_hides_cross_tenant(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    from app.core.errors import ResourceNotFoundError

    service = DetectionGovernanceService(session_factory)
    decision = await service.record_decision(
        _approver(),
        _artifact(eligible=True),
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.REJECT),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    with pytest.raises(ResourceNotFoundError):
        await service.get_decision(decision.decision_id, tenant_id="other-tenant")


def test_policy_loader_reads_manifest_limits() -> None:
    policy = load_detection_governance_policy()
    assert policy.policy_version == "issue125_v1"
    assert policy.max_runtime_errors >= 0
    assert policy.require_gate_pass is True
    assert policy.default_approval_ttl_hours == 168


@pytest.mark.asyncio
@requires_postgres
async def test_record_approve_applies_default_ttl_when_expires_at_missing(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    now = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
    service = DetectionGovernanceService(session_factory, now=lambda: now)
    decision = await service.record_decision(
        _approver(),
        _artifact(eligible=True),
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    assert decision.expires_at is not None
    assert decision.expires_at == now + timedelta(hours=168)


@pytest.mark.asyncio
@requires_postgres
async def test_record_approve_requires_threshold_manifest_path(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    with pytest.raises(ValidationError, match="threshold_manifest_path required"):
        await service.record_decision(
            _approver(),
            _artifact(eligible=True),
            DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
        )


@pytest.mark.asyncio
@requires_postgres
async def test_record_approve_rejects_duplicate_active_binding(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    artifact = _artifact(eligible=True)
    await service.record_decision(
        _approver(),
        artifact,
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    with pytest.raises(ValidationError, match="active approval already exists"):
        await service.record_decision(
            _approver(),
            artifact,
            DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
            threshold_manifest_path=THRESHOLD_PATH,
        )


@pytest.mark.asyncio
@requires_postgres
async def test_record_decision_rejects_cross_tenant_principal(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    from app.core.errors import ResourceNotFoundError

    service = DetectionGovernanceService(session_factory)
    with pytest.raises(ResourceNotFoundError):
        await service.record_decision(
            _approver(tenant_id="other-tenant"),
            _artifact(eligible=True),
            DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.REJECT),
            threshold_manifest_path=THRESHOLD_PATH,
        )


@pytest.mark.asyncio
@requires_postgres
async def test_get_decision_rejects_cross_tenant_principal(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    from app.core.errors import ResourceNotFoundError

    service = DetectionGovernanceService(session_factory)
    decision = await service.record_decision(
        _approver(),
        _artifact(eligible=True),
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.REJECT),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    with pytest.raises(ResourceNotFoundError):
        await service.get_decision(
            decision.decision_id,
            tenant_id=decision.tenant_id,
            principal=_approver(tenant_id="other-tenant"),
        )


@pytest.mark.asyncio
@requires_postgres
async def test_expire_active_approvals_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    now = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
    service = DetectionGovernanceService(session_factory, now=lambda: now)
    artifact = _artifact(eligible=True)
    await service.record_decision(
        _approver(),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            expires_at=now - timedelta(minutes=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    first = await service.expire_active_approvals()
    second = await service.expire_active_approvals()
    assert len(first) == 1
    assert second == []
    chain, _ = await service.list_decisions(tenant_id=artifact.tenant_id, limit=20)
    expire_records = [
        item for item in chain if item.decision == DetectionGovernanceDecisionKind.EXPIRE
    ]
    assert len(expire_records) == 1


@pytest.mark.asyncio
async def test_eligibility_fail_closed_without_threshold_path() -> None:
    assessment = assess_governance_eligibility(_artifact(eligible=True))
    assert assessment.eligible is False
    assert assessment.threshold_manifest_validated is False
    assert DetectionGovernanceReasonCode.THRESHOLD_MANIFEST_MISSING in assessment.reason_codes


@pytest.mark.asyncio
async def test_baseline_artifact_never_eligible_for_approve() -> None:
    import json

    baseline_path = (
        REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1" / "baseline_artifact.json"
    )
    artifact = DetectionEvaluationArtifact.model_validate(
        json.loads(baseline_path.read_text(encoding="utf-8"))
    )
    assessment = assess_governance_eligibility(artifact, threshold_manifest_path=THRESHOLD_PATH)
    assert assessment.eligible is False
    assert assessment.threshold_manifest_validated is True


@pytest.mark.asyncio
@requires_postgres
async def test_governance_approve_revoke_gate_chain(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    artifact = _artifact(eligible=True)
    approved = await service.record_decision(
        _approver(),
        artifact,
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    gate = await service.evaluate_promotion_gate(artifact)
    assert gate.allowed is True
    assert gate.decision_id == approved.decision_id

    await service.revoke_decision(
        _approver(),
        approved.decision_id,
        reason_note="regression found",
        tenant_id=approved.tenant_id,
    )
    gate_after = await service.evaluate_promotion_gate(artifact)
    assert gate_after.allowed is False
    assert DetectionGovernanceReasonCode.NO_ACTIVE_APPROVAL in gate_after.reason_codes


@pytest.mark.asyncio
@requires_postgres
async def test_revoke_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    service = DetectionGovernanceService(session_factory)
    approved = await service.record_decision(
        _approver(),
        _artifact(eligible=True),
        DetectionGovernanceDecisionRequest(decision=DetectionGovernanceDecisionKind.APPROVE),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    await service.revoke_decision(
        _approver(),
        approved.decision_id,
        reason_note="first revoke",
        tenant_id=approved.tenant_id,
    )
    with pytest.raises(ValidationError, match="already revoked or expired"):
        await service.revoke_decision(
            _approver(),
            approved.decision_id,
            reason_note="duplicate revoke",
            tenant_id=approved.tenant_id,
        )
    chain, _ = await service.list_decisions(binding_hash=approved.binding_hash, limit=20)
    revoke_records = [
        item for item in chain if item.decision == DetectionGovernanceDecisionKind.REVOKE
    ]
    assert len(revoke_records) == 1


@pytest.mark.asyncio
@requires_postgres
async def test_decision_hash_includes_expires_at(
    session_factory: async_sessionmaker[AsyncSession],
    clean_governance_rows: None,
) -> None:
    from app.services.detection_governance_binding import compute_decision_hash

    now = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
    service = DetectionGovernanceService(session_factory, now=lambda: now)
    approved = await service.record_decision(
        _approver(),
        _artifact(eligible=True),
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            expires_at=now + timedelta(days=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    variant = approved.model_copy(
        update={
            "expires_at": now + timedelta(days=2),
            "decision_hash": "",
        }
    )
    assert compute_decision_hash(approved) != compute_decision_hash(variant)
