"""Detection context snapshot projector tests (ISSUE-127 / #633)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.db.orm.detection_context_snapshot import DetectionContextSnapshotORM
from app.db.orm.detection_governance import DetectionGovernanceDecisionORM
from app.db.orm.detection_promotion import DerivedDetectionConnectorORM, DetectionPromotionORM
from app.evaluation.detection.fixture_loader import load_detection_fixture_index
from app.evaluation.detection.fixture_seeder import (
    build_candidate_refs,
    clear_detection_tables,
    seed_detection_replay_fixture,
)
from app.ingestion.source_ingester import SourceIngester
from app.models.detection_context_snapshot import DetectionContextSnapshotQuery
from app.models.detection_governance import (
    DetectionGovernanceDecisionKind,
    DetectionGovernanceDecisionRequest,
)
from app.models.detection_promotion import (
    DetectionPromotionReasonCode,
    DetectionPromotionRequest,
    DetectionPromotionStatus,
)
from app.models.detection_rule import DetectionRuleDefinition, MissingDataPolicy, RuleOperatorKind
from app.models.feature_snapshot import FeatureWindowKind
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.detection_context_projector import DetectionContextProjector
from app.services.detection_context_resolver import (
    compute_snapshot_content_hash,
    extract_attack_refs_from_rule,
)
from app.services.detection_context_service import DetectionContextService
from app.services.detection_governance_service import DetectionGovernanceService
from app.services.detection_promotion_service import (
    PAYLOAD_PROJECTION_ERROR_KEY,
    DetectionPromotionService,
)
from app.services.detection_rule_runtime import DetectionRuleRuntimeService
from app.services.event_service import EventService
from tests.test_services.test_detection_promotion import (
    DATASET_DIR,
    THRESHOLD_PATH,
    _artifact_for_seeded,
    _reviewer_principal,
    requires_postgres,
)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

pytestmark = requires_postgres


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[RedisClient]:
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield client
    await client.aclose()


def test_compute_snapshot_content_hash_is_deterministic() -> None:
    payload = {
        "tenant_id": "tenant-a",
        "event_id": "evt-1",
        "revision": 1,
        "scores": {"matched_value": 1.0, "severity": "high", "operator": "event_match"},
    }
    first = compute_snapshot_content_hash(payload)
    second = compute_snapshot_content_hash(dict(payload))
    assert first == second
    assert len(first) == 64


@pytest_asyncio.fixture(autouse=True)
async def clean_detection_context_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(DetectionContextSnapshotORM))
            await session.execute(delete(DetectionPromotionORM))
            await session.execute(delete(DerivedDetectionConnectorORM))
            await session.execute(delete(DetectionGovernanceDecisionORM))
            await session.execute(delete(orm.DispositionReceipt))
            await session.execute(delete(orm.DispositionOutbox))
            await session.execute(delete(orm.ActionExecutionJob))
            await session.execute(delete(orm.ToolCallLog))
            await session.execute(delete(orm.LLMCallLog))
            await session.execute(delete(orm.EventAuditLog))
            await session.execute(delete(orm.DecisionRecord))
            await session.execute(delete(orm.AgentTrace))
            await session.execute(delete(orm.Action))
            await session.execute(delete(orm.Report))
            await session.execute(delete(orm.Evidence))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.EventContextJournal))
            await session.execute(delete(orm.EventContextFieldVersion))
            await session.execute(delete(orm.SecurityEvent))
    await clear_detection_tables(session_factory)
    yield


def test_extract_attack_refs_from_rule_deduplicates() -> None:
    rule = DetectionRuleDefinition(
        rule_id="rule-1",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version="fc-v1",
        detection_scope_id="dscope-1",
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="high",
        missing_data_policy=MissingDataPolicy.SKIP,
        match_criteria={
            "attack_technique_ids": ["T1059", "T1059.001"],
            "mitre_technique_ids": [
                {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                }
            ],
        },
    )
    refs = extract_attack_refs_from_rule(rule)
    assert len(refs) == 2
    assert {ref.technique_id for ref in refs} == {"T1059", "T1059.001"}


@pytest_asyncio.fixture
async def promotion_service_with_projector(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> DetectionPromotionService:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    events = EventService(session_factory, store, degraded_flags=degraded)
    ingester = SourceIngester(events, session_factory, source_mode="mock_xdr")
    return DetectionPromotionService(
        session_factory,
        event_service=events,
        source_ingester=ingester,
        context_projector=DetectionContextProjector(session_factory),
    )


@pytest.mark.asyncio
async def test_projector_happy_path_after_promotion(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
    redis_client: RedisClient,
) -> None:
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    replay = fixture_index.by_case_id["threat_event_match"]
    seeded = await seed_detection_replay_fixture(session_factory, replay)

    runtime = DetectionRuleRuntimeService(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    result = await runtime.execute_shadow(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
        cutoff_at=cutoff,
    )
    candidate = result.candidates[0]
    candidate_refs = build_candidate_refs(replay, seeded)
    artifact = _artifact_for_seeded(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="c" * 64,
    )
    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        _reviewer_principal(seeded.source_tenant_id),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved for context projection test",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )

    promotion = await promotion_service_with_projector.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert promotion.status is DetectionPromotionStatus.COMPLETED
    assert promotion.ingest_result is not None
    event_id = promotion.ingest_result.event_id
    assert event_id is not None

    service = DetectionContextService(session_factory)
    snapshots = await service.query_snapshots(
        DetectionContextSnapshotQuery(
            tenant_id=seeded.source_tenant_id,
            event_id=event_id,
            latest_only=True,
        )
    )
    assert snapshots.total == 1
    snapshot = snapshots.items[0]
    assert snapshot.promotion_id == promotion.promotion_id
    assert snapshot.content_hash
    assert snapshot.revision == 1

    store = EventContextStore(redis_client, session_factory)
    ctx = await store.rebuild_context(event_id)
    assert ctx.detection_context_snapshot is not None
    assert ctx.detection_context_snapshot.snapshot_id == snapshot.snapshot_id

    async with session_factory() as session:
        journal_versions = list(
            await session.scalars(
                select(orm.EventContextJournal.version).where(
                    orm.EventContextJournal.event_id == event_id,
                    orm.EventContextJournal.field_name == "detection_context_snapshot",
                )
            )
        )
    assert len(journal_versions) == 1

    projected = await DetectionContextProjector(session_factory).project_from_promotion(
        promotion.record.promotion_id,
        tenant_id=seeded.source_tenant_id,
    )
    assert projected is not None
    assert projected.snapshot_id == snapshot.snapshot_id

    async with session_factory() as session:
        journal_versions_after_idempotent = list(
            await session.scalars(
                select(orm.EventContextJournal.version).where(
                    orm.EventContextJournal.event_id == event_id,
                    orm.EventContextJournal.field_name == "detection_context_snapshot",
                )
            )
        )
    assert journal_versions_after_idempotent == journal_versions

    replay = await promotion_service_with_projector.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert replay.resumed is True
    snapshots_again = await service.query_snapshots(
        DetectionContextSnapshotQuery(
            tenant_id=seeded.source_tenant_id,
            event_id=event_id,
            latest_only=True,
        )
    )
    assert snapshots_again.total == 1
    assert snapshots_again.items[0].snapshot_id == snapshot.snapshot_id
    assert snapshots_again.items[0].content_hash == snapshot.content_hash


@pytest.mark.asyncio
async def test_projector_fail_closed_for_wrong_tenant(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
) -> None:
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    replay = fixture_index.by_case_id["threat_event_match"]
    seeded = await seed_detection_replay_fixture(session_factory, replay)
    runtime = DetectionRuleRuntimeService(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    result = await runtime.execute_shadow(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
        cutoff_at=cutoff,
    )
    candidate = result.candidates[0]
    candidate_refs = build_candidate_refs(replay, seeded)
    artifact = _artifact_for_seeded(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="d" * 64,
    )
    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        _reviewer_principal(seeded.source_tenant_id),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    promotion = await promotion_service_with_projector.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    projector = DetectionContextProjector(session_factory)
    with pytest.raises(ValidationError):
        await projector.project_from_promotion(
            promotion.promotion_id,
            tenant_id="other-tenant",
        )


async def _seed_completed_promotion(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service: DetectionPromotionService,
) -> tuple[object, object, object, object, object]:
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    replay = fixture_index.by_case_id["threat_event_match"]
    seeded = await seed_detection_replay_fixture(session_factory, replay)
    runtime = DetectionRuleRuntimeService(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    result = await runtime.execute_shadow(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
        cutoff_at=cutoff,
    )
    candidate = result.candidates[0]
    candidate_refs = build_candidate_refs(replay, seeded)
    artifact = _artifact_for_seeded(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="c" * 64,
    )
    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        _reviewer_principal(seeded.source_tenant_id),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved for context projection test",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    promotion = await promotion_service.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert promotion.status is DetectionPromotionStatus.COMPLETED
    return seeded, candidate, artifact, decision, promotion


@pytest.mark.asyncio
async def test_deps_promotion_wires_context_projector() -> None:
    from app.api.v1 import deps

    deps.reset_deps()
    service = await deps.get_detection_promotion_service()
    assert service._context_projector is not None


@pytest.mark.asyncio
async def test_projector_skips_incomplete_promotion(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
) -> None:
    seeded, candidate, artifact, decision, promotion = await _seed_completed_promotion(
        session_factory,
        promotion_service_with_projector,
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(DetectionPromotionORM, promotion.record.promotion_id)
            assert row is not None
            row.status = DetectionPromotionStatus.PENDING.value
            row.event_id = None

    projector = DetectionContextProjector(session_factory)
    skipped = await projector.project_from_promotion(
        promotion.record.promotion_id,
        tenant_id=seeded.source_tenant_id,
    )
    assert skipped is None


@pytest.mark.asyncio
async def test_projector_fail_closed_candidate_hash_mismatch(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
) -> None:
    seeded, candidate, _artifact, _decision, promotion = await _seed_completed_promotion(
        session_factory,
        promotion_service_with_projector,
    )
    async with session_factory() as session:
        async with session.begin():
            candidate_row = await session.get(
                orm.CandidateDetection,
                candidate.candidate_detection_id,
            )
            assert candidate_row is not None
            candidate_row.content_hash = "f" * 64

    projector = DetectionContextProjector(session_factory)
    with pytest.raises(ValidationError, match="candidate hash mismatch"):
        await projector.project_from_promotion(
            promotion.record.promotion_id,
            tenant_id=seeded.source_tenant_id,
        )


@pytest.mark.asyncio
async def test_projector_fail_closed_stale_event_revision(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
) -> None:
    seeded, _candidate, _artifact, _decision, promotion = await _seed_completed_promotion(
        session_factory,
        promotion_service_with_projector,
    )
    assert promotion.ingest_result is not None
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(DetectionPromotionORM, promotion.record.promotion_id)
            assert row is not None
            ingest = dict(row.ingest_result or {})
            ingest["event_revision"] = 999
            row.ingest_result = ingest

    projector = DetectionContextProjector(session_factory)
    with pytest.raises(ValidationError, match="stale event revision"):
        await projector.project_from_promotion(
            promotion.record.promotion_id,
            tenant_id=seeded.source_tenant_id,
        )


@pytest.mark.asyncio
async def test_projector_fail_closed_when_decision_expired(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> None:
    approved_at = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
    expired_at = datetime(2026, 8, 3, 13, 0, 0, tzinfo=UTC)
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    events = EventService(session_factory, store, degraded_flags=degraded)
    ingester = SourceIngester(events, session_factory, source_mode="mock_xdr")
    governance = DetectionGovernanceService(session_factory, now=lambda: approved_at)
    promotion_service = DetectionPromotionService(
        session_factory,
        governance=governance,
        event_service=events,
        source_ingester=ingester,
        context_projector=DetectionContextProjector(session_factory, governance=governance),
    )
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    replay = fixture_index.by_case_id["threat_event_match"]
    seeded = await seed_detection_replay_fixture(session_factory, replay)
    runtime = DetectionRuleRuntimeService(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    result = await runtime.execute_shadow(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
        cutoff_at=cutoff,
    )
    candidate = result.candidates[0]
    candidate_refs = build_candidate_refs(replay, seeded)
    artifact = _artifact_for_seeded(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="c" * 64,
    )
    decision = await governance.record_decision(
        _reviewer_principal(seeded.source_tenant_id),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved then expired",
            expires_at=expired_at,
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    promotion = await promotion_service.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert promotion.status is DetectionPromotionStatus.COMPLETED

    expired_governance = DetectionGovernanceService(session_factory, now=lambda: expired_at)
    await expired_governance.expire_active_approvals()

    projector = DetectionContextProjector(session_factory, governance=expired_governance)
    with pytest.raises(ValidationError, match="governance approval not active"):
        await projector.project_from_promotion(
            promotion.record.promotion_id,
            tenant_id=seeded.source_tenant_id,
        )


@pytest.mark.asyncio
async def test_projector_records_missing_feature_snapshot_errors(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    events = EventService(session_factory, store, degraded_flags=degraded)
    ingester = SourceIngester(events, session_factory, source_mode="mock_xdr")
    promotion_service = DetectionPromotionService(
        session_factory,
        event_service=events,
        source_ingester=ingester,
    )
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    replay = fixture_index.by_case_id["threat_event_match"]
    seeded = await seed_detection_replay_fixture(session_factory, replay)
    runtime = DetectionRuleRuntimeService(session_factory)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    result = await runtime.execute_shadow(
        source_tenant_id=seeded.source_tenant_id,
        package_id=seeded.package_id,
        cutoff_at=cutoff,
    )
    candidate = result.candidates[0]
    async with session_factory() as session:
        async with session.begin():
            candidate_row = await session.get(
                orm.CandidateDetection,
                candidate.candidate_detection_id,
            )
            assert candidate_row is not None
            provenance = dict(candidate_row.provenance or {})
            provenance["snapshot_ids"] = ["fsnap-missing-001"]
            candidate_row.provenance = provenance

    candidate_refs = build_candidate_refs(replay, seeded)
    artifact = _artifact_for_seeded(
        seeded=seeded,
        candidate_refs=candidate_refs,
        candidate_set_hash="c" * 64,
    )
    governance = DetectionGovernanceService(session_factory)
    decision = await governance.record_decision(
        _reviewer_principal(seeded.source_tenant_id),
        artifact,
        DetectionGovernanceDecisionRequest(
            decision=DetectionGovernanceDecisionKind.APPROVE,
            reason_note="approved for missing snapshot test",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
        threshold_manifest_path=THRESHOLD_PATH,
    )
    promotion = await promotion_service.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert promotion.status is DetectionPromotionStatus.COMPLETED

    projector = DetectionContextProjector(session_factory)
    projected = await projector.project_from_promotion(
        promotion.record.promotion_id,
        tenant_id=seeded.source_tenant_id,
    )
    assert projected is not None
    assert projected.projection_errors == ["missing_feature_snapshot:fsnap-missing-001"]


@pytest.mark.asyncio
async def test_promotion_records_projection_failure_on_blocked_projection(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    events = EventService(session_factory, store, degraded_flags=degraded)
    ingester = SourceIngester(events, session_factory, source_mode="mock_xdr")
    mock_projector = AsyncMock(spec=DetectionContextProjector)
    mock_projector.project_from_promotion = AsyncMock(
        side_effect=ValidationError(
            "detection context projection blocked: candidate hash mismatch",
            details={"reason": "candidate_content_hash_mismatch"},
        )
    )
    promotion_service = DetectionPromotionService(
        session_factory,
        event_service=events,
        source_ingester=ingester,
        context_projector=mock_projector,
    )
    seeded, candidate, artifact, decision, promotion = await _seed_completed_promotion(
        session_factory,
        promotion_service,
    )
    assert promotion.status is DetectionPromotionStatus.COMPLETED

    async with session_factory() as session:
        row = await session.get(DetectionPromotionORM, promotion.record.promotion_id)
        assert row is not None
        payload = dict(row.payload or {})
        assert PAYLOAD_PROJECTION_ERROR_KEY in payload
        assert payload[PAYLOAD_PROJECTION_ERROR_KEY]["reason"] == "candidate_content_hash_mismatch"
        assert DetectionPromotionReasonCode.CONTEXT_PROJECTION_FAILED.value in (
            row.reason_codes or []
        )
    assert promotion.context_projection_error is not None
    assert promotion.context_projection_error.reason == "candidate_content_hash_mismatch"
    assert "candidate hash mismatch" in promotion.context_projection_error.message
    from app.services.detection_promotion_service import _row_to_record

    record = _row_to_record(row)
    assert record.context_projection_error is not None
    assert record.context_projection_error.reason == "candidate_content_hash_mismatch"

    listed, _ = await promotion_service.list_promotions(tenant_id=seeded.source_tenant_id)
    assert listed[0].context_projection_error is not None
    mock_projector.project_from_promotion.side_effect = None
    mock_projector.project_from_promotion.return_value = None
    retried = await promotion_service.promote_candidate(
        artifact,
        DetectionPromotionRequest(
            tenant_id=seeded.source_tenant_id,
            candidate_detection_id=candidate.candidate_detection_id,
            decision_id=decision.decision_id,
        ),
    )
    assert retried.record.context_projection_error is None
    refreshed = await promotion_service.get_promotion(
        promotion.promotion_id,
        tenant_id=seeded.source_tenant_id,
    )
    assert refreshed.context_projection_error is None
    assert DetectionPromotionReasonCode.CONTEXT_PROJECTION_FAILED not in refreshed.reason_codes


def test_build_detection_context_snapshot_same_inputs_same_hash() -> None:
    from app.models.detection_evaluation import DetectionCandidateRefs
    from app.models.detection_governance import (
        DetectionGovernanceCandidateBinding,
        DetectionGovernanceDecision,
        DetectionGovernanceDecisionKind,
        DetectionGovernanceEvaluationBinding,
        DetectionGovernanceThresholdBinding,
    )
    from app.models.detection_promotion import (
        DetectionPromotionRecord,
        DetectionPromotionStatus,
    )
    from app.models.detection_rule import (
        CandidateDetection,
        CandidateDetectionProvenance,
        DetectionRuleDefinition,
        MissingDataPolicy,
        RuleOperatorKind,
    )
    from app.models.feature_snapshot import FeatureWindowKind
    from app.services.detection_context_resolver import build_detection_context_snapshot

    hash64 = "a" * 64
    candidate = CandidateDetection(
        candidate_detection_id="cand-hash-test",
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-1",
        package_id="pkg-1",
        package_version=1,
        rule_id="rule-1",
        rule_version=1,
        operator=RuleOperatorKind.EVENT_MATCH,
        group_key={"entity_type": "account", "entity_id": "alice"},
        cutoff_at=datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC),
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        matched_value=2.0,
        severity="high",
        provenance=CandidateDetectionProvenance(detection_score=88.5),
        content_hash=hash64,
        idempotency_key="idem-hash-test",
    )
    refs = DetectionCandidateRefs(
        package_id=candidate.package_id,
        package_version=candidate.package_version,
        package_content_hash="b" * 64,
        rule_ids=[candidate.rule_id],
        feature_contract_version="1.0",
        detection_scope_id=candidate.detection_scope_id,
        scope_revision_id="dsrev-1",
    )
    decision = DetectionGovernanceDecision(
        decision_id="dgov-hash-test",
        tenant_id=candidate.source_tenant_id,
        decision=DetectionGovernanceDecisionKind.APPROVE,
        candidate_binding=DetectionGovernanceCandidateBinding(
            candidate_set_hash="c" * 64,
            candidate_refs=refs,
            feature_contract_version="1.0",
            detection_scope_id=candidate.detection_scope_id,
            scope_revision_id="dsrev-1",
        ),
        evaluation_binding=DetectionGovernanceEvaluationBinding(
            evaluation_id="deval-hash-test",
            dataset_id="detection_shadow_v1",
            dataset_version="2026.08.02",
            dataset_content_hash="d" * 64,
            artifact_hash="e" * 64,
            code_sha="abc1234",
        ),
        threshold_binding=DetectionGovernanceThresholdBinding(manifest_version="2026.08.02"),
        binding_hash="f" * 64,
        decision_hash="0" * 64,
        policy_version="issue125_v1",
        reviewer_subject="approver-1",
        decided_at=datetime(2026, 8, 1, 16, 0, 0, tzinfo=UTC),
    )
    promotion = DetectionPromotionRecord(
        promotion_id="dprom-hash-test",
        tenant_id=candidate.source_tenant_id,
        promotion_key="promotion-key",
        status=DetectionPromotionStatus.COMPLETED,
        decision_id=decision.decision_id,
        candidate_detection_id=candidate.candidate_detection_id,
        candidate_content_hash=candidate.content_hash,
        package_id=candidate.package_id,
        package_version=candidate.package_version,
        package_content_hash=refs.package_content_hash,
        detection_scope_id=candidate.detection_scope_id,
        scope_revision_id="dsrev-1",
        event_id="evt-hash-test",
        link_revision=1,
    )
    rule = DetectionRuleDefinition(
        rule_id=candidate.rule_id,
        rule_version=candidate.rule_version,
        operator=RuleOperatorKind.EVENT_MATCH,
        feature_contract_version="1.0",
        detection_scope_id=candidate.detection_scope_id,
        window_kind=FeatureWindowKind.ONE_HOUR.value,
        group_key_fields=["entity_type", "entity_id"],
        threshold=1.0,
        severity="high",
        missing_data_policy=MissingDataPolicy.SKIP,
        match_criteria={"attack_technique_ids": ["T1059"]},
    )
    kwargs = {
        "promotion": promotion,
        "candidate": candidate,
        "decision": decision,
        "event_revision": 1,
        "rule": rule,
        "feature_snapshots": [],
        "revision": 1,
    }
    first = build_detection_context_snapshot(**kwargs)
    second = build_detection_context_snapshot(**kwargs)
    assert first.content_hash == second.content_hash
    assert first.snapshot_id == second.snapshot_id
    assert first.idempotency_key == second.idempotency_key


@pytest.mark.asyncio
async def test_projector_fail_closed_package_hash_mismatch(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
) -> None:
    seeded, _candidate, _artifact, _decision, promotion = await _seed_completed_promotion(
        session_factory,
        promotion_service_with_projector,
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(DetectionPromotionORM, promotion.record.promotion_id)
            assert row is not None
            row.package_content_hash = "f" * 64

    projector = DetectionContextProjector(session_factory)
    with pytest.raises(ValidationError, match="package hash mismatch"):
        await projector.project_from_promotion(
            promotion.record.promotion_id,
            tenant_id=seeded.source_tenant_id,
        )


@pytest.mark.asyncio
async def test_projector_appends_revision_on_second_promotion(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
) -> None:
    seeded, _candidate, _artifact, _decision, promotion = await _seed_completed_promotion(
        session_factory,
        promotion_service_with_projector,
    )
    assert promotion.ingest_result is not None
    event_id = promotion.ingest_result.event_id
    assert event_id is not None

    service = DetectionContextService(session_factory)
    first = await service.query_snapshots(
        DetectionContextSnapshotQuery(
            tenant_id=seeded.source_tenant_id,
            event_id=event_id,
            latest_only=True,
        )
    )
    assert first.total == 1
    first_snapshot = first.items[0]
    assert first_snapshot.revision == 1

    async with session_factory() as session:
        async with session.begin():
            first_row = await session.get(DetectionPromotionORM, promotion.record.promotion_id)
            assert first_row is not None
            session.add(
                DetectionPromotionORM(
                    promotion_id="dprom-revision-2-test",
                    tenant_id=first_row.tenant_id,
                    promotion_key=f"{first_row.promotion_key}|link2",
                    status=DetectionPromotionStatus.COMPLETED.value,
                    decision_id=first_row.decision_id,
                    candidate_detection_id=first_row.candidate_detection_id,
                    candidate_content_hash=first_row.candidate_content_hash,
                    package_id=first_row.package_id,
                    package_version=first_row.package_version,
                    package_content_hash=first_row.package_content_hash,
                    detection_scope_id=first_row.detection_scope_id,
                    scope_revision_id=first_row.scope_revision_id,
                    derived_connector_id=first_row.derived_connector_id,
                    source_record_id=first_row.source_record_id,
                    event_id=first_row.event_id,
                    link_revision=2,
                    ingest_result=dict(first_row.ingest_result or {}),
                    reason_codes=list(first_row.reason_codes or []),
                    reason_message=first_row.reason_message,
                    payload=dict(first_row.payload or {}),
                )
            )

    projector = DetectionContextProjector(session_factory)
    second_snapshot = await projector.project_from_promotion(
        "dprom-revision-2-test",
        tenant_id=seeded.source_tenant_id,
    )
    assert second_snapshot is not None
    assert second_snapshot.revision == 2
    assert second_snapshot.supersedes_snapshot_id == first_snapshot.snapshot_id

    latest = await service.query_snapshots(
        DetectionContextSnapshotQuery(
            tenant_id=seeded.source_tenant_id,
            event_id=event_id,
            latest_only=True,
        )
    )
    assert latest.total == 1
    assert latest.items[0].snapshot_id == second_snapshot.snapshot_id


@pytest.mark.asyncio
async def test_get_event_detail_includes_detection_context_snapshot_summary(
    session_factory: async_sessionmaker[AsyncSession],
    promotion_service_with_projector: DetectionPromotionService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from fastapi.testclient import TestClient

    from app.api.v1.deps import reset_deps
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv(
        "DEV_AUTH_TOKENS",
        json.dumps({"analyst-token": {"subject": "analyst-1", "roles": ["analyst"]}}),
    )
    get_settings.cache_clear()
    reset_deps()

    seeded, _candidate, _artifact, _decision, promotion = await _seed_completed_promotion(
        session_factory,
        promotion_service_with_projector,
    )
    assert promotion.ingest_result is not None
    event_id = promotion.ingest_result.event_id
    assert event_id is not None

    client = TestClient(app)
    resp = client.get(
        f"/api/v1/events/{event_id}",
        headers={"Authorization": "Bearer analyst-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    summary = data.get("detection_context_snapshot")
    assert summary is not None
    assert summary["promotion_id"] == promotion.record.promotion_id
    assert summary["revision"] == 1
    assert data.get("detection_context_projection_error") is None
