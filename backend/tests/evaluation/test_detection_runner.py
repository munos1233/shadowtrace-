"""Detection evaluation pipeline tests (ISSUE-126 / #631 Phase A)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.evaluation.detection.artifact import (
    compute_detection_artifact_hash,
    finalize_detection_artifact,
)
from app.evaluation.detection.diff import diff_detection_against_baseline, diff_detection_artifacts
from app.evaluation.detection.fixture_loader import load_detection_fixture_index
from app.evaluation.detection.fixture_seeder import (
    clear_detection_tables,
    derive_all_candidate_refs,
    derive_candidate_refs,
)
from app.evaluation.detection.runner import (
    DetectionEvaluationRunner,
    run_fixture_detection_evaluation,
)
from app.evaluation.detection.scorers.registry import default_detection_scorer_registry
from app.evaluation.fixture_loader import load_fixture_dataset
from app.models.evaluation_run import EvaluationRunStatus, GateVerdict, ScorerOutcome
from app.models.evaluation_truth import SliceType
from app.models.feature_snapshot import FEATURE_CONTRACT_VERSION, FeatureWindowKind
from app.services.evaluation_truth_service import EvaluationTruthService

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATASET_DIR = REPO_ROOT / "data" / "evaluation" / "detection_shadow_v1"
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="module")
def migrated_database() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    from app.db import models as orm

    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.EvaluationCaseTruth))
    await clear_detection_tables(session_factory)
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.EvaluationCaseTruth))
    await clear_detection_tables(session_factory)


@pytest_asyncio.fixture
async def truth_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> EvaluationTruthService:
    return EvaluationTruthService(session_factory)


@pytest_asyncio.fixture
async def loaded_detection_dataset(
    truth_service: EvaluationTruthService,
) -> tuple[object, object]:
    truths, manifest = await load_fixture_dataset(
        truth_service,
        DATASET_DIR,
        tenant_id="tenant-detection-eval",
    )
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    return manifest, fixture_index


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_detection_fixture_dataset_loads(
    loaded_detection_dataset: tuple[object, object],
) -> None:
    manifest, fixture_index = loaded_detection_dataset
    assert manifest.case_count == 7
    assert len(fixture_index.by_case_id) == 7


async def _run_loaded_dataset(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
    *,
    seed: int = 42,
    code_sha: str = "abc1234",
) -> object:
    manifest, fixture_index = loaded_detection_dataset
    candidate_refs_entries, candidate_set_hash = await derive_all_candidate_refs(
        session_factory,
        fixture_index,
    )
    from app.evaluation.detection.fixture_loader import resolve_effective_cutoff_at

    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    return await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=seed,
        code_sha=code_sha,
        cutoff_at=cutoff,
        effective_cutoff_at=resolve_effective_cutoff_at(fixture_index, default_cutoff_at=cutoff),
        candidate_refs=candidate_refs_entries[0],
        candidate_refs_entries=candidate_refs_entries,
        candidate_set_hash=candidate_set_hash,
        threshold_manifest_path=DATASET_DIR / "threshold_manifest.json",
    )


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_detection_shadow_v1_full_dataset(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )

    assert artifact.status == EvaluationRunStatus.FAILED
    assert artifact.aggregates.case_count == 7
    assert artifact.aggregates.pass_count == 4
    assert artifact.aggregates.error_count == 2
    assert artifact.aggregates.unevaluable_count == 1
    assert artifact.artifact_hash
    assert artifact.approval_note.startswith("Not a governance approval")
    assert artifact.tenant_safety.probe_count >= 1
    assert artifact.tenant_safety.fail_count == 0
    assert artifact.quality_report is not None
    assert artifact.resource_summary.total_replay_duration_ms >= 0
    assert artifact.config.candidate_set_hash
    assert len(artifact.config.candidate_refs_entries) >= 5

    cold_start = next(
        case
        for case in artifact.case_results
        if case.case_id == "threat_cold_start_insufficient_history"
    )
    assert cold_start.case_status == EvaluationRunStatus.FAILED
    assert cold_start.observation.runtime_errors

    resource_case = next(
        case for case in artifact.case_results if case.case_id == "threat_resource_budget_exceeded"
    )
    assert resource_case.case_status == EvaluationRunStatus.FAILED
    budget = next(r for r in resource_case.scorer_results if r.scorer_id == "resource_budget")
    assert budget.outcome == ScorerOutcome.FAIL


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_detection_evaluation_deterministic_hash(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    first = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    second = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )

    assert first.artifact_hash == second.artifact_hash
    assert compute_detection_artifact_hash(first) == first.artifact_hash


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_threat_case_produces_candidates(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    threat_case = next(
        case for case in artifact.case_results if case.case_id == "threat_event_match"
    )
    assert threat_case.slice_type == SliceType.THREAT
    assert len(threat_case.observation.candidates) >= 1
    assert all(result.outcome != ScorerOutcome.FAIL for result in threat_case.scorer_results)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_benign_hard_negative_stays_silent(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    benign_case = next(
        case for case in artifact.case_results if case.case_id == "benign_hard_negative"
    )
    assert benign_case.slice_type == SliceType.BENIGN
    assert not benign_case.observation.candidates


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_unevaluable_not_counted_as_benign(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    unknown_case = next(
        case for case in artifact.case_results if case.case_id == "unevaluable_partial_telemetry"
    )
    assert unknown_case.case_status == EvaluationRunStatus.UNEVALUABLE
    coverage = next(
        result
        for result in unknown_case.scorer_results
        if result.scorer_id == "unevaluable_coverage"
    )
    assert coverage.outcome == ScorerOutcome.UNEVALUABLE


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_late_observation_does_not_fire(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    late_case = next(
        case for case in artifact.case_results if case.case_id == "benign_late_observation"
    )
    assert not late_case.observation.candidates


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_foreign_tenant_cannot_execute_victim_package(
    session_factory: async_sessionmaker[AsyncSession],
    loaded_detection_dataset: tuple[object, object],
) -> None:
    from app.evaluation.detection.replayer import DetectionShadowReplayer

    _, fixture_index = loaded_detection_dataset
    replay = fixture_index.by_case_id["threat_event_match"]
    replayer = DetectionShadowReplayer(session_factory)
    outcome = await replayer.probe_tenant_isolation(
        replay,
        probe_tenant_id="tenant-det-foreign",
    )
    assert outcome.execution_error is None
    assert outcome.foreign_candidates == []


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_diff_detects_candidate_set_hash_drift(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    baseline = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
        seed=42,
        code_sha="baseline0001",
    )
    mutated_config = baseline.config.model_copy(update={"candidate_set_hash": "0" * 64})
    candidate = baseline.model_copy(update={"config": mutated_config})
    candidate = finalize_detection_artifact(candidate)
    diffs = diff_detection_artifacts(baseline, candidate)
    assert any(diff.field == "config.candidate_set_hash" for diff in diffs)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_resource_failure_fail_closed(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    case = next(
        item for item in artifact.case_results if item.case_id == "threat_resource_budget_exceeded"
    )
    assert case.case_status == EvaluationRunStatus.FAILED
    assert case.observation.runtime_errors
    threat = next(
        result for result in case.scorer_results if result.scorer_id == "threat_detection"
    )
    assert threat.outcome == ScorerOutcome.ERROR
    budget = next(result for result in case.scorer_results if result.scorer_id == "resource_budget")
    assert budget.outcome == ScorerOutcome.FAIL


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_gate_fail_closed_on_missing_scorer(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    from app.evaluation.detection.runner import DetectionEvaluationRunRequest
    from app.models.evaluation_run import EvaluationThresholdManifest

    manifest, fixture_index = loaded_detection_dataset
    candidate_refs_entries, candidate_set_hash = await derive_all_candidate_refs(
        session_factory,
        fixture_index,
    )
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    threshold = EvaluationThresholdManifest(
        manifest_version="test",
        dataset_id=manifest.dataset_id,
        dataset_version=manifest.dataset_version,
        required_scorers=["threat_detection", "missing_scorer"],
        required_gate=True,
    )
    runner = DetectionEvaluationRunner(truth_service, session_factory)
    artifact = await runner.run(
        DetectionEvaluationRunRequest(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            dataset_content_hash=manifest.content_hash,
            seed=42,
            code_sha="abc1234",
            cutoff_at=cutoff,
            effective_cutoff_at=cutoff,
            candidate_refs=candidate_refs_entries[0],
            candidate_refs_entries=candidate_refs_entries,
            candidate_set_hash=candidate_set_hash,
            fixture_index=fixture_index,
            threshold_manifest=threshold,
        )
    )
    assert artifact.gate is not None
    assert artifact.gate.verdict == GateVerdict.FAIL_CLOSED


@pytest.mark.evaluation
def test_default_detection_scorer_registry_has_required_scorers() -> None:
    registry = default_detection_scorer_registry()
    assert "threat_detection" in registry.scorer_ids
    assert "benign_detection" in registry.scorer_ids
    assert "tenant_isolation" in registry.all_required_ids()


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_diff_against_baseline_aligns_code_sha(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    baseline = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
        seed=42,
        code_sha="baseline0001",
    )
    candidate = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
        seed=42,
        code_sha="different01",
    )
    assert diff_detection_against_baseline(baseline, candidate) == []


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_diff_detects_case_status_drift(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    baseline = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    mutated_case = baseline.case_results[0].model_copy(
        update={"case_status": EvaluationRunStatus.FAILED}
    )
    candidate = baseline.model_copy(
        update={"case_results": [mutated_case, *baseline.case_results[1:]]}
    )
    candidate = finalize_detection_artifact(candidate)
    diffs = diff_detection_artifacts(baseline, candidate)
    assert any(diff.field.endswith(".case_status") for diff in diffs)


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_duplicate_observation_idempotent_replay(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    dup_case = next(
        case for case in artifact.case_results if case.case_id == "benign_duplicate_observation"
    )
    assert dup_case.slice_type == SliceType.BENIGN
    assert not dup_case.observation.candidates
    assert dup_case.scorer_results
    for result in dup_case.scorer_results:
        if result.scorer_id == "resource_budget":
            assert result.outcome == ScorerOutcome.SKIPPED
        else:
            assert result.outcome == ScorerOutcome.PASS


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_cold_start_insufficient_history_fail_closed(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    case = next(
        item
        for item in artifact.case_results
        if item.case_id == "threat_cold_start_insufficient_history"
    )
    assert case.case_status == EvaluationRunStatus.FAILED
    assert case.observation.runtime_errors
    threat = next(
        result for result in case.scorer_results if result.scorer_id == "threat_detection"
    )
    assert threat.outcome == ScorerOutcome.ERROR


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_artifact_candidate_refs_cover_all_packages(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    artifact = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
    )
    package_ids = {entry.package_id for entry in artifact.config.candidate_refs_entries}
    case_package_ids = {
        case.candidate_refs.package_id
        for case in artifact.case_results
        if case.candidate_refs is not None
    }
    assert case_package_ids.issubset(package_ids)
    assert len(package_ids) >= 5


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_detection_evaluation_matches_pinned_baseline(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    import json

    from app.models.detection_evaluation import DetectionEvaluationArtifact

    baseline_path = DATASET_DIR / "baseline_artifact.json"
    baseline_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline = DetectionEvaluationArtifact.model_validate(baseline_payload)

    candidate = await _run_loaded_dataset(
        session_factory,
        truth_service,
        loaded_detection_dataset,
        seed=42,
        code_sha="baseline0001",
    )
    assert diff_detection_against_baseline(baseline, candidate) == []


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_force_runtime_error_path(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from app.evaluation.detection.fixture_loader import parse_detection_replay_fixture
    from app.evaluation.fixture_loader import build_truth_from_fixture_case

    case_payload = {
        "case_id": "forced_error_case",
        "slice_expectation": {
            "slice_type": "threat",
            "expected_case_label": "true_positive",
            "expected_final_verdict": "confirmed_threat",
        },
        "label_provenance": {
            "adjudicator": "test",
            "adjudicated_at": "2026-08-01T08:00:00+00:00",
            "source_kind": "test",
        },
        "detection_replay": {
            "source_tenant_id": "tenant-det-forced",
            "cutoff_at": "2026-08-01T15:30:00+00:00",
            "force_runtime_error": True,
            "scope_seed": {
                "integration_instance_id": "inst-forced-001",
                "connector_id": "conn-forced-001",
            },
            "package_id": "drpkg-det-forced-v1",
            "package_version": 1,
            "rules": [
                {
                    "rule_id": "rule-forced",
                    "rule_version": 1,
                    "operator": "event_match",
                    "feature_contract_version": FEATURE_CONTRACT_VERSION,
                    "detection_scope_id": "scope-placeholder",
                    "window_kind": FeatureWindowKind.ONE_HOUR.value,
                    "group_key_fields": ["entity_type", "entity_id"],
                    "threshold": 1.0,
                    "severity": "medium",
                    "match_criteria": {"action": "create_process"},
                }
            ],
            "observations": [],
        },
    }

    truth_service = EvaluationTruthService(session_factory)
    await truth_service.persist(
        build_truth_from_fixture_case(
            case_payload,
            tenant_id="tenant-detection-eval",
            dataset_id="detection_forced_error_test",
            dataset_version="2026.08.02",
        )
    )
    manifest = await truth_service.get_dataset_manifest(
        tenant_id="tenant-detection-eval",
        dataset_id="detection_forced_error_test",
        dataset_version="2026.08.02",
    )
    replay = parse_detection_replay_fixture(case_payload)
    assert replay is not None
    candidate_refs = await derive_candidate_refs(session_factory, replay)
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    fixture_index.by_case_id["forced_error_case"] = replay
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)

    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=cutoff,
        effective_cutoff_at=cutoff,
        candidate_refs=candidate_refs,
        candidate_refs_entries=[candidate_refs],
        candidate_set_hash="",
    )
    case = next(item for item in artifact.case_results if item.case_id == "forced_error_case")
    assert case.observation.runtime_errors
    assert case.observation.runtime_errors[0].error_category == "fixture_forced_error"


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_gate_fail_closed_with_shipped_threshold_manifest(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
) -> None:
    from app.evaluation.detection.runner import DetectionEvaluationRunRequest
    from app.evaluation.threshold import load_threshold_manifest

    manifest, fixture_index = loaded_detection_dataset
    candidate_refs_entries, candidate_set_hash = await derive_all_candidate_refs(
        session_factory,
        fixture_index,
    )
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    shipped = load_threshold_manifest(DATASET_DIR / "threshold_manifest.json")
    threshold = shipped.model_copy(
        update={"required_scorers": [*shipped.required_scorers, "missing_scorer"]}
    )
    runner = DetectionEvaluationRunner(truth_service, session_factory)
    artifact = await runner.run(
        DetectionEvaluationRunRequest(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            dataset_content_hash=manifest.content_hash,
            seed=42,
            code_sha="abc1234",
            cutoff_at=cutoff,
            effective_cutoff_at=cutoff,
            candidate_refs=candidate_refs_entries[0],
            candidate_refs_entries=candidate_refs_entries,
            candidate_set_hash=candidate_set_hash,
            fixture_index=fixture_index,
            threshold_manifest=threshold,
        )
    )
    assert artifact.gate is not None
    assert artifact.gate.verdict == GateVerdict.FAIL_CLOSED


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_insufficient_sample_fails_run(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from app.evaluation.detection.fixture_loader import parse_detection_replay_fixture
    from app.evaluation.fixture_loader import build_truth_from_fixture_case
    from app.models.evaluation_quality import QualityMetricStatus

    benign_replay = {
        "source_tenant_id": "tenant-det-benign-only",
        "cutoff_at": "2026-08-01T15:30:00+00:00",
        "scope_seed": {
            "integration_instance_id": "inst-benign-only",
            "connector_id": "conn-benign-only",
        },
        "package_id": "drpkg-det-benign-only",
        "package_version": 1,
        "rules": [
            {
                "rule_id": "rule-benign-silent",
                "rule_version": 1,
                "operator": "event_match",
                "feature_contract_version": FEATURE_CONTRACT_VERSION,
                "detection_scope_id": "scope-placeholder",
                "window_kind": FeatureWindowKind.ONE_HOUR.value,
                "group_key_fields": ["entity_type", "entity_id"],
                "threshold": 99.0,
                "severity": "medium",
                "match_criteria": {"action": "never_matches"},
            }
        ],
        "observations": [],
    }
    truth_service = EvaluationTruthService(session_factory)
    fixture_index = load_detection_fixture_index(DATASET_DIR)
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)

    for index in (1, 2):
        case_payload = {
            "case_id": f"benign_only_{index}",
            "slice_expectation": {
                "slice_type": "benign",
                "expected_case_label": "false_positive",
                "expected_final_verdict": "false_positive",
            },
            "label_provenance": {
                "adjudicator": "test",
                "adjudicated_at": "2026-08-01T08:00:00+00:00",
                "source_kind": "test",
            },
            "detection_replay": benign_replay,
        }
        await truth_service.persist(
            build_truth_from_fixture_case(
                case_payload,
                tenant_id="tenant-detection-eval",
                dataset_id="detection_benign_only_test",
                dataset_version="2026.08.02",
            )
        )
        replay = parse_detection_replay_fixture(case_payload)
        assert replay is not None
        fixture_index.by_case_id[f"benign_only_{index}"] = replay

    manifest = await truth_service.get_dataset_manifest(
        tenant_id="tenant-detection-eval",
        dataset_id="detection_benign_only_test",
        dataset_version="2026.08.02",
    )
    candidate_refs = await derive_candidate_refs(
        session_factory,
        fixture_index.by_case_id["benign_only_1"],
    )
    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=cutoff,
        effective_cutoff_at=cutoff,
        candidate_refs=candidate_refs,
        candidate_refs_entries=[candidate_refs],
        candidate_set_hash="",
    )
    assert artifact.status == EvaluationRunStatus.FAILED
    assert artifact.quality_report is not None
    threat_recall = next(
        metric for metric in artifact.quality_report.metrics if metric.metric_id == "threat_recall"
    )
    assert threat_recall.status == QualityMetricStatus.INSUFFICIENT_SAMPLE


@pytest.mark.evaluation
@pytest.mark.asyncio
async def test_tenant_probe_validation_error_not_silent_pass(
    session_factory: async_sessionmaker[AsyncSession],
    truth_service: EvaluationTruthService,
    loaded_detection_dataset: tuple[object, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.errors import ValidationError
    from app.services.detection_rule_runtime import DetectionRuleRuntimeService

    manifest, fixture_index = loaded_detection_dataset
    candidate_refs_entries, candidate_set_hash = await derive_all_candidate_refs(
        session_factory,
        fixture_index,
    )
    cutoff = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    original_execute = DetectionRuleRuntimeService.execute_shadow

    async def _execute_with_probe_failure(
        self: DetectionRuleRuntimeService,
        *,
        source_tenant_id: str,
        cutoff_at: datetime,
        package_id: str,
    ) -> object:
        if source_tenant_id == "tenant-det-foreign":
            raise ValidationError("probe tenant package scope misconfigured")
        return await original_execute(
            self,
            source_tenant_id=source_tenant_id,
            cutoff_at=cutoff_at,
            package_id=package_id,
        )

    monkeypatch.setattr(
        DetectionRuleRuntimeService,
        "execute_shadow",
        _execute_with_probe_failure,
    )
    artifact = await run_fixture_detection_evaluation(
        truth_service,
        session_factory,
        manifest,
        fixture_index,
        seed=42,
        code_sha="abc1234",
        cutoff_at=cutoff,
        effective_cutoff_at=cutoff,
        candidate_refs=candidate_refs_entries[0],
        candidate_refs_entries=candidate_refs_entries,
        candidate_set_hash=candidate_set_hash,
    )
    failed_probe = next(
        probe
        for probe in artifact.tenant_safety.probes
        if probe.probe_id == "probe-threat-cross-tenant"
    )
    assert failed_probe.passed is False
    assert failed_probe.reason_code == "probe_execution_error"
    assert artifact.status == EvaluationRunStatus.FAILED
