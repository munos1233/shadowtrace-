"""Detection evaluation runner orchestration (ISSUE-126 / #631 Phase A).

Specialized runner for shadow detection replay (#626–#628). Reuses #608 shared
components (``EvaluationTruthService``, ``evaluate_gate``, threshold manifests)
but does not delegate to ``EvaluationRunner`` — detection cases require shadow
runtime seeding and slice-specific scorers.

Post-promotion production drift comparison is Phase B (#629); this runner emits
pre-promotion ``DetectionEvaluationArtifact`` only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.evaluation.detection.artifact import finalize_detection_artifact
from app.evaluation.detection.fixture_loader import DetectionFixtureIndex, DetectionReplayFixture
from app.evaluation.detection.metrics import (
    build_detection_quality_report,
    build_resource_summary,
    build_tenant_safety_summary,
    quality_report_has_blocking_metrics,
)
from app.evaluation.detection.replayer import DetectionShadowReplayer
from app.evaluation.detection.scorers.base import (
    DetectionScorerContext,
    DetectionScorerRegistration,
)
from app.evaluation.detection.scorers.registry import (
    DetectionScorerRegistry,
    default_detection_scorer_registry,
)
from app.evaluation.paths import repo_relative_manifest_path
from app.evaluation.scorers.registry import ScorerRegistry
from app.evaluation.threshold import (
    evaluate_gate,
    load_threshold_manifest,
    validate_threshold_manifest_for_run,
)
from app.models.detection_evaluation import (
    DetectionCandidateRefs,
    DetectionCaseResult,
    DetectionEvaluationArtifact,
    DetectionEvaluationConfig,
    DetectionTenantSafetyProbe,
)
from app.models.evaluation_quality import EvaluationQualityReport
from app.models.evaluation_run import (
    EvaluationAggregateMetrics,
    EvaluationReleaseRefs,
    EvaluationRunStatus,
    EvaluationScorerResult,
    EvaluationThresholdManifest,
    GateVerdict,
    ScorerOutcome,
)
from app.models.evaluation_run import (
    EvaluationCaseResult as AgentEvaluationCaseResult,
)
from app.models.evaluation_truth import (
    EvaluationCaseTruth,
    EvaluationDatasetManifest,
    EvaluationTruthQuery,
    SliceType,
    UnevaluableSliceExpectation,
)
from app.services.evaluation_truth_service import EvaluationTruthService


def _slice_type(truth: EvaluationCaseTruth) -> SliceType:
    return SliceType(truth.slice_expectation.slice_type)


def _scorer_failure_status(
    scorer_results: list[EvaluationScorerResult],
    *,
    required_scorer_ids: frozenset[str] | None = None,
) -> EvaluationRunStatus | None:
    active = scorer_results
    if required_scorer_ids is not None:
        active = [r for r in scorer_results if r.scorer_id in required_scorer_ids]
    if not active:
        return None
    if any(r.outcome == ScorerOutcome.ERROR for r in active):
        return EvaluationRunStatus.FAILED
    if any(r.outcome == ScorerOutcome.FAIL for r in active):
        return EvaluationRunStatus.FAILED
    if any(r.outcome == ScorerOutcome.SKIPPED for r in active):
        return EvaluationRunStatus.FAILED
    return None


def _case_status(
    slice_type: SliceType,
    scorer_results: list[EvaluationScorerResult],
    *,
    required_scorer_ids: frozenset[str] | None = None,
) -> EvaluationRunStatus:
    failure = _scorer_failure_status(
        scorer_results,
        required_scorer_ids=required_scorer_ids,
    )
    if failure is not None:
        return failure
    if slice_type == SliceType.UNEVALUABLE:
        active = (
            scorer_results
            if required_scorer_ids is None
            else [r for r in scorer_results if r.scorer_id in required_scorer_ids]
        )
        if not active:
            return EvaluationRunStatus.UNEVALUABLE
        if all(r.outcome == ScorerOutcome.UNEVALUABLE for r in active):
            return EvaluationRunStatus.UNEVALUABLE
        return EvaluationRunStatus.FAILED
    active = (
        scorer_results
        if required_scorer_ids is None
        else [r for r in scorer_results if r.scorer_id in required_scorer_ids]
    )
    if not active:
        return EvaluationRunStatus.FAILED
    if all(r.outcome == ScorerOutcome.PASS for r in active):
        return EvaluationRunStatus.COMPLETED
    return EvaluationRunStatus.FAILED


def _aggregate(
    case_results: list[DetectionCaseResult],
    *,
    required_scorer_ids: frozenset[str],
) -> EvaluationAggregateMetrics:
    pass_count = fail_count = unevaluable_count = error_count = 0
    required_scorer_error_count = 0

    for case in case_results:
        required_results = [r for r in case.scorer_results if r.scorer_id in required_scorer_ids]
        outcomes = {r.outcome for r in required_results}
        if ScorerOutcome.ERROR in outcomes:
            error_count += 1
            required_scorer_error_count += sum(
                1
                for r in required_results
                if r.outcome == ScorerOutcome.ERROR and r.scorer_id in required_scorer_ids
            )
        elif case.case_status == EvaluationRunStatus.UNEVALUABLE:
            unevaluable_count += 1
        elif ScorerOutcome.FAIL in outcomes or case.case_status == EvaluationRunStatus.FAILED:
            fail_count += 1
        elif required_results and all(r.outcome == ScorerOutcome.PASS for r in required_results):
            pass_count += 1
        else:
            fail_count += 1

    evaluable = pass_count + fail_count + error_count
    pass_rate = (pass_count / evaluable) if evaluable else 1.0

    return EvaluationAggregateMetrics(
        case_count=len(case_results),
        pass_count=pass_count,
        fail_count=fail_count,
        unevaluable_count=unevaluable_count,
        error_count=error_count,
        pass_rate=pass_rate,
        required_scorer_error_count=required_scorer_error_count,
    )


def _required_scorer_ids(
    manifest: EvaluationThresholdManifest | None,
    registry: DetectionScorerRegistry,
) -> frozenset[str]:
    if manifest is not None and manifest.required_scorers:
        return frozenset(manifest.required_scorers)
    return frozenset(registry.all_required_ids())


def _run_status(
    aggregates: EvaluationAggregateMetrics,
    gate_verdict: GateVerdict | None,
    errors: list[str],
    tenant_safety_failures: int,
    *,
    quality_report: EvaluationQualityReport | None = None,
) -> EvaluationRunStatus:
    if errors or tenant_safety_failures > 0:
        return EvaluationRunStatus.FAILED
    if quality_report_has_blocking_metrics(quality_report):
        return EvaluationRunStatus.FAILED
    if gate_verdict in {GateVerdict.FAIL, GateVerdict.FAIL_CLOSED}:
        return EvaluationRunStatus.FAILED
    if aggregates.error_count > 0 or aggregates.fail_count > 0:
        return EvaluationRunStatus.FAILED
    if aggregates.case_count == aggregates.unevaluable_count:
        return EvaluationRunStatus.UNEVALUABLE
    return EvaluationRunStatus.COMPLETED


@dataclass(frozen=True, slots=True)
class DetectionEvaluationRunRequest:
    tenant_id: str
    dataset_id: str
    dataset_version: str
    dataset_content_hash: str
    seed: int
    code_sha: str
    cutoff_at: datetime
    effective_cutoff_at: datetime
    candidate_refs: DetectionCandidateRefs
    candidate_refs_entries: list[DetectionCandidateRefs]
    candidate_set_hash: str
    fixture_index: DetectionFixtureIndex
    release_refs: EvaluationReleaseRefs = field(default_factory=EvaluationReleaseRefs)
    scorer_ids: list[str] | None = None
    threshold_manifest: EvaluationThresholdManifest | None = None
    threshold_manifest_path: str | None = None


class DetectionEvaluationRunner:
    """Shadow detection evaluation runner consuming canonical truth."""

    def __init__(
        self,
        truth_service: EvaluationTruthService,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        replayer: DetectionShadowReplayer | None = None,
        registry: DetectionScorerRegistry | None = None,
    ) -> None:
        self._truth_service = truth_service
        self._session_factory = session_factory
        self._replayer = replayer or DetectionShadowReplayer(session_factory)
        self._registry = registry or default_detection_scorer_registry()

    async def _load_truths(
        self, request: DetectionEvaluationRunRequest
    ) -> list[EvaluationCaseTruth]:
        truths: list[EvaluationCaseTruth] = []
        page = 1
        while True:
            result = await self._truth_service.query_truths(
                EvaluationTruthQuery(
                    tenant_id=request.tenant_id,
                    dataset_id=request.dataset_id,
                    dataset_version=request.dataset_version,
                    latest_revision_only=True,
                    page=page,
                    page_size=200,
                )
            )
            truths.extend(result.items)
            if len(truths) >= result.total:
                break
            page += 1
        if not truths:
            raise ValidationError(
                "no canonical truth rows for dataset",
                details={
                    "tenant_id": request.tenant_id,
                    "dataset_id": request.dataset_id,
                    "dataset_version": request.dataset_version,
                },
            )
        return sorted(truths, key=lambda t: t.case_id)

    async def _validate_dataset_content_hash(self, request: DetectionEvaluationRunRequest) -> None:
        manifest = await self._truth_service.get_dataset_manifest(
            tenant_id=request.tenant_id,
            dataset_id=request.dataset_id,
            dataset_version=request.dataset_version,
        )
        if manifest.content_hash != request.dataset_content_hash:
            raise ValidationError(
                "dataset content hash mismatch",
                details={
                    "expected": manifest.content_hash,
                    "actual": request.dataset_content_hash,
                    "dataset_id": request.dataset_id,
                    "dataset_version": request.dataset_version,
                },
            )

    def _resolve_scorers(self, request: DetectionEvaluationRunRequest) -> list[str]:
        if request.scorer_ids:
            for scorer_id in request.scorer_ids:
                self._registry.get(scorer_id)
            return list(request.scorer_ids)
        return self._registry.scorer_ids

    def _get_replay_fixture(
        self,
        request: DetectionEvaluationRunRequest,
        truth: EvaluationCaseTruth,
    ) -> DetectionReplayFixture:
        replay = request.fixture_index.by_case_id.get(truth.case_id)
        if replay is None:
            raise ValidationError(
                "missing detection_replay fixture for case",
                details={"case_id": truth.case_id},
            )
        return replay

    async def _run_tenant_probe(
        self,
        replay: DetectionReplayFixture,
    ) -> DetectionTenantSafetyProbe | None:
        probe_cfg = replay.tenant_isolation_probe
        if probe_cfg is None:
            return None
        probe_outcome = await self._replayer.probe_tenant_isolation(
            replay,
            probe_tenant_id=probe_cfg.probe_tenant_id,
        )
        if probe_outcome.execution_error:
            passed = False
            reason_code = "probe_execution_error"
            message = probe_outcome.execution_error
        else:
            passed = len(probe_outcome.foreign_candidates) == 0
            reason_code = "cross_tenant_leak" if not passed else ""
            message = (
                f"foreign tenant saw {len(probe_outcome.foreign_candidates)} candidate(s)"
                if not passed
                else "no cross-tenant candidates observed"
            )
        return DetectionTenantSafetyProbe(
            probe_id=probe_cfg.probe_id,
            source_tenant_id=replay.source_tenant_id,
            probe_tenant_id=probe_cfg.probe_tenant_id,
            passed=passed,
            reason_code=reason_code,
            message=message,
        )

    async def run(self, request: DetectionEvaluationRunRequest) -> DetectionEvaluationArtifact:
        started_at = datetime.now(tz=UTC)
        await self._validate_dataset_content_hash(request)
        truths = await self._load_truths(request)
        scorer_ids = self._resolve_scorers(request)

        case_results: list[DetectionCaseResult] = []
        errors: list[str] = []
        tenant_probes: list[DetectionTenantSafetyProbe] = []

        for truth in truths:
            slice_type = _slice_type(truth)
            replay = self._get_replay_fixture(request, truth)
            observation = await self._replayer.replay(truth, replay, seed=request.seed)

            probe = await self._run_tenant_probe(replay)
            if probe is not None:
                tenant_probes.append(probe)

            case_candidate_refs = await self._replayer.candidate_refs_for(replay)

            ctx = DetectionScorerContext(
                seed=request.seed,
                dataset_id=request.dataset_id,
                dataset_version=request.dataset_version,
                replay_mode=self._replayer.replay_mode,
                source_tenant_id=replay.source_tenant_id,
                probe_tenant_id=(
                    replay.tenant_isolation_probe.probe_tenant_id
                    if replay.tenant_isolation_probe
                    else None
                ),
                expected_rule_ids=replay.expected_rule_ids,
                max_observations_scanned=replay.max_observations_scanned,
            )

            registrations = self._registry.list_for_slice(slice_type)
            active_registrations = [r for r in registrations if r.scorer_id in scorer_ids]
            if slice_type != SliceType.UNEVALUABLE and not active_registrations:
                if registrations:
                    errors.append(
                        "no active detection scorers for slice "
                        f"{slice_type.value} case {truth.case_id} "
                        f"(configured scorer_ids={scorer_ids})"
                    )
                else:
                    errors.append(
                        "no detection scorers registered for slice "
                        f"{slice_type.value}: {truth.case_id}"
                    )

            scorer_results: list[EvaluationScorerResult] = []
            for registration in active_registrations:
                try:
                    scorer_results.append(registration.scorer.score(truth, observation, ctx))
                except Exception as exc:  # noqa: BLE001 — scorer boundary fail-closed
                    scorer_results.append(
                        EvaluationScorerResult(
                            scorer_id=registration.scorer_id,
                            outcome=ScorerOutcome.ERROR,
                            reason_code="scorer_exception",
                            message=str(exc)[:512],
                        )
                    )

            required_for_case = frozenset(
                reg.scorer_id for reg in active_registrations if reg.required
            )
            case_results.append(
                DetectionCaseResult(
                    case_id=truth.case_id,
                    truth_id=truth.truth_id,
                    truth_revision=truth.revision,
                    truth_content_hash=truth.content_hash,
                    slice_type=slice_type,
                    observation=observation,
                    scorer_results=scorer_results,
                    case_status=_case_status(
                        slice_type,
                        scorer_results,
                        required_scorer_ids=required_for_case,
                    ),
                    unevaluable_reason=(
                        truth.slice_expectation.reason_code
                        if isinstance(truth.slice_expectation, UnevaluableSliceExpectation)
                        else None
                    ),
                    candidate_refs=case_candidate_refs,
                )
            )

        if request.threshold_manifest is not None:
            validate_threshold_manifest_for_run(
                request.threshold_manifest,
                dataset_id=request.dataset_id,
                dataset_version=request.dataset_version,
            )

        required_ids = _required_scorer_ids(request.threshold_manifest, self._registry)
        aggregates = _aggregate(case_results, required_scorer_ids=required_ids)

        # Adapt detection registry scorers for shared gate evaluator interface.
        gate_registry = _GateRegistryAdapter(self._registry)
        gate = evaluate_gate(
            request.threshold_manifest,
            aggregates=aggregates,
            case_results=_gate_case_adapter(case_results),
            registry=cast(ScorerRegistry, gate_registry),
            manifest_path=request.threshold_manifest_path,
        )

        tenant_safety = build_tenant_safety_summary(tenant_probes)
        tenant_failures = tenant_safety.fail_count
        quality_report = build_detection_quality_report(
            dataset_id=request.dataset_id,
            dataset_version=request.dataset_version,
            dataset_content_hash=request.dataset_content_hash,
            code_sha=request.code_sha,
            release_refs=request.release_refs,
            case_results=case_results,
        )
        status = _run_status(
            aggregates,
            gate.verdict if gate else None,
            errors,
            tenant_failures,
            quality_report=quality_report,
        )
        completed_at = datetime.now(tz=UTC)

        config = DetectionEvaluationConfig(
            seed=request.seed,
            cutoff_at=request.cutoff_at,
            effective_cutoff_at=request.effective_cutoff_at,
            replay_mode=self._replayer.replay_mode,
            replay_fidelity=self._replayer.replay_fidelity,
            candidate_refs=request.candidate_refs,
            candidate_refs_entries=request.candidate_refs_entries,
            candidate_set_hash=request.candidate_set_hash,
            scorer_ids=scorer_ids,
        )

        artifact = DetectionEvaluationArtifact(
            evaluation_id=f"det-eval-{uuid.uuid4()}",
            tenant_id=request.tenant_id,
            dataset_id=request.dataset_id,
            dataset_version=request.dataset_version,
            dataset_content_hash=request.dataset_content_hash,
            code_sha=request.code_sha,
            config=config,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            case_results=case_results,
            aggregates=aggregates,
            gate=gate,
            quality_report=quality_report,
            resource_summary=build_resource_summary(case_results),
            tenant_safety=tenant_safety,
            errors=errors,
        )
        return finalize_detection_artifact(artifact)


class _GateRegistryAdapter:
    """Bridge detection scorer registry to shared threshold gate evaluator."""

    def __init__(self, registry: DetectionScorerRegistry) -> None:
        self._registry = registry

    def get(self, scorer_id: str) -> DetectionScorerRegistration:
        return self._registry.get(scorer_id)

    def all_required_ids(self) -> list[str]:
        return self._registry.all_required_ids()

    @property
    def scorer_ids(self) -> list[str]:
        return self._registry.scorer_ids


def _gate_case_adapter(
    case_results: list[DetectionCaseResult],
) -> list[AgentEvaluationCaseResult]:
    """Minimal adapter so evaluate_gate can inspect required scorer errors."""
    from app.models.evaluation_run import CaseObservation

    adapted: list[AgentEvaluationCaseResult] = []
    for case in case_results:
        adapted.append(
            AgentEvaluationCaseResult(
                case_id=case.case_id,
                truth_id=case.truth_id,
                truth_revision=case.truth_revision,
                truth_content_hash=case.truth_content_hash,
                slice_type=case.slice_type,
                observation=CaseObservation(
                    case_id=case.case_id,
                    slice_type=case.slice_type,
                    observation_available=case.observation.observation_available,
                ),
                scorer_results=case.scorer_results,
                case_status=case.case_status,
                unevaluable_reason=case.unevaluable_reason,
            )
        )
    return adapted


async def run_fixture_detection_evaluation(
    truth_service: EvaluationTruthService,
    session_factory: async_sessionmaker[AsyncSession],
    manifest: EvaluationDatasetManifest,
    fixture_index: DetectionFixtureIndex,
    *,
    seed: int,
    code_sha: str,
    cutoff_at: datetime,
    candidate_refs: DetectionCandidateRefs,
    candidate_refs_entries: list[DetectionCandidateRefs] | None = None,
    candidate_set_hash: str = "",
    effective_cutoff_at: datetime | None = None,
    release_refs: EvaluationReleaseRefs | None = None,
    threshold_manifest_path: Path | None = None,
    registry: DetectionScorerRegistry | None = None,
) -> DetectionEvaluationArtifact:
    """Convenience entry for fixture-backed detection evaluation datasets."""
    threshold: EvaluationThresholdManifest | None = None
    threshold_path_str: str | None = None
    if threshold_manifest_path is not None:
        threshold_path_str = repo_relative_manifest_path(threshold_manifest_path)
        threshold = load_threshold_manifest(threshold_manifest_path)

    runner = DetectionEvaluationRunner(
        truth_service,
        session_factory,
        registry=registry,
    )
    return await runner.run(
        DetectionEvaluationRunRequest(
            tenant_id=manifest.tenant_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            dataset_content_hash=manifest.content_hash,
            seed=seed,
            code_sha=code_sha,
            cutoff_at=cutoff_at,
            effective_cutoff_at=effective_cutoff_at or cutoff_at,
            candidate_refs=candidate_refs,
            candidate_refs_entries=candidate_refs_entries or [candidate_refs],
            candidate_set_hash=candidate_set_hash,
            fixture_index=fixture_index,
            release_refs=release_refs or EvaluationReleaseRefs(),
            threshold_manifest=threshold,
            threshold_manifest_path=threshold_path_str,
        )
    )


__all__ = [
    "DetectionEvaluationRunRequest",
    "DetectionEvaluationRunner",
    "run_fixture_detection_evaluation",
]
