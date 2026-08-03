"""Detection shadow replayer (ISSUE-126 / #631 Phase A).

Replays canonical truth cases through the shadow detection runtime (#626–#628).
Never reads post-promotion Event severity, agent conclusions, or response outcomes.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.evaluation.detection.fixture_loader import DetectionReplayFixture
from app.evaluation.detection.fixture_seeder import (
    SeededDetectionContext,
    build_candidate_refs,
    seed_detection_replay_fixture,
)
from app.models.detection_evaluation import (
    DetectionCandidateRefs,
    DetectionCaseObservation,
    DetectionResourceMetrics,
)
from app.models.detection_rule import CandidateDetection, DetectionRuleRuntimeError
from app.models.evaluation_truth import EvaluationCaseTruth, SliceType, UnevaluableSliceExpectation
from app.services.detection_rule_runtime import DetectionRuleRuntimeService


def _derive_case_nonce(case_id: str, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}:{case_id}".encode()).hexdigest()
    return int(digest[:8], 16)


def _replay_cache_key(replay: DetectionReplayFixture) -> str:
    return (
        f"{replay.source_tenant_id}:{replay.scope_seed.integration_instance_id}:{replay.package_id}"
    )


def _is_probe_misconfiguration_error(exc: ValidationError) -> bool:
    """Distinguish probe setup failures from expected tenant/package isolation."""
    message = str(exc).lower()
    if "not found for tenant" in message:
        return False
    details = getattr(exc, "details", None) or {}
    if isinstance(details, dict) and details.get("package_id") and details.get("source_tenant_id"):
        return False
    return True


@dataclass(frozen=True, slots=True)
class TenantIsolationProbeOutcome:
    """Result of executing a cross-tenant isolation probe."""

    foreign_candidates: list[CandidateDetection]
    execution_error: str | None = None


class DetectionShadowReplayer:
    """Deterministic shadow runtime replay for detection evaluation cases."""

    replay_mode = "detection_shadow"
    replay_fidelity = "shadow_runtime_v1"

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._runtime = DetectionRuleRuntimeService(session_factory)
        self._seed_cache: dict[str, SeededDetectionContext] = {}

    async def seed_case(self, replay: DetectionReplayFixture) -> SeededDetectionContext:
        cache_key = _replay_cache_key(replay)
        if cache_key not in self._seed_cache:
            self._seed_cache[cache_key] = await seed_detection_replay_fixture(
                self._session_factory,
                replay,
            )
        return self._seed_cache[cache_key]

    async def candidate_refs_for(self, replay: DetectionReplayFixture) -> DetectionCandidateRefs:
        seeded = await self.seed_case(replay)
        return build_candidate_refs(replay, seeded)

    async def replay(
        self,
        truth: EvaluationCaseTruth,
        replay: DetectionReplayFixture,
        *,
        seed: int,
    ) -> DetectionCaseObservation:
        started = time.perf_counter()
        slice_type = SliceType(truth.slice_expectation.slice_type)
        nonce = _derive_case_nonce(truth.case_id, seed)

        if isinstance(truth.slice_expectation, UnevaluableSliceExpectation):
            seeded = await self.seed_case(replay)
            if replay.skip_shadow_execute:
                duration_ms = int((time.perf_counter() - started) * 1000)
                return DetectionCaseObservation(
                    case_id=truth.case_id,
                    slice_type=slice_type,
                    observation_available=False,
                    replay_cutoff_at=replay.cutoff_at,
                    replay_notes=(
                        f"unevaluable:{truth.slice_expectation.reason_code};seed={seed};n={nonce:x}"
                    ),
                    resource_metrics=DetectionResourceMetrics(replay_duration_ms=duration_ms),
                )

        seeded = await self.seed_case(replay)

        if replay.force_runtime_error:
            duration_ms = int((time.perf_counter() - started) * 1000)
            runtime_error = DetectionRuleRuntimeError(
                error_id=f"err-{truth.case_id}",
                source_tenant_id=replay.source_tenant_id,
                package_id=seeded.package_id,
                rule_id=replay.rules[0].rule_id if replay.rules else None,
                error_category="fixture_forced_error",
                error_message="fixture forced runtime error",
                detail={"case_id": truth.case_id},
            )
            return DetectionCaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                runtime_errors=[runtime_error],
                resource_metrics=DetectionResourceMetrics(
                    runtime_error_count=1,
                    replay_duration_ms=duration_ms,
                ),
                observation_available=False,
                replay_cutoff_at=replay.cutoff_at,
                replay_notes=f"forced_error;seed={seed};n={nonce:x}",
            )

        if replay.skip_shadow_execute:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return DetectionCaseObservation(
                case_id=truth.case_id,
                slice_type=slice_type,
                observation_available=False,
                replay_cutoff_at=replay.cutoff_at,
                replay_notes=f"skip_shadow_execute;seed={seed};n={nonce:x}",
                resource_metrics=DetectionResourceMetrics(replay_duration_ms=duration_ms),
            )

        result = await self._runtime.execute_shadow(
            source_tenant_id=replay.source_tenant_id,
            cutoff_at=replay.cutoff_at,
            package_id=seeded.package_id,
        )
        duration_ms = int((time.perf_counter() - started) * 1000)

        return DetectionCaseObservation(
            case_id=truth.case_id,
            slice_type=slice_type,
            candidates=list(result.candidates),
            runtime_errors=list(result.errors),
            resource_metrics=DetectionResourceMetrics(
                rules_evaluated=result.rules_evaluated,
                observations_scanned=result.observations_scanned,
                runtime_error_count=len(result.errors),
                candidate_count=len(result.candidates),
                replay_duration_ms=duration_ms,
            ),
            observation_available=True,
            replay_cutoff_at=replay.cutoff_at,
            replay_notes=f"shadow_runtime_v1;seed={seed};n={nonce:x}",
        )

    async def probe_tenant_isolation(
        self,
        replay: DetectionReplayFixture,
        *,
        probe_tenant_id: str,
    ) -> TenantIsolationProbeOutcome:
        seeded = await self.seed_case(replay)
        try:
            result = await self._runtime.execute_shadow(
                source_tenant_id=probe_tenant_id,
                cutoff_at=replay.cutoff_at,
                package_id=seeded.package_id,
            )
        except ValidationError as exc:
            if _is_probe_misconfiguration_error(exc):
                return TenantIsolationProbeOutcome(
                    foreign_candidates=[],
                    execution_error=str(exc)[:512],
                )
            return TenantIsolationProbeOutcome(foreign_candidates=[])
        return TenantIsolationProbeOutcome(
            foreign_candidates=list(result.candidates),
        )


__all__ = ["DetectionShadowReplayer", "TenantIsolationProbeOutcome"]
