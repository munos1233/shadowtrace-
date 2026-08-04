"""Detection production promotion saga (ISSUE-124 / #629)."""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.db.orm.detection_promotion import DetectionPromotionORM
from app.ingestion.source_ingester import SourceIngester
from app.models.detection_evaluation import DetectionEvaluationArtifact
from app.models.detection_governance import (
    DetectionGovernanceDecision,
    DetectionGovernanceDecisionKind,
    DetectionGovernanceReasonCode,
)
from app.models.detection_promotion import (
    DETECTION_PROMOTION_SCHEMA_VERSION,
    DetectionContextProjectionError,
    DetectionPromotionReasonCode,
    DetectionPromotionRecord,
    DetectionPromotionRequest,
    DetectionPromotionResult,
    DetectionPromotionStatus,
    TypedIngestResult,
)
from app.models.detection_rule import (
    CandidateDetection,
    DetectionRuleRuntimeState,
)
from app.models.detection_scope import DetectionScopeLifecycleState, DetectionScopeRevision
from app.services.candidate_source_projection import candidate_to_source_alert
from app.services.derived_detection_connector_service import DerivedDetectionConnectorService
from app.services.detection_governance_binding import validate_decision_artifact_binding
from app.services.detection_governance_service import DetectionGovernanceService
from app.services.detection_rule_runtime import row_to_candidate_detection
from app.services.detection_rule_service import (
    DetectionRuleService,
    row_to_detection_rule_package,
)
from app.services.detection_scope_service import DetectionScopeService
from app.services.event_service import EventService, ingest_result_to_typed

MAX_PROMOTION_INGEST_RETRIES = 5
PAYLOAD_RETRY_COUNT_KEY = "ingest_retry_count"
PAYLOAD_PROJECTION_ERROR_KEY = "context_projection_error"

if TYPE_CHECKING:
    from app.services.detection_context_projector import DetectionContextProjector

logger = logging.getLogger(__name__)


def build_promotion_key(
    *,
    candidate_detection_id: str,
    candidate_content_hash: str,
    decision_id: str,
    package_version: int,
) -> str:
    return f"{candidate_detection_id}|{candidate_content_hash}|v{package_version}|{decision_id}"


class DetectionPromotionService:
    """Durable saga: governance-approved candidate → SourceIngester → EventService."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        governance: DetectionGovernanceService | None = None,
        event_service: EventService,
        source_ingester: SourceIngester,
        derived_connectors: DerivedDetectionConnectorService | None = None,
        rule_service: DetectionRuleService | None = None,
        context_projector: DetectionContextProjector | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._governance = governance or DetectionGovernanceService(session_factory)
        self._events = event_service
        self._ingester = source_ingester
        self._derived = derived_connectors or DerivedDetectionConnectorService(session_factory)
        self._rules = rule_service or DetectionRuleService(session_factory)
        self._context_projector = context_projector
        self._now = now or (lambda: datetime.now(UTC))

    async def _maybe_project_detection_context(
        self,
        record: DetectionPromotionRecord,
    ) -> DetectionContextProjectionError | None:
        if self._context_projector is None:
            return None
        if record.status is not DetectionPromotionStatus.COMPLETED or record.event_id is None:
            return None
        try:
            await self._context_projector.project_from_promotion(
                record.promotion_id,
                tenant_id=record.tenant_id,
            )
            return None
        except ValidationError as exc:
            reason = (
                str(
                    exc.details.get(
                        "reason",
                        DetectionPromotionReasonCode.CONTEXT_PROJECTION_FAILED.value,
                    )
                )
                if isinstance(exc.details, dict)
                else DetectionPromotionReasonCode.CONTEXT_PROJECTION_FAILED.value
            )
            await self._record_projection_failure(
                record.promotion_id,
                message=str(exc),
                reason=reason,
            )
            logger.error(
                "detection context projection blocked promotion_id=%s reason=%s",
                record.promotion_id,
                exc.details if isinstance(exc.details, dict) else exc,
            )
            return DetectionContextProjectionError(
                reason=reason,
                message=str(exc)[:512],
                recorded_at=self._now(),
            )
        except Exception as exc:
            reason = DetectionPromotionReasonCode.CONTEXT_PROJECTION_FAILED.value
            await self._record_projection_failure(
                record.promotion_id,
                message=f"{type(exc).__name__}: {exc}",
                reason=reason,
            )
            logger.error(
                "detection context projection failed promotion_id=%s: %s",
                record.promotion_id,
                exc,
            )
            return DetectionContextProjectionError(
                reason=reason,
                message=f"{type(exc).__name__}: {exc}"[:512],
                recorded_at=self._now(),
            )

    async def _record_projection_failure(
        self,
        promotion_id: str,
        *,
        message: str,
        reason: str,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    DetectionPromotionORM,
                    promotion_id,
                    with_for_update=True,
                )
                if row is None:
                    return
                payload = dict(row.payload or {})
                payload[PAYLOAD_PROJECTION_ERROR_KEY] = {
                    "message": message[:512],
                    "reason": reason,
                    "at": self._now().isoformat(),
                }
                row.payload = payload
                codes = list(row.reason_codes or [])
                failed = DetectionPromotionReasonCode.CONTEXT_PROJECTION_FAILED.value
                if failed not in codes:
                    codes.append(failed)
                row.reason_codes = codes

    async def _finalize_promotion(
        self,
        result: DetectionPromotionResult,
    ) -> DetectionPromotionResult:
        finalized = self._finalize_promotion_result(result)
        projection_error = await self._maybe_project_detection_context(finalized.record)
        if projection_error is None:
            return finalized
        return finalized.model_copy(update={"context_projection_error": projection_error})

    async def promote_candidate(
        self,
        artifact: DetectionEvaluationArtifact,
        request: DetectionPromotionRequest,
    ) -> DetectionPromotionResult:
        if artifact.tenant_id != request.tenant_id:
            raise ValidationError(
                "tenant mismatch for promotion request",
                details={
                    "artifact_tenant_id": artifact.tenant_id,
                    "request_tenant_id": request.tenant_id,
                },
            )

        gate = await self._governance.evaluate_promotion_gate(artifact)
        if not gate.allowed:
            raise ValidationError(
                "promotion blocked: governance gate closed",
                details={
                    "reason_codes": [code.value for code in gate.reason_codes],
                    "messages": gate.messages,
                },
            )
        decision_id = request.decision_id or gate.decision_id
        if decision_id is None:
            raise ValidationError("promotion blocked: no active governance decision")

        decision = await self._governance.get_decision(
            decision_id,
            tenant_id=request.tenant_id,
        )
        if decision.decision is not DetectionGovernanceDecisionKind.APPROVE:
            raise ValidationError(
                "promotion blocked: decision is not an active approval",
                details={"decision_id": decision_id, "decision": decision.decision.value},
            )
        validate_decision_artifact_binding(decision, artifact)

        candidate = await self._load_candidate(
            request.candidate_detection_id,
            tenant_id=request.tenant_id,
        )
        self._validate_candidate_binding(decision, artifact, candidate)

        promotion_key = build_promotion_key(
            candidate_detection_id=candidate.candidate_detection_id,
            candidate_content_hash=candidate.content_hash,
            decision_id=decision_id,
            package_version=candidate.package_version,
        )
        existing = await self._get_by_promotion_key(promotion_key)
        if existing is not None:
            if existing.status is DetectionPromotionStatus.COMPLETED:
                return await self._finalize_promotion(
                    DetectionPromotionResult(
                        promotion_id=existing.promotion_id,
                        status=existing.status,
                        record=existing,
                        ingest_result=existing.ingest_result,
                        resumed=True,
                    )
                )
            return await self._finalize_promotion(
                await self._resume(existing, artifact, decision, candidate)
            )

        package_row = await self._load_package_row(candidate.package_id, request.tenant_id)
        package = row_to_detection_rule_package(package_row)
        if package.content_hash != decision.candidate_binding.candidate_refs.package_content_hash:
            raise ValidationError(
                "promotion blocked: package content hash mismatch",
                details={"reason": DetectionPromotionReasonCode.PACKAGE_HASH_MISMATCH.value},
            )
        if package.runtime_state is not DetectionRuleRuntimeState.SHADOW_ACTIVE:
            raise ValidationError(
                "promotion blocked: package not shadow_active",
                details={
                    "reason": DetectionPromotionReasonCode.PACKAGE_NOT_SHADOW_ACTIVE.value,
                    "runtime_state": package.runtime_state.value,
                },
            )

        promotion_id = await self._allocate_promotion_id()
        record = DetectionPromotionRecord(
            promotion_id=promotion_id,
            tenant_id=request.tenant_id,
            promotion_key=promotion_key,
            status=DetectionPromotionStatus.PENDING,
            decision_id=decision_id,
            candidate_detection_id=candidate.candidate_detection_id,
            candidate_content_hash=candidate.content_hash,
            package_id=candidate.package_id,
            package_version=candidate.package_version,
            package_content_hash=package.content_hash,
            detection_scope_id=candidate.detection_scope_id,
            scope_revision_id=decision.candidate_binding.scope_revision_id,
            created_at=self._now(),
            updated_at=self._now(),
        )
        record = await self._insert_ledger(record)
        return await self._finalize_promotion(
            await self._advance(record, artifact, decision, candidate, package_row)
        )

    async def _resume(
        self,
        record: DetectionPromotionRecord,
        artifact: DetectionEvaluationArtifact,
        decision: DetectionGovernanceDecision,
        candidate: CandidateDetection,
    ) -> DetectionPromotionResult:
        package_row = await self._load_package_row(candidate.package_id, record.tenant_id)
        return await self._advance(
            record,
            artifact,
            decision,
            candidate,
            package_row,
            resumed=True,
        )

    async def _advance(
        self,
        record: DetectionPromotionRecord,
        artifact: DetectionEvaluationArtifact,
        decision: DetectionGovernanceDecision,
        candidate: CandidateDetection,
        package_row: orm.DetectionRulePackage,
        *,
        resumed: bool = False,
    ) -> DetectionPromotionResult:
        scope_revision = await self._load_pinned_scope_revision(
            scope_revision_id=record.scope_revision_id,
            detection_scope_id=record.detection_scope_id,
            tenant_id=record.tenant_id,
        )
        derived = await self._derived.ensure_connector(
            source_tenant_id=record.tenant_id,
            detection_scope_id=record.detection_scope_id,
            scope_revision_id=record.scope_revision_id,
            connector_set=scope_revision.connector_set,
            source_product=scope_revision.identity.source_product,
        )
        record = await self._update_ledger(
            record,
            derived_connector_id=derived.connector_id,
        )

        if record.status in {
            DetectionPromotionStatus.PENDING,
            DetectionPromotionStatus.RETRY,
        }:
            alert = candidate_to_source_alert(
                candidate,
                derived_connector=derived,
                promotion_id=record.promotion_id,
            )
            try:
                ingest = await self._ingester.ingest_source_alert(
                    alert,
                    source_type=DERIVED_DETECTION_SOURCE_TYPE,
                )
            except Exception as exc:
                return await self._ingest_failure_result(
                    record,
                    message=f"{type(exc).__name__}: {exc}",
                    resumed=resumed,
                )
            typed = ingest_result_to_typed(ingest)
            if not typed.accepted or typed.event_id is None:
                return await self._ingest_failure_result(
                    record,
                    message=typed.error_message or "ingest did not produce event_id",
                    resumed=resumed,
                    ingest_result=typed,
                )
            record = await self._update_ledger(
                record,
                status=DetectionPromotionStatus.SOURCE_PERSISTED,
                source_record_id=typed.source_record_id,
                ingest_result=typed,
            )

        if record.status is DetectionPromotionStatus.SOURCE_PERSISTED:
            ingest_result = record.ingest_result
            if ingest_result is None or ingest_result.event_id is None:
                raise ValidationError("promotion ledger missing ingest result at event_link step")
            link_revision = record.link_revision
            if record.event_id is not None and record.event_id != ingest_result.event_id:
                link_revision += 1
            record = await self._update_ledger(
                record,
                status=DetectionPromotionStatus.EVENT_LINKED,
                event_id=ingest_result.event_id,
                link_revision=link_revision,
            )

        if record.status is DetectionPromotionStatus.EVENT_LINKED:
            await self._maybe_transition_package_to_production(package_row)
            record = await self._update_ledger(
                record,
                status=DetectionPromotionStatus.COMPLETED,
            )

        return DetectionPromotionResult(
            promotion_id=record.promotion_id,
            status=record.status,
            record=record,
            ingest_result=record.ingest_result,
            resumed=resumed,
        )

    @staticmethod
    def _finalize_promotion_result(
        result: DetectionPromotionResult,
    ) -> DetectionPromotionResult:
        if result.status is DetectionPromotionStatus.DEAD:
            raise ValidationError(
                "promotion failed: retry budget exhausted",
                details={
                    "promotion_id": result.promotion_id,
                    "reason_codes": [code.value for code in result.record.reason_codes],
                    "reason_message": result.record.reason_message,
                    "ingest_result": (
                        result.ingest_result.model_dump(mode="json")
                        if result.ingest_result is not None
                        else None
                    ),
                },
            )
        return result

    async def _maybe_transition_package_to_production(
        self,
        package_row: orm.DetectionRulePackage,
    ) -> None:
        """Promote the entire package on the first successful candidate promotion.

        ISSUE-124 intentionally transitions the whole ``shadow_active`` package to
        ``production_active`` when any governed candidate completes the saga.
        """
        async with self._session_factory() as session:
            fresh = await session.get(orm.DetectionRulePackage, package_row.package_id)
            if fresh is None or fresh.source_tenant_id != package_row.source_tenant_id:
                raise ResourceNotFoundError(
                    "detection rule package not found",
                    details={"package_id": package_row.package_id},
                )
            current = DetectionRuleRuntimeState(fresh.runtime_state)
        if current is DetectionRuleRuntimeState.PRODUCTION_ACTIVE:
            return
        if current is not DetectionRuleRuntimeState.SHADOW_ACTIVE:
            raise ValidationError(
                "promotion blocked: invalid package runtime transition",
                details={
                    "reason": DetectionPromotionReasonCode.PACKAGE_TRANSITION_BLOCKED.value,
                    "runtime_state": current.value,
                },
            )
        try:
            await self._rules.transition_runtime_state(
                package_id=package_row.package_id,
                target_state=DetectionRuleRuntimeState.PRODUCTION_ACTIVE,
                source_tenant_id=package_row.source_tenant_id,
            )
        except ValidationError:
            package = await self._rules.get_package(
                source_tenant_id=package_row.source_tenant_id,
                package_id=package_row.package_id,
            )
            if (
                package is None
                or package.runtime_state is not DetectionRuleRuntimeState.PRODUCTION_ACTIVE
            ):
                raise

    @staticmethod
    def _artifact_approved_candidate_keys(
        artifact: DetectionEvaluationArtifact,
    ) -> set[tuple[str, str]]:
        approved: set[tuple[str, str]] = set()
        for case in artifact.case_results:
            for listed in case.observation.candidates:
                approved.add((listed.candidate_detection_id, listed.content_hash))
        return approved

    @staticmethod
    def _validate_candidate_binding(
        decision: DetectionGovernanceDecision,
        artifact: DetectionEvaluationArtifact,
        candidate: CandidateDetection,
    ) -> None:
        """Validate governance binding against the candidate under promotion.

        When ``artifact.case_results`` is empty, artifact membership is skipped;
        governance ``candidate_binding`` remains the authoritative source of truth.
        When case results list candidates, the promoted candidate must appear in
        that enumeration (fail-closed).
        """
        bound = decision.candidate_binding.candidate_refs
        if candidate.detection_scope_id != bound.detection_scope_id:
            raise ValidationError(
                "promotion blocked: detection scope mismatch",
                details={"reason": DetectionPromotionReasonCode.SCOPE_MISMATCH.value},
            )
        binding_scope_revision_id = decision.candidate_binding.scope_revision_id
        if binding_scope_revision_id and bound.scope_revision_id != binding_scope_revision_id:
            raise ValidationError(
                "promotion blocked: scope revision binding mismatch",
                details={"reason": DetectionPromotionReasonCode.SCOPE_MISMATCH.value},
            )
        if candidate.package_id != bound.package_id:
            raise ValidationError(
                "promotion blocked: package id mismatch",
                details={"reason": DetectionPromotionReasonCode.CANDIDATE_BINDING_MISMATCH.value},
            )
        if candidate.package_version != bound.package_version:
            raise ValidationError(
                "promotion blocked: package version mismatch",
                details={"reason": DetectionPromotionReasonCode.CANDIDATE_BINDING_MISMATCH.value},
            )
        if bound.rule_ids and candidate.rule_id not in bound.rule_ids:
            raise ValidationError(
                "promotion blocked: candidate rule not in governance binding",
                details={"reason": DetectionPromotionReasonCode.CANDIDATE_BINDING_MISMATCH.value},
            )
        provenance = candidate.provenance
        if bound.model_release_id is not None:
            if provenance.model_release_id != bound.model_release_id:
                raise ValidationError(
                    "promotion blocked: model release id mismatch",
                    details={
                        "reason": DetectionPromotionReasonCode.CANDIDATE_BINDING_MISMATCH.value,
                    },
                )
            if (
                bound.model_release_hash is not None
                and provenance.model_release_hash != bound.model_release_hash
            ):
                raise ValidationError(
                    "promotion blocked: model release hash mismatch",
                    details={
                        "reason": DetectionPromotionReasonCode.CANDIDATE_BINDING_MISMATCH.value,
                    },
                )
        if not candidate.shadow_only:
            raise ValidationError(
                "promotion blocked: candidate is not shadow-only",
                details={"reason": DetectionPromotionReasonCode.CANDIDATE_NOT_SHADOW.value},
            )
        if candidate.source_tenant_id != artifact.tenant_id:
            raise ValidationError(
                "promotion blocked: tenant isolation failed",
                details={"reason": DetectionGovernanceReasonCode.TENANT_ISOLATION_FAILED.value},
            )
        approved = DetectionPromotionService._artifact_approved_candidate_keys(artifact)
        if approved:
            key = (candidate.candidate_detection_id, candidate.content_hash)
            if key not in approved:
                raise ValidationError(
                    "promotion blocked: candidate not in evaluation artifact",
                    details={
                        "reason": DetectionPromotionReasonCode.CANDIDATE_BINDING_MISMATCH.value,
                    },
                )

    async def _load_candidate(
        self,
        candidate_detection_id: str,
        *,
        tenant_id: str,
    ) -> CandidateDetection:
        async with self._session_factory() as session:
            row = await session.get(orm.CandidateDetection, candidate_detection_id)
            if row is None or row.source_tenant_id != tenant_id:
                raise ResourceNotFoundError(
                    "candidate detection not found",
                    details={"candidate_detection_id": candidate_detection_id},
                )
            if not row.shadow_only:
                raise ValidationError(
                    "promotion blocked: candidate is not shadow-only",
                    details={"reason": DetectionPromotionReasonCode.CANDIDATE_NOT_SHADOW.value},
                )
            return row_to_candidate_detection(row)

    async def _load_package_row(
        self,
        package_id: str,
        tenant_id: str,
    ) -> orm.DetectionRulePackage:
        async with self._session_factory() as session:
            row = await session.get(orm.DetectionRulePackage, package_id)
            if row is None or row.source_tenant_id != tenant_id:
                raise ResourceNotFoundError(
                    "detection rule package not found",
                    details={"package_id": package_id},
                )
            return row

    async def _load_pinned_scope_revision(
        self,
        *,
        scope_revision_id: str | None,
        detection_scope_id: str,
        tenant_id: str,
    ) -> DetectionScopeRevision:
        if not scope_revision_id:
            raise ValidationError(
                "promotion blocked: governance decision missing scope_revision_id",
                details={
                    "reason": DetectionPromotionReasonCode.SCOPE_MISMATCH.value,
                    "detection_scope_id": detection_scope_id,
                },
            )
        scope_service = DetectionScopeService(self._session_factory)
        revision = await scope_service.get_revision(scope_revision_id)
        if revision is None:
            raise ValidationError(
                "promotion blocked: pinned detection scope revision not found",
                details={
                    "reason": DetectionPromotionReasonCode.SCOPE_MISMATCH.value,
                    "scope_revision_id": scope_revision_id,
                },
            )
        if revision.detection_scope_id != detection_scope_id:
            raise ValidationError(
                "promotion blocked: pinned scope revision scope mismatch",
                details={
                    "reason": DetectionPromotionReasonCode.SCOPE_MISMATCH.value,
                    "scope_revision_id": scope_revision_id,
                    "expected_detection_scope_id": detection_scope_id,
                    "actual_detection_scope_id": revision.detection_scope_id,
                },
            )
        if revision.identity.source_tenant_id != tenant_id:
            raise ValidationError(
                "promotion blocked: pinned scope revision tenant mismatch",
                details={
                    "reason": DetectionPromotionReasonCode.SCOPE_MISMATCH.value,
                    "scope_revision_id": scope_revision_id,
                },
            )
        if revision.lifecycle_state is not DetectionScopeLifecycleState.ACTIVE:
            raise ValidationError(
                "promotion blocked: pinned scope revision is not active",
                details={
                    "reason": DetectionPromotionReasonCode.SCOPE_MISMATCH.value,
                    "scope_revision_id": scope_revision_id,
                    "lifecycle_state": revision.lifecycle_state.value,
                },
            )
        return revision

    async def _ingest_failure_result(
        self,
        record: DetectionPromotionRecord,
        *,
        message: str,
        resumed: bool,
        ingest_result: TypedIngestResult | None = None,
    ) -> DetectionPromotionResult:
        retry_count = await self._increment_ingest_retry_count(record.promotion_id)
        status = (
            DetectionPromotionStatus.DEAD
            if retry_count >= MAX_PROMOTION_INGEST_RETRIES
            else DetectionPromotionStatus.RETRY
        )
        failed = await self._mark_failed(
            record,
            reason_codes=[DetectionPromotionReasonCode.INGEST_FAILED],
            reason_message=message,
            status=status,
        )
        return DetectionPromotionResult(
            promotion_id=failed.promotion_id,
            status=failed.status,
            record=failed,
            ingest_result=ingest_result,
            resumed=resumed,
        )

    async def _increment_ingest_retry_count(self, promotion_id: str) -> int:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    DetectionPromotionORM,
                    promotion_id,
                    with_for_update=True,
                )
                if row is None:
                    raise ResourceNotFoundError(
                        "promotion ledger row not found",
                        details={"promotion_id": promotion_id},
                    )
                payload = dict(row.payload or {})
                count = int(payload.get(PAYLOAD_RETRY_COUNT_KEY, 0)) + 1
                payload[PAYLOAD_RETRY_COUNT_KEY] = count
                row.payload = payload
                return count

    async def _get_by_promotion_key(
        self,
        promotion_key: str,
    ) -> DetectionPromotionRecord | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(DetectionPromotionORM).where(
                    DetectionPromotionORM.promotion_key == promotion_key
                )
            )
            if row is None:
                return None
            return _row_to_record(row)

    async def _insert_ledger(self, record: DetectionPromotionRecord) -> DetectionPromotionRecord:
        orm_row = DetectionPromotionORM(
            promotion_id=record.promotion_id,
            tenant_id=record.tenant_id,
            promotion_key=record.promotion_key,
            status=record.status.value,
            decision_id=record.decision_id,
            candidate_detection_id=record.candidate_detection_id,
            candidate_content_hash=record.candidate_content_hash,
            package_id=record.package_id,
            package_version=record.package_version,
            package_content_hash=record.package_content_hash,
            detection_scope_id=record.detection_scope_id,
            scope_revision_id=record.scope_revision_id,
            derived_connector_id=record.derived_connector_id,
            source_record_id=record.source_record_id,
            event_id=record.event_id,
            link_revision=record.link_revision,
            ingest_result=(
                record.ingest_result.model_dump(mode="json") if record.ingest_result else None
            ),
            reason_codes=[code.value for code in record.reason_codes],
            reason_message=record.reason_message,
            payload={"schema_version": DETECTION_PROMOTION_SCHEMA_VERSION},
        )
        for _ in range(5):
            async with self._session_factory() as session:
                async with session.begin():
                    try:
                        session.add(orm_row)
                        await session.flush()
                        return record
                    except IntegrityError:
                        pass
            existing = await self._get_by_promotion_key(record.promotion_key)
            if existing is not None:
                return existing
        raise RuntimeError(
            f"detection promotion ledger insert lost race for key={record.promotion_key}"
        )

    async def _update_ledger(
        self,
        record: DetectionPromotionRecord,
        **updates: object,
    ) -> DetectionPromotionRecord:
        payload = record.model_dump()
        payload.update(updates)
        if isinstance(payload.get("status"), DetectionPromotionStatus):
            payload["status"] = payload["status"].value
        if isinstance(payload.get("ingest_result"), TypedIngestResult):
            payload["ingest_result"] = payload["ingest_result"].model_dump(mode="json")
        if payload.get("reason_codes"):
            payload["reason_codes"] = [
                code.value if hasattr(code, "value") else code for code in payload["reason_codes"]
            ]
        updated = DetectionPromotionRecord.model_validate(payload)
        updated = updated.model_copy(update={"updated_at": self._now()})
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    DetectionPromotionORM,
                    record.promotion_id,
                    with_for_update=True,
                )
                if row is None:
                    raise ResourceNotFoundError(
                        "promotion ledger row not found",
                        details={"promotion_id": record.promotion_id},
                    )
                row.status = updated.status.value
                row.derived_connector_id = updated.derived_connector_id
                row.source_record_id = updated.source_record_id
                row.event_id = updated.event_id
                row.link_revision = updated.link_revision
                row.ingest_result = (
                    updated.ingest_result.model_dump(mode="json")
                    if updated.ingest_result
                    else row.ingest_result
                )
                row.reason_codes = [code.value for code in updated.reason_codes]
                row.reason_message = updated.reason_message
        return updated

    async def _mark_failed(
        self,
        record: DetectionPromotionRecord,
        *,
        reason_codes: list[DetectionPromotionReasonCode],
        reason_message: str,
        status: DetectionPromotionStatus,
    ) -> DetectionPromotionRecord:
        return await self._update_ledger(
            record,
            status=status,
            reason_codes=reason_codes,
            reason_message=reason_message,
        )

    async def _allocate_promotion_id(self) -> str:
        async with self._session_factory() as session:
            for _ in range(8):
                promotion_id = f"dprom-{secrets.token_hex(4)}"
                existing = await session.get(DetectionPromotionORM, promotion_id)
                if existing is None:
                    return promotion_id
        raise RuntimeError("failed to allocate detection promotion_id")


def _row_to_record(row: DetectionPromotionORM) -> DetectionPromotionRecord:
    ingest = (
        TypedIngestResult.model_validate(row.ingest_result)
        if row.ingest_result is not None
        else None
    )
    return DetectionPromotionRecord(
        promotion_id=row.promotion_id,
        tenant_id=row.tenant_id,
        promotion_key=row.promotion_key,
        status=DetectionPromotionStatus(row.status),
        decision_id=row.decision_id,
        candidate_detection_id=row.candidate_detection_id,
        candidate_content_hash=row.candidate_content_hash,
        package_id=row.package_id,
        package_version=int(row.package_version),
        package_content_hash=row.package_content_hash,
        detection_scope_id=row.detection_scope_id,
        scope_revision_id=row.scope_revision_id,
        derived_connector_id=row.derived_connector_id,
        source_record_id=row.source_record_id,
        event_id=row.event_id,
        link_revision=int(row.link_revision),
        ingest_result=ingest,
        reason_codes=[DetectionPromotionReasonCode(code) for code in (row.reason_codes or [])],
        reason_message=row.reason_message or "",
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


DERIVED_DETECTION_SOURCE_TYPE = "derived_detection"
