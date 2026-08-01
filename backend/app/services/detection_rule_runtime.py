"""Shadow detection rule runtime executor (ISSUE-121 / #626)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.db import models as orm
from app.detection.operators import default_operator_registry
from app.detection.operators.base import OperatorExecutionContext
from app.models.behavior_observation import BehaviorObservation
from app.models.detection_rule import (
    CandidateDetection,
    CandidateDetectionListResult,
    CandidateDetectionProvenance,
    CandidateDetectionQuery,
    DetectionRuleDefinition,
    DetectionRulePackage,
    DetectionRuleRuntimeError,
    DetectionRuleRuntimeResult,
    DetectionRuleRuntimeState,
    RuleOperatorKind,
)
from app.models.feature_snapshot import DEFAULT_ALLOWED_LATENESS, FeatureSnapshot, FeatureWindowKind
from app.services.behavior_observation_service import row_to_behavior_observation
from app.services.detection_rule_resolver import (
    build_candidate_detection,
    build_runtime_error_id,
    ensure_utc,
)
from app.services.detection_rule_service import row_to_detection_rule_package
from app.services.feature_snapshot_resolver import (
    compute_window_bounds,
    dedupe_latest_snapshots_by_entity,
    effective_observation_upper_bound,
    row_to_feature_snapshot,
)

logger = logging.getLogger(__name__)


def row_to_candidate_detection(row: orm.CandidateDetection) -> CandidateDetection:
    return CandidateDetection(
        candidate_detection_id=row.candidate_detection_id,
        source_tenant_id=row.source_tenant_id,
        detection_scope_id=row.detection_scope_id,
        package_id=row.package_id,
        package_version=int(row.package_version),
        rule_id=row.rule_id,
        rule_version=int(row.rule_version),
        operator=RuleOperatorKind(row.operator),
        group_key=dict(row.group_key or {}),
        cutoff_at=row.cutoff_at,
        window_kind=row.window_kind,
        matched_value=float(row.matched_value),
        severity=row.severity,
        shadow_only=bool(row.shadow_only),
        provenance=CandidateDetectionProvenance.model_validate(row.provenance),
        content_hash=row.content_hash,
        idempotency_key=row.idempotency_key,
        schema_version=row.schema_version,
        created_at=row.created_at,
    )


class DetectionRuleRuntimeService:
    """Execute shadow_active packages — outputs candidate detections only."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._operators = default_operator_registry()

    async def _load_observations(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        window_start: datetime,
        upper_bound: datetime,
        max_scan: int,
    ) -> list[BehaviorObservation]:
        rows = list(
            await session.scalars(
                select(orm.BehaviorObservation)
                .where(
                    and_(
                        orm.BehaviorObservation.source_tenant_id == source_tenant_id,
                        orm.BehaviorObservation.detection_scope_id == detection_scope_id,
                        orm.BehaviorObservation.observed_at >= ensure_utc(window_start),
                        orm.BehaviorObservation.observed_at <= ensure_utc(upper_bound),
                    )
                )
                .order_by(orm.BehaviorObservation.observed_at.asc())
                .limit(max_scan + 1)
            )
        )
        if len(rows) > max_scan:
            raise ValidationError(
                "observation scan cost limit exceeded",
                details={"max_scan": max_scan, "found": len(rows)},
            )
        return [row_to_behavior_observation(row) for row in rows]

    async def _load_snapshots(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        entity_type: str | None,
        entity_id: str | None,
        window_kind: FeatureWindowKind,
        cutoff_at: datetime,
        max_scan: int,
    ) -> list[FeatureSnapshot]:
        filters = [
            orm.FeatureSnapshot.source_tenant_id == source_tenant_id,
            orm.FeatureSnapshot.detection_scope_id == detection_scope_id,
            orm.FeatureSnapshot.window_kind == window_kind.value,
            orm.FeatureSnapshot.cutoff_at == ensure_utc(cutoff_at),
        ]
        if entity_type is not None:
            filters.append(orm.FeatureSnapshot.entity_type == entity_type)
        if entity_id is not None:
            filters.append(orm.FeatureSnapshot.entity_id == entity_id)

        rows = list(
            await session.scalars(
                select(orm.FeatureSnapshot)
                .where(and_(*filters))
                .order_by(orm.FeatureSnapshot.revision.desc())
                .limit(max_scan + 1)
            )
        )
        if len(rows) > max_scan:
            raise ValidationError(
                "snapshot scan cost limit exceeded",
                details={"max_scan": max_scan, "found": len(rows)},
            )
        snapshots = [row_to_feature_snapshot(row) for row in rows]
        return dedupe_latest_snapshots_by_entity(snapshots)

    async def persist_candidate_in_session(
        self,
        session: AsyncSession,
        candidate: CandidateDetection,
    ) -> CandidateDetection:
        existing = await session.scalar(
            select(orm.CandidateDetection)
            .where(orm.CandidateDetection.idempotency_key == candidate.idempotency_key)
            .with_for_update()
        )
        if existing is not None:
            if existing.content_hash != candidate.content_hash:
                if existing.candidate_detection_id != candidate.candidate_detection_id:
                    raise ValidationError(
                        "candidate detection idempotency replay with different identity",
                        details={"idempotency_key": candidate.idempotency_key},
                    )
                existing.matched_value = candidate.matched_value
                existing.provenance = candidate.provenance.model_dump(mode="json")
                existing.content_hash = candidate.content_hash
                await session.flush()
                await session.refresh(existing)
                return row_to_candidate_detection(existing)
            return row_to_candidate_detection(existing)

        row = orm.CandidateDetection(
            candidate_detection_id=candidate.candidate_detection_id,
            source_tenant_id=candidate.source_tenant_id,
            detection_scope_id=candidate.detection_scope_id,
            package_id=candidate.package_id,
            package_version=candidate.package_version,
            rule_id=candidate.rule_id,
            rule_version=candidate.rule_version,
            operator=candidate.operator.value,
            group_key=candidate.group_key,
            cutoff_at=candidate.cutoff_at,
            window_kind=candidate.window_kind,
            matched_value=candidate.matched_value,
            severity=candidate.severity,
            shadow_only=candidate.shadow_only,
            provenance=candidate.provenance.model_dump(mode="json"),
            content_hash=candidate.content_hash,
            idempotency_key=candidate.idempotency_key,
            schema_version=candidate.schema_version,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(orm.CandidateDetection)
                .where(orm.CandidateDetection.idempotency_key == candidate.idempotency_key)
                .with_for_update()
            )
            if existing is None:
                raise
            if existing.content_hash != candidate.content_hash:
                if existing.candidate_detection_id != candidate.candidate_detection_id:
                    raise ValidationError(
                        "candidate detection idempotency replay with different identity",
                        details={"idempotency_key": candidate.idempotency_key},
                    ) from None
                existing.matched_value = candidate.matched_value
                existing.provenance = candidate.provenance.model_dump(mode="json")
                existing.content_hash = candidate.content_hash
                await session.flush()
                await session.refresh(existing)
                return row_to_candidate_detection(existing)
            return row_to_candidate_detection(existing)
        return row_to_candidate_detection(row)

    async def persist_runtime_error_in_session(
        self,
        session: AsyncSession,
        error: DetectionRuleRuntimeError,
    ) -> DetectionRuleRuntimeError:
        existing = await session.get(orm.DetectionRuleRuntimeError, error.error_id)
        if existing is not None:
            existing.error_message = error.error_message
            existing.detail = error.detail
            await session.flush()
            return DetectionRuleRuntimeError(
                error_id=existing.error_id,
                source_tenant_id=existing.source_tenant_id,
                package_id=existing.package_id,
                rule_id=existing.rule_id,
                error_category=existing.error_category,
                error_message=existing.error_message,
                detail=dict(existing.detail or {}),
                created_at=existing.created_at,
            )

        row = orm.DetectionRuleRuntimeError(
            error_id=error.error_id,
            source_tenant_id=error.source_tenant_id,
            package_id=error.package_id,
            rule_id=error.rule_id,
            error_category=error.error_category,
            error_message=error.error_message,
            detail=error.detail,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.get(orm.DetectionRuleRuntimeError, error.error_id)
            if existing is None:
                raise
            existing.error_message = error.error_message
            existing.detail = error.detail
            await session.flush()
            return DetectionRuleRuntimeError(
                error_id=existing.error_id,
                source_tenant_id=existing.source_tenant_id,
                package_id=existing.package_id,
                rule_id=existing.rule_id,
                error_category=existing.error_category,
                error_message=existing.error_message,
                detail=dict(existing.detail or {}),
                created_at=existing.created_at,
            )
        return error

    async def _evaluate_rule(
        self,
        session: AsyncSession,
        *,
        package: DetectionRulePackage,
        rule: DetectionRuleDefinition,
        cutoff_at: datetime,
    ) -> tuple[list[CandidateDetection], int, DetectionRuleRuntimeError | None]:
        window_kind = FeatureWindowKind(rule.window_kind)
        window_start, window_end = compute_window_bounds(
            cutoff_at=cutoff_at,
            window_kind=window_kind,
        )
        upper = effective_observation_upper_bound(
            window_end=window_end,
            cutoff_at=cutoff_at,
            allowed_lateness=DEFAULT_ALLOWED_LATENESS,
        )

        entity_type = rule.match_criteria.get("entity_type") if rule.match_criteria else None
        entity_id = rule.match_criteria.get("entity_id") if rule.match_criteria else None
        if not isinstance(entity_type, str):
            entity_type = None
        if not isinstance(entity_id, str):
            entity_id = None

        observations: list[BehaviorObservation] = []
        snapshots: list[FeatureSnapshot] = []
        scanned = 0

        if rule.operator in {RuleOperatorKind.EVENT_MATCH, RuleOperatorKind.EVENT_COUNT}:
            observations = await self._load_observations(
                session,
                source_tenant_id=package.source_tenant_id,
                detection_scope_id=rule.detection_scope_id,
                window_start=window_start,
                upper_bound=upper,
                max_scan=rule.max_observation_scan,
            )
            scanned = len(observations)
        else:
            snapshots = await self._load_snapshots(
                session,
                source_tenant_id=package.source_tenant_id,
                detection_scope_id=rule.detection_scope_id,
                entity_type=entity_type,
                entity_id=entity_id,
                window_kind=window_kind,
                cutoff_at=cutoff_at,
                max_scan=rule.max_observation_scan,
            )
            scanned = len(snapshots)

        operator = self._operators.get(rule.operator.value)
        matches = operator.evaluate(
            rule,
            OperatorExecutionContext(
                source_tenant_id=package.source_tenant_id,
                cutoff_at=cutoff_at,
                observations=observations,
                snapshots=snapshots,
                window_start=window_start,
                window_end=window_end,
            ),
        )

        candidates: list[CandidateDetection] = []
        for match in matches:
            candidates.append(
                build_candidate_detection(
                    source_tenant_id=package.source_tenant_id,
                    detection_scope_id=rule.detection_scope_id,
                    package=package,
                    rule=rule,
                    cutoff_at=cutoff_at,
                    group_key=match.group_key,
                    matched_value=match.matched_value,
                    provenance=CandidateDetectionProvenance(
                        observation_ids=match.observation_ids,
                        snapshot_ids=match.snapshot_ids,
                        window_start=match.window_start,
                        window_end=match.window_end,
                    ),
                )
            )
        return candidates, scanned, None

    async def _persist_rule_runtime_error(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        package: DetectionRulePackage,
        rule: DetectionRuleDefinition,
        cutoff_at: datetime,
        error_category: str,
        exc: Exception,
    ) -> DetectionRuleRuntimeError:
        detail: dict[str, object] = {}
        if isinstance(exc, ValidationError):
            detail = getattr(exc, "details", {}) or {}
        else:
            detail = {"exception_type": type(exc).__name__}
        runtime_error = DetectionRuleRuntimeError(
            error_id=build_runtime_error_id(
                source_tenant_id=source_tenant_id,
                package_id=package.package_id,
                rule_id=rule.rule_id,
                error_category=error_category,
                cutoff_at=cutoff_at,
            ),
            source_tenant_id=source_tenant_id,
            package_id=package.package_id,
            rule_id=rule.rule_id,
            error_category=error_category,
            error_message=str(exc),
            detail=detail,
            created_at=datetime.now(UTC),
        )
        return await self.persist_runtime_error_in_session(session, runtime_error)

    async def execute_shadow(
        self,
        *,
        source_tenant_id: str,
        cutoff_at: datetime,
        package_id: str | None = None,
    ) -> DetectionRuleRuntimeResult:
        async with self._session_factory() as session:
            async with session.begin():
                if package_id is not None:
                    row = await session.get(orm.DetectionRulePackage, package_id)
                    if row is None or row.source_tenant_id != source_tenant_id:
                        raise ValidationError(
                            "detection rule package not found for tenant",
                            details={
                                "package_id": package_id,
                                "source_tenant_id": source_tenant_id,
                            },
                        )
                    package = row_to_detection_rule_package(row)
                    if package.runtime_state is not DetectionRuleRuntimeState.SHADOW_ACTIVE:
                        raise ValidationError(
                            "detection rule package is not shadow_active",
                            details={
                                "package_id": package_id,
                                "runtime_state": package.runtime_state.value,
                            },
                        )
                    packages = [package]
                else:
                    rows = list(
                        await session.scalars(
                            select(orm.DetectionRulePackage).where(
                                and_(
                                    orm.DetectionRulePackage.source_tenant_id == source_tenant_id,
                                    orm.DetectionRulePackage.runtime_state
                                    == DetectionRuleRuntimeState.SHADOW_ACTIVE.value,
                                )
                            )
                        )
                    )
                    packages = [row_to_detection_rule_package(row) for row in rows]

                candidates: list[CandidateDetection] = []
                errors: list[DetectionRuleRuntimeError] = []
                rules_evaluated = 0
                observations_scanned = 0

                for package in packages:
                    if package.runtime_state is not DetectionRuleRuntimeState.SHADOW_ACTIVE:
                        continue
                    for rule in package.rules:
                        rules_evaluated += 1
                        try:
                            rule_candidates, scanned, _ = await self._evaluate_rule(
                                session,
                                package=package,
                                rule=rule,
                                cutoff_at=cutoff_at,
                            )
                            observations_scanned += scanned
                            for candidate in rule_candidates:
                                persisted = await self.persist_candidate_in_session(
                                    session,
                                    candidate,
                                )
                                candidates.append(persisted)
                        except ValidationError as exc:
                            errors.append(
                                await self._persist_rule_runtime_error(
                                    session,
                                    source_tenant_id=source_tenant_id,
                                    package=package,
                                    rule=rule,
                                    cutoff_at=cutoff_at,
                                    error_category="validation_error",
                                    exc=exc,
                                )
                            )
                        except Exception as exc:
                            logger.exception(
                                "detection rule evaluation failed",
                                extra={
                                    "package_id": package.package_id,
                                    "rule_id": rule.rule_id,
                                    "source_tenant_id": source_tenant_id,
                                },
                            )
                            errors.append(
                                await self._persist_rule_runtime_error(
                                    session,
                                    source_tenant_id=source_tenant_id,
                                    package=package,
                                    rule=rule,
                                    cutoff_at=cutoff_at,
                                    error_category="internal_error",
                                    exc=exc,
                                )
                            )

                return DetectionRuleRuntimeResult(
                    candidates=candidates,
                    errors=errors,
                    rules_evaluated=rules_evaluated,
                    observations_scanned=observations_scanned,
                )

    async def get_candidate(
        self,
        *,
        source_tenant_id: str,
        candidate_detection_id: str,
    ) -> CandidateDetection | None:
        async with self._session_factory() as session:
            row = await session.get(orm.CandidateDetection, candidate_detection_id)
            if row is None or row.source_tenant_id != source_tenant_id:
                return None
            return row_to_candidate_detection(row)

    async def query_candidates(
        self,
        query: CandidateDetectionQuery,
    ) -> CandidateDetectionListResult:
        filters = [orm.CandidateDetection.source_tenant_id == query.source_tenant_id]
        if query.detection_scope_id is not None:
            filters.append(orm.CandidateDetection.detection_scope_id == query.detection_scope_id)
        if query.package_id is not None:
            filters.append(orm.CandidateDetection.package_id == query.package_id)
        if query.rule_id is not None:
            filters.append(orm.CandidateDetection.rule_id == query.rule_id)

        async with self._session_factory() as session:
            total = await session.scalar(
                select(func.count()).select_from(orm.CandidateDetection).where(and_(*filters))
            )
            offset = (query.page - 1) * query.page_size
            rows = list(
                await session.scalars(
                    select(orm.CandidateDetection)
                    .where(and_(*filters))
                    .order_by(orm.CandidateDetection.cutoff_at.desc())
                    .offset(offset)
                    .limit(query.page_size)
                )
            )
        return CandidateDetectionListResult(
            total=int(total or 0),
            page=query.page,
            page_size=query.page_size,
            items=[row_to_candidate_detection(row) for row in rows],
        )
