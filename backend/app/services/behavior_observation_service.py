"""BehaviorObservation persistence and retry (ISSUE-119 / #624)."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.models.behavior_observation import (
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationListResult,
    BehaviorObservationProjectionFailureListResult,
    BehaviorObservationProjectionFailureQuery,
    BehaviorObservationProjectionFailureRecord,
    BehaviorObservationProjectionStatus,
    BehaviorObservationProvenance,
    BehaviorObservationQuery,
    BehaviorObservationSourceRef,
)
from app.services.behavior_observation_resolver import (
    SCOPE_CONNECTOR_UNBOUND_ERROR,
    DetectionScopeBinding,
    build_behavior_observation,
    resolve_detection_scope_id,
)

logger = logging.getLogger(__name__)

_MAX_PROJECTION_ATTEMPTS = 5
_RETRY_BASE_SECONDS = 30


def _row_to_projection_failure(
    row: orm.BehaviorObservationProjectionFailure,
) -> BehaviorObservationProjectionFailureRecord:
    return BehaviorObservationProjectionFailureRecord(
        failure_id=row.failure_id,
        source_record_id=row.source_record_id,
        source_tenant_id=row.source_tenant_id,
        attempt=int(row.attempt),
        status=BehaviorObservationProjectionStatus(row.status),
        error_category=row.error_category,
        detail=dict(row.detail or {}),
        next_retry_at=row.next_retry_at,
        resolved_at=row.resolved_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _row_to_observation(row: orm.BehaviorObservation) -> BehaviorObservation:
    return BehaviorObservation(
        observation_id=row.observation_id,
        source_tenant_id=row.source_tenant_id,
        detection_scope_id=row.detection_scope_id,
        source_ref=BehaviorObservationSourceRef.model_validate(row.source_ref),
        observed_at=row.observed_at,
        ingested_at=row.ingested_at,
        entity_refs=[
            BehaviorEntityRef.model_validate(item)
            for item in (row.entity_refs or [])
            if isinstance(item, dict)
        ],
        action=row.action,
        category=row.category,
        normalized_attributes=dict(row.normalized_attributes or {}),
        detection_score=row.detection_score,
        schema_version=row.schema_version,
        projection_schema_version=row.projection_schema_version,
        content_hash=row.content_hash,
        observation_hash=row.observation_hash,
        idempotency_key=row.idempotency_key,
        provenance=BehaviorObservationProvenance.model_validate(row.provenance),
        supersedes_observation_id=row.supersedes_observation_id,
        created_at=row.created_at,
    )


def row_to_behavior_observation(row: orm.BehaviorObservation) -> BehaviorObservation:
    """Public ORM→contract mapper for cross-service reads (ISSUE-119 / #624)."""
    return _row_to_observation(row)


class BehaviorObservationService:
    """Append-only behavior observation store with idempotent upsert semantics."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _find_prior_observation_id(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        source_kind: str,
        source_object_id: str,
        source_revision: int,
    ) -> str | None:
        if source_revision <= 1:
            return None
        prior = await session.scalar(
            select(orm.BehaviorObservation.observation_id)
            .where(
                and_(
                    orm.BehaviorObservation.source_tenant_id == source_tenant_id,
                    orm.BehaviorObservation.detection_scope_id == detection_scope_id,
                    orm.BehaviorObservation.source_kind == source_kind,
                    orm.BehaviorObservation.source_object_id == source_object_id,
                    orm.BehaviorObservation.source_revision == source_revision - 1,
                )
            )
            .order_by(orm.BehaviorObservation.created_at.desc())
            .limit(1)
        )
        return prior

    async def persist_in_session(
        self,
        session: AsyncSession,
        observation: BehaviorObservation,
    ) -> BehaviorObservation:
        existing = await session.scalar(
            select(orm.BehaviorObservation).where(
                orm.BehaviorObservation.idempotency_key == observation.idempotency_key
            )
        )
        if existing is not None:
            if existing.observation_hash != observation.observation_hash:
                raise ValidationError(
                    "behavior observation idempotency replay with different content hash",
                    details={"idempotency_key": observation.idempotency_key},
                )
            return _row_to_observation(existing)

        row = orm.BehaviorObservation(
            observation_id=observation.observation_id,
            source_tenant_id=observation.source_tenant_id,
            detection_scope_id=observation.detection_scope_id,
            source_product=observation.source_ref.source_product,
            connector_id=observation.source_ref.connector_id,
            source_kind=observation.source_ref.source_kind,
            source_object_id=observation.source_ref.source_object_id,
            source_object_type=observation.source_ref.source_object_type,
            source_revision=observation.source_ref.source_revision,
            source_ref=observation.source_ref.model_dump(mode="json"),
            observed_at=observation.observed_at,
            ingested_at=observation.ingested_at,
            entity_refs=[item.model_dump(mode="json") for item in observation.entity_refs],
            action=observation.action,
            category=observation.category,
            normalized_attributes=observation.normalized_attributes,
            detection_score=observation.detection_score,
            schema_version=observation.schema_version,
            projection_schema_version=observation.projection_schema_version,
            content_hash=observation.content_hash,
            observation_hash=observation.observation_hash,
            idempotency_key=observation.idempotency_key,
            provenance=observation.provenance.model_dump(mode="json"),
            supersedes_observation_id=observation.supersedes_observation_id,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(orm.BehaviorObservation).where(
                    orm.BehaviorObservation.idempotency_key == observation.idempotency_key
                )
            )
            if existing is None:
                raise
            if existing.observation_hash != observation.observation_hash:
                raise ValidationError(
                    "behavior observation idempotency replay with different content hash",
                    details={"idempotency_key": observation.idempotency_key},
                ) from None
            return _row_to_observation(existing)
        return _row_to_observation(row)

    async def project_source_object(
        self,
        source_record_id: str,
        *,
        session: AsyncSession | None = None,
    ) -> BehaviorObservation | None:
        async def _run(active_session: AsyncSession) -> BehaviorObservation | None:
            row = await active_session.get(orm.SourceObject, source_record_id)
            if row is None:
                raise ResourceNotFoundError(
                    "source object not found for behavior observation projection",
                    details={"source_record_id": source_record_id},
                )
            binding = await resolve_detection_scope_id(
                active_session,
                source_tenant_id=row.source_tenant_id,
                source_product=row.source_product,
                connector_id=row.connector_id,
            )
            supersedes = await self._find_prior_observation_id(
                active_session,
                source_tenant_id=row.source_tenant_id,
                detection_scope_id=binding.detection_scope_id,
                source_kind=row.source_kind,
                source_object_id=row.source_object_id,
                source_revision=int(row.current_state_version),
            )
            observation = build_behavior_observation(
                row=row,
                detection_scope_id=binding.detection_scope_id,
                supersedes_observation_id=supersedes,
                scope_binding_unverified=binding.scope_binding_unverified,
            )
            persisted = await self.persist_in_session(active_session, observation)
            if binding.scope_binding_unverified:
                await self._record_scope_connector_unbound_quality(
                    active_session,
                    source_record_id=row.source_record_id,
                    source_tenant_id=row.source_tenant_id,
                    connector_id=row.connector_id,
                    binding=binding,
                )
            else:
                await self._resolve_scope_connector_unbound_quality(
                    active_session,
                    source_record_id=row.source_record_id,
                    verified_observation_id=persisted.observation_id,
                    verified_detection_scope_id=binding.detection_scope_id,
                )
            await self._resolve_failure(active_session, source_record_id=source_record_id)
            return persisted

        if session is not None:
            return await _run(session)
        async with self._session_factory() as owned_session:
            async with owned_session.begin():
                return await _run(owned_session)

    async def _record_scope_connector_unbound_quality(
        self,
        session: AsyncSession,
        *,
        source_record_id: str,
        source_tenant_id: str,
        connector_id: str,
        binding: DetectionScopeBinding,
    ) -> None:
        """Observability marker when projection used unverified metadata fallback (ISSUE-157)."""
        detail = {
            "source_record_id": source_record_id,
            "source_tenant_id": source_tenant_id,
            "connector_id": connector_id,
            "integration_instance_id": binding.integration_instance_id,
            "active_detection_scope_ids": list(binding.active_scope_ids),
            "fallback_detection_scope_id": binding.detection_scope_id,
            "verified_detection_scope_id": None,
            "binding_status": "unverified_fallback",
            "fallback_equals_active_scope_id": (
                binding.detection_scope_id in binding.active_scope_ids
            ),
            "scope_binding_unverified": True,
            "runbook": (
                "Add connector to ACTIVE DetectionScope connector_set, then retry projection"
            ),
        }
        existing = await session.scalar(
            select(orm.DataQualityError)
            .where(
                and_(
                    orm.DataQualityError.stage == "behavior_observation_projection",
                    orm.DataQualityError.error_category == SCOPE_CONNECTOR_UNBOUND_ERROR,
                    orm.DataQualityError.detail["source_record_id"].as_string() == source_record_id,
                )
            )
            .limit(1)
        )
        if existing is not None:
            existing.detail = detail
            return
        session.add(
            orm.DataQualityError(
                event_id=None,
                stage="behavior_observation_projection",
                error_category=SCOPE_CONNECTOR_UNBOUND_ERROR,
                detail=detail,
            )
        )

    async def _resolve_scope_connector_unbound_quality(
        self,
        session: AsyncSession,
        *,
        source_record_id: str,
        verified_observation_id: str,
        verified_detection_scope_id: str,
    ) -> None:
        """Mark prior unbound scope quality marker resolved after verified binding."""
        existing = await session.scalar(
            select(orm.DataQualityError)
            .where(
                and_(
                    orm.DataQualityError.stage == "behavior_observation_projection",
                    orm.DataQualityError.error_category == SCOPE_CONNECTOR_UNBOUND_ERROR,
                    orm.DataQualityError.detail["source_record_id"].as_string() == source_record_id,
                )
            )
            .limit(1)
        )
        if existing is None:
            return
        detail = dict(existing.detail or {})
        detail.update(
            {
                "binding_status": "verified",
                "scope_binding_unverified": False,
                "verified_detection_scope_id": verified_detection_scope_id,
                "resolved_by_observation_id": verified_observation_id,
                "resolved_at": datetime.now(UTC).isoformat(),
            }
        )
        existing.detail = detail

    async def record_projection_failure(
        self,
        *,
        source_record_id: str,
        source_tenant_id: str,
        error_category: str,
        detail: dict[str, object],
        session: AsyncSession | None = None,
        force_dead_letter: bool = False,
    ) -> None:
        now = datetime.now(UTC)

        async def _run(active_session: AsyncSession) -> None:
            existing = await active_session.scalar(
                select(orm.BehaviorObservationProjectionFailure)
                .where(
                    and_(
                        orm.BehaviorObservationProjectionFailure.source_record_id
                        == source_record_id,
                        orm.BehaviorObservationProjectionFailure.status
                        != BehaviorObservationProjectionStatus.RESOLVED.value,
                    )
                )
                .order_by(orm.BehaviorObservationProjectionFailure.created_at.desc())
                .limit(1)
            )
            attempt = 1 if existing is None else int(existing.attempt) + 1
            if force_dead_letter:
                attempt = _MAX_PROJECTION_ATTEMPTS
            status = (
                BehaviorObservationProjectionStatus.DEAD_LETTER.value
                if attempt >= _MAX_PROJECTION_ATTEMPTS
                else BehaviorObservationProjectionStatus.PENDING_RETRY.value
            )
            next_retry_at = (
                None
                if status == BehaviorObservationProjectionStatus.DEAD_LETTER.value
                else now + timedelta(seconds=_RETRY_BASE_SECONDS * attempt)
            )
            prior_status = existing.status if existing is not None else None
            if existing is not None:
                existing.attempt = attempt
                existing.status = status
                existing.error_category = error_category
                existing.detail = dict(detail)
                existing.next_retry_at = next_retry_at
                existing.updated_at = now
            else:
                active_session.add(
                    orm.BehaviorObservationProjectionFailure(
                        failure_id=f"bobs-fail-{secrets.token_hex(8)}",
                        source_record_id=source_record_id,
                        source_tenant_id=source_tenant_id,
                        attempt=attempt,
                        status=status,
                        error_category=error_category,
                        detail=dict(detail),
                        next_retry_at=next_retry_at,
                    )
                )
            if prior_status is None or prior_status != status:
                active_session.add(
                    orm.DataQualityError(
                        event_id=None,
                        stage="behavior_observation_projection",
                        error_category=error_category,
                        detail={
                            "source_record_id": source_record_id,
                            "source_tenant_id": source_tenant_id,
                            "attempt": attempt,
                            "status": status,
                            **detail,
                        },
                    )
                )

        if session is not None:
            await _run(session)
            return
        async with self._session_factory() as owned_session:
            async with owned_session.begin():
                await _run(owned_session)

    async def _resolve_failure(
        self,
        session: AsyncSession,
        *,
        source_record_id: str,
    ) -> None:
        rows = await session.scalars(
            select(orm.BehaviorObservationProjectionFailure).where(
                and_(
                    orm.BehaviorObservationProjectionFailure.source_record_id == source_record_id,
                    orm.BehaviorObservationProjectionFailure.status.in_(
                        [
                            BehaviorObservationProjectionStatus.PENDING_RETRY.value,
                            BehaviorObservationProjectionStatus.DEAD_LETTER.value,
                        ]
                    ),
                )
            )
        )
        now = datetime.now(UTC)
        for row in rows:
            row.status = BehaviorObservationProjectionStatus.RESOLVED.value
            row.resolved_at = now

    async def retry_pending(self, *, limit: int = 50) -> int:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            failures = list(
                await session.scalars(
                    select(orm.BehaviorObservationProjectionFailure)
                    .where(
                        and_(
                            orm.BehaviorObservationProjectionFailure.status
                            == BehaviorObservationProjectionStatus.PENDING_RETRY.value,
                            orm.BehaviorObservationProjectionFailure.next_retry_at <= now,
                        )
                    )
                    .order_by(orm.BehaviorObservationProjectionFailure.next_retry_at.asc())
                    .limit(limit)
                )
            )
        retried = 0
        seen_source_records: set[str] = set()
        for failure in failures:
            if failure.source_record_id in seen_source_records:
                continue
            seen_source_records.add(failure.source_record_id)
            try:
                await self.project_source_object(failure.source_record_id)
                retried += 1
            except ValidationError as exc:
                await self.record_projection_failure(
                    source_record_id=failure.source_record_id,
                    source_tenant_id=failure.source_tenant_id,
                    error_category="projection_non_retryable",
                    detail={
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "prior_failure_id": failure.failure_id,
                    },
                    force_dead_letter=True,
                )
            except Exception as exc:  # noqa: BLE001 — record and continue
                await self.record_projection_failure(
                    source_record_id=failure.source_record_id,
                    source_tenant_id=failure.source_tenant_id,
                    error_category="projection_retry_failed",
                    detail={
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "prior_failure_id": failure.failure_id,
                    },
                )
        return retried

    async def get_observation(self, observation_id: str) -> BehaviorObservation | None:
        async with self._session_factory() as session:
            row = await session.get(orm.BehaviorObservation, observation_id)
            if row is None:
                return None
            return _row_to_observation(row)

    async def query_observations(
        self,
        query: BehaviorObservationQuery,
    ) -> BehaviorObservationListResult:
        filters = [orm.BehaviorObservation.source_tenant_id == query.source_tenant_id]
        if query.detection_scope_id is not None:
            filters.append(orm.BehaviorObservation.detection_scope_id == query.detection_scope_id)
        if query.connector_id is not None:
            filters.append(orm.BehaviorObservation.connector_id == query.connector_id)
        if query.source_kind is not None:
            filters.append(orm.BehaviorObservation.source_kind == query.source_kind)
        if query.source_object_id is not None:
            filters.append(orm.BehaviorObservation.source_object_id == query.source_object_id)

        async with self._session_factory() as session:
            total = int(
                await session.scalar(
                    select(func.count()).select_from(orm.BehaviorObservation).where(*filters)
                )
                or 0
            )
            rows = await session.scalars(
                select(orm.BehaviorObservation)
                .where(*filters)
                .order_by(
                    orm.BehaviorObservation.observed_at.desc(),
                    orm.BehaviorObservation.observation_id.desc(),
                )
                .offset((query.page - 1) * query.page_size)
                .limit(query.page_size)
            )
            items = [_row_to_observation(row) for row in rows]
            return BehaviorObservationListResult(
                total=total,
                page=query.page,
                page_size=query.page_size,
                items=items,
            )

    async def query_projection_failures(
        self,
        query: BehaviorObservationProjectionFailureQuery,
    ) -> BehaviorObservationProjectionFailureListResult:
        filters = [
            orm.BehaviorObservationProjectionFailure.source_tenant_id == query.source_tenant_id,
        ]
        if query.status is not None:
            filters.append(orm.BehaviorObservationProjectionFailure.status == query.status.value)
        else:
            filters.append(
                orm.BehaviorObservationProjectionFailure.status.in_(
                    [
                        BehaviorObservationProjectionStatus.PENDING_RETRY.value,
                        BehaviorObservationProjectionStatus.DEAD_LETTER.value,
                    ]
                )
            )

        async with self._session_factory() as session:
            total = int(
                await session.scalar(
                    select(func.count())
                    .select_from(orm.BehaviorObservationProjectionFailure)
                    .where(*filters)
                )
                or 0
            )
            rows = await session.scalars(
                select(orm.BehaviorObservationProjectionFailure)
                .where(*filters)
                .order_by(
                    orm.BehaviorObservationProjectionFailure.updated_at.desc(),
                    orm.BehaviorObservationProjectionFailure.failure_id.desc(),
                )
                .offset((query.page - 1) * query.page_size)
                .limit(query.page_size)
            )
            items = [_row_to_projection_failure(row) for row in rows]
            return BehaviorObservationProjectionFailureListResult(
                total=total,
                page=query.page,
                page_size=query.page_size,
                items=items,
            )
