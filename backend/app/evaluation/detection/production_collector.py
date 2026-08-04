"""Collect post-promotion signals for detection comparison (ISSUE-126 / #631 Phase B)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.orm.detection_promotion import DetectionPromotionORM
from app.models.detection_context_snapshot import (
    DetectionContextSnapshot,
    DetectionContextSnapshotQuery,
)
from app.models.detection_promotion import (
    DetectionPromotionRecord,
    DetectionPromotionStatus,
)
from app.services.detection_context_service import DetectionContextService


def _row_to_promotion_record(row: DetectionPromotionORM) -> DetectionPromotionRecord:
    ingest = None
    if row.ingest_result is not None:
        from app.models.detection_promotion import TypedIngestResult

        ingest = TypedIngestResult.model_validate(row.ingest_result)
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
        reason_codes=[code for code in (row.reason_codes or [])],
        reason_message=row.reason_message or "",
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def list_completed_promotions_by_candidate(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: str,
    candidate_detection_ids: set[str],
) -> dict[str, DetectionPromotionRecord]:
    if not candidate_detection_ids:
        return {}
    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(DetectionPromotionORM).where(
                    DetectionPromotionORM.tenant_id == tenant_id,
                    DetectionPromotionORM.status == DetectionPromotionStatus.COMPLETED.value,
                    DetectionPromotionORM.candidate_detection_id.in_(sorted(candidate_detection_ids)),
                )
            )
        )
    records = [_row_to_promotion_record(row) for row in rows]
    by_candidate: dict[str, DetectionPromotionRecord] = {}
    for record in records:
        existing = by_candidate.get(record.candidate_detection_id)
        record_updated_at = record.updated_at
        existing_updated_at = existing.updated_at if existing is not None else None
        if existing is None or (
            record_updated_at is not None
            and existing_updated_at is not None
            and record_updated_at > existing_updated_at
        ):
            by_candidate[record.candidate_detection_id] = record
    return by_candidate


async def load_latest_snapshot_for_promotion(
    context_service: DetectionContextService,
    *,
    tenant_id: str,
    promotion_id: str,
) -> DetectionContextSnapshot | None:
    result = await context_service.query_snapshots(
        DetectionContextSnapshotQuery(
            tenant_id=tenant_id,
            promotion_id=promotion_id,
            latest_only=True,
        )
    )
    if not result.items:
        return None
    return result.items[0]


async def load_snapshots_for_event(
    context_service: DetectionContextService,
    *,
    tenant_id: str,
    event_id: str,
) -> list[DetectionContextSnapshot]:
    result = await context_service.query_snapshots(
        DetectionContextSnapshotQuery(
            tenant_id=tenant_id,
            event_id=event_id,
            latest_only=False,
        )
    )
    return list(result.items)


__all__ = [
    "list_completed_promotions_by_candidate",
    "load_latest_snapshot_for_promotion",
    "load_snapshots_for_event",
]
