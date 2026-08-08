"""DetectionScopeRevision persistence — canonical scope contract (ISSUE-120 Phase 0)."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.models.detection_scope import (
    DetectionScopeConnectorSet,
    DetectionScopeIdentity,
    DetectionScopeLifecycleState,
    DetectionScopeListResult,
    DetectionScopeQuery,
    DetectionScopeRevision,
    UpstreamConnectorMember,
)
from app.services.detection_scope_resolver import (
    build_detection_scope_revision,
    compute_connector_set_hash,
    compute_scope_content_hash,
    normalize_upstream_connector_set,
)

logger = logging.getLogger(__name__)


def _row_to_revision(row: orm.DetectionScopeRevision) -> DetectionScopeRevision:
    connector_set = DetectionScopeConnectorSet.model_validate(row.connector_set)
    identity = DetectionScopeIdentity(
        source_tenant_id=row.source_tenant_id,
        source_product=row.source_product,
        integration_instance_id=row.integration_instance_id,
        environment=row.environment,
        region=row.region,
    )
    return DetectionScopeRevision(
        scope_revision_id=row.scope_revision_id,
        detection_scope_id=row.detection_scope_id,
        identity=identity,
        connector_set=connector_set,
        lifecycle_state=DetectionScopeLifecycleState(row.lifecycle_state),
        revision=int(row.revision),
        supersedes_scope_revision_id=row.supersedes_scope_revision_id,
        content_hash=row.content_hash,
        identity_hash=row.identity_hash,
        idempotency_key=row.idempotency_key,
        schema_version=row.schema_version,
        activated_at=row.activated_at,
        retired_at=row.retired_at,
        created_at=row.created_at,
    )


def _integration_boundary_filters(row: orm.DetectionScopeRevision) -> tuple[Any, ...]:
    return (
        orm.DetectionScopeRevision.source_tenant_id == row.source_tenant_id,
        orm.DetectionScopeRevision.source_product == row.source_product,
        orm.DetectionScopeRevision.integration_instance_id == row.integration_instance_id,
    )


def _identity_boundary_filters(identity: DetectionScopeIdentity) -> tuple[Any, ...]:
    return (
        orm.DetectionScopeRevision.source_tenant_id == identity.source_tenant_id,
        orm.DetectionScopeRevision.source_product == identity.source_product,
        orm.DetectionScopeRevision.integration_instance_id == identity.integration_instance_id,
    )


def _integration_advisory_lock_key(row: orm.DetectionScopeRevision) -> int:
    material = (
        f"{row.source_tenant_id}|{row.source_product}|{row.integration_instance_id}"
    ).encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], byteorder="big", signed=True)


def _identity_from_row(row: orm.DetectionScopeRevision) -> DetectionScopeIdentity:
    return DetectionScopeIdentity(
        source_tenant_id=row.source_tenant_id,
        source_product=row.source_product,
        integration_instance_id=row.integration_instance_id,
        environment=row.environment,
        region=row.region,
    )


def _content_hash_for_row(
    row: orm.DetectionScopeRevision,
    *,
    lifecycle_state: DetectionScopeLifecycleState,
) -> str:
    identity = _identity_from_row(row)
    body = {
        "detection_scope_id": row.detection_scope_id,
        "identity": identity.model_dump(mode="json"),
        "connector_set": row.connector_set,
        "lifecycle_state": lifecycle_state.value,
        "revision": int(row.revision),
        "schema_version": row.schema_version,
    }
    return compute_scope_content_hash(body)


def _apply_lifecycle_state(
    row: orm.DetectionScopeRevision,
    *,
    lifecycle_state: DetectionScopeLifecycleState,
    now: datetime,
) -> None:
    row.lifecycle_state = lifecycle_state.value
    row.content_hash = _content_hash_for_row(row, lifecycle_state=lifecycle_state)
    if lifecycle_state is DetectionScopeLifecycleState.ACTIVE:
        row.activated_at = now
        row.retired_at = None
    elif lifecycle_state is DetectionScopeLifecycleState.RETIRED:
        row.retired_at = now


class DetectionScopeService:
    """Append-only scope revision store with activation/retirement lifecycle."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _validate_supersedes(
        self,
        session: AsyncSession,
        *,
        identity: DetectionScopeIdentity,
        supersedes_scope_revision_id: str | None,
    ) -> None:
        if supersedes_scope_revision_id is None:
            return
        prior = await session.get(orm.DetectionScopeRevision, supersedes_scope_revision_id)
        if prior is None:
            raise ValidationError(
                "supersedes_scope_revision_id not found",
                details={"supersedes_scope_revision_id": supersedes_scope_revision_id},
            )
        if prior.source_tenant_id != identity.source_tenant_id:
            raise ValidationError(
                "supersedes revision tenant mismatch",
                details={"supersedes_scope_revision_id": supersedes_scope_revision_id},
            )
        if prior.source_product != identity.source_product:
            raise ValidationError(
                "supersedes revision source_product mismatch",
                details={"supersedes_scope_revision_id": supersedes_scope_revision_id},
            )
        if prior.integration_instance_id != identity.integration_instance_id:
            raise ValidationError(
                "supersedes revision integration_instance_id mismatch",
                details={"supersedes_scope_revision_id": supersedes_scope_revision_id},
            )

    async def _validate_connector_set_version_consistency(
        self,
        session: AsyncSession,
        *,
        identity: DetectionScopeIdentity,
        connector_set_version: int,
        connector_set_hash: str,
    ) -> None:
        existing_row = await session.scalar(
            select(orm.DetectionScopeRevision)
            .where(
                and_(
                    *_identity_boundary_filters(identity),
                    orm.DetectionScopeRevision.connector_set_version == connector_set_version,
                )
            )
            .limit(1)
        )
        if existing_row is None:
            return
        existing_set = DetectionScopeConnectorSet.model_validate(existing_row.connector_set)
        existing_hash = compute_connector_set_hash(existing_set)
        if existing_hash != connector_set_hash:
            raise ValidationError(
                "connector membership drift at same connector_set_version; bump version",
                details={
                    "connector_set_version": connector_set_version,
                    "integration_instance_id": identity.integration_instance_id,
                },
            )

    async def register_revision(
        self,
        *,
        identity: DetectionScopeIdentity,
        connector_set_version: int,
        upstream_connectors: list[UpstreamConnectorMember],
        revision: int = 1,
        supersedes_scope_revision_id: str | None = None,
    ) -> DetectionScopeRevision:
        normalized = normalize_upstream_connector_set(
            connector_set_version=connector_set_version,
            upstream_connectors=upstream_connectors,
        )
        scope_revision = build_detection_scope_revision(
            identity=identity,
            connector_set=normalized,
            revision=revision,
            lifecycle_state=DetectionScopeLifecycleState.DRAFT,
            supersedes_scope_revision_id=supersedes_scope_revision_id,
        )
        row = orm.DetectionScopeRevision(
            scope_revision_id=scope_revision.scope_revision_id,
            detection_scope_id=scope_revision.detection_scope_id,
            source_tenant_id=identity.source_tenant_id,
            source_product=identity.source_product,
            integration_instance_id=identity.integration_instance_id,
            environment=identity.environment,
            region=identity.region,
            connector_set=scope_revision.connector_set.model_dump(mode="json"),
            connector_set_version=normalized.connector_set_version,
            lifecycle_state=DetectionScopeLifecycleState.DRAFT.value,
            revision=scope_revision.revision,
            supersedes_scope_revision_id=supersedes_scope_revision_id,
            content_hash=scope_revision.content_hash,
            identity_hash=scope_revision.identity_hash,
            idempotency_key=scope_revision.idempotency_key,
            schema_version=scope_revision.schema_version,
            activated_at=None,
            retired_at=None,
        )
        connector_set_hash = compute_connector_set_hash(normalized)
        async with self._session_factory() as session:
            async with session.begin():
                await self._validate_supersedes(
                    session,
                    identity=identity,
                    supersedes_scope_revision_id=supersedes_scope_revision_id,
                )
                await self._validate_connector_set_version_consistency(
                    session,
                    identity=identity,
                    connector_set_version=normalized.connector_set_version,
                    connector_set_hash=connector_set_hash,
                )
                session.add(row)
                try:
                    await session.flush()
                except IntegrityError as exc:
                    raise ValidationError(
                        "detection scope revision already exists",
                        details={"idempotency_key": scope_revision.idempotency_key},
                    ) from exc
                await session.refresh(row)
                return _row_to_revision(row)

    async def activate_revision(self, scope_revision_id: str) -> DetectionScopeRevision:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.DetectionScopeRevision,
                    scope_revision_id,
                    with_for_update=True,
                )
                if row is None:
                    raise ResourceNotFoundError(
                        "detection scope revision not found",
                        details={"scope_revision_id": scope_revision_id},
                    )
                if row.lifecycle_state == DetectionScopeLifecycleState.RETIRED.value:
                    raise ValidationError(
                        "cannot activate a retired detection scope revision",
                        details={"scope_revision_id": scope_revision_id},
                    )
                if row.lifecycle_state == DetectionScopeLifecycleState.ACTIVE.value:
                    await session.refresh(row)
                    return _row_to_revision(row)

                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {"lock_key": _integration_advisory_lock_key(row)},
                )

                prior_active = list(
                    await session.scalars(
                        select(orm.DetectionScopeRevision)
                        .where(
                            and_(
                                *_integration_boundary_filters(row),
                                orm.DetectionScopeRevision.lifecycle_state
                                == DetectionScopeLifecycleState.ACTIVE.value,
                                orm.DetectionScopeRevision.scope_revision_id != scope_revision_id,
                            )
                        )
                        .with_for_update()
                    )
                )
                for active in prior_active:
                    _apply_lifecycle_state(
                        active,
                        lifecycle_state=DetectionScopeLifecycleState.RETIRED,
                        now=now,
                    )
                if prior_active:
                    await session.flush()
                _apply_lifecycle_state(
                    row,
                    lifecycle_state=DetectionScopeLifecycleState.ACTIVE,
                    now=now,
                )
                await session.flush()
                await session.refresh(row)
                return _row_to_revision(row)

    async def retire_revision(self, scope_revision_id: str) -> DetectionScopeRevision:
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.DetectionScopeRevision,
                    scope_revision_id,
                    with_for_update=True,
                )
                if row is None:
                    raise ResourceNotFoundError(
                        "detection scope revision not found",
                        details={"scope_revision_id": scope_revision_id},
                    )
                if row.lifecycle_state == DetectionScopeLifecycleState.RETIRED.value:
                    await session.refresh(row)
                    return _row_to_revision(row)
                _apply_lifecycle_state(
                    row,
                    lifecycle_state=DetectionScopeLifecycleState.RETIRED,
                    now=now,
                )
                await session.flush()
                await session.refresh(row)
                return _row_to_revision(row)

    async def get_revision(self, scope_revision_id: str) -> DetectionScopeRevision | None:
        async with self._session_factory() as session:
            row = await session.get(orm.DetectionScopeRevision, scope_revision_id)
            if row is None:
                return None
            return _row_to_revision(row)

    async def get_active_revision(
        self,
        *,
        detection_scope_id: str,
    ) -> DetectionScopeRevision | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.DetectionScopeRevision)
                .where(
                    and_(
                        orm.DetectionScopeRevision.detection_scope_id == detection_scope_id,
                        orm.DetectionScopeRevision.lifecycle_state
                        == DetectionScopeLifecycleState.ACTIVE.value,
                    )
                )
                .order_by(orm.DetectionScopeRevision.revision.desc())
                .limit(1)
            )
            if row is None:
                return None
            return _row_to_revision(row)

    async def get_active_revision_for_instance(
        self,
        *,
        source_tenant_id: str,
        source_product: str,
        integration_instance_id: str,
    ) -> DetectionScopeRevision | None:
        """Return the single active scope revision for an upstream integration instance."""
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.DetectionScopeRevision)
                .where(
                    and_(
                        orm.DetectionScopeRevision.source_tenant_id == source_tenant_id,
                        orm.DetectionScopeRevision.source_product == source_product,
                        orm.DetectionScopeRevision.integration_instance_id
                        == integration_instance_id,
                        orm.DetectionScopeRevision.lifecycle_state
                        == DetectionScopeLifecycleState.ACTIVE.value,
                    )
                )
                .order_by(
                    orm.DetectionScopeRevision.connector_set_version.desc(),
                    orm.DetectionScopeRevision.revision.desc(),
                )
                .limit(1)
            )
            if row is None:
                return None
            return _row_to_revision(row)

    async def query_revisions(self, query: DetectionScopeQuery) -> DetectionScopeListResult:
        filters = [orm.DetectionScopeRevision.source_tenant_id == query.source_tenant_id]
        if query.source_product is not None:
            filters.append(orm.DetectionScopeRevision.source_product == query.source_product)
        if query.integration_instance_id is not None:
            filters.append(
                orm.DetectionScopeRevision.integration_instance_id == query.integration_instance_id
            )
        if query.detection_scope_id is not None:
            filters.append(
                orm.DetectionScopeRevision.detection_scope_id == query.detection_scope_id
            )
        if query.lifecycle_state is not None:
            filters.append(
                orm.DetectionScopeRevision.lifecycle_state == query.lifecycle_state.value
            )

        async with self._session_factory() as session:
            if query.latest_revision_only:
                ranked = (
                    select(
                        orm.DetectionScopeRevision.scope_revision_id.label("scope_revision_id"),
                        func.row_number()
                        .over(
                            partition_by=orm.DetectionScopeRevision.detection_scope_id,
                            order_by=orm.DetectionScopeRevision.revision.desc(),
                        )
                        .label("rn"),
                    )
                    .where(*filters)
                    .subquery()
                )
                latest_ids = (
                    select(ranked.c.scope_revision_id)
                    .where(ranked.c.rn == 1)
                    .order_by(ranked.c.scope_revision_id)
                )
                total = int(
                    await session.scalar(select(func.count()).select_from(latest_ids.subquery()))
                    or 0
                )
                page_ids = await session.scalars(
                    latest_ids.offset((query.page - 1) * query.page_size).limit(query.page_size)
                )
                revision_ids = list(page_ids)
                if not revision_ids:
                    return DetectionScopeListResult(
                        total=total,
                        page=query.page,
                        page_size=query.page_size,
                        items=[],
                    )
                rows = await session.scalars(
                    select(orm.DetectionScopeRevision)
                    .where(orm.DetectionScopeRevision.scope_revision_id.in_(revision_ids))
                    .order_by(orm.DetectionScopeRevision.detection_scope_id.asc())
                )
                items = [_row_to_revision(row) for row in rows]
                return DetectionScopeListResult(
                    total=total,
                    page=query.page,
                    page_size=query.page_size,
                    items=items,
                )

            total = int(
                await session.scalar(
                    select(func.count()).select_from(orm.DetectionScopeRevision).where(*filters)
                )
                or 0
            )
            rows = await session.scalars(
                select(orm.DetectionScopeRevision)
                .where(*filters)
                .order_by(
                    orm.DetectionScopeRevision.detection_scope_id.asc(),
                    orm.DetectionScopeRevision.revision.desc(),
                )
                .offset((query.page - 1) * query.page_size)
                .limit(query.page_size)
            )
            items = [_row_to_revision(row) for row in rows]
            return DetectionScopeListResult(
                total=total,
                page=query.page,
                page_size=query.page_size,
                items=items,
            )
