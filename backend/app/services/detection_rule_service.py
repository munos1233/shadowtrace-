"""Detection rule package persistence and lifecycle (ISSUE-121 / #626)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.models.detection_rule import (
    DetectionRuleDefinition,
    DetectionRulePackage,
    DetectionRulePackageListResult,
    DetectionRulePackageProvenance,
    DetectionRulePackageQuery,
    DetectionRuleRuntimeState,
)
from app.models.detection_scope import DetectionScopeLifecycleState
from app.services.detection_rule_resolver import (
    allowed_runtime_transition,
    compile_rule_package,
)

logger = logging.getLogger(__name__)


def row_to_detection_rule_package(row: orm.DetectionRulePackage) -> DetectionRulePackage:
    return DetectionRulePackage(
        package_id=row.package_id,
        source_tenant_id=row.source_tenant_id,
        package_version=int(row.package_version),
        runtime_state=DetectionRuleRuntimeState(row.runtime_state),
        rules=[DetectionRuleDefinition.model_validate(item) for item in (row.rules or [])],
        provenance=DetectionRulePackageProvenance.model_validate(row.provenance),
        content_hash=row.content_hash,
        idempotency_key=row.idempotency_key,
        schema_version=row.schema_version,
        supersedes_package_id=row.supersedes_package_id,
        created_at=row.created_at,
    )


async def _validate_active_scopes_for_rules(
    session: AsyncSession,
    *,
    source_tenant_id: str,
    rules: list[DetectionRuleDefinition],
) -> None:
    seen_scope_ids: set[str] = set()
    for rule in rules:
        if rule.detection_scope_id in seen_scope_ids:
            continue
        seen_scope_ids.add(rule.detection_scope_id)
        row = await session.scalar(
            select(orm.DetectionScopeRevision)
            .where(
                and_(
                    orm.DetectionScopeRevision.detection_scope_id == rule.detection_scope_id,
                    orm.DetectionScopeRevision.source_tenant_id == source_tenant_id,
                    orm.DetectionScopeRevision.lifecycle_state
                    == DetectionScopeLifecycleState.ACTIVE.value,
                )
            )
            .limit(1)
        )
        if row is None:
            raise ValidationError(
                "detection scope not active for tenant",
                details={
                    "detection_scope_id": rule.detection_scope_id,
                    "source_tenant_id": source_tenant_id,
                },
            )


class DetectionRuleService:
    """Append-only rule package store with compile/validate lifecycle transitions."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def persist_in_session(
        self,
        session: AsyncSession,
        package: DetectionRulePackage,
    ) -> DetectionRulePackage:
        existing = await session.scalar(
            select(orm.DetectionRulePackage).where(
                orm.DetectionRulePackage.idempotency_key == package.idempotency_key
            )
        )
        if existing is not None:
            if existing.content_hash != package.content_hash:
                raise ValidationError(
                    "detection rule package idempotency replay with different content hash",
                    details={"idempotency_key": package.idempotency_key},
                )
            return row_to_detection_rule_package(existing)

        row = orm.DetectionRulePackage(
            package_id=package.package_id,
            source_tenant_id=package.source_tenant_id,
            package_version=package.package_version,
            runtime_state=package.runtime_state.value,
            rules=[rule.model_dump(mode="json") for rule in package.rules],
            provenance=package.provenance.model_dump(mode="json"),
            content_hash=package.content_hash,
            idempotency_key=package.idempotency_key,
            schema_version=package.schema_version,
            supersedes_package_id=package.supersedes_package_id,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(orm.DetectionRulePackage).where(
                    orm.DetectionRulePackage.idempotency_key == package.idempotency_key
                )
            )
            if existing is None:
                raise
            if existing.content_hash != package.content_hash:
                raise ValidationError(
                    "detection rule package idempotency replay with different content hash",
                    details={"idempotency_key": package.idempotency_key},
                ) from None
            return row_to_detection_rule_package(existing)
        return row_to_detection_rule_package(row)

    async def register_package(
        self,
        *,
        source_tenant_id: str,
        package_version: int,
        rules: list[DetectionRuleDefinition],
        author: str,
        review_artifact_ref: str | None = None,
        test_artifact_ref: str | None = None,
        supersedes_package_id: str | None = None,
    ) -> DetectionRulePackage:
        provenance = DetectionRulePackageProvenance(
            author=author,
            review_artifact_ref=review_artifact_ref,
            test_artifact_ref=test_artifact_ref,
            compiled_at=datetime.now(UTC),
        )
        package = compile_rule_package(
            source_tenant_id=source_tenant_id,
            package_version=package_version,
            runtime_state=DetectionRuleRuntimeState.DRAFT,
            rules=rules,
            provenance=provenance,
            supersedes_package_id=supersedes_package_id,
        )
        async with self._session_factory() as session:
            async with session.begin():
                return await self.persist_in_session(session, package)

    async def _get_package_row(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        package_id: str,
        for_update: bool = False,
    ) -> orm.DetectionRulePackage:
        stmt = select(orm.DetectionRulePackage).where(
            orm.DetectionRulePackage.package_id == package_id,
            orm.DetectionRulePackage.source_tenant_id == source_tenant_id,
        )
        if for_update:
            stmt = stmt.with_for_update()
        row = await session.scalar(stmt)
        if row is None:
            raise ResourceNotFoundError(
                "detection rule package not found",
                details={"package_id": package_id, "source_tenant_id": source_tenant_id},
            )
        return row

    async def _transition(
        self,
        *,
        source_tenant_id: str,
        package_id: str,
        target_state: DetectionRuleRuntimeState,
    ) -> DetectionRulePackage:
        async with self._session_factory() as session:
            async with session.begin():
                row = await self._get_package_row(
                    session,
                    source_tenant_id=source_tenant_id,
                    package_id=package_id,
                    for_update=True,
                )
                current = DetectionRuleRuntimeState(row.runtime_state)
                if not allowed_runtime_transition(current, target_state):
                    raise ValidationError(
                        "invalid detection rule runtime transition",
                        details={
                            "package_id": package_id,
                            "current_state": current.value,
                            "target_state": target_state.value,
                        },
                    )

                if target_state is DetectionRuleRuntimeState.VALIDATED:
                    rules = [
                        DetectionRuleDefinition.model_validate(item) for item in (row.rules or [])
                    ]
                    await _validate_active_scopes_for_rules(
                        session,
                        source_tenant_id=row.source_tenant_id,
                        rules=rules,
                    )
                    compile_rule_package(
                        source_tenant_id=row.source_tenant_id,
                        package_version=int(row.package_version),
                        runtime_state=target_state,
                        rules=rules,
                        provenance=DetectionRulePackageProvenance.model_validate(row.provenance),
                        supersedes_package_id=row.supersedes_package_id,
                        package_id=row.package_id,
                    )

                row.runtime_state = target_state.value
                await session.flush()
                await session.refresh(row)
                return row_to_detection_rule_package(row)

    async def validate_package(
        self,
        *,
        source_tenant_id: str,
        package_id: str,
    ) -> DetectionRulePackage:
        return await self._transition(
            source_tenant_id=source_tenant_id,
            package_id=package_id,
            target_state=DetectionRuleRuntimeState.VALIDATED,
        )

    async def activate_shadow(
        self,
        *,
        source_tenant_id: str,
        package_id: str,
    ) -> DetectionRulePackage:
        return await self._transition(
            source_tenant_id=source_tenant_id,
            package_id=package_id,
            target_state=DetectionRuleRuntimeState.SHADOW_ACTIVE,
        )

    async def disable_package(
        self,
        *,
        source_tenant_id: str,
        package_id: str,
    ) -> DetectionRulePackage:
        return await self._transition(
            source_tenant_id=source_tenant_id,
            package_id=package_id,
            target_state=DetectionRuleRuntimeState.DISABLED,
        )

    async def get_package(
        self,
        *,
        source_tenant_id: str,
        package_id: str,
    ) -> DetectionRulePackage | None:
        async with self._session_factory() as session:
            row = await session.get(orm.DetectionRulePackage, package_id)
            if row is None or row.source_tenant_id != source_tenant_id:
                return None
            return row_to_detection_rule_package(row)

    async def list_shadow_active_packages(
        self,
        *,
        source_tenant_id: str,
    ) -> list[DetectionRulePackage]:
        async with self._session_factory() as session:
            rows = list(
                await session.scalars(
                    select(orm.DetectionRulePackage)
                    .where(
                        and_(
                            orm.DetectionRulePackage.source_tenant_id == source_tenant_id,
                            orm.DetectionRulePackage.runtime_state
                            == DetectionRuleRuntimeState.SHADOW_ACTIVE.value,
                        )
                    )
                    .order_by(orm.DetectionRulePackage.package_version.desc())
                )
            )
        return [row_to_detection_rule_package(row) for row in rows]

    async def query_packages(
        self,
        query: DetectionRulePackageQuery,
    ) -> DetectionRulePackageListResult:
        filters = [orm.DetectionRulePackage.source_tenant_id == query.source_tenant_id]
        if query.runtime_state is not None:
            filters.append(orm.DetectionRulePackage.runtime_state == query.runtime_state.value)

        async with self._session_factory() as session:
            total = await session.scalar(
                select(func.count()).select_from(orm.DetectionRulePackage).where(and_(*filters))
            )
            offset = (query.page - 1) * query.page_size
            rows = list(
                await session.scalars(
                    select(orm.DetectionRulePackage)
                    .where(and_(*filters))
                    .order_by(
                        orm.DetectionRulePackage.package_version.desc(),
                        orm.DetectionRulePackage.created_at.desc(),
                    )
                    .offset(offset)
                    .limit(query.page_size)
                )
            )
        return DetectionRulePackageListResult(
            total=int(total or 0),
            page=query.page,
            page_size=query.page_size,
            items=[row_to_detection_rule_package(row) for row in rows],
        )
