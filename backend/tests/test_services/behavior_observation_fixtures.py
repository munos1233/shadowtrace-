"""Shared DB seed helpers for BehaviorObservation tests (ISSUE-119 / ISSUE-156)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.detection_scope import DetectionScopeLifecycleState
from app.models.enums import SourceDisposition, SourceObjectKind


class _ScalarRows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def __iter__(self) -> Any:
        return iter(self._rows)

    def all(self) -> list[Any]:
        return self._rows


def build_ambiguous_active_scope_rows(
    *,
    suffix: str,
    tenant_id: str,
    connector_id: str,
    instance_id: str,
) -> list[orm.DetectionScopeRevision]:
    """Two ACTIVE scope rows for one instance (simulates pre-constraint ambiguity)."""
    connector_set = {
        "connector_set_version": 1,
        "upstream_connectors": [{"connector_id": connector_id, "source_product": "mock_xdr"}],
    }
    rows: list[orm.DetectionScopeRevision] = []
    for label, content_char, identity_char in (("a", "a", "b"), ("b", "c", "d")):
        rows.append(
            orm.DetectionScopeRevision(
                scope_revision_id=f"dsrev-{label}-{suffix}",
                detection_scope_id=f"dscope-{label}-{suffix}",
                source_tenant_id=tenant_id,
                source_product="mock_xdr",
                integration_instance_id=instance_id,
                connector_set=connector_set,
                connector_set_version=1,
                lifecycle_state=DetectionScopeLifecycleState.ACTIVE.value,
                revision=1,
                content_hash=content_char * 64,
                identity_hash=identity_char * 64,
                idempotency_key=f"idem-{label}-{suffix}",
                schema_version="1.0",
            )
        )
    return rows


def patch_session_scalars_with_ambiguous_scopes(
    session: AsyncSession,
    ambiguous_rows: list[orm.DetectionScopeRevision],
) -> None:
    """Intercept ACTIVE scope queries without violating DB uniqueness constraints."""
    original_scalars = session.scalars

    async def _scalars(statement: object) -> Any:
        if "detection_scope_revision" in str(statement).lower():
            return _ScalarRows(ambiguous_rows)
        return await original_scalars(statement)

    session.scalars = _scalars  # type: ignore[method-assign]


def ambiguous_scope_binding_error(
    *,
    connector_id: str,
    instance_id: str,
    detection_scope_ids: tuple[str, ...],
) -> Callable[..., Awaitable[Any]]:
    async def _raise(*_args: object, **_kwargs: object) -> Any:
        raise ValidationError(
            "ambiguous detection scope binding for connector",
            details={
                "connector_id": connector_id,
                "integration_instance_id": instance_id,
                "detection_scope_ids": list(detection_scope_ids),
            },
        )

    return _raise


async def truncate_behavior_observation_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Clear BObs-related tables for isolated integration tests."""
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.ActionExecutionJob))
            await session.execute(delete(orm.ActionTargetResult))
            await session.execute(delete(orm.Action))
            await session.execute(delete(orm.BehaviorObservationProjectionFailure))
            await session.execute(delete(orm.BehaviorObservation))
            await session.execute(delete(orm.DetectionScopeRevision))
            await session.execute(delete(orm.DispositionOutbox))
            await session.execute(delete(orm.SourceEventLink))
            await session.execute(delete(orm.SourceObject))
            await session.execute(delete(orm.SourceConnector))
            await session.execute(delete(orm.DataQualityError))
            await session.execute(delete(orm.SecurityEvent))


async def seed_behavior_observation_connector(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    connector_id: str,
    tenant_id: str,
    integration_instance_id: str = "inst-primary",
) -> None:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=connector_id,
                    source_product="mock_xdr",
                    display_name=f"Test {connector_id}",
                    status="online",
                    schema_version="1",
                    connector_metadata={
                        "source_tenant_id": tenant_id,
                        "integration_instance_id": integration_instance_id,
                        "connector_set_version": 1,
                    },
                )
            )


async def seed_behavior_observation_source_log(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    suffix: str,
    tenant_id: str,
    connector_id: str,
    source_revision: int = 1,
    record_id: str | None = None,
) -> str:
    resolved_record_id = record_id or f"src-{suffix}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceObject(
                    source_record_id=resolved_record_id,
                    source_product="mock_xdr",
                    source_tenant_id=tenant_id,
                    connector_id=connector_id,
                    source_kind=SourceObjectKind.LOG.value,
                    source_object_id=f"log-{suffix}",
                    source_object_type="edr",
                    source_status_raw="indexed",
                    source_disposition=SourceDisposition.UNKNOWN.value,
                    schema_version="1",
                    ingested_at=datetime(2026, 8, 1, tzinfo=UTC),
                    raw_payload_hash=f"hash-{suffix}",
                    normalized={
                        "channel": "endpoint",
                        "category": "process_create",
                        "action": "create_process",
                        "src_ip": "10.0.0.10",
                        "detection_score": 55,
                        "logged_at": "2026-08-01T00:00:00+00:00",
                    },
                    raw_payload={"cmdline": "sensitive"},
                    current_source_status_raw="indexed",
                    current_source_disposition=SourceDisposition.UNKNOWN.value,
                    current_state_version=source_revision,
                    source_updated_at=datetime(2026, 8, 1, tzinfo=UTC),
                    source_sync_state="synced",
                )
            )
    return resolved_record_id
