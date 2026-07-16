"""Incremental SourceAdapter ingestion with durable watermarks (ISSUE-016)."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.source.base import BaseSourceAdapter, SourcePage
from app.core.config import get_settings
from app.core.errors import ValidationError
from app.db import models as orm
from app.models.enums import (
    ConnectorStatus,
    DispositionPolicy,
    EventType,
    Severity,
    SourceObjectKind,
)
from app.models.ids import canonical_source_identity
from app.models.source import (
    SourceAlert,
    SourceAsset,
    SourceConnector,
    SourceIncident,
    SourceLog,
    SourceReference,
)
from app.services.event_service import (
    EventService,
    IngestableSource,
    should_apply_source_update,
    stable_source_record_id,
)
from app.services.evidence_projection import EvidenceProjection

logger = logging.getLogger(__name__)

SUPPORTED_SCHEMA_VERSIONS = frozenset({"1"})
_EVENT_SOURCE_TYPES = (SourceIncident, SourceAlert)
_SUPPORTING_SOURCE_TYPES = (SourceAsset, SourceLog)


class IngestionKindSummary(BaseModel):
    """One independently checkpointed object-kind ingestion result."""

    model_config = ConfigDict(extra="forbid")

    object_kind: SourceObjectKind
    accepted: int = 0
    duplicate: int = 0
    rejected: int = 0
    watermark_before: dict[str, Any] | None = None
    watermark_after: dict[str, Any] | None = None
    degraded: bool = False
    errors: list[dict[str, Any]] = Field(default_factory=list)


class IngestionSummary(BaseModel):
    """Aggregate poll result with independently checkpointed kind details."""

    model_config = ConfigDict(extra="forbid")

    accepted: int = 0
    duplicate: int = 0
    rejected: int = 0
    watermark_before: dict[str, Any] | None = None
    watermark_after: dict[str, Any] | None = None
    degraded: bool = False
    errors: list[dict[str, Any]] = Field(default_factory=list)
    kind_summaries: dict[str, IngestionKindSummary] = Field(default_factory=dict)


@dataclass(slots=True)
class _CheckpointState:
    watermark: dict[str, Any] | None
    row_version: int | None


class CheckpointConflictError(RuntimeError):
    """A concurrent poll advanced a kind checkpoint first."""


def source_identity(ref: SourceReference) -> str:
    return canonical_source_identity(
        source_product=ref.source_product,
        source_tenant_id=ref.source_tenant_id,
        connector_id=ref.connector_id,
        source_kind=ref.source_kind.value,
        source_object_id=ref.source_object_id,
    )


def source_to_ingestable(
    item: SourceIncident | SourceAlert,
    *,
    source_type: str,
) -> IngestableSource:
    """Project a validated SourceIncident/Alert into EventService input."""
    normalized = item.normalized or {}
    event_type = _event_type(normalized, item)
    severity = _severity(normalized, item)
    title: str | None
    description = str(normalized.get("description") or "")

    if isinstance(item, SourceIncident):
        title = item.title or _optional_text(normalized.get("title"))
        incident_ref = None
        related_alert_refs = list(item.related_alert_refs)
    else:
        title = (
            _optional_text(normalized.get("title"))
            or _optional_text(normalized.get("alert_type"))
            or f"alert:{item.reference.source_object_id}"
        )
        incident_ref = item.incident_ref
        related_alert_refs = []

    return IngestableSource(
        reference=item.reference,
        raw_payload=item.raw_payload,
        normalized=normalized,
        title=title,
        description=description,
        event_type=event_type,
        severity=severity,
        occurred_at=item.reference.source_updated_at,
        incident_ref=incident_ref,
        related_alert_refs=related_alert_refs,
        source_type=source_type,
    )


class SourceIngester:
    """Pull SourceAdapter pages, persist objects, then durably advance watermark."""

    def __init__(
        self,
        event_service: EventService,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        source_mode: str | None = None,
        supported_schema_versions: frozenset[str] = SUPPORTED_SCHEMA_VERSIONS,
        evidence_projection: EvidenceProjection | None = None,
    ) -> None:
        self._events = event_service
        self._session_factory = session_factory
        self._source_mode = source_mode or get_settings().source_mode
        self._supported_schema_versions = supported_schema_versions
        self._evidence_projection = evidence_projection or EvidenceProjection(session_factory)

    async def poll(
        self,
        adapter: BaseSourceAdapter,
        object_types: Sequence[SourceObjectKind | str],
        batch_size: int,
    ) -> IngestionSummary:
        """Poll each connector/kind stream independently, then project evidence."""
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        self._assert_file_mode(adapter)
        kinds = _normalize_object_kinds(object_types)
        stream_scope = adapter.checkpoint_scope
        aggregate = IngestionSummary()

        try:
            health = await adapter.health_check()
        except Exception as exc:  # noqa: BLE001 — health failure is degradation
            health = ConnectorStatus.OFFLINE
            aggregate.errors.append(
                {
                    "stage": "connector_health",
                    "error_category": "health_check_failed",
                    "detail": {"type": type(exc).__name__, "message": str(exc)},
                }
            )
        if health is not ConnectorStatus.ONLINE:
            aggregate.degraded = True
            aggregate.errors.append(
                {
                    "stage": "connector_health",
                    "error_category": "connector_unavailable",
                    "status": health.value,
                }
            )
            await self._mark_adapter_status(
                adapter.name,
                health,
                error_category="connector_unavailable",
            )
            connector_ids = {
                row.connector_id for row in await self._adapter_connectors(adapter.name)
            }
            for kind in kinds:
                for connector_id in connector_ids:
                    await self._mark_kind_checkpoint(
                        connector_id,
                        kind,
                        health,
                        stream_scope=stream_scope,
                        error_category="connector_unavailable",
                    )
                aggregate.kind_summaries[kind.value] = IngestionKindSummary(
                    object_kind=kind,
                    degraded=True,
                    errors=list(aggregate.errors),
                )
            return aggregate

        try:
            await self._refresh_adapter_connectors(adapter)
        except Exception as exc:  # noqa: BLE001 — connector discovery is transport
            aggregate.degraded = True
            aggregate.errors.append(
                {
                    "stage": "connector_discovery",
                    "error_category": "adapter_unavailable",
                    "detail": {"type": type(exc).__name__, "message": str(exc)},
                }
            )
            await self._mark_adapter_status(
                adapter.name,
                ConnectorStatus.DEGRADED,
                error_category="adapter_unavailable",
            )
            return aggregate

        await self._mark_adapter_status(
            adapter.name,
            ConnectorStatus.ONLINE,
            error_category="",
        )
        connector_ids = {row.connector_id for row in await self._adapter_connectors(adapter.name)}
        for kind in kinds:
            result = await self._poll_kind(
                adapter,
                kind,
                batch_size,
                connector_ids=connector_ids,
                stream_scope=stream_scope,
            )
            kind_result = IngestionKindSummary(
                object_kind=kind,
                accepted=result.accepted,
                duplicate=result.duplicate,
                rejected=result.rejected,
                watermark_before=result.watermark_before,
                watermark_after=result.watermark_after,
                degraded=result.degraded,
                errors=result.errors,
            )
            aggregate.kind_summaries[kind.value] = kind_result
            aggregate.accepted += result.accepted
            aggregate.duplicate += result.duplicate
            aggregate.rejected += result.rejected
            aggregate.degraded = aggregate.degraded or result.degraded
            aggregate.errors.extend(result.errors)
        if len(kinds) == 1:
            only = aggregate.kind_summaries[kinds[0].value]
            aggregate.watermark_before = _copy_watermark(only.watermark_before)
            aggregate.watermark_after = _copy_watermark(only.watermark_after)
        await self._project_adapter_evidence(adapter, summary=aggregate)
        return aggregate

    async def _poll_kind(
        self,
        adapter: BaseSourceAdapter,
        object_kind: SourceObjectKind,
        batch_size: int,
        *,
        connector_ids: set[str],
        stream_scope: str,
    ) -> IngestionSummary:
        """Poll one kind separately for every connector scope."""
        summaries = [
            await self._poll_connector_kind(
                adapter,
                object_kind,
                batch_size,
                connector_id=connector_id,
                stream_scope=stream_scope,
            )
            for connector_id in (sorted(connector_ids) if connector_ids else [None])
        ]
        aggregate = IngestionSummary()
        for summary in summaries:
            _merge_counts(aggregate, summary)
            aggregate.degraded = aggregate.degraded or summary.degraded
            aggregate.errors.extend(summary.errors)
        if len(summaries) == 1:
            aggregate.watermark_before = _copy_watermark(summaries[0].watermark_before)
            aggregate.watermark_after = _copy_watermark(summaries[0].watermark_after)
        return aggregate

    async def _poll_connector_kind(
        self,
        adapter: BaseSourceAdapter,
        object_kind: SourceObjectKind,
        batch_size: int,
        *,
        connector_id: str | None,
        stream_scope: str,
    ) -> IngestionSummary:
        """Poll and commit exactly one connector/kind stream."""
        object_types = [object_kind]
        checkpoint = (
            await self._load_checkpoint(connector_id, object_kind, stream_scope=stream_scope)
            if connector_id is not None
            else _CheckpointState(None, None)
        )
        before = checkpoint.watermark
        summary = IngestionSummary(
            watermark_before=_copy_watermark(before),
            watermark_after=_copy_watermark(before),
        )
        cursor = _watermark_cursor(before)
        updated_after = _watermark_time(before)
        seen_cursors: set[str | None] = set()
        checkpoint_connector_id = connector_id
        checkpoint_version = checkpoint.row_version

        while True:
            if cursor in seen_cursors:
                await self._reject_page(
                    summary,
                    object_kind,
                    "cursor_loop",
                    {"cursor": cursor},
                    connector_id=checkpoint_connector_id,
                    stream_scope=stream_scope,
                    rejected=1,
                )
                break
            seen_cursors.add(cursor)

            try:
                kwargs: dict[str, Any] = {
                    "cursor": cursor,
                    "updated_after": updated_after,
                    "limit": batch_size,
                }
                if connector_id is not None:
                    kwargs["connector_id"] = connector_id
                page = await adapter.list_objects(object_types, **kwargs)
            except Exception as exc:  # noqa: BLE001 — poll reports degradation
                summary.degraded = True
                summary.errors.append(
                    {
                        "stage": "adapter_poll",
                        "error_category": "adapter_unavailable",
                        "detail": {"type": type(exc).__name__, "message": str(exc)},
                    }
                )
                await self._record_quality(
                    stage="adapter_poll",
                    error_category="adapter_unavailable",
                    detail={"adapter": adapter.name, "type": type(exc).__name__},
                )
                if checkpoint_connector_id is not None:
                    await self._mark_kind_checkpoint(
                        checkpoint_connector_id,
                        object_kind,
                        ConnectorStatus.DEGRADED,
                        stream_scope=stream_scope,
                        error_category="adapter_unavailable",
                    )
                break

            page_connector_ids = {
                item_connector
                for item in page.items
                if (item_connector := _connector_id(item)) is not None
            }
            if page.connector_id is not None:
                page_connector_ids.add(page.connector_id)
            if connector_id is not None and page_connector_ids - {connector_id}:
                await self._reject_page(
                    summary,
                    object_kind,
                    "page_connector_mismatch",
                    {
                        "expected_connector_id": connector_id,
                        "actual_connector_ids": sorted(page_connector_ids),
                    },
                    connector_id=connector_id,
                    stream_scope=stream_scope,
                    rejected=max(1, len(page.items)),
                )
                break
            if connector_id is None and len(page_connector_ids) > 1:
                await self._reject_page(
                    summary,
                    object_kind,
                    "page_connector_mismatch",
                    {"actual_connector_ids": sorted(page_connector_ids)},
                    connector_id=None,
                    stream_scope=stream_scope,
                    rejected=max(1, len(page.items)),
                )
                break
            if checkpoint_connector_id is None and page_connector_ids:
                checkpoint_connector_id = next(iter(page_connector_ids))

            if page.object_kind is not object_kind:
                await self._reject_page(
                    summary,
                    object_kind,
                    "page_kind_mismatch",
                    {
                        "expected_kind": object_kind.value,
                        "actual_kind": page.object_kind.value,
                    },
                    connector_id=checkpoint_connector_id,
                    stream_scope=stream_scope,
                    rejected=max(1, len(page.items)),
                )
                break
            if any(
                isinstance(ref := getattr(item, "reference", None), SourceReference)
                and ref.source_kind is not object_kind
                for item in page.items
            ):
                await self._reject_page(
                    summary,
                    object_kind,
                    "page_item_kind_mismatch",
                    {"expected_kind": object_kind.value},
                    connector_id=checkpoint_connector_id,
                    stream_scope=stream_scope,
                    rejected=max(1, len(page.items)),
                )
                break
            if page.malformed_items:
                await self._reject_page(
                    summary,
                    object_kind,
                    "malformed_payload",
                    {"malformed_items": page.malformed_items},
                    connector_id=checkpoint_connector_id,
                    stream_scope=stream_scope,
                    rejected=page.malformed_items,
                )
                break
            if page.schema_version not in self._supported_schema_versions:
                await self._reject_page(
                    summary,
                    object_kind,
                    "schema_unsupported",
                    {"schema_version": page.schema_version},
                    connector_id=checkpoint_connector_id,
                    stream_scope=stream_scope,
                    rejected=max(1, len(page.items)),
                )
                break

            page_summary, page_connectors = await self.ingest_items(
                page.items,
                source_type=adapter.name,
            )
            _merge_counts(summary, page_summary)
            if checkpoint_connector_id is None and len(page_connectors) == 1:
                checkpoint_connector_id = next(iter(page_connectors))

            if page_summary.rejected:
                summary.degraded = True
                summary.errors.extend(page_summary.errors)
                if checkpoint_connector_id is not None:
                    await self._mark_kind_checkpoint(
                        checkpoint_connector_id,
                        object_kind,
                        ConnectorStatus.DEGRADED,
                        stream_scope=stream_scope,
                        error_category="object_rejected",
                    )
                # Accepted objects remain idempotent; no watermark advance means
                # a retry can safely replay the page and recover rejected items.
                break

            if page.has_more and not page.next_cursor:
                await self._reject_page(
                    summary,
                    object_kind,
                    "invalid_pagination",
                    {"reason": "has_more_without_next_cursor"},
                    connector_id=checkpoint_connector_id,
                    stream_scope=stream_scope,
                    rejected=1,
                )
                break

            if checkpoint_connector_id is None:
                # An empty unscoped page has no durable connector identity.
                # Replaying it is safer than inventing an adapter-wide cursor.
                break

            after = _next_watermark(
                before=summary.watermark_after,
                page=page,
            )
            try:
                committed = await self._commit_checkpoint(
                    connector_id=checkpoint_connector_id,
                    object_kind=object_kind,
                    stream_scope=stream_scope,
                    watermark=after,
                    schema_version=page.schema_version,
                    expected_watermark=summary.watermark_after,
                    expected_row_version=checkpoint_version,
                )
            except CheckpointConflictError as exc:
                summary.degraded = True
                summary.errors.append(
                    {
                        "stage": "checkpoint_commit",
                        "error_category": "checkpoint_conflict",
                        "detail": {"kind": object_kind.value, "message": str(exc)},
                    }
                )
                break
            summary.watermark_after = _copy_watermark(committed.watermark)
            checkpoint_version = committed.row_version

            if not page.has_more:
                break
            cursor = page.next_cursor

        return summary

    async def ingest_items(
        self,
        items: list[Any],
        *,
        source_type: str,
    ) -> tuple[IngestionSummary, set[str]]:
        """Process validated Source* items independently (partial acceptance)."""
        summary = IngestionSummary()
        connector_ids: set[str] = set()

        # Incident first gives later linked alerts an existing parent event.
        ordered = sorted(items, key=_source_processing_order)
        for item in ordered:
            connector_id = _connector_id(item)
            if connector_id:
                connector_ids.add(connector_id)
            try:
                duplicate = await self._ingest_one(item, source_type=source_type)
            except Exception as exc:  # noqa: BLE001 — partial batch acceptance
                summary.rejected += 1
                detail: dict[str, Any] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "connector_id": connector_id,
                }
                error = {
                    "stage": "source_ingest",
                    "error_category": "object_rejected",
                    "detail": detail,
                }
                summary.errors.append(error)
                await self._record_quality(
                    stage="source_ingest",
                    error_category="object_rejected",
                    detail=detail,
                )
                continue

            if duplicate:
                summary.duplicate += 1
            else:
                summary.accepted += 1

        return summary, connector_ids

    async def ingest_telemetry(
        self,
        records_by_source: dict[str, list[dict[str, Any]]],
        *,
        source_type: str,
        connector_id: str | None = None,
        source_tenant_id: str = "local",
        watermark: dict[str, Any] | None = None,
    ) -> int:
        """Project adapter-normalized telemetry through the shared evidence store."""
        return await self._evidence_projection.ingest_records(
            records_by_source,
            source_product=source_type,
            source_tenant_id=source_tenant_id,
            connector_id=connector_id or f"{source_type}-evidence",
            watermark=watermark,
        )

    async def _project_adapter_evidence(
        self,
        adapter: BaseSourceAdapter,
        *,
        summary: IngestionSummary,
    ) -> None:
        try:
            # Evidence has its own idempotent identities. Until adapters expose
            # a dedicated evidence watermark, replay the page rather than reuse
            # the SourceObject watermark and risk permanently skipping a failed
            # projection write.
            page = await adapter.list_evidence_records(updated_after=None)
            if page is None:
                return
            if page.schema_version not in self._supported_schema_versions:
                raise ValueError(f"unsupported evidence schema_version={page.schema_version}")
            await self._evidence_projection.ingest_records(
                page.records_by_source,
                source_product=page.source_product,
                source_tenant_id=page.source_tenant_id,
                connector_id=page.connector_id,
                schema_version=page.schema_version,
                watermark=summary.watermark_after,
            )
        except Exception as exc:  # noqa: BLE001 — project gap degrades, never fabricates
            summary.degraded = True
            summary.errors.append(
                {
                    "stage": "evidence_projection",
                    "error_category": "projection_failed",
                    "detail": {
                        "adapter": adapter.name,
                        "type": type(exc).__name__,
                        "message": str(exc),
                    },
                }
            )
            await self._record_quality(
                stage="evidence_projection",
                error_category="projection_failed",
                detail={"adapter": adapter.name, "type": type(exc).__name__},
            )

    async def _ingest_one(self, item: Any, *, source_type: str) -> bool:
        if isinstance(item, _EVENT_SOURCE_TYPES):
            result = await self._events.ingest_source_object(
                source_to_ingestable(item, source_type=source_type)
            )
            return result.idempotent
        if isinstance(item, _SUPPORTING_SOURCE_TYPES):
            return await self._persist_supporting_object(
                item,
                source_type=source_type,
            )
        if isinstance(item, SourceConnector):
            return await self._persist_connector(item, adapter_name=source_type)
        raise TypeError(f"unsupported source object type: {type(item).__name__}")

    async def _persist_supporting_object(
        self,
        item: SourceAsset | SourceLog,
        *,
        source_type: str,
    ) -> bool:
        ref = item.reference
        identity = source_identity(ref)
        record_id = stable_source_record_id(identity=identity)
        projected = _supporting_projection(item)
        async with self._session_factory() as session:
            async with session.begin():
                await self._ensure_connector_for_ref(
                    session,
                    ref,
                    source_type=source_type,
                )
                existing = await session.scalar(
                    select(orm.SourceObject)
                    .where(
                        orm.SourceObject.source_product == ref.source_product,
                        orm.SourceObject.source_tenant_id == ref.source_tenant_id,
                        orm.SourceObject.connector_id == ref.connector_id,
                        orm.SourceObject.source_kind == ref.source_kind.value,
                        orm.SourceObject.source_object_id == ref.source_object_id,
                    )
                    .with_for_update()
                )
                if existing is not None:
                    if not should_apply_source_update(
                        stored_updated_at=existing.current_source_updated_at,
                        stored_token=existing.current_concurrency_token,
                        incoming_updated_at=ref.source_updated_at,
                        incoming_token=ref.source_concurrency_token,
                    ):
                        return True
                    existing.current_source_status_raw = ref.source_status_raw
                    existing.current_source_disposition = ref.source_disposition.value
                    existing.current_concurrency_token = ref.source_concurrency_token
                    existing.current_source_updated_at = ref.source_updated_at
                    existing.current_state_version += 1
                    existing.source_sync_state = "synced"
                    if projected:
                        existing.normalized = projected
                    await session.flush()
                    return True

                session.add(
                    orm.SourceObject(
                        source_record_id=record_id,
                        source_product=ref.source_product,
                        source_tenant_id=ref.source_tenant_id,
                        connector_id=ref.connector_id,
                        source_kind=ref.source_kind.value,
                        source_object_id=ref.source_object_id,
                        source_object_type=ref.source_object_type,
                        parent_source_object_id=ref.parent_source_object_id,
                        source_status_raw=ref.source_status_raw,
                        source_disposition=ref.source_disposition.value,
                        source_concurrency_token=ref.source_concurrency_token,
                        source_updated_at=ref.source_updated_at,
                        schema_version=ref.schema_version,
                        ingested_at=ref.ingested_at or datetime.now(UTC),
                        raw_payload_hash=ref.raw_payload_hash,
                        normalized=projected,
                        raw_payload=item.raw_payload,
                        current_source_status_raw=ref.source_status_raw,
                        current_source_disposition=ref.source_disposition.value,
                        current_concurrency_token=ref.source_concurrency_token,
                        current_source_updated_at=ref.source_updated_at,
                        current_state_version=1,
                        source_sync_state="synced",
                    )
                )
                await session.flush()
                return False

    async def _persist_connector(
        self,
        item: SourceConnector,
        *,
        adapter_name: str,
    ) -> bool:
        async with self._session_factory() as session:
            async with session.begin():
                existing = await session.get(orm.SourceConnector, item.connector_id)
                duplicate = existing is not None
                row = existing or orm.SourceConnector(
                    connector_id=item.connector_id,
                    source_product=item.source_product,
                    display_name=item.display_name,
                )
                row.source_product = item.source_product
                row.display_name = item.display_name
                row.device_type = item.device_type
                row.status = item.status.value
                row.read_endpoint = item.read_endpoint
                row.disposition_endpoint = item.disposition_endpoint
                row.capabilities = {
                    key.value: value.value for key, value in item.capabilities.items()
                }
                row.disposition_policy_default = (
                    item.disposition_policy_default.value
                    if item.disposition_policy_default is not None
                    else None
                )
                row.last_sync_at = item.last_sync_at
                row.schema_version = item.schema_version
                metadata = dict(row.connector_metadata or {})
                metadata.update(item.metadata)
                metadata["ingestion_adapter"] = adapter_name
                row.connector_metadata = metadata
                if existing is None:
                    session.add(row)
                await session.flush()
                return duplicate

    async def _ensure_connector_for_ref(
        self,
        session: AsyncSession,
        ref: SourceReference,
        *,
        source_type: str,
    ) -> orm.SourceConnector:
        row = await session.get(orm.SourceConnector, ref.connector_id)
        if row is not None:
            metadata = dict(row.connector_metadata or {})
            metadata_tenant = metadata.get("source_tenant_id")
            existing_tenants = (
                {str(metadata_tenant)}
                if metadata_tenant is not None
                else set(
                    (
                        await session.scalars(
                            select(orm.SourceObject.source_tenant_id)
                            .where(orm.SourceObject.connector_id == ref.connector_id)
                            .distinct()
                        )
                    ).all()
                )
            )
            existing_adapter = metadata.get("ingestion_adapter")
            if (
                row.source_product != ref.source_product
                or existing_tenants - {ref.source_tenant_id}
                or existing_adapter not in (None, source_type)
            ):
                raise ValidationError(
                    "connector ownership conflicts with source reference",
                    error_code="adapter_validation_error",
                    details={
                        "connector_id": ref.connector_id,
                        "existing_source_product": row.source_product,
                        "incoming_source_product": ref.source_product,
                        "existing_source_tenant_ids": sorted(existing_tenants),
                        "incoming_source_tenant_id": ref.source_tenant_id,
                        "existing_adapter": existing_adapter,
                        "incoming_adapter": source_type,
                    },
                )
            metadata["source_tenant_id"] = ref.source_tenant_id
            metadata["ingestion_adapter"] = source_type
            row.connector_metadata = metadata
            return row
        row = orm.SourceConnector(
            connector_id=ref.connector_id,
            source_product=ref.source_product,
            display_name=ref.connector_id,
            status=ConnectorStatus.ONLINE.value,
            disposition_policy_default=(
                DispositionPolicy.NOT_REQUIRED.value
                if source_type in {"file", "manual"}
                else DispositionPolicy.REQUIRED.value
                if ref.source_product == "mock_xdr"
                else None
            ),
            connector_metadata={
                "ingestion_adapter": source_type,
                "source_tenant_id": ref.source_tenant_id,
            },
        )
        session.add(row)
        await session.flush()
        return row

    async def _load_checkpoint(
        self,
        connector_id: str,
        object_kind: SourceObjectKind,
        *,
        stream_scope: str,
    ) -> _CheckpointState:
        async with self._session_factory() as session:
            checkpoint = await session.scalar(
                select(orm.SourceCheckpoint).where(
                    orm.SourceCheckpoint.connector_id == connector_id,
                    orm.SourceCheckpoint.object_kind == object_kind.value,
                    orm.SourceCheckpoint.stream_scope == stream_scope,
                )
            )
        if checkpoint is None:
            # Deliberately ignore SourceConnector.watermark from pre-0004
            # installations. Replaying is safe; translating an opaque global
            # cursor into connector/kind rows is not.
            return _CheckpointState(None, None)
        return _CheckpointState(
            _copy_watermark(checkpoint.watermark),
            checkpoint.row_version,
        )

    async def _commit_checkpoint(
        self,
        *,
        connector_id: str,
        object_kind: SourceObjectKind,
        stream_scope: str,
        watermark: dict[str, Any],
        schema_version: str,
        expected_watermark: dict[str, Any] | None,
        expected_row_version: int | None,
    ) -> _CheckpointState:
        if _watermark_is_regression(expected_watermark, watermark):
            raise CheckpointConflictError(
                f"{connector_id}:{object_kind.value} watermark regression"
            )
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                if expected_row_version is None:
                    insert_statement = (
                        pg_insert(orm.SourceCheckpoint)
                        .values(
                            connector_id=connector_id,
                            object_kind=object_kind.value,
                            stream_scope=stream_scope,
                            schema_version=schema_version,
                            cursor=_watermark_cursor(watermark),
                            watermark=dict(watermark),
                            status=ConnectorStatus.ONLINE.value,
                            degraded_reason=None,
                            last_sync_at=now,
                            row_version=1,
                        )
                        .on_conflict_do_nothing(
                            index_elements=[
                                orm.SourceCheckpoint.connector_id,
                                orm.SourceCheckpoint.object_kind,
                                orm.SourceCheckpoint.stream_scope,
                            ]
                        )
                    )
                    result = cast(
                        CursorResult[Any],
                        await session.execute(insert_statement),
                    )
                    if result.rowcount != 1:
                        raise CheckpointConflictError(
                            f"{connector_id}:{object_kind.value} insert conflict"
                        )
                    next_version = 1
                else:
                    next_version = expected_row_version + 1
                    update_statement = (
                        update(orm.SourceCheckpoint)
                        .where(
                            orm.SourceCheckpoint.connector_id == connector_id,
                            orm.SourceCheckpoint.object_kind == object_kind.value,
                            orm.SourceCheckpoint.stream_scope == stream_scope,
                            orm.SourceCheckpoint.row_version == expected_row_version,
                        )
                        .values(
                            schema_version=schema_version,
                            cursor=_watermark_cursor(watermark),
                            watermark=dict(watermark),
                            status=ConnectorStatus.ONLINE.value,
                            degraded_reason=None,
                            last_sync_at=now,
                            row_version=next_version,
                        )
                    )
                    result = cast(
                        CursorResult[Any],
                        await session.execute(update_statement),
                    )
                    if result.rowcount != 1:
                        raise CheckpointConflictError(
                            f"{connector_id}:{object_kind.value} row_version conflict"
                        )
        return _CheckpointState(dict(watermark), next_version)

    async def _mark_adapter_status(
        self,
        adapter_name: str,
        status: ConnectorStatus,
        *,
        error_category: str,
    ) -> None:
        rows = await self._adapter_connectors(adapter_name)
        await self._mark_connectors(
            {row.connector_id for row in rows},
            status,
            error_category=error_category,
        )

    async def _mark_connectors(
        self,
        connector_ids: set[str],
        status: ConnectorStatus,
        *,
        error_category: str,
    ) -> None:
        if not connector_ids:
            return
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.scalars(
                        select(orm.SourceConnector).where(
                            orm.SourceConnector.connector_id.in_(connector_ids)
                        )
                    )
                ).all()
                for row in rows:
                    metadata = dict(row.connector_metadata or {})
                    if error_category:
                        metadata["last_ingestion_error"] = error_category
                    else:
                        metadata.pop("last_ingestion_error", None)
                    row.connector_metadata = metadata
                    row.status = status.value
                await session.flush()

    async def _mark_kind_checkpoint(
        self,
        connector_id: str,
        object_kind: SourceObjectKind,
        status: ConnectorStatus,
        *,
        stream_scope: str,
        error_category: str,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                connector = await session.get(orm.SourceConnector, connector_id)
                if connector is None:
                    return
                statement = (
                    pg_insert(orm.SourceCheckpoint)
                    .values(
                        connector_id=connector_id,
                        object_kind=object_kind.value,
                        stream_scope=stream_scope,
                        schema_version=connector.schema_version,
                        status=status.value,
                        degraded_reason=error_category or None,
                        row_version=1,
                    )
                    .on_conflict_do_update(
                        index_elements=[
                            orm.SourceCheckpoint.connector_id,
                            orm.SourceCheckpoint.object_kind,
                            orm.SourceCheckpoint.stream_scope,
                        ],
                        set_={
                            "status": status.value,
                            "degraded_reason": error_category or None,
                            "row_version": orm.SourceCheckpoint.row_version + 1,
                        },
                    )
                )
                await session.execute(statement)

    async def _refresh_adapter_connectors(self, adapter: BaseSourceAdapter) -> None:
        for connector in await adapter.list_connectors():
            if not isinstance(connector, SourceConnector):
                raise TypeError("list_connectors must return SourceConnector items")
            await self._persist_connector(connector, adapter_name=adapter.name)

    async def _adapter_connectors(self, adapter_name: str) -> list[orm.SourceConnector]:
        async with self._session_factory() as session:
            rows = (await session.scalars(select(orm.SourceConnector))).all()
            return [row for row in rows if _row_matches_adapter(row, adapter_name)]

    async def _reject_page(
        self,
        summary: IngestionSummary,
        object_kind: SourceObjectKind,
        category: str,
        detail: dict[str, Any],
        *,
        connector_id: str | None,
        stream_scope: str,
        rejected: int,
    ) -> None:
        summary.rejected += rejected
        summary.degraded = True
        summary.errors.append(
            {
                "stage": "adapter_page",
                "error_category": category,
                "detail": detail,
            }
        )
        await self._record_quality(
            stage="adapter_page",
            error_category=category,
            detail={"connector_id": connector_id, **detail},
        )
        if connector_id is not None:
            await self._mark_kind_checkpoint(
                connector_id,
                object_kind,
                ConnectorStatus.DEGRADED,
                stream_scope=stream_scope,
                error_category=category,
            )

    async def _record_quality(
        self,
        *,
        stage: str,
        error_category: str,
        detail: dict[str, Any],
        **_: Any,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                session.add(
                    orm.DataQualityError(
                        event_id=None,
                        stage=stage,
                        error_category=error_category,
                        detail=detail,
                    )
                )

    def _assert_file_mode(self, adapter: BaseSourceAdapter) -> None:
        if adapter.name == "file" and self._source_mode != "file":
            raise RuntimeError(
                "FileSourceAdapter requires explicit SOURCE_MODE=file; "
                "automatic fallback is forbidden"
            )


def _next_watermark(
    *,
    before: dict[str, Any] | None,
    page: SourcePage,
) -> dict[str, Any]:
    previous_updated = (before or {}).get("updated_after")
    if page.has_more:
        updated_after = previous_updated
    else:
        updated_after = (
            page.server_time.isoformat() if page.server_time is not None else previous_updated
        )
    return {
        "cursor": page.next_cursor,
        "updated_after": updated_after,
    }


def _watermark_cursor(watermark: dict[str, Any] | None) -> str | None:
    if not watermark:
        return None
    cursor = watermark.get("cursor")
    return str(cursor) if cursor else None


def _watermark_time(watermark: dict[str, Any] | None) -> datetime | None:
    if not watermark:
        return None
    raw = watermark.get("updated_after")
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))


def _copy_watermark(watermark: dict[str, Any] | None) -> dict[str, Any] | None:
    return dict(watermark) if watermark is not None else None


def _watermark_is_regression(
    current: dict[str, Any] | None,
    incoming: dict[str, Any],
) -> bool:
    current_time = _watermark_time(current)
    incoming_time = _watermark_time(incoming)
    return current_time is not None and incoming_time is not None and incoming_time < current_time


def _normalize_object_kinds(
    object_types: Sequence[SourceObjectKind | str],
) -> list[SourceObjectKind]:
    kinds: list[SourceObjectKind] = []
    seen: set[SourceObjectKind] = set()
    for value in object_types:
        kind = value if isinstance(value, SourceObjectKind) else SourceObjectKind(str(value))
        if kind not in seen:
            seen.add(kind)
            kinds.append(kind)
    if not kinds:
        raise ValueError("object_types must contain at least one kind")
    return kinds


def _merge_counts(target: IngestionSummary, source: IngestionSummary) -> None:
    target.accepted += source.accepted
    target.duplicate += source.duplicate
    target.rejected += source.rejected


def _connector_id(item: Any) -> str | None:
    if isinstance(item, SourceConnector):
        return item.connector_id
    ref = getattr(item, "reference", None)
    return ref.connector_id if isinstance(ref, SourceReference) else None


def _source_processing_order(item: Any) -> int:
    if isinstance(item, SourceConnector):
        return 0
    if isinstance(item, SourceIncident):
        return 1
    if isinstance(item, SourceAlert):
        return 2
    if isinstance(item, SourceAsset):
        return 3
    if isinstance(item, SourceLog):
        return 4
    return 99


def _supporting_projection(item: SourceAsset | SourceLog) -> dict[str, Any]:
    """Preserve typed SourceAsset/SourceLog fields in the query projection."""
    projected = dict(item.normalized)
    typed = item.model_dump(
        mode="json",
        exclude={"reference", "raw_payload", "normalized"},
        exclude_none=True,
    )
    for key, value in typed.items():
        projected.setdefault(key, value)
    if isinstance(item, SourceAsset):
        projected.setdefault("channel", "asset")
    else:
        device_source = str(item.device_source or "").lower()
        channel = {
            "edr": "endpoint",
            "iam": "identity",
            "nfw": "network",
            "proxy": "network",
        }.get(device_source, device_source or "log")
        projected.setdefault("channel", channel)
    return projected


def _row_matches_adapter(row: orm.SourceConnector, adapter_name: str) -> bool:
    metadata = row.connector_metadata or {}
    return metadata.get("ingestion_adapter") == adapter_name


def _event_type(normalized: dict[str, Any], item: SourceIncident | SourceAlert) -> EventType:
    candidates = [
        normalized.get("event_type"),
        normalized.get("alert_type"),
        getattr(item, "gpt_verdict_label", None),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        raw = str(candidate).lower()
        try:
            return EventType(raw)
        except ValueError:
            if "insider" in raw:
                return EventType.INSIDER_THREAT
            if "exfil" in raw:
                return EventType.DATA_EXFILTRATION
            if "domain" in raw:
                return EventType.SUSPICIOUS_DOMAIN
            if "account" in raw or "login" in raw:
                return EventType.ACCOUNT_ANOMALY
    return EventType.OTHER


def _severity(normalized: dict[str, Any], item: SourceIncident | SourceAlert) -> Severity:
    candidates = [normalized.get("severity"), getattr(item, "level", None)]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return Severity(str(candidate).lower())
        except ValueError:
            continue
    return Severity.LOW


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
