"""Validated, idempotent push-batch receiver (ISSUE-016)."""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters._util import parse_source_item
from app.db import models as orm
from app.ingestion.source_ingester import IngestionSummary, SourceIngester
from app.models.enums import ConnectorStatus, DispositionPolicy, SourceObjectKind
from app.services.event_service import EventService

MAX_DELIVERY_HISTORY = 500


class PushBatchEnvelope(BaseModel):
    """Adapter-neutral push envelope; each object is validated independently."""

    model_config = ConfigDict(extra="forbid")

    connector_id: str
    delivery_id: str
    objects: list[dict[str, Any]] = Field(default_factory=list)
    source_product: str | None = None

    @field_validator("connector_id", "delivery_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value


class PushReceiver:
    """Receive push batches with delivery-level and object-identity idempotency."""

    def __init__(
        self,
        ingester: SourceIngester,
        event_service: EventService,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        supported_schema_versions: frozenset[str] = frozenset({"1"}),
    ) -> None:
        self._ingester = ingester
        # Retained for constructor symmetry with FileIngester; ingest goes via SourceIngester.
        _ = event_service
        self._session_factory = session_factory
        self._supported_schema_versions = supported_schema_versions

    async def receive(self, envelope: PushBatchEnvelope) -> IngestionSummary:
        """Validate and partially accept one delivery.

        A PostgreSQL session advisory lock serializes the same
        ``(connector_id, delivery_id)`` across workers. Accepted source objects are
        independently idempotent through EventService/source identity.
        """
        lock_key = _delivery_lock_key(envelope.connector_id, envelope.delivery_id)
        async with self._session_factory() as lock_session:
            await lock_session.execute(
                text("SELECT pg_advisory_lock(:lock_key)"),
                {"lock_key": lock_key},
            )
            try:
                await self._ensure_connector(lock_session, envelope)
                # EventService uses independent transactions; make the connector
                # visible before processing while retaining the session-level lock.
                await lock_session.commit()
                if await self._delivery_seen(lock_session, envelope):
                    return IngestionSummary(duplicate=len(envelope.objects))

                summary = IngestionSummary()
                valid_items: list[Any] = []
                for position, raw in enumerate(envelope.objects):
                    parsed, error = self._parse_object(envelope, raw)
                    if parsed is None:
                        summary.rejected += 1
                        detail = {
                            "position": position,
                            "connector_id": envelope.connector_id,
                            **(error or {}),
                        }
                        summary.errors.append(
                            {
                                "stage": "push_validation",
                                "error_category": "object_rejected",
                                "detail": detail,
                            }
                        )
                        await self._record_quality(detail)
                    else:
                        valid_items.append(parsed)

                if valid_items:
                    processed, _ = await self._ingester.ingest_items(
                        valid_items,
                        source_type=envelope.source_product or "push",
                    )
                    summary.accepted += processed.accepted
                    summary.duplicate += processed.duplicate
                    summary.rejected += processed.rejected
                    summary.errors.extend(processed.errors)
                    if processed.degraded or processed.rejected:
                        summary.degraded = True

                if summary.rejected:
                    summary.degraded = True

                await self._mark_delivery(
                    lock_session,
                    envelope,
                    degraded=summary.rejected > 0 or summary.degraded,
                )
                await lock_session.commit()
                return summary
            finally:
                await lock_session.execute(
                    text("SELECT pg_advisory_unlock(:lock_key)"),
                    {"lock_key": lock_key},
                )

    def _parse_object(
        self,
        envelope: PushBatchEnvelope,
        raw: dict[str, Any],
    ) -> tuple[Any | None, dict[str, Any] | None]:
        payload_raw = raw.get("payload", raw)
        if not isinstance(payload_raw, dict):
            return None, {"reason": "payload_not_object"}
        payload = dict(payload_raw)

        kind_raw = raw.get("source_kind")
        if kind_raw is None:
            ref = payload.get("reference")
            if isinstance(ref, dict):
                kind_raw = ref.get("source_kind")
        try:
            kind = SourceObjectKind(str(kind_raw))
        except ValueError:
            return None, {"reason": "unknown_source_kind", "source_kind": kind_raw}
        if kind is SourceObjectKind.CONNECTOR:
            return None, {"reason": "connector_object_not_supported_in_push"}

        reference = payload.get("reference")
        if not isinstance(reference, dict):
            return None, {"reason": "missing_reference"}
        if reference.get("connector_id") != envelope.connector_id:
            return None, {
                "reason": "connector_id_mismatch",
                "object_connector_id": reference.get("connector_id"),
            }
        if (
            envelope.source_product is not None
            and reference.get("source_product") != envelope.source_product
        ):
            return None, {
                "reason": "source_product_mismatch",
                "object_source_product": reference.get("source_product"),
            }
        schema_version = str(reference.get("schema_version") or "1")
        if schema_version not in self._supported_schema_versions:
            return None, {
                "reason": "schema_unsupported",
                "schema_version": schema_version,
            }

        parsed = parse_source_item(kind.value, payload)
        if parsed is None:
            return None, {"reason": "schema_validation"}
        if parsed.reference.connector_id != envelope.connector_id:
            return None, {"reason": "connector_id_mismatch"}
        return parsed, None

    async def _ensure_connector(
        self,
        session: AsyncSession,
        envelope: PushBatchEnvelope,
    ) -> None:
        row = await session.get(orm.SourceConnector, envelope.connector_id)
        if row is not None:
            return
        product = envelope.source_product or _infer_source_product(envelope.objects) or "push"
        row = orm.SourceConnector(
            connector_id=envelope.connector_id,
            source_product=product,
            display_name=envelope.connector_id,
            status=ConnectorStatus.ONLINE.value,
            disposition_policy_default=(
                DispositionPolicy.REQUIRED.value if product == "mock_xdr" else None
            ),
            # Push is a delivery mechanism, not the connector's logical
            # ingestion adapter identity.
            connector_metadata={"ingestion_adapter": product},
        )
        session.add(row)
        await session.flush()

    @staticmethod
    async def _delivery_seen(
        session: AsyncSession,
        envelope: PushBatchEnvelope,
    ) -> bool:
        row = await session.get(orm.SourceConnector, envelope.connector_id)
        if row is None:
            return False
        metadata = row.connector_metadata or {}
        deliveries = metadata.get("processed_delivery_ids") or []
        return envelope.delivery_id in deliveries

    @staticmethod
    async def _mark_delivery(
        session: AsyncSession,
        envelope: PushBatchEnvelope,
        *,
        degraded: bool,
    ) -> None:
        row = await session.get(orm.SourceConnector, envelope.connector_id)
        if row is None:
            raise RuntimeError("push connector disappeared before delivery commit")
        metadata = dict(row.connector_metadata or {})
        deliveries = [str(item) for item in (metadata.get("processed_delivery_ids") or [])]
        if envelope.delivery_id not in deliveries:
            deliveries.append(envelope.delivery_id)
        metadata["processed_delivery_ids"] = deliveries[-MAX_DELIVERY_HISTORY:]
        if degraded:
            metadata["last_ingestion_error"] = "object_rejected"
        else:
            metadata.pop("last_ingestion_error", None)
        row.connector_metadata = metadata
        # The delivery transport succeeded even when individual objects were
        # rejected. Kind/item quality is not connector transport health.
        row.status = ConnectorStatus.ONLINE.value
        await session.flush()

    async def _record_quality(self, detail: dict[str, Any]) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                session.add(
                    orm.DataQualityError(
                        event_id=None,
                        stage="push_validation",
                        error_category="object_rejected",
                        detail=detail,
                    )
                )


def _delivery_lock_key(connector_id: str, delivery_id: str) -> int:
    digest = hashlib.sha256(f"{connector_id}|{delivery_id}".encode()).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _infer_source_product(objects: list[dict[str, Any]]) -> str | None:
    for raw in objects:
        payload = raw.get("payload", raw)
        if not isinstance(payload, dict):
            continue
        ref = payload.get("reference")
        if isinstance(ref, dict) and ref.get("source_product"):
            return str(ref["source_product"])
    return None
