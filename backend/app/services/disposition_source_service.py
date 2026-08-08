"""Disposition source selection and readiness recheck (ISSUE-280).

Product routes persist selection with optimistic concurrency and never fall back
to static fixtures when validation or persistence fails.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Any

from sqlalchemy import exc as sa_exc
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.registry import DispositionAdapterRegistry
from app.core.errors import (
    DependencyUnavailableError,
    DispositionPermissionDenied,
    EventNotFoundError,
    WritebackConflictError,
)
from app.db import models as orm
from app.models.disposition import SourceObjectLocator
from app.models.enums import DispositionPolicy, SourceObjectKind, WritebackReadiness
from app.services.context_service import event_summary_from_security_event
from app.services.event_service import EventService, _security_event_from_row
from app.services.writeback_readiness_resolver import WritebackReadinessResolver

logger = logging.getLogger(__name__)

_TRANSIENT_DB_ERRORS = (
    ConnectionRefusedError,
    TimeoutError,
    socket.gaierror,
    sa_exc.OperationalError,
)


@dataclass(frozen=True)
class DispositionSourceSelectResult:
    event_id: str
    disposition_source_ref: SourceObjectLocator
    event_version: int


@dataclass(frozen=True)
class DispositionReadinessRecheckResult:
    event_id: str
    writeback_readiness: WritebackReadiness
    blocked_reason: str | None
    event_version: int


class DispositionSourceService:
    """Select durable disposition sources and recompute writeback readiness."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        event_service: EventService,
        adapter_registry: DispositionAdapterRegistry,
        readiness_resolver: WritebackReadinessResolver | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._event_service = event_service
        self._adapters = adapter_registry
        self._readiness = readiness_resolver or WritebackReadinessResolver()

    async def select_disposition_source(
        self,
        event_id: str,
        *,
        source_record_id: str,
        expected_event_version: int,
        operator: str,
        comment: str | None = None,
    ) -> DispositionSourceSelectResult:
        try:
            return await self._select_disposition_source_impl(
                event_id,
                source_record_id=source_record_id,
                expected_event_version=expected_event_version,
                operator=operator,
                comment=comment,
            )
        except _TRANSIENT_DB_ERRORS as exc:
            logger.warning(
                "disposition-source selection degraded (transient DB error) event=%s",
                event_id,
                exc_info=True,
            )
            raise DependencyUnavailableError(
                "database unavailable for disposition-source selection",
                error_code="dependency_unavailable",
                details={"event_id": event_id},
            ) from exc

    async def recheck_disposition_readiness(
        self,
        event_id: str,
        *,
        expected_event_version: int,
    ) -> DispositionReadinessRecheckResult:
        try:
            return await self._recheck_disposition_readiness_impl(
                event_id,
                expected_event_version=expected_event_version,
            )
        except _TRANSIENT_DB_ERRORS as exc:
            logger.warning(
                "disposition-readiness recheck degraded (transient DB error) event=%s",
                event_id,
                exc_info=True,
            )
            raise DependencyUnavailableError(
                "database unavailable for disposition-readiness recheck",
                error_code="dependency_unavailable",
                details={"event_id": event_id},
            ) from exc

    async def _select_disposition_source_impl(
        self,
        event_id: str,
        *,
        source_record_id: str,
        expected_event_version: int,
        operator: str,
        comment: str | None,
    ) -> DispositionSourceSelectResult:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.SecurityEvent,
                    event_id,
                    with_for_update=True,
                )
                if row is None:
                    raise EventNotFoundError(
                        f"event {event_id} not found",
                        details={"event_id": event_id},
                    )

                current_version = int(row.row_version or 1)
                if current_version != expected_event_version:
                    raise WritebackConflictError(
                        "event version mismatch",
                        details={
                            "expected": expected_event_version,
                            "actual": current_version,
                        },
                    )

                link = await session.scalar(
                    select(orm.SourceEventLink).where(
                        orm.SourceEventLink.source_record_id == source_record_id,
                        orm.SourceEventLink.event_id == event_id,
                    )
                )
                if link is None:
                    raise DispositionPermissionDenied(
                        "source object is not associated with this event",
                        details={
                            "source_record_id": source_record_id,
                            "event_id": event_id,
                        },
                    )

                source_obj = await session.get(orm.SourceObject, source_record_id)
                if source_obj is None:
                    raise DispositionPermissionDenied(
                        "source object not found",
                        details={"source_record_id": source_record_id},
                    )

                self._assert_tenant_consistent(row, source_obj)

                locator = SourceObjectLocator(
                    source_product=source_obj.source_product,
                    source_tenant_id=source_obj.source_tenant_id,
                    connector_id=source_obj.connector_id,
                    source_kind=SourceObjectKind(source_obj.source_kind),
                    source_object_id=source_obj.source_object_id,
                )
                row.disposition_source_ref = locator.model_dump(mode="json")
                row.row_version = current_version + 1

                audit_reason = f"disposition_source_selected:{source_record_id}"
                if comment:
                    audit_reason = f"{audit_reason}; comment={comment.strip()[:240]}"
                session.add(
                    orm.EventAuditLog(
                        event_id=event_id,
                        from_status=row.status,
                        to_status=row.status,
                        operator=operator,
                        reason=audit_reason,
                    )
                )
                await session.flush()
                await session.refresh(row)
                committed = _security_event_from_row(row)
                summary = event_summary_from_security_event(row)

        await self._event_service.sync_event_summary_mutation(
            event_id,
            result=committed,
            summary=summary,
        )
        return DispositionSourceSelectResult(
            event_id=event_id,
            disposition_source_ref=locator,
            event_version=committed.row_version,
        )

    async def _recheck_disposition_readiness_impl(
        self,
        event_id: str,
        *,
        expected_event_version: int,
    ) -> DispositionReadinessRecheckResult:
        async with self._session_factory() as session:
            row = await session.get(orm.SecurityEvent, event_id)
            if row is None:
                raise EventNotFoundError(
                    f"event {event_id} not found",
                    details={"event_id": event_id},
                )

            current_version = int(row.row_version or 1)
            if current_version != expected_event_version:
                raise WritebackConflictError(
                    "event version mismatch",
                    details={
                        "expected": expected_event_version,
                        "actual": current_version,
                    },
                )

            policy = DispositionPolicy(row.disposition_policy)
            if policy is DispositionPolicy.NOT_REQUIRED:
                return DispositionReadinessRecheckResult(
                    event_id=event_id,
                    writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                    blocked_reason=None,
                    event_version=current_version,
                )

            if not row.disposition_source_ref:
                return DispositionReadinessRecheckResult(
                    event_id=event_id,
                    writeback_readiness=WritebackReadiness.SOURCE_UNRESOLVED,
                    blocked_reason="source_unresolved",
                    event_version=current_version,
                )

            locator = SourceObjectLocator.model_validate(row.disposition_source_ref)
            connector = await session.get(orm.SourceConnector, locator.connector_id)
            adapter = self._resolve_adapter(locator)
            readiness, blocked = await self._readiness.resolve_for_locator(
                locator=locator,
                connector=connector,
                adapter=adapter,
            )
            return DispositionReadinessRecheckResult(
                event_id=event_id,
                writeback_readiness=readiness,
                blocked_reason=blocked,
                event_version=current_version,
            )

    @staticmethod
    def _assert_tenant_consistent(
        event_row: orm.SecurityEvent,
        source_obj: orm.SourceObject,
    ) -> None:
        creation_ref = event_row.creation_source_ref
        creation = creation_ref if isinstance(creation_ref, dict) else {}
        event_tenant = creation.get("source_tenant_id")
        if event_tenant and source_obj.source_tenant_id != event_tenant:
            raise DispositionPermissionDenied(
                "source object is not a tenant-consistent source for this event",
                details={
                    "source_record_id": source_obj.source_record_id,
                    "event_id": event_row.event_id,
                    "event_tenant_id": event_tenant,
                    "source_tenant_id": source_obj.source_tenant_id,
                },
            )

    def _resolve_adapter(self, locator: SourceObjectLocator) -> Any:
        product = str(locator.source_product or "mock_xdr")
        return self._adapters.get(product)
