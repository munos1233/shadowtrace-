"""Read-only SourceAdapter contract (ISSUE-012).

Source adapters never expose write methods. SourceIngester / EventService depend
only on this surface — never on vendor HTTP clients.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import CapabilityState, ConnectorCapability, ConnectorStatus, SourceObjectKind
from app.models.source import (
    SourceAlert,
    SourceAsset,
    SourceConnector,
    SourceIncident,
    SourceLog,
)


class SourcePage(BaseModel):
    """One object-kind page from a SourceAdapter.

    A page never combines kinds: schema and cursor therefore describe exactly
    one independently checkpointed stream.
    """

    model_config = ConfigDict(extra="forbid")

    items: list[SourceIncident | SourceAlert | SourceAsset | SourceLog | SourceConnector] = Field(
        default_factory=list
    )
    object_kind: SourceObjectKind
    connector_id: str | None = None
    next_cursor: str | None = None
    has_more: bool = False
    server_time: datetime | None = None
    schema_version: str = "1"
    malformed_items: int = 0


class SourceEvidencePage(BaseModel):
    """Adapter-normalized deep telemetry ready for EvidenceProjection."""

    model_config = ConfigDict(extra="forbid")

    records_by_source: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    source_product: str
    source_tenant_id: str
    connector_id: str
    schema_version: str = "1"


class BaseSourceAdapter(ABC):
    """Pure-read adapter. Implementations must not mutate external systems."""

    name: str = "base"
    checkpoint_scope: str = ""

    @abstractmethod
    def capabilities(self) -> dict[ConnectorCapability, CapabilityState]:
        """Declare read-side connector capabilities."""

    @abstractmethod
    async def list_objects(
        self,
        object_types: Sequence[SourceObjectKind | str],
        *,
        connector_id: str | None = None,
        cursor: str | None = None,
        updated_after: datetime | None = None,
        limit: int = 100,
    ) -> SourcePage:
        """List exactly one Source* object kind.

        Implementations must reject multi-kind requests. Watermark commit is
        caller-owned after persistence.
        """

    async def list_connectors(self) -> list[SourceConnector]:
        """List connector scopes when the adapter can enumerate them."""
        return []

    async def get_object(
        self,
        source_kind: SourceObjectKind | str,
        source_object_id: str,
    ) -> SourceIncident | SourceAlert | SourceAsset | SourceLog | None:
        """Optional single-object fetch. Default: not implemented."""
        return None

    async def list_evidence_records(
        self,
        *,
        updated_after: datetime | None = None,
    ) -> SourceEvidencePage | None:
        """Optional deep-telemetry projection page. Default: unavailable."""
        return None

    @abstractmethod
    async def health_check(self) -> ConnectorStatus:
        """Return connector health without side effects."""


class DataQualityRecorder:
    """Collects validation/normalization failures destined for ``data_quality_error``."""

    def record(
        self,
        *,
        stage: str,
        error_category: str,
        field_name: str | None = None,
        detail: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> None:
        raise NotImplementedError


class InMemoryDataQualityRecorder(DataQualityRecorder):
    """Test / offline sink; later issues flush rows into ``data_quality_error``."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def record(
        self,
        *,
        stage: str,
        error_category: str,
        field_name: str | None = None,
        detail: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> None:
        self.rows.append(
            {
                "event_id": event_id,
                "stage": stage,
                "error_category": error_category,
                "field_name": field_name,
                "detail": detail or {},
            }
        )
