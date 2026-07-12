"""Write-only DispositionAdapter contract (ISSUE-012).

Agents never import this module. DispositionSyncService depends only on
``BaseDispositionAdapter``. Live adapters keep every capability UNKNOWN until
formal docs / sanitized evidence + contract tests flip them to SUPPORTED.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field

from app.models.disposition import DispositionCommand, DispositionReceipt, SourceObjectLocator
from app.models.enums import (
    CapabilityState,
    ConnectorStatus,
    DispositionIntentKind,
)


class DispositionAdapterCapabilities(BaseModel):
    """Capability declaration for disposition intents / operations."""

    model_config = ConfigDict(extra="forbid")

    intents: dict[DispositionIntentKind, CapabilityState] = Field(default_factory=dict)
    operations: dict[str, CapabilityState] = Field(default_factory=dict)
    supports_idempotency: bool = False
    supports_status_query: bool = False
    supports_concurrency_token: bool = False
    supports_lookup_by_idempotency: bool = False


class BaseDispositionAdapter(ABC):
    """Event-disposition writeback only. No free-form dict payloads."""

    name: str = "base"

    @abstractmethod
    def capabilities(self) -> DispositionAdapterCapabilities:
        """Declare intent/operation capability and lookup/status support."""

    @abstractmethod
    def validate_command(self, command: DispositionCommand) -> None:
        """Raise on allowlist / policy violations before submit."""

    @abstractmethod
    async def submit(self, command: DispositionCommand) -> DispositionReceipt:
        """Submit a DispositionCommand. May return sync terminal or async ACCEPTED."""

    async def get_status(self, provider_job_id: str) -> DispositionReceipt | None:
        """Optional async job status. Default: unsupported."""
        return None

    async def lookup_submission(
        self,
        idempotency_key: str,
        source_locator: SourceObjectLocator,
    ) -> DispositionReceipt | None:
        """Optional idempotency lookup after lost responses. Default: unsupported."""
        return None

    @abstractmethod
    async def health_check(self) -> ConnectorStatus:
        """Return connector health without side effects."""
