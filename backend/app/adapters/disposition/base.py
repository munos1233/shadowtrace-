"""Write-only DispositionAdapter contract (ISSUE-012).

Agents never import this module. DispositionSyncService depends only on
``BaseDispositionAdapter``. Live adapters keep every capability UNKNOWN until
formal docs / sanitized evidence + contract tests flip them to SUPPORTED.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field

from app.adapters.disposition.error_classification import (  # noqa: F401
    DispositionDeliveryErrorKind,
    bounded_dead_letter_error_code,
    classify_disposition_delivery_error,
    is_deterministic_adapter_rejection_code,
)
from app.core.errors import WritebackUnsupportedError
from app.models.disposition import DispositionCommand, DispositionReceipt, EntityEffectCompletion, SourceObjectLocator
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
    supports_readback_confirmation: bool = False
    supports_entity_effect_readback: bool = False


class BaseDispositionAdapter(ABC):
    """Event-disposition writeback only. No free-form dict payloads."""

    name: str = "base"

    @abstractmethod
    def capabilities(self) -> DispositionAdapterCapabilities:
        """Declare intent/operation capability and lookup/status support."""

    def allows_safe_retry(self) -> bool:
        """True when idempotent submit + lookup can safely re-enqueue after never-accepted."""
        caps = self.capabilities()
        return caps.supports_idempotency and caps.supports_lookup_by_idempotency

    @abstractmethod
    def validate_command(self, command: DispositionCommand) -> None:
        """Raise on allowlist / policy violations before submit."""

    @abstractmethod
    async def submit(self, command: DispositionCommand) -> DispositionReceipt:
        """Submit a DispositionCommand. May return sync terminal or async ACCEPTED."""

    async def get_status(self, provider_job_id: str) -> DispositionReceipt | None:
        """Optional async job status. Default: unsupported."""
        raise WritebackUnsupportedError(
            "disposition status query is unsupported",
            details={"provider_job_id": provider_job_id},
        )

    async def lookup_submission(
        self,
        idempotency_key: str,
        source_locator: SourceObjectLocator,
    ) -> DispositionReceipt | None:
        """Look up an earlier submission after a lost response.

        When lookup capability is declared, ``None`` means the provider
        authoritatively reported that no submission exists. Transport errors,
        malformed responses, permission failures, and other inconclusive
        outcomes must raise so callers remain PAUSED instead of retrying.
        """
        raise WritebackUnsupportedError(
            "disposition idempotency lookup is unsupported",
            details={"adapter": self.name},
        )

    async def confirm_readback(self, command: DispositionCommand) -> DispositionReceipt | None:
        """Optional authoritative readback confirmation (ISSUE-064).

        After ``submit`` returns ACCEPTED, callers may invoke this to
        verify the provider-side state transition has actually occurred
        and promote the receipt to CONFIRMED+readback_verified.
        Default: unsupported (returns None).
        """
        return None

    async def complete_entity_effect_readback(
        self,
        command: DispositionCommand,
        receipt: DispositionReceipt,
    ) -> EntityEffectCompletion | None:
        """Optional entity effect completion via provider-side applied state (ISSUE-311).

        For ``ENTITY_ACTION_SUBMIT`` only. Must not promote the entity receipt
        to ``CONFIRMED``; returns independent effect evidence instead.
        Default: unsupported (returns None).
        """
        _ = (command, receipt)
        return None

    @abstractmethod
    async def health_check(self) -> ConnectorStatus:
        """Return connector health without side effects."""
