"""Resolve event-level writeback readiness from adapter probes (ISSUE-280).

Readiness recheck must consult real disposition adapter capability,
connectivity, and credential availability — never a fixed placeholder.
"""

from __future__ import annotations

import os
from typing import Any

from app.adapters.disposition.base import BaseDispositionAdapter
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    CapabilityState,
    ConnectorStatus,
    DispositionIntentKind,
    WritebackReadiness,
)


class WritebackReadinessResolver:
    """Map connector + adapter state to ``WritebackReadiness`` for an event locator."""

    async def resolve_for_locator(
        self,
        *,
        locator: SourceObjectLocator,
        connector: Any | None,
        adapter: BaseDispositionAdapter,
    ) -> tuple[WritebackReadiness, str | None]:
        blocked = self._credential_block_reason(connector)
        if blocked is not None:
            return WritebackReadiness.PERMISSION_DENIED, blocked

        try:
            health = await adapter.health_check()
        except Exception:
            return WritebackReadiness.CONNECTOR_UNAVAILABLE, "connector_health_probe_failed"

        if health is ConnectorStatus.OFFLINE:
            return WritebackReadiness.CONNECTOR_UNAVAILABLE, "connector_offline"

        caps = adapter.capabilities()
        intent_state = caps.intents.get(
            DispositionIntentKind.EVENT_STATUS_UPDATE,
            CapabilityState.UNKNOWN,
        )
        if intent_state is CapabilityState.SUPPORTED:
            return WritebackReadiness.READY, None
        if intent_state is CapabilityState.UNSUPPORTED:
            return WritebackReadiness.CAPABILITY_UNSUPPORTED, "capability_unsupported"
        return WritebackReadiness.CAPABILITY_UNKNOWN, "capability_unknown"

    @staticmethod
    def _credential_block_reason(connector: Any | None) -> str | None:
        if connector is None:
            return None
        cred_ref = getattr(connector, "disposition_credential_ref", None)
        if not cred_ref:
            return None
        if cred_ref not in os.environ:
            return "credential_unavailable"
        return None
