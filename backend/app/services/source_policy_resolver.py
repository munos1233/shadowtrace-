"""SourcePolicyResolver — disposition_policy from connector / source type (ISSUE-015)."""

from __future__ import annotations

from typing import Any

from app.models.enums import DispositionPolicy, SourceObjectKind

# Source types that never require external writeback by business policy.
_FILE_MANUAL_TYPES: frozenset[str] = frozenset({"file", "manual"})


class SourcePolicyResolver:
    """Decide ``disposition_policy`` from connector config and source provenance.

    Rules (ISSUE-015):
    - ``file`` / ``manual`` → ``not_required``
    - P0 Mock XDR (``source_product=mock_xdr`` or ``SOURCE_MODE=mock_xdr``) →
      default ``required`` (connector override honored when present)
    - live connectors → must use the connector's explicit
      ``disposition_policy_default`` (never silently invent required/not_required)
    """

    def resolve(
        self,
        *,
        source_type: str | None = None,
        source_kind: SourceObjectKind | str | None = None,
        source_product: str | None = None,
        connector_policy_default: DispositionPolicy | str | None = None,
        source_mode: str | None = None,
        live_configured: bool = False,
    ) -> DispositionPolicy:
        """Return the business disposition policy for a new / promoted event."""
        normalized_type = (source_type or "").strip().lower()
        if normalized_type in _FILE_MANUAL_TYPES:
            return DispositionPolicy.NOT_REQUIRED

        # Reserved for future kind-specific policy; provenance currently wins.
        _ = source_kind

        product = (source_product or "").strip().lower()
        mode = (source_mode or "").strip().lower()
        is_mock = product == "mock_xdr" or mode == "mock_xdr"

        if connector_policy_default is not None:
            return _as_policy(connector_policy_default)

        if is_mock:
            return DispositionPolicy.REQUIRED

        if live_configured:
            # Live without an explicit connector default must not invent policy.
            raise ValueError(
                "live connectors require explicit disposition_policy_default on the connector"
            )

        # Safe default for unknown / unconfigured ingest paths.
        return DispositionPolicy.NOT_REQUIRED

    def readiness_when_required_but_blocked(
        self,
        *,
        has_writable_locator: bool,
        capability_state: str | None,
    ) -> str | None:
        """Return a writeback_readiness block reason, or None when unblocked.

        Does **not** downgrade ``disposition_policy``; callers keep ``required``
        and surface the readiness block to humans / PolicyFilter.
        """
        if not has_writable_locator:
            return "source_unresolved"
        cap = (capability_state or "").strip().upper()
        if cap in {"UNKNOWN", ""}:
            return "capability_unknown"
        if cap == "UNSUPPORTED":
            return "capability_unsupported"
        return None


def _as_policy(value: DispositionPolicy | str) -> DispositionPolicy:
    if isinstance(value, DispositionPolicy):
        return value
    return DispositionPolicy(value)


def connector_policy_from_row(connector: Any | None) -> DispositionPolicy | None:
    """Extract ``disposition_policy_default`` from an ORM/pydantic connector."""
    if connector is None:
        return None
    raw = getattr(connector, "disposition_policy_default", None)
    if raw is None:
        return None
    return _as_policy(raw)
