"""ID and key generation (intro §4.7).

- ``event_id`` is derived deterministically from the first stable source identity
  five-tuple plus the occurred date, so re-ingesting the same external object is
  idempotent. It is computed once and never recomputed.
- Other internal IDs use a typed prefix plus random hex.
- ``report_id_for_event`` is a stable derivation of the event_id, guaranteeing
  idempotent upsert (never random per call).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import date, datetime


def _rand_hex(n_bytes: int = 4) -> str:
    """Return ``n_bytes`` of cryptographically-random hex (default 8 chars)."""
    return secrets.token_hex(n_bytes)


def _yyyymmdd(occurred_at: datetime | date | str) -> str:
    """Normalize an occurred timestamp to a ``YYYYMMDD`` string."""
    if isinstance(occurred_at, str):
        # Accept ISO 8601; fall back to the leading date component.
        parsed = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        return parsed.strftime("%Y%m%d")
    if isinstance(occurred_at, datetime):
        return occurred_at.strftime("%Y%m%d")
    return occurred_at.strftime("%Y%m%d")


def canonical_source_identity(
    *,
    source_product: str,
    source_tenant_id: str,
    connector_id: str,
    source_kind: str,
    source_object_id: str,
) -> str:
    """Build the canonical, collision-safe identity string for the five-tuple.

    The adapter-native ``source_object_type`` and opaque concurrency token are
    deliberately excluded from identity (intro §4.3). Components are joined with a
    delimiter unlikely to appear in IDs so different connectors cannot collide.
    """
    parts = [
        source_product,
        source_tenant_id,
        connector_id,
        source_kind,
        source_object_id,
    ]
    return "|".join(parts)


def new_event_id(identity: str, occurred_at: datetime | date | str) -> str:
    """Derive ``evt-{YYYYMMDD}-{8hex}`` from a canonical identity + occurred date.

    Same ``identity`` + same occurred date always yields the same id; different
    inputs yield different ids. Use :func:`canonical_source_identity` to build the
    identity from a source five-tuple, or a content hash for pure file alerts.
    """
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:8]
    return f"evt-{_yyyymmdd(occurred_at)}-{digest}"


def new_evidence_id() -> str:
    return f"evd-{_rand_hex()}"


def new_conflict_id() -> str:
    return f"cft-{_rand_hex()}"


def new_action_id() -> str:
    return f"act-{_rand_hex()}"


def new_approval_id() -> str:
    return f"apv-{_rand_hex()}"


def new_job_id() -> str:
    return f"job-{_rand_hex()}"


def new_disposition_id() -> str:
    return f"disp-{_rand_hex()}"


def new_writeback_id() -> str:
    return f"wbk-{_rand_hex()}"


def new_trace_id() -> str:
    return f"trc-{_rand_hex()}"


def new_call_id() -> str:
    return f"call-{_rand_hex()}"


def new_case_id() -> str:
    return f"case-{_rand_hex()}"


def report_id_for_event(event_id: str) -> str:
    """Stable report id derived from event_id: ``rpt-`` + SHA256(event_id)[:8]."""
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:8]
    return f"rpt-{digest}"


def new_report_id(event_id: str) -> str:
    """Alias for :func:`report_id_for_event`; requires event_id (never random)."""
    return report_id_for_event(event_id)
