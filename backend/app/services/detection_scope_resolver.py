"""Server-owned Detection Scope resolver (ISSUE-120 Phase 0).

Rules/models/agents must not assemble scope identity locally — all scope IDs and
connector set revisions are produced through this module or DetectionScopeService.
"""

from __future__ import annotations

import hashlib
from typing import Any

import orjson

from app.core.errors import ValidationError
from app.models.detection_scope import (
    DETECTION_SCOPE_SCHEMA_VERSION,
    ConnectorScopeRole,
    DetectionScopeConnectorSet,
    DetectionScopeIdentity,
    DetectionScopeLifecycleState,
    DetectionScopeRevision,
    UpstreamConnectorMember,
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def normalize_upstream_connector_set(
    *,
    connector_set_version: int,
    upstream_connectors: list[UpstreamConnectorMember],
) -> DetectionScopeConnectorSet:
    """Canonicalize upstream connector membership (sorted, deduped, upstream-only)."""
    if connector_set_version < 1:
        raise ValidationError("connector_set_version must be >= 1")
    if not upstream_connectors:
        raise ValidationError("upstream connector set cannot be empty")

    deduped: dict[tuple[str, str], UpstreamConnectorMember] = {}
    for member in upstream_connectors:
        if member.role is not ConnectorScopeRole.UPSTREAM_SOURCE:
            raise ValidationError(
                "derived detection connectors cannot be included in upstream connector set",
                details={"connector_id": member.connector_id, "role": member.role.value},
            )
        key = (member.source_product, member.connector_id)
        if key in deduped:
            raise ValidationError(
                "duplicate upstream connector in scope set",
                details={
                    "connector_id": member.connector_id,
                    "source_product": member.source_product,
                },
            )
        deduped[key] = member

    ordered = sorted(
        deduped.values(),
        key=lambda item: (item.source_product, item.connector_id),
    )
    return DetectionScopeConnectorSet(
        connector_set_version=connector_set_version,
        upstream_connectors=ordered,
    )


def compute_scope_identity_material(identity: DetectionScopeIdentity) -> dict[str, Any]:
    return {
        "source_tenant_id": identity.source_tenant_id,
        "source_product": identity.source_product,
        "integration_instance_id": identity.integration_instance_id,
        "environment": identity.environment,
        "region": identity.region,
        "schema_version": DETECTION_SCOPE_SCHEMA_VERSION,
    }


def compute_scope_identity_hash(identity: DetectionScopeIdentity) -> str:
    return hashlib.sha256(_canonical_bytes(compute_scope_identity_material(identity))).hexdigest()


def build_detection_scope_id(
    identity: DetectionScopeIdentity,
    *,
    connector_set_version: int,
) -> str:
    """Deterministic scope id from identity boundary + versioned connector set revision."""
    if connector_set_version < 1:
        raise ValidationError("connector_set_version must be >= 1")
    material = {
        **compute_scope_identity_material(identity),
        "connector_set_version": connector_set_version,
    }
    digest = hashlib.sha256(_canonical_bytes(material)).hexdigest()[:12]
    return f"dscope-{digest}"


def compute_connector_set_hash(connector_set: DetectionScopeConnectorSet) -> str:
    payload = connector_set.model_dump(mode="json")
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def compute_scope_content_hash(payload: dict[str, Any]) -> str:
    """Hash adjudicated scope body (identity + connector set + lifecycle + revision)."""
    content_keys = (
        "detection_scope_id",
        "identity",
        "connector_set",
        "lifecycle_state",
        "revision",
        "schema_version",
    )
    canonical = {key: payload[key] for key in content_keys if key in payload}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def build_scope_revision_id(*, detection_scope_id: str, revision: int) -> str:
    material = f"{detection_scope_id}|rev{revision}|{DETECTION_SCOPE_SCHEMA_VERSION}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:8]
    return f"dscope-rev-{digest}"


def build_idempotency_key(
    *,
    detection_scope_id: str,
    revision: int,
) -> str:
    return f"{detection_scope_id}:rev{revision}"


def build_detection_scope_revision(
    *,
    identity: DetectionScopeIdentity,
    connector_set: DetectionScopeConnectorSet,
    revision: int = 1,
    lifecycle_state: DetectionScopeLifecycleState = DetectionScopeLifecycleState.DRAFT,
    supersedes_scope_revision_id: str | None = None,
    scope_revision_id: str | None = None,
) -> DetectionScopeRevision:
    """Construct a canonical scope revision with deterministic ids and hashes."""
    if revision < 1:
        raise ValidationError("revision must be >= 1")

    normalized_set = normalize_upstream_connector_set(
        connector_set_version=connector_set.connector_set_version,
        upstream_connectors=list(connector_set.upstream_connectors),
    )
    detection_scope_id = build_detection_scope_id(
        identity,
        connector_set_version=normalized_set.connector_set_version,
    )
    resolved_revision_id = scope_revision_id or build_scope_revision_id(
        detection_scope_id=detection_scope_id,
        revision=revision,
    )
    body = {
        "detection_scope_id": detection_scope_id,
        "identity": identity.model_dump(mode="json"),
        "connector_set": normalized_set.model_dump(mode="json"),
        "lifecycle_state": lifecycle_state.value,
        "revision": revision,
        "schema_version": DETECTION_SCOPE_SCHEMA_VERSION,
    }
    content_hash = compute_scope_content_hash(body)
    identity_hash = compute_scope_identity_hash(identity)
    return DetectionScopeRevision(
        scope_revision_id=resolved_revision_id,
        detection_scope_id=detection_scope_id,
        identity=identity,
        connector_set=normalized_set,
        lifecycle_state=lifecycle_state,
        revision=revision,
        supersedes_scope_revision_id=supersedes_scope_revision_id,
        content_hash=content_hash,
        identity_hash=identity_hash,
        idempotency_key=build_idempotency_key(
            detection_scope_id=detection_scope_id,
            revision=revision,
        ),
        schema_version=DETECTION_SCOPE_SCHEMA_VERSION,
    )


class DetectionScopeResolver:
    """Server-owned entry point for scope assembly — do not duplicate in agents."""

    build_detection_scope_revision = staticmethod(build_detection_scope_revision)
    normalize_upstream_connector_set = staticmethod(normalize_upstream_connector_set)
    build_detection_scope_id = staticmethod(build_detection_scope_id)
    compute_scope_content_hash = staticmethod(compute_scope_content_hash)
    compute_connector_set_hash = staticmethod(compute_connector_set_hash)

    @staticmethod
    def assert_derived_connector_excluded_from_set(
        connector_id: str,
        connector_set: DetectionScopeConnectorSet,
    ) -> None:
        """Derived connectors must reference scope externally, never define membership."""
        member_ids = {item.connector_id for item in connector_set.upstream_connectors}
        if connector_id in member_ids:
            raise ValidationError(
                "derived detection connector cannot appear in upstream connector set",
                details={"connector_id": connector_id},
            )
