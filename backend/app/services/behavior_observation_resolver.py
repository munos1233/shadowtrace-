"""Server-owned BehaviorObservation resolver (ISSUE-119 / #624).

Rules/models/agents must not assemble observation identity locally. Scope binding
consumes the Detection Scope Phase 0 contract (#625).
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

import orjson
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.behavior_observation import (
    BEHAVIOR_OBSERVATION_PROJECTION_SCHEMA_VERSION,
    BEHAVIOR_OBSERVATION_SCHEMA_VERSION,
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationProvenance,
    BehaviorObservationSourceRef,
)
from app.models.detection_scope import (
    DetectionScopeConnectorSet,
    DetectionScopeIdentity,
    DetectionScopeLifecycleState,
)
from app.models.enums import SourceObjectKind
from app.services.detection_scope_resolver import build_detection_scope_id

_RAW_PAYLOAD_KEY_PATTERN = re.compile(
    r"^(raw_payload|password|secret|token|credential)",
    re.IGNORECASE,
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def _sanitize_attributes(normalized: dict[str, Any]) -> dict[str, Any]:
    """Keep semantic attributes only; strip raw/sensitive keys."""
    cleaned: dict[str, Any] = {}
    for key, value in normalized.items():
        if _RAW_PAYLOAD_KEY_PATTERN.match(key) or key == "risk_score":
            continue
        if isinstance(value, dict):
            nested = _sanitize_attributes(value)
            if nested:
                cleaned[key] = nested
            continue
        cleaned[key] = value
    return cleaned


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(100.0, score))


def _extract_entity_refs(normalized: dict[str, Any]) -> list[BehaviorEntityRef]:
    refs: list[BehaviorEntityRef] = []
    seen: set[tuple[str, str, str | None]] = set()

    def _add(entity_type: str, entity_id: object | None, *, role: str | None) -> None:
        if entity_id is None:
            return
        text = str(entity_id).strip()
        if not text:
            return
        key = (entity_type, text, role)
        if key in seen:
            return
        seen.add(key)
        refs.append(BehaviorEntityRef(entity_type=entity_type, entity_id=text, role=role))

    mapping = (
        ("src_ip", "ip", "src"),
        ("dst_ip", "ip", "dst"),
        ("source_ip", "ip", "src"),
        ("ip", "ip", None),
        ("hostname", "host", None),
        ("asset_name", "asset", None),
        ("owner", "user", None),
        ("user", "user", None),
        ("account", "user", None),
    )
    for field, entity_type, role in mapping:
        _add(entity_type, normalized.get(field), role=role)
    return refs


def _observed_at_from_row(row: orm.SourceObject) -> datetime:
    normalized = row.normalized if isinstance(row.normalized, dict) else {}
    for key in ("logged_at", "last_seen_at", "first_seen_at", "occurred_at"):
        candidate = normalized.get(key)
        if isinstance(candidate, str):
            try:
                return datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            except ValueError:
                continue
        if isinstance(candidate, datetime):
            return candidate if candidate.tzinfo else candidate.replace(tzinfo=UTC)
    if row.source_updated_at is not None:
        return row.source_updated_at
    if row.ingested_at is not None:
        return row.ingested_at
    return datetime.now(UTC)


def _connector_integration_instance_id(
    connector: orm.SourceConnector | None,
    *,
    connector_id: str,
) -> str:
    metadata = dict(connector.connector_metadata or {}) if connector is not None else {}
    return str(metadata.get("integration_instance_id") or connector_id)


def _metadata_fallback_scope_id(
    *,
    connector: orm.SourceConnector | None,
    source_tenant_id: str,
    source_product: str,
    integration_instance_id: str,
) -> str:
    """Bootstrap scope id from connector metadata when no ACTIVE scope is registered."""
    metadata = dict(connector.connector_metadata or {}) if connector is not None else {}
    identity = DetectionScopeIdentity(
        source_tenant_id=source_tenant_id,
        source_product=source_product,
        integration_instance_id=integration_instance_id,
        environment=metadata.get("environment"),
        region=metadata.get("region"),
    )
    connector_set_version = int(metadata.get("connector_set_version") or 1)
    if connector_set_version < 1:
        raise ValidationError("connector_set_version must be >= 1")
    return build_detection_scope_id(identity, connector_set_version=connector_set_version)


async def resolve_detection_scope_id(
    session: AsyncSession,
    *,
    source_tenant_id: str,
    source_product: str,
    connector_id: str,
) -> str:
    """Bind connector to a canonical detection scope id (#625 contract)."""
    connector = await session.get(orm.SourceConnector, connector_id)
    integration_instance_id = _connector_integration_instance_id(
        connector,
        connector_id=connector_id,
    )

    active_rows = list(
        await session.scalars(
            select(orm.DetectionScopeRevision)
            .where(
                and_(
                    orm.DetectionScopeRevision.source_tenant_id == source_tenant_id,
                    orm.DetectionScopeRevision.source_product == source_product,
                    orm.DetectionScopeRevision.lifecycle_state
                    == DetectionScopeLifecycleState.ACTIVE.value,
                )
            )
            .order_by(orm.DetectionScopeRevision.integration_instance_id.asc())
        )
    )
    if not active_rows:
        return _metadata_fallback_scope_id(
            connector=connector,
            source_tenant_id=source_tenant_id,
            source_product=source_product,
            integration_instance_id=integration_instance_id,
        )

    instance_scopes = [
        row for row in active_rows if row.integration_instance_id == integration_instance_id
    ]
    if not instance_scopes:
        return _metadata_fallback_scope_id(
            connector=connector,
            source_tenant_id=source_tenant_id,
            source_product=source_product,
            integration_instance_id=integration_instance_id,
        )

    matching_scope_ids: list[str] = []
    for scope_row in instance_scopes:
        connector_set = DetectionScopeConnectorSet.model_validate(scope_row.connector_set)
        if any(member.connector_id == connector_id for member in connector_set.upstream_connectors):
            matching_scope_ids.append(scope_row.detection_scope_id)

    if len(matching_scope_ids) == 1:
        return matching_scope_ids[0]
    if len(matching_scope_ids) > 1:
        raise ValidationError(
            "ambiguous detection scope binding for connector",
            details={
                "connector_id": connector_id,
                "integration_instance_id": integration_instance_id,
                "detection_scope_ids": matching_scope_ids,
            },
        )

    raise ValidationError(
        "connector not in active detection scope connector set",
        details={
            "connector_id": connector_id,
            "integration_instance_id": integration_instance_id,
            "source_tenant_id": source_tenant_id,
            "source_product": source_product,
        },
    )


def build_observation_idempotency_key(
    *,
    source_tenant_id: str,
    detection_scope_id: str,
    source_kind: str,
    source_object_id: str,
    source_revision: int,
    projection_schema_version: str = BEHAVIOR_OBSERVATION_PROJECTION_SCHEMA_VERSION,
) -> str:
    return (
        f"{source_tenant_id}:{detection_scope_id}:{source_kind}:"
        f"{source_object_id}:rev{source_revision}:psv{projection_schema_version}"
    )


def build_observation_id(*, idempotency_key: str) -> str:
    digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:12]
    return f"bobs-{digest}"


def compute_observation_content_hash(payload: dict[str, Any]) -> str:
    content_keys = (
        "observation_id",
        "source_tenant_id",
        "detection_scope_id",
        "source_ref",
        "observed_at",
        "ingested_at",
        "entity_refs",
        "action",
        "category",
        "normalized_attributes",
        "detection_score",
        "schema_version",
        "projection_schema_version",
        "provenance",
        "supersedes_observation_id",
    )
    canonical = {key: payload[key] for key in content_keys if key in payload}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def compute_observation_hash(payload: dict[str, Any]) -> str:
    exclude = frozenset({"observation_hash", "idempotency_key", "created_at"})
    canonical = {key: value for key, value in payload.items() if key not in exclude}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def build_behavior_observation(
    *,
    row: orm.SourceObject,
    detection_scope_id: str,
    supersedes_observation_id: str | None = None,
) -> BehaviorObservation:
    if row.source_kind == SourceObjectKind.CONNECTOR.value:
        raise ValidationError("connector source objects cannot produce behavior observations")

    normalized = dict(row.normalized or {})
    source_ref = BehaviorObservationSourceRef(
        source_product=row.source_product,
        connector_id=row.connector_id,
        source_kind=row.source_kind,
        source_object_id=row.source_object_id,
        source_object_type=row.source_object_type,
        source_revision=int(row.current_state_version),
    )
    idempotency_key = build_observation_idempotency_key(
        source_tenant_id=row.source_tenant_id,
        detection_scope_id=detection_scope_id,
        source_kind=row.source_kind,
        source_object_id=row.source_object_id,
        source_revision=int(row.current_state_version),
    )
    observation_id = build_observation_id(idempotency_key=idempotency_key)
    observed_at = _observed_at_from_row(row)
    ingested_at = row.ingested_at or datetime.now(UTC)
    entity_refs = _extract_entity_refs(normalized)
    action = normalized.get("action") or normalized.get("event_action")
    category = normalized.get("category") or normalized.get("channel")
    detection_score = _optional_float(normalized.get("detection_score"))
    if detection_score is None and normalized.get("risk_score") is not None:
        # Explicitly ignore risk_score for detection semantics.
        detection_score = None

    provenance = BehaviorObservationProvenance(
        source_record_id=row.source_record_id,
        raw_payload_hash=row.raw_payload_hash,
        source_concurrency_token=row.current_concurrency_token,
    )
    body = {
        "observation_id": observation_id,
        "source_tenant_id": row.source_tenant_id,
        "detection_scope_id": detection_scope_id,
        "source_ref": source_ref.model_dump(mode="json"),
        "observed_at": observed_at.isoformat(),
        "ingested_at": ingested_at.isoformat(),
        "entity_refs": [item.model_dump(mode="json") for item in entity_refs],
        "action": action,
        "category": category,
        "normalized_attributes": _sanitize_attributes(normalized),
        "detection_score": detection_score,
        "schema_version": BEHAVIOR_OBSERVATION_SCHEMA_VERSION,
        "projection_schema_version": BEHAVIOR_OBSERVATION_PROJECTION_SCHEMA_VERSION,
        "provenance": provenance.model_dump(mode="json"),
        "supersedes_observation_id": supersedes_observation_id,
    }
    content_hash = compute_observation_content_hash(body)
    observation_hash = compute_observation_hash({**body, "content_hash": content_hash})
    return BehaviorObservation(
        observation_id=observation_id,
        source_tenant_id=row.source_tenant_id,
        detection_scope_id=detection_scope_id,
        source_ref=source_ref,
        observed_at=observed_at,
        ingested_at=ingested_at,
        entity_refs=entity_refs,
        action=str(action) if action is not None else None,
        category=str(category) if category is not None else None,
        normalized_attributes=_sanitize_attributes(normalized),
        detection_score=detection_score,
        content_hash=content_hash,
        observation_hash=observation_hash,
        idempotency_key=idempotency_key,
        provenance=provenance,
        supersedes_observation_id=supersedes_observation_id,
        schema_version=BEHAVIOR_OBSERVATION_SCHEMA_VERSION,
        projection_schema_version=BEHAVIOR_OBSERVATION_PROJECTION_SCHEMA_VERSION,
    )
