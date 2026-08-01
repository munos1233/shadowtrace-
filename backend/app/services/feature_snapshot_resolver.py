"""Server-owned FeatureSnapshot resolver (ISSUE-120 Phase A/B / #625).

Rules/models/agents must not assemble snapshot identity or feature vectors locally.
Event-time windows, cutoff/watermark semantics, and content hashes are canonical here.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import orjson
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.behavior_observation import BehaviorObservation
from app.models.feature_snapshot import (
    BASELINE_SCHEMA_VERSION,
    DEFAULT_ALLOWED_LATENESS,
    FEATURE_CONTRACT_VERSION,
    FEATURE_SNAPSHOT_SCHEMA_VERSION,
    MIN_OBSERVATIONS_1H,
    MIN_OBSERVATIONS_7D,
    MIN_OBSERVATIONS_24H,
    MIN_OBSERVATIONS_30D,
    DetectionBaselineStatus,
    DetectionFeatureBaseline,
    FeatureSnapshot,
    FeatureSnapshotProvenance,
    FeatureSnapshotStatus,
    FeatureWindowKind,
    SeasonalityProfile,
)
from app.services.behavior_observation_service import row_to_behavior_observation

_WINDOW_DURATIONS: dict[FeatureWindowKind, timedelta] = {
    FeatureWindowKind.ONE_HOUR: timedelta(hours=1),
    FeatureWindowKind.TWENTY_FOUR_HOURS: timedelta(hours=24),
    FeatureWindowKind.SEVEN_DAYS: timedelta(days=7),
    FeatureWindowKind.THIRTY_DAYS: timedelta(days=30),
}

_MIN_OBSERVATIONS: dict[FeatureWindowKind, int] = {
    FeatureWindowKind.ONE_HOUR: MIN_OBSERVATIONS_1H,
    FeatureWindowKind.TWENTY_FOUR_HOURS: MIN_OBSERVATIONS_24H,
    FeatureWindowKind.SEVEN_DAYS: MIN_OBSERVATIONS_7D,
    FeatureWindowKind.THIRTY_DAYS: MIN_OBSERVATIONS_30D,
}

# Minimum temporal span as a fraction of window duration for READY coverage.
_COVERAGE_FRACTION: dict[FeatureWindowKind, float] = {
    FeatureWindowKind.ONE_HOUR: 0.5,
    FeatureWindowKind.TWENTY_FOUR_HOURS: 0.25,
    FeatureWindowKind.SEVEN_DAYS: 0.2,
    FeatureWindowKind.THIRTY_DAYS: 0.15,
}


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def align_window_end(cutoff_at: datetime, window_kind: FeatureWindowKind) -> datetime:
    """UTC-aligned window end at or before cutoff (event-time semantics)."""
    cutoff = ensure_utc(cutoff_at)
    if window_kind is FeatureWindowKind.ONE_HOUR:
        aligned = cutoff.replace(minute=0, second=0, microsecond=0)
        if aligned > cutoff:
            aligned -= timedelta(hours=1)
        return aligned
    aligned = cutoff.replace(hour=0, minute=0, second=0, microsecond=0)
    if aligned > cutoff:
        aligned -= timedelta(days=1)
    return aligned


def compute_window_bounds(
    *,
    cutoff_at: datetime,
    window_kind: FeatureWindowKind,
) -> tuple[datetime, datetime]:
    window_end = align_window_end(cutoff_at, window_kind)
    duration = _WINDOW_DURATIONS[window_kind]
    window_start = window_end - duration
    return window_start, window_end


def effective_observation_upper_bound(
    *,
    window_end: datetime,
    cutoff_at: datetime,
    allowed_lateness: timedelta,
) -> datetime:
    """Inclusive event-time upper bound with lateness only near window close."""
    cutoff = ensure_utc(cutoff_at)
    end = ensure_utc(window_end)
    lateness_cap = end + allowed_lateness
    if cutoff <= lateness_cap:
        return cutoff
    return end


def observation_matches_entity(
    observation: BehaviorObservation,
    *,
    entity_type: str,
    entity_id: str,
) -> bool:
    for ref in observation.entity_refs:
        if ref.entity_type == entity_type and ref.entity_id == entity_id:
            return True
    return False


def filter_observations_for_entity(
    observations: list[BehaviorObservation],
    *,
    entity_type: str,
    entity_id: str,
    window_start: datetime,
    upper_bound: datetime,
) -> list[BehaviorObservation]:
    start = ensure_utc(window_start)
    upper = ensure_utc(upper_bound)
    matched: list[BehaviorObservation] = []
    for obs in observations:
        observed = ensure_utc(obs.observed_at)
        if observed < start or observed > upper:
            continue
        if observation_matches_entity(obs, entity_type=entity_type, entity_id=entity_id):
            matched.append(obs)
    matched.sort(key=lambda item: (item.observed_at, item.observation_id))
    return matched


def _aggregate_features(observations: list[BehaviorObservation]) -> dict[str, Any]:
    action_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    scores: list[float] = []
    for obs in observations:
        if obs.action:
            action_counts[obs.action] = action_counts.get(obs.action, 0) + 1
        if obs.category:
            category_counts[obs.category] = category_counts.get(obs.category, 0) + 1
        if obs.detection_score is not None:
            scores.append(obs.detection_score)
    features: dict[str, Any] = {
        "observation_count": len(observations),
        "unique_action_count": len(action_counts),
        "unique_category_count": len(category_counts),
        "action_counts": action_counts,
        "category_counts": category_counts,
    }
    if scores:
        features["avg_detection_score"] = round(sum(scores) / len(scores), 4)
        features["max_detection_score"] = max(scores)
    return features


def _evaluate_readiness(
    observations: list[BehaviorObservation],
    *,
    window_kind: FeatureWindowKind,
    window_start: datetime,
    window_end: datetime,
) -> FeatureSnapshotStatus:
    min_count = _MIN_OBSERVATIONS[window_kind]
    if len(observations) < min_count:
        return FeatureSnapshotStatus.INSUFFICIENT_HISTORY

    duration = _WINDOW_DURATIONS[window_kind]
    required_span = duration * _COVERAGE_FRACTION[window_kind]
    first_at = ensure_utc(observations[0].observed_at)
    last_at = ensure_utc(observations[-1].observed_at)
    if last_at - first_at < required_span:
        return FeatureSnapshotStatus.INSUFFICIENT_COVERAGE
    return FeatureSnapshotStatus.READY


def compute_snapshot_content_hash(payload: dict[str, Any]) -> str:
    content_keys = (
        "source_tenant_id",
        "detection_scope_id",
        "entity_type",
        "entity_id",
        "feature_contract_version",
        "window_kind",
        "window_start",
        "window_end",
        "cutoff_at",
        "allowed_lateness_seconds",
        "source_watermark",
        "status",
        "features",
        "provenance",
        "revision",
        "schema_version",
    )
    canonical = {key: payload[key] for key in content_keys if key in payload}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def build_snapshot_idempotency_key(
    *,
    detection_scope_id: str,
    entity_type: str,
    entity_id: str,
    feature_contract_version: str,
    window_kind: FeatureWindowKind,
    window_end: datetime,
    cutoff_at: datetime,
    revision: int,
) -> str:
    window_end_iso = ensure_utc(window_end).isoformat()
    cutoff_iso = ensure_utc(cutoff_at).isoformat()
    return (
        f"{detection_scope_id}:{entity_type}:{entity_id}:"
        f"{feature_contract_version}:{window_kind.value}:{window_end_iso}:{cutoff_iso}:rev{revision}"
    )


def build_snapshot_id(*, content_hash: str, revision: int) -> str:
    digest = hashlib.sha256(f"{content_hash}|rev{revision}".encode()).hexdigest()[:12]
    return f"fsnap-{digest}"


def build_feature_snapshot(
    *,
    source_tenant_id: str,
    detection_scope_id: str,
    entity_type: str,
    entity_id: str,
    window_kind: FeatureWindowKind,
    cutoff_at: datetime,
    observations: list[BehaviorObservation],
    revision: int = 1,
    supersedes_snapshot_id: str | None = None,
    allowed_lateness: timedelta = DEFAULT_ALLOWED_LATENESS,
    feature_contract_version: str = FEATURE_CONTRACT_VERSION,
    snapshot_id: str | None = None,
) -> FeatureSnapshot:
    if revision < 1:
        raise ValidationError("revision must be >= 1")

    window_start, window_end = compute_window_bounds(
        cutoff_at=cutoff_at,
        window_kind=window_kind,
    )
    upper = effective_observation_upper_bound(
        window_end=window_end,
        cutoff_at=cutoff_at,
        allowed_lateness=allowed_lateness,
    )
    matched = filter_observations_for_entity(
        observations,
        entity_type=entity_type,
        entity_id=entity_id,
        window_start=window_start,
        upper_bound=upper,
    )
    status = _evaluate_readiness(
        matched,
        window_kind=window_kind,
        window_start=window_start,
        window_end=window_end,
    )
    features = _aggregate_features(matched) if status is FeatureSnapshotStatus.READY else {}
    source_watermark = (
        min(ensure_utc(cutoff_at), ensure_utc(matched[-1].observed_at))
        if matched
        else ensure_utc(cutoff_at)
    )
    provenance = FeatureSnapshotProvenance(
        observation_ids=[obs.observation_id for obs in matched],
        observation_count=len(matched),
        first_observed_at=matched[0].observed_at if matched else None,
        last_observed_at=matched[-1].observed_at if matched else None,
    )
    body = {
        "source_tenant_id": source_tenant_id,
        "detection_scope_id": detection_scope_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "feature_contract_version": feature_contract_version,
        "window_kind": window_kind.value,
        "window_start": ensure_utc(window_start).isoformat(),
        "window_end": ensure_utc(window_end).isoformat(),
        "cutoff_at": ensure_utc(cutoff_at).isoformat(),
        "allowed_lateness_seconds": int(allowed_lateness.total_seconds()),
        "source_watermark": source_watermark.isoformat(),
        "status": status.value,
        "features": features,
        "provenance": provenance.model_dump(mode="json"),
        "revision": revision,
        "schema_version": FEATURE_SNAPSHOT_SCHEMA_VERSION,
    }
    content_hash = compute_snapshot_content_hash(body)
    resolved_id = snapshot_id or build_snapshot_id(content_hash=content_hash, revision=revision)
    idempotency_key = build_snapshot_idempotency_key(
        detection_scope_id=detection_scope_id,
        entity_type=entity_type,
        entity_id=entity_id,
        feature_contract_version=feature_contract_version,
        window_kind=window_kind,
        window_end=window_end,
        cutoff_at=cutoff_at,
        revision=revision,
    )
    return FeatureSnapshot(
        snapshot_id=resolved_id,
        source_tenant_id=source_tenant_id,
        detection_scope_id=detection_scope_id,
        entity_type=entity_type,
        entity_id=entity_id,
        feature_contract_version=feature_contract_version,
        window_kind=window_kind,
        window_start=window_start,
        window_end=window_end,
        cutoff_at=ensure_utc(cutoff_at),
        allowed_lateness_seconds=int(allowed_lateness.total_seconds()),
        source_watermark=source_watermark,
        status=status,
        features=features,
        provenance=provenance,
        revision=revision,
        supersedes_snapshot_id=supersedes_snapshot_id,
        content_hash=content_hash,
        cache_key=content_hash,
        idempotency_key=idempotency_key,
    )


def derive_peer_group_id(*, entity_type: str, primary_category: str | None) -> str:
    """MVP peer label: entity_type + dominant category bucket (not cross-entity cohort yet)."""
    material = f"{entity_type}|{primary_category or '_none_'}"
    digest = hashlib.sha256(material.encode()).hexdigest()[:10]
    return f"peer-{digest}"


def _primary_category_from_features(features: dict[str, Any]) -> str | None:
    counts = features.get("category_counts")
    if not isinstance(counts, dict) or not counts:
        return None
    return max(counts.items(), key=lambda item: (item[1], item[0]))[0]


def compute_baseline_content_hash(payload: dict[str, Any]) -> str:
    content_keys = (
        "source_tenant_id",
        "detection_scope_id",
        "entity_type",
        "entity_id",
        "peer_group_id",
        "feature_contract_version",
        "window_kind",
        "cutoff_at",
        "status",
        "stats",
        "seasonality_profile",
        "snapshot_revision_refs",
        "revision",
        "schema_version",
    )
    canonical = {key: payload[key] for key in content_keys if key in payload}
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def build_baseline_idempotency_key(
    *,
    detection_scope_id: str,
    entity_type: str,
    entity_id: str,
    window_kind: FeatureWindowKind,
    cutoff_at: datetime,
    revision: int,
) -> str:
    cutoff_iso = ensure_utc(cutoff_at).isoformat()
    return (
        f"{detection_scope_id}:{entity_type}:{entity_id}:{window_kind.value}:"
        f"{cutoff_iso}:rev{revision}"
    )


def build_baseline_id(*, content_hash: str, revision: int) -> str:
    digest = hashlib.sha256(f"{content_hash}|baseline|rev{revision}".encode()).hexdigest()[:12]
    return f"fbase-{digest}"


def dedupe_latest_snapshot_revisions(snapshots: list[FeatureSnapshot]) -> list[FeatureSnapshot]:
    """Keep highest revision per (window_end, cutoff_at) — superseded rows excluded."""
    latest: dict[tuple[datetime, datetime], FeatureSnapshot] = {}
    for snap in snapshots:
        key = (ensure_utc(snap.window_end), ensure_utc(snap.cutoff_at))
        current = latest.get(key)
        if current is None or snap.revision > current.revision:
            latest[key] = snap
    return sorted(latest.values(), key=lambda item: (item.cutoff_at, item.revision))


def dedupe_latest_snapshots_by_entity(snapshots: list[FeatureSnapshot]) -> list[FeatureSnapshot]:
    """Keep highest revision per entity — for rule runtime snapshot scans at fixed cutoff."""
    latest: dict[tuple[str, str], FeatureSnapshot] = {}
    for snap in snapshots:
        key = (snap.entity_type, snap.entity_id)
        current = latest.get(key)
        if current is None or snap.revision > current.revision:
            latest[key] = snap
    return sorted(
        latest.values(), key=lambda item: (item.entity_type, item.entity_id, item.revision)
    )


def _build_seasonality_profile(snapshots: list[FeatureSnapshot]) -> SeasonalityProfile:
    hour_of_week: dict[str, int] = {}
    ready_count = 0
    for snap in snapshots:
        if snap.status is not FeatureSnapshotStatus.READY:
            continue
        ready_count += 1
        observed = ensure_utc(snap.window_end)
        key = str(observed.weekday() * 24 + observed.hour)
        hour_of_week[key] = hour_of_week.get(key, 0) + 1
    return SeasonalityProfile(hour_of_week=hour_of_week, sample_snapshot_count=ready_count)


def build_detection_feature_baseline(
    *,
    source_tenant_id: str,
    detection_scope_id: str,
    entity_type: str,
    entity_id: str,
    window_kind: FeatureWindowKind,
    cutoff_at: datetime,
    snapshots: list[FeatureSnapshot],
    revision: int = 1,
    supersedes_baseline_id: str | None = None,
    baseline_id: str | None = None,
    feature_contract_version: str = FEATURE_CONTRACT_VERSION,
) -> DetectionFeatureBaseline:
    """Aggregate baseline from snapshots at or before cutoff — no post-cutoff leakage."""
    cutoff = ensure_utc(cutoff_at)
    deduped = dedupe_latest_snapshot_revisions(snapshots)
    eligible = [
        snap
        for snap in deduped
        if snap.status is FeatureSnapshotStatus.READY and ensure_utc(snap.cutoff_at) <= cutoff
    ]
    eligible.sort(key=lambda item: (item.cutoff_at, item.snapshot_id))

    min_required = max(2, _MIN_OBSERVATIONS[window_kind] // 2)
    if len(eligible) < min_required:
        status = DetectionBaselineStatus.INSUFFICIENT_HISTORY
        stats: dict[str, Any] = {}
    else:
        scores = [
            float(snap.features["avg_detection_score"])
            for snap in eligible
            if isinstance(snap.features.get("avg_detection_score"), (int, float))
        ]
        counts = [int(snap.features.get("observation_count", 0)) for snap in eligible]
        if len(scores) < min_required:
            status = DetectionBaselineStatus.INSUFFICIENT_COVERAGE
            stats = {"snapshot_count": len(eligible)}
        else:
            status = DetectionBaselineStatus.READY
            mean_score = sum(scores) / len(scores)
            variance = sum((value - mean_score) ** 2 for value in scores) / len(scores)
            stats = {
                "snapshot_count": len(eligible),
                "mean_avg_detection_score": round(mean_score, 4),
                "std_avg_detection_score": round(variance**0.5, 4),
                "mean_observation_count": round(sum(counts) / len(counts), 4),
                "max_observation_count": max(counts),
            }

    latest = eligible[-1] if eligible else None
    peer_group_id = (
        derive_peer_group_id(
            entity_type=entity_type,
            primary_category=_primary_category_from_features(latest.features) if latest else None,
        )
        if latest
        else None
    )
    seasonality = _build_seasonality_profile(eligible) if eligible else None
    snapshot_refs = [snap.snapshot_id for snap in eligible[-16:]]

    body = {
        "source_tenant_id": source_tenant_id,
        "detection_scope_id": detection_scope_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "peer_group_id": peer_group_id,
        "feature_contract_version": feature_contract_version,
        "window_kind": window_kind.value,
        "cutoff_at": cutoff.isoformat(),
        "status": status.value,
        "stats": stats,
        "seasonality_profile": seasonality.model_dump(mode="json") if seasonality else None,
        "snapshot_revision_refs": snapshot_refs,
        "revision": revision,
        "schema_version": BASELINE_SCHEMA_VERSION,
    }
    content_hash = compute_baseline_content_hash(body)
    resolved_id = baseline_id or build_baseline_id(content_hash=content_hash, revision=revision)
    idempotency_key = build_baseline_idempotency_key(
        detection_scope_id=detection_scope_id,
        entity_type=entity_type,
        entity_id=entity_id,
        window_kind=window_kind,
        cutoff_at=cutoff,
        revision=revision,
    )
    return DetectionFeatureBaseline(
        baseline_id=resolved_id,
        source_tenant_id=source_tenant_id,
        detection_scope_id=detection_scope_id,
        entity_type=entity_type,
        entity_id=entity_id,
        peer_group_id=peer_group_id,
        feature_contract_version=feature_contract_version,
        window_kind=window_kind,
        cutoff_at=cutoff,
        status=status,
        stats=stats,
        seasonality_profile=seasonality,
        snapshot_revision_refs=snapshot_refs,
        revision=revision,
        supersedes_baseline_id=supersedes_baseline_id,
        content_hash=content_hash,
        cache_key=content_hash,
        idempotency_key=idempotency_key,
    )


class FeatureSnapshotResolver:
    """High-level resolver entry points for services and tests."""

    async def load_observations_for_window(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        window_start: datetime,
        upper_bound: datetime,
    ) -> list[BehaviorObservation]:
        rows = list(
            await session.scalars(
                select(orm.BehaviorObservation)
                .where(
                    and_(
                        orm.BehaviorObservation.source_tenant_id == source_tenant_id,
                        orm.BehaviorObservation.detection_scope_id == detection_scope_id,
                        orm.BehaviorObservation.observed_at >= ensure_utc(window_start),
                        orm.BehaviorObservation.observed_at <= ensure_utc(upper_bound),
                    )
                )
                .order_by(orm.BehaviorObservation.observed_at.asc())
            )
        )
        return [row_to_behavior_observation(row) for row in rows]

    async def materialize_snapshot(
        self,
        session: AsyncSession,
        *,
        source_tenant_id: str,
        detection_scope_id: str,
        entity_type: str,
        entity_id: str,
        window_kind: FeatureWindowKind,
        cutoff_at: datetime,
        revision: int = 1,
        supersedes_snapshot_id: str | None = None,
        allowed_lateness: timedelta = DEFAULT_ALLOWED_LATENESS,
    ) -> FeatureSnapshot:
        window_start, window_end = compute_window_bounds(
            cutoff_at=cutoff_at,
            window_kind=window_kind,
        )
        upper = effective_observation_upper_bound(
            window_end=window_end,
            cutoff_at=cutoff_at,
            allowed_lateness=allowed_lateness,
        )
        observations = await self.load_observations_for_window(
            session,
            source_tenant_id=source_tenant_id,
            detection_scope_id=detection_scope_id,
            window_start=window_start,
            upper_bound=upper,
        )
        return build_feature_snapshot(
            source_tenant_id=source_tenant_id,
            detection_scope_id=detection_scope_id,
            entity_type=entity_type,
            entity_id=entity_id,
            window_kind=window_kind,
            cutoff_at=cutoff_at,
            observations=observations,
            revision=revision,
            supersedes_snapshot_id=supersedes_snapshot_id,
            allowed_lateness=allowed_lateness,
        )


def row_to_feature_snapshot(row: orm.FeatureSnapshot) -> FeatureSnapshot:
    return FeatureSnapshot(
        snapshot_id=row.snapshot_id,
        source_tenant_id=row.source_tenant_id,
        detection_scope_id=row.detection_scope_id,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        feature_contract_version=row.feature_contract_version,
        window_kind=FeatureWindowKind(row.window_kind),
        window_start=row.window_start,
        window_end=row.window_end,
        cutoff_at=row.cutoff_at,
        allowed_lateness_seconds=row.allowed_lateness_seconds,
        source_watermark=row.source_watermark,
        status=FeatureSnapshotStatus(row.status),
        features=dict(row.features or {}),
        provenance=FeatureSnapshotProvenance.model_validate(row.provenance),
        revision=int(row.revision),
        supersedes_snapshot_id=row.supersedes_snapshot_id,
        content_hash=row.content_hash,
        cache_key=row.cache_key,
        idempotency_key=row.idempotency_key,
        schema_version=row.schema_version,
        created_at=row.created_at,
    )


def row_to_detection_baseline(row: orm.DetectionFeatureBaseline) -> DetectionFeatureBaseline:
    seasonality = (
        SeasonalityProfile.model_validate(row.seasonality_profile)
        if row.seasonality_profile
        else None
    )
    return DetectionFeatureBaseline(
        baseline_id=row.baseline_id,
        source_tenant_id=row.source_tenant_id,
        detection_scope_id=row.detection_scope_id,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        peer_group_id=row.peer_group_id,
        feature_contract_version=row.feature_contract_version,
        window_kind=FeatureWindowKind(row.window_kind),
        cutoff_at=row.cutoff_at,
        status=DetectionBaselineStatus(row.status),
        stats=dict(row.stats or {}),
        seasonality_profile=seasonality,
        snapshot_revision_refs=list(row.snapshot_revision_refs or []),
        revision=int(row.revision),
        supersedes_baseline_id=row.supersedes_baseline_id,
        content_hash=row.content_hash,
        cache_key=row.cache_key,
        idempotency_key=row.idempotency_key,
        schema_version=row.schema_version,
        created_at=row.created_at,
    )
