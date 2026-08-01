"""Unit tests for FeatureSnapshot resolver (ISSUE-120 Phase A/B)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.behavior_observation import (
    BehaviorEntityRef,
    BehaviorObservation,
    BehaviorObservationProvenance,
    BehaviorObservationSourceRef,
)
from app.models.feature_snapshot import FeatureSnapshotStatus, FeatureWindowKind
from app.services.feature_snapshot_resolver import (
    align_window_end,
    build_detection_feature_baseline,
    build_feature_snapshot,
    compute_window_bounds,
    dedupe_latest_snapshot_revisions,
    derive_peer_group_id,
    effective_observation_upper_bound,
    ensure_utc,
)


def _observation(
    *,
    obs_id: str,
    observed_at: datetime,
    entity_id: str = "10.0.0.1",
    action: str = "create_process",
    category: str = "process_create",
    score: float = 50.0,
) -> BehaviorObservation:
    return BehaviorObservation(
        observation_id=obs_id,
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        source_ref=BehaviorObservationSourceRef(
            source_product="mock_xdr",
            connector_id="conn-a",
            source_kind="log",
            source_object_id=f"src-{obs_id}",
            source_object_type="edr",
            source_revision=1,
        ),
        observed_at=observed_at,
        ingested_at=observed_at,
        entity_refs=[BehaviorEntityRef(entity_type="ip", entity_id=entity_id, role="src")],
        action=action,
        category=category,
        detection_score=score,
        content_hash="a" * 64,
        observation_hash="b" * 64,
        idempotency_key=f"idem-{obs_id}",
        provenance=BehaviorObservationProvenance(source_record_id=f"rec-{obs_id}"),
    )


def test_align_window_end_one_hour_utc() -> None:
    cutoff = datetime(2026, 8, 1, 15, 37, 12, tzinfo=UTC)
    aligned = align_window_end(cutoff, FeatureWindowKind.ONE_HOUR)
    assert aligned == datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC)


def test_align_window_end_twenty_four_hours_utc() -> None:
    cutoff = datetime(2026, 8, 1, 15, 37, 12, tzinfo=UTC)
    aligned = align_window_end(cutoff, FeatureWindowKind.TWENTY_FOUR_HOURS)
    assert aligned == datetime(2026, 8, 1, 0, 0, 0, tzinfo=UTC)


def test_effective_upper_bound_is_leakage_safe() -> None:
    window_end = datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC)
    cutoff = datetime(2026, 8, 1, 15, 5, 0, tzinfo=UTC)
    upper = effective_observation_upper_bound(
        window_end=window_end,
        cutoff_at=cutoff,
        allowed_lateness=timedelta(minutes=15),
    )
    assert upper == cutoff


def test_effective_upper_bound_caps_at_window_end_plus_lateness() -> None:
    window_end = datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC)
    cutoff = datetime(2026, 8, 1, 15, 10, 0, tzinfo=UTC)
    upper = effective_observation_upper_bound(
        window_end=window_end,
        cutoff_at=cutoff,
        allowed_lateness=timedelta(minutes=15),
    )
    assert upper == cutoff


def test_effective_upper_bound_closes_window_after_lateness_band() -> None:
    window_end = datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC)
    cutoff = datetime(2026, 8, 1, 16, 0, 0, tzinfo=UTC)
    upper = effective_observation_upper_bound(
        window_end=window_end,
        cutoff_at=cutoff,
        allowed_lateness=timedelta(minutes=15),
    )
    assert upper == window_end


def test_build_feature_snapshot_deterministic_hash() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(minutes=50)),
        _observation(obs_id="o2", observed_at=base - timedelta(minutes=40)),
        _observation(obs_id="o3", observed_at=base - timedelta(minutes=30)),
    ]
    first = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
    )
    second = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
    )
    assert first.content_hash == second.content_hash
    assert first.cache_key == first.content_hash


def test_cold_start_insufficient_history() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(minutes=20)),
    ]
    snapshot = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
    )
    assert snapshot.status is FeatureSnapshotStatus.INSUFFICIENT_HISTORY
    assert snapshot.features == {}


def test_cold_start_insufficient_coverage() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(hours=1, minutes=25)),
        _observation(obs_id="o2", observed_at=base - timedelta(hours=1, minutes=24)),
        _observation(obs_id="o3", observed_at=base - timedelta(hours=1, minutes=23)),
    ]
    snapshot = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
    )
    assert snapshot.status is FeatureSnapshotStatus.INSUFFICIENT_COVERAGE
    assert snapshot.features == {}


def test_post_cutoff_observations_excluded() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(minutes=50)),
        _observation(obs_id="o2", observed_at=base - timedelta(minutes=40)),
        _observation(obs_id="o3", observed_at=base - timedelta(minutes=30)),
        _observation(obs_id="leak", observed_at=base + timedelta(minutes=1)),
    ]
    snapshot = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
    )
    assert "leak" not in snapshot.provenance.observation_ids
    assert snapshot.provenance.observation_count == 3


def test_late_event_time_within_lateness_included() -> None:
    window_end = datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC)
    cutoff = datetime(2026, 8, 1, 15, 10, 0, tzinfo=UTC)
    late = _observation(obs_id="late", observed_at=window_end + timedelta(minutes=5))
    on_time = [
        _observation(obs_id="o1", observed_at=window_end - timedelta(minutes=50)),
        _observation(obs_id="o2", observed_at=window_end - timedelta(minutes=40)),
        _observation(obs_id="o3", observed_at=window_end - timedelta(minutes=30)),
    ]
    snapshot = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
        observations=[*on_time, late],
    )
    assert "late" in snapshot.provenance.observation_ids


def test_observation_beyond_lateness_excluded_even_before_cutoff() -> None:
    window_end = datetime(2026, 8, 1, 15, 0, 0, tzinfo=UTC)
    cutoff = datetime(2026, 8, 1, 15, 10, 0, tzinfo=UTC)
    too_late = _observation(obs_id="too-late", observed_at=window_end + timedelta(minutes=20))
    on_time = [
        _observation(obs_id="o1", observed_at=window_end - timedelta(minutes=50)),
        _observation(obs_id="o2", observed_at=window_end - timedelta(minutes=40)),
        _observation(obs_id="o3", observed_at=window_end - timedelta(minutes=30)),
    ]
    snapshot = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
        observations=[*on_time, too_late],
    )
    assert "too-late" not in snapshot.provenance.observation_ids
    assert snapshot.provenance.observation_count == 3


def test_revision_changes_hash() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(minutes=50)),
        _observation(obs_id="o2", observed_at=base - timedelta(minutes=40)),
        _observation(obs_id="o3", observed_at=base - timedelta(minutes=30)),
    ]
    rev1 = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
        revision=1,
    )
    rev2 = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
        revision=2,
        supersedes_snapshot_id=rev1.snapshot_id,
    )
    assert rev1.content_hash != rev2.content_hash


def test_baseline_excludes_post_cutoff_snapshots() -> None:
    cutoff = datetime(2026, 8, 2, 0, 0, 0, tzinfo=UTC)
    ready_obs = [
        _observation(obs_id="a1", observed_at=datetime(2026, 8, 1, 11, 0, tzinfo=UTC)),
        _observation(obs_id="a2", observed_at=datetime(2026, 8, 1, 11, 20, tzinfo=UTC)),
        _observation(obs_id="a3", observed_at=datetime(2026, 8, 1, 11, 40, tzinfo=UTC)),
    ]
    before = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC),
        observations=ready_obs,
    )
    assert before.status is FeatureSnapshotStatus.READY
    after = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=datetime(2026, 8, 3, 0, 0, 0, tzinfo=UTC),
        observations=[
            _observation(obs_id="b1", observed_at=datetime(2026, 8, 2, 11, 0, tzinfo=UTC)),
            _observation(obs_id="b2", observed_at=datetime(2026, 8, 2, 11, 20, tzinfo=UTC)),
            _observation(obs_id="b3", observed_at=datetime(2026, 8, 2, 11, 40, tzinfo=UTC)),
        ],
    )
    baseline = build_detection_feature_baseline(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
        snapshots=[before, after],
    )
    assert after.snapshot_id not in baseline.snapshot_revision_refs
    assert before.snapshot_id in baseline.snapshot_revision_refs


def test_peer_group_id_deterministic() -> None:
    left = derive_peer_group_id(entity_type="ip", primary_category="process_create")
    right = derive_peer_group_id(entity_type="ip", primary_category="process_create")
    other = derive_peer_group_id(entity_type="ip", primary_category="network")
    assert left == right
    assert left != other


def test_seven_day_window_bounds() -> None:
    cutoff = datetime(2026, 8, 8, 12, 0, 0, tzinfo=UTC)
    start, end = compute_window_bounds(cutoff_at=cutoff, window_kind=FeatureWindowKind.SEVEN_DAYS)
    assert end == datetime(2026, 8, 8, 0, 0, 0, tzinfo=UTC)
    assert start == datetime(2026, 8, 1, 0, 0, 0, tzinfo=UTC)


def test_twenty_four_hour_window_bounds_cross_utc_midnight() -> None:
    cutoff = datetime(2026, 3, 8, 14, 30, 0, tzinfo=UTC)
    start, end = compute_window_bounds(
        cutoff_at=cutoff,
        window_kind=FeatureWindowKind.TWENTY_FOUR_HOURS,
    )
    assert end == datetime(2026, 3, 8, 0, 0, 0, tzinfo=UTC)
    assert start == datetime(2026, 3, 7, 0, 0, 0, tzinfo=UTC)


def test_naive_datetime_treated_as_utc() -> None:
    naive = datetime(2026, 8, 1, 15, 37, 12)
    assert ensure_utc(naive).tzinfo is UTC


def test_dedupe_latest_snapshot_revisions_keeps_highest_revision() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(minutes=50)),
        _observation(obs_id="o2", observed_at=base - timedelta(minutes=40)),
        _observation(obs_id="o3", observed_at=base - timedelta(minutes=30)),
    ]
    rev1 = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
        revision=1,
    )
    rev2 = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
        revision=2,
        supersedes_snapshot_id=rev1.snapshot_id,
    )
    deduped = dedupe_latest_snapshot_revisions([rev1, rev2])
    assert len(deduped) == 1
    assert deduped[0].revision == 2


def test_baseline_dedupes_superseded_snapshot_revisions() -> None:
    base = datetime(2026, 8, 1, 15, 30, 0, tzinfo=UTC)
    observations = [
        _observation(obs_id="o1", observed_at=base - timedelta(minutes=60)),
        _observation(obs_id="o2", observed_at=base - timedelta(minutes=45)),
        _observation(obs_id="o3", observed_at=base - timedelta(minutes=30)),
    ]
    rev1 = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
        revision=1,
    )
    rev2 = build_feature_snapshot(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        observations=observations,
        revision=2,
        supersedes_snapshot_id=rev1.snapshot_id,
    )
    baseline = build_detection_feature_baseline(
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="ip",
        entity_id="10.0.0.1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=base,
        snapshots=[rev1, rev2],
    )
    assert rev1.snapshot_id not in baseline.snapshot_revision_refs
    assert rev2.snapshot_id in baseline.snapshot_revision_refs
    assert baseline.stats.get("snapshot_count", 0) <= 1
