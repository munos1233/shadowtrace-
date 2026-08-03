"""Unit tests for anomaly scorer (ISSUE-122 / #627)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.errors import ValidationError
from app.detection.scoring.anomaly_scorer import score_snapshot
from app.detection.scoring.release import MOCK_ACCOUNT_MAD_RELEASE
from app.models.feature_snapshot import (
    DetectionBaselineStatus,
    DetectionFeatureBaseline,
    FeatureSnapshot,
    FeatureSnapshotProvenance,
    FeatureSnapshotStatus,
    FeatureWindowKind,
)


def _snapshot(
    *,
    status: FeatureSnapshotStatus = FeatureSnapshotStatus.READY,
    features: dict[str, float] | None = None,
) -> FeatureSnapshot:
    cutoff = datetime(2026, 8, 3, 15, 30, 0, tzinfo=UTC)
    body_features = features or {
        "observation_count": 3.0,
        "avg_detection_score": 50.0,
        "unique_action_count": 2.0,
    }
    return FeatureSnapshot(
        snapshot_id="fsnap-test",
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="user",
        entity_id="account-1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        window_start=datetime(2026, 8, 3, 14, 30, 0, tzinfo=UTC),
        window_end=datetime(2026, 8, 3, 15, 0, 0, tzinfo=UTC),
        cutoff_at=cutoff,
        source_watermark=cutoff,
        status=status,
        features=body_features,
        provenance=FeatureSnapshotProvenance(observation_count=3),
        content_hash="a" * 64,
        cache_key="a" * 64,
        idempotency_key="idem-snap",
    )


def _baseline(*, stats: dict | None = None) -> DetectionFeatureBaseline:
    cutoff = datetime(2026, 8, 3, 15, 30, 0, tzinfo=UTC)
    default_stats = {
        "snapshot_count": 3,
        "robust": {
            "observation_count": {"median": 3.0, "mad": 0.5, "p25": 2.0, "p75": 4.0, "p95": 5.0},
            "avg_detection_score": {
                "median": 50.0,
                "mad": 2.0,
                "p25": 48.0,
                "p75": 52.0,
                "p95": 55.0,
            },
            "unique_action_count": {"median": 2.0, "mad": 0.5, "p25": 2.0, "p75": 2.0, "p95": 2.0},
        },
    }
    return DetectionFeatureBaseline(
        baseline_id="fbase-test",
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="user",
        entity_id="account-1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
        status=DetectionBaselineStatus.READY,
        stats=stats if stats is not None else default_stats,
        content_hash="b" * 64,
        cache_key="b" * 64,
        idempotency_key="idem-base",
    )


def test_insufficient_history_snapshot_fail_closed() -> None:
    with pytest.raises(ValidationError, match="insufficient history"):
        score_snapshot(
            snapshot=_snapshot(status=FeatureSnapshotStatus.INSUFFICIENT_HISTORY),
            baseline=_baseline(),
            release=MOCK_ACCOUNT_MAD_RELEASE,
            robust_z_threshold=3.5,
        )


def test_insufficient_history_baseline_fail_closed() -> None:
    cutoff = datetime(2026, 8, 3, 15, 30, 0, tzinfo=UTC)
    baseline = DetectionFeatureBaseline(
        baseline_id="fbase-test",
        source_tenant_id="tenant-a",
        detection_scope_id="dscope-test",
        entity_type="user",
        entity_id="account-1",
        window_kind=FeatureWindowKind.ONE_HOUR,
        cutoff_at=cutoff,
        status=DetectionBaselineStatus.INSUFFICIENT_HISTORY,
        stats={},
        content_hash="b" * 64,
        cache_key="b" * 64,
        idempotency_key="idem-base",
    )
    with pytest.raises(ValidationError, match="baseline insufficient history"):
        score_snapshot(
            snapshot=_snapshot(),
            baseline=baseline,
            release=MOCK_ACCOUNT_MAD_RELEASE,
            robust_z_threshold=3.5,
        )


def test_release_hash_mismatch_fail_closed() -> None:
    with pytest.raises(ValidationError, match="release hash mismatch"):
        score_snapshot(
            snapshot=_snapshot(),
            baseline=_baseline(),
            release=MOCK_ACCOUNT_MAD_RELEASE,
            robust_z_threshold=3.5,
            expected_release_hash="deadbeef" * 8,
        )


def test_anomaly_score_is_deterministic() -> None:
    snapshot = _snapshot(
        features={
            "observation_count": 30.0,
            "avg_detection_score": 90.0,
            "unique_action_count": 8.0,
        }
    )
    first = score_snapshot(
        snapshot=snapshot,
        baseline=_baseline(),
        release=MOCK_ACCOUNT_MAD_RELEASE,
        robust_z_threshold=3.5,
    )
    second = score_snapshot(
        snapshot=snapshot,
        baseline=_baseline(),
        release=MOCK_ACCOUNT_MAD_RELEASE,
        robust_z_threshold=3.5,
    )
    assert first.detection_score == second.detection_score
    assert first.is_anomaly is True
    assert first.contributing_features[0].feature_name == "observation_count"


def test_normal_snapshot_not_anomaly() -> None:
    result = score_snapshot(
        snapshot=_snapshot(),
        baseline=_baseline(),
        release=MOCK_ACCOUNT_MAD_RELEASE,
        robust_z_threshold=3.5,
    )
    assert result.is_anomaly is False
    assert result.detection_score < 100.0


def test_poisoned_feature_value_fail_closed() -> None:
    with pytest.raises(ValidationError, match="poisoned feature value"):
        score_snapshot(
            snapshot=_snapshot(
                features={
                    "observation_count": float("nan"),
                    "avg_detection_score": 50.0,
                    "unique_action_count": 2.0,
                }
            ),
            baseline=_baseline(),
            release=MOCK_ACCOUNT_MAD_RELEASE,
            robust_z_threshold=3.5,
        )


def test_snapshot_baseline_binding_mismatch_fail_closed() -> None:
    baseline = _baseline()
    mismatched = DetectionFeatureBaseline(
        baseline_id=baseline.baseline_id,
        source_tenant_id="tenant-other",
        detection_scope_id=baseline.detection_scope_id,
        entity_type=baseline.entity_type,
        entity_id=baseline.entity_id,
        window_kind=baseline.window_kind,
        cutoff_at=baseline.cutoff_at,
        status=baseline.status,
        stats=baseline.stats,
        content_hash=baseline.content_hash,
        cache_key=baseline.cache_key,
        idempotency_key=baseline.idempotency_key,
    )
    with pytest.raises(ValidationError, match="binding mismatch"):
        score_snapshot(
            snapshot=_snapshot(),
            baseline=mismatched,
            release=MOCK_ACCOUNT_MAD_RELEASE,
            robust_z_threshold=3.5,
        )


def test_baseline_content_hash_mismatch_fail_closed() -> None:
    with pytest.raises(ValidationError, match="baseline content hash mismatch"):
        score_snapshot(
            snapshot=_snapshot(),
            baseline=_baseline(),
            release=MOCK_ACCOUNT_MAD_RELEASE,
            robust_z_threshold=3.5,
            expected_baseline_content_hash="deadbeef" * 8,
        )


def test_baseline_missing_release_feature_stats_fail_closed() -> None:
    partial_stats = {
        "snapshot_count": 3,
        "robust": {
            "observation_count": {"median": 3.0, "mad": 0.5, "p25": 2.0, "p75": 4.0, "p95": 5.0},
        },
    }
    with pytest.raises(ValidationError, match="baseline missing robust stats for feature"):
        score_snapshot(
            snapshot=_snapshot(),
            baseline=_baseline(stats=partial_stats),
            release=MOCK_ACCOUNT_MAD_RELEASE,
            robust_z_threshold=3.5,
        )


def test_mad_zero_feature_uses_quantile_fallback_not_silent_normal() -> None:
    stats = {
        "snapshot_count": 3,
        "robust": {
            "observation_count": {"median": 3.0, "mad": 0.5, "p25": 2.0, "p75": 4.0, "p95": 5.0},
            "avg_detection_score": {
                "median": 50.0,
                "mad": 2.0,
                "p25": 48.0,
                "p75": 52.0,
                "p95": 55.0,
            },
            "unique_action_count": {
                "median": 2.0,
                "mad": 0.0,
                "p25": 2.0,
                "p75": 4.0,
                "p95": 5.0,
            },
        },
    }
    result = score_snapshot(
        snapshot=_snapshot(
            features={
                "observation_count": 3.0,
                "avg_detection_score": 50.0,
                "unique_action_count": 8.0,
            }
        ),
        baseline=_baseline(stats=stats),
        release=MOCK_ACCOUNT_MAD_RELEASE,
        robust_z_threshold=3.5,
    )
    methods = {item.feature_name: item.scoring_method for item in result.contributing_features}
    assert methods["unique_action_count"] == "quantile_iqr"
    assert any(
        item.robust_z > 0
        for item in result.contributing_features
        if item.feature_name == "unique_action_count"
    )


def test_snapshot_baseline_cutoff_mismatch_fail_closed() -> None:
    baseline = _baseline()
    mismatched = DetectionFeatureBaseline(
        baseline_id=baseline.baseline_id,
        source_tenant_id=baseline.source_tenant_id,
        detection_scope_id=baseline.detection_scope_id,
        entity_type=baseline.entity_type,
        entity_id=baseline.entity_id,
        window_kind=baseline.window_kind,
        cutoff_at=datetime(2026, 8, 4, 15, 30, 0, tzinfo=UTC),
        status=baseline.status,
        stats=baseline.stats,
        content_hash=baseline.content_hash,
        cache_key=baseline.cache_key,
        idempotency_key=baseline.idempotency_key,
    )
    with pytest.raises(ValidationError, match="cutoff_at binding mismatch"):
        score_snapshot(
            snapshot=_snapshot(),
            baseline=mismatched,
            release=MOCK_ACCOUNT_MAD_RELEASE,
            robust_z_threshold=3.5,
        )
