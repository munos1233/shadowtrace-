"""Unit tests for SnapshotDiffer tolerances (ISSUE-087)."""

from __future__ import annotations

from tests.regression.snapshot import SnapshotDiffer


def _base_snapshot() -> dict:
    return {
        "schema_version": 1,
        "scenario_id": "insider_data_exfiltration",
        "final_verdict": "confirmed_threat",
        "risk_score": 82,
        "executed_actions": ["create_ticket", "isolate_host"],
        "dispositions": [
            {
                "operation": "isolate_host",
                "execution_owner": "xdr_managed",
                "writeback_status": "confirmed",
            }
        ],
        "trajectory_metrics": {"evidence_yield": 1.0, "steps_to_verdict": 10.0},
        "quality_scores": {"triage": 0.80, "risk": 0.75},
    }


def test_diff_zero_when_snapshots_match() -> None:
    baseline = _base_snapshot()
    drifts = SnapshotDiffer().diff(baseline, dict(baseline))
    assert drifts == []


def test_final_verdict_mismatch_is_block() -> None:
    current = _base_snapshot()
    current["final_verdict"] = "false_positive"
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert any(item.field == "final_verdict" and item.severity == "block" for item in drifts)


def test_executed_actions_mismatch_is_block() -> None:
    current = _base_snapshot()
    current["executed_actions"] = ["create_ticket"]
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert any(item.field == "executed_actions" and item.severity == "block" for item in drifts)


def test_executed_actions_order_only_is_not_block() -> None:
    baseline = _base_snapshot()
    current = _base_snapshot()
    current["executed_actions"] = ["isolate_host", "create_ticket"]
    drifts = SnapshotDiffer().diff(baseline, current)
    assert not SnapshotDiffer.blocking_drifts(drifts)


def test_dispositions_mismatch_is_block() -> None:
    current = _base_snapshot()
    current["dispositions"] = [
        {
            "operation": "isolate_host",
            "execution_owner": "xdr_managed",
            "writeback_status": "failed",
        }
    ]
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert any(item.field == "dispositions" and item.severity == "block" for item in drifts)


def test_schema_version_mismatch_is_block() -> None:
    current = _base_snapshot()
    current["schema_version"] = 2
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert any(item.field == "schema_version" and item.severity == "block" for item in drifts)


def test_risk_score_within_tolerance_passes() -> None:
    current = _base_snapshot()
    current["risk_score"] = 86
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert not SnapshotDiffer.blocking_drifts(drifts)


def test_risk_score_at_tolerance_boundary_passes() -> None:
    current = _base_snapshot()
    current["risk_score"] = 87
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert not SnapshotDiffer.blocking_drifts(drifts)


def test_risk_score_beyond_tolerance_blocks() -> None:
    current = _base_snapshot()
    current["risk_score"] = 88
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert any(item.field == "risk_score" and item.severity == "block" for item in drifts)


def test_trajectory_metric_drift_over_twenty_percent_is_warn_only() -> None:
    current = _base_snapshot()
    current["trajectory_metrics"] = {"evidence_yield": 0.7, "steps_to_verdict": 10.0}
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert not SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "trajectory_metrics.evidence_yield" for item in drifts)
    assert all(item.severity == "warn" for item in drifts)


def test_trajectory_metric_drift_at_twenty_percent_passes() -> None:
    current = _base_snapshot()
    current["trajectory_metrics"] = {"evidence_yield": 0.8, "steps_to_verdict": 10.0}
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert not any(item.field == "trajectory_metrics.evidence_yield" for item in drifts)


def test_zero_baseline_metric_within_absolute_tolerance_passes() -> None:
    baseline = _base_snapshot()
    current = _base_snapshot()
    baseline["trajectory_metrics"] = {"evidence_yield": 0.0, "steps_to_verdict": 10.0}
    current["trajectory_metrics"] = {"evidence_yield": 0.04, "steps_to_verdict": 10.0}
    drifts = SnapshotDiffer().diff(baseline, current)
    assert not any(item.field == "trajectory_metrics.evidence_yield" for item in drifts)


def test_quality_score_drift_is_warn_only() -> None:
    current = _base_snapshot()
    current["quality_scores"] = {"triage": 0.60, "risk": 0.75}
    drifts = SnapshotDiffer().diff(_base_snapshot(), current)
    assert not SnapshotDiffer.blocking_drifts(drifts)
    assert any(item.field == "quality_scores.triage" for item in drifts)
