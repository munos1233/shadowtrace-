"""Unit tests for ISSUE-282 resume isolation diagnostics (no external services)."""

from __future__ import annotations

import pytest

from app.models.enums import EventStatus, ExecutionSubstate
from app.orchestration.workflow_graph import NODE_CLOSE, NODE_MANUAL_HOLD
from tests.integration.resume_isolation_support import (
    ISOLATION_PASSES,
    IsolationRunRecord,
    ResumeIsolationSnapshot,
    assert_resume_snapshot_coherent,
    build_artifact,
    detect_approval_halted_stale_anomaly,
    detect_checkpoint_close_node_anomaly,
    summarize_consecutive_runs,
)


def _snapshot(**overrides: object) -> ResumeIsolationSnapshot:
    base = {
        "phase": "post_resume",
        "graph_wired": True,
        "checkpoint_present": True,
        "halted": False,
        "needs_approval_wait": False,
        "execution_substate": ExecutionSubstate.NONE.value,
        "event_status": EventStatus.CLOSED.value,
        "db_event_status": EventStatus.CLOSED.value,
        "next_nodes": (),
        "node_trace": ("triage_node", NODE_CLOSE),
    }
    base.update(overrides)
    return ResumeIsolationSnapshot(**base)  # type: ignore[arg-type]


def test_detect_checkpoint_close_node_anomaly_when_missing() -> None:
    snap = _snapshot(
        node_trace=("triage_node", "report_node"),
        event_status=EventStatus.CLOSED.value,
    )
    detail = detect_checkpoint_close_node_anomaly(snap)
    assert detail is not None
    assert NODE_CLOSE in detail


def test_detect_checkpoint_close_node_anomaly_absent_when_present() -> None:
    assert detect_checkpoint_close_node_anomaly(_snapshot()) is None


def test_detect_approval_halted_stale_anomaly() -> None:
    snap = _snapshot(halted=True, needs_approval_wait=False)
    detail = detect_approval_halted_stale_anomaly(snap)
    assert detail is not None
    assert "incoherent halt flags" in detail


def test_detect_approval_halted_stale_anomaly_ignores_manual_hold_tail() -> None:
    snap = _snapshot(
        halted=True,
        needs_approval_wait=False,
        node_trace=("approval_node", "execute_node", "verify_node", NODE_MANUAL_HOLD),
        db_event_status=EventStatus.VERIFYING.value,
    )
    assert detect_approval_halted_stale_anomaly(snap) is None


def test_assert_resume_snapshot_coherent_rejects_wait_without_halt() -> None:
    snap = _snapshot(
        halted=False,
        needs_approval_wait=True,
        execution_substate=ExecutionSubstate.WAITING_APPROVAL.value,
    )
    with pytest.raises(AssertionError, match="needs_approval_wait=true"):
        assert_resume_snapshot_coherent(snap)


def test_summarize_consecutive_runs_not_reproduced() -> None:
    records = [
        IsolationRunRecord(
            run_index=i,
            artifact=build_artifact(
                phenomenon="checkpoint_resume_close_node",
                pre_resume=_snapshot(phase="pre_resume"),
                post_resume=_snapshot(),
                run_index=i,
            ),
        )
        for i in range(1, ISOLATION_PASSES + 1)
    ]
    summary = summarize_consecutive_runs(records)
    assert summary.verdict == "NOT_REPRODUCED"
    assert summary.consecutive_passes == ISOLATION_PASSES


def test_summarize_consecutive_runs_reproduced() -> None:
    bad_post = _snapshot(halted=True, needs_approval_wait=False)
    records = [
        IsolationRunRecord(
            run_index=1,
            artifact=build_artifact(
                phenomenon="approval_resume_halted_stale",
                pre_resume=_snapshot(phase="pre_resume", halted=True, needs_approval_wait=True),
                post_resume=bad_post,
                run_index=1,
            ),
        )
    ]
    records.extend(
        IsolationRunRecord(
            run_index=i,
            artifact=build_artifact(
                phenomenon="approval_resume_halted_stale",
                pre_resume=_snapshot(phase="pre_resume"),
                post_resume=_snapshot(),
                run_index=i,
            ),
        )
        for i in range(2, ISOLATION_PASSES + 1)
    )
    summary = summarize_consecutive_runs(records)
    assert summary.verdict == "REPRODUCED"
    assert summary.run_index == 1
