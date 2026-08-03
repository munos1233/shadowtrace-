"""Exit-code contract for detection evaluation CLI (ISSUE-167 / #686)."""

from __future__ import annotations

from scripts.run_detection_evaluation import cli_exit_code


def test_cli_exit_code_fails_on_baseline_drift_even_with_allow_gate_fail() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="fail_closed",
            baseline_compare_failed=True,
            allow_gate_fail=True,
        )
        == 1
    )


def test_cli_exit_code_report_only_allows_pinned_fail_closed() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="fail_closed",
            baseline_compare_failed=False,
            allow_gate_fail=True,
        )
        == 0
    )


def test_cli_exit_code_required_mode_hard_fails_on_gate() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="fail_closed",
            baseline_compare_failed=False,
            allow_gate_fail=False,
        )
        == 1
    )
    assert (
        cli_exit_code(
            artifact_status="completed",
            gate_verdict="fail",
            baseline_compare_failed=False,
            allow_gate_fail=False,
        )
        == 1
    )


def test_cli_exit_code_success_when_completed_and_gate_pass() -> None:
    assert (
        cli_exit_code(
            artifact_status="completed",
            gate_verdict="pass",
            baseline_compare_failed=False,
            allow_gate_fail=False,
        )
        == 0
    )
