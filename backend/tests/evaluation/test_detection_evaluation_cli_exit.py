"""Exit-code contract for detection evaluation CLI (ISSUE-167 / #686, ISSUE-263)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.run_detection_evaluation import cli_exit_code


def test_cli_exit_code_fails_on_baseline_drift_even_with_allow_gate_fail() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="fail_closed",
            baseline_compare_failed=True,
            allow_gate_fail=True,
            required_scorer_error_count=2,
        )
        == 1
    )


def test_cli_exit_code_observe_mode_allows_pinned_fail_closed() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="fail_closed",
            baseline_compare_failed=False,
            allow_gate_fail=True,
            required_scorer_error_count=2,
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
            required_scorer_error_count=2,
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


def test_cli_exit_code_required_mode_fails_on_non_completed_status() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict=None,
            baseline_compare_failed=False,
            allow_gate_fail=False,
        )
        == 1
    )


def test_cli_exit_code_required_mode_fails_on_required_scorer_errors() -> None:
    assert (
        cli_exit_code(
            artifact_status="completed",
            gate_verdict="pass",
            baseline_compare_failed=False,
            allow_gate_fail=False,
            required_scorer_error_count=1,
        )
        == 1
    )


def test_cli_exit_code_observe_mode_allows_non_completed_with_gate_pass() -> None:
    assert (
        cli_exit_code(
            artifact_status="failed",
            gate_verdict="pass",
            baseline_compare_failed=False,
            allow_gate_fail=True,
        )
        == 0
    )


@pytest.mark.evaluation
def test_ci_required_detection_step_omits_allow_gate_fail_bypass() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    ci_yaml = (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    required_marker = "Run mock detection evaluation (required gate)"
    observe_marker = "--allow-gate-fail"

    start = ci_yaml.index(required_marker)
    next_frontend = ci_yaml.index("  frontend-build:", start)
    required_block = ci_yaml[start:next_frontend]

    assert observe_marker not in required_block
    assert "if: always()" in ci_yaml.split("Upload evaluation artifact", 1)[1]


@pytest.mark.evaluation
def test_format_evaluation_summary_includes_gate_and_policy() -> None:
    from types import SimpleNamespace

    from scripts.run_detection_evaluation import format_evaluation_summary

    threshold_path = (
        Path(__file__).resolve().parents[3]
        / "data"
        / "evaluation"
        / "detection_shadow_v1"
        / "threshold_manifest.json"
    )
    artifact = SimpleNamespace(
        status=SimpleNamespace(value="failed"),
        gate=SimpleNamespace(
            verdict=SimpleNamespace(value="fail_closed"),
            diffs=[SimpleNamespace(field="pass_rate", reason="pass_rate below manifest minimum")],
        ),
        aggregates=SimpleNamespace(pass_rate=0.66, required_scorer_error_count=2),
        artifact_hash="abc123",
    )
    summary = format_evaluation_summary(artifact=artifact, threshold_path=threshold_path)
    assert "**status**: `failed`" in summary
    assert "**gate_verdict**: `fail_closed`" in summary
    assert "**required_gate** (manifest): `True`" in summary
    assert "pass_rate below manifest minimum" in summary
