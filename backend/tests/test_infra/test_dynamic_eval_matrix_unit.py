"""ISSUE-301 unit tests: dynamic eval matrix helpers (no Docker required)."""

from __future__ import annotations

import importlib.util
import json
import signal
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = REPO_ROOT / "scripts" / "dynamic_eval_matrix.py"


def _mock_subprocess_result() -> object:
    return type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()


FULL_LOOP_PATH = REPO_ROOT / "scripts" / "dynamic_eval_full_loop.py"


def _load_matrix_module():
    scripts_dir = str(REPO_ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(
        "dynamic_eval_matrix_under_test",
        MATRIX_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["dynamic_eval_matrix_under_test"] = module
    spec.loader.exec_module(module)
    return module


def _load_full_loop_module():
    scripts_dir = str(REPO_ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(
        "dynamic_eval_full_loop_under_test",
        FULL_LOOP_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["dynamic_eval_full_loop_under_test"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def full_loop_mod():
    return _load_full_loop_module()


@pytest.fixture(scope="module")
def matrix_mod():
    return _load_matrix_module()


def test_event_ids_from_seed_summary_returns_explicit_ids(matrix_mod) -> None:
    summary = {"accepted": 1, "event_ids": ["evt-a", "evt-b"]}
    assert matrix_mod.event_ids_from_seed_summary(
        summary,
        scenario="insider_data_exfiltration",
        max_events=1,
    ) == ["evt-a"]


def test_event_ids_from_seed_summary_raises_when_missing(matrix_mod) -> None:
    with pytest.raises(matrix_mod.MatrixError, match="missing event_ids"):
        matrix_mod.event_ids_from_seed_summary(
            {"accepted": 1},
            scenario="insider_data_exfiltration",
            max_events=1,
        )


def test_parse_full_loop_stdout_extracts_result_from_mixed_progress_logs(
    full_loop_mod,
) -> None:
    mixed = (
        "[dynamic-eval] gold path events=['evt-a']\n"
        "[dynamic-eval] triggered full_loop event_id=evt-a generate_report=True\n"
        '{\n  "final_statuses": {"evt-a": "closed"},\n  "elapsed_s": 12.5\n}\n'
    )
    parsed = full_loop_mod.parse_full_loop_stdout(mixed)
    assert parsed["final_statuses"] == {"evt-a": "closed"}
    assert parsed["elapsed_s"] == 12.5


def test_run_full_loop_via_exec_accepts_mixed_progress_and_json(matrix_mod) -> None:
    mixed = (
        "[dynamic-eval] triggered full_loop event_id=evt-a generate_report=True\n"
        '{"final_statuses": {"evt-a": "closed"}, "elapsed_s": 9}\n'
    )

    def _fake_run(cmd: list[str], **kwargs):
        return type("Proc", (), {"returncode": 0, "stdout": mixed, "stderr": ""})()

    with patch.object(matrix_mod, "_run", side_effect=_fake_run):
        result = matrix_mod._run_full_loop_via_exec(
            "proj",
            [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
            event_ids=["evt-a"],
            scenario="account_anomaly_fp",
            token="bootstrap-token",
            require_closed=False,
            analysis_only=True,
            semantic_profile="analysis_only_fp",
            max_wait_s=10.0,
            poll_interval_s=1.0,
        )
    assert result["final_statuses"] == {"evt-a": "closed"}


def test_scenario_seed_offset_is_stable(matrix_mod) -> None:
    first = matrix_mod.scenario_seed_offset(42, "insider_data_exfiltration")
    second = matrix_mod.scenario_seed_offset(42, "insider_data_exfiltration")
    assert first == second
    assert first != matrix_mod.scenario_seed_offset(42, "account_anomaly_fp")


def test_service_row_unhealthy_flags_running_unhealthy(matrix_mod) -> None:
    required = {"backend"}
    row = {"Service": "backend", "State": "running", "Health": "unhealthy"}
    assert matrix_mod._service_row_unhealthy(row, required=required) is True


def test_service_row_unhealthy_accepts_running_healthy(matrix_mod) -> None:
    required = {"backend"}
    row = {"Service": "backend", "State": "running", "Health": "healthy"}
    assert matrix_mod._service_row_unhealthy(row, required=required) is False


def test_sanitize_error_text_redacts_bearer(matrix_mod) -> None:
    raw = "failed Authorization: Bearer secret-token-value"
    sanitized = matrix_mod._sanitize_error_text(raw)
    assert "secret-token-value" not in sanitized
    assert "<redacted>" in sanitized


def test_sanitize_error_text_redacts_password_key(matrix_mod) -> None:
    raw = 'seed failed password="hunter2" during ingest'
    sanitized = matrix_mod._sanitize_error_text(raw)
    assert "hunter2" not in sanitized
    assert "<redacted>" in sanitized


def test_parse_args_defaults_compat_profile(matrix_mod) -> None:
    args = matrix_mod.parse_args(["--scenarios", "insider_data_exfiltration"])
    assert args.require_closed is False
    assert args.profile_by_scenario is False
    assert args.fresh_volumes is True
    assert args.suite == "demo"


def test_matrix_default_scenarios_remain_gold_three(matrix_mod) -> None:
    args = matrix_mod.parse_args([])
    assert args.suite == "demo"
    assert args.scenarios is None
    assert matrix_mod.resolve_matrix_scenarios(suite="demo", scenarios_raw=None) == list(
        matrix_mod.GOLD_SCENARIOS
    )
    assert len(matrix_mod.GOLD_SCENARIOS) == 3


def test_matrix_eventtype8_allows_eight_ids_and_rejects_profile_by_scenario(
    matrix_mod,
) -> None:
    ids = matrix_mod.resolve_matrix_scenarios(suite="eventtype8", scenarios_raw=None)
    assert ids == list(matrix_mod.EVENTTYPE8_SCENARIOS)
    assert len(ids) == 8
    assert matrix_mod._parse_scenarios(
        "host_compromise,lateral_movement",
        allowed=matrix_mod.EVENTTYPE8_SCENARIOS,
    ) == ["host_compromise", "lateral_movement"]
    with pytest.raises(SystemExit, match="profile-by-scenario"):
        matrix_mod.main(
            [
                "--suite",
                "eventtype8",
                "--profile-by-scenario",
                "--no-build",
            ]
        )


def test_matrix_refuses_max_wait_at_approval_timeout(matrix_mod) -> None:
    with pytest.raises(SystemExit, match="APPROVAL_TIMEOUT"):
        matrix_mod.main(["--max-wait-s", "300", "--no-build"])


def test_parse_args_profile_by_scenario(matrix_mod) -> None:
    args = matrix_mod.parse_args(["--scenarios", "account_anomaly_fp", "--profile-by-scenario"])
    assert args.profile_by_scenario is True


def test_matrix_main_stops_after_first_scenario_failure(matrix_mod) -> None:
    calls: list[str] = []

    def _fake_run_scenario(*, scenario: str, **kwargs):
        calls.append(scenario)
        if scenario == "insider_data_exfiltration":
            raise matrix_mod.MatrixError("simulated failure")
        return {"status": "passed"}

    with patch.object(matrix_mod, "run_scenario", side_effect=_fake_run_scenario):
        rc = matrix_mod.main(
            [
                "--scenarios",
                "insider_data_exfiltration,account_anomaly_fp",
                "--no-build",
            ]
        )
    assert rc == 1
    assert calls == ["insider_data_exfiltration"]


def test_scenario_project_name_unique_for_all_gold_scenarios(matrix_mod) -> None:
    run_id = "20260810T120000Z-deadbeef"
    names = [
        matrix_mod._scenario_project_name(scenario, run_id)
        for scenario in matrix_mod.GOLD_SCENARIOS
    ]
    assert len(names) == len(set(names))
    for name in names:
        assert name == name.lower()
        assert "T" not in name and "Z" not in name


def test_compose_up_places_profile_before_subcommand(matrix_mod) -> None:
    cmd = matrix_mod._compose_cmd(
        "shadowtrace-eval-fp-run",
        [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
        "--profile",
        "worker",
        "up",
        "-d",
    )
    assert cmd.index("--profile") < cmd.index("up")
    assert cmd[cmd.index("--profile") + 1] == "worker"


def test_compose_down_includes_worker_profile_before_subcommand(matrix_mod) -> None:
    captured: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs):
        captured.append(cmd)
        return type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(matrix_mod, "_run", side_effect=_fake_run):
        matrix_mod._compose_down(
            "proj",
            [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
            volumes=True,
        )
    cmd = captured[0]
    assert cmd.index("--profile") < cmd.index("down")
    assert cmd[cmd.index("--profile") + 1] == "worker"
    assert "-v" in cmd


def test_parse_scenarios_rejects_duplicates(matrix_mod) -> None:
    with pytest.raises(matrix_mod.MatrixError, match="duplicate scenario"):
        matrix_mod._parse_scenarios("insider_data_exfiltration,insider_data_exfiltration")


def test_sanitize_redacts_sensitive_dict_keys(matrix_mod) -> None:
    payload = {
        "token": "secret-token",
        "nested": {"password": "secret-password", "ok": "visible"},
    }
    sanitized = matrix_mod._sanitize(payload)
    assert sanitized["token"] == "<redacted>"
    assert sanitized["nested"]["password"] == "<redacted>"
    assert sanitized["nested"]["ok"] == "visible"


def test_compose_down_raises_on_failure(matrix_mod) -> None:
    with patch.object(
        matrix_mod,
        "_run",
        return_value=type(
            "Proc",
            (),
            {"returncode": 1, "stdout": "boom", "stderr": ""},
        )(),
    ):
        with pytest.raises(matrix_mod.MatrixError, match="compose down failed"):
            matrix_mod._compose_down(
                "proj",
                [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
                volumes=True,
            )


def test_run_scenario_finally_compose_down_with_volumes(matrix_mod, tmp_path: Path) -> None:
    down_calls: list[bool] = []

    def _fake_down(_project: str, _files: list[Path], *, volumes: bool) -> None:
        down_calls.append(volumes)

    with (
        patch.object(matrix_mod, "_compose_down", side_effect=_fake_down),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(
            matrix_mod,
            "_seed_scenario",
            return_value={"accepted": 1, "event_ids": ["evt-a"]},
        ),
        patch.object(
            matrix_mod,
            "_run_full_loop_via_exec",
            return_value={"final_statuses": {"evt-a": "closed"}},
        ),
        patch.object(matrix_mod, "_run", return_value=_mock_subprocess_result()),
    ):
        manifest = matrix_mod.run_scenario(
            scenario="insider_data_exfiltration",
            run_id="run-test",
            artifact_root=tmp_path,
            token="bootstrap-token",
            seed=42,
            mock_xdr_url="http://mock-xdr:8100",
            require_closed=False,
            profile_by_scenario=False,
            fresh_volumes=True,
            stack_timeout_s=10.0,
            max_wait_s=10.0,
            poll_interval_s=1.0,
            max_events=1,
            build=False,
        )
    assert manifest["status"] == "passed"
    assert down_calls == [True]


def test_run_scenario_eventtype8_fresh_volumes_loads_kb_once(matrix_mod, tmp_path: Path) -> None:
    load_calls: list[str] = []

    def _fake_load(project: str, _files: list[Path]) -> None:
        load_calls.append(project)

    with (
        patch.object(matrix_mod, "_compose_down"),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(matrix_mod, "_load_kb_once", side_effect=_fake_load),
        patch.object(
            matrix_mod,
            "_seed_scenario",
            return_value={"accepted": 1, "event_ids": ["evt-a"]},
        ),
        patch.object(
            matrix_mod,
            "_run_full_loop_via_exec",
            return_value={"final_statuses": {"evt-a": "closed"}},
        ),
        patch.object(matrix_mod, "_run", return_value=_mock_subprocess_result()),
    ):
        matrix_mod.run_scenario(
            scenario="host_compromise",
            run_id="run-kb",
            artifact_root=tmp_path,
            token="bootstrap-token",
            seed=42,
            mock_xdr_url="http://mock-xdr:8100",
            require_closed=True,
            profile_by_scenario=False,
            fresh_volumes=True,
            stack_timeout_s=10.0,
            max_wait_s=10.0,
            poll_interval_s=1.0,
            max_events=1,
            build=False,
            suite="eventtype8",
        )
    assert len(load_calls) == 1


def test_run_scenario_cleanup_failure_after_pass_raises(matrix_mod, tmp_path: Path) -> None:
    def _fake_down(_project: str, _files: list[Path], *, volumes: bool) -> None:
        raise matrix_mod.MatrixError("compose down failed project=proj-test exit=1")

    with (
        patch.object(matrix_mod, "_compose_down", side_effect=_fake_down),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(
            matrix_mod,
            "_seed_scenario",
            return_value={"accepted": 1, "event_ids": ["evt-a"]},
        ),
        patch.object(
            matrix_mod,
            "_run_full_loop_via_exec",
            return_value={"final_statuses": {"evt-a": "closed"}},
        ),
        patch.object(matrix_mod, "_run", return_value=_mock_subprocess_result()),
    ):
        with pytest.raises(matrix_mod.MatrixError, match="compose down failed"):
            matrix_mod.run_scenario(
                scenario="insider_data_exfiltration",
                run_id="run-test",
                artifact_root=tmp_path,
                token="bootstrap-token",
                seed=42,
                mock_xdr_url="http://mock-xdr:8100",
                require_closed=False,
                profile_by_scenario=False,
                fresh_volumes=True,
                stack_timeout_s=10.0,
                max_wait_s=10.0,
                poll_interval_s=1.0,
                max_events=1,
                build=False,
            )
    manifest = json.loads(
        (tmp_path / "insider_data_exfiltration" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "passed_with_cleanup_error"
    assert "cleanup_error" in manifest


def test_matrix_main_rejects_require_closed_with_profile_by_scenario(matrix_mod) -> None:
    with pytest.raises(SystemExit, match="cannot be combined"):
        matrix_mod.main(
            [
                "--scenarios",
                "account_anomaly_fp",
                "--require-closed",
                "--profile-by-scenario",
            ]
        )


def test_run_full_loop_via_exec_passes_analysis_only_flags(matrix_mod) -> None:
    captured: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs):
        captured.append(cmd)
        return type("Proc", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    with patch.object(matrix_mod, "_run", side_effect=_fake_run):
        matrix_mod._run_full_loop_via_exec(
            "proj",
            [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
            event_ids=["evt-a"],
            scenario="account_anomaly_fp",
            token="bootstrap-token",
            require_closed=False,
            analysis_only=True,
            semantic_profile="analysis_only_fp",
            max_wait_s=10.0,
            poll_interval_s=1.0,
        )
    cmd = captured[0]
    assert "--analysis-only" in cmd
    assert "--semantic-profile" in cmd
    assert "analysis_only_fp" in cmd
    assert "--require-closed" not in cmd


def test_run_full_loop_via_exec_passes_explicit_event_ids(matrix_mod) -> None:
    captured: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs):
        captured.append(cmd)
        return type("Proc", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    with patch.object(matrix_mod, "_run", side_effect=_fake_run):
        matrix_mod._run_full_loop_via_exec(
            "proj",
            [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
            event_ids=["evt-a", "evt-b"],
            scenario="insider_data_exfiltration",
            token="bootstrap-token",
            require_closed=True,
            max_wait_s=10.0,
            poll_interval_s=1.0,
        )
    cmd = captured[0]
    assert cmd.count("--event-id") == 2
    assert "evt-a" in cmd and "evt-b" in cmd
    assert "--require-closed" in cmd
    assert "--generate-report" in cmd
    assert "--suite" not in cmd


def test_run_full_loop_via_exec_passes_eventtype8_suite(matrix_mod) -> None:
    captured: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs):
        captured.append(cmd)
        return type("Proc", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    with patch.object(matrix_mod, "_run", side_effect=_fake_run):
        matrix_mod._run_full_loop_via_exec(
            "proj",
            [matrix_mod._BASE_COMPOSE, matrix_mod._EVAL_COMPOSE],
            event_ids=["evt-a"],
            scenario="host_compromise",
            token="bootstrap-token",
            require_closed=True,
            max_wait_s=10.0,
            poll_interval_s=1.0,
            suite="eventtype8",
        )
    cmd = captured[0]
    assert cmd[cmd.index("--suite") + 1] == "eventtype8"
    assert "--require-closed" in cmd


def test_signal_handler_respects_fresh_volumes_flag(matrix_mod) -> None:
    down_volumes: list[bool] = []

    def _fake_down(_project: str, _files: list[Path], *, volumes: bool) -> None:
        down_volumes.append(volumes)

    matrix_mod._CLEANUP.set_project("proj-test", fresh_volumes=False)
    with patch.object(matrix_mod, "_compose_down", side_effect=_fake_down):
        matrix_mod._CLEANUP.cleanup()
    assert down_volumes == [False]


def test_matrix_failure_summary_includes_manifest_fields(
    matrix_mod,
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    scenario = "insider_data_exfiltration"
    manifest_path = artifact_root / scenario / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "compose_project_name": "shadowtrace-eval-insider-run",
                "event_ids": ["evt-seed-1"],
                "status": "failed",
            }
        ),
        encoding="utf-8",
    )

    def _fake_run_scenario(*, scenario: str, **kwargs):
        raise matrix_mod.MatrixError("simulated failure")

    with patch.object(matrix_mod, "run_scenario", side_effect=_fake_run_scenario):
        rc = matrix_mod.main(
            [
                "--scenarios",
                scenario,
                "--artifact-dir",
                str(artifact_root),
                "--no-build",
            ]
        )
    assert rc == 1
    summary = json.loads((artifact_root / "summary.json").read_text(encoding="utf-8"))
    row = summary["results"][scenario]
    assert row["compose_project_name"] == "shadowtrace-eval-insider-run"
    assert row["event_ids"] == ["evt-seed-1"]


def test_require_closed_rejects_heuristic_event_selection(full_loop_mod) -> None:
    with patch.object(full_loop_mod, "DynamicEvalClient") as client_cls:
        client = client_cls.return_value
        client.get_json.side_effect = lambda path: (
            {"items": []}
            if "/events" in path
            else {
                "playbook_resources": {"status": "ready"},
                "celery": {
                    "task_mode": "celery",
                    "worker": {"status": "ok", "workers": 1},
                },
            }
        )
        with pytest.raises(SystemExit, match="heuristic DB selection is forbidden"):
            full_loop_mod.main(["--require-closed"])


def test_full_loop_rejects_event_id_with_seed_via_compose(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="cannot be combined with --seed-via-compose"):
        full_loop_mod.main(
            [
                "--require-closed",
                "--event-id",
                "evt-x",
                "--seed-via-compose",
            ]
        )


def test_event_outcome_ok_rejects_verifying_when_require_closed(full_loop_mod) -> None:
    assert full_loop_mod.event_outcome_ok("verifying", require_closed=True) is False


def test_signal_handler_writes_summary_when_cleanup_fails(matrix_mod, tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    summary: dict[str, object] = {
        "run_id": "run-x",
        "results": {},
    }
    active_run = {
        "artifact_root": artifact_root,
        "summary": summary,
        "scenario": "insider_data_exfiltration",
        "manifest": {
            "compose_project_name": "shadowtrace-eval-insider-run",
            "event_ids": ["evt-a"],
        },
    }

    def _handler(signum: int, _frame: object) -> None:
        cleanup_error: str | None = None
        try:
            raise matrix_mod.MatrixError("compose down failed")
        except matrix_mod.MatrixError as exc:
            cleanup_error = matrix_mod._sanitize_error_text(str(exc))
        scenario = active_run.get("scenario")
        summary_ref = active_run.get("summary")
        if scenario and isinstance(summary_ref, dict):
            manifest = (
                active_run.get("manifest") if isinstance(active_run.get("manifest"), dict) else {}
            )
            interrupted = {
                "status": "interrupted",
                "compose_project_name": manifest.get("compose_project_name"),
                "event_ids": manifest.get("event_ids"),
            }
            if cleanup_error:
                interrupted["cleanup_error"] = cleanup_error
            summary_ref["status"] = "interrupted"
            summary_ref["results"][scenario] = interrupted
            matrix_mod._write_json(artifact_root / "summary.json", summary_ref)
        raise SystemExit(128 + signum)

    with pytest.raises(SystemExit):
        _handler(signal.SIGINT, None)
    payload = json.loads((artifact_root / "summary.json").read_text(encoding="utf-8"))
    row = payload["results"]["insider_data_exfiltration"]
    assert row["status"] == "interrupted"
    assert "cleanup_error" in row


def test_run_scenario_records_cleanup_error_on_failure_path(
    matrix_mod,
    tmp_path: Path,
) -> None:
    def _fake_down(_project: str, _files: list[Path], *, volumes: bool) -> None:
        raise matrix_mod.MatrixError("down failed after scenario error")

    with (
        patch.object(matrix_mod, "_compose_down", side_effect=_fake_down),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(
            matrix_mod,
            "_seed_scenario",
            side_effect=matrix_mod.MatrixError("seed failed"),
        ),
        patch.object(
            matrix_mod,
            "_run",
            return_value=type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
        ),
    ):
        with pytest.raises(matrix_mod.MatrixError, match="seed failed"):
            matrix_mod.run_scenario(
                scenario="insider_data_exfiltration",
                run_id="run-test",
                artifact_root=tmp_path,
                token="bootstrap-token",
                seed=42,
                mock_xdr_url="http://mock-xdr:8100",
                require_closed=False,
                profile_by_scenario=False,
                fresh_volumes=True,
                stack_timeout_s=10.0,
                max_wait_s=10.0,
                poll_interval_s=1.0,
                max_events=1,
                build=False,
            )
    manifest = json.loads(
        (tmp_path / "insider_data_exfiltration" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "failed"
    assert manifest["cleanup_error"]["message"]


def test_run_scenario_profile_by_scenario_reseeds_distinct_pressure_event(
    matrix_mod, tmp_path: Path
) -> None:
    seed_calls: list[int] = []
    gate_calls: list[tuple[str, list[str]]] = []

    def _fake_seed(*_args, instance: int = 0, **_kwargs):
        seed_calls.append(instance)
        if instance == 0:
            return {"accepted": 1, "event_ids": ["evt-semantic"]}
        return {"accepted": 1, "event_ids": ["evt-pressure"]}

    def _fake_gate(*_args, event_ids: list[str], gate: str, **_kwargs):
        gate_calls.append((gate, list(event_ids)))
        if gate == "pressure":
            raise matrix_mod.MatrixError("pressure boom")
        return {"final_statuses": {event_ids[0]: "closed"}}

    with (
        patch.object(matrix_mod, "_compose_down"),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(matrix_mod, "_seed_scenario", side_effect=_fake_seed),
        patch.object(matrix_mod, "_run_scenario_gate", side_effect=_fake_gate),
        patch.object(matrix_mod, "_run", return_value=_mock_subprocess_result()),
    ):
        with pytest.raises(matrix_mod.MatrixError, match="pressure boom"):
            matrix_mod.run_scenario(
                scenario="suspicious_domain_access",
                run_id="run-domain-reseed",
                artifact_root=tmp_path,
                token="bootstrap-token",
                seed=42,
                mock_xdr_url="http://mock-xdr:8100",
                require_closed=False,
                profile_by_scenario=True,
                fresh_volumes=True,
                stack_timeout_s=10.0,
                max_wait_s=10.0,
                poll_interval_s=1.0,
                max_events=1,
                build=False,
            )

    assert seed_calls == [0, 1]
    assert gate_calls[0] == ("semantic", ["evt-semantic"])
    assert gate_calls[1] == ("pressure", ["evt-pressure"])
    manifest = json.loads(
        (tmp_path / "suspicious_domain_access" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "failed"
    assert manifest["pressure_error"]["type"] == "MatrixError"
    assert "[pressure gate]" in manifest["pressure_error"]["message"]
    assert manifest["semantic_event_ids"] == ["evt-semantic"]
    assert manifest["pressure_event_ids"] == ["evt-pressure"]


def test_fp_profile_by_scenario_skips_pressure_gate(matrix_mod, tmp_path: Path) -> None:
    """ISSUE-313: FP semantic is analysis_only_fp with pressure=none — no reseed."""
    seed_calls: list[int] = []
    gate_calls: list[str] = []

    def _fake_seed(*_args, instance: int = 0, **_kwargs):
        seed_calls.append(instance)
        return {"accepted": 1, "event_ids": ["evt-semantic"]}

    def _fake_gate(*_args, gate: str, **_kwargs):
        gate_calls.append(gate)
        return {"final_statuses": {"evt-semantic": "closed"}}

    with (
        patch.object(matrix_mod, "_compose_down"),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(matrix_mod, "_seed_scenario", side_effect=_fake_seed),
        patch.object(matrix_mod, "_run_scenario_gate", side_effect=_fake_gate),
        patch.object(matrix_mod, "_run", return_value=_mock_subprocess_result()),
    ):
        manifest = matrix_mod.run_scenario(
            scenario="account_anomaly_fp",
            run_id="run-fp",
            artifact_root=tmp_path,
            token="bootstrap-token",
            seed=42,
            mock_xdr_url="http://mock-xdr:8100",
            require_closed=False,
            profile_by_scenario=True,
            fresh_volumes=True,
            stack_timeout_s=10.0,
            max_wait_s=10.0,
            poll_interval_s=1.0,
            max_events=1,
            build=False,
        )
    assert seed_calls == [0]
    assert gate_calls == ["semantic"]
    assert manifest["status"] == "passed"
    assert manifest["pressure_event_ids"] == []


def test_run_scenario_profile_by_scenario_domain_pressure_failure_blocks(
    matrix_mod, tmp_path: Path
) -> None:
    def _fake_seed(*_args, instance: int = 0, **_kwargs):
        if instance == 0:
            return {"accepted": 1, "event_ids": ["evt-semantic"]}
        return {"accepted": 1, "event_ids": ["evt-pressure"]}

    def _fake_gate(*_args, event_ids: list[str], gate: str, **_kwargs):
        if gate == "pressure":
            raise matrix_mod.MatrixError("pressure boom")
        return {"final_statuses": {event_ids[0]: "closed"}}

    with (
        patch.object(matrix_mod, "_compose_down"),
        patch.object(matrix_mod, "_wait_stack_healthy"),
        patch.object(matrix_mod, "_seed_scenario", side_effect=_fake_seed),
        patch.object(matrix_mod, "_run_scenario_gate", side_effect=_fake_gate),
        patch.object(matrix_mod, "_run", return_value=_mock_subprocess_result()),
    ):
        with pytest.raises(matrix_mod.MatrixError, match="pressure boom"):
            matrix_mod.run_scenario(
                scenario="suspicious_domain_access",
                run_id="run-domain",
                artifact_root=tmp_path,
                token="bootstrap-token",
                seed=42,
                mock_xdr_url="http://mock-xdr:8100",
                require_closed=False,
                profile_by_scenario=True,
                fresh_volumes=True,
                stack_timeout_s=10.0,
                max_wait_s=10.0,
                poll_interval_s=1.0,
                max_events=1,
                build=False,
            )

    manifest = json.loads(
        (tmp_path / "suspicious_domain_access" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "failed"
    assert manifest["pressure_error"]["message"]


def test_matrix_main_summary_status_reflects_non_blocking_pressure_error(
    matrix_mod, tmp_path: Path
) -> None:
    artifact_root = tmp_path / "artifacts"

    def _fake_run_scenario(*, scenario: str, **kwargs):
        return {
            "status": "passed_with_pressure_error",
            "event_ids": ["evt-s", "evt-p"],
            "compose_project_name": "proj-fp",
            "result": {"final_statuses": {"evt-s": "closed"}},
            "pressure_error": {"type": "MatrixError", "message": "[pressure gate] boom"},
            "profile": "analysis_only_fp",
        }

    with patch.object(matrix_mod, "run_scenario", side_effect=_fake_run_scenario):
        rc = matrix_mod.main(
            [
                "--scenarios",
                "account_anomaly_fp",
                "--artifact-dir",
                str(artifact_root),
                "--profile-by-scenario",
                "--no-build",
            ]
        )
    assert rc == 0
    summary = json.loads((artifact_root / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "passed_with_pressure_error"
    assert summary["results"]["account_anomaly_fp"]["pressure_error"]["message"]


def test_matrix_failure_summary_copies_pressure_error_from_manifest(
    matrix_mod, tmp_path: Path
) -> None:
    artifact_root = tmp_path / "artifacts"
    scenario = "suspicious_domain_access"
    manifest_path = artifact_root / scenario / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "compose_project_name": "shadowtrace-eval-domain-run",
                "event_ids": ["evt-s", "evt-p"],
                "semantic_event_ids": ["evt-s"],
                "pressure_event_ids": ["evt-p"],
                "status": "failed",
                "pressure_error": {
                    "type": "MatrixError",
                    "message": "[pressure gate] boom",
                },
                "semantic_result": {"final_statuses": {"evt-s": "closed"}},
            }
        ),
        encoding="utf-8",
    )

    def _fake_run_scenario(*, scenario: str, **kwargs):
        raise matrix_mod.MatrixError("[pressure gate] boom")

    with patch.object(matrix_mod, "run_scenario", side_effect=_fake_run_scenario):
        rc = matrix_mod.main(
            [
                "--scenarios",
                scenario,
                "--artifact-dir",
                str(artifact_root),
                "--profile-by-scenario",
                "--no-build",
            ]
        )
    assert rc == 1
    summary = json.loads((artifact_root / "summary.json").read_text(encoding="utf-8"))
    row = summary["results"][scenario]
    assert row["pressure_error"]["message"] == "[pressure gate] boom"
    assert row["pressure_event_ids"] == ["evt-p"]
    assert row["semantic_event_ids"] == ["evt-s"]


def test_run_analysis_only_loop_keeps_polling_on_reporting_until_closed(
    full_loop_mod,
) -> None:
    statuses = ["triaging", "reporting", "closed"]
    from dynamic_eval_approve import ApiResponse

    class _Client:
        def __init__(self) -> None:
            self._idx = 0

        def get_json(self, path: str):
            if path.endswith("/audit-logs?page=1&page_size=5"):
                return {"items": []}
            if path.endswith("/decision-trace"):
                return {}
            if self._idx < len(statuses):
                status = statuses[self._idx]
                self._idx += 1
            else:
                status = "closed"
            return {
                "event": {
                    "event_id": "evt-ao",
                    "status": status,
                    "final_verdict": "false_positive",
                    "disposition_policy": "not_required",
                    "event_context_snapshot": {"collection_status": "completed"},
                }
            }

        def post_json(self, path: str, body: dict):
            return ApiResponse(
                status=202,
                data={
                    "event_id": "evt-ao",
                    "task_id": "t1",
                    "intent_id": "iin-1",
                    "status": "new",
                    "include_response_execution": False,
                    "generate_report": True,
                    "full_loop_available": True,
                },
            )

    with patch.object(full_loop_mod.time, "sleep", return_value=None):
        result = full_loop_mod.run_analysis_only_loop(
            _Client(),  # type: ignore[arg-type]
            event_ids=["evt-ao"],
            generate_report=True,
            poll_interval_s=0.01,
            max_wait_s=5.0,
            semantic_profile="analysis_only_fp",
        )
    assert result["final_statuses"]["evt-ao"] == "closed"
    assert "reporting" in result["status_trace"]["evt-ao"]
    assert result["semantic_assertions"]["evt-ao"]["final_verdict"] == "false_positive"


def test_main_rejects_analysis_only_without_generate_report(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="analysis-only requires report generation"):
        full_loop_mod.main(
            [
                "--analysis-only",
                "--semantic-profile",
                "analysis_only_fp",
                "--event-id",
                "evt-x",
                "--no-generate-report",
                "--skip-baseline-preflight",
            ]
        )


def test_assert_fp_semantic_gate_raises_with_diagnostics(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if path.endswith("/audit-logs?page=1&page_size=5"):
                return {"items": []}
            return {
                "event": {
                    "event_id": "evt-fp",
                    "status": "closed",
                    "final_verdict": "none",
                    "disposition_policy": "not_required",
                    "degraded_flags": ["demo_flag"],
                }
            }

    with pytest.raises(full_loop_mod.EvalFailure) as exc:
        full_loop_mod.assert_fp_semantic_gate(_Client(), "evt-fp")
    assert "false_positive" in str(exc.value)
    assert "demo_flag" in str(exc.value) or "status_trace" in str(exc.value)
    assert exc.value.diagnostics.get("final_verdict") == "none"


def test_assert_domain_semantic_gate_passes_on_closed(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            return {
                "event": {
                    "event_id": "evt-domain",
                    "status": "closed",
                    "final_verdict": "none",
                    "disposition_policy": "not_required",
                }
            }

    result = full_loop_mod.assert_domain_semantic_gate(
        _Client(),
        "evt-domain",
        expected_verdict="none",
    )
    assert result["status"] == "closed"
    assert result["final_verdict"] == "none"


def test_assert_domain_semantic_gate_rejects_wrong_verdict(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            return {
                "event": {
                    "event_id": "evt-domain",
                    "status": "closed",
                    "final_verdict": "confirmed_threat",
                    "disposition_policy": "not_required",
                    "degraded_flags": [],
                }
            }

    with pytest.raises(full_loop_mod.EvalFailure) as exc:
        full_loop_mod.assert_domain_semantic_gate(
            _Client(),
            "evt-domain",
            expected_verdict="none",
        )
    assert "none" in str(exc.value)
    assert exc.value.diagnostics.get("final_verdict") == "confirmed_threat"


def test_assert_fp_full_loop_gate_rejects_entity_response_trace(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            return {
                "event": {
                    "event_id": "evt-fp-pressure",
                    "status": "failed",
                    "final_verdict": "false_positive",
                    "disposition_policy": "not_required",
                    "degraded_flags": [],
                }
            }

    with pytest.raises(full_loop_mod.EvalFailure) as exc:
        full_loop_mod.assert_fp_full_loop_gate(
            _Client(),
            "evt-fp-pressure",
            status_trace=["new", "scoring", "planning_response", "failed"],
            decisions=[{"action_id": "act-1"}],
        )
    assert "planning_response" in str(exc.value)
