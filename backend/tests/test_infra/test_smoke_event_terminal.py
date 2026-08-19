"""ISSUE-304 smoke terminal polling guards."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"
SMOKE_TERMINAL_PATH = SCRIPTS / "smoke_event_terminal.py"
SMOKE_BOOTSTRAP_PATH = SCRIPTS / "smoke_bootstrap.sh"
SMOKE_DEMO_PATH = SCRIPTS / "smoke_demo.sh"
BOOTSTRAP_PATH = SCRIPTS / "bootstrap.sh"
MAKEFILE_PATH = REPO_ROOT / "Makefile"
DEPLOYMENT_DOC = REPO_ROOT / "docs" / "deployment.md"
README = REPO_ROOT / "README.md"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    scripts_dir = str(SCRIPTS)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def smoke_terminal_mod():
    return _load_module(SMOKE_TERMINAL_PATH, "smoke_event_terminal_under_test")


def test_smoke_event_terminal_script_exists() -> None:
    assert SMOKE_TERMINAL_PATH.is_file()


def test_compat_accepts_analysis_only_complete(smoke_terminal_mod) -> None:
    detail = {
        "event": {"event_id": "evt-1", "status": "scoring"},
        "analysis_only_complete": True,
    }
    reached, status = smoke_terminal_mod.compat_terminal_reached(detail)
    assert reached is True
    assert status == "scoring"


def test_compat_rejects_reporting_without_analysis_only_complete(smoke_terminal_mod) -> None:
    detail = {"event": {"event_id": "evt-2", "status": "reporting"}}
    reached, status = smoke_terminal_mod.compat_terminal_reached(detail)
    assert reached is False
    assert status == "reporting"


def test_compat_accepts_reporting_with_analysis_only_complete(smoke_terminal_mod) -> None:
    detail = {
        "event": {"event_id": "evt-2b", "status": "reporting"},
        "analysis_only_complete": True,
    }
    reached, status = smoke_terminal_mod.compat_terminal_reached(detail)
    assert reached is True
    assert status == "reporting"


def test_compat_accepts_closed_and_contained(smoke_terminal_mod) -> None:
    for status in ("closed", "contained"):
        detail = {"event": {"event_id": f"evt-{status}", "status": status}}
        reached, observed = smoke_terminal_mod.compat_terminal_reached(detail)
        assert reached is True
        assert observed == status


def test_compat_accepts_analysis_only_complete_via_snapshot(smoke_terminal_mod) -> None:
    detail = {
        "event": {
            "event_id": "evt-snap",
            "status": "analyzing",
            "event_context_snapshot": {"analysis_only_complete": True},
        }
    }
    reached, status = smoke_terminal_mod.compat_terminal_reached(detail)
    assert reached is True
    assert status == "analyzing"


def test_compat_rejects_failed(smoke_terminal_mod) -> None:
    detail = {"event": {"event_id": "evt-3", "status": "failed"}}
    reached, status = smoke_terminal_mod.compat_terminal_reached(detail)
    assert reached is False
    assert status == "failed"


def test_compat_rejects_in_flight_without_flag(smoke_terminal_mod) -> None:
    detail = {"event": {"event_id": "evt-4", "status": "analyzing"}}
    reached, _ = smoke_terminal_mod.compat_terminal_reached(detail)
    assert reached is False


def test_format_terminal_failure_includes_trajectory(smoke_terminal_mod) -> None:
    trajectories = {
        "evt-a": smoke_terminal_mod.EventTrajectory("evt-a", statuses=["new", "analyzing"]),
    }
    msg = smoke_terminal_mod._format_terminal_failure(
        mode="compat",
        trajectories=trajectories,
        reason="timeout",
    )
    assert "evt-a" in msg
    assert "new -> analyzing" in msg
    assert "mode=compat" in msg
    assert "timeout" in msg


def test_wait_for_terminal_events_off_is_noop(smoke_terminal_mod) -> None:
    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            raise AssertionError("should not be called for mode=off")

    summary = smoke_terminal_mod.wait_for_terminal_events(
        _Client(),  # type: ignore[arg-type]
        mode="off",
        timeout_s=1.0,
        min_events=3,
    )
    assert summary["mode"] == "off"


def test_list_demo_events_raises_when_fewer_than_min(smoke_terminal_mod) -> None:
    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            return {"items": [{"event_id": "evt-only"}]}

    with pytest.raises(smoke_terminal_mod.DynamicEvalApiError, match="expected at least 3"):
        smoke_terminal_mod.list_demo_events(_Client(), min_events=3)  # type: ignore[arg-type]


def test_list_demo_events_monitors_only_newest_min_events(smoke_terminal_mod) -> None:
    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            return {
                "items": [
                    {"event_id": "evt-new-1"},
                    {"event_id": "evt-new-2"},
                    {"event_id": "evt-new-3"},
                    {"event_id": "evt-stale-inflight"},
                    {"event_id": "evt-stale-failed"},
                ]
            }

    events = smoke_terminal_mod.list_demo_events(_Client(), min_events=3)  # type: ignore[arg-type]
    assert [e["event_id"] for e in events] == [
        "evt-new-1",
        "evt-new-2",
        "evt-new-3",
    ]


def test_list_demo_events_ignores_stale_beyond_min_when_polling(
    smoke_terminal_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: stale in-flight events beyond min_events must not block compat smoke."""

    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            if path.startswith("/api/v1/events?page_size"):
                return {
                    "items": [
                        {"event_id": "evt-demo-1"},
                        {"event_id": "evt-demo-2"},
                        {"event_id": "evt-demo-3"},
                        {"event_id": "evt-stale"},
                    ]
                }
            event_id = path.rsplit("/", 1)[-1]
            if event_id == "evt-stale":
                return {"event": {"event_id": event_id, "status": "analyzing"}}
            return {
                "event": {
                    "event_id": event_id,
                    "status": "closed",
                }
            }

    summary = smoke_terminal_mod.wait_for_terminal_events(
        _Client(),  # type: ignore[arg-type]
        mode="compat",
        timeout_s=1.0,
        min_events=3,
        poll_s=0.01,
    )
    assert set(summary["events"]) == {"evt-demo-1", "evt-demo-2", "evt-demo-3"}


def test_wait_for_terminal_events_times_out_with_in_flight_trajectory(smoke_terminal_mod) -> None:
    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            if path.startswith("/api/v1/events?page_size"):
                return {
                    "items": [
                        {"event_id": "evt-1"},
                        {"event_id": "evt-2"},
                        {"event_id": "evt-3"},
                    ]
                }
            return {"event": {"event_id": path.rsplit("/", 1)[-1], "status": "analyzing"}}

    with pytest.raises(RuntimeError, match="timeout") as exc_info:
        smoke_terminal_mod.wait_for_terminal_events(
            _Client(),  # type: ignore[arg-type]
            mode="compat",
            timeout_s=0.05,
            min_events=3,
            poll_s=0.01,
        )
    assert "evt-1" in str(exc_info.value)
    assert "analyzing" in str(exc_info.value)


def test_wait_for_terminal_events_raises_on_failed_status(smoke_terminal_mod) -> None:
    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            if path.startswith("/api/v1/events?page_size"):
                return {"items": [{"event_id": "evt-fail"}]}
            return {"event": {"event_id": "evt-fail", "status": "failed"}}

    with pytest.raises(RuntimeError, match="status=failed"):
        smoke_terminal_mod.wait_for_terminal_events(
            _Client(),  # type: ignore[arg-type]
            mode="compat",
            timeout_s=1.0,
            min_events=1,
            poll_s=0.01,
        )


def test_wait_for_terminal_events_compat_succeeds_when_all_terminal(smoke_terminal_mod) -> None:
    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            if path.startswith("/api/v1/events?page_size"):
                return {
                    "items": [
                        {"event_id": "evt-1"},
                        {"event_id": "evt-2"},
                    ]
                }
            event_id = path.rsplit("/", 1)[-1]
            return {
                "event": {"event_id": event_id, "status": "closed"},
            }

    summary = smoke_terminal_mod.wait_for_terminal_events(
        _Client(),  # type: ignore[arg-type]
        mode="compat",
        timeout_s=1.0,
        min_events=2,
        poll_s=0.01,
    )
    assert summary["mode"] == "compat"
    assert set(summary["events"]) == {"evt-1", "evt-2"}


def test_wait_for_terminal_events_strict_waits_for_closed(
    smoke_terminal_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, float]] = []

    def _assert(client, event_id: str, *, max_wait_s: float = 10.0) -> None:
        calls.append((event_id, max_wait_s))

    monkeypatch.setattr(smoke_terminal_mod, "assert_strict_closed_acceptance", _assert)

    class _Client:
        poll = 0

        def get_json(self, path: str) -> dict[str, Any]:
            if path.startswith("/api/v1/events?page_size"):
                return {"items": [{"event_id": "evt-strict"}]}
            self.poll += 1
            status = "reporting" if self.poll == 1 else "closed"
            return {"event": {"event_id": "evt-strict", "status": status}}

    summary = smoke_terminal_mod.wait_for_terminal_events(
        _Client(),  # type: ignore[arg-type]
        mode="strict",
        timeout_s=30.0,
        min_events=1,
        poll_s=0.01,
    )
    assert summary["events"]["evt-strict"]["profile"] == "strict_closed"
    assert calls == [("evt-strict", pytest.approx(30.0, abs=5.0))]


def test_main_returns_1_on_terminal_timeout(
    smoke_terminal_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*args, **kwargs):
        raise RuntimeError("timeout after 0s")

    monkeypatch.setattr(smoke_terminal_mod, "wait_for_terminal_events", _boom)
    assert smoke_terminal_mod.main(["--mode", "compat", "--timeout-s", "1"]) == 1


def test_main_returns_1_on_strict_assert_failure(
    smoke_terminal_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _strict_fail(*args, **kwargs):
        raise RuntimeError("strict profile: report_quality missing for evt-x")

    monkeypatch.setattr(smoke_terminal_mod, "wait_for_terminal_events", _strict_fail)
    assert smoke_terminal_mod.main(["--mode", "strict"]) == 1


def test_main_returns_0_when_all_compat_terminal(
    smoke_terminal_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        smoke_terminal_mod,
        "wait_for_terminal_events",
        lambda *args, **kwargs: {
            "mode": "compat",
            "events": {"evt-1": {"status": "closed", "profile": "compat"}},
        },
    )
    assert smoke_terminal_mod.main(["--mode", "compat"]) == 0


def test_main_returns_1_on_api_error(smoke_terminal_mod, monkeypatch: pytest.MonkeyPatch) -> None:
    def _api_err(*args, **kwargs):
        raise smoke_terminal_mod.DynamicEvalApiError("bad payload")

    monkeypatch.setattr(smoke_terminal_mod, "wait_for_terminal_events", _api_err)
    assert smoke_terminal_mod.main(["--mode", "compat"]) == 1


def test_smoke_bootstrap_wires_terminal_mode() -> None:
    text = SMOKE_BOOTSTRAP_PATH.read_text(encoding="utf-8")
    assert "smoke_event_terminal.py" in text
    assert "SMOKE_TERMINAL_MODE" in text
    assert "ISSUE-304" in text
    assert "SMOKE_TERMINAL_MIN_EVENTS" in text
    fail_idx = text.index("terminal acceptance failed")
    fail_block = text[fail_idx : text.index("fi", fail_idx)]
    assert "exit 1" in fail_block
    assert "bootstrap-demo-analysis" in fail_block
    assert "NOT CLOSED" in fail_block
    assert "make demo-full-loop" in fail_block


def test_smoke_demo_runs_worker_before_bootstrap_smoke() -> None:
    text = SMOKE_DEMO_PATH.read_text(encoding="utf-8")
    worker_idx = text.index("celery investigation worker")
    bootstrap_idx = text.index("core bootstrap smoke")
    assert worker_idx < bootstrap_idx


def test_smoke_demo_defaults_compat_terminal_mode() -> None:
    text = SMOKE_DEMO_PATH.read_text(encoding="utf-8")
    assert 'SMOKE_TERMINAL_MODE="${SMOKE_TERMINAL_MODE:-compat}"' in text
    fail_idx = text.index("bootstrap smoke failed")
    fail_block = text[fail_idx : text.index("fi", fail_idx)]
    assert "exit 1" in fail_block
    assert "bootstrap-demo-analysis" in fail_block
    assert "NOT CLOSED" in fail_block
    assert "make demo-full-loop" in fail_block


def test_makefile_issue_304_targets() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "bootstrap-demo-full-loop:" in text
    assert "bootstrap-demo-analysis:" in text
    assert "demo-full-loop:" in text
    assert "test-ci-lite:" in text
    assert "test_smoke_event_terminal.py" in text
    assert "SMOKE_TERMINAL_MODE" in text
    assert "EVAL_REQUIRE_CLOSED" in text
    phony = next(line for line in text.splitlines() if line.startswith(".PHONY:"))
    assert "bootstrap-demo-analysis" in phony
    assert "adversarial-closure-gates" in phony


def test_makefile_bootstrap_demo_documents_analysis_only_profile() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    block_start = text.index("# Analysis-only demo seed (ISSUE-352)")
    block_end = text.index("bootstrap-demo-analysis:", block_start)
    block = text[block_start:block_end]
    assert "BOOTSTRAP_INCLUDE_RESPONSE=false" in block
    assert "do NOT reach" in block
    assert "$(MAKE) bootstrap BOOTSTRAP_INCLUDE_RESPONSE=false" in block.replace("\t", "")


def test_makefile_bootstrap_demo_full_loop_sets_response_and_report() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    block_start = text.index("bootstrap-demo-full-loop:")
    block = text[block_start : text.index("# Official single-scenario CLOSED", block_start)]
    assert "BOOTSTRAP_GENERATE_REPORT=true" in block
    assert "BOOTSTRAP_INCLUDE_RESPONSE=true" in block


def test_makefile_demo_full_loop_invokes_eval_with_require_closed() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    block_start = text.index("demo-full-loop:")
    block = text[block_start : text.index("smoke-demo:", block_start)]
    assert "eval-full-loop EVAL_REQUIRE_CLOSED=1" in block


def test_makefile_eval_full_loop_supports_require_closed_flag() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    block_start = text.index("eval-full-loop:")
    block = text[block_start : text.index("eval-full-loop-matrix:", block_start)]
    assert "--require-closed" in block
    assert "--require-llm-quality" in block


def test_makefile_smoke_bootstrap_defaults_terminal_off() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    block_start = text.index("smoke-bootstrap:")
    block = text[block_start : text.index("# ---", block_start)]
    assert "SMOKE_TERMINAL_MODE),off)" in block.replace(" ", "")


def test_deployment_docs_official_demo_path_first() -> None:
    text = DEPLOYMENT_DOC.read_text(encoding="utf-8")
    assert "ISSUE-304" in text
    official_section = text.index("## 一键启动（官方推荐 — ISSUE-304）")
    legacy_section = text.index("### 短路径分析演示（legacy")
    assert official_section < legacy_section
    official_block = text[official_section:legacy_section]
    assert "make up-demo" in official_block
    assert "make demo-full-loop" in official_block
    assert "make bootstrap-demo-full-loop" in official_block
    assert "EVAL_REQUIRE_CLOSED=1 make eval-full-loop" in official_block
    assert "bootstrap-demo-analysis" in official_block
    assert "非 CLOSED" in official_block
    assert "make smoke-demo" in official_block
    assert "官方 Demo 栈" not in official_block
    assert "官方 demo 冒烟" not in text
    assert "make test-ci-lite" in text


def test_readme_points_to_closed_gold_path_first() -> None:
    text = README.read_text(encoding="utf-8")
    demo_full_loop_idx = text.index("make up-demo && make demo-full-loop")
    bootstrap_smoke_idx = text.index("make up-demo && make bootstrap-demo && make smoke-demo")
    assert demo_full_loop_idx < bootstrap_smoke_idx
    assert "bootstrap-demo-full-loop" in text
    assert "bootstrap-demo-analysis" in text
    assert "非 CLOSED" in text
    assert "make demo-full-loop" in text
    assert "make test-ci-lite" in text
    assert "EVAL_SCENARIO=" in text


def test_bootstrap_footer_leads_with_closed_gold_path() -> None:
    text = BOOTSTRAP_PATH.read_text(encoding="utf-8")
    footer = text[text.index("演示环境已就绪") :]
    assert footer.index("make demo-full-loop") < footer.index("make smoke-demo")
    assert "非 CLOSED" in footer
    assert "官方 demo" not in footer
