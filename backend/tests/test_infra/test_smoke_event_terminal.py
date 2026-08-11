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


def test_compat_accepts_reporting(smoke_terminal_mod) -> None:
    detail = {"event": {"event_id": "evt-2", "status": "reporting"}}
    reached, _ = smoke_terminal_mod.compat_terminal_reached(detail)
    assert reached is True


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


def test_smoke_bootstrap_wires_terminal_mode() -> None:
    text = SMOKE_BOOTSTRAP_PATH.read_text(encoding="utf-8")
    assert "smoke_event_terminal.py" in text
    assert "SMOKE_TERMINAL_MODE" in text
    assert "ISSUE-304" in text


def test_smoke_demo_defaults_compat_terminal_mode() -> None:
    text = SMOKE_DEMO_PATH.read_text(encoding="utf-8")
    assert 'SMOKE_TERMINAL_MODE="${SMOKE_TERMINAL_MODE:-compat}"' in text


def test_makefile_issue_304_targets() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "bootstrap-demo-full-loop:" in text
    assert "demo-full-loop:" in text
    assert "test-ci-lite:" in text
    assert "test_smoke_event_terminal.py" in text
    assert "SMOKE_TERMINAL_MODE" in text


def test_deployment_docs_official_demo_path_first() -> None:
    text = DEPLOYMENT_DOC.read_text(encoding="utf-8")
    assert "ISSUE-304" in text
    official_section = text.index("## 一键启动（官方推荐 — ISSUE-304）")
    legacy_section = text.index("### 短路径分析演示（legacy")
    assert official_section < legacy_section
    official_block = text[official_section:legacy_section]
    assert "make up-demo" in official_block
    assert "make smoke-demo" in official_block
    assert "make test-ci-lite" in text
    assert "bootstrap-demo-full-loop" in text


def test_readme_points_to_up_demo_smoke_demo() -> None:
    text = README.read_text(encoding="utf-8")
    assert "make up-demo && make bootstrap-demo && make smoke-demo" in text
    assert "make demo-full-loop" in text
    assert "make test-ci-lite" in text
