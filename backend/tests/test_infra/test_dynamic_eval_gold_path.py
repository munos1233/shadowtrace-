"""ISSUE-256 gold-path dynamic-eval profile guards (no live stack required)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"
APPROVE_PATH = SCRIPTS / "dynamic_eval_approve.py"
FULL_LOOP_PATH = SCRIPTS / "dynamic_eval_full_loop.py"
BOOTSTRAP_PATH = SCRIPTS / "bootstrap.sh"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
DEPLOYMENT_DOC = REPO_ROOT / "docs" / "deployment.md"
MAKEFILE_PATH = REPO_ROOT / "Makefile"
SEED_PATH = SCRIPTS / "seed_mock_xdr_and_ingest.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def approve_mod():
    return _load_module(APPROVE_PATH, "dynamic_eval_approve_under_test")


@pytest.fixture(scope="module")
def full_loop_mod():
    # Ensure sibling import resolves when loading full_loop from absolute path.
    scripts_dir = str(SCRIPTS)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    return _load_module(FULL_LOOP_PATH, "dynamic_eval_full_loop_under_test")


def test_gold_path_scripts_exist() -> None:
    assert APPROVE_PATH.is_file()
    assert FULL_LOOP_PATH.is_file()
    assert SEED_PATH.is_file()


def test_select_pending_actions_prefers_l2(approve_mod) -> None:
    actions = [
        {
            "action_id": "act-l3",
            "action_level": "l3",
            "status": "waiting_approval",
            "tool_name": "isolate_host",
            "action_category": "response",
            "plan_revision": 1,
        },
        {
            "action_id": "act-l2",
            "action_level": "l2",
            "status": "waiting_approval",
            "tool_name": "block_domain",
            "action_category": "response",
            "plan_revision": 1,
        },
        {
            "action_id": "act-sys",
            "action_level": "l0",
            "status": "waiting_approval",
            "tool_name": "generate_report",
            "action_category": "system",
            "plan_revision": 1,
        },
        {
            "action_id": "act-done",
            "action_level": "l2",
            "status": "approved",
            "tool_name": "block_domain",
            "action_category": "response",
            "plan_revision": 1,
        },
    ]
    pending = approve_mod.select_pending_actions(actions)
    assert [a["action_id"] for a in pending] == ["act-l2", "act-l3"]


def test_event_outcome_ok_rejects_failed(full_loop_mod) -> None:
    assert full_loop_mod.event_outcome_ok("reporting") is True
    assert full_loop_mod.event_outcome_ok("contained") is True
    assert full_loop_mod.event_outcome_ok("waiting_approval") is True
    assert full_loop_mod.event_outcome_ok("failed") is False


def test_full_loop_refuses_half_hour_wait(full_loop_mod) -> None:
    with pytest.raises(SystemExit) as excinfo:
        full_loop_mod.main(["--max-wait-s", "1800", "--event-id", "evt-x"])
    assert "30 minutes" in str(excinfo.value) or "APPROVAL_TIMEOUT" in str(excinfo.value)


def test_bootstrap_default_generate_report_false_with_opt_in() -> None:
    text = BOOTSTRAP_PATH.read_text(encoding="utf-8")
    assert 'BOOTSTRAP_GENERATE_REPORT="${BOOTSTRAP_GENERATE_REPORT:-false}"' in text
    assert 'BOOTSTRAP_INCLUDE_RESPONSE="${BOOTSTRAP_INCLUDE_RESPONSE:-false}"' in text
    assert "generate_report" in text
    assert "include_response_execution" in text
    # Default profile must not hardcode generate_report true without the env gate.
    assert "BOOTSTRAP_GENERATE_REPORT" in text
    assert "dynamic_eval_approve" in text
    assert "seed_mock_xdr_and_ingest" in text


def test_env_example_keeps_production_approval_timeout_default() -> None:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    # Active (uncommented) default must remain 30.
    active = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("APPROVAL_TIMEOUT_MINUTES=")
    ]
    assert active == ["APPROVAL_TIMEOUT_MINUTES=30"]
    assert "ISSUE-256" in text
    assert "seed_mock_xdr_and_ingest" in text
    assert "EMBEDDING_MODE" in text
    assert "celery `-c 2`" in text or "celery -c 2" in text or "`-c 2`" in text


def test_makefile_eval_full_loop_target() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "eval-full-loop:" in text
    assert "dynamic_eval_full_loop.py" in text
    assert "--seed-via-compose" in text
    assert "BOOTSTRAP_GENERATE_REPORT" in text


def test_deployment_docs_gold_path_honesty() -> None:
    text = DEPLOYMENT_DOC.read_text(encoding="utf-8")
    assert "ISSUE-256" in text
    assert "eval-full-loop" in text
    assert "seed_mock_xdr_and_ingest" in text
    assert "POST /events" in text
    assert "APPROVAL_TIMEOUT_MINUTES" in text
    assert "EMBEDDING_MODE" in text
    assert "-c 2" in text


def test_full_loop_documents_seed_fixture_not_post_events() -> None:
    text = FULL_LOOP_PATH.read_text(encoding="utf-8")
    assert "seed_mock_xdr_and_ingest" in text
    assert "POST /api/v1/events" in text or "POST /events" in text
    assert "include_response_execution" in text
    assert "APPROVAL_TIMEOUT" in text
