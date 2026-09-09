"""ISSUE-256 / ISSUE-301 gold-path and dynamic-eval matrix profile guards."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import schemas as s
from app.api.v1.deps import get_event_service, reset_deps
from app.main import app
from app.models.enums import EventStatus, WritebackReadiness

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"
APPROVE_PATH = SCRIPTS / "dynamic_eval_approve.py"
FULL_LOOP_PATH = SCRIPTS / "dynamic_eval_full_loop.py"
MATRIX_PATH = SCRIPTS / "dynamic_eval_matrix.py"
EVAL_COMPOSE = REPO_ROOT / "infra" / "docker-compose.eval.yml"
EMBEDDING_REMOTE_COMPOSE = REPO_ROOT / "infra" / "docker-compose.embedding-remote.yml"
REMOTE_EMBEDDING_DOC = REPO_ROOT / "docs" / "rag-remote-embedding-demo.md"
BOOTSTRAP_PATH = SCRIPTS / "bootstrap.sh"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
DEPLOYMENT_DOC = REPO_ROOT / "docs" / "deployment.md"
MAKEFILE_PATH = REPO_ROOT / "Makefile"
SEED_PATH = SCRIPTS / "seed_mock_xdr_and_ingest.py"

_DEV_TOKENS = json.dumps(
    {"analyst-token": {"subject": "analyst-1", "roles": ["analyst"]}},
)
_CELERY_READY_HEALTH = {
    "playbook_resources": {"status": "ready"},
    "celery": {
        "task_mode": "celery",
        "worker": {"status": "ok", "workers": 1, "worker_ids": ["investigation@host"]},
    },
}


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
    assert MATRIX_PATH.is_file()
    assert EVAL_COMPOSE.is_file()
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
            "action_id": "act-l1",
            "action_level": "l1",
            "status": "waiting_approval",
            "tool_name": "create_ticket",
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
    # L2 first, then remaining waiting non-system (including L1/L3).
    assert [a["action_id"] for a in pending] == ["act-l2", "act-l1", "act-l3"]


def test_event_outcome_ok_rejects_failed(full_loop_mod) -> None:
    assert full_loop_mod.event_outcome_ok("reporting") is True
    assert full_loop_mod.event_outcome_ok("contained") is True
    assert full_loop_mod.event_outcome_ok("waiting_approval") is True
    assert full_loop_mod.event_outcome_ok("failed") is False
    assert full_loop_mod.event_outcome_ok("reporting", require_closed=True) is False
    assert full_loop_mod.event_outcome_ok("contained", require_closed=True) is False
    assert full_loop_mod.event_outcome_ok("verifying", require_closed=True) is False
    assert full_loop_mod.event_outcome_ok("closed", require_closed=True) is True


def test_map_gold_final_verdict_never_none(full_loop_mod) -> None:
    assert full_loop_mod.map_gold_final_verdict(decision="approve") == "confirmed_threat"
    assert full_loop_mod.map_gold_final_verdict(decision="reject") == "false_positive"


def test_maybe_submit_analyst_final_verdict_posts_on_planning_response(full_loop_mod) -> None:
    posted: list[tuple[str, dict[str, Any]]] = []

    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            return {
                "event": {
                    "event_id": "evt-plan",
                    "status": "planning_response",
                    "final_verdict": "possible_false_positive",
                },
                "final_verdict": "possible_false_positive",
            }

        def post_json(self, path: str, body: dict[str, Any] | None = None) -> None:
            posted.append((path, body or {}))

    submitted: set[str] = set()
    assert (
        full_loop_mod.maybe_submit_analyst_final_verdict(
            _Client(),
            "evt-plan",
            require_closed=True,
            decision="approve",
            submitted=submitted,
        )
        is True
    )
    assert posted[0][1]["final_verdict"] == "confirmed_threat"


def test_maybe_submit_analyst_final_verdict_posts_on_waiting_approval(full_loop_mod) -> None:
    posted: list[tuple[str, dict[str, Any]]] = []

    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            return {
                "event": {
                    "event_id": "evt-wait",
                    "status": "waiting_approval",
                    "final_verdict": "none",
                },
                "execution_substate": "waiting_approval",
                "final_verdict": "none",
            }

        def post_json(self, path: str, body: dict[str, Any] | None = None) -> None:
            posted.append((path, body or {}))

    submitted: set[str] = set()
    assert (
        full_loop_mod.maybe_submit_analyst_final_verdict(
            _Client(),
            "evt-wait",
            require_closed=True,
            decision="approve",
            submitted=submitted,
        )
        is True
    )
    assert posted[0][1]["final_verdict"] == "confirmed_threat"
    assert posted[0][1]["resume"] is True


def test_maybe_submit_analyst_final_verdict_posts_on_verifying_hold(full_loop_mod) -> None:
    posted: list[tuple[str, dict[str, Any]]] = []

    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            return {
                "event": {
                    "event_id": "evt-hold",
                    "status": "verifying",
                    "final_verdict": "possible_false_positive",
                },
                "execution_substate": "manual_resolution",
                "final_verdict": "possible_false_positive",
            }

        def post_json(self, path: str, body: dict[str, Any] | None = None) -> None:
            posted.append((path, body or {}))

    submitted: set[str] = set()
    assert (
        full_loop_mod.maybe_submit_analyst_final_verdict(
            _Client(),
            "evt-hold",
            require_closed=True,
            decision="approve",
            submitted=submitted,
        )
        is True
    )
    assert submitted == {"evt-hold"}
    assert posted[0][0] == "/api/v1/events/evt-hold/final-verdict"
    assert posted[0][1]["final_verdict"] == "confirmed_threat"
    assert posted[0][1]["resume"] is True


def test_maybe_submit_analyst_final_verdict_skips_when_already_terminal(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            return {
                "event": {
                    "event_id": "evt-hold",
                    "status": "verifying",
                    "final_verdict": "confirmed_threat",
                },
                "execution_substate": "manual_resolution",
                "final_verdict": "confirmed_threat",
            }

        def post_json(self, path: str, body: dict[str, Any] | None = None) -> None:
            raise AssertionError("must not post")

    assert (
        full_loop_mod.maybe_submit_analyst_final_verdict(
            _Client(),
            "evt-hold",
            require_closed=True,
            decision="approve",
            submitted=set(),
        )
        is False
    )


def test_maybe_submit_analyst_final_verdict_skips_entity_response_scenarios(
    full_loop_mod,
) -> None:
    class _Client:
        def get_json(self, path: str) -> dict[str, Any]:
            raise AssertionError("must not GET when skip_entity_response")

        def post_json(self, path: str, body: dict[str, Any] | None = None) -> None:
            raise AssertionError("must not post confirmed_threat for skip_entity_response")

    assert (
        full_loop_mod.maybe_submit_analyst_final_verdict(
            _Client(),
            "evt-other",
            require_closed=True,
            decision="approve",
            submitted=set(),
            skip_entity_response=True,
        )
        is False
    )


def test_unwrap_event_detail_supports_envelope(full_loop_mod) -> None:
    flat = {"event_id": "evt-flat", "status": "new"}
    assert full_loop_mod.unwrap_event_detail(flat)["event_id"] == "evt-flat"
    wrapped = {"event": {"event_id": "evt-wrap", "status": "closed"}, "writeback_required": True}
    assert full_loop_mod.unwrap_event_detail(wrapped)["event_id"] == "evt-wrap"


def test_full_loop_refuses_half_hour_wait(full_loop_mod) -> None:
    with pytest.raises(SystemExit) as excinfo:
        full_loop_mod.main(["--max-wait-s", "1800", "--event-id", "evt-x"])
    assert "30 minutes" in str(excinfo.value) or "APPROVAL_TIMEOUT" in str(excinfo.value)


def test_full_loop_refuses_require_closed_without_report(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="requires report generation"):
        full_loop_mod.main(
            [
                "--require-closed",
                "--no-generate-report",
                "--event-id",
                "evt-x",
            ]
        )


def test_assert_strict_closed_acceptance_requires_closed(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": []}
            return {
                "event": {"event_id": "evt-1", "status": "reporting"},
                "writeback_required": False,
                "writeback_readiness": "not_required",
            }

        def request(self, method: str, path: str):
            raise AssertionError("report must not be fetched for non-closed status")

    with pytest.raises(RuntimeError, match="status=closed"):
        full_loop_mod.assert_strict_closed_acceptance(_Client(), "evt-1")


def test_assert_strict_closed_acceptance_requires_report_body(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": []}
            return {
                "event": {"event_id": "evt-2", "status": "closed"},
                "writeback_required": False,
                "writeback_readiness": "not_required",
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            assert method == "GET" and path.endswith("/report")
            return ApiResponse(status=200, data={})

    with pytest.raises(RuntimeError, match="no report body"):
        full_loop_mod.assert_strict_closed_acceptance(_Client(), "evt-2")


def test_assert_strict_closed_rejects_incomplete_placeholder_report(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": [], "total": 0}
            return {
                "event": {"event_id": "evt-2b", "status": "closed"},
                "writeback_required": False,
                "writeback_readiness": "not_required",
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            return ApiResponse(
                status=200,
                data={"report": {"report_quality": "incomplete_placeholder"}},
            )

    with pytest.raises(RuntimeError, match="incomplete_placeholder"):
        full_loop_mod.assert_strict_closed_acceptance(_Client(), "evt-2b")


def test_assert_strict_closed_acceptance_passes_when_converged(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": []}
            return {
                "event": {"event_id": "evt-3", "status": "closed"},
                "writeback_required": True,
                "writeback_readiness": "ready",
                "writeback_overall_status": "confirmed",
                "pending_writeback_count": 0,
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            return ApiResponse(
                status=200,
                data={"report": {"report_quality": "full"}},
            )

    result = full_loop_mod.assert_strict_closed_acceptance(_Client(), "evt-3")
    assert result["status"] == "closed"
    assert result["writeback_overall_status"] == "confirmed"


def test_assert_strict_closed_rejects_missing_report_quality(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": [], "total": 0}
            return {
                "event": {"event_id": "evt-4", "status": "closed"},
                "writeback_required": False,
                "writeback_readiness": "not_required",
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            return ApiResponse(status=200, data={"report": {"report_quality": ""}})

    with pytest.raises(RuntimeError, match="report_quality missing"):
        full_loop_mod.assert_strict_closed_acceptance(_Client(), "evt-4", max_wait_s=0.0)


def test_assert_strict_closed_rejects_action_writeback_violation(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {
                    "items": [
                        {
                            "action_id": "act-bad",
                            "action_category": "response",
                            "status": "approved",
                            "writeback_required": True,
                            "writeback_applicable": True,
                            "writeback_readiness": "pending",
                            "writeback_status": "pending",
                        }
                    ],
                    "total": 1,
                }
            return {
                "event": {"event_id": "evt-5", "status": "closed"},
                "writeback_required": False,
                "writeback_readiness": "not_required",
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            return ApiResponse(
                status=200,
                data={"report": {"report_quality": "complete"}},
            )

    with pytest.raises(RuntimeError, match="gate-applicable writeback actions not converged"):
        full_loop_mod.assert_strict_closed_acceptance(_Client(), "evt-5", max_wait_s=0.0)


def test_assert_strict_closed_acceptance_retries_until_converged(full_loop_mod) -> None:
    class _Client:
        def __init__(self) -> None:
            self._attempts = 0

        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": [], "total": 0}
            self._attempts += 1
            readiness = "pending" if self._attempts == 1 else "ready"
            wb_status = None if self._attempts == 1 else "confirmed"
            return {
                "event": {"event_id": "evt-6", "status": "closed"},
                "writeback_required": True,
                "writeback_readiness": readiness,
                "writeback_overall_status": wb_status,
                "pending_writeback_count": 1 if self._attempts == 1 else 0,
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            return ApiResponse(
                status=200,
                data={"report": {"report_quality": "complete"}},
            )

    result = full_loop_mod.assert_strict_closed_acceptance(
        _Client(),
        "evt-6",
        max_wait_s=2.0,
        poll_interval_s=0.01,
    )
    assert result["writeback_readiness"] == "ready"


def test_list_all_event_actions_paginates(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "page=1" in path:
                return {"items": [{"action_id": f"act-{i}"} for i in range(2)], "total": 3}
            if "page=2" in path:
                return {"items": [{"action_id": "act-2"}], "total": 3}
            raise AssertionError(path)

    actions = full_loop_mod.list_all_event_actions(_Client(), "evt-page")
    assert len(actions) == 3


def test_list_all_event_actions_raises_when_total_truncated(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "page=1" in path:
                return {"items": [{"action_id": "act-0"}], "total": 3}
            if "page=2" in path:
                return {"items": [], "total": 3}
            raise AssertionError(path)

    with pytest.raises(full_loop_mod.DynamicEvalApiError, match="pagination truncated"):
        full_loop_mod.list_all_event_actions(_Client(), "evt-trunc")


def test_strict_assert_budget_uses_remaining_wall_clock(full_loop_mod) -> None:
    assert full_loop_mod._strict_assert_budget(max_wait_s=240.0, elapsed_s=200.0) == 40.0
    assert full_loop_mod._strict_assert_budget(max_wait_s=240.0, elapsed_s=235.0) == 10.0
    assert full_loop_mod._strict_assert_budget(max_wait_s=30.0, elapsed_s=0.0) == 30.0
    assert full_loop_mod._strict_assert_budget(max_wait_s=240.0, elapsed_s=10.0) == 60.0


def test_require_closed_seed_missing_event_ids_message(full_loop_mod) -> None:
    with (
        patch.object(full_loop_mod, "DynamicEvalClient") as client_cls,
        patch.object(
            full_loop_mod,
            "seed_via_compose",
            return_value={"accepted": 1, "event_ids": []},
        ),
    ):
        client = client_cls.return_value

        def _get_json(path: str) -> dict[str, object]:
            if "/events" in path:
                return {"items": []}
            return dict(_CELERY_READY_HEALTH)

        client.get_json.side_effect = _get_json
        with pytest.raises(SystemExit, match="seed summary missing event_ids"):
            full_loop_mod.main(
                [
                    "--require-closed",
                    "--seed-via-compose",
                ]
            )


def test_empty_event_id_is_ignored(full_loop_mod) -> None:
    with patch.object(full_loop_mod, "DynamicEvalClient") as client_cls:
        client = client_cls.return_value
        client.get_json.side_effect = lambda path: (
            {"items": []} if "/events" in path else dict(_CELERY_READY_HEALTH)
        )
        with pytest.raises(SystemExit, match="heuristic DB selection is forbidden"):
            full_loop_mod.main(["--require-closed", "--event-id", ""])


def test_require_closed_refuses_background_task_mode(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="task_mode=celery"):
        full_loop_mod.assert_strict_closed_celery_ready(
            {
                "celery": {
                    "task_mode": "background",
                    "worker": {"status": "not_applicable", "workers": 0},
                }
            }
        )


def test_require_closed_refuses_celery_without_workers(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="investigation worker"):
        full_loop_mod.assert_strict_closed_celery_ready(
            {
                "celery": {
                    "task_mode": "celery",
                    "worker": {"status": "degraded", "workers": 0},
                }
            }
        )


def test_require_closed_accepts_celery_with_worker(full_loop_mod) -> None:
    full_loop_mod.assert_strict_closed_celery_ready(_CELERY_READY_HEALTH)


def test_require_closed_main_fail_fast_on_background_health(full_loop_mod) -> None:
    with patch.object(full_loop_mod, "DynamicEvalClient") as client_cls:
        client = client_cls.return_value
        client.get_json.return_value = {
            "playbook_resources": {"status": "ready"},
            "celery": {
                "task_mode": "background",
                "worker": {"status": "not_applicable", "workers": 0},
            },
        }
        with pytest.raises(SystemExit, match="task_mode=celery"):
            full_loop_mod.main(
                [
                    "--require-closed",
                    "--event-id",
                    "evt-x",
                    "--skip-baseline-preflight",
                ]
            )


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
    assert "eval-full-loop-matrix:" in text
    assert "eval-eventtype-8:" in text
    assert "dynamic_eval_full_loop.py" in text
    assert "dynamic_eval_matrix.py" in text
    assert "--seed-via-compose" in text
    assert "--fresh-volumes" in text
    assert "EVAL_MATRIX_PROFILE_BY_SCENARIO" in text
    assert "BOOTSTRAP_GENERATE_REPORT" in text
    full_loop_recipe = text[text.index("eval-full-loop:") : text.index("eval-full-loop-matrix:")]
    assert "--suite eventtype8" not in full_loop_recipe
    eventtype8_recipe = text[text.index("eval-eventtype-8:") :]
    assert "--suite eventtype8" in eventtype8_recipe
    assert "--require-closed" in eventtype8_recipe
    assert "docker-compose.worker.yml" in text
    assert "WORKER_COMPOSE" in text
    assert "--seed-via-compose" in eventtype8_recipe


def test_evaluation_targets_support_clean_release_archives() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "SOURCE_REVISION_FILE ?= $(CURDIR)/SOURCE_REVISION" in text
    assert "EVAL_CODE_SHA ?=" in text
    assert text.count('--code-sha "$(EVAL_CODE_SHA)"') == 4
    assert '--code-sha "$$(git -C "$(CURDIR)" rev-parse HEAD)"' not in text


def _makefile_recipe_commands(text: str, start: str, end: str) -> str:
    block = text[text.index(start) : text.index(end)]
    return "\n".join(
        line
        for line in block.splitlines()
        if not line.lstrip().startswith("@echo") and not line.lstrip().startswith("@#")
    )


def test_eval_targets_do_not_compose_remote_embedding() -> None:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    overlay = "docker-compose.embedding-remote.yml"
    full_loop = _makefile_recipe_commands(text, "eval-full-loop:", "eval-full-loop-matrix:")
    matrix = _makefile_recipe_commands(text, "eval-full-loop-matrix:", "eval-eventtype-8:")
    eventtype8 = _makefile_recipe_commands(text, "eval-eventtype-8:", "up-demo:")
    assert overlay not in full_loop
    assert overlay not in matrix
    assert overlay not in eventtype8
    assert "EMBEDDING_MODE=remote" not in full_loop
    assert "EMBEDDING_MODE=remote" not in matrix
    assert "EMBEDDING_MODE=remote" not in eventtype8
    eval_compose = EVAL_COMPOSE.read_text(encoding="utf-8")
    assert "EMBEDDING_MODE" not in eval_compose
    matrix_script = MATRIX_PATH.read_text(encoding="utf-8")
    assert overlay not in matrix_script


def test_remote_embedding_overlay_is_opt_in_not_kind() -> None:
    assert EMBEDDING_REMOTE_COMPOSE.is_file()
    text = EMBEDDING_REMOTE_COMPOSE.read_text(encoding="utf-8")
    assert "EMBEDDING_MODE: remote" in text
    assert "DISPOSITION_ADAPTER_KIND:" not in text
    assert "SOURCE_MODE:" not in text
    assert "DISPOSITION_MODE:" not in text
    assert "TOOL_MODE:" not in text
    assert "eval-eventtype-8" in text
    assert "KIND=mock" in text
    makefile = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "up-embedding-remote:" in makefile
    assert "NOT eval-eventtype-8" in makefile


def test_remote_embedding_runbook_locks_gold_mock() -> None:
    assert REMOTE_EMBEDDING_DOC.is_file()
    text = REMOTE_EMBEDDING_DOC.read_text(encoding="utf-8")
    assert "EMBEDDING_MODE=mock" in text
    assert "eval-eventtype-8" in text
    assert "eval-full-loop" in text
    assert "vector_unavailable" in text
    assert "make load-kb" in text
    assert "embedding_release_id" in text or "EMBEDDING_RELEASE_ID" in text
    assert "禁止写" in text
    assert "300+" in text
    assert "KIND=mock" in text
    deployment = DEPLOYMENT_DOC.read_text(encoding="utf-8")
    assert "rag-remote-embedding-demo.md" in deployment
    env = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "rag-remote-embedding-demo.md" in env
    active = [
        line.strip() for line in env.splitlines() if line.strip().startswith("EMBEDDING_MODE=")
    ]
    assert "EMBEDDING_MODE=remote" not in active


def test_deployment_docs_gold_path_honesty() -> None:
    text = DEPLOYMENT_DOC.read_text(encoding="utf-8")
    assert "ISSUE-256" in text
    assert "ISSUE-301" in text
    assert "ISSUE-304" in text
    assert "ISSUE-313" in text
    assert "eval-full-loop" in text
    assert "eval-full-loop-matrix" in text
    assert "profile-by-scenario" in text
    assert "CHANGE_WINDOW_BASELINE_PATH" in text
    assert "make up-demo" in text
    assert "make smoke-demo" in text
    assert "smoke_event_terminal" in text or "SMOKE_TERMINAL_MODE" in text
    assert "seed_mock_xdr_and_ingest" in text
    assert "POST /events" in text
    assert "APPROVAL_TIMEOUT_MINUTES" in text
    assert "EMBEDDING_MODE" in text
    assert "-c 2" in text
    assert "docker-compose.eval.yml" in text


def test_full_loop_documents_seed_fixture_not_post_events() -> None:
    text = FULL_LOOP_PATH.read_text(encoding="utf-8")
    assert "seed_mock_xdr_and_ingest" in text
    assert "POST /api/v1/events" in text or "POST /events" in text
    assert "include_response_execution" in text
    assert "APPROVAL_TIMEOUT" in text
    assert "--require-closed" in text
    assert "--analysis-only" in text
    assert "unwrap_event_detail" in text


def test_eval_compose_override_unpublishes_host_ports() -> None:
    text = EVAL_COMPOSE.read_text(encoding="utf-8")
    assert "ISSUE-301" in text
    assert "ports: !reset []" in text
    assert "eval-frontend" in text


def test_matrix_script_contains_isolation_keywords() -> None:
    text = MATRIX_PATH.read_text(encoding="utf-8")
    assert "event_ids_from_seed_summary" in text
    assert "down" in text and "remove-orphans" in text
    assert "docker-compose.eval.yml" in text
    assert "--require-closed" in text
    assert "--profile-by-scenario" in text
    assert "127.0.0.1:8000" in text
    assert "BooleanOptionalAction" in text or "default=True" in text


def test_parse_seed_stdout_multiline_json(full_loop_mod) -> None:
    stdout = """
[seed] starting
{
  "scenario_id": "insider_data_exfiltration",
  "object_counts": {"incident": 1}
}
[seed] ingesting
{
  "accepted": 2,
  "duplicate": 0,
  "rejected": 0,
  "degraded": false,
  "event_ids": ["evt-1", "evt-2"]
}
"""
    summary = full_loop_mod.parse_seed_stdout(stdout)
    assert summary["accepted"] == 2
    assert summary["rejected"] == 0
    assert summary["event_ids"] == ["evt-1", "evt-2"]


def test_select_gold_event_ids_prefers_fresh_over_stale(full_loop_mod) -> None:
    events = [
        {
            "event_id": "evt-stale",
            "status": "new",
            "title": "old leftover",
            "created_at": "2026-01-01T00:00:00Z",
        },
        {
            "event_id": "evt-fresh",
            "status": "new",
            "title": "insider data exfiltration finance",
            "created_at": "2026-08-08T00:00:00Z",
        },
        {
            "event_id": "evt-running",
            "status": "analyzing",
            "title": "insider data exfiltration",
            "created_at": "2026-08-08T00:01:00Z",
        },
    ]
    ids = full_loop_mod.select_gold_event_ids(
        events,
        max_events=1,
        scenario="insider_data_exfiltration",
        before_ids={"evt-stale"},
    )
    assert ids == ["evt-fresh"]


def test_assert_evidence_ok_requires_non_failed(full_loop_mod) -> None:
    ok = full_loop_mod.assert_evidence_ok(
        {"event_context_snapshot": {"collection_status": "partial_done"}},
        event_id="evt-1",
    )
    assert ok == "partial_done"
    with pytest.raises(RuntimeError, match="collection_status='failed'"):
        full_loop_mod.assert_evidence_ok(
            {"event_context_snapshot": {"collection_status": "failed"}},
            event_id="evt-1",
        )
    with pytest.raises(RuntimeError, match="evidence missing"):
        full_loop_mod.assert_evidence_ok(
            {"event_context_snapshot": {"risk_assessment": {}}},
            event_id="evt-1",
        )


def _example_event_detail_payload(
    *,
    event_id: str,
    status: EventStatus = EventStatus.ANALYZING,
) -> dict:
    detail = s.EventDetailResponse(
        event=s.example_security_event(event_id).model_copy(update={"status": status}),
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
    )
    return detail.model_dump(mode="json")


def test_unwrap_event_detail_payload_accepts_event_detail_response(approve_mod) -> None:
    payload = _example_event_detail_payload(
        event_id="evt-wrap",
        status=EventStatus.WAITING_APPROVAL,
    )
    event = approve_mod.unwrap_event_detail_payload(payload, expected_event_id="evt-wrap")
    assert event["event_id"] == "evt-wrap"
    assert event["status"] == "waiting_approval"


def test_unwrap_event_detail_payload_accepts_legacy_flat_event(approve_mod) -> None:
    flat = s.example_security_event("evt-flat").model_dump(mode="json")
    event = approve_mod.unwrap_event_detail_payload(flat, expected_event_id="evt-flat")
    assert event["event_id"] == "evt-flat"


def test_unwrap_event_detail_payload_rejects_event_id_mismatch(approve_mod) -> None:
    payload = _example_event_detail_payload(event_id="evt-other")
    with pytest.raises(approve_mod.DynamicEvalApiError, match="event_id mismatch"):
        approve_mod.unwrap_event_detail_payload(payload, expected_event_id="evt-expected")


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "not-a-dict",
        None,
    ],
)
def test_unwrap_event_detail_payload_rejects_non_dict_payload(
    approve_mod,
    payload: Any,
) -> None:
    with pytest.raises(approve_mod.DynamicEvalApiError, match="unexpected event payload"):
        approve_mod.unwrap_event_detail_payload(payload)


def test_unwrap_event_detail_payload_rejects_missing_event_and_event_id(
    approve_mod,
) -> None:
    with pytest.raises(approve_mod.DynamicEvalApiError, match="unexpected event payload"):
        approve_mod.unwrap_event_detail_payload({"writeback_required": False})


def test_unwrap_event_detail_payload_rejects_empty_event_id(approve_mod) -> None:
    with pytest.raises(approve_mod.DynamicEvalApiError, match="unexpected event payload"):
        approve_mod.unwrap_event_detail_payload({"event_id": ""})


def test_unwrap_event_detail_payload_rejects_non_string_event_id(approve_mod) -> None:
    with pytest.raises(approve_mod.DynamicEvalApiError, match="unexpected event payload"):
        approve_mod.unwrap_event_detail_payload({"event_id": 123})


def test_unwrap_event_detail_payload_falls_back_when_event_null_and_flat_event_id_present(
    approve_mod,
) -> None:
    flat = s.example_security_event("evt-null-event").model_dump(mode="json")
    payload = {"event": None, **flat}
    event = approve_mod.unwrap_event_detail_payload(
        payload,
        expected_event_id="evt-null-event",
    )
    assert event["event_id"] == "evt-null-event"


def test_unwrap_event_detail_payload_rejects_event_null_without_flat_event_id(
    approve_mod,
) -> None:
    with pytest.raises(approve_mod.DynamicEvalApiError, match="unexpected event payload"):
        approve_mod.unwrap_event_detail_payload({"event": None, "writeback_required": False})


def test_collection_status_from_event_after_unwrap(full_loop_mod, approve_mod) -> None:
    payload = _example_event_detail_payload(
        event_id="evt-evidence",
        status=EventStatus.SCORING,
    )
    payload["event"]["event_context_snapshot"] = {"collection_status": "partial_done"}
    event = approve_mod.unwrap_event_detail_payload(payload, expected_event_id="evt-evidence")
    assert full_loop_mod.collection_status_from_event(event) == "partial_done"


def test_openapi_get_event_detail_returns_event_detail_response() -> None:
    spec = json.loads((REPO_ROOT / "contracts" / "openapi" / "openapi.json").read_text())
    schema_ref = spec["paths"]["/api/v1/events/{event_id}"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["$ref"]
    assert schema_ref.endswith("/EventDetailResponse")
    required = set(spec["components"]["schemas"]["EventDetailResponse"]["required"])
    assert required == {"event", "writeback_required", "writeback_readiness"}
    event_ref = spec["components"]["schemas"]["EventDetailResponse"]["properties"]["event"]["$ref"]
    assert event_ref.endswith("/SecurityEvent")


def test_get_event_unwraps_event_detail_response(full_loop_mod, approve_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            assert path == "/api/v1/events/evt-detail"
            return _example_event_detail_payload(
                event_id="evt-detail",
                status=EventStatus.CLOSED,
            )

    event = full_loop_mod.get_event(_Client(), "evt-detail")
    assert event["event_id"] == "evt-detail"
    assert event["status"] == "closed"


def test_get_event_unwraps_legacy_flat_event(full_loop_mod) -> None:
    flat = s.example_security_event("evt-flat-get").model_dump(mode="json")

    class _Client:
        def get_json(self, path: str):
            assert path == "/api/v1/events/evt-flat-get"
            return flat

    event = full_loop_mod.get_event(_Client(), "evt-flat-get")
    assert event["event_id"] == "evt-flat-get"


def test_get_event_raises_on_unexpected_payload(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            return {"writeback_required": False}

    with pytest.raises(full_loop_mod.DynamicEvalApiError, match="unexpected event payload"):
        full_loop_mod.get_event(_Client(), "evt-bad")


def test_get_event_detail_testclient_response_unwraps_for_gold_path(
    approve_mod,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live GET detail JSON must parse through gold-path unwrap helper."""
    from app.core.config import get_settings

    bridge_event = s.example_security_event("evt-bridge").model_copy(
        update={"title": "ISSUE-295 unwrap bridge"},
    )

    class _StubEventService:
        async def get_event(self, event_id: str):
            if event_id != bridge_event.event_id:
                return None
            return bridge_event

    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("LLM_MODE", "mock")
    monkeypatch.setenv("TOOL_MODE", "mock")
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("SIMULATION_ENABLED", "true")
    monkeypatch.setenv("TASK_MODE", "background")
    get_settings.cache_clear()

    reset_deps()
    app.dependency_overrides.clear()

    async def _override_event_service() -> _StubEventService:
        return _StubEventService()

    app.dependency_overrides[get_event_service] = _override_event_service
    client = TestClient(app)
    resp = client.get(
        f"/api/v1/events/{bridge_event.event_id}",
        headers={"Authorization": "Bearer analyst-token"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    event = approve_mod.unwrap_event_detail_payload(
        payload,
        expected_event_id=bridge_event.event_id,
    )
    assert event["event_id"] == bridge_event.event_id
    assert event["title"] == "ISSUE-295 unwrap bridge"
    assert "writeback_required" in payload
    assert "writeback_readiness" in payload
    app.dependency_overrides.clear()
    reset_deps()


def test_run_gold_loop_fails_fast_when_waiting_without_actions(full_loop_mod) -> None:
    class _Client:
        def __init__(self) -> None:
            self.calls = 0

        def get_json(self, path: str):
            if path.startswith("/api/v1/events/") and path.endswith("/actions"):
                return {"items": []}
            if "/actions?" in path:
                return {"items": []}
            payload = _example_event_detail_payload(
                event_id="evt-stall",
                status=EventStatus.WAITING_APPROVAL,
            )
            payload["event"]["event_context_snapshot"] = {"collection_status": "completed"}
            return payload

        def post_json(self, path: str, body=None):
            from dynamic_eval_approve import ApiResponse

            if path.endswith("/investigate"):
                return ApiResponse(
                    status=202,
                    data={"include_response_execution": True},
                )
            raise AssertionError(f"unexpected POST {path}")

    client = _Client()
    # Monkeypatch action list helper used by run_gold_loop.
    full_loop_mod._WAITING_STALL_POLLS = 2
    with pytest.raises(RuntimeError, match="no selectable human-gated actions"):
        full_loop_mod.run_gold_loop(
            client,
            event_ids=["evt-stall"],
            decision="approve",
            generate_report=True,
            poll_interval_s=0.01,
            max_wait_s=5,
        )


def test_gold_scenarios_remain_three_demo_ids(full_loop_mod) -> None:
    assert full_loop_mod.GOLD_SCENARIOS == (
        "insider_data_exfiltration",
        "account_anomaly_fp",
        "suspicious_domain_access",
    )
    assert len(full_loop_mod.GOLD_SCENARIOS) == 3


def test_seed_via_compose_passes_eventtype8_suite(full_loop_mod) -> None:
    captured: list[list[str]] = []

    def _fake_run(cmd, **kwargs):  # noqa: ANN001, ANN003
        captured.append(list(cmd))
        return type(
            "Proc",
            (),
            {"returncode": 0, "stdout": '{"accepted": 1, "event_ids": ["evt-x"]}', "stderr": ""},
        )()

    with patch.object(full_loop_mod.subprocess, "run", side_effect=_fake_run):
        with patch.object(full_loop_mod, "_compose_cmd", return_value=["docker", "compose"]):
            full_loop_mod.seed_via_compose(
                scenario="suspicious_domain_access",
                mock_xdr_url="http://mock-xdr:8100",
                seed=42,
                suite="eventtype8",
            )
    cmd = captured[0]
    assert cmd[cmd.index("--suite") + 1] == "eventtype8"


def test_seed_via_compose_demo_suite_keeps_demo_flag(full_loop_mod) -> None:
    captured: list[list[str]] = []

    def _fake_run(cmd, **kwargs):  # noqa: ANN001, ANN003
        captured.append(list(cmd))
        return type(
            "Proc",
            (),
            {"returncode": 0, "stdout": '{"accepted": 1, "event_ids": ["evt-x"]}', "stderr": ""},
        )()

    with patch.object(full_loop_mod.subprocess, "run", side_effect=_fake_run):
        with patch.object(full_loop_mod, "_compose_cmd", return_value=["docker", "compose"]):
            full_loop_mod.seed_via_compose(
                scenario="suspicious_domain_access",
                mock_xdr_url="http://mock-xdr:8100",
                seed=42,
            )
    cmd = captured[0]
    assert cmd[cmd.index("--suite") + 1] == "demo"


def test_analysis_only_cannot_combine_with_require_closed(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="cannot be combined"):
        full_loop_mod.main(
            [
                "--analysis-only",
                "--require-closed",
                "--event-id",
                "evt-x",
                "--skip-baseline-preflight",
            ]
        )


def test_eventtype8_rejects_analysis_only(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="analysis-only"):
        full_loop_mod.main(
            [
                "--suite",
                "eventtype8",
                "--analysis-only",
                "--event-id",
                "evt-x",
                "--skip-baseline-preflight",
            ]
        )


def test_eventtype8_refuses_mock_llm_health_mode(full_loop_mod) -> None:
    with patch.object(full_loop_mod, "DynamicEvalClient") as client_cls:
        client = client_cls.return_value
        client.get_json.return_value = {
            "llm": {"mode": "mock"},
            "playbook_resources": {"status": "ready"},
        }
        with pytest.raises(SystemExit, match="MockLLM"):
            full_loop_mod.main(
                [
                    "--suite",
                    "eventtype8",
                    "--event-id",
                    "evt-x",
                    "--skip-baseline-preflight",
                ]
            )


def test_demo_suite_does_not_refuse_mock_llm(full_loop_mod) -> None:
    with patch.object(full_loop_mod, "DynamicEvalClient") as client_cls:
        client = client_cls.return_value
        client.get_json.return_value = {
            "llm": {"mode": "mock"},
            "playbook_resources": {"status": "ready"},
        }
        with patch.object(
            full_loop_mod,
            "run_gold_loop",
            return_value={
                "final_statuses": {"evt-x": "closed"},
                "elapsed_s": 1,
                "approval_timeout_used": False,
                "status_trace": {},
                "decisions": {},
            },
        ):
            rc = full_loop_mod.main(
                [
                    "--event-id",
                    "evt-x",
                    "--skip-baseline-preflight",
                    "--json",
                ]
            )
    assert rc == 0


def test_assert_report_generated_by_llm_rejects_template(full_loop_mod) -> None:
    with pytest.raises(RuntimeError, match="generated_by"):
        full_loop_mod.assert_report_generated_by_llm(
            {"generated_by": "template"},
            event_id="evt-1",
        )


def test_assert_report_generated_by_llm_accepts_llm(full_loop_mod) -> None:
    full_loop_mod.assert_report_generated_by_llm(
        {"generated_by": "llm"},
        event_id="evt-1",
    )


def test_strict_closed_template_fails_when_llm_report_required(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": []}
            return {
                "event": {"event_id": "evt-tmpl", "status": "closed"},
                "writeback_required": False,
                "writeback_readiness": "not_required",
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            return ApiResponse(
                status=200,
                data={"report": {"report_quality": "full", "generated_by": "template"}},
            )

    with pytest.raises(RuntimeError, match="generated_by"):
        full_loop_mod.assert_strict_closed_acceptance(
            _Client(),
            "evt-tmpl",
            max_wait_s=0.0,
            require_llm_generated_report=True,
        )


def test_strict_closed_llm_report_passes_when_required(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": []}
            return {
                "event": {"event_id": "evt-llm", "status": "closed"},
                "writeback_required": False,
                "writeback_readiness": "not_required",
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            return ApiResponse(
                status=200,
                data={"report": {"report_quality": "full", "generated_by": "llm"}},
            )

    result = full_loop_mod.assert_strict_closed_acceptance(
        _Client(),
        "evt-llm",
        max_wait_s=0.0,
        require_llm_generated_report=True,
    )
    assert result["generated_by"] == "llm"


def test_demo_suite_rejects_eventtype8_only_scenario(full_loop_mod) -> None:
    with pytest.raises(SystemExit, match="not in suite=demo"):
        full_loop_mod.main(
            [
                "--scenario",
                "host_compromise",
                "--event-id",
                "evt-x",
                "--skip-baseline-preflight",
            ]
        )


def test_strict_closed_template_ok_when_llm_report_not_required(full_loop_mod) -> None:
    class _Client:
        def get_json(self, path: str):
            if "/actions" in path:
                return {"items": []}
            return {
                "event": {"event_id": "evt-tmpl-demo", "status": "closed"},
                "writeback_required": False,
                "writeback_readiness": "not_required",
            }

        def request(self, method: str, path: str):
            from dynamic_eval_approve import ApiResponse

            return ApiResponse(
                status=200,
                data={"report": {"report_quality": "full", "generated_by": "template"}},
            )

    result = full_loop_mod.assert_strict_closed_acceptance(
        _Client(),
        "evt-tmpl-demo",
        max_wait_s=0.0,
        require_llm_generated_report=False,
    )
    assert result["generated_by"] == "template"


def test_demo_suite_does_not_call_eventtype8_mock_column(full_loop_mod) -> None:
    with patch.object(full_loop_mod, "DynamicEvalClient") as client_cls:
        client = client_cls.return_value
        client.get_json.return_value = {
            "llm": {"mode": "mock"},
            "playbook_resources": {"status": "ready"},
        }
        with patch.object(
            full_loop_mod,
            "run_gold_loop",
            return_value={
                "final_statuses": {"evt-x": "closed"},
                "elapsed_s": 1,
                "approval_timeout_used": False,
                "status_trace": {},
                "decisions": {},
            },
        ):
            with patch.object(full_loop_mod, "run_eventtype8_mock_column_gate") as gate:
                rc = full_loop_mod.main(
                    [
                        "--event-id",
                        "evt-x",
                        "--skip-baseline-preflight",
                        "--json",
                    ]
                )
    assert rc == 0
    gate.assert_not_called()


def test_eventtype8_suite_calls_mock_column_gate(full_loop_mod, monkeypatch) -> None:
    monkeypatch.delenv("LLM_MODE", raising=False)
    monkeypatch.setenv("LLM_MODE", "openai")
    with patch.object(full_loop_mod, "DynamicEvalClient") as client_cls:
        client = client_cls.return_value
        client.get_json.return_value = {
            "llm": {"mode": "openai"},
            "playbook_resources": {"status": "ready"},
            "celery": {
                "task_mode": "celery",
                "worker": {"status": "ok", "workers": 1},
            },
        }
        with patch.object(
            full_loop_mod,
            "run_gold_loop",
            return_value={
                "final_statuses": {"evt-x": "closed"},
                "elapsed_s": 1,
                "approval_timeout_used": False,
                "status_trace": {},
                "decisions": {},
            },
        ):
            with patch.object(
                full_loop_mod,
                "run_eventtype8_mock_column_gate",
                return_value={"scenario": "insider_data_exfiltration", "column": "mock_xdr"},
            ) as gate:
                rc = full_loop_mod.main(
                    [
                        "--suite",
                        "eventtype8",
                        "--event-id",
                        "evt-x",
                        "--skip-baseline-preflight",
                        "--json",
                    ]
                )
    assert rc == 0
    gate.assert_called()
    assert gate.call_args.args[1] == "evt-x"
    assert gate.call_args.args[2] == "insider_data_exfiltration"
