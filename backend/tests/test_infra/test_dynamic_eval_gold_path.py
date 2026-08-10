"""ISSUE-256 gold-path dynamic-eval profile guards (no live stack required)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from app.api.v1 import schemas as s
from app.models.enums import EventStatus, WritebackReadiness

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
  "degraded": false
}
"""
    summary = full_loop_mod.parse_seed_stdout(stdout)
    assert summary["accepted"] == 2
    assert summary["rejected"] == 0


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
    schema_ref = (
        spec["paths"]["/api/v1/events/{event_id}"]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
    )
    assert schema_ref.endswith("/EventDetailResponse")
    required = set(spec["components"]["schemas"]["EventDetailResponse"]["required"])
    assert {"event", "writeback_required", "writeback_readiness"}.issubset(required)


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
