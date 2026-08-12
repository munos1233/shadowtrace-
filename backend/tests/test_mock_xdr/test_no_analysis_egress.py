"""Assert analysis / report / prompt / evidence never accepted (ISSUE-010 §验收5)."""

from __future__ import annotations

import pytest

from app.mock_xdr.state import find_forbidden_analysis_keys


def test_find_forbidden_keys_nested() -> None:
    payload = {
        "disposition_id": "disp-1",
        "operation_params": {"target_disposition": "contained"},
        "meta": {
            "decision_trace": [{"thought": "nope"}],
            "nested": {"prompt": "system: ..."},
        },
        "evidence": [{"raw": "secret"}],
        "report": "# markdown",
    }
    hits = find_forbidden_analysis_keys(payload)
    assert any("decision_trace" in h for h in hits)
    assert any("prompt" in h for h in hits)
    assert any("evidence" in h for h in hits)
    assert any("report" in h for h in hits)


def test_captured_requests_contain_no_forbidden(state, client) -> None:
    from tests.test_mock_xdr.conftest import disposition_command

    token = state.objects[("incident", "INC-1")].concurrency_token
    cmd = disposition_command(token=token, idempotency_key="idem-clean")
    headers = {"Authorization": f"Bearer {state.write_token}"}
    r = client.post(
        "/mock-xdr/v1/dispositions",
        headers=headers,
        json=cmd.model_dump(mode="json"),
    )
    assert r.status_code == 200
    captured_resp = client.get("/mock-xdr/v1/control/captured-requests")
    assert captured_resp.status_code == 200, captured_resp.text
    captured = captured_resp.json()["items"]
    assert captured
    for item in captured:
        assert find_forbidden_analysis_keys(item) == []
    # Also assert against in-memory capture (control plane may be gated).
    assert state.captured_requests
    for item in state.captured_requests:
        assert find_forbidden_analysis_keys(item) == []


# ---------------------------------------------------------------------------
# Parameterized: all four DispositionIntentKind payload variants (ISSUE-064)
# ---------------------------------------------------------------------------

_INTENT_PAYLOADS = [
    (
        "entity_action_submit",
        {
            "disposition_id": "disp-1",
            "operation_code": "submit_entity_action",
            "operation_params": {
                "entity_action_code": "isolate_host",
                "canonical_target": "host:host-1",
            },
        },
    ),
    (
        "event_status_update",
        {
            "disposition_id": "disp-2",
            "operation_code": "set_event_disposition",
            "operation_params": {
                "target_disposition": "contained",
                "comment_code": "threat_contained",
            },
        },
    ),
    (
        "execution_result_record",
        {
            "disposition_id": "disp-3",
            "operation_code": "record_execution_result",
            "operation_params": {
                "summary_code": "isolate_success",
            },
        },
    ),
    (
        "compensation_record",
        {
            "disposition_id": "disp-4",
            "operation_code": "record_compensation",
            "operation_params": {
                "summary_code": "rollback_complete",
            },
        },
    ),
]


@pytest.mark.parametrize("scenario_name,payload", _INTENT_PAYLOADS)
def test_all_intent_kinds_no_analysis_content_leaked(
    scenario_name: str,
    payload: dict,
) -> None:
    """Verify no forbidden analysis keys appear in any disposition intent kind.

    Covers all four DispositionIntentKind variants:
    ENTITY_ACTION_SUBMIT, EVENT_STATUS_UPDATE, EXECUTION_RESULT_RECORD,
    and COMPENSATION_RECORD.  Also self-tests that detection catches an
    injected forbidden key (``report``).
    """
    hits = find_forbidden_analysis_keys(payload)
    assert not hits, f"{scenario_name}: payload contains forbidden analysis keys: {hits}"

    # Also test with injected forbidden keys to confirm detection works
    contaminated = dict(payload)
    contaminated["report"] = "# Secret Analysis Report"
    contaminated_hits = find_forbidden_analysis_keys(contaminated)
    assert contaminated_hits, (
        f"{scenario_name}: detection is broken — injected 'report' key was not flagged"
    )
    assert any("report" in h for h in contaminated_hits), (
        f"{scenario_name}: expected 'report' to be flagged"
    )
