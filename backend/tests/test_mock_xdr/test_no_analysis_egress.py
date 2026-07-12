"""Assert analysis / report / prompt / evidence never accepted (ISSUE-010 §验收5)."""

from __future__ import annotations

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
