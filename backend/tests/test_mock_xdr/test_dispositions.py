"""Disposition writeback statuses, async jobs, idempotency (ISSUE-010 §验收3)."""

from __future__ import annotations

import pytest

from app.mock_xdr.models import MockFailureProfile
from app.mock_xdr.state import MockValidationError, MockXDRState, idempotency_key_hash
from app.models.enums import (
    ConfirmationEvidence,
    DispositionIntentKind,
    ExecutionJobStatus,
    SourceDisposition,
    WritebackStatus,
)
from tests.test_mock_xdr.conftest import disposition_command


def test_sync_accept_then_readback_confirmed(state: MockXDRState) -> None:
    token = state.objects[("incident", "INC-1")].concurrency_token
    cmd = disposition_command(token=token)
    receipt = state.submit_disposition(cmd)
    assert receipt.status is WritebackStatus.ACCEPTED
    assert receipt.provider_job_id is None
    confirmed = state.confirm_via_readback(cmd.disposition_id)
    assert confirmed.status is WritebackStatus.CONFIRMED
    assert confirmed.confirmation_evidence is ConfirmationEvidence.READBACK_VERIFIED
    assert confirmed.simulated is True


def test_conflict_on_token_mismatch(state: MockXDRState) -> None:
    cmd = disposition_command(token="wrong-token", idempotency_key="idem-conflict")
    receipt = state.submit_disposition(cmd)
    assert receipt.status is WritebackStatus.CONFLICT
    assert receipt.provider_code == "version_conflict"


def test_partial_target_success(state: MockXDRState) -> None:
    state.failure_profile = MockFailureProfile(seed=1, force_partial_targets=True)
    token = state.objects[("incident", "INC-1")].concurrency_token
    cmd = disposition_command(
        intent=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
        idempotency_key="idem-partial",
        token=token,
        disposition_id="disp-partial",
    )
    receipt = state.submit_disposition(cmd)
    assert receipt.status is WritebackStatus.PARTIAL
    assert len(receipt.target_results) == 1
    # With one target and force_partial, first is CONFIRMED in our impl when only one —
    # ensure status domain is WritebackStatus not job status.
    assert receipt.provider_job_id is None


def test_async_job_queued_running_terminal(state: MockXDRState) -> None:
    state.failure_profile = MockFailureProfile(seed=2, async_disposition=True)
    token = state.objects[("incident", "INC-1")].concurrency_token
    cmd = disposition_command(
        token=token, idempotency_key="idem-async", disposition_id="disp-async"
    )
    receipt = state.submit_disposition(cmd)
    assert receipt.status is WritebackStatus.ACCEPTED
    assert receipt.provider_job_id is not None
    job = state.get_job(receipt.provider_job_id)
    assert job.status is ExecutionJobStatus.QUEUED
    state.advance_job(receipt.provider_job_id, ExecutionJobStatus.RUNNING)
    assert state.get_job(receipt.provider_job_id).status is ExecutionJobStatus.RUNNING
    state.advance_job(receipt.provider_job_id, ExecutionJobStatus.SUCCESS)
    assert state.get_job(receipt.provider_job_id).status is ExecutionJobStatus.SUCCESS
    # WritebackStatus lives on receipts — not mixed into job.status
    latest = state.disposition_by_id["disp-async"].receipts[-1]
    assert latest.status is WritebackStatus.CONFIRMED
    assert state.get_job(receipt.provider_job_id).status is ExecutionJobStatus.SUCCESS


def test_idempotency_lookup_after_lost_response(state: MockXDRState, client) -> None:
    token = state.objects[("incident", "INC-1")].concurrency_token
    cmd = disposition_command(token=token, idempotency_key="idem-lost", disposition_id="disp-lost")
    first = state.submit_disposition(cmd)
    # Simulate lost response: look up by hash
    key_hash = idempotency_key_hash("idem-lost")
    headers = {"Authorization": f"Bearer {state.write_token}"}
    r = client.get(f"/mock-xdr/v1/dispositions/by-idempotency/{key_hash}", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["writeback_id"] == first.writeback_id
    assert body["disposition_id"] == "disp-lost"
    # Replay same key returns same acceptance
    second = state.submit_disposition(cmd)
    assert second.writeback_id == first.writeback_id
    assert second.sequence == first.sequence


def test_idempotency_reuse_with_different_payload_rejected(state: MockXDRState) -> None:
    token = state.objects[("incident", "INC-1")].concurrency_token
    first = disposition_command(token=token, idempotency_key="idem-dup", disposition_id="disp-x")
    state.submit_disposition(first)
    # Same idempotency key + a different command payload is a caller bug → reject.
    token2 = state.objects[("incident", "INC-1")].concurrency_token
    second = disposition_command(
        token=token2,
        idempotency_key="idem-dup",
        disposition_id="disp-y",
        target=SourceDisposition.COMPLETED,
    )
    with pytest.raises(MockValidationError, match="idempotency key reused"):
        state.submit_disposition(second)


def test_source_disposition_unchanged_until_confirm(state: MockXDRState) -> None:
    token = state.objects[("incident", "INC-1")].concurrency_token
    cmd = disposition_command(token=token, target=SourceDisposition.CONTAINED)
    receipt = state.submit_disposition(cmd)
    assert receipt.status is WritebackStatus.ACCEPTED
    # Accept alone must NOT mutate the source object's disposition.
    rb = state.readback_source_disposition("incident", "INC-1")
    assert rb["source_disposition"] == SourceDisposition.PENDING.value
    # Only the authoritative readback confirm applies provider truth.
    state.confirm_via_readback(cmd.disposition_id)
    rb2 = state.readback_source_disposition("incident", "INC-1")
    assert rb2["source_disposition"] == SourceDisposition.CONTAINED.value


def test_unauthorized_analysis_fields_rejected(state: MockXDRState, client) -> None:
    token = state.objects[("incident", "INC-1")].concurrency_token
    payload = disposition_command(token=token, idempotency_key="idem-leak").model_dump(mode="json")
    payload["decision_trace"] = {"step": "bad"}
    payload["report"] = "should never egress"
    headers = {"Authorization": f"Bearer {state.write_token}"}
    r = client.post("/mock-xdr/v1/dispositions", headers=headers, json=payload)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error_code"] == "unauthorized_field"
