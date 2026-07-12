"""Disposition/writeback envelope tests (ISSUE-002 实现步骤 3 & 7)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.models.disposition import (
    DispositionCommand,
    DispositionReceipt,
    SetEventDispositionParams,
    SourceObjectLocator,
    TargetDispositionResult,
    TargetWritebackResult,
)
from app.models.enums import (
    ConfirmationEvidence,
    DispositionIntentKind,
    ExecutionOwner,
    SourceDisposition,
    SourceObjectKind,
    TargetExecutionStatus,
    TargetWritebackStatus,
    WritebackStatus,
)


def _locator() -> SourceObjectLocator:
    return SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="t1",
        connector_id="conn-1",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id="INC-1",
    )


def _command(**overrides: object) -> DispositionCommand:
    base = {
        "disposition_id": "disp-1",
        "action_id": "act-1",
        "closure_cycle": 1,
        "intent_kind": DispositionIntentKind.EVENT_STATUS_UPDATE,
        "source_locator": _locator(),
        "operation_code": "set_event_disposition",
        "operation_params": {
            "operation_code": "set_event_disposition",
            "target_disposition": "contained",
        },
        "operator_id": "system",
        "idempotency_key": "idem-1",
        "execution_owner": ExecutionOwner.XDR_MANAGED,
    }
    base.update(overrides)
    return DispositionCommand(**base)  # type: ignore[arg-type]


def test_command_parses_discriminated_operation_params() -> None:
    cmd = _command()
    assert isinstance(cmd.operation_params, SetEventDispositionParams)
    assert cmd.operation_params.target_disposition is SourceDisposition.CONTAINED


def test_command_rejects_extra_top_level_field() -> None:
    # Outbound allowlist: leaking Action.parameters/reason/raw must be impossible.
    with pytest.raises(ValidationError):
        _command(reason="do not leak this")


def test_operation_params_forbid_extra() -> None:
    with pytest.raises(ValidationError):
        _command(
            operation_params={
                "operation_code": "set_event_disposition",
                "target_disposition": "contained",
                "free_text": "leak",
            }
        )


def test_direct_tool_cannot_submit_entity_action() -> None:
    with pytest.raises(ValidationError):
        _command(
            intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
            operation_code="submit_entity_action",
            operation_params={
                "operation_code": "submit_entity_action",
                "entity_action_code": "block",
                "canonical_target": "ip:203.0.113.9",
            },
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )


def test_event_status_update_must_be_xdr_managed() -> None:
    with pytest.raises(ValidationError):
        _command(execution_owner=ExecutionOwner.DIRECT_TOOL)


def test_command_rejects_operation_code_params_mismatch() -> None:
    # Top-level operation_code disagreeing with the params variant must fail.
    with pytest.raises(ValidationError):
        _command(operation_code="record_execution_result")


def test_intent_kind_must_match_params_type() -> None:
    # EVENT_STATUS_UPDATE intent carrying non-SetEventDisposition params fails.
    with pytest.raises(ValidationError):
        _command(
            operation_code="record_execution_result",
            operation_params={"operation_code": "record_execution_result"},
        )


def test_outbound_command_json_keys_are_allowlisted() -> None:
    # Serialize and prove only the allowlisted envelope fields ever appear;
    # Action.parameters / reason / raw_result can never ride along outbound.
    allowed = set(DispositionCommand.model_fields.keys())
    dumped = json.loads(_command().model_dump_json())
    assert set(dumped.keys()) <= allowed
    for forbidden in ("reason", "parameters", "raw_result", "raw"):
        assert forbidden not in dumped


def test_target_disposition_result_is_allowlisted() -> None:
    tr = TargetDispositionResult(
        canonical_target="ip:203.0.113.9",
        status=TargetExecutionStatus.SUCCESS,
        provider_code="ok",
    )
    assert tr.status is TargetExecutionStatus.SUCCESS
    with pytest.raises(ValidationError):
        TargetDispositionResult(
            canonical_target="ip:1",
            status=TargetExecutionStatus.SUCCESS,
            raw_result={"secret": "x"},  # free raw not allowed outbound
        )


def test_receipt_confirmed_requires_evidence() -> None:
    with pytest.raises(ValidationError):
        DispositionReceipt(
            writeback_id="wbk-1",
            sequence=1,
            disposition_id="disp-1",
            action_id="act-1",
            source_record_id="INC-1",
            status=WritebackStatus.CONFIRMED,
        )
    ok = DispositionReceipt(
        writeback_id="wbk-1",
        sequence=2,
        disposition_id="disp-1",
        action_id="act-1",
        source_record_id="INC-1",
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
    )
    assert ok.confirmation_evidence is ConfirmationEvidence.READBACK_VERIFIED


def test_receipt_unknown_allows_null_evidence() -> None:
    r = DispositionReceipt(
        writeback_id="wbk-1",
        sequence=1,
        disposition_id="disp-1",
        action_id="act-1",
        source_record_id="INC-1",
        status=WritebackStatus.UNKNOWN,
    )
    assert r.confirmation_evidence is None


def test_partial_success_and_conflict_targets() -> None:
    r = DispositionReceipt(
        writeback_id="wbk-1",
        sequence=1,
        disposition_id="disp-1",
        action_id="act-1",
        source_record_id="INC-1",
        status=WritebackStatus.PARTIAL,
        target_results=[
            TargetWritebackResult(
                canonical_target="ip:1", status=TargetWritebackStatus.CONFIRMED
            ),
            TargetWritebackResult(
                canonical_target="ip:2", status=TargetWritebackStatus.CONFLICT
            ),
        ],
    )
    statuses = {t.status for t in r.target_results}
    assert TargetWritebackStatus.CONFIRMED in statuses
    assert TargetWritebackStatus.CONFLICT in statuses


def test_opaque_concurrency_token_conflict_is_representable() -> None:
    # An opaque token drives a CONFLICT receipt; token stays an opaque string.
    cmd = _command(source_concurrency_token="opaque-etag-abc")
    assert cmd.source_concurrency_token == "opaque-etag-abc"
    conflict = DispositionReceipt(
        writeback_id="wbk-9",
        sequence=1,
        disposition_id=cmd.disposition_id,
        action_id=cmd.action_id,
        source_record_id="INC-1",
        status=WritebackStatus.CONFLICT,
        provider_code="concurrency_conflict",
    )
    assert conflict.status is WritebackStatus.CONFLICT
