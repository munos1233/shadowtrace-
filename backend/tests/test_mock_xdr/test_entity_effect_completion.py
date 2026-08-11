"""Unit tests for Mock XDR entity effect completion (ISSUE-311)."""

from __future__ import annotations

import pytest

from app.mock_xdr.state import MockValidationError, MockXDRState
from app.models.disposition import DispositionCommand
from app.models.enums import DispositionIntentKind, WritebackStatus
from app.providers.tools.mock_provider import (
    MockToolProvider,
    write_xdr_entity_effect_observation,
)
from app.tools.mock_state import MockEnvironmentState


def _entity_command(*, disposition_id: str = "disp-entity-1") -> DispositionCommand:
    return DispositionCommand.model_validate(
        {
            "disposition_id": disposition_id,
            "action_id": "act-entity-1",
            "closure_cycle": 1,
            "intent_kind": DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
            "source_locator": {
                "source_product": "mock_xdr",
                "source_tenant_id": "tenant-demo",
                "connector_id": "conn-1",
                "source_kind": "incident",
                "source_object_id": "inc-1",
            },
            "operation_code": "submit_entity_action",
            "operation_params": {
                "operation_code": "submit_entity_action",
                "entity_action_code": "block_ip",
                "canonical_target": "203.0.113.50",
            },
            "target_results": [
                {
                    "canonical_target": "203.0.113.50",
                    "status": "unknown",
                }
            ],
            "operator_id": "test",
            "idempotency_key": "idem-entity-1",
            "execution_owner": "xdr_managed",
        }
    )


def test_complete_entity_effect_applies_provider_state_and_readback() -> None:
    state = MockXDRState()
    state.upsert_object(
        "incident",
        "inc-1",
        {
            "reference": {
                "source_product": "mock_xdr",
                "source_tenant_id": "tenant-demo",
                "connector_id": "conn-1",
                "source_kind": "incident",
                "source_object_id": "inc-1",
                "source_disposition": "processing",
            }
        },
    )
    command = _entity_command()
    receipt = state.submit_disposition(command)
    assert receipt.status is WritebackStatus.ACCEPTED

    payload = state.complete_entity_effect(
        command.disposition_id,
        writeback_id=receipt.writeback_id,
        action_id=command.action_id,
    )
    assert payload["verified"] is True
    assert payload["applied_status"] == "blocked"
    assert payload["target_type"] == "ip"
    assert payload["target"] == "203.0.113.50"
    assert payload["provider_record_id"]

    again = state.complete_entity_effect(
        command.disposition_id,
        writeback_id=receipt.writeback_id,
        action_id=command.action_id,
    )
    assert again["verified"] is True
    assert again["provider_record_id"] == payload["provider_record_id"]


def test_complete_entity_effect_rejects_non_accepted_receipt() -> None:
    state = MockXDRState()
    state.upsert_object(
        "incident",
        "inc-1",
        {"reference": {"source_object_id": "inc-1", "source_disposition": "processing"}},
    )
    command = _entity_command(disposition_id="disp-failed")
    receipt = state.submit_disposition(command)
    attempt = state.disposition_by_id[command.disposition_id]
    attempt.receipts[-1] = receipt.model_copy(update={"status": WritebackStatus.FAILED})

    with pytest.raises(MockValidationError, match="ACCEPTED"):
        state.complete_entity_effect(
            command.disposition_id,
            writeback_id=receipt.writeback_id,
            action_id=command.action_id,
        )


@pytest.mark.asyncio
async def test_write_xdr_entity_effect_observation_projects_verify_surface() -> None:
    state = MockEnvironmentState.in_memory()
    await write_xdr_entity_effect_observation(
        state,
        entity_action_code="block_ip",
        target_type="ip",
        target="203.0.113.50",
        applied_status="blocked",
        job_id="job-obs-1",
        action_id="act-obs-1",
        writeback_id="wbk-obs-1",
        provider_record_id="entfx-00000001",
        observed_version=1,
        observation_delay_ms=0,
    )
    observation = await state.get_observation(
        "ip_blocks",
        "203.0.113.50",
        include_pending=True,
        job_id="job-obs-1",
    )
    assert observation is not None
    assert observation.status == "blocked"
    assert observation.action_id == "act-obs-1"
    assert observation.value["writeback_id"] == "wbk-obs-1"
