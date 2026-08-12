"""Outbound message_code hardening in DispositionCommandFactory (ISSUE-188).

The factory must never copy free-form ``TargetExecutionResult.message`` text into
the outbound ``TargetDispositionResult.message_code``. Long / narrative / marker
-bearing provider messages are replaced with the deterministic
``message_truncated`` placeholder; short code phrases (as the Mock provider
emits) pass through unchanged so the normal DIRECT_TOOL writeback stays green.
"""

from __future__ import annotations

import pytest

from app.core.guardrails import OutboundDispositionGuard
from app.models.action import Action
from app.models.disposition import SourceObjectLocator, TargetDispositionResult
from app.models.enums import (
    ActionCategory,
    ActionLevel,
    ExecutionJobStatus,
    ExecutionOwner,
    SourceObjectKind,
    TargetExecutionStatus,
    WritebackReadiness,
)
from app.models.execution import ActionExecutionJob, TargetExecutionResult
from app.services.disposition_command_factory import DispositionCommandFactory

# ISSUE-188 §目标: 出站 message_code 仅为短码/枚举.
FALLBACK = "message_truncated"
NARRATIVE = (
    "the host was compromised by a sophisticated attacker who exfiltrated "
    "credentials and moved laterally to a second internal network segment"
)


def _locator() -> SourceObjectLocator:
    return SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="t1",
        connector_id="conn-1",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id="INC-1",
    )


def _action() -> Action:
    return Action(
        action_id="act-1",
        event_id="evt-1",
        plan_revision=1,
        action_fingerprint="fp",
        action_category=ActionCategory.RESPONSE,
        action_name="Isolate Host",
        tool_name="isolate_host",
        action_level=ActionLevel.L3,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
        target="host-1",
    )


def _job(results: list[TargetExecutionResult]) -> ActionExecutionJob:
    return ActionExecutionJob(
        job_id="job-1",
        event_id="evt-1",
        action_id="act-1",
        provider_name="mock_tool",
        idempotency_key="idem-1",
        status=ExecutionJobStatus.SUCCESS,
        target_results=results,
    )


def _build(messages: list[str | None]) -> list[TargetDispositionResult]:
    factory = DispositionCommandFactory()
    command = factory.build_execution_result_record(
        _action(),
        _job(
            [
                TargetExecutionResult(
                    canonical_target="host:host-1",
                    status=TargetExecutionStatus.SUCCESS,
                    code="isolate_success",
                    message=message,
                )
                for message in messages
            ]
        ),
        source_locator=_locator(),
        source_concurrency_token=None,
        operator_id="system",
        disposition_id="disp-1",
        closure_cycle=1,
    )
    return command.target_results


def test_mock_style_short_message_code_is_preserved() -> None:
    # The Mock main path emits short lowercase phrases like "isolate success".
    # The outbound message_code must survive unchanged so writeback stays green.
    results = _build(["isolate success"])
    assert results[0].message_code == "isolate success"
    assert results[0].provider_code == "isolate_success"


def test_none_message_code_stays_none() -> None:
    results = _build([None])
    assert results[0].message_code is None


def test_blank_message_code_is_treated_as_absent() -> None:
    for blank in ("", "   "):
        results = _build([blank])
        assert results[0].message_code is None, repr(blank)


def test_overlong_narrative_is_replaced_not_emitted() -> None:
    assert len(NARRATIVE) > 64
    results = _build([NARRATIVE])
    assert results[0].message_code == FALLBACK
    assert results[0].message_code != NARRATIVE


def test_marker_bearing_message_is_replaced() -> None:
    # ISSUE-188 recommended fix #3: message containing decision_trace / report
    # keywords must be blocked by guard or factory. Here the factory replaces it.
    for marker_text in (
        "attacker used decision_trace to pivot",
        "see investigation report for full analysis",
        "system prompt was injected via api_key",
        "Bearer sk-leak-1234567890abcdef",
    ):
        results = _build([marker_text])
        assert results[0].message_code == FALLBACK, marker_text
        assert marker_text not in (results[0].message_code or "")


def test_invalid_charset_message_is_replaced() -> None:
    results = _build(["Blocked! <b>host</b> @ 198.51.100.9\n"])
    assert results[0].message_code == FALLBACK


def test_outbound_command_never_carries_narrative_verbatim() -> None:
    narrative = (
        "the attacker leveraged decision_trace evidence and an investigation "
        "report to establish persistence across multiple systems"
    )
    command = _build([narrative])
    dumped = command[0].model_dump(mode="json")
    assert narrative not in (dumped["message_code"] or "")
    assert narrative not in str(dumped)
    assert dumped["message_code"] == FALLBACK


def test_mixed_target_results_sanitize_independently() -> None:
    results = _build(["isolate success", NARRATIVE, None])
    assert [item.message_code for item in results] == ["isolate success", FALLBACK, None]


@pytest.mark.asyncio
async def test_sanitized_command_passes_outbound_guard() -> None:
    # A factory-built command (sanitized) must clear the outbound guard, proving
    # the normal DIRECT_TOOL writeback path is still green after hardening.
    factory = DispositionCommandFactory()
    command = factory.build_execution_result_record(
        _action(),
        _job(
            [
                TargetExecutionResult(
                    canonical_target="host:host-1",
                    status=TargetExecutionStatus.SUCCESS,
                    code="isolate_success",
                    message="isolate success",
                )
            ]
        ),
        source_locator=_locator(),
        source_concurrency_token=None,
        operator_id="system",
        disposition_id="disp-1",
        closure_cycle=1,
    )
    result = await OutboundDispositionGuard().validate(
        command,
        {
            "event_id": "evt-1",
            "source_locator": _locator(),
            "approved_action_ids": {"act-1"},
        },
    )
    assert result.passed is True


def _xdr_managed_action(*, tool_name: str = "isolate_host") -> Action:
    return Action(
        action_id="act-xdr-1",
        event_id="evt-1",
        plan_revision=1,
        action_fingerprint="fp",
        action_category=ActionCategory.RESPONSE,
        action_name="Isolate Host",
        tool_name=tool_name,
        action_level=ActionLevel.L3,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
        target="host-1",
        target_type="host",
    )


def test_build_entity_action_submit_unknown_code_lists_known_specs() -> None:
    factory = DispositionCommandFactory()
    with pytest.raises(ValueError, match=r"known codes: .*isolate_host"):
        factory.build_entity_action_submit(
            _xdr_managed_action(),
            source_locator=_locator(),
            source_concurrency_token=None,
            operator_id="system",
            disposition_id="disp-1",
            writeback_id="wbk-1",
            closure_cycle=1,
            entity_action_code="contain_device",
        )


def test_entity_action_code_for_unknown_tool_lists_known_specs() -> None:
    from app.services.disposition_command_factory import entity_action_code_for

    with pytest.raises(ValueError, match=r"known codes: .*isolate_host"):
        entity_action_code_for(_xdr_managed_action(tool_name="contain_device"))
