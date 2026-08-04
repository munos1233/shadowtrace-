"""ISSUE-171: Close API writeback pre-check aligns with the StateMachine gate.

The event-level aggregate (``_build_writeback_info``) can pass while a
per-action gap remains (an applicable Action without a disposition command,
or outbox rows that are not all CONFIRMED).  The API pre-check must fail
early with the same predicate the StateMachine CLOSED gate applies.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.v1 import events as events_module
from app.core.errors import WritebackPendingError
from app.models.enums import (
    ActionCategory,
    DispositionIntentKind,
    DispositionPolicy,
    SourceDisposition,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.workflow import ClosedGateActionView, TerminalEventWritebackView
from app.services.state_machine_service import (
    closed_gate_blockers_for_views,
    terminal_gate_blockers,
)


def _event(*, policy: DispositionPolicy = DispositionPolicy.REQUIRED) -> Any:
    return MagicMock(disposition_policy=policy)


def _view(
    *,
    action_id: str = "act-1",
    action_category: ActionCategory = ActionCategory.RESPONSE,
    writeback_required: bool = True,
    writeback_applicable: bool = True,
    readiness: WritebackReadiness = WritebackReadiness.READY,
    has_command: bool = True,
    all_confirmed: bool = True,
    wb_status: WritebackStatus | None = WritebackStatus.CONFIRMED,
    rejected: bool = False,
) -> ClosedGateActionView:
    return ClosedGateActionView(
        action_id=action_id,
        action_category=action_category,
        writeback_required=writeback_required,
        writeback_applicable=writeback_applicable,
        writeback_readiness=readiness,
        writeback_status=wb_status,
        has_command=has_command,
        all_required_intents_confirmed=all_confirmed,
        rejected=rejected,
    )


# --------------------------------------------------------------------------- #
# closed_gate_blockers_for_views (shared predicate)
# --------------------------------------------------------------------------- #


def test_blockers_empty_for_fully_confirmed_actions() -> None:
    assert closed_gate_blockers_for_views([_view(), _view(action_id="act-2")]) == []


def test_blocker_non_ready_readiness() -> None:
    reasons = closed_gate_blockers_for_views(
        [_view(readiness=WritebackReadiness.CAPABILITY_UNKNOWN)]
    )
    assert any("readiness is not READY" in reason for reason in reasons)


def test_blocker_missing_disposition_command() -> None:
    reasons = closed_gate_blockers_for_views([_view(has_command=False)])
    assert any("no disposition command" in reason for reason in reasons)


def test_blocker_intents_not_all_confirmed() -> None:
    reasons = closed_gate_blockers_for_views([_view(all_confirmed=False)])
    assert any("not all CONFIRMED" in reason for reason in reasons)


def test_blocker_writeback_status_not_confirmed() -> None:
    reasons = closed_gate_blockers_for_views(
        [_view(all_confirmed=True, wb_status=WritebackStatus.PENDING)]
    )
    assert any("writeback status is pending" in reason for reason in reasons)


def test_blockers_skip_non_applicable_actions() -> None:
    """Rejected / non-response actions are not part of the applicable set."""
    views = [
        _view(action_id="rejected", rejected=True),
        _view(action_id="ticket", action_category=ActionCategory.VERIFICATION),
    ]
    assert closed_gate_blockers_for_views(views) == []


# --------------------------------------------------------------------------- #
# terminal_gate_blockers (shared predicate, terminal EVENT_STATUS_UPDATE)
# --------------------------------------------------------------------------- #


def _terminal(
    *,
    plan_revision: int = 1,
    closure_cycle: int = 1,
    intent_kind: DispositionIntentKind = DispositionIntentKind.EVENT_STATUS_UPDATE,
    approved: SourceDisposition = SourceDisposition.CONTAINED,
    actual: SourceDisposition = SourceDisposition.CONTAINED,
    receipt: WritebackStatus = WritebackStatus.CONFIRMED,
) -> TerminalEventWritebackView:
    return TerminalEventWritebackView(
        action_id="act-term",
        disposition_id="disp-term",
        writeback_id="wbk-term",
        closure_cycle=closure_cycle,
        intent_kind=intent_kind,
        approved_disposition=approved,
        actual_disposition=actual,
        receipt_status=receipt,
        plan_revision=plan_revision,
    )


def test_terminal_blockers_pass_when_fully_confirmed() -> None:
    assert terminal_gate_blockers(_terminal(), current_revision=1, current_closure_cycle=1) == []


def test_terminal_blocker_missing_terminal() -> None:
    reasons = terminal_gate_blockers(None, current_revision=1, current_closure_cycle=1)
    assert any("missing terminal EVENT_STATUS_UPDATE" in reason for reason in reasons)


def test_terminal_blocker_receipt_not_confirmed() -> None:
    reasons = terminal_gate_blockers(
        _terminal(receipt=WritebackStatus.PENDING),
        current_revision=1,
        current_closure_cycle=1,
    )
    assert any("receipt status is pending" in reason for reason in reasons)


def test_terminal_blocker_plan_revision_mismatch() -> None:
    reasons = terminal_gate_blockers(
        _terminal(plan_revision=2), current_revision=1, current_closure_cycle=1
    )
    assert any("does not bind current plan_revision" in reason for reason in reasons)


def test_terminal_blocker_closure_cycle_mismatch() -> None:
    reasons = terminal_gate_blockers(
        _terminal(closure_cycle=2), current_revision=1, current_closure_cycle=1
    )
    assert any("closure_cycle mismatch" in reason for reason in reasons)


def test_terminal_blocker_non_terminal_approved_disposition() -> None:
    reasons = terminal_gate_blockers(
        _terminal(approved=SourceDisposition.PENDING),
        current_revision=1,
        current_closure_cycle=1,
    )
    assert any("approved disposition pending is not terminal" in reason for reason in reasons)


def test_terminal_blocker_non_event_status_update_intent() -> None:
    reasons = terminal_gate_blockers(
        _terminal(intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD),
        current_revision=1,
        current_closure_cycle=1,
    )
    assert any("not EVENT_STATUS_UPDATE" in reason for reason in reasons)


# --------------------------------------------------------------------------- #
# _validate_writeback_gate error mapping
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_gate_noop_for_not_required_policy() -> None:
    with patch.object(
        events_module, "_build_writeback_info", AsyncMock(side_effect=AssertionError)
    ):
        # NOT_REQUIRED returns before any DB access.
        await events_module._validate_writeback_gate(
            "evt-iss171-nr", _event(policy=DispositionPolicy.NOT_REQUIRED)
        )


@pytest.mark.asyncio
async def test_gate_passes_when_shared_predicate_has_no_blockers() -> None:
    with (
        patch.object(
            events_module,
            "_build_writeback_info",
            AsyncMock(return_value=(WritebackReadiness.READY, WritebackStatus.CONFIRMED, 0)),
        ),
        patch(
            "app.services.state_machine_service.event_closed_gate_blockers",
            AsyncMock(return_value=[]),
        ),
    ):
        await events_module._validate_writeback_gate("evt-iss171-ok", _event())


@pytest.mark.asyncio
async def test_gate_blocks_unconfirmed_intents_with_pending_error() -> None:
    blockers = ["action act-1 required intents are not all CONFIRMED"]
    with (
        patch.object(
            events_module,
            "_build_writeback_info",
            AsyncMock(return_value=(WritebackReadiness.READY, WritebackStatus.CONFIRMED, 0)),
        ),
        patch(
            "app.services.state_machine_service.event_closed_gate_blockers",
            AsyncMock(return_value=blockers),
        ),
    ):
        with pytest.raises(WritebackPendingError) as exc_info:
            await events_module._validate_writeback_gate("evt-iss171-blocked", _event())

    assert exc_info.value.status_code == 409
    assert exc_info.value.default_error_code == "writeback_pending"
    assert exc_info.value.details["blockers"] == blockers


@pytest.mark.asyncio
async def test_gate_blocks_missing_command_via_pending_error() -> None:
    # Event-level aggregate says CONFIRMED, but the shared predicate sees an
    # action without a disposition command — the exact ISSUE-171 gap.
    blockers = ["action act-1 has no disposition command"]
    with (
        patch.object(
            events_module,
            "_build_writeback_info",
            AsyncMock(return_value=(WritebackReadiness.READY, WritebackStatus.CONFIRMED, 0)),
        ),
        patch(
            "app.services.state_machine_service.event_closed_gate_blockers",
            AsyncMock(return_value=blockers),
        ),
    ):
        with pytest.raises(WritebackPendingError):
            await events_module._validate_writeback_gate("evt-iss171-nocmd", _event())
