"""Side-effect convergence for CLOSED gate (ISSUE-302)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import InvalidStateTransitionError
from app.db import models as orm
from app.models.enums import (
    ActionCategory,
    ActionStatus,
    DispositionPolicy,
    EventStatus,
    ExecutionJobStatus,
    FinalVerdict,
    OutboxDeliveryStatus,
    Severity,
    WritebackStatus,
)
from app.models.side_effect_convergence import SideEffectScope
from app.models.workflow import TransitionContext, validate_closed_gate
from app.services.side_effect_convergence import (
    build_side_effect_convergence_summary,
    check_gate_applicable_side_effect_convergence,
)


async def _seed_not_required_closed_with_running_job(
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    action_id = f"act-{sfx}"
    job_id = f"job-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="account_anomaly",
                    title="NOT_REQUIRED background side effects",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.LOW.value,
                    final_verdict=FinalVerdict.FALSE_POSITIVE.value,
                    risk_score=10,
                    entities={},
                    disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block domain",
                    tool_name="block_domain",
                    action_level="l2",
                    execution_owner="direct_tool",
                    writeback_applicable=False,
                    writeback_required=False,
                    status=ActionStatus.APPROVED.value,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_tool",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.RUNNING.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )
    return event_id


async def _seed_required_with_executing_action(
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    action_id = f"act-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="REQUIRED gate-applicable side effect",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="isolate host",
                    tool_name="isolate_host",
                    action_level="l2",
                    execution_owner="direct_tool",
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.EXECUTING.value,
                )
            )
    return event_id


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_not_required_classifies_running_job_as_background_detached(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_not_required_closed_with_running_job(session_factory)

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
        )

    assert summary.background_outstanding_count == 1
    assert summary.gate_applicable_outstanding_count == 0
    assert summary.outstanding_actions[0].scope is SideEffectScope.BACKGROUND_DETACHED
    assert check_gate_applicable_side_effect_convergence(summary) is None


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_not_required_closed_gate_allows_background_side_effects(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_not_required_closed_with_running_job(session_factory)

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
        )

    validate_closed_gate(
        TransitionContext(
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
            report_exists=True,
            side_effect_convergence=summary,
        )
    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_required_executing_action_blocks_closed_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_required_with_executing_action(session_factory)

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    assert summary.gate_applicable_outstanding_count == 1
    violation = check_gate_applicable_side_effect_convergence(summary)
    assert violation is not None
    assert violation.action_id.startswith("act-")

    with pytest.raises(InvalidStateTransitionError, match="gate-applicable side effects"):
        validate_closed_gate(
            TransitionContext(
                disposition_policy=DispositionPolicy.REQUIRED,
                report_exists=True,
                side_effect_convergence=summary,
            )
        )


async def _seed_superseded_outbox_not_gate_applicable(
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    action_id = f"act-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="superseded outbox detached",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=0,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level="l2",
                    execution_owner="xdr_managed",
                    writeback_applicable=True,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                    superseded_by_revision=1,
                )
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{sfx}",
                    writeback_id=f"wbk-{sfx}",
                    disposition_id=f"disp-{sfx}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=0,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="slot-0",
                    idempotency_key=f"idem-{sfx}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    latest_writeback_status=WritebackStatus.PENDING.value,
                )
            )
    return event_id


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_superseded_revision_outbox_is_background_detached(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_superseded_outbox_not_gate_applicable(session_factory)

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    assert summary.gate_applicable_outstanding_count == 0
    assert summary.background_outstanding_count == 1
    assert check_gate_applicable_side_effect_convergence(summary) is None
