"""Side-effect convergence for CLOSED gate (ISSUE-302)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import InvalidStateTransitionError
from app.db import models as orm
from app.models.agent_io import (
    EffectStatus,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionStatus,
    ConfirmationEvidence,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    ExecutionJobStatus,
    FinalVerdict,
    OutboxDeliveryStatus,
    Severity,
    SourceDisposition,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.side_effect_convergence import (
    OutstandingSideEffectView,
    SideEffectConvergencePolicy,
    SideEffectConvergenceReason,
    SideEffectConvergenceSummary,
    SideEffectScope,
)
from app.models.workflow import (
    ClosedGateActionView,
    TerminalEventWritebackView,
    TransitionContext,
    validate_closed_gate,
)
from app.services.side_effect_convergence import (
    _action_side_effect_blocks_convergence,
    _build_jobs_by_action,
    build_side_effect_convergence_summary,
    check_gate_applicable_side_effect_convergence,
    reconcile_stale_executions_before_close,
)


def test_check_gate_blocks_on_blocking_reason_not_head_outbox_snapshot() -> None:
    """Gate check must honor blocking_reason across all outboxes, not head-only fields."""
    summary = SideEffectConvergenceSummary(
        event_id="evt-unit",
        current_plan_revision=1,
        gate_applicable_outstanding_count=1,
        outstanding_actions=[
            OutstandingSideEffectView(
                action_id="act-unit",
                scope=SideEffectScope.GATE_APPLICABLE,
                action_status=ActionStatus.APPROVED,
                execution_phase=ActionExecutionPhase.IMMEDIATE,
                writeback_applicable=True,
                outbox_delivery_status=OutboxDeliveryStatus.DELIVERED,
                outbox_writeback_status=WritebackStatus.CONFIRMED,
                plan_revision=1,
                blocking_reason=SideEffectConvergenceReason.OUTBOX_UNDELIVERED,
            )
        ],
    )
    violation = check_gate_applicable_side_effect_convergence(summary)
    assert violation is not None
    assert violation.reason is SideEffectConvergenceReason.OUTBOX_UNDELIVERED


def test_required_closed_gate_fails_without_convergence_summary() -> None:
    with pytest.raises(InvalidStateTransitionError, match="missing side_effect_convergence"):
        validate_closed_gate(
            TransitionContext(
                disposition_policy=DispositionPolicy.REQUIRED,
                report_exists=True,
                side_effect_convergence=None,
            )
        )


def _unit_verified_entity_result(action_id: str) -> VerificationResult:
    return VerificationResult(
        results=[
            VerificationActionResult(
                action_id=action_id,
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                detail="effect_verified",
                verification_phase=VerificationPhase.EFFECT,
            )
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )


def test_entity_effect_phase_verification_satisfies_accepted_outbox_gate() -> None:
    """ISSUE-312: gate evidence is verification_result EFFECT VERIFIED, not job.raw_result."""
    action_id = "act-entity-converged"
    action = orm.Action(
        action_id=action_id,
        status=ActionStatus.SUCCESS.value,
        writeback_applicable=False,
        writeback_required=True,
        execution_owner="xdr_managed",
    )
    outbox = orm.DispositionOutbox(
        action_id=action_id,
        disposition_id="disp-entity-converged",
        writeback_id="wbk-entity-converged",
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
        delivery_status=OutboxDeliveryStatus.DELIVERED.value,
        latest_writeback_status=WritebackStatus.ACCEPTED.value,
    )
    job = orm.ActionExecutionJob(
        action_id=action_id,
        status=ExecutionJobStatus.SUCCESS.value,
        raw_result={"effect_completion": {"verified": True}},
    )

    reason, policy = _action_side_effect_blocks_convergence(
        action,
        jobs_by_action={action_id: job},
        active_outboxes=[outbox],
        verification=_unit_verified_entity_result(action_id),
    )
    assert reason is None
    assert policy is SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT


def test_entity_job_raw_result_without_verification_blocks_effect_unverified() -> None:
    """job.raw_result.effect_completion alone must not satisfy CLOSED convergence."""
    action_id = "act-entity-pending"
    action = orm.Action(
        action_id=action_id,
        status=ActionStatus.SUCCESS.value,
        writeback_applicable=False,
        writeback_required=True,
        execution_owner="xdr_managed",
    )
    outbox = orm.DispositionOutbox(
        action_id=action_id,
        disposition_id="disp-entity-pending",
        writeback_id="wbk-entity-pending",
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
        delivery_status=OutboxDeliveryStatus.DELIVERED.value,
        latest_writeback_status=WritebackStatus.ACCEPTED.value,
    )
    job = orm.ActionExecutionJob(
        action_id=action_id,
        status=ExecutionJobStatus.SUCCESS.value,
        raw_result={
            "effect_projection_pending": False,
            "effect_completion": {"verified": True},
        },
    )

    reason, policy = _action_side_effect_blocks_convergence(
        action,
        jobs_by_action={action_id: job},
        active_outboxes=[outbox],
        verification=None,
    )
    assert reason is SideEffectConvergenceReason.EFFECT_UNVERIFIED
    assert policy is SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT


def test_entity_failed_job_with_success_action_and_verified_effect_blocks_gate() -> None:
    """Job FAILED must block even when Action SUCCESS + EFFECT VERIFIED (ISSUE-312)."""
    action_id = "act-entity-failed-job"
    action = orm.Action(
        action_id=action_id,
        status=ActionStatus.SUCCESS.value,
        writeback_applicable=False,
        writeback_required=True,
        execution_owner="xdr_managed",
    )
    outbox = orm.DispositionOutbox(
        action_id=action_id,
        disposition_id="disp-entity-failed-job",
        writeback_id="wbk-entity-failed-job",
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
        delivery_status=OutboxDeliveryStatus.DELIVERED.value,
        latest_writeback_status=WritebackStatus.ACCEPTED.value,
    )
    job = orm.ActionExecutionJob(
        action_id=action_id,
        status=ExecutionJobStatus.FAILED.value,
    )

    reason, policy = _action_side_effect_blocks_convergence(
        action,
        jobs_by_action={action_id: job},
        active_outboxes=[outbox],
        verification=_unit_verified_entity_result(action_id),
    )
    assert reason is SideEffectConvergenceReason.IN_FLIGHT_JOB
    assert policy is SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT


def test_entity_missing_job_with_success_action_and_verified_effect_blocks_gate() -> None:
    """Missing job must not be substituted by Action SUCCESS for entity effects."""
    action_id = "act-entity-missing-job"
    action = orm.Action(
        action_id=action_id,
        status=ActionStatus.SUCCESS.value,
        writeback_applicable=False,
        writeback_required=True,
        execution_owner="xdr_managed",
    )
    outbox = orm.DispositionOutbox(
        action_id=action_id,
        disposition_id="disp-entity-missing-job",
        writeback_id="wbk-entity-missing-job",
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
        delivery_status=OutboxDeliveryStatus.DELIVERED.value,
        latest_writeback_status=WritebackStatus.ACCEPTED.value,
    )

    reason, policy = _action_side_effect_blocks_convergence(
        action,
        jobs_by_action={},
        active_outboxes=[outbox],
        verification=_unit_verified_entity_result(action_id),
    )
    assert reason is SideEffectConvergenceReason.IN_FLIGHT_JOB
    assert policy is SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT


def test_entity_xdr_heuristic_without_entity_outbox_blocks_gate() -> None:
    """SPECS XDR_MANAGED + writeback_required with no entity outbox must fail closed."""
    action_id = "act-entity-no-outbox"
    action = orm.Action(
        action_id=action_id,
        tool_name="disable_account",
        status=ActionStatus.SUCCESS.value,
        writeback_applicable=False,
        writeback_required=True,
        execution_owner="xdr_managed",
    )
    job = orm.ActionExecutionJob(
        action_id=action_id,
        status=ExecutionJobStatus.SUCCESS.value,
    )

    reason, policy = _action_side_effect_blocks_convergence(
        action,
        jobs_by_action={action_id: job},
        active_outboxes=[],
        verification=_unit_verified_entity_result(action_id),
    )
    assert reason is SideEffectConvergenceReason.OUTBOX_UNDELIVERED
    assert policy is SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT


def test_non_specs_xdr_without_entity_outbox_uses_execution_job_only() -> None:
    """Non-SPECS XDR+writeback (e.g. misrouted ticket) must not block CLOSED."""
    action_id = "act-ticket-misrouted"
    action = orm.Action(
        action_id=action_id,
        tool_name="create_ticket",
        status=ActionStatus.SUCCESS.value,
        writeback_applicable=False,
        writeback_required=True,
        execution_owner="xdr_managed",
    )
    job = orm.ActionExecutionJob(
        action_id=action_id,
        status=ExecutionJobStatus.SUCCESS.value,
    )

    reason, policy = _action_side_effect_blocks_convergence(
        action,
        jobs_by_action={action_id: job},
        active_outboxes=[],
        verification=None,
    )
    assert reason is None
    assert policy is SideEffectConvergencePolicy.EXECUTION_JOB_ONLY


def test_entity_unknown_delivery_status_blocks_gate() -> None:
    """Corrupt/unknown outbox delivery_status must fail closed."""
    action_id = "act-entity-bad-delivery"
    action = orm.Action(
        action_id=action_id,
        status=ActionStatus.SUCCESS.value,
        writeback_applicable=False,
        writeback_required=True,
        execution_owner="xdr_managed",
    )
    outbox = orm.DispositionOutbox(
        action_id=action_id,
        disposition_id="disp-entity-bad-delivery",
        writeback_id="wbk-entity-bad-delivery",
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
        delivery_status="not_a_real_delivery_status",
        latest_writeback_status=WritebackStatus.ACCEPTED.value,
    )
    job = orm.ActionExecutionJob(
        action_id=action_id,
        status=ExecutionJobStatus.SUCCESS.value,
    )

    reason, policy = _action_side_effect_blocks_convergence(
        action,
        jobs_by_action={action_id: job},
        active_outboxes=[outbox],
        verification=_unit_verified_entity_result(action_id),
    )
    assert reason is SideEffectConvergenceReason.OUTBOX_UNDELIVERED
    assert policy is SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT


async def _ensure_source_record(
    session: AsyncSession,
    *,
    source_record_id: str,
    object_suffix: str,
) -> None:
    connector_id = "conn-side-effect"
    existing = await session.get(orm.SourceConnector, connector_id)
    if existing is None:
        session.add(
            orm.SourceConnector(
                connector_id=connector_id,
                source_product="mock_xdr",
                display_name="Mock XDR",
            )
        )
        await session.flush()
    if await session.get(orm.SourceObject, source_record_id) is None:
        session.add(
            orm.SourceObject(
                source_record_id=source_record_id,
                source_product="mock_xdr",
                source_tenant_id="tenant-demo",
                connector_id=connector_id,
                source_kind="incident",
                source_object_id=f"inc-{object_suffix}",
                next_outbox_sequence=0,
            )
        )
        await session.flush()


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
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
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
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
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
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
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
            await _ensure_source_record(
                session,
                source_record_id=f"src-{sfx}",
                object_suffix=f"src-{sfx}".removeprefix("src-"),
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
    assert summary.outstanding_actions[0].scope is SideEffectScope.BACKGROUND_DETACHED
    # Superseded writeback_applicable action uses TERMINAL_WRITEBACK policy; PENDING
    # writeback surfaces as terminal_writeback_unconfirmed while remaining detached.
    assert summary.outstanding_actions[0].blocking_reason is (
        SideEffectConvergenceReason.TERMINAL_WRITEBACK_UNCONFIRMED
    )
    assert check_gate_applicable_side_effect_convergence(summary) is None


async def _seed_required_with_running_job(
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
                    event_type="data_exfiltration",
                    title="REQUIRED running job gate",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
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


async def _seed_required_with_undelivered_outbox(
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
                    title="REQUIRED undelivered outbox gate",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level="l2",
                    execution_owner="xdr_managed",
                    writeback_applicable=True,
                    writeback_required=True,
                    status=ActionStatus.APPROVED.value,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-{sfx}",
                object_suffix=f"src-{sfx}".removeprefix("src-"),
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


async def _seed_required_multi_outbox_tail_blocks(
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    action_id = f"act-{sfx}"
    now = datetime.now(UTC)
    earlier = now.replace(microsecond=0)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="multi-outbox tail blocks gate",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level="l2",
                    execution_owner="xdr_managed",
                    writeback_applicable=True,
                    writeback_required=True,
                    status=ActionStatus.APPROVED.value,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-head-{sfx}",
                object_suffix=f"src-head-{sfx}".removeprefix("src-"),
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-head-{sfx}",
                    writeback_id=f"wbk-head-{sfx}",
                    disposition_id=f"disp-head-{sfx}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=0,
                    source_record_id=f"src-head-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind="entity_action_submit",
                    logical_slot="slot-head",
                    idempotency_key=f"idem-head-{sfx}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                    latest_writeback_status=WritebackStatus.CONFIRMED.value,
                    created_at=earlier,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-tail-{sfx}",
                object_suffix=f"src-tail-{sfx}".removeprefix("src-"),
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-tail-{sfx}",
                    writeback_id=f"wbk-tail-{sfx}",
                    disposition_id=f"disp-tail-{sfx}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=0,
                    source_record_id=f"src-tail-{sfx}",
                    source_locator_hash="i" * 64,
                    source_sequence=2,
                    intent_kind="entity_action_submit",
                    logical_slot="slot-tail",
                    idempotency_key=f"idem-tail-{sfx}",
                    command_payload={},
                    command_payload_sha256="b" * 64,
                    delivery_status=OutboxDeliveryStatus.READY.value,
                    latest_writeback_status=WritebackStatus.PENDING.value,
                    created_at=now,
                )
            )
    return event_id


async def _seed_executing_with_terminal_job(
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
                    event_type="data_exfiltration",
                    title="EXECUTING with terminal job",
                    description="ISSUE-302 reconcile fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
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
                    execution_job_id=job_id,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_tool",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.SUCCESS.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )
    return event_id


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_required_running_job_blocks_closed_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_required_with_running_job(session_factory)

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
    assert violation.reason is SideEffectConvergenceReason.IN_FLIGHT_JOB


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_required_undelivered_outbox_blocks_closed_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_required_with_undelivered_outbox(session_factory)

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    violation = check_gate_applicable_side_effect_convergence(summary)
    assert violation is not None
    assert violation.reason in {
        SideEffectConvergenceReason.OUTBOX_UNDELIVERED,
        SideEffectConvergenceReason.TERMINAL_WRITEBACK_UNCONFIRMED,
        SideEffectConvergenceReason.OUTBOX_NOT_CONFIRMED,
    }


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_gate_blocks_when_tail_outbox_undelivered_head_confirmed(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_required_multi_outbox_tail_blocks(session_factory)

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
    with pytest.raises(InvalidStateTransitionError, match="gate-applicable side effects"):
        validate_closed_gate(
            TransitionContext(
                disposition_policy=DispositionPolicy.REQUIRED,
                report_exists=True,
                side_effect_convergence=summary,
            )
        )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_reconcile_terminal_job_unblocks_convergence_summary(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_executing_with_terminal_job(session_factory)

    async with session_factory() as session:
        summary_before = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )
    assert summary_before.gate_applicable_outstanding_count == 1

    await reconcile_stale_executions_before_close(session_factory, event_id)

    async with session_factory() as session:
        summary_after = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )
    assert summary_after.gate_applicable_outstanding_count == 0
    assert check_gate_applicable_side_effect_convergence(summary_after) is None

    async with session_factory() as session:
        action_row = await session.get(orm.Action, summary_before.outstanding_actions[0].action_id)
    assert action_row is not None
    assert action_row.status == ActionStatus.SUCCESS.value


async def _seed_required_with_dead_letter_outbox(
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
                    title="REQUIRED dead-letter outbox gate",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level="l2",
                    execution_owner="direct_tool",
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-{sfx}",
                object_suffix=f"src-{sfx}".removeprefix("src-"),
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
                    delivery_status=OutboxDeliveryStatus.DEAD_LETTER.value,
                    latest_writeback_status=None,
                )
            )
    return event_id


async def _seed_required_rollback_with_running_job(
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
                    event_type="data_exfiltration",
                    title="REQUIRED rollback running job gate",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.ROLLBACK.value,
                    action_name="rollback isolate",
                    tool_name="rollback_isolate",
                    action_level="l2",
                    execution_owner="direct_tool",
                    writeback_applicable=False,
                    writeback_required=True,
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


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_required_dead_letter_outbox_blocks_closed_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_required_with_dead_letter_outbox(session_factory)

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    violation = check_gate_applicable_side_effect_convergence(summary)
    assert violation is not None
    assert violation.reason is SideEffectConvergenceReason.OUTBOX_UNDELIVERED


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_rollback_in_flight_job_blocks_required_close(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_required_rollback_with_running_job(session_factory)

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
    assert violation.reason is SideEffectConvergenceReason.IN_FLIGHT_JOB


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_reconcile_before_close_bypasses_disabled_global_reconcile(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    event_id = await _seed_executing_with_terminal_job(session_factory)
    get_settings.cache_clear()
    monkeypatch.setenv("ACTION_EXECUTION_RECONCILE_ENABLED", "false")
    get_settings.cache_clear()

    settings = get_settings()
    assert settings.action_execution_reconcile_enabled is False

    await reconcile_stale_executions_before_close(session_factory, event_id)

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )
    assert summary.gate_applicable_outstanding_count == 0

    get_settings.cache_clear()
    monkeypatch.delenv("ACTION_EXECUTION_RECONCILE_ENABLED", raising=False)


@pytest.mark.asyncio
async def test_reconcile_before_close_failure_blocks_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import action_execution_service as aes_module

    async def _boom(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("reconcile unavailable")

    monkeypatch.setattr(aes_module, "reconcile_stale_executions_for_event", _boom)

    with pytest.raises(InvalidStateTransitionError, match="reconcile failed") as exc:
        await reconcile_stale_executions_before_close(object(), "evt-missing")
    assert exc.value.error_code == "closed_side_effects_pending"
    assert exc.value.status_code == 409


def test_gate_applicable_unknown_with_running_job_blocks() -> None:
    """Terminal UNKNOWN must not skip in-flight job checks (ISSUE-302 review)."""
    now = datetime.now(UTC)
    action_id = "act-unknown"
    action = orm.Action(
        action_id=action_id,
        event_id="evt-unknown",
        plan_revision=1,
        action_fingerprint="fp-unknown",
        action_category=ActionCategory.RESPONSE.value,
        action_name="isolate host",
        tool_name="isolate_host",
        action_level="l2",
        execution_owner="direct_tool",
        writeback_applicable=False,
        writeback_required=True,
        status=ActionStatus.UNKNOWN.value,
    )
    jobs = [
        orm.ActionExecutionJob(
            job_id="job-terminal",
            event_id="evt-unknown",
            action_id=action_id,
            provider_name="mock_tool",
            idempotency_key="idem-terminal",
            status=ExecutionJobStatus.SUCCESS.value,
            attempt=1,
            created_at=now,
            updated_at=now,
        ),
        orm.ActionExecutionJob(
            job_id="job-active",
            event_id="evt-unknown",
            action_id=action_id,
            provider_name="mock_tool",
            idempotency_key="idem-active",
            status=ExecutionJobStatus.RUNNING.value,
            attempt=1,
            created_at=now,
            updated_at=now,
        ),
    ]
    jobs_by_action = _build_jobs_by_action(jobs)
    reason, _policy = _action_side_effect_blocks_convergence(
        action,
        jobs_by_action=jobs_by_action,
        active_outboxes=[],
        verification=None,
    )
    assert reason is SideEffectConvergenceReason.IN_FLIGHT_JOB


def test_build_jobs_by_action_prefers_active_job() -> None:
    now = datetime.now(UTC)
    action_id = "act-multi"
    terminal = orm.ActionExecutionJob(
        job_id="job-done",
        event_id="evt-multi",
        action_id=action_id,
        provider_name="mock_tool",
        idempotency_key="idem-done",
        status=ExecutionJobStatus.SUCCESS.value,
        attempt=1,
        created_at=now,
        updated_at=now,
    )
    active = orm.ActionExecutionJob(
        job_id="job-run",
        event_id="evt-multi",
        action_id=action_id,
        provider_name="mock_tool",
        idempotency_key="idem-run",
        status=ExecutionJobStatus.RUNNING.value,
        attempt=1,
        created_at=now,
        updated_at=now,
    )
    jobs_by_action = _build_jobs_by_action([terminal, active])
    picked = jobs_by_action[action_id]
    assert picked.job_id == "job-run"


async def _seed_unknown_with_running_job(
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
                    event_type="data_exfiltration",
                    title="UNKNOWN with running job",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
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
                    status=ActionStatus.UNKNOWN.value,
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


async def _seed_required_with_system_running_job(
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
                    event_type="data_exfiltration",
                    title="SYSTEM action must not block gate",
                    description="ISSUE-302 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.SYSTEM.value,
                    action_name="audit log",
                    tool_name="audit_log",
                    action_level="l1",
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


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_gate_applicable_unknown_with_running_job_blocks_close(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_unknown_with_running_job(session_factory)

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
    assert violation.reason is SideEffectConvergenceReason.IN_FLIGHT_JOB


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_system_action_running_job_does_not_block_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = await _seed_required_with_system_running_job(session_factory)

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    assert summary.gate_applicable_outstanding_count == 0
    assert check_gate_applicable_side_effect_convergence(summary) is None


def _verification_with_verified_entity(action_id: str) -> VerificationResult:
    return _unit_verified_entity_result(action_id)


async def _seed_entity_accepted_with_terminal_job(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    include_verification: bool,
) -> tuple[str, str]:
    from app.models.enums import DispositionIntentKind, ExecutionOwner

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
                    event_type="data_exfiltration",
                    title="entity ACCEPTED convergence fixture",
                    description="ISSUE-312 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                    event_context_snapshot=(
                        {
                            "verification_result": _verification_with_verified_entity(
                                action_id
                            ).model_dump(mode="json")
                        }
                        if include_verification
                        else None
                    ),
                )
            )
            await session.flush()
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
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                    execution_job_id=job_id,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_xdr",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.SUCCESS.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-{sfx}",
                object_suffix=sfx,
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{sfx}",
                    writeback_id=f"wbk-{sfx}",
                    disposition_id=f"disp-{sfx}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    logical_slot="entity_action",
                    idempotency_key=f"idem-outbox-{sfx}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                    latest_writeback_status=WritebackStatus.ACCEPTED.value,
                )
            )
    return event_id, action_id


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_entity_accepted_with_verified_effect_does_not_block_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, _action_id = await _seed_entity_accepted_with_terminal_job(
        session_factory,
        include_verification=True,
    )

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    assert summary.gate_applicable_outstanding_count == 0
    assert check_gate_applicable_side_effect_convergence(summary) is None


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_entity_accepted_without_effect_proof_blocks_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id, action_id = await _seed_entity_accepted_with_terminal_job(
        session_factory,
        include_verification=False,
    )

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
    assert violation.action_id == action_id
    assert violation.reason is SideEffectConvergenceReason.EFFECT_UNVERIFIED
    view = summary.outstanding_actions[0]
    assert view.convergence_policy is SideEffectConvergencePolicy.INDEPENDENT_ENTITY_EFFECT
    assert view.outbox_writeback_status is WritebackStatus.ACCEPTED
    with pytest.raises(InvalidStateTransitionError, match="gate-applicable side effects"):
        validate_closed_gate(
            TransitionContext(
                disposition_policy=DispositionPolicy.REQUIRED,
                report_exists=True,
                side_effect_convergence=summary,
            )
        )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_terminal_writeback_accepted_still_blocks_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from app.models.action import TERMINAL_DISPOSITION_TOOL
    from app.models.enums import DispositionIntentKind, ExecutionOwner

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    action_id = f"act-term-{sfx}"
    now = datetime.now(UTC)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="terminal ACCEPTED blocks gate",
                    description="ISSUE-312 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name=TERMINAL_DISPOSITION_TOOL,
                    tool_name=TERMINAL_DISPOSITION_TOOL,
                    action_level="l1",
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    execution_phase=ActionExecutionPhase.POST_VERIFY.value,
                    writeback_applicable=True,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-{sfx}",
                object_suffix=sfx,
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{sfx}",
                    writeback_id=f"wbk-{sfx}",
                    disposition_id=f"disp-{sfx}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    logical_slot="terminal",
                    idempotency_key=f"idem-{sfx}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                    latest_writeback_status=WritebackStatus.ACCEPTED.value,
                )
            )

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    violation = check_gate_applicable_side_effect_convergence(summary)
    assert violation is not None
    assert violation.reason is SideEffectConvergenceReason.TERMINAL_WRITEBACK_UNCONFIRMED
    assert summary.outstanding_actions[0].convergence_policy is (
        SideEffectConvergencePolicy.TERMINAL_WRITEBACK
    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_required_entity_verified_and_terminal_confirmed_allows_close(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Contract matrix: entity ACCEPTED+VERIFIED + terminal CONFIRMED → gate clear."""
    from app.models.action import TERMINAL_DISPOSITION_TOOL
    from app.models.enums import DispositionIntentKind, ExecutionOwner

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    entity_id = f"act-ent-{sfx}"
    terminal_id = f"act-term-{sfx}"
    job_id = f"job-{sfx}"
    now = datetime.now(UTC)
    verification = VerificationResult(
        results=[
            VerificationActionResult(
                action_id=entity_id,
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                detail="effect_verified",
                verification_phase=VerificationPhase.EFFECT,
            )
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="entity+terminal converged close",
                    description="ISSUE-312 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                    event_context_snapshot={
                        "verification_result": verification.model_dump(mode="json")
                    },
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=entity_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-ent-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="isolate host",
                    tool_name="isolate_host",
                    action_level="l2",
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                    execution_job_id=job_id,
                )
            )
            session.add(
                orm.Action(
                    action_id=terminal_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-term-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name=TERMINAL_DISPOSITION_TOOL,
                    tool_name=TERMINAL_DISPOSITION_TOOL,
                    action_level="l1",
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    execution_phase=ActionExecutionPhase.POST_VERIFY.value,
                    writeback_applicable=True,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=entity_id,
                    provider_name="mock_xdr",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.SUCCESS.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-{sfx}",
                object_suffix=sfx,
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-ent-{sfx}",
                    writeback_id=f"wbk-ent-{sfx}",
                    disposition_id=f"disp-ent-{sfx}",
                    action_id=entity_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    logical_slot="entity_action",
                    idempotency_key=f"idem-ent-{sfx}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                    latest_writeback_status=WritebackStatus.ACCEPTED.value,
                )
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-term-{sfx}",
                    writeback_id=f"wbk-term-{sfx}",
                    disposition_id=f"disp-term-{sfx}",
                    action_id=terminal_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="i" * 64,
                    source_sequence=2,
                    intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    logical_slot="terminal",
                    idempotency_key=f"idem-term-{sfx}",
                    command_payload={},
                    command_payload_sha256="b" * 64,
                    delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                    latest_writeback_status=WritebackStatus.CONFIRMED.value,
                )
            )

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    assert summary.gate_applicable_outstanding_count == 0
    assert check_gate_applicable_side_effect_convergence(summary) is None
    # Side-effect gate is clear; full CLOSED still needs writeback receipt views
    # (covered by test_state_machine / production full-loop).


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_entity_verified_terminal_accepted_still_blocks_gate(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Contract matrix: entity VERIFIED + terminal ACCEPTED still blocks CLOSED."""
    from app.models.action import TERMINAL_DISPOSITION_TOOL
    from app.models.enums import DispositionIntentKind, ExecutionOwner

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    entity_id = f"act-ent-{sfx}"
    terminal_id = f"act-term-{sfx}"
    job_id = f"job-{sfx}"
    now = datetime.now(UTC)
    verification = _verification_with_verified_entity(entity_id)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="entity verified terminal accepted blocks",
                    description="ISSUE-312 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                    event_context_snapshot={
                        "verification_result": verification.model_dump(mode="json")
                    },
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=entity_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-ent-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="isolate host",
                    tool_name="isolate_host",
                    action_level="l2",
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                    execution_job_id=job_id,
                )
            )
            session.add(
                orm.Action(
                    action_id=terminal_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-term-{sfx}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name=TERMINAL_DISPOSITION_TOOL,
                    tool_name=TERMINAL_DISPOSITION_TOOL,
                    action_level="l1",
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    execution_phase=ActionExecutionPhase.POST_VERIFY.value,
                    writeback_applicable=True,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=entity_id,
                    provider_name="mock_xdr",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.SUCCESS.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-{sfx}",
                object_suffix=sfx,
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-ent-{sfx}",
                    writeback_id=f"wbk-ent-{sfx}",
                    disposition_id=f"disp-ent-{sfx}",
                    action_id=entity_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    logical_slot="entity_action",
                    idempotency_key=f"idem-ent-{sfx}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                    latest_writeback_status=WritebackStatus.ACCEPTED.value,
                )
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-term-{sfx}",
                    writeback_id=f"wbk-term-{sfx}",
                    disposition_id=f"disp-term-{sfx}",
                    action_id=terminal_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="i" * 64,
                    source_sequence=2,
                    intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    logical_slot="terminal",
                    idempotency_key=f"idem-term-{sfx}",
                    command_payload={},
                    command_payload_sha256="b" * 64,
                    delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                    latest_writeback_status=WritebackStatus.ACCEPTED.value,
                )
            )

    async with session_factory() as session:
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    violation = check_gate_applicable_side_effect_convergence(summary)
    assert violation is not None
    assert violation.reason is SideEffectConvergenceReason.TERMINAL_WRITEBACK_UNCONFIRMED
    assert violation.convergence_policy is SideEffectConvergencePolicy.TERMINAL_WRITEBACK
    with pytest.raises(InvalidStateTransitionError, match="gate-applicable side effects"):
        validate_closed_gate(
            TransitionContext(
                disposition_policy=DispositionPolicy.REQUIRED,
                report_exists=True,
                side_effect_convergence=summary,
            )
        )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.usefixtures("clean_state")
async def test_corrupt_journal_verification_does_not_fall_back_to_snapshot(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Corrupt journal verification_result must fail closed (no snapshot open)."""
    from app.models.enums import DispositionIntentKind, ExecutionOwner
    from app.services.side_effect_convergence import _load_verification_result

    sfx = uuid4().hex[:8]
    event_id = f"evt-{sfx}"
    action_id = f"act-{sfx}"
    job_id = f"job-{sfx}"
    now = datetime.now(UTC)
    good = _verification_with_verified_entity(action_id)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="data_exfiltration",
                    title="corrupt journal fixture",
                    description="ISSUE-312 fixture",
                    status=EventStatus.REPORTING.value,
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    risk_score=90,
                    entities={},
                    creation_source_ref={"source_product": "mock_xdr"},
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    source_type="mock_xdr",
                    occurred_at=now,
                    row_version=1,
                    event_context_snapshot={"verification_result": good.model_dump(mode="json")},
                )
            )
            await session.flush()
            session.add(
                orm.EventContextJournal(
                    event_id=event_id,
                    field_name="verification_result",
                    version=1,
                    value={"not": "a valid VerificationResult"},
                    created_at=now,
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
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    writeback_applicable=False,
                    writeback_required=True,
                    status=ActionStatus.SUCCESS.value,
                    execution_job_id=job_id,
                )
            )
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_xdr",
                    idempotency_key=f"idem-{sfx}",
                    status=ExecutionJobStatus.SUCCESS.value,
                    attempt=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await _ensure_source_record(
                session,
                source_record_id=f"src-{sfx}",
                object_suffix=sfx,
            )
            session.add(
                orm.DispositionOutbox(
                    outbox_id=f"obx-{sfx}",
                    writeback_id=f"wbk-{sfx}",
                    disposition_id=f"disp-{sfx}",
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{sfx}",
                    source_locator_hash="h" * 64,
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    logical_slot="entity_action",
                    idempotency_key=f"idem-outbox-{sfx}",
                    command_payload={},
                    command_payload_sha256="a" * 64,
                    delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                    latest_writeback_status=WritebackStatus.ACCEPTED.value,
                )
            )

    async with session_factory() as session:
        loaded = await _load_verification_result(session, event_id)
        assert loaded is None
        summary = await build_side_effect_convergence_summary(
            session,
            event_id,
            current_revision=1,
            disposition_policy=DispositionPolicy.REQUIRED,
        )

    violation = check_gate_applicable_side_effect_convergence(summary)
    assert violation is not None
    assert violation.reason is SideEffectConvergenceReason.EFFECT_UNVERIFIED


def _closed_gate_terminal_ctx(**overrides: object) -> TransitionContext:
    """Minimal required CLOSED context with converged side effects (ISSUE-333)."""
    terminal = TerminalEventWritebackView(
        action_id="act-disp",
        disposition_id="disp-1",
        writeback_id="wbk-1",
        closure_cycle=1,
        approved_disposition=SourceDisposition.CONTAINED,
        actual_disposition=SourceDisposition.CONTAINED,
        receipt_status=WritebackStatus.CONFIRMED,
        plan_revision=1,
        simulated=False,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
    )
    base: dict[str, object] = {
        "disposition_policy": DispositionPolicy.REQUIRED,
        "report_exists": True,
        "applicable_required_actions": [
            ClosedGateActionView(
                action_id="act-1",
                action_category=ActionCategory.RESPONSE,
                writeback_required=True,
                writeback_applicable=True,
                writeback_readiness=WritebackReadiness.READY,
                writeback_status=WritebackStatus.CONFIRMED,
                has_command=True,
                all_required_intents_confirmed=True,
                tool_name="block_ip",
            )
        ],
        "terminal_event_writeback": terminal,
        "current_plan_revision": 1,
        "current_closure_cycle": 1,
        "side_effect_convergence": SideEffectConvergenceSummary(
            event_id="evt-closed-evidence-test",
            current_plan_revision=1,
        ),
    }
    base.update(overrides)
    return TransitionContext(**base)  # type: ignore[arg-type]


def test_required_closed_gate_rejects_ack_confirmed_non_mock_terminal() -> None:
    """ISSUE-333: ACK+CONFIRMED+non-mock must not pass CLOSED."""
    with pytest.raises(InvalidStateTransitionError, match="strong confirmation_evidence"):
        validate_closed_gate(
            _closed_gate_terminal_ctx(
                disposition_is_mock=False,
                terminal_event_writeback=TerminalEventWritebackView(
                    action_id="act-disp",
                    disposition_id="disp-1",
                    writeback_id="wbk-1",
                    closure_cycle=1,
                    approved_disposition=SourceDisposition.CONTAINED,
                    actual_disposition=SourceDisposition.CONTAINED,
                    receipt_status=WritebackStatus.CONFIRMED,
                    plan_revision=1,
                    simulated=False,
                    confirmation_evidence=ConfirmationEvidence.ADAPTER_ACKNOWLEDGED,
                ),
            )
        )


def test_required_closed_gate_accepts_readback_verified_non_mock_terminal() -> None:
    validate_closed_gate(_closed_gate_terminal_ctx(disposition_is_mock=False))


def test_required_closed_gate_mock_accepts_ack_simulated_terminal() -> None:
    """Mock P0: simulated CONFIRMED with adapter_acknowledged may still close."""
    validate_closed_gate(
        _closed_gate_terminal_ctx(
            disposition_is_mock=True,
            terminal_event_writeback=TerminalEventWritebackView(
                action_id="act-disp",
                disposition_id="disp-1",
                writeback_id="wbk-1",
                closure_cycle=1,
                approved_disposition=SourceDisposition.CONTAINED,
                actual_disposition=SourceDisposition.CONTAINED,
                receipt_status=WritebackStatus.CONFIRMED,
                plan_revision=1,
                simulated=True,
                confirmation_evidence=ConfirmationEvidence.ADAPTER_ACKNOWLEDGED,
            ),
        )
    )
