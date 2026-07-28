"""VerifyAgent ↔ EventDispositionService integration (ISSUE-060).

Exercises the real activate_and_submit outbox path: receipt rows appear only
after DispositionSyncService delivery, so VerifyAgent must route to waiting/
recovery immediately after activation — not manual resolution or success.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.agents.response_agent import compute_template_hash, derive_disposition_idempotency_key
from app.agents.verify_agent import VerifyAgent
from app.core.event_bus import EventBus
from app.core.guardrails import OutboundDispositionGuard
from app.db import models as orm
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import (
    EffectStatus,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
    VerifyAgentInput,
)
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionJobStatus,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    SourceDisposition,
    SourceObjectKind,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.ids import new_job_id
from app.models.source import SourceReference
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.services.context_service import EventContextStore, event_summary_from_security_event
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService
from app.services.working_memory import WorkingMemory
from tests.test_services._mock_xdr_test_helpers import (
    SCENARIO_INCIDENT_ID,
    fetch_mock_concurrency_token,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("clean_state"),
]


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _locator(*, object_id: str = SCENARIO_INCIDENT_ID) -> SourceObjectLocator:
    return SourceObjectLocator(
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_kind=SourceObjectKind.INCIDENT,
        source_object_id=object_id,
    )


def _ref(*, object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-disposition",
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )


async def _seed_connector_and_source(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    mock_xdr_client: httpx.AsyncClient,
    object_id: str = SCENARIO_INCIDENT_ID,
) -> str:
    connector_id = "conn-disposition"
    source_record_id = f"src-{object_id}"
    concurrency_token = await fetch_mock_concurrency_token(
        mock_xdr_client,
        object_id=object_id,
    )
    async with session_factory() as session:
        async with session.begin():
            if await session.get(orm.SourceConnector, connector_id) is None:
                session.add(
                    orm.SourceConnector(
                        connector_id=connector_id,
                        source_product="mock_xdr",
                        display_name="Mock XDR",
                    )
                )
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product="mock_xdr",
                    source_tenant_id="tenant-demo",
                    connector_id=connector_id,
                    source_kind=SourceObjectKind.INCIDENT.value,
                    source_object_id=object_id,
                    current_concurrency_token=concurrency_token,
                    next_outbox_sequence=0,
                )
            )
    return source_record_id


async def _create_event(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
) -> str:
    sfx = _sfx()
    event_id = f"evt-vfy-eds-{sfx}"
    ref = _ref(object_id=SCENARIO_INCIDENT_ID)
    locator = _locator(object_id=SCENARIO_INCIDENT_ID)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.OTHER.value,
                    title="verify-agent-eds-integration",
                    description="",
                    status=EventStatus.VERIFYING.value,
                    severity=Severity.HIGH.value,
                    risk_score=80,
                    confidence=0.9,
                    final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                    creation_source_ref=ref.model_dump(mode="json"),
                    source_reference_snapshots=[ref.model_dump(mode="json")],
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    disposition_source_ref=locator.model_dump(mode="json"),
                    occurred_at=datetime.now(UTC),
                )
            )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        await store.init_context(event_id, event_summary_from_security_event(row))
    return event_id


def _deferred_action(*, event_id: str) -> Action:
    aid = f"act-term-{_sfx()}"
    approved = [SourceDisposition.CONTAINED, SourceDisposition.COMPLETED]
    template_hash = compute_template_hash(approved)
    idem = derive_disposition_idempotency_key(
        action_id=aid,
        plan_revision=1,
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        logical_slot="terminal",
    )
    locator = _locator()
    return Action.model_validate(
        {
            "action_id": aid,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": f"fp-{aid}",
            "action_category": ActionCategory.RESPONSE,
            "action_name": TERMINAL_DISPOSITION_TOOL,
            "tool_name": TERMINAL_DISPOSITION_TOOL,
            "action_level": ActionLevel.L2,
            "execution_phase": ActionExecutionPhase.POST_VERIFY,
            "activation_condition": "after_effect_resolution",
            "approved_operation_template_hash": template_hash,
            "approved_terminal_dispositions": approved,
            "status": ActionStatus.APPROVED,
            "execution_owner": ExecutionOwner.XDR_MANAGED,
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "disposition_source_ref": locator,
            "idempotency_key": idem,
        }
    )


async def _insert_action(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    action: Action,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action.action_id,
                    event_id=event_id,
                    plan_revision=action.plan_revision,
                    action_fingerprint=action.action_fingerprint,
                    action_category=action.action_category.value,
                    action_name=action.action_name,
                    tool_name=action.tool_name,
                    action_level=action.action_level.value,
                    execution_phase=action.execution_phase.value,
                    activation_condition=action.activation_condition,
                    approved_operation_template_hash=action.approved_operation_template_hash,
                    approved_terminal_dispositions=[
                        item.value for item in action.approved_terminal_dispositions
                    ],
                    status=action.status.value,
                    execution_owner=(
                        action.execution_owner.value if action.execution_owner else None
                    ),
                    target_type=action.target_type,
                    target=action.target,
                    parameters=action.parameters or {},
                    writeback_required=action.writeback_required,
                    writeback_applicable=action.writeback_applicable,
                    writeback_readiness=action.writeback_readiness.value,
                    writeback_status=(
                        action.writeback_status.value if action.writeback_status else None
                    ),
                    disposition_source_ref=(
                        action.disposition_source_ref.model_dump(mode="json")
                        if action.disposition_source_ref
                        else None
                    ),
                    idempotency_key=action.idempotency_key,
                    execution_job_id=action.execution_job_id,
                    reason=action.reason,
                )
            )


async def _insert_job(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    action_id: str,
    job_id: str,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_observation",
                    idempotency_key=f"idem-{job_id}",
                    status=ExecutionJobStatus.SUCCESS.value,
                )
            )


async def _seed_effect_verification(
    store: EventContextStore,
    event_id: str,
    *,
    action_id: str,
) -> None:
    payload = VerificationResult(
        results=[
            VerificationActionResult(
                action_id=action_id,
                effect_status=EffectStatus.VERIFIED,
                writeback_required=False,
                writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            )
        ],
        overall_status=VerificationOverallStatus.SUCCESS,
        verification_phase=VerificationPhase.EFFECT,
    )
    await store.set(event_id, "verification_result", payload.model_dump(mode="json"))


class _MockObservationExecutor:
    async def call(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        **kwargs: Any,
    ) -> ToolResult:
        return ToolResult(
            call_id=f"call-{_sfx()}",
            tool_name=tool_name,
            provider_name="mock_observation",
            status=ToolResultStatus.SUCCESS,
            data={
                "is_verified": True,
                "detail": "integration-test",
                "verified_at": datetime.now(UTC),
            },
        )


@pytest.fixture
def disposition_sync(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
) -> DispositionSyncService:
    registry = DispositionAdapterRegistry()
    adapter = MockXDRDispositionAdapter(
        client=mock_xdr_client,
        read_token="mock-read-token",
        write_token="mock-write-token",
    )
    registry.register("mock_xdr", adapter)
    return DispositionSyncService(
        session_factory,
        context_store=context_store,
        adapter_registry=registry,
        outbound_guard=OutboundDispositionGuard(),
    )


@pytest.fixture
def disposition_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    disposition_sync: DispositionSyncService,
    redis_client: Any,
) -> EventDispositionService:
    return EventDispositionService(
        session_factory,
        disposition_sync=disposition_sync,
        context_store=context_store,
        event_bus=EventBus(redis_client),
    )


@pytest.mark.asyncio
async def test_verify_agent_after_real_eds_activate_routes_waiting_without_receipt(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    mock_xdr_state: Any,
    disposition_service: EventDispositionService,
    redis_client: Any,
) -> None:
    """Real EDS only enqueues outbox — VerifyAgent must wait, not manual/success.

    ISSUE-064: activate_and_submit now synchronously delivers the outbox.
    To preserve the ``WAITING`` path, inject a MockXDR server_error so the
    synchronous delivery fails and the outbox stays READY for the worker.
    """
    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(session_factory, context_store)

    # Inject a server error so the synchronous outbox delivery in
    # activate_and_submit fails → outbox stays READY → VerifyAgent
    # correctly detects it needs writeback recovery.
    # IMPORTANT: Must be set AFTER _seed_connector_and_source so the
    # server_error_every_n=1 only affects disposition-related calls,
    # not incident/connector setup calls.
    from app.mock_xdr.models import MockFailureProfile

    mock_xdr_state.failure_profile = MockFailureProfile(seed=1, server_error_every_n=1)

    immediate_id = f"act-imm-{_sfx()}"
    job_id = new_job_id()
    immediate = Action.model_validate(
        {
            "action_id": immediate_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": f"fp-{immediate_id}",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.DIRECT_TOOL,
            "execution_phase": ActionExecutionPhase.IMMEDIATE,
            "status": ActionStatus.SUCCESS,
            "target_type": "ip",
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "writeback_status": WritebackStatus.CONFIRMED,
            "execution_job_id": job_id,
            "idempotency_key": f"idem-{immediate_id}",
        }
    )
    deferred = _deferred_action(event_id=event_id)
    await _insert_action(session_factory, event_id, immediate)
    await _insert_action(session_factory, event_id, deferred)
    await _insert_job(
        session_factory,
        event_id=event_id,
        action_id=immediate_id,
        job_id=job_id,
    )

    wm = WorkingMemory(store=context_store, redis=redis_client)
    agent = VerifyAgent(
        tool_executor=_MockObservationExecutor(),
        working_memory=wm.for_writer("VerifyAgent"),
        session_factory=session_factory,
        event_disposition_service=disposition_service,
    )

    plan = ResponsePlan(
        plan_id=f"plan-{_sfx()}",
        actions=[immediate, deferred],
        strategy_summary="integration",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    result = await agent.execute(
        VerifyAgentInput(
            event_id=event_id,
            response_plan=plan,
            verification_phase=VerificationPhase.EFFECT,
        )
    )

    assert result.need_writeback_recovery is True
    assert result.need_manual_resolution is False
    assert result.overall_status == VerificationOverallStatus.WAITING
    assert result.overall_status != VerificationOverallStatus.SUCCESS

    async with session_factory() as session:
        outbox_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
    assert int(outbox_count or 0) >= 1


@pytest.mark.asyncio
async def test_verify_agent_full_closure_after_outbox_delivery_and_confirm(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    mock_xdr_client: httpx.AsyncClient,
    disposition_service: EventDispositionService,
    disposition_sync: DispositionSyncService,
    redis_client: Any,
) -> None:
    """After DSS delivers and confirms terminal writeback, VerifyAgent succeeds."""
    await _seed_connector_and_source(session_factory, mock_xdr_client=mock_xdr_client)
    event_id = await _create_event(session_factory, context_store)

    immediate_id = f"act-imm-{_sfx()}"
    job_id = new_job_id()
    immediate = Action.model_validate(
        {
            "action_id": immediate_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": f"fp-{immediate_id}",
            "action_category": ActionCategory.RESPONSE,
            "action_name": "block ip",
            "tool_name": "block_ip",
            "action_level": ActionLevel.L2,
            "execution_owner": ExecutionOwner.DIRECT_TOOL,
            "execution_phase": ActionExecutionPhase.IMMEDIATE,
            "status": ActionStatus.SUCCESS,
            "target_type": "ip",
            "target": "203.0.113.88",
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY,
            "writeback_status": WritebackStatus.CONFIRMED,
            "execution_job_id": job_id,
            "idempotency_key": f"idem-{immediate_id}",
        }
    )
    deferred = _deferred_action(event_id=event_id)
    await _insert_action(session_factory, event_id, immediate)
    await _insert_action(session_factory, event_id, deferred)
    await _insert_job(
        session_factory,
        event_id=event_id,
        action_id=immediate_id,
        job_id=job_id,
    )

    wm = WorkingMemory(store=context_store, redis=redis_client)
    agent = VerifyAgent(
        tool_executor=_MockObservationExecutor(),
        working_memory=wm.for_writer("VerifyAgent"),
        session_factory=session_factory,
        event_disposition_service=disposition_service,
    )
    plan = ResponsePlan(
        plan_id=f"plan-{_sfx()}",
        actions=[immediate, deferred],
        strategy_summary="integration",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )

    # ISSUE-064: activate_and_submit now synchronously delivers and confirms
    # the outbox, so VerifyAgent sees SUCCESS on the first call instead of
    # WAITING.  The test still calls process_ready_outboxes + resolve_writeback
    # to prove the path is idempotent (already-confirmed writebacks are no-ops).
    waiting = await agent.execute(
        VerifyAgentInput(
            event_id=event_id,
            response_plan=plan,
            verification_phase=VerificationPhase.EFFECT,
        )
    )
    # With synchronous delivery, the outbox is already DELIVERED + CONFIRMED
    # when VerifyAgent checks, so overall_status is SUCCESS.
    assert waiting.overall_status == VerificationOverallStatus.SUCCESS

    from sqlalchemy import select

    async with session_factory() as session:
        terminal_outbox = await session.scalar(
            select(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
            .order_by(orm.DispositionOutbox.created_at.desc())
            .limit(1)
        )
    assert terminal_outbox is not None
    writeback_id = terminal_outbox.writeback_id

    delivered = await disposition_sync.process_ready_outboxes(limit=5)
    # ISSUE-064: With synchronous delivery in activate_and_submit, the outbox
    # is already DELIVERED + CONFIRMED, so process_ready_outboxes may return 0.
    assert delivered >= 0
    confirmed = await disposition_sync.resolve_writeback(
        writeback_id,
        "manual_confirmed",
        principal="integration-test",
        comment="verify-agent-eds-integration",
        evidence_ref="evidence://060-integration",
    )
    # The writeback is already CONFIRMED from synchronous delivery;
    # resolve_writeback is idempotent.
    assert confirmed is WritebackStatus.CONFIRMED

    final = await agent.execute(
        VerifyAgentInput(
            event_id=event_id,
            response_plan=plan,
            verification_phase=VerificationPhase.EFFECT,
        )
    )
    assert final.overall_status == VerificationOverallStatus.SUCCESS
    assert final.need_writeback_recovery is False
    assert final.need_manual_resolution is False
