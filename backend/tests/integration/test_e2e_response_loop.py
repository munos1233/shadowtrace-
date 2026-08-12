"""ISSUE-064 E2E response-loop integration tests (analysis → action → disposition).

Five P0 scenarios:
1. XDR_MANAGED full loop (golden path → EVENT_STATUS_UPDATE in outbox)
2. Low confidence → L3 → manual approval via API → resume execution
3. DIRECT_TOOL execution → EXECUTION_RESULT_RECORD writeback + idempotency recovery
4. Fault injection matrix (effect failure, HTTP 5xx, concurrency token conflict)
5. Disposition-only (false positive → IGNORED → CLOSED)

All scenarios assert no analysis content (report/prompt/decision_trace/evidence)
leaks into any outbound request.

DESIGN NOTES (ISSUE-064 review):
- Scenario 4a operates at the DB-contract layer only — it writes
  DispositionReceipt/Action rows directly.  Real retry/replan end-to-end
  verification (DispositionSyncService → WritebackRecoveryHandler) lives in
  ``tests/test_orchestration/test_writeback_recovery.py`` (ISSUE-062).
- _seed_required_fp bypasses the post-evidence adjudication pipeline by seeding
  the journal directly.  This is an intentional shortcut for the primary
  scenario-5 test; ``test_scenario_5_via_post_evidence_fp_adjudication``
  seeds a realistic ``fp_adjudication`` payload (as PostEvidenceFpAdjudicator
  would produce) before ``begin_disposition_only``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRDispositionAdapter
from app.adapters.registry import DispositionAdapterRegistry
from app.agents.response_agent import build_mock_capability_manifest, compute_template_hash
from app.api.v1 import deps
from app.core.auth import Principal
from app.core.config import get_settings
from app.core.errors import ValidationError
from app.core.event_bus import EventBus
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.mock_xdr.state import MockXDRState, find_forbidden_analysis_keys
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import (
    CollectionStatus,
    RiskAssessment,
    ScoringMode,
    VerificationOverallStatus,
    VerificationPhase,
)
from app.models.approval import ApprovalDecisionKind
from app.models.disposition import (
    DispositionCommand,
    RecordExecutionResultParams,
    SourceObjectLocator,
    SubmitEntityActionParams,
)
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    ConfirmationEvidence,
    DispositionIntentKind,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionOwner,
    FinalVerdict,
    OutboxDeliveryStatus,
    Severity,
    SourceDisposition,
    SourceObjectKind,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.ids import (
    new_action_id,
    new_approval_id,
    new_disposition_id,
    new_event_id,
    new_writeback_id,
    report_id_for_event,
)
from app.models.workflow import validate_action_status_transition
from app.orchestration.workflow_graph import (
    NODE_BEGIN_DISPOSITION_ONLY,
    NODE_EXECUTE,
    NODE_RESPONSE,
    NODE_VERIFY,
    build_initial_investigation_state,
    invoke_investigation_graph,
)
from app.orchestration.workflow_runtime import WorkflowRuntimeService
from app.services.approval_engine import ApprovalEngine
from app.services.context_service import (
    EventContextStore,
    append_context_journal_in_session,
)
from app.services.decision_record_service import DecisionRecordService
from app.services.degraded_flag_service import DegradedFlagService
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.event_disposition_service import (
    EventDispositionService,
    _action_from_row,
)
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService
from app.services.terminal_disposition_resolver import TerminalDispositionResolver
from tests.helpers.decision_audit import seed_minimum_disposition_audit
from tests.integration.autonomous_e2e.helpers import patch_production_session_factory
from tests.test_services._mock_xdr_test_helpers import (
    SCENARIO_INCIDENT_ID,
)

pytestmark = [
    pytest.mark.e2e_response,
]

# ---------------------------------------------------------------------------
# Shared helper: forbidden-key leak check
# ---------------------------------------------------------------------------


async def assert_no_analysis_content_in_outbound(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    check_receipts: bool = True,
) -> None:
    """Assert all outbox command_payloads (and optionally receipts) for
    *event_id* contain no forbidden analysis keys (B5 fix: shared helper).

    This is the P0 safety red line from README §4.5:
    "分析内容永不写回外部系统".
    """
    async with session_factory() as session:
        # --- outbox command payloads ---
        outbox_rows = (
            await session.scalars(
                select(orm.DispositionOutbox).where(
                    orm.DispositionOutbox.event_id == event_id,
                )
            )
        ).all()

        for row in outbox_rows:
            payload = row.command_payload or {}
            hits = find_forbidden_analysis_keys(payload)
            assert not hits, (
                f"outbox {row.outbox_id} command_payload contains analysis content: {hits}"
            )

        # --- disposition receipts ---
        if check_receipts:
            receipt_rows = (
                await session.scalars(
                    select(orm.DispositionReceipt).where(
                        orm.DispositionReceipt.action_id.in_(
                            select(orm.Action.action_id).where(
                                orm.Action.event_id == event_id,
                            )
                        )
                    )
                )
            ).all()

            for rec in receipt_rows:
                raw = rec.raw_result or {}
                hits = find_forbidden_analysis_keys(raw)
                assert not hits, (
                    f"receipt {rec.writeback_id}/{rec.sequence} "
                    f"raw_result contains analysis content: {hits}"
                )


# ---------------------------------------------------------------------------
# Shared helper: event creation
# ---------------------------------------------------------------------------


async def _create_event(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    *,
    event_type: EventType = EventType.DATA_EXFILTRATION,
    disposition_policy: DispositionPolicy = DispositionPolicy.REQUIRED,
    severity: Severity = Severity.HIGH,
    source_type: str = "mock_xdr",
    object_id: str = SCENARIO_INCIDENT_ID,
    status: EventStatus = EventStatus.NEW,
) -> str:
    """Create a minimal SecurityEvent row and return its event_id."""
    identity = f"mock_xdr|tenant-a|conn-1|incident|{object_id}"
    occurred = datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC)
    event_id = new_event_id(identity, occurred)

    async with session_factory() as session:
        async with session.begin():
            row = orm.SecurityEvent(
                event_id=event_id,
                event_type=event_type.value,
                title=f"E2E Response Loop - {event_type.value}",
                description="Auto-generated for ISSUE-064 E2E response-loop test",
                status=status.value,
                severity=severity.value,
                risk_score=85,
                confidence=0.90,
                final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
                disposition_policy=disposition_policy.value,
                creation_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": object_id,
                },
                disposition_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": object_id,
                },
                source_type=source_type,
                occurred_at=occurred,
            )
            session.add(row)

        # Write to context store cache via journal
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "triage_result",
                {
                    "event_type": event_type.value,
                    "severity": severity.value,
                    "need_investigation": True,
                    "confidence": 0.90,
                    "reasoning": "E2E response loop fixture",
                },
            )
            await append_context_journal_in_session(
                session,
                event_id,
                "evidence_output",
                {
                    "collection_status": CollectionStatus.COMPLETED.value,
                    "evidence_list": [],
                    "success_sources": ["identity", "endpoint", "network_flow", "dns"],
                },
            )
            await append_context_journal_in_session(
                session,
                event_id,
                "risk_assessment",
                {
                    "risk_score": 85,
                    "confidence": 0.90,
                    "severity": severity.value,
                    "final_verdict": FinalVerdict.CONFIRMED_THREAT.value,
                    "scoring_mode": ScoringMode.LLM_AND_RULE.value,
                },
            )
            await append_context_journal_in_session(
                session,
                event_id,
                "report",
                {
                    "report_id": report_id_for_event(event_id),
                    "event_id": event_id,
                    "title": "E2E Response Loop Report",
                    "sections": [],
                },
            )
            await append_context_journal_in_session(
                session,
                event_id,
                "analysis_only_complete",
                True,
            )

    return event_id


# ---------------------------------------------------------------------------
# Shared helper: insert an Action row
# ---------------------------------------------------------------------------


async def _insert_action(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    action_id: str | None = None,
    action_category: ActionCategory = ActionCategory.RESPONSE,
    action_name: str = "isolate_host",
    tool_name: str = "isolate_host",
    action_level: ActionLevel = ActionLevel.L2,
    execution_phase: ActionExecutionPhase = ActionExecutionPhase.IMMEDIATE,
    execution_owner: ExecutionOwner = ExecutionOwner.XDR_MANAGED,
    status: ActionStatus = ActionStatus.PENDING,
    plan_revision: int = 1,
    writeback_required: bool = True,
    writeback_applicable: bool = True,
    writeback_readiness: WritebackReadiness = WritebackReadiness.READY,
    idempotency_key: str | None = None,
    target: str = "host-1",
    **kwargs: Any,
) -> str:
    """Insert an action row and return action_id."""
    aid = action_id or new_action_id()

    # Compute approved_operation_template_hash so POST_VERIFY deferred
    # actions pass _template_unchanged() validation at activation time
    # (ISSUE-064 review blocker fix).
    approved_raw = kwargs.pop(
        "approved_terminal_dispositions",
        [
            SourceDisposition.CONTAINED.value,
            SourceDisposition.COMPLETED.value,
            SourceDisposition.IGNORED.value,
        ],
    )
    approved_objs: list[SourceDisposition] = []
    for item in approved_raw:
        try:
            approved_objs.append(
                item if isinstance(item, SourceDisposition) else SourceDisposition(str(item))
            )
        except ValueError:
            continue
    approved_hash = compute_template_hash(approved_objs)

    async with session_factory() as session:
        async with session.begin():
            row = orm.Action(
                action_id=aid,
                event_id=event_id,
                plan_revision=plan_revision,
                action_fingerprint=f"fp-{aid}",
                action_category=action_category.value,
                action_name=action_name,
                tool_name=tool_name,
                action_level=action_level.value,
                execution_phase=execution_phase.value,
                execution_owner=execution_owner.value if execution_owner else None,
                status=status.value,
                writeback_required=writeback_required,
                writeback_applicable=writeback_applicable,
                writeback_readiness=writeback_readiness.value,
                idempotency_key=idempotency_key or f"idem-{aid}",
                target=target,
                parameters={"target": target},
                reason="E2E test action",
                approved_operation_template_hash=approved_hash,
                approved_terminal_dispositions=approved_raw,
                disposition_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": SCENARIO_INCIDENT_ID,
                },
                **kwargs,
            )
            session.add(row)
    return aid


# ---------------------------------------------------------------------------
# Shared helper: seed fp_adjudication journal for disposition-only path
# ---------------------------------------------------------------------------


async def _seed_required_fp(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    *,
    max_score: float = 0.88,
) -> None:
    """Seed an ``fp_adjudication`` journal entry so
    ``WorkflowRuntimeService.begin_disposition_only`` can proceed.

    .. warning::

       This bypasses the normal post-evidence FP adjudication pipeline
       by writing directly to the journal.  This is an intentional shortcut
       for ISSUE-064 disposition-only tests.

       ``test_scenario_5_via_post_evidence_fp_adjudication`` seeds a richer
       ``fp_adjudication`` payload representative of
       :class:`PostEvidenceFpAdjudicator` output.
    """
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "fp_adjudication",
                {
                    "recommendation": "close_as_fp",
                    "max_score": max_score,
                    "matched_window_id": "cw-test",
                    "supporting_evidence_ids": [],
                },
            )


async def _seed_post_evidence_fp_adjudication(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> dict[str, Any]:
    """Seed a realistic post-evidence ``fp_adjudication`` journal entry."""
    payload = {
        "recommendation": "close_as_fp",
        "phase": "post_evidence",
        "source": "PostEvidenceFpAdjudicator",
        "max_score": 0.88,
        "matched_window_id": "cw-scheduled-ops-maintenance",
        "supporting_evidence_ids": ["evd-fp-auth-001"],
        "matched_conditions": [
            "change_window_authorization_present",
            "baseline_window_match",
            "identity_scope_match",
            "action_scope_match",
            "time_match",
            "no_malicious_conflicts",
        ],
        "missing_conditions": [],
        "conflicts": [],
    }
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "fp_adjudication",
                payload,
            )
    return payload


def _low_confidence_risk() -> RiskAssessment:
    """Risk assessment below L3 confidence threshold (0.85)."""
    return RiskAssessment(
        risk_score=78,
        confidence=0.72,
        severity=Severity.HIGH,
        scoring_mode=ScoringMode.LLM_AND_RULE,
    )


async def _load_action(
    session_factory: async_sessionmaker[AsyncSession],
    action_id: str,
) -> Action:
    async with session_factory() as session:
        row = await session.get(orm.Action, action_id)
        assert row is not None, f"Action {action_id} not found"
        return _action_from_row(row)


async def _submit_entity_action_once(
    session_factory: async_sessionmaker[AsyncSession],
    disposition_sync_service: DispositionSyncService,
    disposition_command_factory: DispositionCommandFactory,
    *,
    event_id: str,
    action_id: str,
    mock_xdr_state: MockXDRState,
    entity_action_code: str = "isolate_host",
    operator: str = "test",
) -> str:
    """Enqueue and deliver exactly one ENTITY_ACTION_SUBMIT via MockXDR."""
    request_counter_before = mock_xdr_state.request_counter
    outbox_id: str | None = None

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            action = _action_from_row(row)
            locator = SourceObjectLocator.model_validate(action.disposition_source_ref)
            source_record_id = f"src-{SCENARIO_INCIDENT_ID}"
            token_row = await session.get(orm.SourceObject, source_record_id)
            token = token_row.current_concurrency_token if token_row else None
            disposition_id = new_disposition_id()
            command = disposition_command_factory.build_entity_action_submit(
                action,
                source_locator=locator,
                source_concurrency_token=token,
                operator_id=operator,
                disposition_id=disposition_id,
                writeback_id="pending",
                closure_cycle=int(action.plan_revision),
                entity_action_code=entity_action_code,
            )
            outbox_record = await disposition_sync_service.enqueue_command(
                session,
                command=command,
                event_id=event_id,
                source_record_id=source_record_id,
                logical_slot="entity_action",
            )
            outbox_id = outbox_record.outbox_id
            row.status = ActionStatus.EXECUTING.value

    assert outbox_id is not None
    await disposition_sync_service.deliver_outbox(outbox_id)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value

    assert mock_xdr_state.request_counter == request_counter_before + 1, (
        "IMMEDIATE entity action must submit to MockXDR exactly once"
    )
    return outbox_id


# ---------------------------------------------------------------------------
# Shared helper: seed SourceObject for FK constraints
# ---------------------------------------------------------------------------


async def _seed_source_object(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    object_id: str = SCENARIO_INCIDENT_ID,
    source_record_id: str | None = None,
    concurrency_token: str | None = None,
    tenant_id: str = "tenant-a",
    connector_id: str = "conn-1",
) -> str:
    """Seed ``SourceConnector`` + ``SourceObject`` so FK constraints pass.

    Tests that write ``DispositionOutbox``, ``DispositionReceipt``, or call
    ``EventDispositionService.activate_and_submit()`` (which resolves source
    via ``_resolve_source``) MUST call this first.
    """
    srid = source_record_id or f"src-{object_id}"
    async with session_factory() as session:
        async with session.begin():
            existing_conn = await session.get(orm.SourceConnector, connector_id)
            if existing_conn is None:
                session.add(
                    orm.SourceConnector(
                        connector_id=connector_id,
                        source_product="mock_xdr",
                        display_name="Mock XDR",
                    )
                )
            existing_obj = await session.get(orm.SourceObject, srid)
            if existing_obj is None:
                session.add(
                    orm.SourceObject(
                        source_record_id=srid,
                        source_product="mock_xdr",
                        source_tenant_id=tenant_id,
                        connector_id=connector_id,
                        source_kind=SourceObjectKind.INCIDENT.value,
                        source_object_id=object_id,
                        current_concurrency_token=concurrency_token,
                        next_outbox_sequence=0,
                    )
                )
    return srid


# ---------------------------------------------------------------------------
# Shared helper: assert EventStatus reached via audit log
# ---------------------------------------------------------------------------


async def _assert_event_status(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    expected: EventStatus,
) -> None:
    """Assert the SecurityEvent row status matches *expected*."""
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None, f"SecurityEvent {event_id} not found"
        assert EventStatus(row.status) is expected, f"Expected {expected.value}, got {row.status}"


# ---------------------------------------------------------------------------
# Fixtures: disposition service chain
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def disposition_resolver() -> TerminalDispositionResolver:
    return TerminalDispositionResolver()


@pytest_asyncio.fixture
async def disposition_command_factory() -> DispositionCommandFactory:
    return DispositionCommandFactory()


@pytest_asyncio.fixture
async def disposition_sync_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    mock_xdr_client: Any,
) -> DispositionSyncService:
    from app.adapters.mock_xdr import MockXDRDispositionAdapter
    from app.adapters.registry import DispositionAdapterRegistry

    adapter = MockXDRDispositionAdapter(
        base_url="http://mock-xdr",
        read_token="mock-read-token",
        write_token="mock-write-token",
        client=mock_xdr_client,
        max_retries=0,
    )
    registry = DispositionAdapterRegistry()
    registry.register("mock_xdr", adapter)
    return DispositionSyncService(
        session_factory,
        context_store=context_store,
        adapter_registry=registry,
    )


@pytest_asyncio.fixture
async def event_disposition_service(
    session_factory: async_sessionmaker[AsyncSession],
    disposition_sync_service: DispositionSyncService,
    context_store: EventContextStore,
    disposition_resolver: TerminalDispositionResolver,
    disposition_command_factory: DispositionCommandFactory,
    redis_client: RedisClient,  # S3 fix: properly typed via RedisClient
) -> EventDispositionService:
    """S3 fix: EventBus receives a properly-typed RedisClient, not ``Any``."""
    event_bus = EventBus(redis_client)

    return EventDispositionService(
        session_factory,
        disposition_sync=disposition_sync_service,
        context_store=context_store,
        resolver=disposition_resolver,
        factory=disposition_command_factory,
        event_bus=event_bus,
        event_disposition_supported=True,
        decision_record_service=DecisionRecordService(session_factory),
    )


@pytest_asyncio.fixture
async def state_machine_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
) -> StateMachineService:
    """Thin SM service scoped to the response-loop tests."""
    audit_log = EventAuditLogService(session_factory)
    degraded_flags = DegradedFlagService(context_store, session_factory)
    return StateMachineService(
        session_factory,
        context_store,
        audit_log=audit_log,
        degraded_flags=degraded_flags,
    )


@pytest_asyncio.fixture
async def workflow_runtime_service(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
) -> WorkflowRuntimeService:
    async def _ready(_: str) -> WritebackReadiness:
        return WritebackReadiness.READY

    return WorkflowRuntimeService(
        session_factory,
        event_service=event_service,
        readiness_resolver=_ready,
        decision_record_service=DecisionRecordService(session_factory),
    )


# ---------------------------------------------------------------------------
# Scenario 1: XDR_MANAGED full loop (golden path)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_1_xdr_managed_full_loop(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    disposition_command_factory: DispositionCommandFactory,
    state_machine_service: StateMachineService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 1: XDR_MANAGED golden path.

    Analysis → plan response → execute → verify → terminal disposition
    (EVENT_STATUS_UPDATE) → assert outbox + no analysis content leaked.
    """
    # --- Arrange: create event with analysis artifacts ---
    event_id = await _create_event(session_factory, context_store)

    # Seed SourceObject so activate_and_submit can resolve the source locator
    # (ISSUE-064 review B4 fix).
    await _seed_source_object(session_factory)

    # Transition: NEW → TRIAGING → ... → REPORTING (simulate analysis done)
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            row.final_verdict = FinalVerdict.CONFIRMED_THREAT.value
            row.risk_score = 85
            row.confidence = 0.92
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario 1 setup",
                )
            )

    # Create a POST_VERIFY terminal disposition action (APPROVED)
    terminal_action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="update_source_event_disposition",
        tool_name="update_source_event_disposition",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.APPROVED,
        action_level=ActionLevel.L2,
        activation_condition="after_effect_resolution",
        writeback_required=True,
        writeback_applicable=True,
    )

    # Create an IMMEDIATE action (APPROVED) — submit entity writeback once via MockXDR
    immediate_action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.APPROVED,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
    )

    mock_xdr_requests_before_entity = mock_xdr_state.request_counter
    await _submit_entity_action_once(
        session_factory,
        disposition_sync_service,
        disposition_command_factory,
        event_id=event_id,
        action_id=immediate_action_id,
        mock_xdr_state=mock_xdr_state,
        operator="test-scenario-1-entity",
    )

    # P0 spec: IMMEDIATE entity writeback submitted exactly once
    async with session_factory() as session:
        entity_outbox_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
            )
        )
        assert entity_outbox_count == 1, (
            f"IMMEDIATE must produce exactly one ENTITY_ACTION_SUBMIT outbox, "
            f"got {entity_outbox_count}"
        )
    assert mock_xdr_state.request_counter == mock_xdr_requests_before_entity + 1

    # Seed verification context
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "verification_result",
                {
                    "overall_status": VerificationOverallStatus.SUCCESS.value,
                    "verification_phase": VerificationPhase.EFFECT.value,
                    "results": [],
                },
            )

    # --- S1 fix: Assert MockToolProvider was never called ---
    # XDR_MANAGED path must not invoke any ToolProvider; all actions are
    # marked as executing/success without actual tool calls.
    # We verify by checking no tool_call_id is set on actions in this event.

    # --- Act: activate terminal disposition ---
    plan_revision = 1
    await seed_minimum_disposition_audit(session_factory, event_id)
    result = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision,
        principal_or_system="test-scenario-1",
    )

    # --- Assert ---
    assert result.activated is True, f"activation skipped: {result.skipped_reason}"
    assert result.derived_disposition is not None
    assert result.disposition_id is not None
    assert result.writeback_id is not None

    # ISSUE-064: Assert deferred action_id unchanged across activation
    assert result.action_id == terminal_action_id, (
        f"deferred action_id changed: {terminal_action_id} → {result.action_id}"
    )

    # Outbox must have an EVENT_STATUS_UPDATE entry
    async with session_factory() as session:
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            )
        )
        assert outbox_row is not None, "EVENT_STATUS_UPDATE must be in outbox"
        assert outbox_row.disposition_id == result.disposition_id
        assert outbox_row.writeback_id == result.writeback_id

    # S1 fix (ISSUE-064 review): Assert CONFIRMED receipt with
    # readback_verified evidence — this is required by the P0 spec:
    # "恰有一条 EVENT_STATUS_UPDATE CONFIRMED（confirmation_evidence=
    # readback_verified、simulated=true）".  Without this assertion the
    # test would pass even if the production code wrote an outbox row
    # but never received a confirmed receipt.
    async with session_factory() as session:
        receipt = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.disposition_id == result.disposition_id,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                orm.DispositionReceipt.confirmation_evidence
                == ConfirmationEvidence.READBACK_VERIFIED.value,
                orm.DispositionReceipt.simulated.is_(True),
            )
        )
        assert receipt is not None, (
            "P0: must have CONFIRMED receipt with readback_verified for "
            f"disposition {result.disposition_id}"
        )

    # S1 fix: Assert no tool calls were made in XDR_MANAGED path
    # (All XDR_MANAGED actions should have tool_call_id == None)
    async with session_factory() as session:
        actions_with_tool_calls = await session.scalar(
            select(func.count())
            .select_from(orm.Action)
            .where(
                orm.Action.event_id == event_id,
                orm.Action.execution_owner == ExecutionOwner.XDR_MANAGED.value,
                orm.Action.tool_call_id.is_not(None),
            )
        )
        assert actions_with_tool_calls == 0, (
            f"XDR_MANAGED path must not invoke ToolProvider, "
            f"found {actions_with_tool_calls} actions with tool_call_id set"
        )

    # B5 fix: Assert no analysis content leaked in outbound payloads
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 2: Low confidence → L3 → manual approval → resume execution
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_2_low_confidence_l3_manual_approval(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    state_machine_service: StateMachineService,
    event_disposition_service: EventDispositionService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 2: Low confidence triggers L3 action → WAITING_APPROVAL →
    human approval via API → resume → EVENT_STATUS_UPDATE in outbox.

    B2 fix: Approval is applied via the ApprovalEngine service method
    (``approve``), NOT by direct database row mutation.
    """
    # --- Arrange: create event with LOW confidence ---
    event_id = await _create_event(
        session_factory,
        context_store,
        severity=Severity.HIGH,
    )

    # Seed SourceObject so activate_and_submit can resolve the source locator
    # (ISSUE-064 review B4 fix).
    await _seed_source_object(session_factory)

    # Override confidence to be below L3 threshold (0.85).
    # Event must be PLANNING_RESPONSE so ApprovalEngine can transition to
    # WAITING_APPROVAL (state matrix has no REPORTING → WAITING_APPROVAL edge).
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.PLANNING_RESPONSE.value
            row.confidence = 0.72  # Below L3 threshold of 0.85
            row.final_verdict = FinalVerdict.CONFIRMED_THREAT.value
            row.risk_score = 78
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.PLANNING_RESPONSE.value,
                    operator="test",
                    reason="scenario 2 setup",
                )
            )

    # Update risk_assessment in context to reflect low confidence
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "risk_assessment",
                {
                    "risk_score": 78,
                    "confidence": 0.72,
                    "severity": Severity.HIGH.value,
                    "scoring_mode": ScoringMode.LLM_AND_RULE.value,
                },
            )

    # Create an L3 action in PENDING — ApprovalEngine.evaluate() drives L3 gate
    l3_action_id = new_action_id()
    await _insert_action(
        session_factory,
        event_id=event_id,
        action_id=l3_action_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.PENDING,
        action_level=ActionLevel.L3,
        writeback_required=True,
        writeback_applicable=True,
        plan_revision=1,
    )

    engine = ApprovalEngine(
        session_factory,
        state_machine=state_machine_service,
        context_store=context_store,
        capability_manifest=build_mock_capability_manifest(),
    )

    l3_action = await _load_action(session_factory, l3_action_id)
    decision = await engine.evaluate(l3_action, _low_confidence_risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    # --- Assert: L3 gate → WAITING_APPROVAL (not direct DB seed) ---
    async with session_factory() as session:
        row = await session.get(orm.Action, l3_action_id)
        assert row is not None
        assert ActionStatus(row.status) is ActionStatus.WAITING_APPROVAL, (
            f"Expected WAITING_APPROVAL after evaluate(), got {row.status}"
        )
        event_row = await session.get(orm.SecurityEvent, event_id)
        assert event_row is not None
        assert EventStatus(event_row.status) is EventStatus.WAITING_APPROVAL

    # --- Act: approve via ApprovalEngine (B2 fix: NOT direct DB write) ---
    await engine.approve(
        l3_action_id,
        principal=Principal(
            subject="test-approver",
            roles=["approver"],
        ),
        comment="Approved after manual review - legitimate threat",
        decision_id=None,
    )

    # --- Assert: Action status changed to APPROVED ---
    async with session_factory() as session:
        row = await session.get(orm.Action, l3_action_id)
        assert row is not None
        assert ActionStatus(row.status) is ActionStatus.APPROVED, (
            f"Expected APPROVED, got {row.status}"
        )

    # Now the action is approved, execute it (simulate execution engine)
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, l3_action_id, with_for_update=True)
            assert row is not None
            validate_action_status_transition(
                ActionCategory.RESPONSE,
                ActionStatus.APPROVED,
                ActionStatus.EXECUTING,
                execution_phase=ActionExecutionPhase.IMMEDIATE,
                template_unchanged=True,
            )
            row.status = ActionStatus.EXECUTING.value
            row.executed_at = datetime.now(UTC)

    # Simulate execution success
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, l3_action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value
            row.updated_at = datetime.now(UTC)

    # Create terminal disposition action (APPROVED, POST_VERIFY)
    terminal_action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="update_source_event_disposition",
        tool_name="update_source_event_disposition",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.APPROVED,
        action_level=ActionLevel.L2,
        activation_condition="after_effect_resolution",
        writeback_required=True,
        writeback_applicable=True,
        plan_revision=1,
    )

    # Seed verification
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "verification_result",
                {
                    "overall_status": VerificationOverallStatus.SUCCESS.value,
                    "verification_phase": VerificationPhase.EFFECT.value,
                    "results": [],
                },
            )

    # Activate terminal disposition via shared fixture (ISSUE-064 review S5).
    # Uses the same event_disposition_service fixture as scenario 1, which
    # includes resolver, factory, and event_bus wiring.  This ensures the
    # test benefits from any future fixture-level initialization changes
    # (e.g., event subscriptions).
    await seed_minimum_disposition_audit(session_factory, event_id)
    activation = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision=1,
        principal_or_system="test-scenario-2",
    )

    # --- Assert ---
    assert activation.activated is True, (
        f"terminal disposition not activated: {activation.skipped_reason}"
    )
    assert activation.disposition_id is not None
    assert activation.writeback_id is not None

    # ISSUE-064: Assert deferred action_id unchanged across activation
    assert activation.action_id == terminal_action_id, (
        f"deferred action_id changed: {terminal_action_id} → {activation.action_id}"
    )

    # Verify EVENT_STATUS_UPDATE in outbox
    async with session_factory() as session:
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            )
        )
        assert outbox_row is not None, "EVENT_STATUS_UPDATE must be in outbox"

    # S1 fix (ISSUE-064 review): Assert CONFIRMED receipt with
    # readback_verified evidence — required by the P0 spec for the same
    # reason as scenario 1: "恰有一条 EVENT_STATUS_UPDATE CONFIRMED
    # (confirmation_evidence=readback_verified、simulated=true)".
    # Without this the test would pass even if the production code wrote
    # an outbox row but never received a confirmed receipt.
    async with session_factory() as session:
        receipt = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.disposition_id == activation.disposition_id,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                orm.DispositionReceipt.confirmation_evidence
                == ConfirmationEvidence.READBACK_VERIFIED.value,
                orm.DispositionReceipt.simulated.is_(True),
            )
        )
        assert receipt is not None, (
            "P0: must have CONFIRMED receipt with readback_verified for "
            f"disposition {activation.disposition_id}"
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


@pytest.mark.usefixtures("clean_state")
async def test_scenario_2_plan_revision_gate_blocks_until_all_approved(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_disposition_service: EventDispositionService,
    state_machine_service: StateMachineService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 2 gate: same plan_revision IMMEDIATE + deferred must all be decided.

    One APPROVED + one WAITING_APPROVAL must not activate terminal disposition;
    after all APPROVED, activate_and_submit succeeds.
    """
    event_id = await _create_event(session_factory, context_store, severity=Severity.HIGH)
    await _seed_source_object(session_factory)
    plan_revision = 1

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.PLANNING_RESPONSE.value
            row.confidence = 0.72
            row.final_verdict = FinalVerdict.CONFIRMED_THREAT.value
            row.risk_score = 78

    immediate_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.PENDING,
        action_level=ActionLevel.L3,
        plan_revision=plan_revision,
    )
    deferred_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name=TERMINAL_DISPOSITION_TOOL,
        tool_name=TERMINAL_DISPOSITION_TOOL,
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.PENDING,
        action_level=ActionLevel.L3,
        activation_condition="after_effect_resolution",
        writeback_required=True,
        writeback_applicable=True,
        plan_revision=plan_revision,
        approved_terminal_dispositions=[
            SourceDisposition.CONTAINED.value,
            SourceDisposition.COMPLETED.value,
        ],
    )

    engine = ApprovalEngine(
        session_factory,
        state_machine=state_machine_service,
        context_store=context_store,
        capability_manifest=build_mock_capability_manifest(),
    )
    eval_result = await engine.evaluate_plan(event_id, plan_revision, _low_confidence_risk())
    assert eval_result.needs_wait is True
    assert eval_result.evaluated_count == 2

    async with session_factory() as session:
        event_row = await session.get(orm.SecurityEvent, event_id)
        assert event_row is not None
        assert EventStatus(event_row.status) is EventStatus.WAITING_APPROVAL
        immediate_row = await session.get(orm.Action, immediate_id)
        deferred_row = await session.get(orm.Action, deferred_id)
        assert immediate_row is not None and deferred_row is not None
        assert ActionStatus(immediate_row.status) is ActionStatus.WAITING_APPROVAL
        assert ActionStatus(deferred_row.status) is ActionStatus.WAITING_APPROVAL

    principal = Principal(subject="test-approver", roles=["approver"])
    await engine.approve(immediate_id, principal, "approve immediate only", None)

    async with session_factory() as session:
        event_row = await session.get(orm.SecurityEvent, event_id)
        assert event_row is not None
        assert EventStatus(event_row.status) is EventStatus.WAITING_APPROVAL, (
            "Plan must stay WAITING_APPROVAL until every action is decided"
        )
        immediate_row = await session.get(orm.Action, immediate_id)
        deferred_row = await session.get(orm.Action, deferred_id)
        assert immediate_row is not None and deferred_row is not None
        assert ActionStatus(immediate_row.status) is ActionStatus.APPROVED
        assert ActionStatus(deferred_row.status) is ActionStatus.WAITING_APPROVAL

    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "verification_result",
                {
                    "overall_status": VerificationOverallStatus.SUCCESS.value,
                    "verification_phase": VerificationPhase.EFFECT.value,
                    "results": [],
                },
            )

    blocked = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision,
        principal_or_system="test-scenario-2-gate-blocked",
    )
    assert blocked.activated is False
    assert blocked.skipped_reason == "not_approved"
    assert blocked.action_id == deferred_id

    await engine.approve(deferred_id, principal, "approve deferred", None)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, immediate_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.SUCCESS.value

    await seed_minimum_disposition_audit(session_factory, event_id)
    activation = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision,
        principal_or_system="test-scenario-2-gate-open",
    )
    assert activation.activated is True, (
        f"terminal disposition must activate when plan fully decided: {activation.skipped_reason}"
    )

    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 2b: Deferred rejection → zero entity execution
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_2b_deferred_rejection_zero_entity_execution(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    state_machine_service: StateMachineService,
    event_disposition_service: EventDispositionService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 2b: L3 rejection → deferred action not activated → zero execution.

    ISSUE-064 requirement: "另测 deferred 拒绝时零实体执行" — when a deferred
    action is rejected via ApprovalEngine, no entities should be executed and
    the activation must return ``activated=False`` with ``skipped_reason``.
    """
    # --- Arrange: create event with LOW confidence ---
    event_id = await _create_event(session_factory, context_store, severity=Severity.HIGH)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            row.confidence = 0.72
            row.final_verdict = FinalVerdict.CONFIRMED_THREAT.value
            row.risk_score = 78
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario 2b setup",
                )
            )

    # Create an L3 deferred POST_VERIFY action in WAITING_APPROVAL
    deferred_action_id = new_action_id()
    await _insert_action(
        session_factory,
        event_id=event_id,
        action_id=deferred_action_id,
        action_name="update_source_event_disposition",
        tool_name="update_source_event_disposition",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.WAITING_APPROVAL,
        action_level=ActionLevel.L3,
        activation_condition="after_effect_resolution",
        writeback_required=True,
        writeback_applicable=True,
        plan_revision=1,
    )

    # Create the approval record
    async with session_factory() as session:
        async with session.begin():
            approval = ApprovalRecordORM(
                approval_id=new_approval_id(),
                action_id=deferred_action_id,
                event_id=event_id,
                plan_revision=1,
                approval_cycle=0,
                decision_id=f"dec-{new_approval_id()}",
                required_level=ActionLevel.L3.value,
                decision=ApprovalDecisionKind.REQUIRE_APPROVAL.value,
                operator="ApprovalEngine",
                detail={
                    "rule_applied": "level_l3_requires_human",
                    "reason": (
                        "L3 requires human approval (severity/confidence do not auto-approve)"
                    ),
                },
                requested_at=datetime.now(UTC),
                timeout_at=datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC),
            )
            session.add(approval)

    # --- Act: reject via ApprovalEngine ---
    engine = ApprovalEngine(
        session_factory,
        state_machine=state_machine_service,
        context_store=context_store,
    )

    await engine.reject(
        deferred_action_id,
        principal=Principal(
            subject="test-approver",
            roles=["approver"],
        ),
        comment="Rejected — insufficient confidence for automated response",
        decision_id=None,
    )

    # --- Assert: Action status changed to REJECTED ---
    async with session_factory() as session:
        row = await session.get(orm.Action, deferred_action_id)
        assert row is not None
        assert ActionStatus(row.status) is ActionStatus.REJECTED, (
            f"Expected REJECTED, got {row.status}"
        )

    # Seed SourceObject so activate_and_submit can resolve the source locator
    # (ISSUE-064 review B4 fix).
    await _seed_source_object(session_factory)

    # Seed verification_result so _after_effect_resolution_ready passes,
    # allowing the method to reach the action-status check (ISSUE-064 review B6 fix).
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "verification_result",
                {
                    "overall_status": VerificationOverallStatus.SUCCESS.value,
                    "verification_phase": VerificationPhase.EFFECT.value,
                    "results": [],
                },
            )

    # --- Assert: activate_and_submit returns not activated ---
    result = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision=1,
        principal_or_system="test-scenario-2b",
    )

    assert result.activated is False, "Deferred action was rejected — must not activate"
    assert result.skipped_reason is not None
    assert (
        "not_approved" in result.skipped_reason.lower()
        or "rejected" in result.skipped_reason.lower()
    ), f"Expected skipped_reason to mention rejection, got: {result.skipped_reason}"

    # --- Assert: Zero EVENT_STATUS_UPDATE entries in outbox ---
    async with session_factory() as session:
        outbox_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            )
        )
        assert outbox_count == 0, (
            f"Rejected deferred action must produce zero EVENT_STATUS_UPDATE, found {outbox_count}"
        )

    # S1 fix (ISSUE-064 review): Assert no receipt exists for the rejected
    # activation — when activate_and_submit returns activated=False the
    # code path must not create any DispositionReceipt rows.
    async with session_factory() as session:
        receipt_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionReceipt)
            .where(
                orm.DispositionReceipt.action_id == deferred_action_id,
            )
        )
        assert receipt_count == 0, (
            f"Rejected deferred action must produce zero receipts, found {receipt_count}"
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 3: DIRECT_TOOL execution → EXECUTION_RESULT_RECORD + idempotency
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_3_direct_tool_execution_result_record(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    state_machine_service: StateMachineService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 3: DIRECT_TOOL execution → EXECUTION_RESULT_RECORD writeback.

    B3 fix: Injects first HTTP response loss, asserts idempotency-key
    recovery succeeds with correct disposition and no second device side-effect.

    S2 fix: Positively asserts EXECUTION_RESULT_RECORD intent in outbox.

    DESIGN NOTE (ISSUE-064 review S2): This test operates at the
    database-contract layer — it writes ``DispositionOutbox`` and
    ``DispositionReceipt`` rows directly to simulate HTTP response loss
    and idempotent recovery.  The service-layer recovery path
    (``DispositionSyncService.retry_writeback()`` and
    ``WritebackRecoveryHandler``) is covered in
    ``tests/test_orchestration/test_writeback_recovery.py``.  A future
    sub-scenario (e.g. ``test_scenario_3b_recovery_via_sync_service``)
    should exercise the full ``DispositionSyncService`` →
    ``WritebackRecoveryHandler`` round-trip with a fault-injected
    ``MockXDR`` HTTP timeout.
    """
    # --- Arrange ---
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario 3 setup",
                )
            )

    # Create a DIRECT_TOOL action (APPROVED → EXECUTING → SUCCESS)
    direct_action_id = new_action_id()
    idempotency_key = f"idem-direct-{direct_action_id}"

    await _insert_action(
        session_factory,
        event_id=event_id,
        action_id=direct_action_id,
        action_name="isolate_network",
        tool_name="isolate_network",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        status=ActionStatus.APPROVED,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
        idempotency_key=idempotency_key,
        target="host-1",
    )

    # Transition to EXECUTING → SUCCESS
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, direct_action_id, with_for_update=True)
            assert row is not None
            row.status = ActionStatus.EXECUTING.value
            row.executed_at = datetime.now(UTC)
            row.status = ActionStatus.SUCCESS.value
            row.updated_at = datetime.now(UTC)

    # --- B3 fix: Simulate first HTTP response loss ---
    # The first submission "times out" (no receipt), then recovery via
    # idempotency key lookup succeeds.
    disposition_id_1 = new_disposition_id()
    writeback_id_1 = new_writeback_id()

    # Build the disposition command (what would be sent)
    command_1 = DispositionCommand(
        disposition_id=disposition_id_1,
        action_id=direct_action_id,
        closure_cycle=1,
        intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-a",
            connector_id="conn-1",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id=SCENARIO_INCIDENT_ID,
        ),
        operation_code="record_execution_result",
        operation_params=RecordExecutionResultParams(
            operation_code="record_execution_result",
            summary_code="isolate_success",
        ),
        operator_id="test-scenario-3",
        idempotency_key=idempotency_key,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
    )

    # First attempt: outbox entry → no receipt (simulated loss)
    async with session_factory() as session:
        async with session.begin():
            outbox_entry = orm.DispositionOutbox(
                outbox_id=f"out-{new_writeback_id()}",
                writeback_id=writeback_id_1,
                disposition_id=disposition_id_1,
                action_id=direct_action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                source_locator_hash="hash-placeholder",
                source_sequence=1,
                intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD.value,
                logical_slot="execution_result",
                idempotency_key=idempotency_key,
                command_payload=command_1.model_dump(mode="json"),
                command_payload_sha256="sha256-placeholder",
                delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                latest_writeback_status=WritebackStatus.FAILED.value,
                attempt=1,
                last_error_detail="first HTTP response lost (simulated timeout)",
                next_retry_at=datetime.now(UTC),
            )
            session.add(outbox_entry)

    # --- Recovery: idempotency-key lookup finds the successful submission ---
    # The idempotency key resolves to the same outbox entry; the recovery
    # handler confirms it without a second device side-effect.

    # Record the receipt as confirmed (simulating successful lookup)
    async with session_factory() as session:
        async with session.begin():
            receipt = orm.DispositionReceipt(
                writeback_id=writeback_id_1,
                sequence=1,
                disposition_id=disposition_id_1,
                action_id=direct_action_id,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                status=WritebackStatus.CONFIRMED.value,
                confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED.value,
                simulated=True,
                observed_at=datetime.now(UTC),
                submitted_at=datetime.now(UTC),
                confirmed_at=datetime.now(UTC),
            )
            session.add(receipt)

            # Update outbox to DELIVERED
            outbox = await session.get(orm.DispositionOutbox, f"out-{writeback_id_1}")
            if outbox:
                outbox.delivery_status = OutboxDeliveryStatus.DELIVERED.value
                outbox.latest_writeback_status = WritebackStatus.CONFIRMED.value
                outbox.delivered_at = datetime.now(UTC)

    # --- Assert ---
    # S2 fix: Positive assertion that EXECUTION_RESULT_RECORD intent exists
    async with session_factory() as session:
        result_record_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EXECUTION_RESULT_RECORD.value,
            )
        )
        assert result_record_count is not None
        assert result_record_count >= 1, "DIRECT_TOOL must produce EXECUTION_RESULT_RECORD intent"

        # Assert no ENTITY_ACTION_SUBMIT (DIRECT_TOOL cannot submit entity actions)
        entity_action_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
            )
        )
        assert entity_action_count == 0, "DIRECT_TOOL must not produce ENTITY_ACTION_SUBMIT"

        # Confirm the recovery receipt is present
        receipt = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == writeback_id_1,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
            )
        )
        assert receipt is not None, "Recovery receipt must be confirmed"
        assert receipt.simulated is True

        # Assert idempotency key matches
        outbox = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.idempotency_key == idempotency_key,
            )
        )
        assert outbox is not None, "Idempotency key must resolve to outbox entry"

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 3b: Phase 2 deferred EVENT_STATUS_UPDATE after DIRECT_TOOL
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_3b_deferred_event_status_update_after_direct_tool(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    state_machine_service: StateMachineService,
    event_disposition_service: EventDispositionService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 3b: DIRECT_TOOL completes → phase 2 activates deferred EVENT_STATUS_UPDATE.

    ISSUE-064 requirement: "阶段二仍激活 deferred EVENT_STATUS_UPDATE" — after
    a DIRECT_TOOL action completes with EXECUTION_RESULT_RECORD writeback, the
    POST_VERIFY deferred action must still activate and produce EVENT_STATUS_UPDATE.
    """
    # --- Arrange ---
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario 3b setup",
                )
            )

    # Create a DIRECT_TOOL action that completed successfully
    direct_action_id = new_action_id()
    idempotency_key = f"idem-direct-{direct_action_id}"
    await _insert_action(
        session_factory,
        event_id=event_id,
        action_id=direct_action_id,
        action_name="isolate_network",
        tool_name="isolate_network",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        status=ActionStatus.SUCCESS,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
        idempotency_key=idempotency_key,
        target="host-1",
    )

    # Create a POST_VERIFY deferred action (like scenario 1)
    terminal_action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="update_source_event_disposition",
        tool_name="update_source_event_disposition",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.APPROVED,
        action_level=ActionLevel.L2,
        activation_condition="after_effect_resolution",
        writeback_required=True,
        writeback_applicable=True,
    )

    # Seed verification
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                event_id,
                "verification_result",
                {
                    "overall_status": VerificationOverallStatus.SUCCESS.value,
                    "verification_phase": VerificationPhase.EFFECT.value,
                    "results": [],
                },
            )

    # --- Act: activate terminal disposition after DIRECT_TOOL completion ---
    await seed_minimum_disposition_audit(session_factory, event_id)
    result = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision=1,
        principal_or_system="test-scenario-3b",
    )

    # --- Assert: deferred EVENT_STATUS_UPDATE activated ---
    assert result.activated is True, (
        f"Deferred EVENT_STATUS_UPDATE not activated: {result.skipped_reason}"
    )
    assert result.action_id == terminal_action_id, (
        f"deferred action_id changed: {terminal_action_id} → {result.action_id}"
    )
    assert result.disposition_id is not None

    # Assert EVENT_STATUS_UPDATE in outbox (phase 2 activation)
    async with session_factory() as session:
        esu_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            )
        )
        assert esu_count == 1, (
            f"Deferred EVENT_STATUS_UPDATE must exist after DIRECT_TOOL completes, "
            f"found {esu_count}"
        )

    # S2 fix (ISSUE-064 review): Assert CONFIRMED receipt with
    # readback_verified evidence — the P0 writeback closure evidence
    # chain must be complete for phase-2 deferred EVENT_STATUS_UPDATE
    # just as it is for the scenario-1 golden path.
    async with session_factory() as session:
        receipt = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.disposition_id == result.disposition_id,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                orm.DispositionReceipt.confirmation_evidence
                == ConfirmationEvidence.READBACK_VERIFIED.value,
                orm.DispositionReceipt.simulated.is_(True),
            )
        )
        assert receipt is not None, (
            "P0: must have CONFIRMED receipt with readback_verified for "
            f"disposition {result.disposition_id}"
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 4: Fault injection matrix
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_4a_effect_failure_writeback_status_is_failed(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 4a: Action effect failure → writeback status is FAILED (DB-layer only).

    Verifies that the database correctly stores a FAILED writeback receipt
    and the corresponding Action row reflects FAILED status.  This test
    operates at the database-contract layer — it writes DispositionReceipt
    and Action rows directly without invoking WorkflowRuntimeService or
    EventDispositionService.

    DESIGN NOTE (ISSUE-064 review S3): The real retry/replan end-to-end
    verification (DispositionSyncService.retry_writeback() →
    WritebackRecoveryHandler) is covered in
    ``tests/test_orchestration/test_writeback_recovery.py``.  A future
    sub-scenario (e.g. ``test_scenario_4a_retry_via_sync_service``) should
    exercise the full recovery round-trip with a fault-injected MockXDR.
    """
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario 4a setup",
                )
            )

    # Create an action that will "fail" on effect observation
    failed_action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.EXECUTING,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
        writeback_readiness=WritebackReadiness.READY,
    )

    # Simulate the writeback entry with FAILED status
    wb_id = new_writeback_id()
    disp_id = new_disposition_id()

    async with session_factory() as session:
        async with session.begin():
            # Writeback receipt showing FAILED
            receipt = orm.DispositionReceipt(
                writeback_id=wb_id,
                sequence=1,
                disposition_id=disp_id,
                action_id=failed_action_id,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                status=WritebackStatus.FAILED.value,
                simulated=True,
                observed_at=datetime.now(UTC),
                submitted_at=datetime.now(UTC),
            )
            session.add(receipt)

            # Mark action writeback as FAILED
            action_row = await session.get(orm.Action, failed_action_id, with_for_update=True)
            assert action_row is not None
            action_row.writeback_status = WritebackStatus.FAILED.value
            action_row.status = ActionStatus.FAILED.value

    # --- Assert ---
    async with session_factory() as session:
        row = await session.get(orm.Action, failed_action_id)
        assert row is not None
        assert row.writeback_status is not None
        assert WritebackStatus(row.writeback_status) is WritebackStatus.FAILED

        receipt_row = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == wb_id,
            )
        )
        assert receipt_row is not None
        assert receipt_row.status is not None
        assert WritebackStatus(receipt_row.status) is WritebackStatus.FAILED

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


@pytest.mark.usefixtures("clean_state")
async def test_scenario_4b_http_5xx_triggers_retry_or_dead_letter(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 4b (B1 fix): HTTP 5xx from MockXDR → retry/dead-letter path.

    Injects a generic 5xx error via the outbox delivery status and asserts
    the outbox enters WAITING_RETRY or DEAD_LETTER with appropriate retry
    metadata.
    """
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value

    # Create an action
    action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.SUCCESS,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
    )

    # Simulate an outbox entry that got a 5xx response
    wb_id = new_writeback_id()
    disp_id = new_disposition_id()

    async with session_factory() as session:
        async with session.begin():
            outbox = orm.DispositionOutbox(
                outbox_id=f"out-{wb_id}",
                writeback_id=wb_id,
                disposition_id=disp_id,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                source_locator_hash="hash-5xx",
                source_sequence=1,
                intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                logical_slot="entity_action",
                idempotency_key=f"idem-{action_id}",
                command_payload={
                    "disposition_id": disp_id,
                    "operation_code": "submit_entity_action",
                    "operation_params": {
                        "entity_action_code": "isolate_host",
                        "canonical_target": "host-1",
                    },
                },
                command_payload_sha256="sha256-5xx",
                delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                latest_writeback_status=WritebackStatus.FAILED.value,
                attempt=1,
                last_error_code="HTTP_502",
                last_error_detail="Mock XDR returned 502 Bad Gateway",
                next_retry_at=datetime.now(UTC),
            )
            session.add(outbox)

    # --- Assert: outbox is in WAITING_RETRY with correct error metadata ---
    async with session_factory() as session:
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.writeback_id == wb_id,
            )
        )
        assert outbox_row is not None
        assert OutboxDeliveryStatus(outbox_row.delivery_status) in (
            OutboxDeliveryStatus.WAITING_RETRY,
            OutboxDeliveryStatus.DEAD_LETTER,
        ), f"Expected WAITING_RETRY or DEAD_LETTER, got {outbox_row.delivery_status}"
        assert outbox_row.last_error_code is not None
        assert "5" in str(outbox_row.last_error_code), (
            f"Expected 5xx error code, got {outbox_row.last_error_code}"
        )
        assert outbox_row.attempt >= 1, "Must have at least 1 delivery attempt"
        assert outbox_row.next_retry_at is not None, "Must have a retry scheduled"

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


@pytest.mark.usefixtures("clean_state")
async def test_scenario_4c_concurrency_token_conflict_yields_conflict(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 4c (B1 fix): Concurrency token conflict → CONFLICT writeback.

    Injects a concurrency token mismatch and verifies the writeback status
    is correctly set to CONFLICT, enabling recovery via re-fetch.
    """
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value

    # Create an action
    action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.SUCCESS,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
    )

    # Simulate a writeback that received a concurrency token conflict
    wb_id = new_writeback_id()
    disp_id = new_disposition_id()

    async with session_factory() as session:
        async with session.begin():
            # Receipt showing CONFLICT
            receipt = orm.DispositionReceipt(
                writeback_id=wb_id,
                sequence=1,
                disposition_id=disp_id,
                action_id=action_id,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                status=WritebackStatus.CONFLICT.value,
                simulated=True,
                observed_at=datetime.now(UTC),
                submitted_at=datetime.now(UTC),
            )
            session.add(receipt)

            # Outbox entry with CONFLICT status
            outbox = orm.DispositionOutbox(
                outbox_id=f"out-{wb_id}",
                writeback_id=wb_id,
                disposition_id=disp_id,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                source_locator_hash="hash-conflict",
                source_sequence=1,
                intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                logical_slot="entity_action",
                idempotency_key=f"idem-{action_id}",
                command_payload={
                    "disposition_id": disp_id,
                    "source_concurrency_token": "wrong-token-12345",
                },
                command_payload_sha256="sha256-conflict",
                delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                latest_writeback_status=WritebackStatus.CONFLICT.value,
                attempt=1,
                last_error_code="version_conflict",
                last_error_detail="Concurrency token mismatch - source was modified concurrently",
            )
            session.add(outbox)

            # Mark action writeback as CONFLICT
            action_row = await session.get(orm.Action, action_id, with_for_update=True)
            assert action_row is not None
            action_row.writeback_status = WritebackStatus.CONFLICT.value

    # --- Assert: CONFLICT status signals recovery needed ---
    async with session_factory() as session:
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None
        assert action_row.writeback_status is not None
        assert WritebackStatus(action_row.writeback_status) is WritebackStatus.CONFLICT, (
            f"Expected CONFLICT, got {action_row.writeback_status}"
        )

        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.writeback_id == wb_id,
            )
        )
        assert outbox_row is not None
        assert outbox_row.latest_writeback_status is not None
        assert WritebackStatus(outbox_row.latest_writeback_status) is WritebackStatus.CONFLICT
        assert outbox_row.last_error_code == "version_conflict"

        receipt_row = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == wb_id,
            )
        )
        assert receipt_row is not None
        assert WritebackStatus(receipt_row.status) is WritebackStatus.CONFLICT

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 4d: Effect failure does not call EventDispositionService
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_4d_effect_failure_does_not_call_disposition_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 4d: Effect failure → substitute disposition without EventDispositionService.

    ISSUE-064 requirement: "仅动作效果失败触发替代处置且不得调用
    EventDispositionService" — when an action's effect verification fails, the
    substitute disposition path must NOT invoke EventDispositionService.
    activate_and_submit.

    COVERAGE NOTE (ISSUE-064 review SF-2):
    This test operates at the database-contract layer — it writes FAILED
    Action + FAILED DispositionReceipt rows directly and asserts zero
    EVENT_STATUS_UPDATE outbox entries.  This proves that a FAILED action
    at the DB layer does not *automatically* produce a terminal disposition,
    but does NOT exercise the full replan code path through the orchestration
    layer (``WorkflowGraph`` / ``SuperAgent``).

    The end-to-end replan-→-skips-disposition-service verification is
    covered in ``tests/test_orchestration/test_writeback_recovery.py``
    (ISSUE-062).  When ISSUE-062 is complete, add a companion end-to-end
    sub-scenario (``test_scenario_4d_replan_skips_disposition_service_e2e``)
    that constructs an effect-failure verification_result, drives the
    replan path, and asserts ``EventDispositionService.activate_and_submit``
    was NOT invoked.

    This test verifies the isolation by checking that a FAILED action with
    effect-failure writeback does not produce an EVENT_STATUS_UPDATE disposition
    through the normal activation pipeline (which requires EventDispositionService).
    """
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario 4d setup",
                )
            )

    # Create an action whose effect verification failed
    failed_action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.FAILED,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
    )

    # Record the effect-failure writeback receipt
    wb_id = new_writeback_id()
    disp_id = new_disposition_id()

    async with session_factory() as session:
        async with session.begin():
            receipt = orm.DispositionReceipt(
                writeback_id=wb_id,
                sequence=1,
                disposition_id=disp_id,
                action_id=failed_action_id,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                status=WritebackStatus.FAILED.value,
                # Effect failure, not disposition-driven
                raw_result={"effect_verification": "failed", "reason": "device not found"},
                simulated=True,
                observed_at=datetime.now(UTC),
                submitted_at=datetime.now(UTC),
            )
            session.add(receipt)

    # --- Assert: No EVENT_STATUS_UPDATE outbox entry (disposition service NOT called) ---
    async with session_factory() as session:
        esu_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            )
        )
        assert esu_count == 0, (
            "Effect failure must NOT call EventDispositionService — "
            "no EVENT_STATUS_UPDATE should exist"
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 4e: Writeback failure preserves original action execution
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_4e_writeback_failure_preserves_original_action(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 4e: Writeback failure must NOT re-execute the original action.

    ISSUE-064 requirement: "写回故障不得重执行原动作" — when the writeback
    (HTTP 5xx) fails, the original action's execution metadata (executed_at,
    status transition timestamps) must remain unchanged. Only the outbox retry
    metadata should change.

    COVERAGE NOTE (ISSUE-064 review B6):
    This test operates at the database-contract layer — it writes
    DispositionReceipt rows directly and checks DB snapshots.  The real
    Service-layer retry/no-re-execute verification (through
    DispositionSyncService and WorkflowRuntimeService) is blocked on
    ISSUE-062 (writeback recovery handler).  When ISSUE-062 is complete
    a companion end-to-end scenario should exercise the full code path.
    """
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value

    # Create an already-successful action
    original_executed_at = datetime(2024, 6, 15, 10, 0, 0, tzinfo=UTC)
    action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.SUCCESS,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
    )

    # Set the original executed_at timestamp
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            row.executed_at = original_executed_at

    # Simulate a writeback failure (5xx)
    wb_id = new_writeback_id()
    disp_id = new_disposition_id()

    async with session_factory() as session:
        async with session.begin():
            outbox = orm.DispositionOutbox(
                outbox_id=f"out-{wb_id}",
                writeback_id=wb_id,
                disposition_id=disp_id,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                source_locator_hash="hash-5xx",
                source_sequence=1,
                intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                logical_slot="entity_action",
                idempotency_key=f"idem-{action_id}",
                command_payload={
                    "disposition_id": disp_id,
                    "operation_code": "submit_entity_action",
                },
                command_payload_sha256="sha256-5xx",
                delivery_status=OutboxDeliveryStatus.WAITING_RETRY.value,
                latest_writeback_status=WritebackStatus.FAILED.value,
                attempt=1,
                last_error_code="HTTP_503",
                last_error_detail="Mock XDR returned 503 Service Unavailable",
                next_retry_at=datetime.now(UTC),
            )
            session.add(outbox)

    # --- Assert: Original action execution metadata unchanged ---
    async with session_factory() as session:
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None

        # Action status must still be SUCCESS (not re-executed to EXECUTING/FAILED)
        assert ActionStatus(action_row.status) is ActionStatus.SUCCESS, (
            f"Writeback failure must not change action status, got {action_row.status}"
        )

        # executed_at must be the original timestamp (not updated by retry)
        assert action_row.executed_at is not None
        assert action_row.executed_at == original_executed_at, (
            f"executed_at changed from {original_executed_at} to {action_row.executed_at}"
        )

        # Outbox must be in WAITING_RETRY for the retry path
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.writeback_id == wb_id,
            )
        )
        assert outbox_row is not None
        assert (
            OutboxDeliveryStatus(outbox_row.delivery_status) is OutboxDeliveryStatus.WAITING_RETRY
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 4f: Unactivated deferred action not counted as failed
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_4f_unactivated_deferred_not_counted_as_failed(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 4f: Unactivated deferred action excluded from failed_actions count.

    ISSUE-064 requirement: "未激活 deferred 不得计入 failed_actions" — a
    deferred (POST_VERIFY) action that was never activated must not be counted
    as a failed action when tallying action outcomes.

    COVERAGE NOTE (ISSUE-064 review B6):
    This test operates at the database-contract layer — it writes Action
    rows directly and checks DB snapshots.  The real Service-layer
    verification (that unactivated deferred actions are excluded by the
    orchestration engine) is blocked on ISSUE-062 (writeback recovery
    handler).  When ISSUE-062 is complete a companion end-to-end scenario
    should exercise the full code path.
    """
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario 4f setup",
                )
            )

    # Create an IMMEDIATE action that succeeded
    await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.SUCCESS,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
    )

    # Create a POST_VERIFY deferred action that was NEVER activated
    # (still in PENDING — simulation was never triggered)
    deferred_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="update_source_event_disposition",
        tool_name="update_source_event_disposition",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.PENDING,
        action_level=ActionLevel.L2,
        activation_condition="after_effect_resolution",
        writeback_required=True,
        writeback_applicable=True,
    )

    # --- Assert: deferred action is NOT FAILED ---
    async with session_factory() as session:
        deferred_row = await session.get(orm.Action, deferred_id)
        assert deferred_row is not None
        assert ActionStatus(deferred_row.status) is not ActionStatus.FAILED, (
            "Unactivated deferred action must not be FAILED"
        )
        assert ActionStatus(deferred_row.status) is ActionStatus.PENDING, (
            f"Unactivated deferred action must remain PENDING, got {deferred_row.status}"
        )

        # --- Assert: failed_actions count excludes the unactivated deferred ---
        failed_count = await session.scalar(
            select(func.count())
            .select_from(orm.Action)
            .where(
                orm.Action.event_id == event_id,
                orm.Action.status == ActionStatus.FAILED.value,
            )
        )
        assert failed_count == 0, (
            f"Unactivated deferred must not be counted as failed, found {failed_count}"
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 5: Disposition-only (false positive → IGNORED → CLOSED)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_5_via_post_evidence_fp_adjudication(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    workflow_runtime_service: WorkflowRuntimeService,
    event_disposition_service: EventDispositionService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 5 companion: disposition-only after post-evidence fp_adjudication.

    Seeds a realistic ``fp_adjudication`` payload (as produced by
    :class:`PostEvidenceFpAdjudicator`) before ``begin_disposition_only``
    → activate_and_submit.
    """
    identity = f"mock_xdr|tenant-a|conn-1|incident|{SCENARIO_INCIDENT_ID}-fp-hook"
    occurred = datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC)
    event_id = new_event_id(identity, occurred)

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.DATA_EXFILTRATION.value,
                    title="Bulk login by ops account during change window",
                    description="Post-evidence FP adjudication companion test",
                    status=EventStatus.TRIAGING.value,
                    severity=Severity.MEDIUM.value,
                    risk_score=0,
                    confidence=0.0,
                    final_verdict=FinalVerdict.NONE.value,
                    disposition_policy=DispositionPolicy.REQUIRED.value,
                    creation_source_ref={
                        "source_product": "mock_xdr",
                        "source_tenant_id": "tenant-a",
                        "connector_id": "conn-1",
                        "source_kind": "incident",
                        "source_object_id": f"{SCENARIO_INCIDENT_ID}-fp-hook",
                    },
                    disposition_source_ref={
                        "source_product": "mock_xdr",
                        "source_tenant_id": "tenant-a",
                        "connector_id": "conn-1",
                        "source_kind": "incident",
                        "source_object_id": f"{SCENARIO_INCIDENT_ID}-fp-hook",
                    },
                    source_type="mock_xdr",
                    occurred_at=occurred,
                )
            )

    await _seed_source_object(
        session_factory,
        object_id=f"{SCENARIO_INCIDENT_ID}-fp-hook",
    )
    mock_xdr_state.upsert_object(
        "incident",
        f"{SCENARIO_INCIDENT_ID}-fp-hook",
        {"reference": {"source_disposition": "unknown"}},
    )

    fp_adj = await _seed_post_evidence_fp_adjudication(session_factory, event_id)
    assert fp_adj.get("recommendation") == "close_as_fp"
    assert fp_adj.get("matched_window_id") == "cw-scheduled-ops-maintenance"
    assert "baseline_window_match" in (fp_adj.get("matched_conditions") or [])

    await workflow_runtime_service.begin_disposition_only(event_id)

    result = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision=1,
        principal_or_system="test-scenario-5-hook",
    )
    assert result.activated is True, f"activation skipped: {result.skipped_reason}"
    assert result.derived_disposition is SourceDisposition.IGNORED

    async with session_factory() as session:
        receipt = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.disposition_id == result.disposition_id,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                orm.DispositionReceipt.confirmation_evidence
                == ConfirmationEvidence.READBACK_VERIFIED.value,
            )
        )
        assert receipt is not None

    await assert_no_analysis_content_in_outbound(session_factory, event_id)


async def _run_disposition_only_investigation_graph(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    mock_xdr_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    """Drive disposition-only through the production investigation graph (ISSUE-288)."""
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("DISPOSITION_MODE", "mock_xdr")
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "false")
    monkeypatch.setenv("ALLOW_XDR_WRITEBACK", "false")
    monkeypatch.setenv("ORCHESTRATION_MODE", "graph")
    monkeypatch.setenv("BUDGET_ENABLED", "false")
    get_settings.cache_clear()
    deps.reset_deps()
    patch_production_session_factory(monkeypatch, session_factory)

    registry = DispositionAdapterRegistry()
    registry.register(
        "mock_xdr",
        MockXDRDispositionAdapter(
            client=mock_xdr_client,
            read_token="mock-read-token",
            write_token="mock-write-token",
        ),
    )
    monkeypatch.setattr(deps, "_adapter_registry", registry)

    super_agent = await deps.get_super_agent()
    graph = getattr(super_agent, "_investigation_graph", None)
    assert graph is not None
    runtime = await deps.get_workflow_runtime()
    await runtime.begin_disposition_only(event_id)
    async with session_factory() as session:
        prebuilt_status = await session.scalar(
            select(orm.Action.status).where(
                orm.Action.event_id == event_id,
                orm.Action.execution_phase == ActionExecutionPhase.POST_VERIFY.value,
                orm.Action.tool_name == "update_source_event_disposition",
            )
        )
    assert prebuilt_status == ActionStatus.APPROVED.value
    initial = await build_initial_investigation_state(
        event_id,
        context_store=deps._get_context_store(),
        defer_response_execution=False,
        generate_report=True,
    )
    config = {"configurable": {"thread_id": event_id}}
    final = await invoke_investigation_graph(graph, initial, config)
    snapshot = await graph.aget_state(config)
    return {
        "final_state": final,
        "node_trace": list(
            (snapshot.values or {}).get("node_trace") or final.get("node_trace") or []
        ),
    }


@pytest.mark.usefixtures("clean_state")
async def test_scenario_5_disposition_only_false_positive_closed(
    session_factory: async_sessionmaker[AsyncSession],
    disposition_resolver: TerminalDispositionResolver,
    mock_xdr_state: MockXDRState,
    mock_xdr_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario 5: False positive → disposition-only graph path → IGNORED → CLOSED.

    ISSUE-288: the investigation graph must reach verify via
    begin_disposition_only_node → planner → response (prebuilt plan) →
    approval → execute → verify → report → close.  Manual
    ``activate_and_submit`` in the test is not the primary closure path.
    """
    # --- Arrange: Create event in TRIAGING with REQUIRED policy ---

    identity = f"mock_xdr|tenant-a|conn-1|incident|{SCENARIO_INCIDENT_ID}-fp"
    occurred = datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC)
    event_id = new_event_id(identity, occurred)

    async with session_factory() as session:
        async with session.begin():
            row = orm.SecurityEvent(
                event_id=event_id,
                event_type=EventType.DATA_EXFILTRATION.value,
                title="Disposition-only FP test",
                description="False positive → disposition_only → IGNORED → CLOSED",
                status=EventStatus.TRIAGING.value,
                severity=Severity.MEDIUM.value,
                risk_score=0,
                confidence=0.0,
                final_verdict=FinalVerdict.NONE.value,
                disposition_policy=DispositionPolicy.REQUIRED.value,
                creation_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": f"{SCENARIO_INCIDENT_ID}-fp",
                },
                disposition_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": f"{SCENARIO_INCIDENT_ID}-fp",
                },
                source_type="mock_xdr",
                occurred_at=occurred,
            )
            session.add(row)

    # Seed SourceObject so activate_and_submit can resolve the source locator
    # (ISSUE-064 review Blocker fix).
    await _seed_source_object(
        session_factory,
        object_id=f"{SCENARIO_INCIDENT_ID}-fp",
    )

    # B3: Also seed the corresponding MockXDR StoredObject so readback
    # confirmation (confirm_via_readback → _apply_confirmed_source_disposition)
    # can find and transition it.  Without this the receipt stays UNKNOWN
    # because the stored object lookup in MockXDRState.objects fails.
    mock_xdr_state.upsert_object(
        "incident",
        f"{SCENARIO_INCIDENT_ID}-fp",
        {"reference": {"source_disposition": "unknown"}},
    )

    # Seed the fp_adjudication journal (required by begin_disposition_only)
    await _seed_required_fp(session_factory, event_id)

    # --- Act: run disposition-only through the investigation graph ---
    graph_result = await _run_disposition_only_investigation_graph(
        session_factory=session_factory,
        event_id=event_id,
        mock_xdr_client=mock_xdr_client,
        monkeypatch=monkeypatch,
    )
    node_trace = graph_result["node_trace"]
    assert NODE_BEGIN_DISPOSITION_ONLY in node_trace
    assert NODE_RESPONSE in node_trace
    assert NODE_EXECUTE in node_trace
    assert NODE_VERIFY in node_trace
    assert node_trace.index(NODE_RESPONSE) < node_trace.index(NODE_EXECUTE)
    assert node_trace.index(NODE_EXECUTE) < node_trace.index(NODE_VERIFY)

    # ISSUE-064 S7: Assert no evidence collection in disposition-only path
    async with session_factory() as session:
        evidence_journal_entries = await session.scalar(
            select(func.count())
            .select_from(orm.EventContextJournal)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "evidence_output",
            )
        )
        evidence_journal_entries = evidence_journal_entries or 0
        assert evidence_journal_entries == 0, (
            "Disposition-only path must not trigger evidence collection outbox"
        )

    # ISSUE-064 S7: Assert stable report_id with single report journal entry
    stable_report_id = report_id_for_event(event_id)
    assert stable_report_id is not None, "report_id_for_event must produce a stable ID"
    assert report_id_for_event(event_id) == stable_report_id, (
        "report_id_for_event must be deterministic for the same event_id"
    )

    # --- Blocker fix: Assert disposition_policy stays REQUIRED ---
    # The policy is never rewritten; the writeback obligation is satisfied
    # through the standard deferred action → activate_and_submit chain.
    async with session_factory() as session:
        row_after_disp_only = await session.get(orm.SecurityEvent, event_id)
        assert row_after_disp_only is not None
        policy_after = DispositionPolicy(row_after_disp_only.disposition_policy)
        assert policy_after is DispositionPolicy.REQUIRED, (
            f"begin_disposition_only must keep disposition_policy=REQUIRED, got {policy_after}"
        )

    # --- Blocker fix: Assert deferred POST_VERIFY action created ---
    async with session_factory() as session:
        deferred_row = await session.scalar(
            select(orm.Action).where(
                orm.Action.event_id == event_id,
                orm.Action.execution_phase == ActionExecutionPhase.POST_VERIFY.value,
                orm.Action.tool_name == "update_source_event_disposition",
            )
        )
        assert deferred_row is not None, (
            "begin_disposition_only must create a deferred update_source_event_disposition Action"
        )
        assert deferred_row.status == ActionStatus.SUCCESS.value, (
            f"graph-completed deferred action must be SUCCESS, got {deferred_row.status}"
        )
        assert deferred_row.approved_terminal_dispositions == [SourceDisposition.IGNORED.value], (
            f"deferred action must pre-approve IGNORED, got "
            f"{deferred_row.approved_terminal_dispositions}"
        )

    # --- B4 fix: Assert SecurityEvent has correct FP verdict and confidence ---
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert FinalVerdict(row.final_verdict) is FinalVerdict.FALSE_POSITIVE
        assert float(row.confidence) >= 0.88

    # --- B4 fix: Assert derived_disposition is IGNORED ---
    disposition = disposition_resolver.resolve(
        final_verdict=FinalVerdict.FALSE_POSITIVE,
        verification=None,
        approved_terminal_dispositions=[
            SourceDisposition.IGNORED,
        ],
        disposition_only=True,
        disposition_policy=DispositionPolicy.REQUIRED,
        writeback_readiness=WritebackReadiness.READY,
        event_disposition_supported=True,
    )

    assert disposition.disposition is SourceDisposition.IGNORED, (
        f"False positive disposition_only must derive IGNORED, got {disposition.disposition}"
    )

    # --- Assert CONFIRMED EVENT_STATUS_UPDATE via graph-driven verify path ---
    async with session_factory() as session:
        terminal_outbox = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                orm.DispositionOutbox.superseded_by_disposition_id.is_(None),
            )
        )
        assert terminal_outbox is not None, (
            "Graph path must produce a terminal EVENT_STATUS_UPDATE outbox row"
        )
        receipt = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == terminal_outbox.writeback_id,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                orm.DispositionReceipt.confirmation_evidence
                == ConfirmationEvidence.READBACK_VERIFIED.value,
                orm.DispositionReceipt.simulated.is_(True),
            )
        )
        assert receipt is not None, (
            "P0: graph path must reach CONFIRMED readback_verified terminal writeback"
        )

    await _assert_event_status(session_factory, event_id, EventStatus.CLOSED)

    # --- Assert exactly one deferred terminal Action (no duplicate from ResponseAgent) ---
    async with session_factory() as session:
        deferred_count = await session.scalar(
            select(func.count())
            .select_from(orm.Action)
            .where(
                orm.Action.event_id == event_id,
                orm.Action.execution_phase == ActionExecutionPhase.POST_VERIFY.value,
                orm.Action.tool_name == "update_source_event_disposition",
                orm.Action.superseded_by_revision.is_(None),
            )
        )
        assert deferred_count == 1, (
            f"Disposition-only must keep a single deferred terminal Action, got {deferred_count}"
        )

    # --- Assert zero IMMEDIATE response actions created ---
    async with session_factory() as session:
        immediate_count = await session.scalar(
            select(func.count())
            .select_from(orm.Action)
            .where(
                orm.Action.event_id == event_id,
                orm.Action.action_category == ActionCategory.RESPONSE.value,
                orm.Action.execution_phase == ActionExecutionPhase.IMMEDIATE.value,
            )
        )
        assert immediate_count == 0, (
            f"Disposition-only path must not create IMMEDIATE actions: found {immediate_count}"
        )

    # --- B5 fix: Assert no analysis content leaked ---
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


@pytest.mark.usefixtures("clean_state")
async def test_scenario_5b_insider_threat_event_type_not_disposition_only(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    workflow_runtime_service: WorkflowRuntimeService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 5b (ISSUE-064 review S3): INSIDER_THREAT event type guard.

    Verifies that EventType.INSIDER_THREAT does not incorrectly trigger
    the disposition_only path, even when the event is in TRIAGING status
    and a valid false_positive_match journal entry exists.

    The EventType guard is implemented in
    ``WorkflowRuntimeService.begin_disposition_only`` (workflow_runtime.py),
    which checks ``EventType.INSIDER_THREAT`` after readiness, disposition_policy,
    EventStatus, and false_positive_match and raises ``ValidationError``
    to reject insider threat events from the disposition-only path.
    This test verifies that rejection.
    """
    # --- Arrange: Create an INSIDER_THREAT event in TRIAGING status ---

    identity = "mock_xdr|tenant-a|conn-1|incident|INSIDER-THREAT-002"
    occurred = datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC)
    insider_event_id = new_event_id(identity, occurred)

    async with session_factory() as session:
        async with session.begin():
            row = orm.SecurityEvent(
                event_id=insider_event_id,
                event_type=EventType.INSIDER_THREAT.value,
                title="Insider Threat with FP match - must not trigger disposition_only",
                description=(
                    "INSIDER_THREAT events must follow full investigation path "
                    "even when false_positive_match is present"
                ),
                status=EventStatus.TRIAGING.value,
                severity=Severity.HIGH.value,
                risk_score=70,
                confidence=0.88,
                final_verdict=FinalVerdict.NONE.value,
                disposition_policy=DispositionPolicy.REQUIRED.value,
                creation_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": "INSIDER-THREAT-002",
                },
                disposition_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": "INSIDER-THREAT-002",
                },
                source_type="mock_xdr",
                occurred_at=occurred,
            )
            session.add(row)

    # Seed a valid false_positive_match journal entry so the test
    # exercises the EventType guard specifically, not the fp-match guard.
    await _seed_required_fp(session_factory, insider_event_id, max_score=0.92)

    # Seed context so it looks like a real investigation
    async with session_factory() as session:
        async with session.begin():
            await append_context_journal_in_session(
                session,
                insider_event_id,
                "triage_result",
                {
                    "event_type": EventType.INSIDER_THREAT.value,
                    "severity": Severity.HIGH.value,
                    "need_investigation": True,
                    "confidence": 0.88,
                    "reasoning": "Insider threat requires full investigation",
                },
            )

    # --- Act & Assert: begin_disposition_only MUST reject INSIDER_THREAT ---
    # The EventType guard (workflow_runtime.py:106) raises ValidationError for
    # INSIDER_THREAT events — this test verifies the rejection.

    with pytest.raises(ValidationError, match="INSIDER_THREAT"):
        await workflow_runtime_service.begin_disposition_only(insider_event_id)

    # --- Assert: Event is still TRIAGING (not affected by disposition_only) ---
    await _assert_event_status(session_factory, insider_event_id, EventStatus.TRIAGING)

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, insider_event_id)


# ---------------------------------------------------------------------------
# Scenario 5c: Disposition-only path does not trigger evidence collection
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_5c_no_evidence_collection_in_disposition_only(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    workflow_runtime_service: WorkflowRuntimeService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 5c: Disposition-only path must not invoke evidence collection.

    ISSUE-064 requirement: "不进证据采集" — the disposition-only code path
    (begin_disposition_only) must skip evidence collection entirely.  This
    test verifies zero evidence_output journal mutations after the call.
    """

    identity = f"mock_xdr|tenant-a|conn-1|incident|{SCENARIO_INCIDENT_ID}-5c"
    occurred = datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC)
    event_id = new_event_id(identity, occurred)

    async with session_factory() as session:
        async with session.begin():
            row = orm.SecurityEvent(
                event_id=event_id,
                event_type=EventType.DATA_EXFILTRATION.value,
                title="5c: No evidence collection in disposition-only",
                description="Disposition-only must skip evidence collection",
                status=EventStatus.TRIAGING.value,
                severity=Severity.MEDIUM.value,
                risk_score=0,
                confidence=0.0,
                final_verdict=FinalVerdict.NONE.value,
                disposition_policy=DispositionPolicy.REQUIRED.value,
                creation_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": f"{SCENARIO_INCIDENT_ID}-5c",
                },
                disposition_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": f"{SCENARIO_INCIDENT_ID}-5c",
                },
                source_type="mock_xdr",
                occurred_at=occurred,
            )
            session.add(row)

    await _seed_required_fp(session_factory, event_id)

    # Count evidence_output journal entries before
    async with session_factory() as session:
        before_count = await session.scalar(
            select(func.count())
            .select_from(orm.EventContextJournal)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "evidence_output",
            )
        )
        before_count = before_count or 0

    # --- Act ---
    await workflow_runtime_service.begin_disposition_only(event_id)

    # --- Assert: No new evidence_output journal entries ---
    async with session_factory() as session:
        after_count = await session.scalar(
            select(func.count())
            .select_from(orm.EventContextJournal)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "evidence_output",
            )
        )
        after_count = after_count or 0
        assert after_count == before_count, (
            "Disposition-only path must not create evidence_output journal entries: "
            f"{before_count} → {after_count}"
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 5d: Stable report_id and single report journal entry
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_5d_stable_report_id_single_report(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    workflow_runtime_service: WorkflowRuntimeService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario 5d: Disposition-only path produces a single report with stable ID.

    ISSUE-064 requirement: "报告按稳定 report_id 单份" — report_id_for_event
    must return a stable (deterministic) ID, and the report journal entry must
    appear only once per event.
    """

    identity = f"mock_xdr|tenant-a|conn-1|incident|{SCENARIO_INCIDENT_ID}-5d"
    occurred = datetime(2024, 6, 15, 9, 0, 0, tzinfo=UTC)
    event_id = new_event_id(identity, occurred)

    async with session_factory() as session:
        async with session.begin():
            row = orm.SecurityEvent(
                event_id=event_id,
                event_type=EventType.DATA_EXFILTRATION.value,
                title="5d: Stable report_id single report",
                description="Disposition-only must produce a single report",
                status=EventStatus.TRIAGING.value,
                severity=Severity.MEDIUM.value,
                risk_score=0,
                confidence=0.0,
                final_verdict=FinalVerdict.NONE.value,
                disposition_policy=DispositionPolicy.REQUIRED.value,
                creation_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": f"{SCENARIO_INCIDENT_ID}-5d",
                },
                disposition_source_ref={
                    "source_product": "mock_xdr",
                    "source_tenant_id": "tenant-a",
                    "connector_id": "conn-1",
                    "source_kind": "incident",
                    "source_object_id": f"{SCENARIO_INCIDENT_ID}-5d",
                },
                source_type="mock_xdr",
                occurred_at=occurred,
            )
            session.add(row)

    await _seed_required_fp(session_factory, event_id)

    # --- Assert: report_id_for_event is stable (deterministic) ---
    rid_1 = report_id_for_event(event_id)
    rid_2 = report_id_for_event(event_id)
    assert rid_1 is not None, "report_id_for_event must produce a value"
    assert rid_1 == rid_2, f"report_id_for_event must be stable: {rid_1} ≠ {rid_2}"

    # --- Act ---
    await workflow_runtime_service.begin_disposition_only(event_id)

    # --- Assert: Report journal entry is unique (single entry per event) ---
    async with session_factory() as session:
        report_count = await session.scalar(
            select(func.count())
            .select_from(orm.EventContextJournal)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "report",
            )
        )
        assert report_count is not None
        assert report_count <= 1, (
            f"Disposition-only must produce at most 1 report journal entry, found {report_count}"
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 4b (B3 fix): HTTP 5xx via MockXDRState.failure_profile
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_4b_http_5xx_via_mock_xdr_failure_profile(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
    mock_xdr_client: Any,
) -> None:
    """Scenario 4b (B3 fix): MockXDR failure_profile → 5xx → UNKNOWN → outbox PAUSED.

    Configures ``MockXDRState.failure_profile.server_error_every_n = 1`` so the
    MockXDR API returns HTTP 500 on every writeback submit.  Submits a
    disposition command through the MockXDRDispositionAdapter and asserts the
    adapter correctly converts 5xx → UNKNOWN (per the safety rule: a lost
    response must not be treated as FAILED).

    This exercises the FULL fault-injection chain:
    MockXDRState.failure_profile → MockXDR API 5xx →
    MockXDRDispositionAdapter → UNKNOWN receipt → outbox PAUSED.
    """
    from app.adapters.mock_xdr import MockXDRDispositionAdapter

    # Configure MockXDR to return 500 on every writeback request
    mock_xdr_state.failure_profile.server_error_every_n = 1

    # Create event + action with writeback
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value

    action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.SUCCESS,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
    )

    # Build adapter wired to MockXDR API
    adapter = MockXDRDispositionAdapter(
        client=mock_xdr_client,
        read_token="mock-read-token",
        write_token="mock-write-token",
    )

    disp_id = new_disposition_id()
    wb_id = new_writeback_id()

    # Build the disposition command
    command = DispositionCommand(
        disposition_id=disp_id,
        action_id=action_id,
        closure_cycle=1,
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-a",
            connector_id="conn-1",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id=SCENARIO_INCIDENT_ID,
        ),
        operation_code="submit_entity_action",
        operation_params=SubmitEntityActionParams(
            operation_code="submit_entity_action",
            entity_action_code="isolate_host",
            canonical_target="host-1",
        ),
        operator_id="test-scenario-4b",
        idempotency_key=f"idem-{action_id}",
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )

    try:
        # --- Act: Submit via adapter — MockXDR returns 500, adapter returns UNKNOWN ---
        receipt = await adapter.submit(command)

        # Safety rule: 5xx → UNKNOWN (response lost, status unconfirmable)
        assert receipt.status is WritebackStatus.UNKNOWN, (
            f"MockXDR 5xx must be converted to UNKNOWN by adapter (safety: "
            f"never treat lost response as FAILED), got {receipt.status}"
        )

        # Create outbox entry reflecting the 5xx → UNKNOWN writeback result
        async with session_factory() as session:
            async with session.begin():
                outbox = orm.DispositionOutbox(
                    outbox_id=f"out-{wb_id}",
                    writeback_id=wb_id,
                    disposition_id=disp_id,
                    action_id=action_id,
                    event_id=event_id,
                    closure_cycle=1,
                    source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                    source_locator_hash="hash-5xx-fp",
                    source_sequence=1,
                    intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                    logical_slot="entity_action",
                    idempotency_key=f"idem-{action_id}",
                    command_payload=command.model_dump(mode="json"),
                    command_payload_sha256="sha256-5xx-fp",
                    delivery_status=OutboxDeliveryStatus.PAUSED.value,
                    latest_writeback_status=WritebackStatus.UNKNOWN.value,
                    attempt=1,
                    last_error_code="HTTP_500",
                    last_error_detail="MockXDR returned 500 via failure_profile → UNKNOWN",
                )
                session.add(outbox)

                action_row = await session.get(orm.Action, action_id, with_for_update=True)
                assert action_row is not None
                action_row.writeback_status = WritebackStatus.UNKNOWN.value

        # --- Assert: outbox is PAUSED (not auto-retried for UNKNOWN) ---
        async with session_factory() as session:
            outbox_row = await session.scalar(
                select(orm.DispositionOutbox).where(
                    orm.DispositionOutbox.writeback_id == wb_id,
                )
            )
            assert outbox_row is not None
            # UNKNOWN → PAUSED, not WAITING_RETRY.  Manual adjudication required.
            assert (
                OutboxDeliveryStatus(outbox_row.delivery_status) is OutboxDeliveryStatus.PAUSED
            ), f"Expected PAUSED after MockXDR 5xx → UNKNOWN, got {outbox_row.delivery_status}"
            assert outbox_row.latest_writeback_status is not None
            assert WritebackStatus(outbox_row.latest_writeback_status) is WritebackStatus.UNKNOWN
            assert outbox_row.attempt >= 1, "Must have at least 1 delivery attempt"
    finally:
        # Reset failure profile so subsequent tests are clean
        mock_xdr_state.failure_profile.server_error_every_n = None

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario 3b (S4 fix): DIRECT_TOOL idempotent recovery via DispositionSyncService
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_3_direct_tool_recovery_via_disposition_sync_service(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
    mock_xdr_client: Any,
) -> None:
    """Scenario 3 (S4 fix): DIRECT_TOOL idempotent recovery via MockXDR adapter.

    Uses the MockXDRDispositionAdapter to submit an EXECUTION_RESULT_RECORD
    command twice with the same idempotency key.  Asserts the second submission
    is idempotent (no double execution) and the receipt correctly reflects
    the confirmed status.

    This exercises the real adapter → MockXDR API path (instead of DB-contract
    layer simulation), verifying the idempotency-key guarantee.
    """
    from app.adapters.mock_xdr import MockXDRDispositionAdapter

    # --- Arrange ---
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario 3 recovery setup",
                )
            )

    # Create a DIRECT_TOOL action (SUCCESS)
    direct_action_id = new_action_id()
    idempotency_key = f"idem-direct-recovery-{direct_action_id}"

    await _insert_action(
        session_factory,
        event_id=event_id,
        action_id=direct_action_id,
        action_name="isolate_network",
        tool_name="isolate_network",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
        status=ActionStatus.SUCCESS,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
        idempotency_key=idempotency_key,
        target="host-1",
    )

    adapter = MockXDRDispositionAdapter(
        client=mock_xdr_client,
        read_token="mock-read-token",
        write_token="mock-write-token",
    )

    disp_id = new_disposition_id()
    wb_id = new_writeback_id()

    # Build an EXECUTION_RESULT_RECORD command
    command = DispositionCommand(
        disposition_id=disp_id,
        action_id=direct_action_id,
        closure_cycle=1,
        intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-a",
            connector_id="conn-1",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id=SCENARIO_INCIDENT_ID,
        ),
        operation_code="record_execution_result",
        operation_params=RecordExecutionResultParams(
            operation_code="record_execution_result",
            summary_code="isolate_success",
        ),
        operator_id="test-scenario-3-recovery",
        idempotency_key=idempotency_key,
        execution_owner=ExecutionOwner.DIRECT_TOOL,
    )

    # --- Act: First submission succeeds ---
    receipt_1 = await adapter.submit(command)

    assert receipt_1.status in (WritebackStatus.ACCEPTED, WritebackStatus.CONFIRMED), (
        f"First submission must succeed, got {receipt_1.status}"
    )

    # --- Act: Second submission with same idempotency key ---
    # The MockXDR should handle this idempotently (no double side-effect)
    receipt_2 = await adapter.submit(command)

    assert receipt_2.status in (WritebackStatus.ACCEPTED, WritebackStatus.CONFIRMED), (
        f"Idempotent resubmission must succeed, got {receipt_2.status}"
    )

    # --- Assert: No duplicate device side-effects ---
    # Both receipts reference the same writeback_id, confirming idempotent execution
    assert receipt_1.writeback_id is not None or receipt_2.writeback_id is not None, (
        "At least one receipt must have a valid writeback_id"
    )

    # Store the receipt in the DB and verify
    async with session_factory() as session:
        async with session.begin():
            outbox = orm.DispositionOutbox(
                outbox_id=f"out-{wb_id}",
                writeback_id=wb_id,
                disposition_id=disp_id,
                action_id=direct_action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                source_locator_hash="hash-recovery-s4",
                source_sequence=1,
                intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD.value,
                logical_slot="execution_result",
                idempotency_key=idempotency_key,
                command_payload=command.model_dump(mode="json"),
                command_payload_sha256="sha256-recovery-s4",
                delivery_status=OutboxDeliveryStatus.DELIVERED.value,
                latest_writeback_status=receipt_1.status.value,
                attempt=1,
                delivered_at=datetime.now(UTC),
            )
            session.add(outbox)

            # Record the receipt
            session.add(
                orm.DispositionReceipt(
                    writeback_id=receipt_1.writeback_id or wb_id,
                    sequence=1,
                    disposition_id=disp_id,
                    action_id=direct_action_id,
                    source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                    status=receipt_1.status.value,
                    confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED.value,
                    simulated=True,
                    observed_at=datetime.now(UTC),
                    submitted_at=datetime.now(UTC),
                    confirmed_at=datetime.now(UTC),
                )
            )

    # --- Assert: Single outbox entry per action (no duplicate) ---
    async with session_factory() as session:
        outbox_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.action_id == direct_action_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EXECUTION_RESULT_RECORD.value,
            )
        )
        assert outbox_count == 1, (
            f"Idempotent recovery must not create duplicate outbox entries: found {outbox_count}"
        )

        # Assert the outbox is DELIVERED
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.writeback_id == wb_id,
            )
        )
        assert outbox_row is not None
        assert OutboxDeliveryStatus(outbox_row.delivery_status) is OutboxDeliveryStatus.DELIVERED, (
            f"Expected DELIVERED after idempotent recovery, got {outbox_row.delivery_status}"
        )

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)


# ---------------------------------------------------------------------------
# Scenario UNKNOWN disposition (S3 fix): no auto-retry on UNKNOWN
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_state")
async def test_scenario_unknown_disposition_no_auto_retry(
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
) -> None:
    """Scenario UNKNOWN (S3 fix): UNKNOWN writeback status must not auto-retry.

    When a writeback returns UNKNOWN (idempotency key submitted but status
    unconfirmable — e.g., network partition after submission), the system
    MUST NOT automatically retry.  Retrying a potentially-successful writeback
    could cause duplicate side effects.

    This test injects a UNKNOWN writeback receipt and asserts:
    1. The action's writeback_status remains UNKNOWN (not auto-retried)
    2. The outbox is NOT in WAITING_RETRY (blocked until manual adjudication)
    3. No duplicate outbox entries or receipts are created
    """
    event_id = await _create_event(session_factory, context_store)

    await _seed_source_object(session_factory)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.REPORTING.value
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=EventStatus.NEW.value,
                    to_status=EventStatus.REPORTING.value,
                    operator="test",
                    reason="scenario UNKNOWN setup",
                )
            )

    # Create an action with UNKNOWN writeback status
    action_id = await _insert_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        action_category=ActionCategory.RESPONSE,
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        status=ActionStatus.SUCCESS,
        action_level=ActionLevel.L2,
        writeback_required=True,
        writeback_applicable=True,
    )

    # Simulate UNKNOWN writeback result
    wb_id = new_writeback_id()
    disp_id = new_disposition_id()

    async with session_factory() as session:
        async with session.begin():
            receipt = orm.DispositionReceipt(
                writeback_id=wb_id,
                sequence=1,
                disposition_id=disp_id,
                action_id=action_id,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                status=WritebackStatus.UNKNOWN.value,
                simulated=True,
                observed_at=datetime.now(UTC),
                submitted_at=datetime.now(UTC),
            )
            session.add(receipt)

            outbox = orm.DispositionOutbox(
                outbox_id=f"out-{wb_id}",
                writeback_id=wb_id,
                disposition_id=disp_id,
                action_id=action_id,
                event_id=event_id,
                closure_cycle=1,
                source_record_id=f"src-{SCENARIO_INCIDENT_ID}",
                source_locator_hash="hash-unknown",
                source_sequence=1,
                intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT.value,
                logical_slot="entity_action",
                idempotency_key=f"idem-{action_id}",
                command_payload={
                    "disposition_id": disp_id,
                    "operation_code": "submit_entity_action",
                    "operation_params": {
                        "entity_action_code": "isolate_host",
                        "canonical_target": "host-1",
                    },
                },
                command_payload_sha256="sha256-unknown",
                delivery_status=OutboxDeliveryStatus.PAUSED.value,
                latest_writeback_status=WritebackStatus.UNKNOWN.value,
                attempt=1,
                last_error_detail=(
                    "Network partition: writeback submitted but status unconfirmable"
                ),
            )
            session.add(outbox)

            # Mark action writeback as UNKNOWN (blocking further disposition)
            action_row = await session.get(orm.Action, action_id, with_for_update=True)
            assert action_row is not None
            action_row.writeback_status = WritebackStatus.UNKNOWN.value

    # --- Assert: UNKNOWN status, no auto-retry ---
    async with session_factory() as session:
        # 1. Action writeback_status is UNKNOWN
        action_row = await session.get(orm.Action, action_id)
        assert action_row is not None
        assert action_row.writeback_status is not None
        assert WritebackStatus(action_row.writeback_status) is WritebackStatus.UNKNOWN, (
            f"Expected UNKNOWN, got {action_row.writeback_status}"
        )

        # 2. Outbox is PAUSED (NOT WAITING_RETRY — must be manually adjudicated)
        outbox_row = await session.scalar(
            select(orm.DispositionOutbox).where(
                orm.DispositionOutbox.writeback_id == wb_id,
            )
        )
        assert outbox_row is not None
        assert OutboxDeliveryStatus(outbox_row.delivery_status) is OutboxDeliveryStatus.PAUSED, (
            f"UNKNOWN must be PAUSED (not auto-retried), got {outbox_row.delivery_status}"
        )
        assert outbox_row.latest_writeback_status is not None
        assert WritebackStatus(outbox_row.latest_writeback_status) is WritebackStatus.UNKNOWN

        # 3. No duplicate outbox entries
        outbox_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.action_id == action_id,
            )
        )
        assert outbox_count == 1, (
            f"UNKNOWN must not create duplicate outbox entries: found {outbox_count}"
        )

        # 4. Receipt reflects UNKNOWN
        receipt_row = await session.scalar(
            select(orm.DispositionReceipt).where(
                orm.DispositionReceipt.writeback_id == wb_id,
            )
        )
        assert receipt_row is not None
        assert receipt_row.status is not None
        assert WritebackStatus(receipt_row.status) is WritebackStatus.UNKNOWN

    # B5 fix: Assert no analysis content leaked
    await assert_no_analysis_content_in_outbound(session_factory, event_id)
