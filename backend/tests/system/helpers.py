"""Shared helpers for ISSUE-086 system tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.response_agent import build_mock_capability_manifest, compute_template_hash
from app.core.auth import Principal
from app.data_generators.scenarios import build_scenario
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.mock_xdr.state import MockXDRState
from app.models.agent_io import (
    RiskAssessment,
    ScoringMode,
    VerificationOverallStatus,
    VerificationPhase,
)
from app.models.approval import ApprovalDecisionKind
from app.models.disposition import SourceObjectLocator
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
    Severity,
    SourceDisposition,
    SourceObjectKind,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.ids import new_action_id, new_disposition_id
from app.models.source import SourceReference
from app.models.workflow import validate_action_status_transition
from app.services.approval_engine import ApprovalEngine
from app.services.context_service import EventContextStore, append_context_journal_in_session
from app.services.disposition_command_factory import DispositionCommandFactory
from app.services.disposition_sync_service import DispositionSyncService
from app.services.event_disposition_service import EventDispositionService, _action_from_row
from app.services.event_service import EventService
from app.services.state_machine_service import StateMachineService
from tests.helpers.decision_audit import seed_minimum_disposition_audit
from tests.integration.conftest import FailingLLMClient, FlakyToolExecutor
from tests.system.scenario_expectations import ScenarioExpectation, risk_bounds_for

ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]


async def event_id_for_incident(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    connector_id: str,
    source_object_id: str,
) -> str:
    async with session_factory() as session:
        event_id = await session.scalar(
            select(orm.SecurityEvent.event_id).where(
                orm.SecurityEvent.creation_source_ref["connector_id"].as_string() == connector_id,
                orm.SecurityEvent.creation_source_ref["source_object_id"].as_string()
                == source_object_id,
            )
        )
    assert event_id is not None, (
        f"no event for connector={connector_id!r} source_object_id={source_object_id!r}"
    )
    return event_id


async def ingest_scenario_event(
    *,
    scenario_id: str,
    source_adapter: Any,
    source_ingester: SourceIngester,
    event_service: EventService,
    mock_xdr_state: MockXDRState,
    session_factory: async_sessionmaker[AsyncSession],
    instance: int = 0,
) -> str:
    scenario = build_scenario(scenario_id, seed=42, instance=instance)
    mock_xdr_state.load_scenario(scenario)
    incident = scenario.incidents[0]
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.rejected == 0, summary.errors
    assert summary.accepted >= 1, summary.model_dump()
    return await event_id_for_incident(
        session_factory,
        connector_id=incident.reference.connector_id,
        source_object_id=incident.reference.source_object_id,
    )


async def run_rule_fallback_main_chain(
    *,
    event_id: str,
    run_graph_investigation: Any,
    scenario_id: str,
) -> None:
    await run_graph_investigation(
        event_id,
        llm_client=FailingLLMClient(),
        scenario_id=scenario_id,
    )


async def assert_main_chain_expectations(
    *,
    event_service: EventService,
    context_store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    spec: ScenarioExpectation,
) -> None:
    event = await event_service.get_event(event_id)
    assert event is not None

    triage_ctx = await context_store.get(event_id, "triage_result")
    risk_ctx = await context_store.get(event_id, "risk_assessment")
    report_ctx = await context_store.get(event_id, "report")
    assert triage_ctx is not None
    # ISSUE-099: LLM text extraction may fail, but source-enriched entities
    # mean triage is not degraded=True.
    assert triage_ctx.get("degraded") is False
    degradation_reasons = triage_ctx.get("degradation_reasons") or []
    assert "text_extraction_empty" in degradation_reasons
    triage_type = str(triage_ctx.get("event_type") or "")
    assert triage_type in {member.value for member in EventType}
    assert risk_ctx is not None
    assert risk_ctx.get("scoring_mode") == ScoringMode.RULE_ONLY.value
    assert report_ctx is not None

    scoring_mode = risk_ctx.get("scoring_mode")
    risk_score_ctx = risk_ctx.get("risk_score")
    rule_only = spec.rule_fallback and scoring_mode == ScoringMode.RULE_ONLY.value
    risk_min, risk_max = risk_bounds_for(spec, rule_only=rule_only)

    if spec.expect_reporting:
        assert event.status in {EventStatus.REPORTING, EventStatus.CLOSED}, (
            f"unexpected terminal status {event.status} for {spec.scenario_id}"
        )
    else:
        assert event.status is EventStatus.CLOSED

    if event.final_verdict is not None:
        assert event.final_verdict in spec.acceptable_verdicts, (
            f"unexpected verdict {event.final_verdict} for {spec.scenario_id}; "
            f"risk_score={event.risk_score} ctx_score={risk_score_ctx} "
            f"scoring_mode={scoring_mode} "
            f"evidence_limited={risk_ctx.get('evidence_limited')} "
            f"high_source_evidence_limited={risk_ctx.get('high_source_evidence_limited')} "
            f"acceptable={tuple(v.value for v in spec.acceptable_verdicts)}"
        )

    if event.risk_score is not None:
        assert risk_min <= int(event.risk_score) <= risk_max, (
            f"risk_score {event.risk_score} outside [{risk_min}, {risk_max}] "
            f"for {spec.scenario_id} (rule_only={rule_only})"
        )

    if risk_score_ctx is not None:
        assert risk_min <= int(risk_score_ctx) <= risk_max, (
            f"context risk_score {risk_score_ctx} outside [{risk_min}, {risk_max}] "
            f"for {spec.scenario_id} (rule_only={rule_only})"
        )

    response_plan = await context_store.get(event_id, "response_plan")
    if isinstance(response_plan, dict):
        for action in response_plan.get("actions") or []:
            if not isinstance(action, dict):
                continue
            tool_name = action.get("tool_name") or action.get("action_name")
            if tool_name:
                assert tool_name in spec.allowed_actions, (
                    f"response plan tool {tool_name!r} not in allowed_actions "
                    f"for {spec.scenario_id}"
                )

    async with session_factory() as session:
        report_row = await session.scalar(select(orm.Report).where(orm.Report.event_id == event_id))
    assert report_row is not None, f"missing persisted Report row for {event_id}"
    assert report_ctx.get("title") or report_row.title


async def assert_approval_record_exists(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> None:
    async with session_factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(orm.ApprovalRecordORM)
            .join(orm.Action, orm.Action.action_id == orm.ApprovalRecordORM.action_id)
            .where(orm.Action.event_id == event_id)
        )
    assert int(count or 0) >= 1, f"expected ApprovalRecord for {event_id}"


async def seed_source_object_for_event(
    session_factory: async_sessionmaker[AsyncSession],
    event: Any,
) -> str:
    ref = SourceReference.model_validate(event.creation_source_ref)
    source_record_id = f"src-{ref.source_object_id}"
    async with session_factory() as session:
        existing = await session.scalar(
            select(orm.SourceObject).where(
                orm.SourceObject.source_product == ref.source_product,
                orm.SourceObject.source_tenant_id == ref.source_tenant_id,
                orm.SourceObject.connector_id == ref.connector_id,
                orm.SourceObject.source_kind == ref.source_kind.value,
                orm.SourceObject.source_object_id == ref.source_object_id,
            )
        )
        if existing is not None:
            return existing.source_record_id

        async with session.begin():
            existing_conn = await session.get(orm.SourceConnector, ref.connector_id)
            if existing_conn is None:
                session.add(
                    orm.SourceConnector(
                        connector_id=ref.connector_id,
                        source_product=ref.source_product,
                        display_name="Mock XDR",
                    )
                )
            session.add(
                orm.SourceObject(
                    source_record_id=source_record_id,
                    source_product=ref.source_product,
                    source_tenant_id=ref.source_tenant_id,
                    connector_id=ref.connector_id,
                    source_kind=ref.source_kind.value,
                    source_object_id=ref.source_object_id,
                    next_outbox_sequence=0,
                )
            )
    return source_record_id


async def insert_response_action(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
    action_name: str,
    tool_name: str,
    execution_phase: ActionExecutionPhase,
    status: ActionStatus,
    disposition_source_ref: dict[str, Any],
    target: str = "host-target-1",
    activation_condition: str | None = None,
) -> str:
    approved_raw = [
        SourceDisposition.CONTAINED.value,
        SourceDisposition.COMPLETED.value,
        SourceDisposition.IGNORED.value,
    ]
    approved_hash = compute_template_hash(
        [SourceDisposition.CONTAINED, SourceDisposition.COMPLETED, SourceDisposition.IGNORED]
    )
    action_id = f"act-system-{tool_name}-{event_id[-8:]}"
    if isinstance(disposition_source_ref, SourceObjectLocator):
        locator = disposition_source_ref
    elif isinstance(disposition_source_ref, SourceReference):
        locator = SourceObjectLocator(
            source_product=disposition_source_ref.source_product,
            source_tenant_id=disposition_source_ref.source_tenant_id,
            connector_id=disposition_source_ref.connector_id,
            source_kind=disposition_source_ref.source_kind,
            source_object_type=disposition_source_ref.source_object_type,
            source_object_id=disposition_source_ref.source_object_id,
        )
    else:
        ref = SourceReference.model_validate(disposition_source_ref)
        locator = SourceObjectLocator(
            source_product=ref.source_product,
            source_tenant_id=ref.source_tenant_id,
            connector_id=ref.connector_id,
            source_kind=ref.source_kind,
            source_object_type=ref.source_object_type,
            source_object_id=ref.source_object_id,
        )
    safe_disposition_ref = json.loads(locator.model_dump_json())
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-system-{tool_name}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name=action_name,
                    tool_name=tool_name,
                    action_level=ActionLevel.L2.value,
                    execution_phase=execution_phase.value,
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    status=status.value,
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    idempotency_key=f"idem-system-{tool_name}-{event_id[-8:]}",
                    target=target,
                    parameters={"target": target},
                    reason="ISSUE-086 system full response chain",
                    approved_operation_template_hash=approved_hash,
                    approved_terminal_dispositions=approved_raw,
                    disposition_source_ref=safe_disposition_ref,
                    activation_condition=activation_condition,
                )
            )
    return action_id


async def submit_entity_action_once(
    session_factory: async_sessionmaker[AsyncSession],
    disposition_sync_service: DispositionSyncService,
    *,
    event_id: str,
    action_id: str,
    mock_xdr_state: MockXDRState,
    source_record_id: str,
) -> None:
    request_counter_before = mock_xdr_state.request_counter
    outbox_id: str | None = None
    factory = DispositionCommandFactory()

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action_id, with_for_update=True)
            assert row is not None
            action = _action_from_row(row)
            token_row = await session.get(orm.SourceObject, source_record_id)
            token = token_row.current_concurrency_token if token_row else None
            disposition_id = new_disposition_id()
            command = factory.build_entity_action_submit(
                action,
                source_locator=action.disposition_source_ref,
                source_concurrency_token=token,
                operator_id="system-test",
                disposition_id=disposition_id,
                writeback_id="pending",
                closure_cycle=int(action.plan_revision),
                entity_action_code="contain_device",
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

    assert mock_xdr_state.request_counter == request_counter_before + 1


async def prepare_event_for_response_chain(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> None:
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id)
            assert row is not None
            row.final_verdict = FinalVerdict.CONFIRMED_THREAT.value
            row.risk_score = max(int(row.risk_score or 0), 82)
            row.confidence = max(float(row.confidence or 0.0), 0.9)


async def run_full_response_chain(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    event_service: EventService,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    mock_xdr_state: MockXDRState,
    event_id: str,
) -> None:
    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status is EventStatus.REPORTING, (
        f"expected REPORTING before response chain, got {event.status}"
    )
    assert event.disposition_policy is DispositionPolicy.REQUIRED

    await prepare_event_for_response_chain(session_factory, event_id)
    event = await event_service.get_event(event_id)
    assert event is not None
    disposition_source_ref = (
        event.creation_source_ref.model_dump(mode="json")
        if hasattr(event.creation_source_ref, "model_dump")
        else dict(event.creation_source_ref)
    )

    source_record_id = await seed_source_object_for_event(session_factory, event)

    terminal_action_id = await insert_response_action(
        session_factory,
        event_id=event_id,
        action_name="update_source_event_disposition",
        tool_name="update_source_event_disposition",
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        status=ActionStatus.APPROVED,
        disposition_source_ref=disposition_source_ref,
        activation_condition="after_effect_resolution",
    )
    immediate_action_id = await insert_response_action(
        session_factory,
        event_id=event_id,
        action_name="isolate_host",
        tool_name="isolate_host",
        execution_phase=ActionExecutionPhase.IMMEDIATE,
        status=ActionStatus.APPROVED,
        disposition_source_ref=disposition_source_ref,
    )

    await submit_entity_action_once(
        session_factory,
        disposition_sync_service,
        event_id=event_id,
        action_id=immediate_action_id,
        mock_xdr_state=mock_xdr_state,
        source_record_id=source_record_id,
    )

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

    await seed_minimum_disposition_audit(session_factory, event_id)
    result = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision=1,
        principal_or_system="system-test",
    )
    assert result.activated is True, result.skipped_reason
    assert result.action_id == terminal_action_id

    refreshed = await event_service.get_event(event_id)
    assert refreshed is not None
    assert refreshed.status in {
        EventStatus.REPORTING,
        EventStatus.VERIFYING,
        EventStatus.CLOSED,
    }

    async with session_factory() as session:
        receipt = await session.scalar(
            select(orm.DispositionReceipt)
            .join(orm.Action, orm.Action.action_id == orm.DispositionReceipt.action_id)
            .where(
                orm.Action.event_id == event_id,
                orm.DispositionReceipt.status == WritebackStatus.CONFIRMED.value,
                orm.DispositionReceipt.confirmation_evidence
                == ConfirmationEvidence.READBACK_VERIFIED.value,
            )
        )
        terminal_outbox = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(
                orm.DispositionOutbox.event_id == event_id,
                orm.DispositionOutbox.intent_kind
                == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
            )
        )
    assert receipt is not None
    assert terminal_outbox == 1


async def assert_no_disposition_writeback(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> None:
    async with session_factory() as session:
        receipt_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionReceipt)
            .join(orm.Action, orm.Action.action_id == orm.DispositionReceipt.action_id)
            .where(orm.Action.event_id == event_id)
        )
        outbox_count = await session.scalar(
            select(func.count())
            .select_from(orm.DispositionOutbox)
            .where(orm.DispositionOutbox.event_id == event_id)
        )
    assert int(receipt_count or 0) == 0, f"expected no receipts for {event_id}"
    assert int(outbox_count or 0) == 0, f"expected no outbox rows for {event_id}"


async def assert_event_has_degraded_flag(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    flag_name: str,
) -> None:
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
    assert row is not None
    flags = [str(item) for item in (row.degraded_flags or [])]
    assert any(item.startswith(f"{flag_name}=") for item in flags), (
        f"expected degraded flag {flag_name!r} on {event_id}, got {flags}"
    )


async def pre_exhaust_event_token_budget(
    budget_service: Any,
    event_id: str,
    *,
    agent_name: str = "EvidenceAgent",
) -> None:
    limit = int(budget_service.allocate_event_budget(Severity.HIGH))
    await budget_service.charge_llm(
        event_id,
        agent_name,
        "mock-model",
        prompt_tokens=limit,
        completion_tokens=1,
    )


async def run_verify_tool_failure_chain(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    e2e_tool_executor: Any,
    working_memory: Any,
    event_id: str,
    fail_tools: frozenset[str] = frozenset({"check_host_isolation_status"}),
    degraded_flags: Any | None = None,
) -> None:
    from app.agents.verify_agent import VerifyAgent
    from app.models.action import Action
    from app.models.agent_io import ResponsePlan, ResponsePlanGeneratedBy, VerifyAgentInput

    event = await event_service.get_event(event_id)
    assert event is not None
    immediate_id = new_action_id()
    deferred_id = new_action_id()
    immediate = Action.model_validate(
        {
            "action_id": immediate_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": f"fp-{immediate_id}",
            "action_category": ActionCategory.RESPONSE.value,
            "action_name": "isolate_host",
            "tool_name": "isolate_host",
            "action_level": ActionLevel.L2.value,
            "execution_owner": ExecutionOwner.XDR_MANAGED.value,
            "execution_phase": ActionExecutionPhase.IMMEDIATE.value,
            "status": ActionStatus.SUCCESS.value,
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY.value,
            "idempotency_key": f"idem-{immediate_id}",
            "target": "host-target-1",
            "parameters": {"target": "host-target-1"},
            "reason": "ISSUE-086 verify degradation",
        }
    )
    deferred = Action.model_validate(
        {
            "action_id": deferred_id,
            "event_id": event_id,
            "plan_revision": 1,
            "action_fingerprint": f"fp-{deferred_id}",
            "action_category": ActionCategory.RESPONSE.value,
            "action_name": "update_source_event_disposition",
            "tool_name": "update_source_event_disposition",
            "action_level": ActionLevel.L2.value,
            "execution_owner": ExecutionOwner.XDR_MANAGED.value,
            "execution_phase": ActionExecutionPhase.POST_VERIFY.value,
            "status": ActionStatus.APPROVED.value,
            "writeback_required": True,
            "writeback_applicable": True,
            "writeback_readiness": WritebackReadiness.READY.value,
            "idempotency_key": f"idem-{deferred_id}",
            "target": "host-target-1",
            "parameters": {"target": "host-target-1"},
            "reason": "ISSUE-086 verify degradation",
            "activation_condition": "after_effect_resolution",
        }
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=immediate.action_id,
                    event_id=event_id,
                    plan_revision=immediate.plan_revision,
                    action_fingerprint=immediate.action_fingerprint,
                    action_category=immediate.action_category,
                    action_name=immediate.action_name,
                    tool_name=immediate.tool_name,
                    action_level=immediate.action_level,
                    execution_phase=immediate.execution_phase,
                    execution_owner=immediate.execution_owner,
                    status=immediate.status,
                    writeback_required=immediate.writeback_required,
                    writeback_applicable=immediate.writeback_applicable,
                    writeback_readiness=immediate.writeback_readiness,
                    idempotency_key=immediate.idempotency_key,
                    target=immediate.target,
                    parameters=immediate.parameters,
                    reason=immediate.reason,
                )
            )
            session.add(
                orm.Action(
                    action_id=deferred.action_id,
                    event_id=event_id,
                    plan_revision=deferred.plan_revision,
                    action_fingerprint=deferred.action_fingerprint,
                    action_category=deferred.action_category,
                    action_name=deferred.action_name,
                    tool_name=deferred.tool_name,
                    action_level=deferred.action_level,
                    execution_phase=deferred.execution_phase,
                    execution_owner=deferred.execution_owner,
                    status=deferred.status,
                    writeback_required=deferred.writeback_required,
                    writeback_applicable=deferred.writeback_applicable,
                    writeback_readiness=deferred.writeback_readiness,
                    idempotency_key=deferred.idempotency_key,
                    target=deferred.target,
                    parameters=deferred.parameters,
                    reason=deferred.reason,
                    activation_condition=deferred.activation_condition,
                )
            )

    flaky = FlakyToolExecutor(e2e_tool_executor, set(fail_tools))
    agent = VerifyAgent(
        tool_executor=flaky,
        working_memory=working_memory.for_writer("VerifyAgent"),
        session_factory=session_factory,
    )
    plan = ResponsePlan(
        plan_id=f"plan-verify-{event_id[-8:]}",
        actions=[immediate, deferred],
        strategy_summary="system verify degradation",
        generated_by=ResponsePlanGeneratedBy.TEMPLATE,
    )
    result = await agent.execute(
        VerifyAgentInput(
            event_id=event_id,
            response_plan=plan,
            verification_phase=VerificationPhase.EFFECT,
        )
    )
    assert result.need_manual_resolution or result.overall_status.value in {
        "failed",
        "partial",
        "waiting",
    }
    verification_ctx = await context_store.get(event_id, "verification_result")
    assert verification_ctx is not None
    if degraded_flags is not None and (
        result.need_manual_resolution
        or result.overall_status.value != VerificationOverallStatus.SUCCESS.value
    ):
        await degraded_flags.set_flag(
            event_id,
            "verify_degraded",
            True,
            writer="InvestigationGraph",
        )


def _low_confidence_risk() -> RiskAssessment:
    return RiskAssessment(
        risk_score=78,
        confidence=0.72,
        severity=Severity.HIGH,
        scoring_mode=ScoringMode.LLM_AND_RULE,
    )


async def run_l3_approval_response_chain(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    context_store: EventContextStore,
    event_service: EventService,
    event_disposition_service: EventDispositionService,
    disposition_sync_service: DispositionSyncService,
    state_machine_service: StateMachineService,
    mock_xdr_state: MockXDRState,
    event_id: str,
) -> None:
    """L3 approval gate → execute → verify journal → terminal disposition."""
    event = await event_service.get_event(event_id)
    assert event is not None
    assert event.status is EventStatus.REPORTING

    source_record_id = await seed_source_object_for_event(session_factory, event)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.PLANNING_RESPONSE.value
            row.confidence = 0.72
            row.final_verdict = FinalVerdict.CONFIRMED_THREAT.value
            row.risk_score = max(int(row.risk_score or 0), 82)
            await append_context_journal_in_session(
                session,
                event_id,
                "risk_assessment",
                {
                    "risk_score": 78,
                    "confidence": 0.72,
                    "severity": Severity.HIGH.value,
                    "scoring_mode": ScoringMode.RULE_ONLY.value,
                },
            )

    l3_action_id = new_action_id()
    ref = SourceReference.model_validate(event.creation_source_ref)
    locator = SourceObjectLocator(
        source_product=ref.source_product,
        source_tenant_id=ref.source_tenant_id,
        connector_id=ref.connector_id,
        source_kind=ref.source_kind,
        source_object_type=ref.source_object_type,
        source_object_id=ref.source_object_id,
    )
    safe_disposition_ref = json.loads(locator.model_dump_json())
    approved_raw = [
        SourceDisposition.CONTAINED.value,
        SourceDisposition.COMPLETED.value,
        SourceDisposition.IGNORED.value,
    ]
    approved_hash = compute_template_hash(
        [SourceDisposition.CONTAINED, SourceDisposition.COMPLETED, SourceDisposition.IGNORED]
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=l3_action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-l3-{event_id[-8:]}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="isolate_host",
                    tool_name="isolate_host",
                    action_level=ActionLevel.L3.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    execution_owner=ExecutionOwner.XDR_MANAGED.value,
                    status=ActionStatus.PENDING.value,
                    writeback_required=True,
                    writeback_applicable=True,
                    writeback_readiness=WritebackReadiness.READY.value,
                    idempotency_key=f"idem-l3-{event_id[-8:]}",
                    target="host-target-1",
                    parameters={"target": "host-target-1"},
                    reason="ISSUE-086 L3 approval chain",
                    approved_operation_template_hash=approved_hash,
                    approved_terminal_dispositions=approved_raw,
                    disposition_source_ref=safe_disposition_ref,
                )
            )

    engine = ApprovalEngine(
        session_factory,
        state_machine=state_machine_service,
        context_store=context_store,
        capability_manifest=build_mock_capability_manifest(),
    )
    async with session_factory() as session:
        l3_row = await session.get(orm.Action, l3_action_id)
        assert l3_row is not None
        l3_action = _action_from_row(l3_row)
    decision = await engine.evaluate(l3_action, _low_confidence_risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    await engine.approve(
        l3_action_id,
        principal=Principal(subject="system-test-approver", roles=["approver"]),
        comment="ISSUE-086 system L3 approval",
        decision_id=None,
    )

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

    await submit_entity_action_once(
        session_factory,
        disposition_sync_service,
        event_id=event_id,
        action_id=l3_action_id,
        mock_xdr_state=mock_xdr_state,
        source_record_id=source_record_id,
    )

    terminal_action_id = await insert_response_action(
        session_factory,
        event_id=event_id,
        action_name="update_source_event_disposition",
        tool_name="update_source_event_disposition",
        execution_phase=ActionExecutionPhase.POST_VERIFY,
        status=ActionStatus.APPROVED,
        disposition_source_ref=safe_disposition_ref,
        activation_condition="after_effect_resolution",
    )

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

    await seed_minimum_disposition_audit(session_factory, event_id)
    result = await event_disposition_service.activate_and_submit(
        event_id,
        plan_revision=1,
        principal_or_system="system-test-l3",
    )
    assert result.activated is True, result.skipped_reason
    assert result.action_id == terminal_action_id


run_insider_l3_approval_response_chain = run_l3_approval_response_chain
