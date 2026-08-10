"""ApprovalEngine tests (ISSUE-058).

Requires Compose PostgreSQL (+ Redis for bus/state tests). Run from ``backend/``:

    pytest tests/test_services/test_approval_engine.py -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.agents.response_agent import build_mock_capability_manifest
from app.core.auth import Principal
from app.core.errors import ApprovalDecisionConflictError, InvalidStateTransitionError
from app.core.event_bus import EventBus
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.models.action import TERMINAL_DISPOSITION_TOOL, Action
from app.models.agent_io import RiskAssessment, ScoringMode
from app.models.approval import ApprovalDecisionKind
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    DispositionPolicy,
    EventStatus,
    EventType,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    SourceObjectKind,
)
from app.models.source import SourceReference
from app.services.approval_engine import (
    SYSTEM_TIMEOUT_OPERATOR,
    ApprovalEngine,
    evaluate_hard_gates,
    evaluate_level_rules,
)
from app.services.context_service import EventContextStore, event_summary_from_security_event
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_audit_log_service import EventAuditLogService
from app.services.state_machine_service import StateMachineService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


class FakeEventBus:
    def __init__(self) -> None:
        self.published: list[tuple[str, str, dict]] = []

    async def publish_event(
        self,
        event_id: str,
        message_type: str,
        payload: dict | None = None,
    ) -> bool:
        self.published.append((event_id, message_type, dict(payload or {})))
        return True


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def _run_migrations() -> None:
    """Alembic env.py reads get_settings().database_url — sync test URL first."""
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")


@pytest.fixture(scope="module")
def migrated() -> None:
    _run_migrations()


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[RedisClient]:
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def store(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> EventContextStore:
    return EventContextStore(redis_client, session_factory)


@pytest_asyncio.fixture
async def fake_bus() -> FakeEventBus:
    return FakeEventBus()


@pytest_asyncio.fixture
async def state_machine(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    redis_client: RedisClient,
) -> StateMachineService:
    bus = EventBus(redis_client)
    audit = EventAuditLogService(session_factory)
    degraded = DegradedFlagService(store, session_factory)
    return StateMachineService(
        session_factory,
        store,
        event_bus=bus,
        audit_log=audit,
        degraded_flags=degraded,
    )


@pytest_asyncio.fixture
async def engine(
    session_factory: async_sessionmaker[AsyncSession],
    fake_bus: FakeEventBus,
    store: EventContextStore,
    state_machine: StateMachineService,
    cleanup: None,
) -> ApprovalEngine:
    return ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        context_store=store,
        capability_manifest=build_mock_capability_manifest(),
    )


@pytest_asyncio.fixture
async def cleanup(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    yield
    async with session_factory() as session:
        async with session.begin():
            for table in (
                ApprovalRecordORM,
                orm.EventAuditLog,
                orm.EventContextJournal,
                orm.EventContextFieldVersion,
                orm.ActionTargetResult,
                orm.ActionExecutionJob,
                orm.DispositionReceipt,
                orm.DispositionOutbox,
                orm.Action,
                orm.Evidence,
                orm.Report,
                orm.SourceEventLink,
                orm.SourceObject,
                orm.SecurityEvent,
            ):
                await session.execute(delete(table))


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _ref(*, kind: SourceObjectKind, object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=kind,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-mock",
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )


def _risk(*, confidence: float = 0.9, severity: Severity = Severity.HIGH) -> RiskAssessment:
    return RiskAssessment(
        risk_score=80,
        severity=severity,
        confidence=confidence,
        scoring_mode=ScoringMode.RULE_ONLY,
    )


def _action_model(**overrides: object) -> Action:
    base = {
        "action_id": f"act-{_sfx()}",
        "event_id": "evt-placeholder",
        "plan_revision": 1,
        "action_fingerprint": f"fp-{_sfx()}",
        "action_category": ActionCategory.RESPONSE,
        "action_name": "block ip",
        "tool_name": "block_ip",
        "action_level": ActionLevel.L4,
        "execution_owner": ExecutionOwner.DIRECT_TOOL,
        "status": ActionStatus.PENDING,
    }
    base.update(overrides)
    return Action.model_validate(base)


async def _create_event(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    *,
    status: EventStatus = EventStatus.PLANNING_RESPONSE,
    disposition_policy: DispositionPolicy = DispositionPolicy.NOT_REQUIRED,
) -> str:
    sfx = _sfx()
    event_id = f"evt-20260723-{sfx}"
    now = datetime.now(UTC)
    ref = _ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}")
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.OTHER.value,
                    title="approval-test",
                    description="",
                    status=status.value,
                    severity=Severity.LOW.value,
                    risk_score=10,
                    confidence=0.5,
                    final_verdict=FinalVerdict.NONE.value,
                    creation_source_ref=ref.model_dump(mode="json"),
                    source_reference_snapshots=[ref.model_dump(mode="json")],
                    disposition_policy=disposition_policy.value,
                    occurred_at=now,
                )
            )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        await store.init_context(event_id, event_summary_from_security_event(row))
    return event_id


async def _insert_action(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
    action: Action,
) -> Action:
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
                    status=action.status.value,
                    execution_owner=(
                        action.execution_owner.value if action.execution_owner else None
                    ),
                    writeback_required=action.writeback_required,
                    writeback_applicable=action.writeback_applicable,
                    writeback_readiness=action.writeback_readiness.value,
                    reason=action.reason,
                    playbook_ref=(
                        action.playbook_ref.model_dump(mode="json")
                        if action.playbook_ref is not None
                        else None
                    ),
                    action_template_snapshot=(
                        action.action_template_snapshot.model_dump(mode="json")
                        if action.action_template_snapshot is not None
                        else None
                    ),
                )
            )
    return action.model_copy(update={"event_id": event_id})


# --------------------------------------------------------------------------- #
# Pure rule tests
# --------------------------------------------------------------------------- #


def test_evaluate_level_rules_l0_auto_approve() -> None:
    action = _action_model(action_level=ActionLevel.L0)
    decision = evaluate_level_rules(action, confidence=0.1, severity=Severity.LOW)
    assert decision.decision is ApprovalDecisionKind.AUTO_APPROVE
    assert decision.rule_applied == "level_l0_l1"


def test_evaluate_level_rules_l1_blocked_when_max_auto_level_l0() -> None:
    action = _action_model(action_level=ActionLevel.L1)
    decision = evaluate_level_rules(
        action,
        confidence=0.99,
        severity=Severity.CRITICAL,
        max_auto_level=ActionLevel.L0,
    )
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == "level_exceeds_auto_cap"


def test_evaluate_level_rules_l0_allowed_when_max_auto_level_l0() -> None:
    action = _action_model(action_level=ActionLevel.L0)
    decision = evaluate_level_rules(
        action,
        confidence=0.99,
        severity=Severity.CRITICAL,
        max_auto_level=ActionLevel.L0,
    )
    assert decision.decision is ApprovalDecisionKind.AUTO_APPROVE
    assert decision.rule_applied == "level_l0_l1"


def test_evaluate_level_rules_l2_always_requires_approval() -> None:
    action = _action_model(action_level=ActionLevel.L2)
    decision = evaluate_level_rules(action, confidence=0.5, severity=Severity.MEDIUM)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL


def test_evaluate_level_rules_l3_high_confidence_requires_approval() -> None:
    # ISSUE-147: L3 no longer auto-approves on high severity + confidence.
    action = _action_model(action_level=ActionLevel.L3)
    decision = evaluate_level_rules(action, confidence=0.9, severity=Severity.HIGH)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == "level_l3_requires_human"


def test_evaluate_level_rules_l2_high_confidence_still_requires_approval() -> None:
    # ISSUE-147: L2 no longer auto-approves on high confidence.
    action = _action_model(action_level=ActionLevel.L2)
    decision = evaluate_level_rules(action, confidence=0.99, severity=Severity.CRITICAL)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == "level_l2_requires_human"


def test_evaluate_level_rules_l4_requires_manual() -> None:
    action = _action_model(action_level=ActionLevel.L4)
    decision = evaluate_level_rules(action, confidence=1.0, severity=Severity.CRITICAL)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == "level_l4_l5_manual"


def test_evaluate_hard_gates_rejects_unknown_tool() -> None:
    manifest = build_mock_capability_manifest(disabled_tools=frozenset({"block_ip"}))
    action = _action_model(tool_name="block_ip")
    gate = evaluate_hard_gates(action, manifest=manifest)
    assert gate is not None
    assert gate.decision is ApprovalDecisionKind.AUTO_REJECT


def test_evaluate_hard_gates_rejects_unsupported_playbook_capability() -> None:
    from app.models.enums import CapabilityState
    from app.models.playbook_release import PlaybookActionTemplateSnapshot, PlaybookRef

    manifest = build_mock_capability_manifest()
    unsupported = manifest.model_copy(update={"entity_response": CapabilityState.UNSUPPORTED})
    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-abcdef012345678",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L2,
        action_name="Block IP",
        required_capabilities=("entity_response",),
        template_hash="c" * 64,
    )
    action = _action_model(
        action_level=ActionLevel.L2,
        playbook_ref=ref,
        action_template_snapshot=snapshot,
    )
    gate = evaluate_hard_gates(action, manifest=unsupported)
    assert gate is not None
    assert gate.decision is ApprovalDecisionKind.AUTO_REJECT
    assert gate.rule_applied == "playbook_capability_unsupported"


def test_manifest_supports_template_capabilities_accepts_mock_manifest() -> None:
    from app.services.playbook_approval_binding import manifest_supports_template_capabilities

    ok, reason = manifest_supports_template_capabilities(
        build_mock_capability_manifest(),
        ("entity_response",),
    )
    assert ok is True
    assert reason is None


# --------------------------------------------------------------------------- #
# Integration tests
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_l0_auto_approve_without_approval_required(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L0),
    )
    decision = await engine.evaluate(action, _risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.AUTO_APPROVE

    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.APPROVED.value

    assert not any(msg_type == "approval_required" for _, msg_type, _ in fake_bus.published)


@pytest.mark.asyncio
async def test_l1_requires_approval_when_auto_response_max_level_l0(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    state_machine: StateMachineService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import Settings

    settings = Settings(
        AUTO_RESPONSE_ENABLED=True,
        AUTO_RESPONSE_MAX_AUTO_LEVEL="L0",
        SOURCE_MODE="mock_xdr",
        TOOL_MODE="mock",
        DISPOSITION_MODE="mock_xdr",
    )
    monkeypatch.setattr("app.services.approval_engine.get_settings", lambda: settings)
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        context_store=store,
        capability_manifest=build_mock_capability_manifest(),
    )
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L1),
    )
    decision = await engine.evaluate(action, _risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL
    assert decision.rule_applied == "level_exceeds_auto_cap"

    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.WAITING_APPROVAL.value


@pytest.mark.asyncio
async def test_auto_approve_record_includes_policy_version(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    engine: ApprovalEngine,
) -> None:
    from app.services.action_approval_policy import APPROVAL_POLICY_SOURCE, APPROVAL_POLICY_VERSION

    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L1),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)

    async with session_factory() as session:
        record = await session.scalar(
            select(ApprovalRecordORM).where(
                ApprovalRecordORM.action_id == action.action_id,
                ApprovalRecordORM.approval_cycle == 0,
            )
        )
    assert record is not None
    detail = record.detail or {}
    assert detail.get("policy_version") == APPROVAL_POLICY_VERSION
    assert detail.get("policy_source") == APPROVAL_POLICY_SOURCE


@pytest.mark.asyncio
async def test_l4_waiting_approval_publishes_once(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    decision = await engine.evaluate(action, _risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.WAITING_APPROVAL.value
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.WAITING_APPROVAL.value

    required = [p for p in fake_bus.published if p[1] == "approval_required"]
    assert len(required) == 1
    assert required[0][2]["action_id"] == action.action_id


@pytest.mark.asyncio
async def test_evaluate_replay_does_not_duplicate_notification(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    await engine.evaluate(action, _risk(), approval_cycle=0)
    required = [p for p in fake_bus.published if p[1] == "approval_required"]
    assert len(required) == 1


@pytest.mark.asyncio
async def test_approve_and_reject_flow(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    await engine.approve(action.action_id, principal, "ok", "dec-1")
    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.APPROVED.value

    updated = [p for p in fake_bus.published if p[1] == "approval_updated"]
    assert updated
    assert updated[-1][2]["decision"] == "approved"


@pytest.mark.asyncio
async def test_approve_non_waiting_returns_400(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            action_level=ActionLevel.L0,
            status=ActionStatus.APPROVED,
        ),
    )
    principal = Principal(subject="approver-1", roles=["approver"])
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        await engine.approve(action.action_id, principal, None, None)
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_decision_id_replay_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
    fake_bus: FakeEventBus,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    first = await engine.approve(action.action_id, principal, "ok", "dec-replay")
    second = await engine.approve(action.action_id, principal, "ok", "dec-replay")
    assert first.persisted_status is ActionStatus.APPROVED
    assert first.idempotent_replay is False
    assert second.persisted_status is ActionStatus.APPROVED
    assert second.idempotent_replay is True
    approval_updates = [item for item in fake_bus.published if item[1] == "approval_updated"]
    assert len(approval_updates) == 1


@pytest.mark.asyncio
async def test_decision_id_reject_replay_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
    fake_bus: FakeEventBus,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    first = await engine.reject(action.action_id, principal, "no", "dec-reject-replay")
    second = await engine.reject(action.action_id, principal, "no", "dec-reject-replay")
    assert first.persisted_status is ActionStatus.REJECTED
    assert second.idempotent_replay is True
    approval_updates = [item for item in fake_bus.published if item[1] == "approval_updated"]
    assert len(approval_updates) == 1


@pytest.mark.asyncio
async def test_decision_id_cross_operation_conflict(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
    fake_bus: FakeEventBus,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    await engine.approve(action.action_id, principal, "ok", "dec-cross")
    with pytest.raises(ApprovalDecisionConflictError) as exc_info:
        await engine.reject(action.action_id, principal, "no", "dec-cross")
    assert "operation or payload mismatch" in str(exc_info.value)
    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.APPROVED.value
    approval_updates = [item for item in fake_bus.published if item[1] == "approval_updated"]
    assert len(approval_updates) == 1


@pytest.mark.asyncio
async def test_decision_id_approve_after_reject_same_key_returns_409(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
    fake_bus: FakeEventBus,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    await engine.reject(action.action_id, principal, "no", "dec-cross-rev")
    with pytest.raises(ApprovalDecisionConflictError) as exc_info:
        await engine.approve(action.action_id, principal, "ok", "dec-cross-rev")
    assert "operation or payload mismatch" in str(exc_info.value)
    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.REJECTED.value
    approval_updates = [item for item in fake_bus.published if item[1] == "approval_updated"]
    assert len(approval_updates) == 1


@pytest.mark.asyncio
async def test_decision_id_replay_after_lifecycle_advance_still_returns_approved(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    first = await engine.approve(action.action_id, principal, "ok", "dec-lifecycle")
    assert first.persisted_status is ActionStatus.APPROVED

    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        row.status = ActionStatus.EXECUTING.value
        await session.commit()

    second = await engine.approve(action.action_id, principal, "ok", "dec-lifecycle")
    assert second.idempotent_replay is True
    assert second.persisted_status is ActionStatus.APPROVED


@pytest.mark.asyncio
async def test_decision_id_replay_skips_hard_gate_when_binding_matches(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            action_level=ActionLevel.L4,
            tool_name="block_ip",
        ),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    first = await engine.approve(action.action_id, principal, "ok", "dec-gate")
    assert first.persisted_status is ActionStatus.APPROVED

    engine._manifest = build_mock_capability_manifest(
        disabled_tools=frozenset({"block_ip"}),
    )
    second = await engine.approve(action.action_id, principal, "ok", "dec-gate")
    assert second.idempotent_replay is True
    assert second.persisted_status is ActionStatus.APPROVED


@pytest.mark.asyncio
async def test_decision_id_payload_mismatch_conflict(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    await engine.approve(action.action_id, principal, "first comment", "dec-payload")
    with pytest.raises(ApprovalDecisionConflictError):
        await engine.approve(action.action_id, principal, "different comment", "dec-payload")
    async with session_factory() as session:
        record = await session.scalar(
            select(ApprovalRecordORM).where(ApprovalRecordORM.action_id == action.action_id)
        )
        assert record is not None
        assert record.comment == "first comment"


@pytest.mark.asyncio
async def test_concurrent_decision_conflict(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    p1 = Principal(subject="approver-a", roles=["approver"])
    p2 = Principal(subject="approver-b", roles=["approver"])
    await engine.approve(action.action_id, p1, "first", "dec-a")
    with pytest.raises(ApprovalDecisionConflictError):
        await engine.reject(action.action_id, p2, "second", "dec-b")


@pytest.mark.asyncio
async def test_timeout_rejects_with_system_timeout(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    async with session_factory() as session:
        async with session.begin():
            record = await session.scalar(
                select(ApprovalRecordORM).where(ApprovalRecordORM.action_id == action.action_id)
            )
            assert record is not None
            record.timeout_at = datetime.now(UTC) - timedelta(minutes=1)
    await engine.handle_timeout(action.action_id, approval_cycle=0)
    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.REJECTED.value
        record = await session.scalar(
            select(ApprovalRecordORM).where(ApprovalRecordORM.action_id == action.action_id)
        )
        assert record is not None
        assert record.operator == SYSTEM_TIMEOUT_OPERATOR
        assert record.decision == ApprovalDecisionKind.AUTO_REJECT.value


@pytest.mark.asyncio
async def test_scan_timeouts_rejects_expired_waiting_approval(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    async with session_factory() as session:
        async with session.begin():
            record = await session.scalar(
                select(ApprovalRecordORM).where(ApprovalRecordORM.action_id == action.action_id)
            )
            assert record is not None
            record.timeout_at = datetime.now(UTC) - timedelta(minutes=1)

    touched: list[str] = []
    async with session_factory() as session:
        async with session.begin():
            touched = await engine._scan_expired_approval_records(session)
    for eid in dict.fromkeys(touched):
        await engine._maybe_advance_plan(eid, await engine._latest_revision(eid))
    assert event_id in touched

    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.REJECTED.value
        record = await session.scalar(
            select(ApprovalRecordORM).where(ApprovalRecordORM.action_id == action.action_id)
        )
        assert record is not None
        assert record.operator == SYSTEM_TIMEOUT_OPERATOR
        assert record.decision == ApprovalDecisionKind.AUTO_REJECT.value


@pytest.mark.asyncio
async def test_l0_without_idempotency_requires_manual(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    manifest = build_mock_capability_manifest().model_copy(
        update={"supports_idempotency": False, "supports_lookup_by_idempotency": False}
    )
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        context_store=store,
        capability_manifest=manifest,
    )
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L0),
    )
    decision = await engine.evaluate(action, _risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.WAITING_APPROVAL.value


@pytest.mark.asyncio
async def test_mixed_l0_l4_stays_waiting_until_l4_decided(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    l0 = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L0, action_name="auto"),
    )
    l4 = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4, action_name="manual"),
    )
    await engine.evaluate(l0, _risk(), approval_cycle=0)
    await engine.evaluate(l4, _risk(), approval_cycle=0)

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.WAITING_APPROVAL.value
        l0_row = await session.get(orm.Action, l0.action_id)
        l4_row = await session.get(orm.Action, l4.action_id)
        assert l0_row is not None and l0_row.status == ActionStatus.APPROVED.value
        assert l4_row is not None and l4_row.status == ActionStatus.WAITING_APPROVAL.value


@pytest.mark.asyncio
async def test_plan_fully_decided_advances_to_executing(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        capability_manifest=build_mock_capability_manifest(),
    )
    event_id = await _create_event(session_factory, store)
    a1 = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L0),
    )
    await engine.evaluate(a1, _risk(), approval_cycle=0)
    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.EXECUTING_RESPONSE.value


@pytest.mark.asyncio
async def test_multiple_l4_single_event_waiting_approval(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    engine: ApprovalEngine,
) -> None:
    event_id = await _create_event(session_factory, store)
    a1 = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4, action_name="a1"),
    )
    a2 = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4, action_name="a2"),
    )
    await engine.evaluate(a1, _risk(), approval_cycle=0)
    await engine.evaluate(a2, _risk(), approval_cycle=0)

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.WAITING_APPROVAL.value

    required = [p for p in fake_bus.published if p[1] == "approval_required"]
    assert len(required) == 2
    assert {p[2]["action_id"] for p in required} == {a1.action_id, a2.action_id}


@pytest.mark.asyncio
async def test_required_deferred_rejected_blocks_executing(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    resume = AsyncMock()
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        resume_investigation=resume,
        capability_manifest=build_mock_capability_manifest(),
    )
    event_id = await _create_event(
        session_factory,
        store,
        disposition_policy=DispositionPolicy.REQUIRED,
    )
    immediate = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L0),
    )
    deferred = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            action_level=ActionLevel.L4,
            tool_name=TERMINAL_DISPOSITION_TOOL,
            execution_phase=ActionExecutionPhase.POST_VERIFY,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            activation_condition="after_effect_resolution",
            writeback_required=True,
        ),
    )
    await engine.evaluate(immediate, _risk(), approval_cycle=0)
    await engine.evaluate(deferred, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    await engine.reject(deferred.action_id, principal, "no writeback", "dec-def")

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.REPORTING.value
    resume.assert_awaited()


@pytest.mark.asyncio
async def test_all_rejected_transitions_to_reporting(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        capability_manifest=build_mock_capability_manifest(),
    )
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    await engine.reject(action.action_id, principal, "declined", "dec-r")
    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.REPORTING.value


@pytest.mark.asyncio
async def test_evaluate_plan_defers_plan_advance_until_all_actions_decided(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        capability_manifest=build_mock_capability_manifest(),
    )
    event_id = await _create_event(session_factory, store)
    l0 = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L0),
    )
    l4 = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    result = await engine.evaluate_plan(event_id, 1, _risk())
    assert result.needs_wait is True
    assert result.evaluated_count == 2
    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.WAITING_APPROVAL.value
        l0_row = await session.get(orm.Action, l0.action_id)
        l4_row = await session.get(orm.Action, l4.action_id)
        assert l0_row is not None and l0_row.status == ActionStatus.APPROVED.value
        assert l4_row is not None and l4_row.status == ActionStatus.WAITING_APPROVAL.value


@pytest.mark.asyncio
async def test_capability_revoked_during_wait_requires_reapproval(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    manifest = build_mock_capability_manifest()
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        capability_manifest=manifest,
    )
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4, tool_name="block_ip"),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    engine._manifest = manifest.model_copy(
        update={
            "allowed_operations": [op for op in manifest.allowed_operations if op != "block_ip"]
        }
    )
    principal = Principal(subject="approver-1", roles=["approver"])
    with pytest.raises(InvalidStateTransitionError, match="re-evaluate"):
        await engine.approve(action.action_id, principal, "ok", "dec-cap-revoked")

    decision = await engine.evaluate(action, _risk(), approval_cycle=1)
    assert decision.decision is ApprovalDecisionKind.AUTO_REJECT
    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.status == ActionStatus.REJECTED.value


@pytest.mark.asyncio
async def test_evaluate_plan_defers_resume_while_graph_active(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    resume = AsyncMock()
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        resume_investigation=resume,
        capability_manifest=build_mock_capability_manifest(),
    )
    event_id = await _create_event(session_factory, store)
    await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L0),
    )
    from app.orchestration.graph_invocation import bind_investigation_graph

    async with bind_investigation_graph(event_id):
        result = await engine.evaluate_plan(event_id, 1, _risk())
    assert result.needs_wait is False
    assert result.resume_deferred is True
    resume.assert_not_awaited()


@pytest.mark.asyncio
async def test_evaluate_plan_resume_hook_called_when_fully_decided(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    resume = AsyncMock()
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        resume_investigation=resume,
        capability_manifest=build_mock_capability_manifest(),
    )
    event_id = await _create_event(session_factory, store)
    await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L0),
    )
    result = await engine.evaluate_plan(event_id, 1, _risk())
    assert result.needs_wait is False
    resume.assert_awaited_once_with(event_id)


@pytest.mark.asyncio
async def test_timeout_all_reject_resume_keeps_reporting_without_full_restart(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-247: system_timeout full reject → REPORTING; resume must not FAILED."""
    from app.models.agent_io import CollectionStatus, EvidenceOutput
    from app.orchestration.graph_resume import resume_investigation_from_checkpoint

    event_id = await _create_event(session_factory, store)
    await store.set(
        event_id,
        "evidence_output",
        EvidenceOutput(collection_status=CollectionStatus.COMPLETED),
    )
    await store.set(event_id, "risk_assessment", _risk())

    report = MagicMock()
    report_agent = MagicMock()
    report_agent.execute = AsyncMock(return_value=report)
    event_service = MagicMock()
    event_service.get_report = AsyncMock(return_value=None)
    agent = MagicMock()
    agent._investigation_graph = None
    agent.report_agent = report_agent
    agent.context_store = store
    agent.event_service = event_service

    execute_mock = AsyncMock()
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.execute_investigation",
        execute_mock,
    )

    async def _resume(eid: str) -> None:
        await resume_investigation_from_checkpoint(
            session_factory,
            eid,
            get_super_agent=AsyncMock(return_value=agent),
            get_workflow_runtime=AsyncMock(return_value=MagicMock()),
        )

    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        context_store=store,
        resume_investigation=_resume,
        capability_manifest=build_mock_capability_manifest(),
    )
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L4),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    async with session_factory() as session:
        async with session.begin():
            record = await session.scalar(
                select(ApprovalRecordORM).where(ApprovalRecordORM.action_id == action.action_id)
            )
            assert record is not None
            record.timeout_at = datetime.now(UTC) - timedelta(minutes=1)

    await engine.handle_timeout(action.action_id, approval_cycle=0)

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.REPORTING.value
        assert "triaging" not in (event.degraded_flags or [])
        assert not any(
            str(flag).startswith("graph_resume_failed=invalid_state_transition")
            for flag in (event.degraded_flags or [])
        )

    execute_mock.assert_not_awaited()
    report_agent.execute.assert_awaited_once()
    assert await store.get(event_id, "report_generated") is True
    # ISSUE-206: REPORTING remains in the on-demand report generation allow-list.
    from app.api.v1.events import REPORT_GENERATION_ALLOWED_STATUSES

    assert EventStatus.REPORTING in REPORT_GENERATION_ALLOWED_STATUSES


@pytest.mark.asyncio
async def test_approve_resume_still_targets_executing_response(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    state_machine: StateMachineService,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    """ISSUE-247 regression: partial/full approve path still advances to execute."""
    resume = AsyncMock()
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        resume_investigation=resume,
        capability_manifest=build_mock_capability_manifest(),
    )
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(event_id=event_id, action_level=ActionLevel.L2),
    )
    await engine.evaluate(action, _risk(), approval_cycle=0)
    principal = Principal(subject="approver-1", roles=["approver"])
    await engine.approve(action.action_id, principal, "approved", "dec-approve-247")

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        assert event is not None
        assert event.status == EventStatus.EXECUTING_RESPONSE.value
    resume.assert_awaited_once_with(event_id)


# --------------------------------------------------------------------------- #
# ISSUE-079: ImpactAssessment integration with ApprovalEngine
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture
async def impact_assessment_service() -> Any:
    """ImpactAssessmentService with a mock asset provider (ISSUE-079)."""
    from app.services.impact_assessment_service import ImpactAssessmentService

    mock_provider = AsyncMock(
        return_value={
            "asset_value": "critical",
            "business_role": "domain_controller",
            "hostname": "DC-01",
        }
    )
    return ImpactAssessmentService(asset_info_provider=mock_provider)


@pytest_asyncio.fixture
async def engine_with_impact(
    session_factory: async_sessionmaker[AsyncSession],
    fake_bus: FakeEventBus,
    store: EventContextStore,
    state_machine: StateMachineService,
    impact_assessment_service: Any,
    cleanup: None,
) -> ApprovalEngine:
    """ApprovalEngine wired with ImpactAssessmentService (ISSUE-079)."""
    return ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        context_store=store,
        capability_manifest=build_mock_capability_manifest(),
        impact_assessment_service=impact_assessment_service,
    )


@pytest.mark.asyncio
async def test_l4_evaluate_stores_impact_assessment_in_record_detail(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine_with_impact: ApprovalEngine,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    """L4 evaluate → approval_record.detail["impact_assessment"] is non-null."""
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            action_level=ActionLevel.L4,
            tool_name="isolate_host",
            target="10.0.0.1",
        ),
    )
    await engine_with_impact.evaluate(action, _risk(), approval_cycle=0)

    async with session_factory() as session:
        record = await session.scalar(
            select(ApprovalRecordORM).where(
                ApprovalRecordORM.action_id == action.action_id,
                ApprovalRecordORM.approval_cycle == 0,
            )
        )
        assert record is not None
        detail = record.detail or {}
        ia = detail.get("impact_assessment")
        assert ia is not None, f"impact_assessment missing from detail: {detail}"
        assert ia.get("action_id") == action.action_id
        assert ia.get("impact_score", 0) > 0
        assert ia.get("business_disruption") == "high"


@pytest.mark.asyncio
async def test_approval_required_payload_includes_impact_assessment(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine_with_impact: ApprovalEngine,
    fake_bus: FakeEventBus,
    cleanup: None,
) -> None:
    """approval_required Socket event payload carries impact_assessment."""
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            action_level=ActionLevel.L4,
            tool_name="isolate_host",
            target="10.0.0.1",
        ),
    )
    await engine_with_impact.evaluate(action, _risk(), approval_cycle=0)

    # Find the approval_required event in the fake bus.
    approval_events = [
        (eid, mtype, payload)
        for (eid, mtype, payload) in fake_bus.published
        if mtype == "approval_required"
    ]
    assert len(approval_events) >= 1, f"No approval_required published; got {fake_bus.published}"
    _, _, payload = approval_events[0]
    assert "impact_assessment" in payload, f"payload missing impact_assessment: {payload}"
    ia = payload["impact_assessment"]
    assert ia is not None
    assert ia.get("action_id") == action.action_id


@pytest.mark.asyncio
async def test_impact_assessment_persisted_to_action_row(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine_with_impact: ApprovalEngine,
    cleanup: None,
) -> None:
    """Action row in DB has impact_assessment JSONB after L4 evaluate."""
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            action_level=ActionLevel.L4,
            tool_name="isolate_host",
            target="10.0.0.1",
        ),
    )
    await engine_with_impact.evaluate(action, _risk(), approval_cycle=0)

    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        assert row.impact_assessment is not None, "impact_assessment not persisted to action row"
        assert row.impact_assessment.get("action_id") == action.action_id
        assert row.impact_assessment.get("impact_score", 0) > 0


@pytest.mark.asyncio
async def test_impact_assessments_written_to_event_context(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine_with_impact: ApprovalEngine,
    cleanup: None,
) -> None:
    """After evaluate, EventContext.impact_assessments contains the assessment."""
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            action_level=ActionLevel.L4,
            tool_name="isolate_host",
            target="10.0.0.1",
        ),
    )
    await engine_with_impact.evaluate(action, _risk(), approval_cycle=0)

    ctx = await store.rebuild_context(event_id)
    assessments = ctx.impact_assessments
    assert len(assessments) >= 1, (
        f"impact_assessments empty in context: {ctx.model_dump(mode='json')}"
    )
    assert any(a.action_id == action.action_id for a in assessments), (
        f"action_id {action.action_id} not in impact_assessments"
    )


@pytest.mark.asyncio
async def test_impact_assessment_degraded_when_no_provider(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    fake_bus: FakeEventBus,
    state_machine: StateMachineService,
    cleanup: None,
) -> None:
    """Without impact_assessment_service, evaluation still completes (degraded)."""
    engine = ApprovalEngine(
        session_factory,
        event_bus=fake_bus,  # type: ignore[arg-type]
        state_machine=state_machine,
        context_store=store,
        capability_manifest=build_mock_capability_manifest(),
        # No impact_assessment_service — degraded path.
    )
    event_id = await _create_event(session_factory, store)
    action = await _insert_action(
        session_factory,
        event_id,
        _action_model(
            event_id=event_id,
            action_level=ActionLevel.L4,
            tool_name="isolate_host",
            target="10.0.0.1",
        ),
    )
    # Should not raise — degraded path swallows the missing service.
    decision = await engine.evaluate(action, _risk(), approval_cycle=0)
    assert decision.decision is ApprovalDecisionKind.REQUIRE_APPROVAL

    async with session_factory() as session:
        row = await session.get(orm.Action, action.action_id)
        assert row is not None
        # No impact_assessment persisted (service not injected).
        assert row.impact_assessment is None


@pytest.mark.asyncio
async def test_approve_rejects_stale_playbook_binding(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    engine: ApprovalEngine,
) -> None:
    from app.core.errors import ValidationError as ShadowValidationError
    from app.models.playbook_release import PlaybookActionTemplateSnapshot, PlaybookRef

    event_id = await _create_event(session_factory, store)
    ref = PlaybookRef(
        playbook_id="pb-a1b2c3d4",
        release_id="krel-abcdef012345678",
        release_version="v1",
        content_hash="a" * 64,
        bundle_content_hash="b" * 64,
    )
    snapshot = PlaybookActionTemplateSnapshot(
        step_order=1,
        tool_name="block_ip",
        action_level=ActionLevel.L4,
        action_name="Block IP",
        required_capabilities=("entity_response",),
        template_hash="c" * 64,
    )
    action = _action_model(
        event_id=event_id,
        action_level=ActionLevel.L4,
        playbook_ref=ref,
        action_template_snapshot=snapshot,
    )
    await _insert_action(session_factory, event_id, action)
    await engine.evaluate(action, _risk(), approval_cycle=0)

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.Action, action.action_id)
            assert row is not None
            row.action_fingerprint = "fp-stale-after-approval-eval"
            await session.flush()

    principal = Principal(subject="approver-1", roles=["approver"])
    with pytest.raises(ShadowValidationError, match="fingerprint changed"):
        await engine.approve(action.action_id, principal, "ok", "dec-playbook-stale")
