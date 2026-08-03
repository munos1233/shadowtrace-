"""Investigation intent durable ledger tests (ISSUE-108 / #612)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.db import models as orm
from app.models.enums import EventStatus, InvestigationIntentStatus, Severity, SourceObjectKind
from app.models.investigation_intent import (
    PRIMARY_LINK_ROLE,
    PROVISIONAL_LINK_ROLE,
    IntentDeliveryAdmission,
    InvestigationIntentTransitionError,
    validate_intent_transition,
)
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.auto_response_policy import AutoResponsePolicyService
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.investigation_intent_service import (
    InvestigationIntentService,
    deterministic_investigation_task_id,
)


@pytest.fixture(autouse=True)
def _suppress_background_intent_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    if request.node.name == "test_reconcile_stale_schedules_dispatch":
        return
    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        lambda: None,
    )


def test_intent_transition_validation() -> None:
    validate_intent_transition(
        InvestigationIntentStatus.PENDING,
        InvestigationIntentStatus.CLAIMED,
    )
    validate_intent_transition(
        InvestigationIntentStatus.CLAIMED,
        InvestigationIntentStatus.SKIPPED,
    )
    validate_intent_transition(
        InvestigationIntentStatus.ENQUEUED,
        InvestigationIntentStatus.DEAD,
    )
    validate_intent_transition(
        InvestigationIntentStatus.PENDING,
        InvestigationIntentStatus.SKIPPED,
    )
    validate_intent_transition(
        InvestigationIntentStatus.RETRY,
        InvestigationIntentStatus.SKIPPED,
    )
    with pytest.raises(InvestigationIntentTransitionError):
        validate_intent_transition(
            InvestigationIntentStatus.PENDING,
            InvestigationIntentStatus.TERMINAL,
        )


def test_deterministic_task_id_stable() -> None:
    first = deterministic_investigation_task_id("iin-abc", 2)
    second = deterministic_investigation_task_id("iin-abc", 2)
    third = deterministic_investigation_task_id("iin-abc", 3)
    assert first == second
    assert first != third


@pytest.mark.asyncio
async def test_create_pending_intent_in_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-intent-create-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            intent_id = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
            assert intent_id is not None
    async with session_factory() as session:
        row = await session.scalar(
            select(orm.InvestigationIntent).where(orm.InvestigationIntent.intent_id == intent_id)
        )
        assert row is not None
        assert row.status == InvestigationIntentStatus.PENDING.value
        assert row.event_id == event_id


@pytest.mark.asyncio
async def test_lookup_active_for_event_returns_matching_intent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-intent-lookup-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            intent_id = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
            assert intent_id is not None

    found = await service.lookup_active_for_event(event_id)
    assert found is not None
    assert found.intent_id == intent_id
    assert found.event_id == event_id

    missing = await service.lookup_active_for_event(f"evt-missing-{uuid4().hex[:8]}")
    assert missing is None


@pytest.mark.asyncio
async def test_duplicate_intent_unique_by_event(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-intent-dup-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            first = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
            second = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
            assert first is not None
            assert second is None


@pytest.mark.asyncio
async def test_mark_started_and_terminal(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-intent-terminal-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            intent_id = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
    assert intent_id is not None
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.InvestigationIntent, intent_id)
            assert row is not None
            row.status = InvestigationIntentStatus.ENQUEUED.value
            row.broker_task_id = "task-123"
    await service.mark_started(intent_id, broker_task_id="task-123")
    await service.mark_terminal(intent_id)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.TERMINAL.value


@pytest.mark.asyncio
async def test_reconcile_stale_enqueued_to_retry(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-stale-{uuid4().hex[:8]}"
    event_id = f"evt-intent-stale-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event.event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-stale",
                    updated_at=datetime.now(UTC) - timedelta(minutes=10),
                )
            )
    await service.reconcile_stale(limit=100)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value


@pytest.mark.asyncio
async def test_mark_started_is_idempotent_for_same_broker_task(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-idem-{uuid4().hex[:8]}"
    event_id = f"evt-idem-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-idem",
                )
            )
    await service.mark_started(intent_id, broker_task_id="task-idem")
    again = await service.mark_started(intent_id, broker_task_id="task-idem")
    assert again is IntentDeliveryAdmission.ACCEPTED
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.STARTED.value


@pytest.mark.asyncio
async def test_create_pending_intent_never_sets_include_response_execution(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-no-response-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            event = orm.SecurityEvent(
                event_id=event_id,
                event_type="malicious_process",
                title="Suspicious process",
                description="",
                status=EventStatus.NEW.value,
                severity=Severity.HIGH.value,
                final_verdict="none",
                creation_source_ref={"source_product": "mock_xdr"},
                source_reference_snapshots=[],
                disposition_policy="not_required",
                raw_alert_ids=[],
                source_type="mock_xdr",
            )
            session.add(event)
            await session.flush()
            intent_id = await service.maybe_create_pending_in_session(
                session,
                event,
                link_role="primary",
                source_product="mock_xdr",
                created_or_promoted=True,
            )
    assert intent_id is not None
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.include_response_execution is False


@pytest.mark.asyncio
async def test_reconcile_stale_started_event_new_goes_retry(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-started-{uuid4().hex[:8]}"
    event_id = f"evt-started-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.STARTED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-started",
                    updated_at=datetime.now(UTC) - timedelta(minutes=15),
                )
            )
    await service.reconcile_stale(limit=100)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value
        assert row.broker_task_id is None


@pytest.mark.asyncio
async def test_reconcile_stale_started_event_triaging_goes_terminal(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-triage-{uuid4().hex[:8]}"
    event_id = f"evt-triage-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.TRIAGING.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.STARTED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-triage",
                    updated_at=datetime.now(UTC) - timedelta(minutes=15),
                )
            )
    await service.reconcile_stale(limit=100)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.TERMINAL.value


@pytest.mark.asyncio
async def test_publish_failure_marks_retry(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kombu.exceptions import OperationalError

    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-pubfail-{uuid4().hex[:8]}"
    event_id = f"evt-pubfail-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )

    def _boom(**kwargs: object) -> None:
        raise OperationalError("broker unavailable")

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is False
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value
        assert row.last_error is not None


@pytest.mark.asyncio
async def test_publish_skips_when_event_not_new(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-skip-{uuid4().hex[:8]}"
    event_id = f"evt-skip-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )
    async with session_factory() as session:
        async with session.begin():
            event = await session.get(orm.SecurityEvent, event_id)
            assert event is not None
            event.status = EventStatus.TRIAGING.value

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        lambda **_kwargs: None,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is False
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.SKIPPED.value
        assert row.skip_reason == "event_not_new"


@pytest.mark.asyncio
async def test_reconcile_stale_enqueued_max_attempts_goes_dead(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
        AUTO_INVESTIGATE_MAX_ATTEMPTS=1,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-dead-enq-{uuid4().hex[:8]}"
    event_id = f"evt-dead-enq-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-dead-enq",
                    updated_at=datetime.now(UTC) - timedelta(minutes=10),
                )
            )
    await service.reconcile_stale(limit=100)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_materialize_is_idempotent_when_intent_exists(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
) -> None:
    """Provisional rows with an existing intent must not consume materialize batch slots."""
    from app.models.enums import EventType, SourceObjectKind
    from app.models.source import SourceReference
    from app.services.context_service import EventContextStore
    from app.services.degraded_flag_service import DegradedFlagService
    from app.services.event_service import EventService, IngestableSource

    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_PROVISIONAL_WINDOW_S=60,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=service,
    )
    ref = SourceReference(
        source_kind=SourceObjectKind.ALERT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=f"al-mat-idem-{uuid4().hex[:8]}",
        source_updated_at=datetime.now(UTC),
    )
    source = IngestableSource(
        reference=ref,
        title="Suspicious alert",
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        normalized={"risk_score": 76},
    )
    result = await events.ingest_source_object(source)
    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, result.event_id)
        assert event is not None
        event.created_at = datetime.now(UTC) - timedelta(minutes=10)
        await session.commit()
    first = await service._materialize_provisional_intents(limit=5)
    assert first >= 1
    second = await service._materialize_provisional_intents(limit=5)
    assert second == 0


@pytest.mark.asyncio
async def test_mark_started_accepts_current_revision_task_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-rev-{uuid4().hex[:8]}"
    event_id = f"evt-rev-{uuid4().hex[:8]}"
    revision = 3
    current_task = deterministic_investigation_task_id(intent_id, revision)
    stale_task = deterministic_investigation_task_id(intent_id, revision - 1)
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.STARTED.value,
                    revision=revision,
                    attempt=1,
                    broker_task_id=stale_task,
                )
            )
    await service.mark_started(intent_id, broker_task_id=current_task)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.broker_task_id == current_task


def test_beat_schedule_excludes_auto_investigate_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "false")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    schedule = _build_beat_schedule()
    assert "shadowtrace-dispatch-investigation-intents" not in schedule
    assert "shadowtrace-reconcile-investigation-intents" not in schedule
    get_settings.cache_clear()


def test_beat_schedule_includes_auto_investigate_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings

    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "true")
    monkeypatch.setenv("AUTO_INVESTIGATE_DISPATCH_INTERVAL_S", "20")
    monkeypatch.setenv("AUTO_INVESTIGATE_RECONCILE_INTERVAL_S", "90")
    get_settings.cache_clear()
    from app.core.celery_app import _build_beat_schedule

    schedule = _build_beat_schedule()
    assert schedule["shadowtrace-dispatch-investigation-intents"]["schedule"] == 20.0
    assert schedule["shadowtrace-reconcile-investigation-intents"]["schedule"] == 90.0
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_mark_started_returns_stale_for_superseded_enqueued_task(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-stale-enq-{uuid4().hex[:8]}"
    event_id = f"evt-stale-enq-{uuid4().hex[:8]}"
    current_task = "task-current"
    stale_task = "task-stale"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id=current_task,
                )
            )
    admission = await service.mark_started(intent_id, broker_task_id=stale_task)
    assert admission is IntentDeliveryAdmission.STALE_SUPERSEDED
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.ENQUEUED.value
        assert row.broker_task_id == current_task


@pytest.mark.asyncio
async def test_mark_started_returns_stale_for_retry_state_without_dead(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-retry-{uuid4().hex[:8]}"
    event_id = f"evt-retry-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.RETRY.value,
                    revision=2,
                    attempt=1,
                )
            )
    admission = await service.mark_started(intent_id, broker_task_id="task-old")
    assert admission is IntentDeliveryAdmission.STALE_SUPERSEDED
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.RETRY.value


@pytest.mark.asyncio
async def test_publish_claimed_intent_success(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-success-{uuid4().hex[:8]}"
    event_id = f"evt-success-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        lambda **kwargs: None,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is True
    expected_task = deterministic_investigation_task_id(intent_id, 1)
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.ENQUEUED.value
        assert row.broker_task_id == expected_task


@pytest.mark.asyncio
async def test_publish_commits_enqueued_before_broker_publish(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-precommit-{uuid4().hex[:8]}"
    event_id = f"evt-precommit-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )

    observed: list[str] = []

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    real_commit = service._commit_enqueued_publish_target

    async def _tracked_commit(intent_id: str):
        target = await real_commit(intent_id)
        if target is not None:
            observed.append("enqueued")
        return target

    monkeypatch.setattr(service, "_commit_enqueued_publish_target", _tracked_commit)

    def _apply_async(**_kwargs: object) -> None:
        observed.append("publish")
        return None

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _apply_async,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is True
    assert observed == ["enqueued", "publish"]


@pytest.mark.asyncio
async def test_reconcile_stale_schedules_dispatch(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=5,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-dispatch-{uuid4().hex[:8]}"
    event_id = f"evt-dispatch-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.ENQUEUED.value,
                    revision=1,
                    attempt=0,
                    broker_task_id="task-dispatch",
                    updated_at=datetime.now(UTC) - timedelta(minutes=10),
                )
            )
    calls: list[str] = []

    def _delay() -> None:
        calls.append("dispatch")

    monkeypatch.setattr(
        "app.tasks.investigation_intent_tasks.dispatch_pending_investigation_intents.delay",
        _delay,
    )
    assert await service.reconcile_stale(limit=5) >= 1
    assert calls == ["dispatch"]


@pytest.mark.asyncio
async def test_publish_unexpected_error_marks_dead(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        AUTO_INVESTIGATE_ENABLED=True,
        SOURCE_MODE="mock_xdr",
        AUTO_INVESTIGATE_CLAIM_LEASE_S=30,
    )
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-unexpected-{uuid4().hex[:8]}"
    event_id = f"evt-unexpected-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    claim_owner="test",
                )
            )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _boom(**_kwargs: object) -> None:
        raise ValueError("unexpected publish bug")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )
    published = await service._publish_claimed_intent(intent_id)
    assert published is False
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.DEAD.value


@pytest.mark.asyncio
async def test_skip_active_intents_for_event_in_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(AUTO_INVESTIGATE_ENABLED=True, SOURCE_MODE="mock_xdr")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        settings=settings,
    )
    event_id = f"evt-skip-active-{uuid4().hex[:8]}"
    intent_id = f"iin-skip-active-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                )
            )
            await session.flush()
            skipped = await service.skip_active_intents_for_event_in_session(
                session,
                event_id,
                reason="event_merged",
            )
            assert skipped == 1
    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.status == InvestigationIntentStatus.SKIPPED.value
        assert row.skip_reason == "event_merged"


def _auto_response_settings(**overrides: object) -> Settings:
    base = {
        "AUTO_INVESTIGATE_ENABLED": True,
        "AUTO_RESPONSE_ENABLED": True,
        "SOURCE_MODE": "mock_xdr",
        "TOOL_MODE": "mock",
        "DISPOSITION_MODE": "mock_xdr",
    }
    base.update(overrides)
    return Settings(**base)


async def _seed_primary_source_link(
    session: AsyncSession,
    *,
    event_id: str,
    connector_id: str = "conn-mock",
) -> str:
    source_record_id = f"src-primary-{uuid4().hex[:8]}"
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
            source_object_id=f"INC-{uuid4().hex[:8]}",
            next_outbox_sequence=0,
        )
    )
    await session.flush()
    session.add(
        orm.SourceEventLink(
            source_record_id=source_record_id,
            event_id=event_id,
            role=PRIMARY_LINK_ROLE,
        )
    )
    return source_record_id


@pytest.mark.asyncio
async def test_commit_enqueued_sets_include_response_when_policy_matches(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-response-{uuid4().hex[:8]}"
    event_id = f"evt-response-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    target = await service._commit_enqueued_publish_target(intent_id)
    assert target is not None
    assert target.include_response_execution is True

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.include_response_execution is True
        audit = (
            await session.scalars(
                select(orm.EventAuditLog).where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.operator == "AutoResponsePolicyService",
                )
            )
        ).all()
    assert len(audit) == 1
    assert audit[0].reason == "auto_response:policy_match"


@pytest.mark.asyncio
async def test_commit_enqueued_skips_response_for_provisional_link(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-prov-{uuid4().hex[:8]}"
    event_id = f"evt-prov-{uuid4().hex[:8]}"
    source_record_id = f"src-prov-{uuid4().hex[:8]}"
    connector_id = "conn-mock"
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
                    source_object_id=f"INC-{uuid4().hex[:8]}",
                    next_outbox_sequence=0,
                )
            )
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            session.add(
                orm.SourceEventLink(
                    source_record_id=source_record_id,
                    event_id=event_id,
                    role=PROVISIONAL_LINK_ROLE,
                )
            )
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    target = await service._commit_enqueued_publish_target(intent_id)
    assert target is not None
    assert target.include_response_execution is False

    async with session_factory() as session:
        row = await session.get(orm.InvestigationIntent, intent_id)
        assert row is not None
        assert row.include_response_execution is False


@pytest.mark.asyncio
async def test_publish_forwards_include_response_execution_flag(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-publish-{uuid4().hex[:8]}"
    event_id = f"evt-publish-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    captured: dict[str, object] = {}

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _apply_async(**kwargs: object) -> None:
        captured["kwargs"] = kwargs.get("kwargs")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _apply_async,
    )

    published = await service._publish_claimed_intent(intent_id)
    assert published is True
    assert captured["kwargs"] == {
        "include_response_execution": True,
        "intent_id": intent_id,
    }


@pytest.mark.asyncio
async def test_auto_response_broker_failure_sets_degraded_flag(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    intent_id = f"iin-degraded-{uuid4().hex[:8]}"
    event_id = f"evt-degraded-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                    claim_expires_at=datetime.now(UTC) + timedelta(minutes=5),
                )
            )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _boom(**_kwargs: object) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )

    published = await service._publish_claimed_intent(intent_id)
    assert published is False

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
    assert event is not None
    assert any(
        flag.startswith("auto_response_dispatch_unavailable=") for flag in event.degraded_flags
    )


@pytest.mark.asyncio
async def test_commit_enqueued_skips_response_without_source_link(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-nolink-{uuid4().hex[:8]}"
    event_id = f"evt-nolink-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    target = await service._commit_enqueued_publish_target(intent_id)
    assert target is not None
    assert target.include_response_execution is False

    async with session_factory() as session:
        audit = (
            await session.scalars(
                select(orm.EventAuditLog).where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.operator == "AutoResponsePolicyService",
                )
            )
        ).all()
    assert len(audit) == 1
    assert audit[0].reason == "auto_response:skipped_link_role_not_primary"


@pytest.mark.asyncio
async def test_commit_enqueued_audit_logs_policy_skip_reason(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = _auto_response_settings(AUTO_RESPONSE_MIN_SEVERITY="critical")
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        settings=settings,
    )
    intent_id = f"iin-skip-{uuid4().hex[:8]}"
    event_id = f"evt-skip-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                )
            )

    target = await service._commit_enqueued_publish_target(intent_id)
    assert target is not None
    assert target.include_response_execution is False

    async with session_factory() as session:
        audit = (
            await session.scalars(
                select(orm.EventAuditLog).where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.operator == "AutoResponsePolicyService",
                )
            )
        ).all()
    assert len(audit) == 1
    assert audit[0].reason == "auto_response:skipped_below_min_severity"


@pytest.mark.asyncio
async def test_auto_response_unexpected_publish_failure_sets_degraded_flag(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    settings = _auto_response_settings()
    service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(settings),
        auto_response_policy=AutoResponsePolicyService(settings),
        degraded_flags=degraded,
        settings=settings,
    )
    intent_id = f"iin-unexpected-{uuid4().hex[:8]}"
    event_id = f"evt-unexpected-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            await _seed_primary_source_link(session, event_id=event_id)
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.CLAIMED.value,
                    revision=1,
                    attempt=0,
                    include_response_execution=False,
                    claim_owner="test",
                    claim_expires_at=datetime.now(UTC) + timedelta(minutes=5),
                )
            )

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        return None

    def _boom(**_kwargs: object) -> None:
        raise RuntimeError("unexpected publish failure")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.register_task_metadata",
        _noop_register,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )

    published = await service._publish_claimed_intent(intent_id)
    assert published is False

    async with session_factory() as session:
        event = await session.get(orm.SecurityEvent, event_id)
        row = await session.get(orm.InvestigationIntent, intent_id)
    assert event is not None
    assert row is not None
    assert row.status == InvestigationIntentStatus.DEAD.value
    assert any(
        flag.startswith("auto_response_dispatch_unavailable=") for flag in event.degraded_flags
    )
