"""EventService tests against Compose PostgreSQL + Redis (ISSUE-015)."""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import (
    DependencyUnavailableError,
    InvalidStateTransitionError,
    InvalidVerdictStatusCombinationError,
    ValidationError,
)
from app.core.event_bus import EventBus
from app.core.redis_client import RedisClient
from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.source import SourceReference
from app.models.workflow import TransitionContext
from app.services.context_service import EventContextStore, ctx_key
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService, IngestableSource
from app.services.source_policy_resolver import SourcePolicyResolver

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(migrated: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
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
async def event_service(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    redis_client: RedisClient,
) -> EventService:
    degraded = DegradedFlagService(store, session_factory)
    bus = EventBus(redis_client)
    return EventService(
        session_factory,
        store,
        event_bus=bus,
        degraded_flags=degraded,
        policy_resolver=SourcePolicyResolver(),
    )


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _ref(
    *,
    kind: SourceObjectKind,
    object_id: str,
    connector_id: str = "conn-mock",
    product: str = "mock_xdr",
) -> SourceReference:
    return SourceReference(
        source_kind=kind,
        source_product=product,
        source_tenant_id="tenant-1",
        connector_id=connector_id,
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )


# --------------------------------------------------------------------------- #
# Create / idempotency / associations
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_ingest_creates_event_pg_redis_audit(
    event_service: EventService,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> None:
    sfx = _sfx()
    result = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}"),
            title="incident-create",
            event_type=EventType.INSIDER_THREAT,
            severity=Severity.HIGH,
            source_type="mock_xdr",
        )
    )
    assert result.accepted and result.created and result.event_id
    event_id = result.event_id

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.status == EventStatus.NEW.value
        assert row.final_verdict == FinalVerdict.NONE.value
        assert row.disposition_policy == DispositionPolicy.REQUIRED.value
        audits = (
            await session.scalars(
                select(orm.EventAuditLog).where(orm.EventAuditLog.event_id == event_id)
            )
        ).all()
        assert any(a.reason == "event_created" for a in audits)

    raw = await redis_client.get_client().hget(ctx_key(event_id), "event")
    assert raw is not None
    ctx_event = await store.get(event_id, "event")
    assert ctx_event["event_id"] == event_id
    assert ctx_event["status"] == "new"


@pytest.mark.asyncio
async def test_ingest_same_source_is_idempotent(event_service: EventService) -> None:
    sfx = _sfx()
    src = IngestableSource(
        reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}"),
        title="idem",
        source_type="mock_xdr",
    )
    first = await event_service.ingest_source_object(src)
    second = await event_service.ingest_source_object(src)
    assert first.event_id == second.event_id
    assert second.idempotent is True
    assert second.created is False


@pytest.mark.asyncio
async def test_concurrent_same_source_is_idempotent(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    src = IngestableSource(
        reference=_ref(
            kind=SourceObjectKind.INCIDENT,
            object_id=f"INC-concurrent-{sfx}",
            connector_id=f"conn-concurrent-{sfx}",
        ),
        title="concurrent-idempotency",
        source_type="mock_xdr",
    )
    first, second = await asyncio.gather(
        event_service.ingest_source_object(src),
        event_service.ingest_source_object(src),
    )
    assert first.event_id == second.event_id
    assert sum(result.created for result in (first, second)) == 1
    assert sum(result.idempotent for result in (first, second)) == 1
    assert first.event_id
    async with session_factory() as session:
        journals = (
            await session.scalars(
                select(orm.EventContextJournal).where(
                    orm.EventContextJournal.event_id == first.event_id,
                    orm.EventContextJournal.field_name == "event",
                )
            )
        ).all()
        version = await session.get(
            orm.EventContextFieldVersion,
            (first.event_id, "event"),
        )
    assert len(journals) == 1
    assert version is not None and version.current_version == 1


@pytest.mark.asyncio
async def test_idempotent_retry_repairs_missing_context(
    event_service: EventService,
    store: EventContextStore,
    redis_client: RedisClient,
) -> None:
    sfx = _sfx()
    src = IngestableSource(
        reference=_ref(
            kind=SourceObjectKind.INCIDENT,
            object_id=f"INC-repair-{sfx}",
            connector_id=f"conn-repair-{sfx}",
        ),
        source_type="mock_xdr",
    )
    with patch.object(
        store,
        "init_context",
        new_callable=AsyncMock,
        side_effect=RuntimeError("injected context init failure"),
    ):
        with pytest.raises(RuntimeError, match="injected context init failure"):
            await event_service.ingest_source_object(src)

    repaired = await event_service.ingest_source_object(src)
    assert repaired.idempotent is True
    assert repaired.event_id
    assert (await store.get(repaired.event_id, "event"))["event_id"] == repaired.event_id
    assert await redis_client.get_client().hget(ctx_key(repaired.event_id), "event") is not None


@pytest.mark.asyncio
async def test_unconfigured_live_connector_fails_closed(
    event_service: EventService,
) -> None:
    sfx = _sfx()
    with patch(
        "app.services.event_service.get_settings",
        return_value=SimpleNamespace(source_mode="live"),
    ):
        with pytest.raises(ValidationError) as exc_info:
            await event_service.ingest_source_object(
                IngestableSource(
                    reference=_ref(
                        kind=SourceObjectKind.INCIDENT,
                        object_id=f"LIVE-{sfx}",
                        connector_id=f"conn-live-{sfx}",
                        product="live_xdr",
                    ),
                    source_type="live",
                )
            )
    assert exc_info.value.error_code == "adapter_validation_error"


@pytest.mark.asyncio
async def test_unrelated_alerts_stay_independent(event_service: EventService) -> None:
    sfx = _sfx()
    a1 = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.ALERT, object_id=f"AL-{sfx}-1"),
            title="alert-1",
            source_type="mock_xdr",
        )
    )
    a2 = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.ALERT, object_id=f"AL-{sfx}-2"),
            title="alert-2",
            source_type="mock_xdr",
        )
    )
    assert a1.event_id != a2.event_id


@pytest.mark.asyncio
async def test_required_source_without_locator_is_not_ready(
    event_service: EventService,
    store: EventContextStore,
) -> None:
    sfx = _sfx()
    created = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(
                kind=SourceObjectKind.LOG,
                object_id=f"LOG-{sfx}",
                connector_id=f"conn-log-{sfx}",
            ),
            source_type="mock_xdr",
        )
    )
    assert created.event_id
    context_event = await store.get(created.event_id, "event")
    assert context_event["disposition_policy"] == DispositionPolicy.REQUIRED.value
    assert context_event["writeback_readiness"] == WritebackReadiness.SOURCE_UNRESOLVED.value


@pytest.mark.asyncio
async def test_alert_then_incident_promotes_when_no_actions(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    alert_ref = _ref(kind=SourceObjectKind.ALERT, object_id=f"AL-{sfx}")
    incident_ref = _ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}")

    alert = await event_service.ingest_source_object(
        IngestableSource(
            reference=alert_ref,
            title="provisional-alert",
            source_type="mock_xdr",
            incident_ref=None,  # orphan first
        )
    )
    assert alert.created is True
    provisional_id = alert.event_id

    promoted = await event_service.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            title="parent-incident",
            source_type="mock_xdr",
            related_alert_refs=[alert_ref],
        )
    )
    assert promoted.promoted is True
    assert promoted.event_id == provisional_id

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, provisional_id)
        assert row is not None
        assert row.current_primary_source_record_id == promoted.source_record_id
        assert row.disposition_source_ref is not None
        assert row.disposition_source_ref["source_object_id"] == f"INC-{sfx}"
        # creation_source_ref preserved (still the alert)
        assert row.creation_source_ref["source_object_id"] == f"AL-{sfx}"
        snaps = row.source_reference_snapshots or []
        assert any(s["source_object_id"] == f"INC-{sfx}" for s in snaps)


@pytest.mark.asyncio
async def test_duplicate_related_alert_refs_promote_once(
    event_service: EventService,
) -> None:
    sfx = _sfx()
    alert_ref = _ref(kind=SourceObjectKind.ALERT, object_id=f"AL-duplicate-{sfx}")
    incident_ref = _ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-duplicate-{sfx}")
    alert = await event_service.ingest_source_object(
        IngestableSource(reference=alert_ref, source_type="mock_xdr")
    )
    promoted = await event_service.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            source_type="mock_xdr",
            related_alert_refs=[alert_ref, alert_ref],
        )
    )
    assert promoted.promoted is True
    assert promoted.event_id == alert.event_id


@pytest.mark.asyncio
async def test_multiple_pristine_alert_events_merge_into_one_incident_event(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: RedisClient,
) -> None:
    sfx = _sfx()
    connector_id = f"conn-multi-{sfx}"
    first_ref = _ref(
        kind=SourceObjectKind.ALERT,
        object_id=f"AL-multi-{sfx}-1",
        connector_id=connector_id,
    )
    second_ref = _ref(
        kind=SourceObjectKind.ALERT,
        object_id=f"AL-multi-{sfx}-2",
        connector_id=connector_id,
    )
    first = await event_service.ingest_source_object(
        IngestableSource(reference=first_ref, source_type="mock_xdr")
    )
    second = await event_service.ingest_source_object(
        IngestableSource(reference=second_ref, source_type="mock_xdr")
    )
    assert first.event_id and second.event_id and first.event_id != second.event_id

    promoted = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(
                kind=SourceObjectKind.INCIDENT,
                object_id=f"INC-multi-{sfx}",
                connector_id=connector_id,
            ),
            source_type="mock_xdr",
            related_alert_refs=[first_ref, second_ref],
        )
    )
    assert promoted.event_id == first.event_id
    assert await event_service.get_event(second.event_id) is None

    async with session_factory() as session:
        alert_records = (
            await session.scalars(
                select(orm.SourceObject.source_record_id).where(
                    orm.SourceObject.source_object_id.in_(
                        [first_ref.source_object_id, second_ref.source_object_id]
                    )
                )
            )
        ).all()
        linked_event_ids = (
            await session.scalars(
                select(orm.SourceEventLink.event_id).where(
                    orm.SourceEventLink.source_record_id.in_(alert_records)
                )
            )
        ).all()
    assert set(linked_event_ids) == {first.event_id}
    assert await redis_client.get_client().exists(ctx_key(second.event_id)) == 0


@pytest.mark.asyncio
async def test_cross_connector_association_is_rejected(
    event_service: EventService,
) -> None:
    sfx = _sfx()
    with pytest.raises(ValidationError) as exc_info:
        await event_service.ingest_source_object(
            IngestableSource(
                reference=_ref(
                    kind=SourceObjectKind.ALERT,
                    object_id=f"AL-cross-{sfx}",
                    connector_id=f"conn-a-{sfx}",
                ),
                incident_ref=_ref(
                    kind=SourceObjectKind.INCIDENT,
                    object_id=f"INC-cross-{sfx}",
                    connector_id=f"conn-b-{sfx}",
                ),
                source_type="mock_xdr",
            )
        )
    assert exc_info.value.error_code == "adapter_validation_error"


@pytest.mark.asyncio
async def test_promotion_blocked_when_actions_exist_keeps_two_events(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    alert_ref = _ref(kind=SourceObjectKind.ALERT, object_id=f"AL-{sfx}")
    incident_ref = _ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}")

    alert = await event_service.ingest_source_object(
        IngestableSource(reference=alert_ref, title="a", source_type="mock_xdr")
    )
    assert alert.event_id

    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.Action(
                    action_id=f"act-{sfx}",
                    event_id=alert.event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{sfx}",
                    action_category="response",
                    action_name="block_ip",
                    tool_name="block_ip",
                    action_level="l2",
                )
            )

    incident = await event_service.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            title="inc",
            source_type="mock_xdr",
            related_alert_refs=[alert_ref],
        )
    )
    assert incident.created is True
    assert incident.related_only is True
    assert incident.event_id != alert.event_id
    repeated = await event_service.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            title="inc",
            source_type="mock_xdr",
            related_alert_refs=[alert_ref],
        )
    )
    assert repeated.idempotent is True
    assert repeated.event_id == incident.event_id


@pytest.mark.asyncio
async def test_promotion_blocked_when_any_approval_history_exists(
    event_service: EventService,
    store: EventContextStore,
) -> None:
    sfx = _sfx()
    alert_ref = _ref(kind=SourceObjectKind.ALERT, object_id=f"AL-approved-{sfx}")
    incident_ref = _ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-approved-{sfx}")
    alert = await event_service.ingest_source_object(
        IngestableSource(reference=alert_ref, source_type="mock_xdr")
    )
    assert alert.event_id
    # An earlier empty write must not hide a later non-empty approval record.
    await store.set(alert.event_id, "approval_records", [])
    await store.set(
        alert.event_id,
        "approval_records",
        [{"approval_id": f"apr-{sfx}", "decision": "approved"}],
    )

    incident = await event_service.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            source_type="mock_xdr",
            related_alert_refs=[alert_ref],
        )
    )
    assert incident.created is True
    assert incident.related_only is True
    assert incident.event_id != alert.event_id


@pytest.mark.asyncio
async def test_alert_with_verified_incident_ref_merges(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    incident_ref = _ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}")
    alert_ref = _ref(kind=SourceObjectKind.ALERT, object_id=f"AL-{sfx}")

    inc = await event_service.ingest_source_object(
        IngestableSource(
            reference=incident_ref,
            title="inc-first",
            source_type="mock_xdr",
            related_alert_refs=[],
        )
    )
    linked = await event_service.ingest_source_object(
        IngestableSource(
            reference=alert_ref,
            title="alert-later",
            source_type="mock_xdr",
            incident_ref=incident_ref,
        )
    )
    assert linked.event_id == inc.event_id

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, inc.event_id)
        assert row is not None
        assert f"AL-{sfx}" in (row.raw_alert_ids or [])


@pytest.mark.asyncio
async def test_file_create_event_not_required_and_idempotent(
    event_service: EventService,
) -> None:
    raw = {"title": "file-hit", "entity": "user-a", "description": "x"}
    first = await event_service.create_event(raw, source_type="file", title="file-hit")
    second = await event_service.create_event(raw, source_type="file", title="file-hit")
    assert first.event_id == second.event_id
    assert first.disposition_policy is DispositionPolicy.NOT_REQUIRED
    assert first.disposition_source_ref is None
    assert first.status is EventStatus.NEW
    assert first.final_verdict is FinalVerdict.NONE


@pytest.mark.asyncio
async def test_file_dedup_uses_canonical_nested_json(event_service: EventService) -> None:
    first = await event_service.create_event(
        {"entity": "user-json", "nested": {"a": 1, "b": 2}},
        occurred_at=datetime(2026, 7, 13, 8, 0, tzinfo=UTC),
    )
    second = await event_service.create_event(
        {"nested": {"b": 2, "a": 1}, "entity": "user-json"},
        occurred_at=datetime(2026, 7, 13, 8, 5, tzinfo=UTC),
    )
    assert first.event_id == second.event_id


@pytest.mark.asyncio
async def test_concurrent_file_create_is_idempotent(event_service: EventService) -> None:
    sfx = _sfx()
    now = datetime.now(UTC)
    raw = {"entity": f"user-concurrent-{sfx}", "value": 1}
    first, second = await asyncio.gather(
        event_service.create_event(raw, occurred_at=now),
        event_service.create_event(raw, occurred_at=now),
    )
    assert first.event_id == second.event_id


# --------------------------------------------------------------------------- #
# Query / verdict / status boundary
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_events_filters(
    event_service: EventService,
) -> None:
    sfx = _sfx()
    await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}-a"),
            title=f"filter-alpha-{sfx}",
            event_type=EventType.ACCOUNT_ANOMALY,
            severity=Severity.LOW,
            source_type="mock_xdr",
        )
    )
    await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}-b"),
            title=f"filter-beta-{sfx}",
            event_type=EventType.INSIDER_THREAT,
            severity=Severity.HIGH,
            source_type="mock_xdr",
        )
    )
    result = await event_service.list_events(
        event_type=EventType.INSIDER_THREAT,
        severity=Severity.HIGH,
        keyword=f"beta-{sfx}",
        page=1,
        page_size=10,
    )
    assert result.total >= 1
    assert all(i.event_type is EventType.INSIDER_THREAT for i in result.items)
    assert any(sfx in i.title for i in result.items)


@pytest.mark.asyncio
async def test_set_final_verdict_and_reject_illegal(
    event_service: EventService,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    created = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}"),
            title="verdict",
            source_type="mock_xdr",
        )
    )
    assert created.event_id
    # NEW + false_positive is allowed (not in forbidden set).
    updated = await event_service.set_final_verdict(created.event_id, FinalVerdict.FALSE_POSITIVE)
    assert updated.final_verdict is FinalVerdict.FALSE_POSITIVE
    context_event = await store.get(created.event_id, "event")
    assert context_event["final_verdict"] == FinalVerdict.FALSE_POSITIVE.value
    async with session_factory() as session:
        audit = await session.scalar(
            select(orm.EventAuditLog)
            .where(
                orm.EventAuditLog.event_id == created.event_id,
                orm.EventAuditLog.reason.like("final_verdict:%"),
            )
            .order_by(orm.EventAuditLog.id.desc())
        )
        assert audit is not None
        assert audit.from_status == EventStatus.NEW.value
        assert audit.to_status == EventStatus.NEW.value

    # Force status to VERIFYING then reject false_positive without disposition-only.
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, created.event_id)
            assert row is not None
            row.status = EventStatus.VERIFYING.value
            row.final_verdict = FinalVerdict.NONE.value

    with pytest.raises(InvalidVerdictStatusCombinationError):
        await event_service.set_final_verdict(
            created.event_id,
            FinalVerdict.FALSE_POSITIVE,
            context=TransitionContext(disposition_only_intent=False),
        )


@pytest.mark.asyncio
async def test_concurrent_verdict_updates_serialize_versions_and_context(
    event_service: EventService,
    store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    created = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(
                kind=SourceObjectKind.INCIDENT,
                object_id=f"INC-verdict-race-{sfx}",
            ),
            source_type="mock_xdr",
        )
    )
    assert created.event_id
    async with session_factory() as session:
        before = await session.get(orm.SecurityEvent, created.event_id)
        assert before is not None
        initial_version = before.row_version

    first, second = await asyncio.gather(
        event_service.set_final_verdict(
            created.event_id,
            FinalVerdict.CONFIRMED_THREAT,
        ),
        event_service.set_final_verdict(
            created.event_id,
            FinalVerdict.FALSE_POSITIVE,
        ),
    )
    assert {first.final_verdict, second.final_verdict} == {
        FinalVerdict.CONFIRMED_THREAT,
        FinalVerdict.FALSE_POSITIVE,
    }

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, created.event_id)
        audit_count = await session.scalar(
            select(func.count())
            .select_from(orm.EventAuditLog)
            .where(
                orm.EventAuditLog.event_id == created.event_id,
                orm.EventAuditLog.reason.like("final_verdict:%"),
            )
        )
    assert row is not None
    assert row.row_version == initial_version + 2
    assert audit_count == 2
    context_event = await store.get(created.event_id, "event")
    assert context_event["final_verdict"] == row.final_verdict


@pytest.mark.asyncio
async def test_set_final_verdict_rejects_forged_trusted_context(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    created = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-forged-{sfx}"),
            source_type="mock_xdr",
        )
    )
    assert created.event_id
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, created.event_id)
            assert row is not None
            row.status = EventStatus.PLANNING_RESPONSE.value

    with pytest.raises(InvalidVerdictStatusCombinationError):
        await event_service.set_final_verdict(
            created.event_id,
            FinalVerdict.FALSE_POSITIVE,
            context=TransitionContext(
                disposition_only_intent=True,
                response_actions_are_disposition_only=True,
                has_entity_side_effect_actions=False,
            ),
        )
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, created.event_id)
        assert row is not None
        assert row.final_verdict == FinalVerdict.NONE.value


@pytest.mark.asyncio
async def test_no_update_event_status_and_illegal_transition_unchanged(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    assert not hasattr(event_service, "update_event_status")

    sfx = _sfx()
    created = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}"),
            title="status-boundary",
            source_type="mock_xdr",
        )
    )
    assert created.event_id

    with pytest.raises(InvalidStateTransitionError):
        await event_service.transition_status(
            created.event_id,
            EventStatus.CLOSED,  # NEW → CLOSED illegal
        )

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, created.event_id)
        assert row is not None
        assert row.status == EventStatus.NEW.value

    # Legal edge still requires StateMachineService.
    with pytest.raises(DependencyUnavailableError):
        await event_service.transition_status(created.event_id, EventStatus.TRIAGING)


@pytest.mark.asyncio
async def test_redis_init_failure_marks_degraded_flag(
    session_factory: async_sessionmaker[AsyncSession],
    store: EventContextStore,
    redis_client: RedisClient,
) -> None:
    degraded = DegradedFlagService(store, session_factory)
    service = EventService(
        session_factory,
        store,
        event_bus=EventBus(redis_client),
        degraded_flags=degraded,
    )
    sfx = _sfx()

    with patch.object(store, "init_context", new_callable=AsyncMock) as mock_init:
        from app.services.context_service import InitResult

        mock_init.return_value = InitResult(redis_ok=False, version=1)
        with patch("app.services.context_service.asyncio.sleep", new_callable=AsyncMock):
            result = await service.ingest_source_object(
                IngestableSource(
                    reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-{sfx}"),
                    title="redis-down",
                    source_type="mock_xdr",
                )
            )

    assert result.event_id
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, result.event_id)
        assert row is not None
        assert any(
            str(f).startswith("redis_context_unavailable=") for f in (row.degraded_flags or [])
        )


@pytest.mark.asyncio
async def test_live_connector_without_explicit_policy_fails_closed(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """NULL disposition_policy_default must not be treated as explicit not_required."""
    sfx = _sfx()
    cid = f"conn-live-null-{sfx}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=cid,
                    source_product="vendor_x",
                    display_name=cid,
                    disposition_policy_default=None,
                )
            )

    with patch(
        "app.services.event_service.get_settings",
        return_value=SimpleNamespace(source_mode="live"),
    ):
        with pytest.raises(ValidationError) as exc_info:
            await event_service.ingest_source_object(
                IngestableSource(
                    reference=_ref(
                        kind=SourceObjectKind.ALERT,
                        object_id=f"LIVE-NULL-{sfx}",
                        connector_id=cid,
                        product="vendor_x",
                    ),
                    source_type="live",
                )
            )
    assert exc_info.value.error_code == "adapter_validation_error"


@pytest.mark.asyncio
async def test_live_connector_with_explicit_not_required_allowed(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    cid = f"conn-live-explicit-{sfx}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SourceConnector(
                    connector_id=cid,
                    source_product="vendor_x",
                    display_name=cid,
                    disposition_policy_default=DispositionPolicy.NOT_REQUIRED.value,
                )
            )

    with patch(
        "app.services.event_service.get_settings",
        return_value=SimpleNamespace(source_mode="live"),
    ):
        result = await event_service.ingest_source_object(
            IngestableSource(
                reference=_ref(
                    kind=SourceObjectKind.ALERT,
                    object_id=f"LIVE-OK-{sfx}",
                    connector_id=cid,
                    product="vendor_x",
                ),
                source_type="live",
            )
        )
    assert result.event_id
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, result.event_id)
        assert row is not None
        assert row.disposition_policy == DispositionPolicy.NOT_REQUIRED.value


@pytest.mark.asyncio
async def test_concurrent_ingest_publishes_event_created_once(
    event_service: EventService,
) -> None:
    bus = AsyncMock()
    bus.publish_event = AsyncMock(return_value=None)
    event_service._bus = bus  # noqa: SLF001 — test seam

    sfx = _sfx()
    src = IngestableSource(
        reference=_ref(kind=SourceObjectKind.INCIDENT, object_id=f"INC-bus-{sfx}"),
        title="bus-once",
        source_type="mock_xdr",
    )

    real_post = event_service._post_create_side_effects
    posts: list[bool] = []

    async def delayed_post(
        row: orm.SecurityEvent,
        *,
        force_context_refresh: bool,
        publish_event: bool,
    ):
        posts.append(publish_event)
        if publish_event:
            # Let idempotent losers reach post-create / init_context first.
            for _ in range(50):
                if any(not flag for flag in posts):
                    break
                await asyncio.sleep(0.002)
            await asyncio.sleep(0.02)
        return await real_post(
            row,
            force_context_refresh=force_context_refresh,
            publish_event=publish_event,
        )

    event_service._post_create_side_effects = delayed_post  # noqa: SLF001
    results = await asyncio.gather(
        *(event_service.ingest_source_object(src) for _ in range(6)),
        return_exceptions=True,
    )
    assert not any(isinstance(r, Exception) for r in results)
    created_calls = [c for c in bus.publish_event.call_args_list if c.args[1] == "event_created"]
    assert len(created_calls) == 1


@pytest.mark.asyncio
async def test_noop_set_final_verdict_skips_bus_publish(
    event_service: EventService,
) -> None:
    bus = AsyncMock()
    bus.publish_event = AsyncMock(return_value=None)
    event_service._bus = bus  # noqa: SLF001

    sfx = _sfx()
    created = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.ALERT, object_id=f"AL-noop-{sfx}"),
            title="noop-verdict",
            source_type="mock_xdr",
        )
    )
    bus.publish_event.reset_mock()
    await event_service.set_final_verdict(created.event_id, FinalVerdict.NONE, operator="test")
    assert bus.publish_event.await_count == 0


@pytest.mark.asyncio
async def test_transition_ignores_forged_disposition_only_intent(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    sfx = _sfx()
    created = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref(kind=SourceObjectKind.ALERT, object_id=f"AL-forge-{sfx}"),
            title="forge-transition",
            source_type="mock_xdr",
        )
    )
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, created.event_id)
            assert row is not None
            row.status = EventStatus.TRIAGING.value
            row.final_verdict = FinalVerdict.FALSE_POSITIVE.value

    forged = TransitionContext(
        disposition_only_intent=True,
        final_verdict=FinalVerdict.FALSE_POSITIVE,
    )
    with pytest.raises(InvalidStateTransitionError, match="disposition_only_intent"):
        await event_service.transition_status(
            created.event_id,
            EventStatus.PLANNING_RESPONSE,
            context=forged,
        )
