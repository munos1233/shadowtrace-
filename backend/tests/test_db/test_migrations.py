"""Migration + schema-behavior tests against a real PostgreSQL (ISSUE-003).

Requires the Compose PostgreSQL to be reachable via ``DATABASE_URL`` (async).
Run with e.g.::

    DATABASE_URL=postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace \\
        pytest tests/test_db/test_migrations.py -v
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.db import models as m
from tests.test_db.test_migration_revisions import _load_revision_width

BACKEND_DIR = Path(__file__).resolve().parents[2]

# Must match Alembic head public tables (excl. alembic_version) and
# ``Base.metadata.tables``; update in the same PR as any core migration.
CORE_TABLES = {
    "agent_task",
    "agent_task_attempt",
    "agent_artifact",
    "action",
    "action_execution_job",
    "action_target_result",
    "agent_trace",
    "approval_record",
    "attack_control_mapping",
    "behavior_observation",
    "behavior_observation_projection_failure",
    "candidate_detection",
    "data_quality_error",
    "decision_record",
    "derived_detection_connector",
    "detection_context_snapshot",
    "detection_feature_baseline",
    "detection_governance_decision",
    "detection_promotion",
    "detection_rule_package",
    "detection_rule_runtime_error",
    "detection_scope_revision",
    "disposition_outbox",
    "disposition_receipt",
    "entity_profile",
    "evaluation_case_truth",
    "event_audit_log",
    "event_context_field_version",
    "event_context_journal",
    "evidence",
    "feature_snapshot",
    "graph_edge",
    "graph_node",
    "investigation_intent",
    "knowledge_chunk",
    "knowledge_release",
    "knowledge_stix_object",
    "llm_call_log",
    "memory_review",
    "organization_policy_profile",
    "playbook_release_object",
    "policy_release_object",
    "report",
    "security_event",
    "shadow_decision_record",
    "shadow_query_artifact",
    "shadow_run",
    "source_checkpoint",
    "source_connector",
    "source_event_link",
    "source_object",
    "tool_call_attempt",
    "tool_call_grant",
    "tool_call_log",
}


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    """Ensure the schema is at head for the module (sync; runs its own loop)."""
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session(migrated: None) -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


async def _seed_event(session: AsyncSession, sfx: str) -> str:
    event_id = f"evt-2026-{sfx}"
    session.add(
        m.SecurityEvent(
            event_id=event_id,
            event_type="insider_threat",
            title="test",
            creation_source_ref={"source_object_id": f"INC-{sfx}"},
        )
    )
    await session.flush()
    return event_id


async def _seed_connector_source(session: AsyncSession, sfx: str) -> tuple[str, str]:
    connector_id = f"conn-{sfx}"
    source_record_id = f"src-{sfx}"
    session.add(
        m.SourceConnector(connector_id=connector_id, source_product="mock_xdr", display_name="Mock")
    )
    await session.flush()
    session.add(
        m.SourceObject(
            source_record_id=source_record_id,
            source_product="mock_xdr",
            source_tenant_id="t1",
            connector_id=connector_id,
            source_kind="incident",
            source_object_id=f"INC-{sfx}",
        )
    )
    await session.flush()
    return connector_id, source_record_id


async def _seed_action(session: AsyncSession, event_id: str, sfx: str, fingerprint: str) -> str:
    action_id = f"act-{sfx}"
    session.add(
        m.Action(
            action_id=action_id,
            event_id=event_id,
            plan_revision=1,
            action_fingerprint=fingerprint,
            action_category="response",
            action_name="block ip",
            tool_name="block_ip",
            action_level="l2",
            execution_owner="direct_tool",
        )
    )
    await session.flush()
    return action_id


# --------------------------------------------------------------------------- #


async def test_all_core_tables_exist(session: AsyncSession) -> None:
    rows = await session.execute(
        text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
        )
    )
    present = {r[0] for r in rows}
    assert CORE_TABLES <= present, {"missing": CORE_TABLES - present}
    assert present == CORE_TABLES, {"unexpected": present - CORE_TABLES}


def test_alembic_version_num_column_width(migrated: None) -> None:
    """ISSUE-214: version_num must fit long head revision ids."""
    min_width = _load_revision_width()

    async def _assert_width() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                row = await conn.execute(
                    text(
                        "SELECT character_maximum_length FROM information_schema.columns "
                        "WHERE table_schema = 'public' "
                        "AND table_name = 'alembic_version' "
                        "AND column_name = 'version_num'"
                    )
                )
                result = row.one()
                assert result[0] >= min_width, f"expected width >= {min_width}, got {result[0]}"
                stamped = await conn.scalar(text("SELECT version_num FROM alembic_version"))
                assert stamped == "0032_investigation_intent_generate_report"
        finally:
            await engine.dispose()

    asyncio.run(_assert_width())


def test_upgrade_head_when_generate_report_column_preexists() -> None:
    """ISSUE-214: half-applied ISSUE-204 envs can upgrade without DuplicateColumn."""
    cfg = _alembic_config()
    command.downgrade(cfg, "0031_report_quality")

    async def _seed_half_applied_column() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "ALTER TABLE investigation_intent "
                        "ADD COLUMN IF NOT EXISTS generate_report BOOLEAN NOT NULL DEFAULT TRUE"
                    )
                )
        finally:
            await engine.dispose()

    asyncio.run(_seed_half_applied_column())
    command.upgrade(cfg, "head")

    async def _assert_head() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                stamped = await conn.scalar(text("SELECT version_num FROM alembic_version"))
                assert stamped == "0032_investigation_intent_generate_report"
                has_col = await conn.scalar(
                    text(
                        "SELECT 1 FROM information_schema.columns "
                        "WHERE table_schema = 'public' "
                        "AND table_name = 'investigation_intent' "
                        "AND column_name = 'generate_report'"
                    )
                )
                assert has_col == 1
        finally:
            await engine.dispose()

    asyncio.run(_assert_head())


async def test_llm_call_log_supports_prompt_status_and_failure_audit(
    session: AsyncSession,
) -> None:
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    row = m.LLMCallLog(
        event_id=event_id,
        agent_name="RiskAgent",
        prompt_key="risk_score",
        model_name="primary-model",
        prompt_tokens=0,
        completion_tokens=0,
        total_tokens=0,
        latency_ms=25,
        fallback_level=0,
        status="llm_timeout",
    )
    session.add(row)
    await session.flush()

    stored = await session.get(m.LLMCallLog, row.id)
    assert stored is not None
    assert stored.prompt_key == "risk_score"
    assert stored.status == "llm_timeout"
    await session.rollback()


async def test_action_fingerprint_unique(session: AsyncSession) -> None:
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    fp = f"fp-{sfx}"
    await _seed_action(session, event_id, sfx, fp)
    session.add(
        m.Action(
            action_id=f"act-dup-{sfx}",
            event_id=event_id,
            plan_revision=1,
            action_fingerprint=fp,
            action_category="response",
            action_name="dup",
            tool_name="block_ip",
            action_level="l2",
            execution_owner="direct_tool",
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_action_event_foreign_key(session: AsyncSession) -> None:
    sfx = _sfx()
    session.add(
        m.Action(
            action_id=f"act-{sfx}",
            event_id=f"evt-missing-{sfx}",
            plan_revision=1,
            action_fingerprint=f"fp-{sfx}",
            action_category="response",
            action_name="orphan",
            tool_name="block_ip",
            action_level="l2",
            execution_owner="direct_tool",
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_outbox_idempotency_and_source_sequence_unique(session: AsyncSession) -> None:
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    _, source_record_id = await _seed_connector_source(session, sfx)
    action_id = await _seed_action(session, event_id, sfx, f"fp-{sfx}")

    def _outbox(oid: str, idem: str, seq: int, slot: str) -> m.DispositionOutbox:
        return m.DispositionOutbox(
            outbox_id=oid,
            writeback_id=f"wbk-{oid}",
            disposition_id=f"disp-{oid}",
            action_id=action_id,
            event_id=event_id,
            closure_cycle=1,
            source_record_id=source_record_id,
            source_locator_hash="hash",
            source_sequence=seq,
            intent_kind="entity_action_submit",
            logical_slot=slot,
            idempotency_key=idem,
            command_payload={"k": "v"},
            command_payload_sha256="sha",
        )

    session.add(_outbox(f"ob1-{sfx}", f"idem-{sfx}", 1, "slot-a"))
    await session.flush()

    # duplicate idempotency_key
    session.add(_outbox(f"ob2-{sfx}", f"idem-{sfx}", 2, "slot-b"))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()

    # re-seed then duplicate (source_record_id, source_sequence)
    sfx2 = _sfx()
    event_id = await _seed_event(session, sfx2)
    _, source_record_id = await _seed_connector_source(session, sfx2)
    action_id = await _seed_action(session, event_id, sfx2, f"fp-{sfx2}")
    session.add(_outbox(f"ob1-{sfx2}", f"idemA-{sfx2}", 5, "slot-a"))
    await session.flush()
    session.add(_outbox(f"ob2-{sfx2}", f"idemB-{sfx2}", 5, "slot-b"))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_event_status_update_single_active_head_and_superseding(
    session: AsyncSession,
) -> None:
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    _, source_record_id = await _seed_connector_source(session, sfx)
    action_id = await _seed_action(session, event_id, sfx, f"fp-{sfx}")

    def _head(oid: str, seq: int, superseded_by: str | None) -> m.DispositionOutbox:
        return m.DispositionOutbox(
            outbox_id=oid,
            writeback_id=f"wbk-{oid}",
            disposition_id=f"disp-{oid}",
            action_id=action_id,
            event_id=event_id,
            closure_cycle=1,
            source_record_id=source_record_id,
            source_locator_hash="hash",
            source_sequence=seq,
            intent_kind="event_status_update",
            logical_slot="terminal",
            supersedes_disposition_id=None,
            superseded_by_disposition_id=superseded_by,
            idempotency_key=f"idem-{oid}",
            command_payload={"op": "set_event_disposition"},
            command_payload_sha256="sha",
        )

    session.add(_head(f"h1-{sfx}", 1, None))
    await session.flush()
    # second active head for same lineage violates the partial unique index
    session.add(_head(f"h2-{sfx}", 2, None))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()

    # legal superseding: mark old head superseded first, then insert new active head
    event_id = await _seed_event(session, sfx + "b")
    _, source_record_id = await _seed_connector_source(session, sfx + "b")
    action_id = await _seed_action(session, event_id, sfx + "b", f"fp-{sfx}b")
    old = _head(f"old-{sfx}", 1, None)
    session.add(old)
    await session.flush()
    old.superseded_by_disposition_id = f"disp-new-{sfx}"
    await session.flush()
    session.add(_head(f"new-{sfx}", 2, None))
    await session.flush()  # succeeds: only one active head remains
    await session.rollback()


async def test_event_status_update_active_head_is_event_scoped_not_action(
    session: AsyncSession,
) -> None:
    """ISSUE-093 §4: two *different* Actions on the same event/cycle/slot must
    collide on the active-head index — it is not enough that each Action has
    at most one active head of its own."""
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    _, source_record_id = await _seed_connector_source(session, sfx)
    action_a = await _seed_action(session, event_id, sfx, f"fp-a-{sfx}")
    action_b = await _seed_action(session, event_id, sfx + "b", f"fp-b-{sfx}")

    def _head(oid: str, action_id: str, seq: int) -> m.DispositionOutbox:
        return m.DispositionOutbox(
            outbox_id=oid,
            writeback_id=f"wbk-{oid}",
            disposition_id=f"disp-{oid}",
            action_id=action_id,
            event_id=event_id,
            closure_cycle=1,
            source_record_id=source_record_id,
            source_locator_hash="hash",
            source_sequence=seq,
            intent_kind="event_status_update",
            logical_slot="terminal",
            supersedes_disposition_id=None,
            superseded_by_disposition_id=None,
            idempotency_key=f"idem-{oid}",
            command_payload={"op": "set_event_disposition"},
            command_payload_sha256="sha",
        )

    session.add(_head(f"ha-{sfx}", action_a, 1))
    await session.flush()
    # A *different* action claiming an active head for the same
    # event/closure_cycle/slot must be rejected, even though action_b itself
    # has no other active head.
    session.add(_head(f"hb-{sfx}", action_b, 2))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_receipt_writeback_sequence_pk(session: AsyncSession) -> None:
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    _, source_record_id = await _seed_connector_source(session, sfx)
    action_id = await _seed_action(session, event_id, sfx, f"fp-{sfx}")

    def _receipt(seq: int, status: str) -> m.DispositionReceipt:
        return m.DispositionReceipt(
            writeback_id=f"wbk-{sfx}",
            sequence=seq,
            disposition_id=f"disp-{sfx}",
            action_id=action_id,
            source_record_id=source_record_id,
            status=status,
        )

    session.add(_receipt(1, "sending"))
    await session.flush()
    session.add(_receipt(2, "confirmed"))  # different sequence is fine
    await session.flush()
    session.add(_receipt(1, "unknown"))  # duplicate (writeback_id, sequence)
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_row_version_cas(session: AsyncSession) -> None:
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    await session.commit()

    # optimistic update from version 1 -> 2 succeeds
    res = await session.execute(
        update(m.SecurityEvent)
        .where(m.SecurityEvent.event_id == event_id, m.SecurityEvent.row_version == 1)
        .values(status="triaging", row_version=2)
    )
    assert res.rowcount == 1

    # a stale writer still using version 1 matches no rows (CAS miss)
    res_stale = await session.execute(
        update(m.SecurityEvent)
        .where(m.SecurityEvent.event_id == event_id, m.SecurityEvent.row_version == 1)
        .values(status="analyzing", row_version=2)
    )
    assert res_stale.rowcount == 0
    await session.rollback()


async def test_source_checkpoint_identity_is_connector_and_kind(
    session: AsyncSession,
) -> None:
    sfx = _sfx()
    connector_id, _ = await _seed_connector_source(session, sfx)
    session.add(
        m.SourceCheckpoint(
            connector_id=connector_id,
            object_kind="incident",
            schema_version="1",
            watermark={"cursor": "incident"},
        )
    )
    session.add(
        m.SourceCheckpoint(
            connector_id=connector_id,
            object_kind="alert",
            schema_version="1",
            watermark={"cursor": "alert"},
        )
    )
    session.add(
        m.SourceCheckpoint(
            connector_id=connector_id,
            object_kind="incident",
            stream_scope="file:scenario-b",
            schema_version="1",
            watermark={"cursor": "scenario-b"},
        )
    )
    await session.flush()
    duplicate = m.SourceCheckpoint(
        connector_id=connector_id,
        object_kind="incident",
        schema_version="1",
    )
    session.add(duplicate)
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


def test_checkpoint_upgrade_does_not_backfill_legacy_global_watermark(
    migrated: None,
) -> None:
    cfg = _alembic_config()
    command.downgrade(cfg, "0003_outbox_active_head_evt")
    connector_id = f"legacy-{_sfx()}"

    async def _seed_legacy_connector() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO source_connector "
                        "(connector_id, source_product, display_name, status, capabilities, "
                        "watermark, schema_version, connector_metadata) "
                        "VALUES (:connector_id, 'mock_xdr', 'Legacy', 'online', "
                        "'{}'::jsonb, '{\"cursor\":\"unsafe-global\"}'::jsonb, '1', "
                        "'{}'::jsonb)"
                    ),
                    {"connector_id": connector_id},
                )
        finally:
            await engine.dispose()

    asyncio.run(_seed_legacy_connector())
    command.upgrade(cfg, "head")

    async def _assert_no_backfill() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                checkpoint_count = await conn.scalar(
                    text(
                        "SELECT count(*) FROM source_checkpoint WHERE connector_id = :connector_id"
                    ),
                    {"connector_id": connector_id},
                )
                watermark = await conn.scalar(
                    text(
                        "SELECT watermark FROM source_connector WHERE connector_id = :connector_id"
                    ),
                    {"connector_id": connector_id},
                )
                assert checkpoint_count == 0
                assert watermark == {"cursor": "unsafe-global"}
                await conn.execute(
                    text("DELETE FROM source_connector WHERE connector_id = :connector_id"),
                    {"connector_id": connector_id},
                )
        finally:
            await engine.dispose()

    asyncio.run(_assert_no_backfill())


async def test_transaction_rollback(session: AsyncSession) -> None:
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    await session.rollback()
    found = await session.execute(
        select(func.count())
        .select_from(m.SecurityEvent)
        .where(m.SecurityEvent.event_id == event_id)
    )
    assert found.scalar_one() == 0


def test_downgrade_base_then_upgrade_head_roundtrip(migrated: None) -> None:
    # Sync test: Alembic runs its own event loop, so it must not be called from
    # inside a running (async test) loop. Prove a full rollback works, then
    # restore head for any following tests.
    cfg = _alembic_config()
    command.downgrade(cfg, "base")

    async def _remaining_core_tables() -> set[str]:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
                    )
                )
                return {r[0] for r in rows} & CORE_TABLES
        finally:
            await engine.dispose()

    assert asyncio.run(_remaining_core_tables()) == set()
    command.upgrade(cfg, "head")


def test_0023_retention_upgrade_idempotent_when_column_from_0022(migrated: None) -> None:
    """ISSUE-166: 0023 must not fail when 0022 already created retention_expires_at."""
    cfg = _alembic_config()
    command.downgrade(cfg, "0022_shadow_run")
    command.upgrade(cfg, "head")

    async def _assert_retention_column_not_nullable() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                row = await conn.execute(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'public' "
                        "AND table_name = 'shadow_query_artifact' "
                        "AND column_name = 'retention_expires_at'"
                    )
                )
                result = row.one_or_none()
                assert result is not None, "retention_expires_at column missing after 0023"
                assert result[0] == "NO", f"expected NOT NULL, got is_nullable={result[0]}"
        finally:
            await engine.dispose()

    asyncio.run(_assert_retention_column_not_nullable())


async def test_enqueue_supersedes_prior_head_and_keeps_single_active(
    session: AsyncSession,
) -> None:
    """ISSUE-219: enqueueing a second active EVENT_STATUS_UPDATE head for the
    same (event_id, closure_cycle, logical_slot) atomically marks the prior
    head ``superseded_by_disposition_id`` (business lineage, not test fixture)
    and leaves exactly one active head."""
    from unittest.mock import AsyncMock

    from app.models.disposition import (
        DispositionCommand,
        SetEventDispositionParams,
        SourceDisposition,
        SourceObjectLocator,
    )
    from app.models.enums import DispositionIntentKind, ExecutionOwner, SourceObjectKind
    from app.services.disposition_sync_service import DispositionSyncService

    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    _, source_record_id = await _seed_connector_source(session, sfx)
    action_id = await _seed_action(session, event_id, sfx, f"fp-{sfx}")

    def _command(disposition_id: str, idem: str) -> DispositionCommand:
        return DispositionCommand(
            disposition_id=disposition_id,
            action_id=action_id,
            closure_cycle=1,
            intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
            source_locator=SourceObjectLocator(
                source_product="mock_xdr",
                source_tenant_id="t1",
                connector_id=f"conn-{sfx}",
                source_kind=SourceObjectKind.INCIDENT,
                source_object_type="incident",
                source_object_id=f"INC-{sfx}",
            ),
            operation_code="set_event_disposition",
            operation_params=SetEventDispositionParams(
                target_disposition=SourceDisposition.CONTAINED
            ),
            target_results=[],
            operator_id="test-operator",
            idempotency_key=idem,
            source_concurrency_token=None,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            parent_disposition_id=None,
            supersedes_disposition_id=None,
        )

    service = DispositionSyncService(
        session_factory=AsyncMock(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=AsyncMock(),  # type: ignore[arg-type]
    )

    first = await service.enqueue_command(
        session,
        command=_command(f"disp-first-{sfx}", f"idem-first-{sfx}"),
        event_id=event_id,
        source_record_id=source_record_id,
        logical_slot="terminal",
    )
    # Same cycle, second head: must supersede the first, not violate the index.
    second = await service.enqueue_command(
        session,
        command=_command(f"disp-second-{sfx}", f"idem-second-{sfx}"),
        event_id=event_id,
        source_record_id=source_record_id,
        logical_slot="terminal",
    )
    await session.flush()

    first_row = await session.get(m.DispositionOutbox, first.outbox_id)
    assert first_row is not None
    assert first_row.superseded_by_disposition_id == second.disposition_id
    second_row = await session.get(m.DispositionOutbox, second.outbox_id)
    assert second_row is not None
    assert second_row.supersedes_disposition_id == first.disposition_id
    assert second_row.superseded_by_disposition_id is None

    # Invariant: exactly one active (non-superseded) head for the lineage.
    active = (
        (
            await session.execute(
                select(m.DispositionOutbox).where(
                    m.DispositionOutbox.event_id == event_id,
                    m.DispositionOutbox.closure_cycle == 1,
                    m.DispositionOutbox.intent_kind
                    == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    m.DispositionOutbox.logical_slot == "terminal",
                    m.DispositionOutbox.superseded_by_disposition_id.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(active) == 1
    assert active[0].disposition_id == second.disposition_id

    # Same cycle re-enqueue after supersede keeps exactly one active head
    # (third head supersedes the second — chain lineage).
    third = await service.enqueue_command(
        session,
        command=_command(f"disp-third-{sfx}", f"idem-third-{sfx}"),
        event_id=event_id,
        source_record_id=source_record_id,
        logical_slot="terminal",
    )
    await session.flush()
    second_row = await session.get(m.DispositionOutbox, second.outbox_id)
    assert second_row.superseded_by_disposition_id == third.disposition_id
    active = (
        (
            await session.execute(
                select(m.DispositionOutbox).where(
                    m.DispositionOutbox.event_id == event_id,
                    m.DispositionOutbox.closure_cycle == 1,
                    m.DispositionOutbox.intent_kind
                    == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                    m.DispositionOutbox.logical_slot == "terminal",
                    m.DispositionOutbox.superseded_by_disposition_id.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(active) == 1
    assert active[0].disposition_id == third.disposition_id

    await session.rollback()


async def test_enqueue_does_not_supersede_across_closure_cycles(
    session: AsyncSession,
) -> None:
    """ISSUE-219: a new head never supersedes history heads of earlier cycles."""
    from unittest.mock import AsyncMock

    from app.models.disposition import (
        DispositionCommand,
        SetEventDispositionParams,
        SourceDisposition,
        SourceObjectLocator,
    )
    from app.models.enums import DispositionIntentKind, ExecutionOwner, SourceObjectKind
    from app.services.disposition_sync_service import DispositionSyncService

    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    _, source_record_id = await _seed_connector_source(session, sfx)
    action_id = await _seed_action(session, event_id, sfx, f"fp-{sfx}")

    def _command(disposition_id: str, idem: str, cycle: int) -> DispositionCommand:
        return DispositionCommand(
            disposition_id=disposition_id,
            action_id=action_id,
            closure_cycle=cycle,
            intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
            source_locator=SourceObjectLocator(
                source_product="mock_xdr",
                source_tenant_id="t1",
                connector_id=f"conn-{sfx}",
                source_kind=SourceObjectKind.INCIDENT,
                source_object_type="incident",
                source_object_id=f"INC-{sfx}",
            ),
            operation_code="set_event_disposition",
            operation_params=SetEventDispositionParams(
                target_disposition=SourceDisposition.CONTAINED
            ),
            target_results=[],
            operator_id="test-operator",
            idempotency_key=idem,
            source_concurrency_token=None,
            execution_owner=ExecutionOwner.XDR_MANAGED,
            parent_disposition_id=None,
            supersedes_disposition_id=None,
        )

    service = DispositionSyncService(
        session_factory=AsyncMock(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=AsyncMock(),  # type: ignore[arg-type]
    )

    cycle1 = await service.enqueue_command(
        session,
        command=_command(f"disp-c1-{sfx}", f"idem-c1-{sfx}", cycle=1),
        event_id=event_id,
        source_record_id=source_record_id,
        logical_slot="terminal",
    )
    # Later cycle: an active head may exist per cycle; the cycle-1 head must
    # NOT be superseded by a cycle-2 head (history stays intact).
    cycle2 = await service.enqueue_command(
        session,
        command=_command(f"disp-c2-{sfx}", f"idem-c2-{sfx}", cycle=2),
        event_id=event_id,
        source_record_id=source_record_id,
        logical_slot="terminal",
    )
    await session.flush()

    c1_row = await session.get(m.DispositionOutbox, cycle1.outbox_id)
    assert c1_row.superseded_by_disposition_id is None
    c2_row = await session.get(m.DispositionOutbox, cycle2.outbox_id)
    assert c2_row.superseded_by_disposition_id is None
    assert c2_row.supersedes_disposition_id is None

    # Both cycles each hold one active head (index key includes closure_cycle).
    active = (
        (
            await session.execute(
                select(m.DispositionOutbox).where(
                    m.DispositionOutbox.event_id == event_id,
                    m.DispositionOutbox.superseded_by_disposition_id.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    assert {r.closure_cycle for r in active} == {1, 2}

    await session.rollback()


async def test_concurrent_enqueue_same_lineage_keeps_single_active_head() -> None:
    """ISSUE-219: two concurrent activations of the same lineage can never
    leave two active heads — the partial unique index is the final invariant
    and the racing loser either supersedes (serialized after the winner) or
    surfaces an IntegrityError (handled by the caller)."""
    import asyncio
    from unittest.mock import AsyncMock

    from app.models.disposition import (
        DispositionCommand,
        SetEventDispositionParams,
        SourceDisposition,
        SourceObjectLocator,
    )
    from app.models.enums import DispositionIntentKind, ExecutionOwner, SourceObjectKind
    from app.services.disposition_sync_service import DispositionSyncService

    sfx = _sfx()
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    try:
        async with factory() as seed_session:
            event_id = await _seed_event(seed_session, sfx)
            _, source_record_id = await _seed_connector_source(seed_session, sfx)
            action_id = await _seed_action(seed_session, event_id, sfx, f"fp-{sfx}")
            await seed_session.commit()

        def _command(disposition_id: str, idem: str) -> DispositionCommand:
            return DispositionCommand(
                disposition_id=disposition_id,
                action_id=action_id,
                closure_cycle=1,
                intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
                source_locator=SourceObjectLocator(
                    source_product="mock_xdr",
                    source_tenant_id="t1",
                    connector_id=f"conn-{sfx}",
                    source_kind=SourceObjectKind.INCIDENT,
                    source_object_type="incident",
                    source_object_id=f"INC-{sfx}",
                ),
                operation_code="set_event_disposition",
                operation_params=SetEventDispositionParams(
                    target_disposition=SourceDisposition.CONTAINED
                ),
                target_results=[],
                operator_id="test-operator",
                idempotency_key=idem,
                source_concurrency_token=None,
                execution_owner=ExecutionOwner.XDR_MANAGED,
                parent_disposition_id=None,
                supersedes_disposition_id=None,
            )

        async def _enqueue(disposition_id: str, idem: str) -> str:
            async with factory() as sess:
                async with sess.begin():
                    service = DispositionSyncService(
                        session_factory=AsyncMock(),  # type: ignore[arg-type]
                        context_store=AsyncMock(),  # type: ignore[arg-type]
                        adapter_registry=AsyncMock(),  # type: ignore[arg-type]
                    )
                    record = await service.enqueue_command(
                        sess,
                        command=_command(disposition_id, idem),
                        event_id=event_id,
                        source_record_id=source_record_id,
                        logical_slot="terminal",
                    )
                    return record.outbox_id

        results = await asyncio.gather(
            _enqueue(f"disp-ca-{sfx}", f"idem-ca-{sfx}"),
            _enqueue(f"disp-cb-{sfx}", f"idem-cb-{sfx}"),
            return_exceptions=True,
        )

        # At least one enqueue must succeed; the loser may have superseded the
        # winner (serialized) or failed with IntegrityError — never two heads.
        assert any(not isinstance(r, Exception) for r in results), results

        async with factory() as check_session:
            active = (
                (
                    await check_session.execute(
                        select(m.DispositionOutbox).where(
                            m.DispositionOutbox.event_id == event_id,
                            m.DispositionOutbox.closure_cycle == 1,
                            m.DispositionOutbox.intent_kind
                            == DispositionIntentKind.EVENT_STATUS_UPDATE.value,
                            m.DispositionOutbox.logical_slot == "terminal",
                            m.DispositionOutbox.superseded_by_disposition_id.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(active) == 1, f"expected exactly one active head, got {len(active)}"
    finally:
        await engine.dispose()


async def test_action_execution_job_idempotency_key_unique(
    session: AsyncSession,
) -> None:
    """ISSUE-220: the DB rejects a second action_execution_job with the same
    idempotency_key (one authoritative job per key — reclaim can no longer
    insert a duplicate that re-invokes the Provider)."""
    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    await _seed_connector_source(session, sfx)
    action_id = await _seed_action(session, event_id, sfx, f"fp-{sfx}")

    def _job(job_id: str) -> m.ActionExecutionJob:
        return m.ActionExecutionJob(
            job_id=job_id,
            event_id=event_id,
            action_id=action_id,
            provider_name="mock_tool_provider",
            idempotency_key=f"idem-uq-{sfx}",
            status="running",
            claimed_by="worker",
            lease_expires_at=None,
            attempt=1,
        )

    session.add(_job(f"job-a-{sfx}"))
    await session.flush()
    session.add(_job(f"job-b-{sfx}"))
    with pytest.raises(IntegrityError, match="uq_action_execution_job_idempotency_key"):
        await session.flush()
    await session.rollback()


async def test_duplicate_job_dedup_repoints_action_execution_job_id(
    session: AsyncSession,
) -> None:
    """ISSUE-220: migration dedup SQL repoints action.execution_job_id to the
    keeper row before duplicate jobs are deleted."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import text

    sfx = _sfx()
    event_id = await _seed_event(session, sfx)
    action_id = await _seed_action(session, event_id, sfx, f"fp-{sfx}")
    idem = f"idem-dedup-{sfx}"
    old_job_id = f"job-old-{sfx}"
    new_job_id = f"job-new-{sfx}"
    t_old = datetime(2026, 1, 1, tzinfo=UTC)
    t_new = datetime(2026, 1, 2, tzinfo=UTC)

    session.add(
        m.ActionExecutionJob(
            job_id=old_job_id,
            event_id=event_id,
            action_id=action_id,
            provider_name="mock_tool_provider",
            idempotency_key=idem,
            status="queued",
            claimed_by=None,
            lease_expires_at=None,
            attempt=1,
            created_at=t_old,
            updated_at=t_old,
        )
    )
    session.add(
        m.ActionExecutionJob(
            job_id=new_job_id,
            event_id=event_id,
            action_id=action_id,
            provider_name="mock_tool_provider",
            idempotency_key=idem,
            status="running",
            claimed_by="worker",
            lease_expires_at=t_new + timedelta(hours=1),
            attempt=2,
            created_at=t_new,
            updated_at=t_new,
        )
    )
    await session.execute(
        text("UPDATE action SET execution_job_id = :job_id WHERE action_id = :action_id"),
        {"job_id": old_job_id, "action_id": action_id},
    )
    await session.flush()

    await session.execute(
        text(
            """
            UPDATE action a
            SET execution_job_id = kept.job_id
            FROM action_execution_job doomed
            JOIN action_execution_job kept
              ON kept.idempotency_key = doomed.idempotency_key
             AND (kept.created_at, kept.job_id) > (doomed.created_at, doomed.job_id)
            WHERE a.execution_job_id = doomed.job_id
            """
        )
    )
    await session.flush()

    row = await session.get(m.Action, action_id)
    assert row is not None
    assert row.execution_job_id == new_job_id

    await session.rollback()
