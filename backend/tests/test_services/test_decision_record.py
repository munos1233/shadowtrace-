"""DecisionRecordService persistence and idempotency tests (ISSUE-131)."""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.errors import ValidationError
from app.db import models as orm
from app.models.decision_record import DecisionRecord, DecisionStage
from app.services.decision_record_service import (
    DecisionRecordService,
    _legacy_record_hash_for_existing_identity,
)

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


def _run_migrations() -> None:
    """Alembic env.py reads get_settings().database_url — sync test URL first."""
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    loggers = {
        name: logger
        for name, logger in logging.root.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    disabled_before = {name: logger.disabled for name, logger in loggers.items()}
    try:
        command.upgrade(_alembic_config(), "head")
    finally:
        # Alembic's fileConfig(disable_existing_loggers=True) is process-global.
        # Restore the pre-migration states so later tests can capture warnings.
        for name, disabled in disabled_before.items():
            loggers[name].disabled = disabled


@pytest.fixture(scope="module")
def migrated_database() -> None:
    _run_migrations()


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_decision_records(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.AgentTrace))
            await session.execute(delete(orm.DecisionRecord))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.AgentTrace))
            await session.execute(delete(orm.DecisionRecord))


@pytest.fixture
def service(session_factory: async_sessionmaker[AsyncSession]) -> DecisionRecordService:
    return DecisionRecordService(session_factory)


def _event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_persist_from_agent_trace_is_idempotent(
    service: DecisionRecordService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    trace_id = "trc-test0001"
    payload = {
        "decision_summary": "Stop after sufficient evidence",
        "reason_code": "stop_sufficient",
        "selected_action": "finish:",
        "confidence": 0.9,
    }

    first = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="react_engine",
        trace_id=trace_id,
        input_data={"event_id": event_id},
        output_data=payload,
    )
    second = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="react_engine",
        trace_id=trace_id,
        input_data={"event_id": event_id},
        output_data=payload,
    )

    assert first is not None
    assert second == first

    async with session_factory() as session:
        rows = list(await session.scalars(select(orm.DecisionRecord)))
    assert len(rows) == 1
    assert rows[0].record_hash
    assert rows[0].trace_ref == trace_id


@pytest.mark.asyncio
async def test_unresolved_refs_blocks_auto_disposition(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-test0002",
        input_data={"event_id": event_id, "evidence_refs": ["not-a-valid-ref"]},
        output_data={
            "stage": "verify",
            "decision_summary": "Need more evidence",
            "reason_code": "fill_evidence_gap",
            "confidence": 0.4,
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-test0002")
    assert row is not None
    assert row.unresolved_refs
    assert DecisionRecordService.blocks_auto_disposition(row)


@pytest.mark.asyncio
async def test_skips_empty_decision_payload(service: DecisionRecordService) -> None:
    record_id = await service.persist_from_agent_trace(
        event_id=_event_id(),
        agent_name="memory_agent",
        trace_id="trc-empty",
        input_data={},
        output_data={"unrelated_field": "value"},
    )
    assert record_id is None


@pytest.mark.asyncio
async def test_persist_react_reflect_resolves_evd_refs(
    service: DecisionRecordService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="react_engine",
        trace_id="trc-ref0001",
        input_data={"event_id": event_id, "round_index": 2},
        output_data={
            "decision_summary": "DNS corroborated",
            "reason_code": "corroborate_indicator",
            "gap_code": "none",
            "confidence": 0.6,
            "evidence_refs": [{"evidence_id": "evd-dead0001"}, {"evidence_id": "evd-beef0002"}],
            "selected_action": "call_tool:query_dns",
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-ref0001")
    assert row is not None
    assert row.unresolved_refs == []
    assert any(ref.get("ref_id") == "evd-dead0001" for ref in row.input_refs)


@pytest.mark.asyncio
async def test_idempotency_uses_semantic_round_key_not_trace_id(
    service: DecisionRecordService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    payload = {
        "decision_summary": "Round 1 think",
        "reason_code": "corroborate_indicator",
        "selected_action": "call_tool:query_threat_intel",
        "confidence": 0.45,
    }
    first = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="react_engine",
        trace_id="trc-round-a",
        input_data={"event_id": event_id, "round_index": 1},
        output_data=payload,
    )
    second = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="react_engine",
        trace_id="trc-round-b",
        input_data={"event_id": event_id, "round_index": 1},
        output_data=payload,
    )
    assert first is not None
    assert second == first
    async with session_factory() as session:
        rows = list(await session.scalars(select(orm.DecisionRecord)))
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_risk_agent_output_enriched_into_decision_record(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="risk_agent",
        trace_id="trc-risk001",
        input_data={"event_id": event_id},
        output_data={
            "risk_score": 82,
            "severity": "high",
            "confidence": 0.91,
            "scoring_mode": "llm_and_rule",
            "possible_false_positive": False,
            "risk_factors": [],
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-risk001")
    assert row is not None
    assert "risk_score=82" in row.decision_summary
    assert row.confidence == pytest.approx(0.91)
    assert row.stage == "risk"


@pytest.mark.asyncio
async def test_evidence_agent_output_enriched_into_decision_record(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="evidence_agent",
        trace_id="trc-evd001",
        input_data={"event_id": event_id},
        output_data={
            "collection_status": "completed",
            "query_timings": [
                {"tool_name": "query_dns", "dedupe_key": "dedupe-abc123"},
            ],
            "evidence_list": [{"evidence_id": "evd-dead0001"}],
            "gaps": [{"missing_source": "dns", "reason": "no_records"}],
            "query_plan": {
                "plan_step_orders": [1],
                "degraded_reasons": ["budget_trimmed_optional_queries"],
            },
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-evd001")
    assert row is not None
    assert row.stage == DecisionStage.EVIDENCE.value
    assert "plan_steps:1" in (row.reason_codes or [])
    assert "budget_trimmed_optional_queries" in (row.decision_summary or "")
    assert (row.selected or {}).get("selected_action") == "evidence:completed"
    candidates = row.candidates or []
    assert any(
        item.get("name") == "query_dns" and item.get("candidate_type") == "evidence_query"
        for item in candidates
        if isinstance(item, dict)
    )


@pytest.mark.asyncio
async def test_verify_agent_output_enriched_into_decision_record(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-verify001",
        input_data={"event_id": event_id},
        output_data={
            "overall_status": "success",
            "verification_phase": "effect",
            "results": [
                {
                    "action_id": "act-dead0001",
                    "effect_status": "verified",
                    "writeback_required": False,
                }
            ],
            "failed_actions": [],
            "need_action_replan": False,
            "need_writeback_recovery": False,
            "need_manual_resolution": False,
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-verify001")
    assert row is not None
    assert row.stage == DecisionStage.VERIFY.value
    assert row.selected == {"selected_action": "verify:effect:success"}
    assert row.reason_codes == ["success"]


@pytest.mark.asyncio
async def test_verify_agent_failed_output_enriched_into_decision_record(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-verify-fail",
        input_data={"event_id": event_id},
        output_data={
            "overall_status": "failed",
            "verification_phase": "effect",
            "results": [],
            "failed_actions": ["act-beef0002"],
            "need_action_replan": True,
            "need_writeback_recovery": False,
            "need_manual_resolution": False,
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-verify-fail")
    assert row is not None
    assert row.stage == DecisionStage.VERIFY.value
    assert row.reason_codes == ["need_action_replan"]
    assert "overall_status=failed" in (row.decision_summary or "")


@pytest.mark.asyncio
async def test_blocks_auto_disposition_when_minimum_audit_missing(
    service: DecisionRecordService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    async with session_factory() as session:
        async with session.begin():
            row = orm.DecisionRecord(
                record_id=f"dec-{uuid.uuid4().hex[:12]}",
                event_id=event_id,
                stage=DecisionStage.VERIFY.value,
                actor="test",
                idempotency_key=f"{event_id}:verify:test:r1",
                record_hash="abc",
                schema_version="1.0",
            )
            session.add(row)
    fetched = await service.list_by_event(event_id)
    assert len(fetched) == 1
    assert DecisionRecordService.blocks_auto_disposition(fetched[0])


@pytest.mark.asyncio
async def test_assert_auto_disposition_allowed_rejects_unresolved_refs(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-block001",
        input_data={"event_id": event_id},
        output_data={
            "stage": "verify",
            "decision_summary": "Need more evidence",
            "reason_code": "fill_evidence_gap",
            "confidence": 0.4,
            "evidence_refs": ["not-a-valid-ref"],
        },
    )
    with pytest.raises(ValidationError, match="blocked by decision audit"):
        await service.assert_auto_disposition_allowed(event_id)


@pytest.mark.asyncio
async def test_migration_redacts_legacy_react_cot_fields(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    trace_id = "trc-legacy01"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.AgentTrace(
                    trace_id=trace_id,
                    event_id=event_id,
                    agent_name="react_engine",
                    status="success",
                    input_data={},
                    output_data={
                        "thought": "hidden reasoning",
                        "reflection": "hidden reflection",
                        "summary": "legacy summary",
                        "decision_summary": "kept summary",
                    },
                )
            )
        async with session.begin():
            await session.execute(
                sa_text(
                    """
                    UPDATE agent_trace
                    SET output_data = (
                        COALESCE(output_data, '{}'::jsonb)
                        - 'thought'
                        - 'reflection'
                        - 'rationale'
                        - 'summary'
                        - 'gap'
                    ) || jsonb_build_object(
                        'decision_summary',
                        COALESCE(NULLIF(output_data->>'decision_summary', ''), '')
                    )
                    WHERE agent_name = 'react_engine'
                      AND trace_id = :trace_id
                    """
                ),
                {"trace_id": trace_id},
            )
        row = await session.get(orm.AgentTrace, trace_id)
        assert row is not None
        output = row.output_data
        assert "thought" not in output
        assert "reflection" not in output
        assert "summary" not in output
        assert output.get("decision_summary") == "kept summary"


@pytest.mark.asyncio
async def test_react_finish_round_stage_is_react_think(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="react_engine",
        trace_id="trc-stage01",
        input_data={"event_id": event_id, "round_index": 1},
        output_data={
            "stage": "react_think",
            "decision_summary": "finish round think",
            "reason_code": "stop_sufficient",
            "selected_action": "finish:",
            "confidence": 0.9,
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-stage01")
    assert row is not None
    assert row.stage == "react_think"


@pytest.mark.asyncio
async def test_planner_revision_links_parent_and_supersedes(
    service: DecisionRecordService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    plan_id = "plan-revtest"
    first_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="planner_agent",
        trace_id="trc-plan-r1",
        input_data={"event_id": event_id},
        output_data={
            "plan_id": plan_id,
            "revision": 1,
            "steps": [{"assigned_agent": "EvidenceAgent", "step_goal": "collect", "step_order": 1}],
        },
    )
    second_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="planner_agent",
        trace_id="trc-plan-r2",
        input_data={"event_id": event_id},
        output_data={
            "plan_id": plan_id,
            "revision": 2,
            "steps": [{"assigned_agent": "RiskAgent", "step_goal": "score", "step_order": 1}],
        },
    )
    assert first_id is not None
    assert second_id is not None
    assert second_id != first_id
    async with session_factory() as session:
        second = await session.get(orm.DecisionRecord, second_id)
        assert second is not None
        assert second.revision == 2
        assert second.parent_record_id == first_id
        assert second.supersedes_record_id == first_id


@pytest.mark.asyncio
async def test_response_agent_playbook_refs_persist_in_db(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="response_agent",
        trace_id="trc-playbook-persist",
        input_data={"event_id": event_id},
        output_data={
            "plan_id": "rsp-playbook1",
            "generated_by": "template",
            "actions": [
                {
                    "action_id": "act-playbook1",
                    "action_name": "Block IP",
                    "tool_name": "block_ip",
                    "playbook_ref": {
                        "playbook_id": "pb-a1b2c3d4",
                        "release_id": "krel-abcdef012345678",
                        "release_version": "v1-test",
                        "content_hash": "a" * 64,
                        "bundle_content_hash": "b" * 64,
                    },
                }
            ],
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-playbook-persist")
    assert row is not None
    ref_types = {(item["ref_type"], item["ref_id"]) for item in row.input_refs}
    assert ("playbook_release_id", "krel-abcdef012345678") in ref_types
    assert ("playbook_id", "pb-a1b2c3d4") in ref_types
    assert row.kb_version == "v1-test"


@pytest.mark.asyncio
async def test_response_agent_decision_record_summary_is_bounded_structured(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="response_agent",
        trace_id="trc-resp001",
        input_data={"event_id": event_id},
        output_data={
            "plan_id": "plan-resp01",
            "generated_by": "template",
            "strategy_summary": "This free-text strategy must not become decision_summary",
            "actions": [
                {
                    "action_id": "act-resp01",
                    "action_name": "block ip",
                    "tool_name": "block_ip",
                }
            ],
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-resp001")
    assert row is not None
    assert "strategy must not" not in row.decision_summary
    assert "actions=1" in row.decision_summary
    assert "strategy=" not in (row.decision_summary or "")
    assert row.rule_version is None


@pytest.mark.asyncio
async def test_response_agent_decision_record_surfaces_allowlisted_gate_tokens(
    service: DecisionRecordService,
) -> None:
    event_id = _event_id()
    prose = "This free-text strategy must not become decision_summary"
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="response_agent",
        trace_id="trc-resp-gates",
        input_data={"event_id": event_id},
        output_data={
            "plan_id": "plan-resp-gates",
            "generated_by": "llm",
            "strategy_summary": f"{prose}; containment_quality_gate: entity_coverage_merge",
            "actions": [
                {
                    "action_id": "act-resp-gates",
                    "action_name": "isolate host",
                    "tool_name": "isolate_host",
                }
            ],
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-resp-gates")
    assert row is not None
    assert "gates=entity_coverage_merge" in (row.decision_summary or "")
    assert "generated_by=llm" in (row.decision_summary or "")
    assert prose not in (row.decision_summary or "")
    assert "strategy=" not in (row.decision_summary or "")


@pytest.mark.asyncio
async def test_react_unresolved_refs_do_not_block_disposition(
    service: DecisionRecordService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="react_engine",
        trace_id="trc-react-bad-ref",
        input_data={"event_id": event_id, "round_index": 1},
        output_data={
            "stage": "react_reflect",
            "decision_summary": "Investigation note",
            "reason_code": "fill_evidence_gap",
            "confidence": 0.4,
            "evidence_refs": ["not-a-valid-ref"],
        },
    )
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DecisionRecord(
                    record_id=f"dec-{uuid.uuid4().hex[:12]}",
                    event_id=event_id,
                    stage=DecisionStage.VERIFY.value,
                    actor="verify_agent",
                    decision_summary="minimum verify audit",
                    reason_codes=["minimum_audit"],
                    confidence=0.9,
                    selected={"selected_action": "verify:minimum_audit"},
                    idempotency_key=f"{event_id}:verify:seed:r1",
                    record_hash="deadbeef",
                    schema_version="1.0",
                )
            )
    await service.assert_auto_disposition_allowed(event_id)


@pytest.mark.asyncio
async def test_idempotency_hash_mismatch_sets_degraded(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    degraded_calls: list[tuple[str, str, bool, str]] = []

    class FakeDegradedFlags:
        async def has_flag(self, event_id: str, flag_name: str) -> bool:
            return any(item[1] == flag_name for item in degraded_calls)

        async def set_flag(
            self,
            event_id: str,
            flag_name: str,
            value: bool,
            writer: str,
        ) -> list[str]:
            degraded_calls.append((event_id, flag_name, value, writer))
            return [f"{flag_name}=true"]

    service = DecisionRecordService(session_factory, degraded_flag_service=FakeDegradedFlags())
    payload = {
        "stage": "verify",
        "decision_summary": "first summary",
        "reason_code": "minimum_audit",
        "confidence": 0.9,
        "selected_action": "verify:first",
    }
    first = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-hash-a",
        input_data={"event_id": event_id},
        output_data=payload,
    )
    second = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-hash-b",
        input_data={"event_id": event_id},
        output_data={**payload, "decision_summary": "corrected summary"},
    )
    assert first is not None
    assert second == first
    assert degraded_calls
    assert degraded_calls[0][1] == "decision_audit_degraded"


@pytest.mark.asyncio
async def test_idempotent_replay_ignores_generated_record_and_trace_identity(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    degraded_calls: list[tuple[str, str, bool, str]] = []

    class FakeDegradedFlags:
        async def set_flag(
            self,
            event_id: str,
            flag_name: str,
            value: bool,
            writer: str,
        ) -> list[str]:
            degraded_calls.append((event_id, flag_name, value, writer))
            return [f"{flag_name}=true"]

    service = DecisionRecordService(
        session_factory,
        degraded_flag_service=FakeDegradedFlags(),
    )
    payload = {
        "stage": "verify",
        "overall_status": "success",
        "verification_phase": "effect",
        "results": [],
    }
    first = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-replay-a",
        input_data={"event_id": event_id},
        output_data=payload,
    )
    second = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-replay-b",
        input_data={"event_id": event_id},
        output_data=payload,
    )

    assert second == first
    assert degraded_calls == []


@pytest.mark.asyncio
async def test_idempotent_replay_accepts_pre_issue261_hash(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    degraded_calls: list[tuple[str, str, bool, str]] = []

    class FakeDegradedFlags:
        async def set_flag(
            self,
            event_id: str,
            flag_name: str,
            value: bool,
            writer: str,
        ) -> list[str]:
            degraded_calls.append((event_id, flag_name, value, writer))
            return [f"{flag_name}=true"]

    service = DecisionRecordService(
        session_factory,
        degraded_flag_service=FakeDegradedFlags(),
    )
    payload = {
        "stage": "verify",
        "overall_status": "success",
        "verification_phase": "effect",
        "results": [],
    }
    first = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-legacy-a",
        input_data={"event_id": event_id},
        output_data=payload,
    )
    assert first is not None
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.DecisionRecord, first)
            assert row is not None
            record = DecisionRecord.model_validate(row, from_attributes=True)
            row.record_hash = _legacy_record_hash_for_existing_identity(record, row)

    second = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-legacy-b",
        input_data={"event_id": event_id},
        output_data=payload,
    )

    assert second == first
    assert degraded_calls == []


@pytest.mark.asyncio
async def test_verify_outcome_transition_creates_distinct_audit_records(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    degraded_calls: list[tuple[str, str, bool, str]] = []

    class FakeDegradedFlags:
        async def set_flag(
            self,
            event_id: str,
            flag_name: str,
            value: bool,
            writer: str,
        ) -> list[str]:
            degraded_calls.append((event_id, flag_name, value, writer))
            return [f"{flag_name}=true"]

    service = DecisionRecordService(
        session_factory,
        degraded_flag_service=FakeDegradedFlags(),
    )
    common = {
        "stage": "verify",
        "verification_phase": "effect",
        "results": [],
    }
    waiting = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-outcome-waiting",
        input_data={"event_id": event_id},
        output_data={
            **common,
            "overall_status": "waiting",
            "need_writeback_recovery": True,
            "recoverable_writeback_ids": ["wbk-1234abcd"],
        },
    )
    success = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-outcome-success",
        input_data={"event_id": event_id},
        output_data={**common, "overall_status": "success"},
    )

    assert waiting is not None
    assert success is not None
    assert success != waiting
    assert degraded_calls == []


@pytest.mark.asyncio
async def test_verify_result_change_creates_distinct_audit_records(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    service = DecisionRecordService(session_factory)
    common = {
        "stage": "verify",
        "verification_phase": "effect",
        "overall_status": "success",
    }
    first = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-result-a",
        input_data={"event_id": event_id},
        output_data={
            **common,
            "results": [{"action_id": "act-1234abcd", "effect_status": "verified"}],
        },
    )
    second = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-result-b",
        input_data={"event_id": event_id},
        output_data={
            **common,
            "results": [{"action_id": "act-1234abcd", "effect_status": "failed"}],
        },
    )

    assert first is not None
    assert second is not None
    assert second != first


@pytest.mark.asyncio
async def test_verify_result_order_is_semantically_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    degraded_calls: list[tuple[str, str, bool, str]] = []

    class FakeDegradedFlags:
        async def set_flag(
            self,
            event_id: str,
            flag_name: str,
            value: bool,
            writer: str,
        ) -> list[str]:
            degraded_calls.append((event_id, flag_name, value, writer))
            return [f"{flag_name}=true"]

    service = DecisionRecordService(
        session_factory,
        degraded_flag_service=FakeDegradedFlags(),
    )
    result_a = {
        "action_id": "act-1234abcd",
        "effect_status": "verified",
        "writeback_ids": ["wbk-bbbbbbbb", "wbk-aaaaaaaa"],
    }
    result_b = {
        "action_id": "act-5678efab",
        "effect_status": "verified",
        "writeback_ids": [],
    }
    common = {
        "stage": "verify",
        "verification_phase": "effect",
        "overall_status": "success",
    }
    first = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-order-a",
        input_data={"event_id": event_id},
        output_data={**common, "results": [result_a, result_b]},
    )
    second = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-order-b",
        input_data={"event_id": event_id},
        output_data={
            **common,
            "results": [
                result_b,
                {**result_a, "writeback_ids": list(reversed(result_a["writeback_ids"]))},
            ],
        },
    )

    assert second == first
    assert degraded_calls == []


@pytest.mark.asyncio
async def test_non_material_replay_mismatch_degrades_decision_audit(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()
    degraded_calls: list[tuple[str, str, bool, str]] = []

    class FakeDegradedFlags:
        async def set_flag(
            self,
            event_id: str,
            flag_name: str,
            value: bool,
            writer: str,
        ) -> list[str]:
            degraded_calls.append((event_id, flag_name, value, writer))
            return [f"{flag_name}=true"]

    service = DecisionRecordService(
        session_factory,
        degraded_flag_service=FakeDegradedFlags(),
    )
    common = {
        "stage": "other",
        "reason_code": "graph_built",
        "selected_action": "graph:persist",
    }
    first = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="graph_agent",
        trace_id="trc-graph-a",
        input_data={"event_id": event_id},
        output_data={**common, "decision_summary": "first graph projection"},
    )
    second = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="graph_agent",
        trace_id="trc-graph-b",
        input_data={"event_id": event_id},
        output_data={**common, "decision_summary": "refreshed graph projection"},
    )

    assert first is not None
    assert second == first
    assert degraded_calls
    assert degraded_calls[0][1] == "decision_audit_degraded"


@pytest.mark.asyncio
async def test_auto_disposition_blocked_when_audit_degraded(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    event_id = _event_id()

    class FakeDegradedFlags:
        async def has_flag(self, event_id: str, flag_name: str) -> bool:
            return flag_name == "decision_audit_degraded"

        async def set_flag(self, *args: object, **kwargs: object) -> list[str]:
            return ["decision_audit_degraded=true"]

    service = DecisionRecordService(session_factory, degraded_flag_service=FakeDegradedFlags())
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.DecisionRecord(
                    record_id=f"dec-{uuid.uuid4().hex[:12]}",
                    event_id=event_id,
                    stage=DecisionStage.VERIFY.value,
                    actor="verify_agent",
                    decision_summary="minimum verify audit",
                    reason_codes=["minimum_audit"],
                    confidence=0.9,
                    selected={"selected_action": "verify:minimum_audit"},
                    idempotency_key=f"{event_id}:verify:seed:r1",
                    record_hash="deadbeef",
                    schema_version="1.0",
                )
            )
    with pytest.raises(ValidationError, match="degraded decision audit"):
        await service.assert_auto_disposition_allowed(event_id)


@pytest.mark.asyncio
async def test_decision_record_summary_redacts_secrets_on_persist(
    service: DecisionRecordService,
) -> None:
    secret = "Bearer super-secret-token-131"
    event_id = _event_id()
    record_id = await service.persist_from_agent_trace(
        event_id=event_id,
        agent_name="verify_agent",
        trace_id="trc-redact001",
        input_data={"event_id": event_id},
        output_data={
            "stage": "verify",
            "decision_summary": f"action selected {secret}",
            "reason_code": "minimum_audit",
            "confidence": 0.9,
            "selected_action": "verify:redacted",
        },
    )
    assert record_id is not None
    row = await service.get_by_trace_ref("trc-redact001")
    assert row is not None
    assert secret not in row.decision_summary
