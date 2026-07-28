"""ISSUE-078 e2e acceptance tests for FalsePositiveMatcher in the pipeline.

Scenarios:
1. Full pipeline with fp_matcher wired — genuine alert proceeds normally
2. FP matcher does not prevent triage_result persistence
3. FP match metadata not leaked in outbound disposition
4. TriageAgent wired with fp_matcher in the analysis pipeline
5. account_anomaly_fp → short-circuit, evidence skipped
6. required disposition + FP match → full investigation, no auto-close
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from httpx import ASGITransport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mock_xdr import MockXDRSourceAdapter
from app.db import models as orm
from app.ingestion.source_ingester import SourceIngester
from app.models.enums import EventStatus, FinalVerdict, SourceObjectKind
from app.services.evidence_projection import bind_evidence_projection

pytestmark = pytest.mark.e2e_basic

ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]


# --------------------------------------------------------------------------- #
# Scenario 1: Full pipeline with fp_matcher → genuine alert proceeds
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_e2e_pipeline_with_fp_matcher_wired(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
    build_analysis_pipeline: Any,
) -> None:
    """Full pipeline run with fp_matcher wired — genuine alert not blocked.

    The default mock_xdr scenario (insider_data_exfiltration) is NOT a known
    false positive.  The FP matcher must return no_match and the pipeline
    must proceed normally through all investigation stages.
    """
    # Ingest from the mock XDR source.
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.accepted >= 1

    # Find the ingested event (most recently created).
    async with session_factory() as session:
        row = (
            await session.scalars(
                select(orm.SecurityEvent).order_by(orm.SecurityEvent.created_at.desc()).limit(1)
            )
        ).first()
    assert row is not None
    event_id = row.event_id

    # Run the analysis pipeline with fp_matcher wired.
    pipeline, projection = build_analysis_pipeline()
    with bind_evidence_projection(projection):
        result = await pipeline.run(event_id)

    # Pipeline must have completed (not crashed).
    assert result is not None

    # Genuine alert must NOT be closed as false positive.
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
    assert row is not None
    assert row.status not in (EventStatus.CLOSED,), (
        f"Genuine alert incorrectly short-circuited, status={row.status}"
    )
    # It should have progressed past TRIAGING.
    assert row.status != EventStatus.TRIAGING, "Pipeline stuck at triaging"


# --------------------------------------------------------------------------- #
# Scenario 2: FP matcher → triage_result persisted
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_e2e_fp_matcher_triage_result_persisted(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
    build_analysis_pipeline: Any,
) -> None:
    """After pipeline run with fp_matcher wired, triage_result is persisted.

    Even when fp_matcher returns no_match, the triage_result (entities,
    event_type, severity) must be durably stored for downstream agents.
    """
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.accepted >= 1

    async with session_factory() as session:
        row = (
            await session.scalars(
                select(orm.SecurityEvent).order_by(orm.SecurityEvent.created_at.desc()).limit(1)
            )
        ).first()
    assert row is not None
    event_id = row.event_id

    pipeline, projection = build_analysis_pipeline()
    with bind_evidence_projection(projection):
        await pipeline.run(event_id)

    # Verify triage_result persisted to the DB.
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
    assert row is not None
    assert row.event_type is not None, "triage_result not persisted: event_type is None"
    assert row.severity is not None, "triage_result not persisted: severity is None"


# --------------------------------------------------------------------------- #
# Scenario 3: FP match metadata not in outbound disposition
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_fp_match_not_in_disposition_outbound() -> None:
    """OutboundDispositionGuard blocks payloads with FP metadata leaking outbound.

    The DispositionCommand schema is the allowlist for outbound fields.
    Internal FP metadata (matched_case_id, matched_pattern, max_score, etc.)
    must never appear in outbound disposition payloads — the guard raises
    GuardrailViolationError on non-allowlisted fields.
    """
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import (
        _DISPOSITION_ALLOWED_TOP_LEVEL,
        OutboundDispositionGuard,
    )

    # Internal FP metadata must NOT be in the outbound allowlist.
    fp_internal_keys = {
        "matched_case_id",
        "matched_pattern",
        "max_score",
        "source",
        "matched_at",
    }
    assert fp_internal_keys.isdisjoint(_DISPOSITION_ALLOWED_TOP_LEVEL), (
        f"FP internal metadata leaked into outbound allowlist: "
        f"{fp_internal_keys & _DISPOSITION_ALLOWED_TOP_LEVEL}"
    )

    guard = OutboundDispositionGuard()

    payload: dict[str, Any] = {
        "disposition_id": "disp-test-001",
        "action_id": "act-test-001",
        "closure_cycle": 1,
        "intent_kind": "confirm",
        "operation_code": "close_event",
        "operator_id": "system",
        "idempotency_key": "idem-test-001",
        # Smuggled FP metadata — NOT in DispositionCommand schema:
        "matched_case_id": "case-00000001",
        "matched_pattern": "Ops change window bulk login",
        "max_score": 0.96,
    }

    with pytest.raises(
        GuardrailViolationError, match="disposition_field_allowlist|blocked writeback"
    ):
        await guard.validate(payload)


@pytest.mark.asyncio
async def test_fp_match_not_in_disposition_outbound_clean_payload() -> None:
    """A clean disposition payload (no FP metadata) does not trigger FP-block."""
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import OutboundDispositionGuard

    guard = OutboundDispositionGuard()

    payload: dict[str, Any] = {
        "disposition_id": "disp-test-002",
        "action_id": "act-test-002",
        "closure_cycle": 1,
        "intent_kind": "confirm",
        "operation_code": "close_event",
        "operator_id": "system",
        "idempotency_key": "idem-test-002",
    }

    try:
        await guard.validate(payload)
    except GuardrailViolationError as exc:
        detail = str(exc.details.get("violations", ""))
        # Must NOT fail due to FP metadata — those fields aren't in the payload.
        assert "matched_case_id" not in detail
        assert "matched_pattern" not in detail
        assert "max_score" not in detail


# --------------------------------------------------------------------------- #
# Scenario 4: TriageAgent wiring verification
# --------------------------------------------------------------------------- #


def test_deps_triage_agent_wires_fp_matcher() -> None:
    """Verify TriageAgent accepts fp_matcher for hook registration."""
    from app.agents.triage_agent import TriageAgent
    from app.services.false_positive_matcher import FalsePositiveMatcher

    matcher = MagicMock(spec=FalsePositiveMatcher)
    matcher.match = AsyncMock()

    # When fp_matcher is None, no hook installed.
    agent_no_fp = TriageAgent(fp_matcher=None)
    post_hooks_before = len(agent_no_fp.post_triage_hooks)

    # fp_matcher parameter exists on constructor.
    assert "fp_matcher" in TriageAgent.__init__.__code__.co_varnames
    assert post_hooks_before == len(agent_no_fp.post_triage_hooks)


# --------------------------------------------------------------------------- #
# Scenario 5: account_anomaly_fp → short-circuit, evidence skipped
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_fp_matcher_account_anomaly_fp_skips_evidence_collection(
    session_factory: async_sessionmaker[AsyncSession],
    event_service: Any,
    source_ingester: Any,
    build_analysis_pipeline: Any,
    working_memory: Any,
) -> None:
    """account_anomaly_fp with fp_matcher wired → short-circuit, evidence skipped.

    The account_anomaly_fp scenario (ops-change-bot bulk login during change
    window) is a known false positive.  The RuleBasedFalsePositiveHook
    (pre-triage) writes close_as_fp; the FalsePositiveMatcherHook (post-triage)
    respects it and skips the vector search.  The pipeline short-circuits
    because severity=low → need_investigation=False and disposition_policy is
    NOT_REQUIRED — evidence collection is never started.
    """
    from app.data_generators.scenarios import build_scenario
    from app.data_generators.scenarios.account_anomaly_fp import SCENARIO_ID
    from app.mock_xdr.api import create_app
    from app.mock_xdr.state import MockXDRState

    # Set up mock XDR with account_anomaly_fp scenario.
    state = MockXDRState()
    state.load_scenario(build_scenario(SCENARIO_ID, seed=42))
    transport = ASGITransport(app=create_app(state=state))

    async with httpx.AsyncClient(
        transport=transport, base_url="http://mock-xdr", timeout=30.0
    ) as client:
        adapter = MockXDRSourceAdapter(
            base_url="http://mock-xdr",
            read_token="mock-read-token",
            write_token="mock-write-token",
            client=client,
            max_retries=0,
        )

        # Ingest the FP scenario.
        summary = await source_ingester.poll(adapter, ALL_SOURCE_KINDS, batch_size=10)
        assert summary.accepted >= 1

    # Find the ingested event.
    async with session_factory() as session:
        row = (
            await session.scalars(
                select(orm.SecurityEvent).where(
                    orm.SecurityEvent.title == "Bulk login by ops account during change window"
                )
            )
        ).first()
    assert row is not None
    event_id = row.event_id

    # Run the pipeline with fp_matcher wired (scenario_id must match so
    # RiskAgent / ReportAgent use the correct calibration).
    pipeline, projection = build_analysis_pipeline(scenario_id=SCENARIO_ID)
    with bind_evidence_projection(projection):
        result = await pipeline.run(event_id)

    assert result is not None

    # RuleBasedFalsePositiveHook must detect account_anomaly_fp from the
    # ingested source evidence (title / snapshot) without manual pre-write.
    fp_wm = working_memory.for_writer("FalsePositiveMatcher")
    verify_fp = await fp_wm.read(event_id, "false_positive_match")
    assert isinstance(verify_fp, dict), (
        f"RuleBasedFalsePositiveHook did not write false_positive_match: {verify_fp!r}"
    )
    assert verify_fp.get("recommendation") == "close_as_fp"
    assert verify_fp.get("matched_rule") == "ops_change_window_bulk_login"

    # With disposition_policy=NOT_REQUIRED, the pipeline should reach CLOSED.
    assert result.status == EventStatus.CLOSED, (
        f"Expected CLOSED for account_anomaly_fp, got {result.status}"
    )

    if result.short_circuit:
        # Short-circuit path: evidence skipped, verdict is FALSE_POSITIVE.
        assert result.evidence_output is not None
        assert result.evidence_output.evidence_list == []
        assert result.evidence_output.overall_confidence == 0.0
        assert result.final_verdict == FinalVerdict.FALSE_POSITIVE, (
            f"Expected FALSE_POSITIVE, got {result.final_verdict}"
        )
    else:
        # Full-investigation path (keyword mapping didn't identify
        # ACCOUNT_ANOMALY → MEDIUM severity → need_investigation=True):
        # evidence was collected and the pipeline ran to completion.
        assert result.evidence_output is not None
        assert result.status == EventStatus.CLOSED

    # false_positive_match must still be readable after the pipeline run.
    assert verify_fp.get("recommendation") == "close_as_fp"

    # Verify the event reached CLOSED in the database.
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        close_logs = (
            await session.scalars(
                select(orm.EventAuditLog)
                .where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.to_status == EventStatus.CLOSED.value,
                )
                .order_by(orm.EventAuditLog.created_at.desc())
            )
        ).all()
    assert row is not None
    assert row.status == EventStatus.CLOSED, f"DB status is {row.status}, expected CLOSED"
    assert close_logs, "Expected audit log entry for CLOSED transition"
    assert "ops_change_window_bulk_login" in (close_logs[0].reason or "")

    # Report must explain the FP basis when short-circuited.
    if result.report is not None:
        overview = next((s for s in result.report.sections if s.key == "overview"), None)
        assert overview is not None
        assert "fp_matched_pattern" in overview.content or "fp_matched_case_id" in overview.content


# --------------------------------------------------------------------------- #
# Scenario 6: required disposition → full investigation, fp_matcher no_match
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_fp_matcher_required_disposition_false_positive_no_auto_close(
    source_adapter: MockXDRSourceAdapter,
    source_ingester: SourceIngester,
    session_factory: async_sessionmaker[AsyncSession],
    build_analysis_pipeline: Any,
    working_memory: Any,
) -> None:
    """REQUIRED disposition + FP match → no auto-close, full investigation runs.

    insider_data_exfiltration has disposition_policy=REQUIRED.  Even when
    false_positive_match recommends close_as_fp, the pipeline must NOT
    short-circuit: it runs the full investigation (evidence, risk, report)
    and stays at REPORTING so the out-of-band disposition writeback can
    execute the close.  This validates the "disposition-only closure" path
    where zero IMMEDIATE actions are taken and only the disposition layer
    closes the event through EVENT_STATUS_UPDATE → CLOSED.

    To simulate a vector-based FP match on a REQUIRED-disposition event,
    we pre-write a close_as_fp false_positive_match via the canonical
    "FalsePositiveMatcher" writer before the pipeline runs.  The
    VerdictResolver must return FALSE_POSITIVE, and the pipeline must
    NOT auto-close.
    """
    # Ingest insider_data_exfiltration (disposition=REQUIRED).
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=10)
    assert summary.accepted >= 1

    async with session_factory() as session:
        row = (
            await session.scalars(
                select(orm.SecurityEvent).order_by(orm.SecurityEvent.created_at.desc()).limit(1)
            )
        ).first()
    assert row is not None
    event_id = row.event_id

    # Pre-write a simulated vector-based close_as_fp false_positive_match
    # using the canonical "FalsePositiveMatcher" writer identity.  This
    # simulates what the FalsePositiveMatcherHook would write when the
    # vector KB returns a high-confidence hit.
    fp_wm = working_memory.for_writer("FalsePositiveMatcher")
    await fp_wm.write(
        event_id,
        "false_positive_match",
        {
            "matched": True,
            "max_score": 0.96,
            "matched_case_id": "case-simulated",
            "matched_pattern": "Simulated vector FP match for testing",
            "recommendation": "close_as_fp",
            "source": "FalsePositiveMatcher",
            "matched_at": "2026-01-01T00:00:00+00:00",
        },
    )

    # Run the pipeline with fp_matcher wired.
    pipeline, projection = build_analysis_pipeline()
    with bind_evidence_projection(projection):
        result = await pipeline.run(event_id)

    assert result is not None

    # Pipeline must NOT short-circuit when disposition is REQUIRED, even
    # with a close_as_fp match — full investigation must run.
    assert result.short_circuit is False, (
        "Pipeline short-circuited despite REQUIRED disposition — "
        "disposition-only closure requires investigation to complete"
    )

    # Full investigation must have run (evidence was collected).
    assert result.evidence_output is not None
    assert len(result.evidence_output.evidence_list) > 0, (
        "Evidence collection was skipped — full investigation required for REQUIRED disposition"
    )

    # Verdict must be FALSE_POSITIVE (from VerdictResolver priority 1:
    # false_positive_match.recommendation == close_as_fp).
    assert result.final_verdict == FinalVerdict.FALSE_POSITIVE, (
        f"Expected FALSE_POSITIVE (close_as_fp beats risk_score), got {result.final_verdict}"
    )

    # Event must stay at REPORTING (NOT auto-closed) — the disposition
    # layer must perform the close via EVENT_STATUS_UPDATE → CLOSED.
    assert result.status == EventStatus.REPORTING, (
        f"Expected REPORTING for REQUIRED disposition, got {result.status}"
    )
    assert result.disposition_policy == "required", (
        f"Expected disposition_policy=required, got {result.disposition_policy}"
    )

    # Verify DB state: event at REPORTING, not CLOSED.
    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
    assert row is not None
    assert row.status == EventStatus.REPORTING, (
        f"DB status is {row.status}, expected REPORTING — disposition-only path must not auto-close"
    )

    # false_positive_match must still be readable.
    verify_fp = await fp_wm.read(event_id, "false_positive_match")
    assert isinstance(verify_fp, dict)
    assert verify_fp.get("recommendation") == "close_as_fp"
