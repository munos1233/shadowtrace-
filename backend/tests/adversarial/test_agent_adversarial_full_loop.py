"""Adversarial production full loop through SuperAgent graph and disposition writeback.

Uses production ``execute_investigation(include_response_execution=True)`` wiring.
Does **not** inject APPROVED actions via ``run_full_response_chain`` or verify-tail shims.

ISSUE-203 quality gates (hard failures):
- Terminal ``REPORTING``/``CLOSED`` with non-empty report
- ``response_agent``/``verify_agent`` traces (snake_case agent_name)
- Response plan targets cover ``GROUND_TRUTH.must_response_targets``
- Mock writeback ``CONFIRMED(readback_verified)`` + terminal outbox enqueued
- ``shims_used`` must be empty (ISSUE-204: no runner hooks or sunset shims).

Default runner timeout: ~120s (Mock). Override with ``ADVERSARIAL_FULL_LOOP_TIMEOUT_S``
(Live ``LLM_MODE=openai_compatible`` defaults to 600s unless overridden).

    cd backend
    export DATABASE_URL=postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace
    export REDIS_URL=redis://localhost:6379/0
    uv run --frozen python -m pytest \\
        tests/adversarial/test_agent_adversarial_full_loop.py -m adversarial_audit -v -s

Artifact: ``tests/adversarial/artifacts/latest_full_loop_audit.json``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import EventStatus
from app.services.context_service import EventContextStore
from app.services.event_service import EventService
from tests.adversarial.audit_report import (
    AdversarialAuditChecks,
    collect_entity_tokens,
    normalize_enum,
)
from tests.adversarial.full_loop_runner import run_production_full_loop
from tests.adversarial.helpers import ingest_true_positive_event, missing_response_targets
from tests.adversarial.scenario_credential_db_staging_exfil import GROUND_TRUTH

pytestmark = [pytest.mark.integration, pytest.mark.adversarial_audit]

ARTIFACT_PATH = Path(__file__).resolve().parent / "artifacts" / "latest_full_loop_audit.json"


async def _audit_status_sequence(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> list[str]:
    async with session_factory() as session:
        rows = list(
            await session.scalars(
                select(orm.EventAuditLog)
                .where(
                    orm.EventAuditLog.event_id == event_id,
                    orm.EventAuditLog.to_status.is_not(None),
                )
                .order_by(orm.EventAuditLog.created_at.asc(), orm.EventAuditLog.id.asc())
            )
        )
    return [row.to_status for row in rows if row.to_status]


def _report_excerpt(report_ctx: dict[str, Any]) -> str:
    title = str(report_ctx.get("title") or "")
    summary = str(report_ctx.get("summary") or "")
    return (title + "\n" + summary).strip()[:1200]


@pytest.mark.usefixtures("clean_state")
@pytest.mark.asyncio
async def test_adversarial_noisy_production_full_response_closed_loop(
    monkeypatch: pytest.MonkeyPatch,
    adversarial_source_adapter,
    source_ingester,
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
    redis_client,
    context_store: EventContextStore,
    e2e_tool_executor,
    adversarial_disposition_sync_service,
    adversarial_event_disposition_service,
) -> None:
    """Ingest noisy mock XDR data, run production full loop, audit all subsystems."""
    event_id = await ingest_true_positive_event(
        adversarial_source_adapter,
        source_ingester,
        event_service,
    )

    event_before = await event_service.get_event(event_id)
    assert event_before is not None
    new_events = await event_service.list_events(status=EventStatus.NEW)
    print(
        f"\n[adversarial-full-loop] target event_id={event_id} "
        f"title={event_before.title!r} NEW queue={new_events.total}"
    )

    loop_result = await run_production_full_loop(
        monkeypatch=monkeypatch,
        session_factory=session_factory,
        redis_client=redis_client,
        event_service=event_service,
        context_store=context_store,
        adversarial_disposition_sync_service=adversarial_disposition_sync_service,
        adversarial_event_disposition_service=adversarial_event_disposition_service,
        e2e_tool_executor=e2e_tool_executor,
        event_id=event_id,
    )
    print(
        f"[adversarial-full-loop] production loop finished in {loop_result.elapsed_s:.1f}s "
        f"status={loop_result.investigate_status!r} approvals={loop_result.approval_rounds}"
    )

    event_final = await event_service.get_event(event_id)
    assert event_final is not None

    triage_ctx = await context_store.get(event_id, "triage_result") or {}
    evidence_ctx = await context_store.get(event_id, "evidence_output") or {}
    report_ctx = await context_store.get(event_id, "report") or {}
    status_sequence = await _audit_status_sequence(session_factory, event_id)
    disposition_gaps = missing_response_targets(
        ground_truth=GROUND_TRUTH,
        actions=list(loop_result.response_plan_actions),
    )

    token_sources: list[Any] = [
        triage_ctx,
        evidence_ctx,
        report_ctx,
        event_final.model_dump(mode="json"),
    ]
    tokens = collect_entity_tokens(token_sources)
    joined = "\n".join(tokens).lower()
    entities_found = [e for e in GROUND_TRUTH["must_identify_entities"] if e.lower() in joined]
    indicators_found = [i for i in GROUND_TRUTH["must_identify_indicators"] if i.lower() in joined]

    async with session_factory() as session:
        action_count = await session.scalar(
            select(func.count()).select_from(orm.Action).where(orm.Action.event_id == event_id)
        )

    checks = AdversarialAuditChecks(
        ground_truth=GROUND_TRUTH,
        event_type=normalize_enum(triage_ctx.get("event_type") or event_final.event_type),
        severity=normalize_enum(triage_ctx.get("severity") or event_final.severity),
        risk_score=int(event_final.risk_score or 0),
        final_verdict=normalize_enum(event_final.final_verdict),
        entities_found=entities_found,
        indicators_found=indicators_found,
        report_excerpt=_report_excerpt(report_ctx),
        triage_summary=str(triage_ctx.get("decision_summary") or ""),
        evidence_collection_status=str(
            evidence_ctx.get("collection_status") or evidence_ctx.get("status") or ""
        ),
        status_sequence=status_sequence,
    )
    report = checks.to_dict()
    obs = loop_result.observability
    report["full_loop"] = {
        "mode": "production_graph",
        "elapsed_s": round(loop_result.elapsed_s, 2),
        "investigate_status": loop_result.investigate_status,
        "terminal_status": event_final.status.value,
        "approval_rounds": loop_result.approval_rounds,
        "approved_action_ids": list(loop_result.approved_action_ids),
        "approval_records": loop_result.approval_records,
        "response_plan_present": loop_result.response_plan_present,
        "response_plan_actions": list(loop_result.response_plan_actions),
        "response_agent_traced": loop_result.response_agent_traced,
        "verification_present": loop_result.verification_present,
        "verify_agent_traced": loop_result.verify_agent_traced,
        "writeback_confirmed": loop_result.writeback_confirmed,
        "terminal_outbox_enqueued": loop_result.terminal_outbox_enqueued,
        "response_actions_present": int(action_count or 0) > 0,
        "tool_call_count": loop_result.tool_call_count,
        "llm_call_count": loop_result.llm_call_count,
        "agent_trace_count": obs.agent_trace_count,
        "disposition_outbox_count": obs.disposition_outbox_count,
        "execution_job_count": obs.execution_job_count,
        "execution_ran": loop_result.execution_ran,
        "resume_attempts": loop_result.resume_attempts,
        "shims_used": list(loop_result.shims_used),
        "disposition_target_gaps": disposition_gaps,
        "status_sequence_includes_closed": EventStatus.CLOSED.value in status_sequence,
        "status_sequence_includes_reporting": EventStatus.REPORTING.value in status_sequence,
        "status_sequence_includes_planning": EventStatus.PLANNING_RESPONSE.value in status_sequence,
        "status_sequence_includes_waiting_approval": EventStatus.WAITING_APPROVAL.value
        in status_sequence,
        "status_sequence_includes_executing": EventStatus.EXECUTING_RESPONSE.value
        in status_sequence,
        "status_sequence_includes_verifying": EventStatus.VERIFYING.value in status_sequence,
        "notes": loop_result.notes,
    }
    report["production_checks"] = {
        "response_agent_ran": loop_result.response_agent_traced,
        "approval_flow_ran": loop_result.approval_records > 0 or loop_result.approval_rounds > 0,
        "execution_ran": loop_result.execution_ran,
        "verify_agent_ran": loop_result.verify_agent_traced,
        "verify_agent_traced": loop_result.verify_agent_traced,
        "verification_context_present": loop_result.verification_present,
        "disposition_writeback_ok": loop_result.writeback_confirmed,
        "disposition_targets_aligned": not disposition_gaps,
        "no_test_shims": len(loop_result.shims_used) == 0,
        "tools_invoked": loop_result.tool_call_count > 0,
        "llm_invoked": loop_result.llm_call_count > 0,
    }
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("\n[adversarial-full-loop] human verdict:", report["verdict_for_human"])
    print(
        "[adversarial-full-loop] production_checks:",
        json.dumps(report["production_checks"], indent=2),
    )
    print("[adversarial-full-loop] full_loop:", json.dumps(report["full_loop"], indent=2))
    print(f"[adversarial-full-loop] artifact → {ARTIFACT_PATH}")

    prod = report["production_checks"]
    assert prod["no_test_shims"], (
        f"ISSUE-204: shims_used must be empty, got {loop_result.shims_used}"
    )
    assert prod["response_agent_ran"], "expected response_agent trace"
    assert prod["execution_ran"], "expected ActionExecution jobs after approval"
    assert prod["verify_agent_ran"], "expected verify_agent trace"
    assert prod["disposition_targets_aligned"], (
        f"ISSUE-198: response plan must cover GROUND_TRUTH targets; missing={disposition_gaps}"
    )
    assert prod["tools_invoked"], "expected tool_call_log rows from evidence/verify/execute"
    assert prod["llm_invoked"], "expected llm_call_log rows from live/mock LLM agents"
    assert prod["disposition_writeback_ok"], (
        "expected CONFIRMED+readback_verified disposition receipt on Mock path"
    )
    assert loop_result.terminal_outbox_enqueued, "expected terminal EVENT_STATUS_UPDATE outbox row"
    assert event_final.status in {
        EventStatus.REPORTING,
        EventStatus.CLOSED,
    }
    assert _report_excerpt(report_ctx).strip(), (
        "ISSUE-196: full loop must reach REPORTING/CLOSED with non-empty report"
    )
    assert EventStatus.EXECUTING_RESPONSE.value in status_sequence, (
        "expected audited transition through executing_response"
    )
    assert (
        report["checks"]["verdict_matches_expected"]
        or report["checks"]["risk_score_at_least_minimum"]
    )
