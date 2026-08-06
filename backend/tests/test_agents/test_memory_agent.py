"""MemoryAgent knowledge-consolidation tests (ISSUE-080)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import yaml

from app.agents.memory_agent import MemoryAgent
from app.agents.super_agent import SuperAgent
from app.models.agent_io import InvestigationResult, MemoryAgentInput
from app.models.case import HistoryCase
from app.models.context import EventContext
from app.models.enums import (
    CaseLabel,
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    WritebackReadiness,
)
from app.models.memory import MemoryCandidate
from app.models.report import InvestigationReport
from app.models.security_event import EventSummary
from app.services.case_kb_service import _response_succeeded
from app.services.profile_service import profile_id_for

EVENT_ID = "evt-memory-0001"


class _DegradedFlags:
    def __init__(self) -> None:
        self.flags: list[tuple[str, str, object, str]] = []

    async def set_flag(
        self,
        event_id: str,
        flag_name: str,
        value: object,
        writer: str,
    ) -> list[str]:
        self.flags.append((event_id, flag_name, value, writer))
        return [f"{flag_name}={value}"]


class _CaseKB:
    def __init__(self, *, fail: bool = False, ineligible: bool = False) -> None:
        self.fail = fail
        self.ineligible = ineligible
        self.archived: list[str] = []

    async def prepare_history_case(self, event_id: str) -> HistoryCase:
        if self.fail:
            raise RuntimeError("case archive unavailable")
        if self.ineligible:
            raise ValueError("event is not eligible for history_case_kb")
        self.archived.append(event_id)
        return HistoryCase(
            case_id="case-acde1234",
            event_id=event_id,
            event_type=EventType.DATA_EXFILTRATION,
            case_label=CaseLabel.TRUE_POSITIVE,
            summary="Evidence confirms a WebDAV upload.",
            key_entities="account=zhangsan",
            final_verdict=FinalVerdict.CONFIRMED_THREAT.value,
            risk_score=88,
            resolution="closed",
        )


class _Profiles:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.updates: list[Any] = []

    async def upsert(self, update: Any) -> None:
        if self.fail:
            raise RuntimeError("profile store unavailable")
        self.updates.append(update)


class _Governance:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.candidates: list[MemoryCandidate] = []
        self.maintenance: list[tuple[str, str]] = []
        self.fallback_candidates: list[MemoryCandidate] = []

    async def ingest_candidate(self, candidate: MemoryCandidate) -> str:
        self.candidates.append(candidate)
        if self.fail:
            raise RuntimeError("review queue unavailable")
        return f"rev-{len(self.candidates):08x}"

    async def persist_pending_fallback(self, candidate: MemoryCandidate) -> str:
        self.fallback_candidates.append(candidate)
        if self.fail:
            raise RuntimeError("review fallback unavailable")
        return "rev-fallback"

    async def dedupe(self, kb_name: str) -> int:
        self.maintenance.append(("dedupe", kb_name))
        return 0

    async def resolve_conflict(self, kb_name: str, key: str) -> None:
        self.maintenance.append(("resolve", f"{kb_name}:{key}"))

    async def apply_retention(self, kb_name: str) -> int:
        self.maintenance.append(("retention", kb_name))
        return 0

    def fingerprint(self, candidate: MemoryCandidate) -> str:
        return f"{candidate.candidate_type}:fingerprint"


class _ContextStore:
    def __init__(self, context: EventContext) -> None:
        self.context = context
        self.refresh_count = 0

    async def get_full_context(self, event_id: str) -> EventContext:
        assert event_id == EVENT_ID
        return self.context

    async def refresh_closed_snapshot(self, event_id: str) -> EventContext:
        assert event_id == EVENT_ID
        self.refresh_count += 1
        return self.context


class _WorkingMemory:
    def __init__(self, context: EventContext) -> None:
        self.context = context
        self.writes: list[tuple[str, str, Any]] = []

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.writes.append((event_id, key, value))
        # Only the canonical key maps onto EventContext.memory_output; ISSUE-208
        # early-pass key ("memory_output_early") must not mark full consolidation.
        if key == "memory_output":
            self.context.memory_output = value
        elif key == "memory_output_early":
            self.context.memory_output_early = value


class _UnavailableLLM:
    async def chat(self, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("LLM unavailable")


class _FailingMemoryAgent:
    async def execute(self, _input: MemoryAgentInput) -> None:
        raise RuntimeError("memory failed")


class _SuccessfulMemoryAgent:
    def __init__(self) -> None:
        self.inputs: list[MemoryAgentInput] = []

    async def execute(self, input: MemoryAgentInput) -> None:
        self.inputs.append(input)


class _BlockingMemoryAgent:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(self, _input: MemoryAgentInput) -> None:
        self.started.set()
        await self.release.wait()


class _Audit:
    def __init__(self) -> None:
        self.entries: list[tuple[Any, ...]] = []

    async def log_transition(self, *args: Any) -> str:
        self.entries.append(args)
        return "audit-1"


def _context(
    verdict: FinalVerdict,
    *,
    external_unsynced: bool = False,
    status: EventStatus = EventStatus.CLOSED,
    analysis_only_complete: bool = False,
    with_report: bool = True,
) -> EventContext:
    return EventContext(
        event=EventSummary(
            event_id=EVENT_ID,
            event_type=EventType.DATA_EXFILTRATION,
            title="Suspicious upload by zhangsan",
            status=status,
            severity=Severity.HIGH,
            risk_score=88,
            final_verdict=verdict,
            writeback_required=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            disposition_policy=DispositionPolicy.NOT_REQUIRED,
            external_unsynced=external_unsynced,
        ),
        graph_output={
            "nodes": [
                {
                    "node_id": "node-account",
                    "event_id": EVENT_ID,
                    "entity_type": "account",
                    "entity_value": "zhangsan",
                    "properties": {},
                }
            ],
            "edges": [],
            "central_entities": ["zhangsan"],
            "attack_path_candidates": [],
        },
        storyline={
            "storyline_id": "story-1",
            "event_id": EVENT_ID,
            "narrative_summary": "Credential use followed by upload.",
            "phases": [
                {
                    "phase_order": 1,
                    "phase_name": "initial_access",
                    "narrative": "Account access",
                    "entries": [],
                }
            ],
            "generated_by": "rule",
        },
        evidence_output={
            "evidence_list": [
                {
                    "evidence_id": "evd-1",
                    "event_id": EVENT_ID,
                    "source": "xdr",
                    "evidence_type": "process_execution",
                    "description": "WebDAV upload",
                    "confidence": 0.95,
                    "related_entities": ["zhangsan"],
                    "raw_data": {},
                    "mitre_technique": "T1048",
                    "is_conflicting": False,
                }
            ],
            "conflicts": [],
            "gaps": [],
            "success_sources": ["xdr"],
            "failed_sources": [],
            "overall_confidence": 0.95,
            "collection_status": "complete",
        },
        report=(
            InvestigationReport(
                report_id="rpt-memory-1",
                event_id=EVENT_ID,
                title="Confirmed exfiltration",
                summary="Evidence confirms a WebDAV upload.",
                final_verdict=verdict,
                risk_score=88,
                severity=Severity.HIGH,
            )
            if with_report
            else None
        ),
        analysis_only_complete=analysis_only_complete,
    )


def _input(
    verdict: FinalVerdict,
    *,
    external_unsynced: bool = False,
    final_status: EventStatus = EventStatus.CLOSED,
) -> MemoryAgentInput:
    return MemoryAgentInput(
        event_id=EVENT_ID,
        investigation_result=InvestigationResult(
            event_id=EVENT_ID,
            final_status=final_status,
            final_verdict=verdict,
            external_unsynced=external_unsynced,
            writeback_required=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        ),
    )


@pytest.mark.asyncio
async def test_confirmed_threat_archives_case_updates_profile_and_builds_sigma() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    cases = _CaseKB()
    profiles = _Profiles()
    governance = _Governance()
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=cases,  # type: ignore[arg-type]
        profile_service=profiles,  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert cases.archived == [EVENT_ID]
    assert output.case_records[0].archived is False
    assert output.case_records[0].pending_review is True
    assert output.case_records[0].review_id == "rev-00000001"
    assert profiles.updates == []
    assert [update.entity_value for update in output.profile_updates] == ["zhangsan"]
    assert output.profile_updates[0].risk_score == 88
    assert output.profile_updates[0].pending_review is True
    assert [candidate.candidate_type for candidate in governance.candidates] == [
        "history_case",
        "profile",
    ]
    assert len(output.sigma_drafts) == 1
    sigma = yaml.safe_load(output.sigma_drafts[0])
    assert EVENT_ID in sigma["title"]
    assert sigma["detection"]["condition"] == "selection"
    assert sigma["detection"]["selection"]["event_id"] == EVENT_ID
    assert memory.writes[0][1] == "memory_output"


@pytest.mark.asyncio
async def test_false_positive_candidate_is_pending_review_with_llm_fallback() -> None:
    context = _context(FinalVerdict.FALSE_POSITIVE)
    governance = _Governance()
    agent = MemoryAgent(
        case_kb_service=_CaseKB(),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=_WorkingMemory(context),
        llm_client=_UnavailableLLM(),
    )

    output = await agent.execute(_input(FinalVerdict.FALSE_POSITIVE))

    assert len(output.fp_rules) == 1
    assert output.fp_rules[0].pending_review is True
    assert output.fp_rules[0].source_event_id == EVENT_ID
    assert output.fp_rules[0].review_id == "rev-00000002"
    assert output.sigma_drafts == []
    assert [candidate.candidate_type for candidate in governance.candidates] == [
        "history_case",
        "fp_rule",
        "profile",
    ]


@pytest.mark.asyncio
async def test_individual_persistence_failures_degrade_without_losing_memory_output() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    memory = _WorkingMemory(context)
    governance = _Governance(fail=True)
    agent = MemoryAgent(
        case_kb_service=_CaseKB(fail=True),  # type: ignore[arg-type]
        profile_service=_Profiles(fail=True),  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert output.case_records == []
    assert len(output.profile_updates) == 1
    assert output.profile_updates[0].review_id is None
    assert output.profile_updates[0].pending_review is False
    assert len(governance.fallback_candidates) == 1
    assert len(output.sigma_drafts) == 1
    assert memory.writes


@pytest.mark.asyncio
async def test_enqueue_failure_records_degraded_flag() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    memory = _WorkingMemory(context)
    governance = _Governance(fail=True)
    degraded = _DegradedFlags()
    agent = MemoryAgent(
        case_kb_service=_CaseKB(fail=True),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
        degraded_flags=degraded,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert output.profile_updates[0].pending_review is False
    assert degraded.flags == [
        (EVENT_ID, "memory_review_enqueue_failed", "profile", "MemoryAgent"),
    ]


@pytest.mark.asyncio
async def test_governance_maintenance_failure_records_degraded_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(FinalVerdict.FALSE_POSITIVE)
    memory = _WorkingMemory(context)
    governance = _Governance()
    degraded = _DegradedFlags()

    async def fail_dedupe(_kb_name: str) -> int:
        raise RuntimeError("dedupe unavailable")

    monkeypatch.setattr(governance, "dedupe", fail_dedupe)
    agent = MemoryAgent(
        case_kb_service=_CaseKB(),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
        degraded_flags=degraded,
        llm_client=_UnavailableLLM(),
    )

    await agent.execute(_input(FinalVerdict.FALSE_POSITIVE))

    assert any(
        flag_name == "memory_governance_maintenance_failed"
        for _, flag_name, _, writer in degraded.flags
        if writer == "MemoryAgent"
    )


@pytest.mark.asyncio
async def test_ineligible_case_uses_info_log_without_hiding_other_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    memory = _WorkingMemory(context)
    info_calls: list[tuple[Any, ...]] = []
    warning_calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        "app.agents.memory_agent.logger.info",
        lambda *args, **_kwargs: info_calls.append(args),
    )
    monkeypatch.setattr(
        "app.agents.memory_agent.logger.warning",
        lambda *args, **_kwargs: warning_calls.append(args),
    )
    agent = MemoryAgent(
        case_kb_service=_CaseKB(ineligible=True),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=_Governance(),  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert output.case_records == []
    assert output.profile_updates
    assert output.sigma_drafts
    assert "case archival ineligible" in info_calls[0][0]
    assert warning_calls == []


@pytest.mark.asyncio
async def test_external_unsynced_skips_all_consolidation() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT, external_unsynced=True)
    cases = _CaseKB()
    profiles = _Profiles()
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=cases,  # type: ignore[arg-type]
        profile_service=profiles,  # type: ignore[arg-type]
        memory_governance=_Governance(),  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT, external_unsynced=True))

    assert output.case_records == []
    assert output.fp_rules == []
    assert output.profile_updates == []
    assert output.sigma_drafts == []
    assert cases.archived == []
    assert profiles.updates == []
    assert memory.writes[0][2] == output.model_dump(mode="json")


@pytest.mark.asyncio
async def test_memory_failure_keeps_event_closed_and_records_audit() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context_store = _ContextStore(context)
    audit = _Audit()
    super_agent = SuperAgent(
        memory_agent=_FailingMemoryAgent(),
        context_store=context_store,
        audit_service=audit,
    )

    task = await super_agent._schedule_memory_after_close(EVENT_ID, context)
    assert task is not None
    await task

    assert context.event is not None
    assert context.event.status is EventStatus.CLOSED
    assert context_store.refresh_count == 1
    assert len(audit.entries) == 1
    _, from_status, to_status, operator, reason = audit.entries[0]
    assert from_status == to_status == EventStatus.CLOSED.value
    assert operator == "MemoryAgent"
    assert "memory_agent_failed:consolidation" in reason


@pytest.mark.asyncio
async def test_schedule_memory_skipped_when_event_not_closed() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context.event.status = EventStatus.ANALYZING  # type: ignore[union-attr]
    context_store = _ContextStore(context)
    memory_agent = _SuccessfulMemoryAgent()
    super_agent = SuperAgent(
        memory_agent=memory_agent,
        context_store=context_store,
    )

    task = await super_agent._schedule_memory_after_close(EVENT_ID, context)

    assert task is None
    assert memory_agent.inputs == []
    assert context_store.refresh_count == 0


class _RefreshFailAfterFirstContextStore(_ContextStore):
    async def refresh_closed_snapshot(self, event_id: str) -> EventContext:
        self.refresh_count += 1
        if self.refresh_count >= 2:
            raise RuntimeError("snapshot refresh unavailable")
        return self.context


@pytest.mark.asyncio
async def test_snapshot_refresh_failure_after_memory_success_is_audited() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context_store = _RefreshFailAfterFirstContextStore(context)
    audit = _Audit()
    super_agent = SuperAgent(
        memory_agent=_SuccessfulMemoryAgent(),
        context_store=context_store,
        audit_service=audit,
    )

    task = await super_agent._schedule_memory_after_close(EVENT_ID, context)
    assert task is not None
    await task

    assert context_store.refresh_count == 2
    assert len(audit.entries) == 1
    assert "memory_agent_failed:snapshot_refresh" in audit.entries[0][4]


@pytest.mark.asyncio
async def test_successful_post_close_hook_refreshes_snapshot() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context_store = _ContextStore(context)
    memory_agent = _SuccessfulMemoryAgent()
    super_agent = SuperAgent(
        memory_agent=memory_agent,
        context_store=context_store,
    )

    task = await super_agent._schedule_memory_after_close(EVENT_ID, context)
    assert task is not None
    await task

    assert len(memory_agent.inputs) == 1
    assert memory_agent.inputs[0].investigation_result.final_status is EventStatus.CLOSED
    assert context_store.refresh_count == 2


@pytest.mark.asyncio
async def test_post_close_hook_runs_memory_without_blocking_caller() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context_store = _ContextStore(context)
    memory_agent = _BlockingMemoryAgent()
    super_agent = SuperAgent(
        memory_agent=memory_agent,
        context_store=context_store,
    )

    task = await super_agent._schedule_memory_after_close(EVENT_ID, context)

    assert task is not None
    await asyncio.wait_for(memory_agent.started.wait(), timeout=1)
    assert not task.done()
    assert context_store.refresh_count == 1

    memory_agent.release.set()
    await asyncio.wait_for(task, timeout=1)
    assert context_store.refresh_count == 2


@pytest.mark.asyncio
async def test_existing_memory_output_makes_replay_idempotent() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context.memory_output = {
        "case_records": [],
        "fp_rules": [],
        "profile_updates": [],
        "sigma_drafts": ["existing"],
    }
    cases = _CaseKB()
    profiles = _Profiles()
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=cases,  # type: ignore[arg-type]
        profile_service=profiles,  # type: ignore[arg-type]
        memory_governance=_Governance(),  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    output = await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))

    assert output.sigma_drafts == ["existing"]
    assert cases.archived == []
    assert profiles.updates == []
    assert memory.writes == []


def test_response_success_requires_verified_effect_and_synchronized_writeback() -> None:
    assert _response_succeeded(
        effect_status="verified",
        writeback_status=None,
        policy=DispositionPolicy.NOT_REQUIRED,
        terminal_confirmed=False,
    )
    assert _response_succeeded(
        effect_status="verified",
        writeback_status="confirmed",
        policy=DispositionPolicy.REQUIRED,
        terminal_confirmed=False,
    )
    assert _response_succeeded(
        effect_status="verified",
        writeback_status=None,
        policy=DispositionPolicy.REQUIRED,
        terminal_confirmed=True,
    )
    assert not _response_succeeded(
        effect_status="pending",
        writeback_status="confirmed",
        policy=DispositionPolicy.REQUIRED,
        terminal_confirmed=True,
    )
    assert not _response_succeeded(
        effect_status="verified",
        writeback_status="accepted",
        policy=DispositionPolicy.REQUIRED,
        terminal_confirmed=False,
    )


def test_profile_id_is_stable_and_case_insensitive() -> None:
    assert profile_id_for("account", "zhangsan").startswith("prf-")
    assert profile_id_for(" Account ", "ZhangSan") == profile_id_for("account", "zhangsan")


# --------------------------------------------------------------------------- #
# ISSUE-208: profile-only early enqueue after analysis completion
# --------------------------------------------------------------------------- #


def _make_agent(
    *,
    context: EventContext,
    early_enqueue_enabled: bool = True,
) -> MemoryAgent:
    return MemoryAgent(
        case_kb_service=_CaseKB(),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=_Governance(),  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=_WorkingMemory(context),
        early_enqueue_enabled=early_enqueue_enabled,
    )


@pytest.mark.asyncio
async def test_reporting_analysis_complete_enqueues_profile_only() -> None:
    context = _context(
        FinalVerdict.CONFIRMED_THREAT,
        status=EventStatus.REPORTING,
        analysis_only_complete=True,
    )
    governance = _Governance()
    agent = MemoryAgent(
        case_kb_service=_CaseKB(),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=_WorkingMemory(context),
    )

    output = await agent.execute(
        _input(FinalVerdict.CONFIRMED_THREAT, final_status=EventStatus.REPORTING)
    )

    # Only profile candidates may be enqueued early (ISSUE-208 gate).
    assert [c.candidate_type for c in governance.candidates] == ["profile"]
    assert output.profile_updates[0].pending_review is True
    # Closure-semantics artifacts stay absent before CLOSED.
    assert output.case_records == []
    assert output.fp_rules == []
    # Sigma draft is a local working-memory artifact (not enqueued), so it may
    # exist for confirmed threats even in the early path.
    assert len(output.sigma_drafts) == 1


@pytest.mark.asyncio
async def test_reporting_without_analysis_complete_raises() -> None:
    context = _context(
        FinalVerdict.CONFIRMED_THREAT,
        status=EventStatus.REPORTING,
        analysis_only_complete=False,
        with_report=False,
    )
    agent = _make_agent(context=context)

    with pytest.raises(ValueError, match="analysis_only_complete or a"):
        await agent.execute(
            _input(FinalVerdict.CONFIRMED_THREAT, final_status=EventStatus.REPORTING)
        )


@pytest.mark.asyncio
async def test_early_enqueue_flag_off_keeps_closed_only_contract() -> None:
    context = _context(
        FinalVerdict.CONFIRMED_THREAT,
        status=EventStatus.REPORTING,
        analysis_only_complete=True,
    )
    agent = _make_agent(context=context, early_enqueue_enabled=False)

    with pytest.raises(ValueError, match="only accepts CLOSED"):
        await agent.execute(
            _input(FinalVerdict.CONFIRMED_THREAT, final_status=EventStatus.REPORTING)
        )


@pytest.mark.asyncio
async def test_closed_still_enqueues_all_types_with_flag_on() -> None:
    # Regression: with early enqueue enabled, CLOSED keeps the full contract
    # (history_case + fp_rule + profile), not just profile.
    context = _context(
        FinalVerdict.FALSE_POSITIVE,
        status=EventStatus.CLOSED,
    )
    governance = _Governance()
    agent = MemoryAgent(
        case_kb_service=_CaseKB(),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=_WorkingMemory(context),
    )

    output = await agent.execute(_input(FinalVerdict.FALSE_POSITIVE))

    assert [c.candidate_type for c in governance.candidates] == [
        "history_case",
        "fp_rule",
        "profile",
    ]
    assert len(output.fp_rules) == 1


# --------------------------------------------------------------------------- #
# ISSUE-208: SuperAgent schedules profile-only early enqueue after analysis
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_schedule_memory_after_analysis_fires_for_reporting_snapshot() -> None:
    context = _context(
        FinalVerdict.CONFIRMED_THREAT,
        status=EventStatus.REPORTING,
        analysis_only_complete=True,
    )
    context_store = _ContextStore(context)
    memory_agent = _SuccessfulMemoryAgent()
    super_agent = SuperAgent(
        memory_agent=memory_agent,
        context_store=context_store,
    )

    task = await super_agent._schedule_memory_after_analysis(EVENT_ID, context)
    assert task is not None
    await task

    assert len(memory_agent.inputs) == 1
    assert memory_agent.inputs[0].investigation_result.final_status is EventStatus.REPORTING


@pytest.mark.asyncio
async def test_schedule_memory_after_analysis_skipped_for_non_reporting() -> None:
    context = _context(FinalVerdict.CONFIRMED_THREAT)
    context.event.status = EventStatus.ANALYZING  # type: ignore[union-attr]
    context_store = _ContextStore(context)
    memory_agent = _SuccessfulMemoryAgent()
    super_agent = SuperAgent(
        memory_agent=memory_agent,
        context_store=context_store,
    )

    task = await super_agent._schedule_memory_after_analysis(EVENT_ID, context)

    assert task is None
    assert memory_agent.inputs == []


@pytest.mark.asyncio
async def test_schedule_memory_after_analysis_skipped_when_early_enqueue_off() -> None:
    context = _context(
        FinalVerdict.CONFIRMED_THREAT,
        status=EventStatus.REPORTING,
        analysis_only_complete=True,
    )
    context_store = _ContextStore(context)
    memory_agent = _SuccessfulMemoryAgent()
    memory_agent.early_enqueue_enabled = False  # type: ignore[attr-defined]
    super_agent = SuperAgent(
        memory_agent=memory_agent,
        context_store=context_store,
    )

    task = await super_agent._schedule_memory_after_analysis(EVENT_ID, context)

    assert task is None
    assert memory_agent.inputs == []


@pytest.mark.asyncio
async def test_early_enqueue_does_not_short_circuit_closed_consolidation() -> None:
    """ISSUE-208 regression: the early (REPORTING) pass must not block the later
    CLOSED pass from enqueueing closure-semantics candidates."""
    context = _context(
        FinalVerdict.CONFIRMED_THREAT,
        status=EventStatus.REPORTING,
        analysis_only_complete=True,
    )
    governance = _Governance()
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=_CaseKB(),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )

    # Early pass (REPORTING): profile-only, writes a separate memory key.
    await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT, final_status=EventStatus.REPORTING))
    assert [c.candidate_type for c in governance.candidates] == ["profile"]
    assert context.memory_output is None  # full consolidation is NOT marked done

    # Event closes; the CLOSED pass must still enqueue history_case (+ profile).
    context.event.status = EventStatus.CLOSED  # type: ignore[union-attr]
    governance.candidates.clear()
    await agent.execute(_input(FinalVerdict.CONFIRMED_THREAT))
    assert [c.candidate_type for c in governance.candidates] == ["history_case", "profile"]


@pytest.mark.asyncio
async def test_early_path_is_idempotent() -> None:
    """Repeated early triggers must not re-enqueue profile candidates."""
    context = _context(
        FinalVerdict.CONFIRMED_THREAT,
        status=EventStatus.REPORTING,
        analysis_only_complete=True,
    )
    governance = _Governance()
    memory = _WorkingMemory(context)
    agent = MemoryAgent(
        case_kb_service=_CaseKB(),  # type: ignore[arg-type]
        profile_service=_Profiles(),  # type: ignore[arg-type]
        memory_governance=governance,  # type: ignore[arg-type]
        context_store=_ContextStore(context),
        working_memory=memory,
    )
    input_early = _input(
        FinalVerdict.CONFIRMED_THREAT,
        final_status=EventStatus.REPORTING,
    )

    await agent.execute(input_early)
    assert [c.candidate_type for c in governance.candidates] == ["profile"]
    assert context.memory_output_early is not None

    # Second early trigger: short-circuits on the persisted early marker.
    await agent.execute(input_early)
    assert [c.candidate_type for c in governance.candidates] == ["profile"]
    assert len(governance.candidates) == 1


def test_memory_output_early_is_registered_working_memory_field() -> None:
    """The early key must be a legal WorkingMemory field (ISSUE-208 blocker)."""
    from app.services.working_memory import FIELD_OWNERSHIP

    assert FIELD_OWNERSHIP["memory_output_early"] == "MemoryAgent"
