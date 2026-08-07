"""ISSUE-212 — report_quality assessment + gate semantics.

ISSUE-246 — degraded_template enrichment keeps honest quality grades while
injecting structured summary paragraphs (not raw key=value-only dumps).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.agents.report_agent import GENERATED_BY_TEMPLATE, ReportAgent
from app.agents.report_section_builder import (
    ACTIONS_STATUS_SUMMARY_LABEL,
    DECISION_BRIEF_LABEL,
    EVIDENCE_LIMITED_REASON_LABEL,
    EVIDENCE_SUMMARY_LABEL,
    INCOMPLETE_ACTIONS_PLACEHOLDER,
    NOT_EXECUTED_ACTIONS,
    NOT_EXECUTED_VERIFICATION,
    PLACEHOLDER_NO_ACTIONS,
    PLACEHOLDER_NO_VERIFICATION,
    SECTION_KEYS,
    ReportSectionBuilder,
)
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ReportAgentInput,
    ReportPhaseStatus,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.context import EventContext
from app.models.enums import (
    EventType,
    EvidenceSource,
    FinalVerdict,
    ReportQuality,
    Severity,
)
from app.models.evidence import EvidenceGap
from app.models.report import InvestigationReport, ReportSection
from app.services.report_quality import (
    ReportPhaseFlags,
    assess_report_quality,
    is_degraded_quality,
    with_assessed_quality,
)


def _sections(**overrides: str) -> list[ReportSection]:
    contents = {key: f"content for {key}" for key in SECTION_KEYS}
    contents["executed_actions"] = NOT_EXECUTED_ACTIONS
    contents["verification_results"] = NOT_EXECUTED_VERIFICATION
    contents.update(overrides)
    return [ReportSection(key=key, title=key, content=contents[key]) for key in SECTION_KEYS]


def _report(
    *,
    generated_by: str | None = "llm",
    sections: list[ReportSection] | None = None,
) -> InvestigationReport:
    return InvestigationReport(
        report_id="rpt-evt-212",
        event_id="evt-212",
        title="quality test",
        summary="summary",
        sections=sections or _sections(),
        final_verdict=FinalVerdict.NONE,
        risk_score=40,
        severity=Severity.MEDIUM,
        generated_by=generated_by,
        generated_at=datetime.now(UTC),
    )


def test_analysis_only_not_executed_chapters_are_complete() -> None:
    report = _report(generated_by="llm")
    quality = assess_report_quality(
        report,
        ReportPhaseFlags(
            response_phase_status=ReportPhaseStatus.NOT_EXECUTED,
            verification_phase_status=ReportPhaseStatus.NOT_EXECUTED,
        ),
    )
    assert quality is ReportQuality.COMPLETE
    stamped = with_assessed_quality(report)
    assert stamped.report_quality is ReportQuality.COMPLETE
    assert stamped.degraded is False


def test_event_context_accepts_report_dump_with_computed_degraded() -> None:
    """Context store round-trip must not 422 on computed ``degraded`` (CI regression)."""
    report = with_assessed_quality(_report(generated_by="template"))
    assert report.degraded is True
    payload = report.model_dump(mode="json")
    assert payload.get("degraded") is True
    ctx = EventContext.model_validate({"report": payload})
    assert ctx.report is not None
    assert ctx.report.report_quality is ReportQuality.DEGRADED_TEMPLATE
    assert ctx.report.degraded is True


def test_legacy_placeholder_no_actions_is_incomplete_even_when_not_executed() -> None:
    report = _report(
        sections=_sections(executed_actions=PLACEHOLDER_NO_ACTIONS),
    )
    quality = assess_report_quality(
        report,
        response_phase_status=ReportPhaseStatus.NOT_EXECUTED,
        verification_phase_status=ReportPhaseStatus.NOT_EXECUTED,
    )
    assert quality is ReportQuality.INCOMPLETE_PLACEHOLDER
    assert is_degraded_quality(quality) is True


def test_executed_response_with_incomplete_placeholder_is_incomplete() -> None:
    report = _report(
        sections=_sections(executed_actions=INCOMPLETE_ACTIONS_PLACEHOLDER),
    )
    quality = assess_report_quality(
        report,
        ReportPhaseFlags(
            response_phase_status=ReportPhaseStatus.EXECUTED,
            verification_phase_status=ReportPhaseStatus.NOT_EXECUTED,
        ),
    )
    assert quality is ReportQuality.INCOMPLETE_PLACEHOLDER


def test_executed_verification_with_legacy_placeholder_is_incomplete() -> None:
    report = _report(
        sections=_sections(verification_results=PLACEHOLDER_NO_VERIFICATION),
    )
    quality = assess_report_quality(
        report,
        response_phase_status=ReportPhaseStatus.EXECUTED,
        verification_phase_status=ReportPhaseStatus.EXECUTED,
    )
    assert quality is ReportQuality.INCOMPLETE_PLACEHOLDER


def test_executed_phases_with_real_summaries_are_complete() -> None:
    report = _report(
        generated_by="llm",
        sections=_sections(
            executed_actions="- blocked src_ip=203.0.113.10 (SUCCESS)",
            verification_results="- effect verified for act-1",
        ),
    )
    quality = assess_report_quality(
        report,
        ReportPhaseFlags(
            response_phase_status=ReportPhaseStatus.EXECUTED,
            verification_phase_status=ReportPhaseStatus.EXECUTED,
        ),
    )
    assert quality is ReportQuality.COMPLETE


def test_template_caps_at_degraded_even_when_chapters_look_complete() -> None:
    report = _report(generated_by="template")
    quality = assess_report_quality(
        report,
        response_phase_status=ReportPhaseStatus.NOT_EXECUTED,
        verification_phase_status=ReportPhaseStatus.NOT_EXECUTED,
    )
    assert quality is ReportQuality.DEGRADED_TEMPLATE
    assert with_assessed_quality(report).degraded is True


def test_quick_close_always_quick_close() -> None:
    report = _report(
        generated_by="quick_close",
        sections=_sections(
            executed_actions=PLACEHOLDER_NO_ACTIONS,
            verification_results=PLACEHOLDER_NO_VERIFICATION,
        ),
    )
    quality = assess_report_quality(
        report,
        response_phase_status=ReportPhaseStatus.EXECUTED,
        verification_phase_status=ReportPhaseStatus.EXECUTED,
    )
    assert quality is ReportQuality.QUICK_CLOSE


def test_incomplete_beats_template() -> None:
    """Incomplete chapter check has priority over template cap."""
    report = _report(
        generated_by="template",
        sections=_sections(executed_actions=INCOMPLETE_ACTIONS_PLACEHOLDER),
    )
    quality = assess_report_quality(
        report,
        response_phase_status=ReportPhaseStatus.EXECUTED,
        verification_phase_status=ReportPhaseStatus.NOT_EXECUTED,
    )
    assert quality is ReportQuality.INCOMPLETE_PLACEHOLDER


@pytest.mark.asyncio
async def test_upsert_persists_report_quality_on_orm_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ORM upsert writes report_quality; get_report reads it back."""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock, patch

    from app.services.event_service import EventService

    report = with_assessed_quality(
        _report(generated_by="quick_close"),
    )
    assert report.report_quality is ReportQuality.QUICK_CLOSE

    class _AsyncCM:
        def __init__(self, value: object | None = None) -> None:
            self._value = value if value is not None else self

        async def __aenter__(self) -> object:
            return self._value

        async def __aexit__(self, *args: object) -> None:
            return None

    captured: dict[str, object] = {}

    def _add(obj: object) -> None:
        captured["row"] = obj

    session = AsyncMock()
    session.get = AsyncMock(return_value=None)
    session.add = MagicMock(side_effect=_add)
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.begin = MagicMock(return_value=_AsyncCM())
    session_factory = MagicMock(return_value=_AsyncCM(session))

    service = EventService(
        session_factory=session_factory,
        store=AsyncMock(),
        degraded_flags=AsyncMock(),
    )
    saved = await service.upsert_report(report)
    assert saved.report_quality is ReportQuality.QUICK_CLOSE
    row = captured["row"]
    assert row.report_quality == "quick_close"

    # Simulate get_report reading the same row.
    session.get = AsyncMock(return_value=row)
    session.scalar = AsyncMock(return_value=row)
    with patch(
        "app.services.event_service.select",
        return_value=MagicMock(),
    ):
        # Direct reconstruction path via get when report_id provided.
        loaded_row = SimpleNamespace(
            report_id=report.report_id,
            event_id=report.event_id,
            title=report.title,
            summary=report.summary,
            sections=[s.model_dump(mode="json") for s in report.sections],
            final_verdict=report.final_verdict.value,
            risk_score=report.risk_score,
            severity=report.severity.value,
            version=1,
            generated_by="quick_close",
            report_quality="quick_close",
            generated_at=report.generated_at,
            updated_at=report.updated_at,
        )
        session.get = AsyncMock(return_value=loaded_row)
        loaded = await service.get_report(report_id=report.report_id)
    assert loaded is not None
    assert loaded.report_quality is ReportQuality.QUICK_CLOSE
    assert loaded.degraded is True


def test_should_reject_incomplete_without_force() -> None:
    from app.services.report_quality import should_reject_incomplete_without_force

    assert (
        should_reject_incomplete_without_force(
            ReportQuality.INCOMPLETE_PLACEHOLDER,
            force=False,
            gate_enforced=True,
        )
        is True
    )
    assert (
        should_reject_incomplete_without_force(
            ReportQuality.INCOMPLETE_PLACEHOLDER,
            force=True,
            gate_enforced=True,
        )
        is False
    )
    assert (
        should_reject_incomplete_without_force(
            ReportQuality.INCOMPLETE_PLACEHOLDER,
            force=False,
            gate_enforced=False,
        )
        is False
    )
    assert (
        should_reject_incomplete_without_force(
            ReportQuality.DEGRADED_TEMPLATE,
            force=False,
            gate_enforced=True,
        )
        is False
    )


def test_should_reject_complete_downgrade() -> None:
    from app.services.report_quality import should_reject_complete_downgrade

    assert (
        should_reject_complete_downgrade(
            ReportQuality.COMPLETE,
            ReportQuality.DEGRADED_TEMPLATE,
            confirm_downgrade=False,
        )
        is True
    )
    assert (
        should_reject_complete_downgrade(
            ReportQuality.COMPLETE,
            ReportQuality.QUICK_CLOSE,
            confirm_downgrade=True,
        )
        is False
    )
    assert (
        should_reject_complete_downgrade(
            ReportQuality.COMPLETE,
            ReportQuality.COMPLETE,
            confirm_downgrade=False,
        )
        is False
    )
    assert (
        should_reject_complete_downgrade(
            None,
            ReportQuality.INCOMPLETE_PLACEHOLDER,
            confirm_downgrade=False,
        )
        is False
    )
    assert (
        should_reject_complete_downgrade(
            ReportQuality.QUICK_CLOSE,
            ReportQuality.INCOMPLETE_PLACEHOLDER,
            confirm_downgrade=False,
        )
        is False
    )


@pytest.mark.asyncio
async def test_upsert_report_allows_agent_downgrade_from_complete() -> None:
    """Graph/ReportAgent must be able to honestly rewrite complete→degraded."""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock

    from app.services.event_service import EventService

    complete = with_assessed_quality(_report(generated_by="llm"))
    assert complete.report_quality is ReportQuality.COMPLETE
    degraded = with_assessed_quality(_report(generated_by="template"))
    assert degraded.report_quality is ReportQuality.DEGRADED_TEMPLATE

    existing_row = SimpleNamespace(
        report_id=complete.report_id,
        event_id=complete.event_id,
        report_quality="complete",
        version=1,
        title=complete.title,
        summary=complete.summary,
        sections=[],
        final_verdict=complete.final_verdict.value,
        risk_score=complete.risk_score,
        severity=complete.severity.value,
        generated_by="llm",
        generated_at=complete.generated_at,
        updated_at=complete.updated_at,
    )

    class _AsyncCM:
        def __init__(self, value: object | None = None) -> None:
            self._value = value if value is not None else self

        async def __aenter__(self) -> object:
            return self._value

        async def __aexit__(self, *args: object) -> None:
            return None

    session = AsyncMock()
    session.get = AsyncMock(return_value=existing_row)
    session.add = MagicMock()
    session.begin = MagicMock(return_value=_AsyncCM())
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session_factory = MagicMock(return_value=_AsyncCM(session))

    service = EventService(
        session_factory=session_factory,
        store=AsyncMock(),
        degraded_flags=AsyncMock(),
    )
    allowed = await service.upsert_report(degraded)
    assert allowed.report_quality is ReportQuality.DEGRADED_TEMPLATE
    assert existing_row.report_quality == "degraded_template"
    assert existing_row.generated_by == "template"
    assert existing_row.version == 2


def _enriched_template_fixture() -> tuple[
    InvestigationReport,
    dict[str, ReportSection],
]:
    """Build a template-path report with ISSUE-246 structured enrichment."""
    event_id = "evt-246-enrich"
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        decision_summary="可疑外传行为，需保留高风险并补充流量证据",
    )
    evidence = EvidenceOutput(
        evidence_list=[],
        overall_confidence=0.2,
        collection_status=CollectionStatus.FAILED,
        failed_sources=["network_flow", "dns"],
        gaps=[
            EvidenceGap(
                event_id=event_id,
                missing_source=EvidenceSource.NETWORK_FLOW,
                reason="provider_timeout",
            )
        ],
    )
    risk = RiskAssessment(
        risk_score=72,
        severity=Severity.HIGH,
        confidence=0.35,
        risk_factors=[],
        possible_false_positive=False,
        scoring_mode=ScoringMode.RULE_ONLY,
        evidence_limited=True,
        severity_floor_applied=True,
        source_risk_baseline=76,
        high_source_evidence_limited=True,
        confidence_cap_version="issue102_v1",
    )
    sections = ReportSectionBuilder().build(
        event_id=event_id,
        evidence_output=evidence,
        risk_assessment=risk,
        triage_result=triage,
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        response_phase_status=ReportPhaseStatus.NOT_EXECUTED,
        verification_phase_status=ReportPhaseStatus.NOT_EXECUTED,
    )
    summary = ReportSectionBuilder().default_summary(
        risk_assessment=risk,
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        triage_result=triage,
        evidence_output=evidence,
        response_phase_status=ReportPhaseStatus.NOT_EXECUTED,
    )
    report = InvestigationReport(
        report_id="rpt-evt-246-enrich",
        event_id=event_id,
        title="ISSUE-246 enrichment",
        summary=summary,
        sections=sections,
        final_verdict=FinalVerdict.CONFIRMED_THREAT,
        risk_score=risk.risk_score,
        severity=risk.severity,
        generated_by=GENERATED_BY_TEMPLATE,
        generated_at=datetime.now(UTC),
    )
    return report, {section.key: section for section in sections}


def test_degraded_template_includes_structured_summary_paragraphs() -> None:
    """ISSUE-246: template enrichment is prose/structured, not key=value-only."""
    report, by_key = _enriched_template_fixture()
    overview = by_key["overview"].content
    summary = report.summary

    assert f"{DECISION_BRIEF_LABEL}:" in overview
    assert "可疑外传行为" in overview
    assert f"{EVIDENCE_SUMMARY_LABEL}:" in overview
    assert "共采集 0 条证据" in overview
    assert f"{EVIDENCE_LIMITED_REASON_LABEL}:" in overview
    assert "provider_timeout" in overview
    assert f"{ACTIONS_STATUS_SUMMARY_LABEL}:" in overview
    assert "RESPONSE 动作 0 个" in overview

    # Report-level summary must also carry the structured briefs.
    assert f"{DECISION_BRIEF_LABEL}:" in summary
    assert f"{EVIDENCE_SUMMARY_LABEL}:" in summary
    assert f"{EVIDENCE_LIMITED_REASON_LABEL}:" in summary
    assert f"{ACTIONS_STATUS_SUMMARY_LABEL}:" in summary

    # Structured paragraphs are more than raw key=value dumps.
    assert "；" in overview or "。" in overview
    assert "event_type=" not in summary.splitlines()[0]

    # Machine-readable enrichment also lands in section.data.
    overview_data = by_key["overview"].data
    assert overview_data.get(DECISION_BRIEF_LABEL)
    assert overview_data.get(EVIDENCE_SUMMARY_LABEL)
    assert overview_data.get(EVIDENCE_LIMITED_REASON_LABEL)
    assert overview_data.get(ACTIONS_STATUS_SUMMARY_LABEL)


def test_enriched_template_still_marks_degraded_not_complete() -> None:
    """ISSUE-246 + ISSUE-212: richer template content must not fake complete."""
    report, _ = _enriched_template_fixture()
    quality = assess_report_quality(
        report,
        ReportPhaseFlags(
            response_phase_status=ReportPhaseStatus.NOT_EXECUTED,
            verification_phase_status=ReportPhaseStatus.NOT_EXECUTED,
        ),
    )
    assert quality is ReportQuality.DEGRADED_TEMPLATE
    stamped = with_assessed_quality(report)
    assert stamped.report_quality is ReportQuality.DEGRADED_TEMPLATE
    assert stamped.degraded is True
    assert is_degraded_quality(stamped.report_quality) is True


@pytest.mark.asyncio
async def test_report_agent_template_fallback_keeps_enrichment_and_degraded() -> None:
    """End-to-end template fallback: enrichment present, quality stays degraded."""

    class _FailingLLM:
        async def chat(self, *args: object, **kwargs: object) -> object:
            raise RuntimeError("llm unavailable for ISSUE-246")

    class _WM:
        def __init__(self) -> None:
            self.values: dict[tuple[str, str], object] = {}

        async def read(self, event_id: str, key: str) -> object:
            return self.values.get((event_id, key))

        async def write(self, event_id: str, key: str, value: object) -> None:
            self.values[(event_id, key)] = value

        async def append_scratchpad(self, event_id: str, note: str) -> None:
            return None

    event_id = "evt-246-agent"
    wm = _WM()
    await wm.write(
        event_id,
        "triage_result",
        TriageResult(
            event_type=EventType.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            need_investigation=True,
            decision_summary="模板降级仍需可读决策摘要",
        ).model_dump(mode="json"),
    )
    agent = ReportAgent(llm_client=_FailingLLM(), working_memory=wm, event_service=None)
    report = await agent.execute(
        ReportAgentInput(
            event_id=event_id,
            evidence_output=EvidenceOutput(
                evidence_list=[],
                overall_confidence=0.1,
                collection_status=CollectionStatus.FAILED,
                failed_sources=["endpoint"],
                gaps=[
                    EvidenceGap(
                        event_id=event_id,
                        missing_source=EvidenceSource.ENDPOINT,
                        reason="tool_error",
                    )
                ],
            ),
            risk_assessment=RiskAssessment(
                risk_score=70,
                severity=Severity.HIGH,
                confidence=0.3,
                risk_factors=[],
                scoring_mode=ScoringMode.RULE_ONLY,
                evidence_limited=True,
                severity_floor_applied=True,
            ),
            persist_report=False,
        )
    )
    assert report.generated_by == GENERATED_BY_TEMPLATE
    assert report.report_quality is ReportQuality.DEGRADED_TEMPLATE
    assert report.degraded is True
    blob = "\n".join([report.summary, *(s.content for s in report.sections)])
    assert "模板降级仍需可读决策摘要" in blob
    assert f"{DECISION_BRIEF_LABEL}:" in blob
    assert f"{EVIDENCE_SUMMARY_LABEL}:" in blob
    assert f"{EVIDENCE_LIMITED_REASON_LABEL}:" in blob
    assert f"{ACTIONS_STATUS_SUMMARY_LABEL}:" in blob
    assert agent.last_report_markdown is not None
    assert "模板降级结构化摘要" in agent.last_report_markdown
    assert "decision_brief" in agent.last_report_markdown
