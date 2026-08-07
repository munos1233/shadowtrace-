"""ISSUE-212 — report_quality assessment + gate semantics."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.agents.report_section_builder import (
    INCOMPLETE_ACTIONS_PLACEHOLDER,
    NOT_EXECUTED_ACTIONS,
    NOT_EXECUTED_VERIFICATION,
    PLACEHOLDER_NO_ACTIONS,
    PLACEHOLDER_NO_VERIFICATION,
    SECTION_KEYS,
)
from app.models.agent_io import ReportPhaseStatus
from app.models.context import EventContext
from app.models.enums import FinalVerdict, ReportQuality, Severity
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
