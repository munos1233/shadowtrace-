"""Report quality assessment + POST gate helpers (ISSUE-212).

``report_quality`` is computed at generation time from ``generated_by`` and
phase-aware chapter content, then persisted on the ORM ``report`` row.

HTTP quality gate is **POST /report only**:
- ``incomplete_placeholder`` → 422 unless ``force=true`` (when enforced)
- complete→degraded overwrite → 409 unless ``confirm_downgrade=true``

Graph / ReportAgent upserts stamp honest grades and are not HTTP-gated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.agents.report_section_builder import (
    INCOMPLETE_ACTIONS_PLACEHOLDER,
    INCOMPLETE_VERIFICATION_PLACEHOLDER,
    NOT_EXECUTED_ACTIONS,
    NOT_EXECUTED_VERIFICATION,
    PLACEHOLDER_NO_ACTIONS,
    PLACEHOLDER_NO_VERIFICATION,
    UNAVAILABLE_ACTIONS,
    UNAVAILABLE_VERIFICATION,
)
from app.models.agent_io import ReportPhaseStatus
from app.models.enums import ReportQuality
from app.models.report import InvestigationReport

GENERATED_BY_TEMPLATE = "template"
GENERATED_BY_QUICK_CLOSE = "quick_close"
GENERATED_BY_LLM = "llm"

_ACTIONS_KEY = "executed_actions"
_VERIFICATION_KEY = "verification_results"

_BAD_ACTIONS_MARKERS: tuple[str, ...] = (
    PLACEHOLDER_NO_ACTIONS,
    INCOMPLETE_ACTIONS_PLACEHOLDER,
    UNAVAILABLE_ACTIONS,
)
_BAD_VERIFICATION_MARKERS: tuple[str, ...] = (
    PLACEHOLDER_NO_VERIFICATION,
    INCOMPLETE_VERIFICATION_PLACEHOLDER,
    UNAVAILABLE_VERIFICATION,
)


@dataclass(frozen=True, slots=True)
class ReportPhaseFlags:
    """Phase-execution signals used by :func:`assess_report_quality`."""

    response_phase_status: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED
    verification_phase_status: ReportPhaseStatus = ReportPhaseStatus.NOT_EXECUTED


def phase_flags_from_statuses(
    *,
    response_phase_status: ReportPhaseStatus | str | None = None,
    verification_phase_status: ReportPhaseStatus | str | None = None,
) -> ReportPhaseFlags:
    """Normalize builder/agent phase statuses into assessment flags."""
    return ReportPhaseFlags(
        response_phase_status=_coerce_phase(response_phase_status),
        verification_phase_status=_coerce_phase(verification_phase_status),
    )


def _coerce_phase(value: ReportPhaseStatus | str | None) -> ReportPhaseStatus:
    if isinstance(value, ReportPhaseStatus):
        return value
    if value is None or value == "":
        return ReportPhaseStatus.NOT_EXECUTED
    try:
        return ReportPhaseStatus(str(value))
    except ValueError:
        return ReportPhaseStatus.NOT_EXECUTED


def _section_content(report: InvestigationReport, key: str) -> str:
    for section in report.sections:
        if section.key == key:
            return str(section.content or "")
    return ""


def _contains_any(content: str, markers: tuple[str, ...]) -> bool:
    return any(marker in content for marker in markers)


def _actions_chapter_incomplete(
    content: str,
    phase: ReportPhaseStatus,
) -> bool:
    """True when executed_actions violates the ISSUE-212 complete contract."""
    if _contains_any(content, _BAD_ACTIONS_MARKERS):
        return True
    if "incomplete_placeholder" in content.lower():
        return True
    if phase is ReportPhaseStatus.NOT_EXECUTED:
        # Bad markers (incl. 「暂无处置动作」) already rejected above; honest
        # NOT_EXECUTED_ACTIONS text is allowed.
        return False
    # EXECUTED / INCOMPLETE / UNAVAILABLE must not pretend the phase never ran,
    # and must not leave an empty chapter.
    if NOT_EXECUTED_ACTIONS in content:
        return True
    return not content.strip()


def _verification_chapter_incomplete(
    content: str,
    phase: ReportPhaseStatus,
) -> bool:
    """True when verification_results violates the ISSUE-212 complete contract."""
    if _contains_any(content, _BAD_VERIFICATION_MARKERS):
        return True
    if "incomplete_placeholder" in content.lower():
        return True
    if phase is ReportPhaseStatus.NOT_EXECUTED:
        # Bad markers (incl. 「暂无验证结果」) already rejected above.
        return False
    if NOT_EXECUTED_VERIFICATION in content:
        return True
    return not content.strip()


def assess_report_quality(
    report: InvestigationReport,
    event_phase_flags: ReportPhaseFlags | None = None,
    *,
    response_phase_status: ReportPhaseStatus | str | None = None,
    verification_phase_status: ReportPhaseStatus | str | None = None,
) -> ReportQuality:
    """Compute ``report_quality`` for a generated report (ISSUE-212 hard contract).

    Priority:
    1. ``generated_by=quick_close`` → ``quick_close`` (never complete)
    2. Phase/content incomplete markers → ``incomplete_placeholder``
    3. ``generated_by=template`` → ``degraded_template`` (never complete)
    4. else → ``complete``
    """
    flags = event_phase_flags or phase_flags_from_statuses(
        response_phase_status=response_phase_status,
        verification_phase_status=verification_phase_status,
    )
    generated_by = str(report.generated_by or "").strip().lower()
    if generated_by == GENERATED_BY_QUICK_CLOSE:
        return ReportQuality.QUICK_CLOSE

    actions = _section_content(report, _ACTIONS_KEY)
    verification = _section_content(report, _VERIFICATION_KEY)
    if _actions_chapter_incomplete(actions, flags.response_phase_status):
        return ReportQuality.INCOMPLETE_PLACEHOLDER
    if _verification_chapter_incomplete(verification, flags.verification_phase_status):
        return ReportQuality.INCOMPLETE_PLACEHOLDER

    if generated_by == GENERATED_BY_TEMPLATE:
        return ReportQuality.DEGRADED_TEMPLATE

    return ReportQuality.COMPLETE


def with_assessed_quality(
    report: InvestigationReport,
    event_phase_flags: ReportPhaseFlags | None = None,
    *,
    response_phase_status: ReportPhaseStatus | str | None = None,
    verification_phase_status: ReportPhaseStatus | str | None = None,
) -> InvestigationReport:
    """Return a copy of ``report`` with ``report_quality`` stamped."""
    quality = assess_report_quality(
        report,
        event_phase_flags,
        response_phase_status=response_phase_status,
        verification_phase_status=verification_phase_status,
    )
    return report.model_copy(update={"report_quality": quality})


def is_degraded_quality(quality: ReportQuality | str | None) -> bool:
    """API ``degraded`` derivation: anything other than ``complete``."""
    if quality is None:
        return False
    value = quality if isinstance(quality, ReportQuality) else ReportQuality(str(quality))
    return value is not ReportQuality.COMPLETE


def report_quality_from_row(value: Any) -> ReportQuality:
    """Parse ORM / legacy rows; missing values default to ``complete`` (migration)."""
    if isinstance(value, ReportQuality):
        return value
    if value in (None, ""):
        return ReportQuality.COMPLETE
    try:
        return ReportQuality(str(value))
    except ValueError:
        return ReportQuality.COMPLETE


def should_reject_incomplete_without_force(
    quality: ReportQuality | str | None,
    *,
    force: bool,
    gate_enforced: bool = True,
) -> bool:
    """True when POST must 422 (incomplete + force=false + gate on)."""
    parsed = report_quality_from_row(quality)
    return (
        parsed is ReportQuality.INCOMPLETE_PLACEHOLDER and not bool(force) and bool(gate_enforced)
    )


def should_reject_complete_downgrade(
    existing_quality: ReportQuality | str | None,
    incoming_quality: ReportQuality | str | None,
    *,
    confirm_downgrade: bool,
) -> bool:
    """True when POST must 409 (complete→degraded without confirm_downgrade).

    Not used by ``EventService.upsert_report`` — system regeneration may
    honestly rewrite quality grades without this HTTP gate.
    """
    if existing_quality is None:
        return False
    existing = report_quality_from_row(existing_quality)
    incoming = report_quality_from_row(incoming_quality)
    return (
        existing is ReportQuality.COMPLETE
        and is_degraded_quality(incoming)
        and not bool(confirm_downgrade)
    )
