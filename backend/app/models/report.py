"""InvestigationReport model (15-section structured report; ReportAgent output).

The report is a ShadowTrace-local artifact and is NEVER written back to XDR.
``report_id`` is a stable derivation of the event_id (see ``ids.report_id_for_event``)
to guarantee idempotent upsert.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import FinalVerdict, Severity


class ReportSection(BaseModel):
    """One chapter of the structured report."""

    model_config = ConfigDict(extra="forbid")

    key: str
    title: str
    content: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class InvestigationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: str
    event_id: str
    title: str
    summary: str = ""
    sections: list[ReportSection] = Field(default_factory=list)
    final_verdict: FinalVerdict = FinalVerdict.NONE
    risk_score: int = Field(default=0, ge=0, le=100)
    severity: Severity = Severity.LOW
    version: int = 1
    generated_by: str | None = None
    generated_at: datetime | None = None
    updated_at: datetime | None = None
    warnings: list[str] = Field(default_factory=list)
    error_detail: str | None = None


_APPENDIX_OBSERVABILITY_WARNINGS_KEY = "report_warnings"
_APPENDIX_OBSERVABILITY_ERROR_DETAIL_KEY = "report_error_detail"


def stamp_report_observability_in_sections(
    sections: list[ReportSection],
    *,
    warnings: list[str],
    error_detail: str | None,
) -> list[ReportSection]:
    """Dual-write observability to top-level fields and appendix_index.data (no DB migration)."""
    stamped: list[ReportSection] = []
    for section in sections:
        if section.key != "appendix_index":
            stamped.append(section)
            continue
        data = dict(section.data)
        data.pop(_APPENDIX_OBSERVABILITY_WARNINGS_KEY, None)
        data.pop(_APPENDIX_OBSERVABILITY_ERROR_DETAIL_KEY, None)
        if warnings:
            data[_APPENDIX_OBSERVABILITY_WARNINGS_KEY] = list(warnings)
        if error_detail:
            data[_APPENDIX_OBSERVABILITY_ERROR_DETAIL_KEY] = error_detail
        stamped.append(
            ReportSection(
                key=section.key,
                title=section.title,
                content=section.content,
                data=data,
            )
        )
    return stamped


def observability_from_sections(
    sections: list[ReportSection],
) -> tuple[list[str], str | None]:
    """Restore fallback observability fields stored in appendix_index.data."""
    for section in sections:
        if section.key != "appendix_index":
            continue
        data = section.data or {}
        raw_warnings = data.get(_APPENDIX_OBSERVABILITY_WARNINGS_KEY)
        warnings = [str(item) for item in raw_warnings] if isinstance(raw_warnings, list) else []
        raw_detail = data.get(_APPENDIX_OBSERVABILITY_ERROR_DETAIL_KEY)
        error_detail = str(raw_detail) if raw_detail not in (None, "") else None
        return warnings, error_detail
    return [], None
