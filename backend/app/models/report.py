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
