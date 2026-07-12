"""Evidence models (intro §4.3.5 / ISSUE-002 field spec)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EvidenceSource
from app.models.source import SourceReference


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    event_id: str
    source: EvidenceSource
    evidence_type: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime | None = None
    related_entities: list[str] = Field(default_factory=list)
    source_ref: SourceReference | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    mitre_technique: str | None = None
    is_conflicting: bool = False


class EvidenceConflict(BaseModel):
    """A detected contradiction between two or more pieces of evidence."""

    model_config = ConfigDict(extra="forbid")

    conflict_id: str
    event_id: str
    description: str
    evidence_ids: list[str] = Field(default_factory=list)
    sources: list[EvidenceSource] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


class EvidenceGap(BaseModel):
    """A required evidence source that could not be collected."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    missing_source: EvidenceSource
    reason: str
    detail: dict[str, Any] = Field(default_factory=dict)
