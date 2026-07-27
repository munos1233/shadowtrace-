"""RollbackResult model (ISSUE-061 field spec).

Describes the outcome of a single rollback attempt, including
compensation writeback status for the Saga pattern.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.models.enums import WritebackReadiness, WritebackStatus

RollbackEffectStatus = Literal[
    "verified",
    "failed",
    "unverifiable",
    "not_supported",
    "skipped",
]


class CompensationWritebackItem(BaseModel):
    """One compensation writeback record linked to this rollback."""

    model_config = ConfigDict(extra="forbid")

    writeback_id: str
    disposition_id: str
    status: WritebackStatus | None = None
    intent_kind: str = "COMPENSATION_RECORD"


class RollbackResult(BaseModel):
    """Result of a single ``rollback_action`` operation.

    Naming and cardinality rules follow intro §4.5 / ISSUE-061:
    - ``compensation_writebacks`` is a list; empty when no sync is required.
    - ``compensation_writeback_id`` is a compatibility field populated ONLY
      when exactly one compensation writeback exists; otherwise null.
    - ``compensation_writeback_status`` is an aggregate WritebackStatus or null.
    """

    model_config = ConfigDict(extra="forbid")

    action_id: str
    """The original Action being rolled back."""

    rollback_action_id: str | None = None
    """The newly persisted rollback Action (action_category=rollback)."""

    rollback_tool: str | None = None
    """Name of the rollback tool that was invoked."""

    rollback_effect_status: RollbackEffectStatus | None = None
    """Independent verification of the rollback effect."""

    compensation_writeback_required: bool = False
    """Whether the original Action requires external compensation sync."""

    compensation_writeback_readiness: WritebackReadiness = WritebackReadiness.NOT_REQUIRED
    """Pre-submission readiness for compensation writebacks."""

    compensation_writebacks: list[CompensationWritebackItem] = Field(default_factory=list)
    """One entry per applicable original writeback
    (ENTITY_ACTION_SUBMIT / EXECUTION_RESULT_RECORD)."""

    compensation_writeback_status: WritebackStatus | None = None
    """Aggregate WritebackStatus across all compensation writebacks; null when empty."""

    rolled_back: bool = False
    """True only after original Action status is CAS'd to ROLLED_BACK."""

    warning: str | None = None
    """Human-readable warning (e.g. 'not_rollbackable', 'compensation_unsupported')."""

    audit_log_id: str | None = None
    """event_audit_log row id for this rollback operation."""

    # --- Compatibility single-writeback field --------------------------------
    @computed_field  # type: ignore[prop-decorator]
    @property
    def compensation_writeback_id(self) -> str | None:
        """Compatibility: populated only when exactly one compensation writeback exists."""
        if len(self.compensation_writebacks) == 1:
            return self.compensation_writebacks[0].writeback_id
        return None
