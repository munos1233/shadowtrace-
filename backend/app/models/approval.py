"""Approval domain models (ISSUE-058)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ActionLevel


class ApprovalDecisionKind(StrEnum):
    AUTO_APPROVE = "auto_approve"
    REQUIRE_APPROVAL = "require_approval"
    AUTO_REJECT = "auto_reject"


class ApprovalDecision(BaseModel):
    """Outcome of ``ApprovalEngine.evaluate`` (rule output, not human vote)."""

    model_config = ConfigDict(extra="forbid")

    decision: ApprovalDecisionKind
    rule_applied: str
    reason: str


class ApprovalRecord(BaseModel):
    """Persisted approval audit row."""

    model_config = ConfigDict(extra="forbid")

    approval_id: str
    action_id: str
    event_id: str
    plan_revision: int
    approval_cycle: int = 0
    decision_id: str | None = None
    required_level: ActionLevel
    decision: ApprovalDecisionKind
    operator: str | None = None
    comment: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    requested_at: datetime
    decided_at: datetime | None = None
    timeout_at: datetime | None = None
