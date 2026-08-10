"""Side-effect convergence projections (ISSUE-302)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    ActionExecutionPhase,
    ActionStatus,
    ExecutionJobStatus,
    OutboxDeliveryStatus,
    WritebackStatus,
)


class SideEffectScope(StrEnum):
    """Whether an outstanding side effect participates in the CLOSED gate."""

    GATE_APPLICABLE = "gate_applicable"
    BACKGROUND_DETACHED = "background_detached"


class SideEffectConvergenceReason(StrEnum):
    IN_FLIGHT_JOB = "in_flight_job"
    EXECUTING_ACTION = "executing_action"
    OUTBOX_NOT_CONFIRMED = "outbox_not_confirmed"
    OUTBOX_UNDELIVERED = "outbox_undelivered"


class OutstandingSideEffectView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    scope: SideEffectScope
    action_status: ActionStatus
    execution_phase: ActionExecutionPhase
    writeback_applicable: bool
    job_status: ExecutionJobStatus | None = None
    outbox_delivery_status: OutboxDeliveryStatus | None = None
    outbox_writeback_status: WritebackStatus | None = None
    plan_revision: int
    superseded: bool = False


class SideEffectConvergenceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    current_plan_revision: int | None = None
    gate_applicable_outstanding_count: int = 0
    background_outstanding_count: int = 0
    outstanding_actions: list[OutstandingSideEffectView] = Field(default_factory=list)
    background_side_effects_pending: bool = False


class SideEffectConvergenceViolation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: SideEffectConvergenceReason
    action_id: str
    scope: SideEffectScope = SideEffectScope.GATE_APPLICABLE
