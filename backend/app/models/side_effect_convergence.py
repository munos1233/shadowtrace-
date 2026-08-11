"""Side-effect convergence projections (ISSUE-302 / ISSUE-312).

Convergence policy (required ``disposition_policy``):

- ``TERMINAL_WRITEBACK`` (``writeback_applicable=true``, e.g. ``EVENT_STATUS_UPDATE``):
  active outbox must be delivered with ``WritebackStatus.CONFIRMED`` and
  readback-verified evidence on the terminal disposition path.
- ``INDEPENDENT_ENTITY_EFFECT`` (``entity_action_submit``,
  ``writeback_applicable=false``): terminal execution job success plus an
  independent provider effect observation ``EffectStatus.VERIFIED`` (VerifyAgent
  phase ``effect``). Entity submit receipts may remain ``ACCEPTED``.
- ``EXECUTION_JOB_ONLY`` (``writeback_applicable=false`` direct-tool paths without
  entity outbox): terminal job / action success; outbox receipts are not gate
  inputs.
"""

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


class SideEffectConvergencePolicy(StrEnum):
    """Structured convergence contract per side-effect kind (ISSUE-312)."""

    TERMINAL_WRITEBACK = "terminal_writeback"
    INDEPENDENT_ENTITY_EFFECT = "independent_entity_effect"
    EXECUTION_JOB_ONLY = "execution_job_only"


class SideEffectConvergenceReason(StrEnum):
    """Outstanding side-effect blocking reasons exposed on API / state machine."""

    IN_FLIGHT_JOB = "in_flight_job"
    EXECUTING_ACTION = "executing_action"
    EFFECT_UNVERIFIED = "effect_unverified"
    TERMINAL_WRITEBACK_UNCONFIRMED = "terminal_writeback_unconfirmed"
    OUTBOX_NOT_CONFIRMED = "outbox_not_confirmed"
    OUTBOX_UNDELIVERED = "outbox_undelivered"


class OutstandingSideEffectView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    scope: SideEffectScope
    action_status: ActionStatus
    execution_phase: ActionExecutionPhase
    writeback_applicable: bool
    convergence_policy: SideEffectConvergencePolicy | None = None
    job_status: ExecutionJobStatus | None = None
    outbox_delivery_status: OutboxDeliveryStatus | None = None
    outbox_writeback_status: WritebackStatus | None = None
    plan_revision: int
    superseded: bool = False
    blocking_reason: SideEffectConvergenceReason | None = None


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
