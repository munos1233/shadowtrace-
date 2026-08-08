"""Durable graph resume intent contract (ISSUE-277 / #873)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.models.enums import InvestigationIntentStatus
from app.models.investigation_intent import (
    INTENT_TRANSITIONS,
    TERMINAL_INTENT_STATUSES,
    InvestigationIntentTransitionError,
    validate_intent_transition,
)

INTENT_KIND_GRAPH_RESUME = "graph_resume"
INTENT_VERSION_ISSUE277_V1 = "issue277_v1"

RESOLUTION_KIND_ACTION = "action"
RESOLUTION_KIND_WRITEBACK = "writeback"


class GraphResumeDeliveryAdmission(StrEnum):
    ACCEPTED = "accepted"
    STALE_SUPERSEDED = "stale_superseded"
    ALREADY_TERMINAL = "already_terminal"
    HOLD_MISMATCH = "hold_mismatch"
    MISSING = "missing"


@dataclass(frozen=True)
class GraphResumeIntentRecord:
    intent_id: str
    event_id: str
    operation_id: str
    resolution_kind: str
    subject_id: str
    hold_generation: int
    status: InvestigationIntentStatus


__all__ = [
    "GraphResumeDeliveryAdmission",
    "GraphResumeIntentRecord",
    "INTENT_KIND_GRAPH_RESUME",
    "INTENT_TRANSITIONS",
    "INTENT_VERSION_ISSUE277_V1",
    "InvestigationIntentTransitionError",
    "RESOLUTION_KIND_ACTION",
    "RESOLUTION_KIND_WRITEBACK",
    "TERMINAL_INTENT_STATUSES",
    "validate_intent_transition",
]
