"""Durable auto-investigate intent contract (ISSUE-108 / #612)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.models.enums import InvestigationIntentStatus

INTENT_KIND_AUTO_INVESTIGATE = "auto_investigate"
INTENT_VERSION_ISSUE108_V1 = "issue108_v1"
INTENT_KIND_HTTP_INVESTIGATE = "http_investigate"
INTENT_VERSION_ISSUE276_V1 = "issue276_v1"
PROVISIONAL_LINK_ROLE = "provisional"
PRIMARY_LINK_ROLE = "primary"
UNKNOWN_LINK_ROLE = "unknown"


class IntentDeliveryAdmission(StrEnum):
    """Whether a Celery delivery may execute SuperAgent for an intent."""

    ACCEPTED = "accepted"
    STALE_SUPERSEDED = "stale_superseded"
    ALREADY_TERMINAL = "already_terminal"
    MISSING = "missing"


INTENT_TRANSITIONS: dict[InvestigationIntentStatus, frozenset[InvestigationIntentStatus]] = {
    InvestigationIntentStatus.PENDING: frozenset(
        {
            InvestigationIntentStatus.CLAIMED,
            InvestigationIntentStatus.SKIPPED,
        }
    ),
    InvestigationIntentStatus.CLAIMED: frozenset(
        {
            InvestigationIntentStatus.ENQUEUED,
            InvestigationIntentStatus.RETRY,
            InvestigationIntentStatus.PENDING,
            InvestigationIntentStatus.SKIPPED,
            InvestigationIntentStatus.DEAD,
        }
    ),
    InvestigationIntentStatus.ENQUEUED: frozenset(
        {
            InvestigationIntentStatus.STARTED,
            InvestigationIntentStatus.RETRY,
            InvestigationIntentStatus.SKIPPED,
            InvestigationIntentStatus.DEAD,
        }
    ),
    InvestigationIntentStatus.STARTED: frozenset(
        {
            InvestigationIntentStatus.TERMINAL,
            InvestigationIntentStatus.SKIPPED,
            InvestigationIntentStatus.RETRY,
            InvestigationIntentStatus.DEAD,
        }
    ),
    InvestigationIntentStatus.RETRY: frozenset(
        {
            InvestigationIntentStatus.CLAIMED,
            InvestigationIntentStatus.DEAD,
            InvestigationIntentStatus.SKIPPED,
        }
    ),
    InvestigationIntentStatus.TERMINAL: frozenset(),
    InvestigationIntentStatus.SKIPPED: frozenset(),
    InvestigationIntentStatus.DEAD: frozenset(),
}

TERMINAL_INTENT_STATUSES = frozenset(
    {
        InvestigationIntentStatus.TERMINAL,
        InvestigationIntentStatus.SKIPPED,
        InvestigationIntentStatus.DEAD,
    }
)


class InvestigationIntentTransitionError(ValueError):
    """Raised when an intent status transition is not allowed."""


def validate_intent_transition(
    current: InvestigationIntentStatus,
    target: InvestigationIntentStatus,
) -> None:
    allowed = INTENT_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise InvestigationIntentTransitionError(
            f"invalid investigation intent transition: {current.value} -> {target.value}"
        )


@dataclass(frozen=True)
class InvestigationIntentRecord:
    intent_id: str
    event_id: str
    intent_kind: str
    intent_version: str
    status: InvestigationIntentStatus
    revision: int
    attempt: int
    broker_task_id: str | None
    skip_reason: str | None
    last_error: str | None


__all__ = [
    "INTENT_KIND_AUTO_INVESTIGATE",
    "INTENT_KIND_HTTP_INVESTIGATE",
    "INTENT_TRANSITIONS",
    "INTENT_VERSION_ISSUE108_V1",
    "INTENT_VERSION_ISSUE276_V1",
    "PRIMARY_LINK_ROLE",
    "PROVISIONAL_LINK_ROLE",
    "IntentDeliveryAdmission",
    "InvestigationIntentRecord",
    "InvestigationIntentTransitionError",
    "TERMINAL_INTENT_STATUSES",
    "validate_intent_transition",
]
