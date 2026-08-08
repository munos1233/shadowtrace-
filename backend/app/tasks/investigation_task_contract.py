"""Shared Celery investigation task payload contract (ISSUE-264 / ISSUE-283).

Production dispatch builders and test doubles must construct kwargs from these
typed payloads so ``generate_report`` and lease fields never drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Public Celery task parameter order for contract tests (``run_investigation``).
INVESTIGATION_TASK_PARAM_NAMES: tuple[str, ...] = (
    "event_id",
    "include_response_execution",
    "generate_report",
    "intent_id",
    "owner_id",
    "lease_acquired",
)

ANALYSIS_ONLY_TASK_PARAM_NAMES: tuple[str, ...] = (
    "event_id",
    "generate_report",
    "owner_id",
    "lease_acquired",
)


@dataclass(frozen=True, slots=True)
class InvestigationDispatchKwargs:
    include_response_execution: bool = False
    generate_report: bool = True
    owner_id: str | None = None
    lease_acquired: bool = False

    def to_apply_async_kwargs(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "include_response_execution": self.include_response_execution,
            "generate_report": self.generate_report,
        }
        if self.owner_id is not None:
            payload["owner_id"] = self.owner_id
        if self.lease_acquired:
            payload["lease_acquired"] = True
        return payload


@dataclass(frozen=True, slots=True)
class InvestigationIntentPublishKwargs:
    intent_id: str
    include_response_execution: bool = False
    generate_report: bool = True

    def to_apply_async_kwargs(self) -> dict[str, Any]:
        return {
            "include_response_execution": bool(self.include_response_execution),
            "generate_report": bool(self.generate_report),
            "intent_id": self.intent_id,
        }


@dataclass(frozen=True, slots=True)
class AnalysisOnlyDispatchKwargs:
    generate_report: bool = True
    owner_id: str | None = None
    lease_acquired: bool = False

    def to_apply_async_kwargs(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"generate_report": self.generate_report}
        if self.owner_id is not None:
            payload["owner_id"] = self.owner_id
        if self.lease_acquired:
            payload["lease_acquired"] = True
        return payload


__all__ = [
    "ANALYSIS_ONLY_TASK_PARAM_NAMES",
    "AnalysisOnlyDispatchKwargs",
    "INVESTIGATION_TASK_PARAM_NAMES",
    "InvestigationDispatchKwargs",
    "InvestigationIntentPublishKwargs",
]
