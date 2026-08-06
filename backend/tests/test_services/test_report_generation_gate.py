"""ISSUE-206: report generation lifecycle gate tests.

The POST /events/{id}/report endpoint refuses generation while the
investigation is still running. This module locks the allowed-status contract;
the full endpoint behaviour (with quality gate) is covered by API integration
tests that require a PostgreSQL/Redis stack.
"""

from __future__ import annotations

from app.api.v1.events import REPORT_GENERATION_ALLOWED_STATUSES
from app.models.enums import EventStatus


def test_report_generation_allows_reporting_and_closed() -> None:
    assert EventStatus.REPORTING in REPORT_GENERATION_ALLOWED_STATUSES
    assert EventStatus.CLOSED in REPORT_GENERATION_ALLOWED_STATUSES


def test_report_generation_rejects_incomplete_lifecycle_states() -> None:
    for status in (
        EventStatus.NEW,
        EventStatus.TRIAGING,
        EventStatus.COLLECTING_EVIDENCE,
        EventStatus.ANALYZING,
        EventStatus.SCORING,
        EventStatus.PLANNING_RESPONSE,
        EventStatus.WAITING_APPROVAL,
        EventStatus.EXECUTING_RESPONSE,
        EventStatus.VERIFYING,
        EventStatus.REPLANNING,
        EventStatus.CONTAINED,
        EventStatus.FAILED,
    ):
        assert status not in REPORT_GENERATION_ALLOWED_STATUSES, status
