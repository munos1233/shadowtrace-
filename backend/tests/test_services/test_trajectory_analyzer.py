"""TrajectoryAnalyzer tests (ISSUE-066)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.decision_trace import DecisionTrace, DecisionTraceEntry, DecisionTraceSummary
from app.models.enums import DecisionTraceEntryType, TrajectoryMetric

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _entry(
    entry_type: DecisionTraceEntryType,
    actor: str = "test",
    detail: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
) -> DecisionTraceEntry:
    return DecisionTraceEntry(
        entry_id=f"dte-{actor}",
        entry_type=entry_type,
        timestamp=timestamp or datetime(2026, 1, 1, tzinfo=UTC),
        actor=actor,
        title=f"{entry_type.value}: {actor}",
        detail=detail or {},
    )


def _mock_trace(entries: list[DecisionTraceEntry]) -> DecisionTrace:
    return DecisionTrace(
        event_id="evt-test",
        entries=entries,
        summary=DecisionTraceSummary(),
    )


# --------------------------------------------------------------------------- #
# TrajectoryAnalyzer tests
# --------------------------------------------------------------------------- #


class TestTrajectoryAnalyzer:
    @pytest.mark.asyncio
    async def test_empty_trace_returns_insufficient(self) -> None:
        from app.services.trajectory_analyzer import TrajectoryAnalyzer

        mock_trace = _mock_trace([])
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=mock_trace)
        mock_sf = MagicMock()

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(
                "app.services.trajectory_analyzer.DecisionTraceService",
                lambda sf: mock_dt_service,
            )
            analyzer = TrajectoryAnalyzer(mock_sf)
            report = await analyzer.analyze("evt-empty")

        assert report.insufficient_trace is True
        assert report.total_steps == 0

    @pytest.mark.asyncio
    async def test_redundant_tool_calls_detected(self) -> None:
        from app.services.trajectory_analyzer import _DUPLICATE_TOOL_THRESHOLD, TrajectoryAnalyzer

        # Same tool + same params called 4 times
        entries = [
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_endpoint",
                {"tool_category": "query", "parameters": {"ip": "10.0.0.1"}},
            ),
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_endpoint",
                {"tool_category": "query", "parameters": {"ip": "10.0.0.1"}},
            ),
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_endpoint",
                {"tool_category": "query", "parameters": {"ip": "10.0.0.1"}},
            ),
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_endpoint",
                {"tool_category": "query", "parameters": {"ip": "10.0.0.1"}},
            ),
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "block_ip",
                {"tool_category": "action", "parameters": {"ip": "10.0.0.2"}},
            ),
        ]
        mock_trace = _mock_trace(entries)
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=mock_trace)

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(
                "app.services.trajectory_analyzer.DecisionTraceService",
                lambda sf: mock_dt_service,
            )
            analyzer = TrajectoryAnalyzer(MagicMock())
            report = await analyzer.analyze("evt-test")

        redundant = report.metrics.get(TrajectoryMetric.REDUNDANT_TOOL_CALLS, 0)
        assert redundant >= _DUPLICATE_TOOL_THRESHOLD  # 4 calls of same fingerprint
        assert any("冗余工具调用" in f for f in report.findings)

    @pytest.mark.asyncio
    async def test_no_redundant_when_below_threshold(self) -> None:
        from app.services.trajectory_analyzer import TrajectoryAnalyzer

        entries = [
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_endpoint",
                {"parameters": {"ip": "10.0.0.1"}},
            ),
            _entry(
                DecisionTraceEntryType.TOOL_CALL,
                "query_endpoint",
                {"parameters": {"ip": "10.0.0.1"}},
            ),  # only 2 calls < threshold
        ]
        mock_trace = _mock_trace(entries)
        mock_dt_service = MagicMock()
        mock_dt_service.get_decision_trace = AsyncMock(return_value=mock_trace)

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(
                "app.services.trajectory_analyzer.DecisionTraceService",
                lambda sf: mock_dt_service,
            )
            analyzer = TrajectoryAnalyzer(MagicMock())
            report = await analyzer.analyze("evt-test")

        assert report.metrics.get(TrajectoryMetric.REDUNDANT_TOOL_CALLS, 0) == 0.0

    @pytest.mark.asyncio
    async def test_loop_suspected_zero_for_normal_trace(self) -> None:
        from app.services.trajectory_analyzer import TrajectoryAnalyzer

        entries = [
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "triage_agent"),
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "evidence_agent"),
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "risk_agent"),
        ]
        mock_trace = _mock_trace(entries)

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(
                "app.services.trajectory_analyzer.DecisionTraceService",
                lambda sf: MagicMock(get_decision_trace=AsyncMock(return_value=mock_trace)),
            )
            analyzer = TrajectoryAnalyzer(MagicMock())
            report = await analyzer.analyze("evt-test")

        assert report.metrics.get(TrajectoryMetric.LOOP_SUSPECTED, 0) == 0.0

    @pytest.mark.asyncio
    async def test_replan_effectiveness_positive(self) -> None:
        from app.services.trajectory_analyzer import TrajectoryAnalyzer

        entries = [
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "verify_agent", {"status": "failed"}),
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "planner_agent"),
            _entry(DecisionTraceEntryType.AGENT_EXECUTION, "verify_agent", {"status": "success"}),
        ]
        mock_trace = _mock_trace(entries)

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(
                "app.services.trajectory_analyzer.DecisionTraceService",
                lambda sf: MagicMock(get_decision_trace=AsyncMock(return_value=mock_trace)),
            )
            analyzer = TrajectoryAnalyzer(MagicMock())
            report = await analyzer.analyze("evt-test")

        assert report.metrics.get(TrajectoryMetric.REPLAN_EFFECTIVENESS, 0) == 1.0

    @pytest.mark.asyncio
    async def test_api_response_structure(self) -> None:
        from app.models.trajectory import TrajectoryReport

        report = TrajectoryReport(
            event_id="evt-test",
            total_steps=5,
            agent_invocations=3,
            tool_calls=1,
            llm_calls=1,
            metrics={TrajectoryMetric.STEPS_TO_VERDICT: 5.0},
            findings=["轨迹分析未发现异常"],
        )
        data = report.model_dump()
        assert data["event_id"] == "evt-test"
        assert data["total_steps"] == 5
        assert data["metrics"]["steps_to_verdict"] == 5.0
        assert len(data["findings"]) == 1


__all__ = ["TestTrajectoryAnalyzer"]
