"""DecisionTraceService tests (ISSUE-063).

Covers:
1. Empty event returns empty trace
2. Mixed entry types are sorted by timestamp
3. entry_type filter works
4. Summary counts match entries
5. Missing source is recorded, other sources still return
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.decision_trace_service import (
    DecisionTraceEntry,
    DecisionTraceService,
    _compute_summary,
    _sort_key,
)

# --------------------------------------------------------------------------- #
# _sort_key / _compute_summary — unit tests
# --------------------------------------------------------------------------- #


class TestSortKey:
    def test_timestamp_takes_priority(self) -> None:
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        t2 = datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC)
        e1 = DecisionTraceEntry("a", "agent_execution", t1, "x", "t")
        e2 = DecisionTraceEntry("b", "state_transition", t2, "x", "t")
        assert _sort_key(e1) < _sort_key(e2)

    def test_same_timestamp_entry_type_order(self) -> None:
        t = datetime(2026, 1, 1, tzinfo=UTC)
        e_st = DecisionTraceEntry("a", "state_transition", t, "x", "t")
        e_agent = DecisionTraceEntry("b", "agent_execution", t, "x", "t")
        assert _sort_key(e_st) < _sort_key(e_agent)


class TestComputeSummary:
    def test_empty(self) -> None:
        s = _compute_summary([])
        assert s.agent_count == 0
        assert s.total_tokens == 0
        assert s.total_duration_ms == 0

    def test_mixed_entries(self) -> None:
        t = datetime(2026, 1, 1, tzinfo=UTC)
        entries = [
            DecisionTraceEntry("1", "agent_execution", t, "a", "t"),
            DecisionTraceEntry("2", "llm_call", t, "a", "t", detail={"total_tokens": 500}),
            DecisionTraceEntry("3", "llm_call", t, "a", "t", detail={"total_tokens": 300}),
            DecisionTraceEntry("4", "tool_call", t, "a", "t"),
            DecisionTraceEntry("5", "state_transition", t, "a", "t"),
            DecisionTraceEntry("6", "approval", t, "a", "t"),
            DecisionTraceEntry("7", "action_execution", t, "a", "t"),
            DecisionTraceEntry("8", "disposition", t, "a", "t"),
            DecisionTraceEntry("9", "writeback", t, "a", "t"),
        ]
        s = _compute_summary(entries)
        assert s.agent_count == 1
        assert s.llm_call_count == 2
        assert s.total_tokens == 800
        assert s.tool_call_count == 1
        assert s.state_transition_count == 1
        assert s.approval_count == 1
        assert s.action_execution_count == 1
        assert s.disposition_count == 1
        assert s.writeback_count == 1

    def test_total_duration(self) -> None:
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        t2 = datetime(2026, 1, 1, 12, 0, 5, tzinfo=UTC)
        entries = [
            DecisionTraceEntry("1", "agent_execution", t1, "a", "t"),
            DecisionTraceEntry("2", "agent_execution", t2, "a", "t"),
        ]
        s = _compute_summary(entries)
        assert s.total_duration_ms == 5000


# --------------------------------------------------------------------------- #
# DecisionTraceService.get_decision_trace — integration-style
# --------------------------------------------------------------------------- #


class TestDecisionTraceService:
    """Test the service via a mocked SQLAlchemy session."""

    @pytest.mark.asyncio
    async def test_empty_event_returns_empty_trace(self) -> None:
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=[])))
        mock_sf = MagicMock()
        mock_sf.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

        service = DecisionTraceService(mock_sf)
        trace = await service.get_decision_trace("evt-empty")

        assert trace.event_id == "evt-empty"
        assert trace.entries == []
        assert trace.summary.agent_count == 0

    @pytest.mark.asyncio
    async def test_entries_sorted_by_timestamp(self) -> None:
        """Entries from multiple sources are merged and sorted."""
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        t2 = datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC)
        t3 = datetime(2026, 1, 1, 12, 0, 2, tzinfo=UTC)

        from app.db import models as orm

        agent_row = MagicMock(
            spec=orm.AgentTrace,
            trace_id="tr-1",
            event_id="evt-1",
            agent_name="triage_agent",
            status="success",
            started_at=t1,
            completed_at=None,
            duration_ms=100,
            llm_model=None,
            llm_tokens_used=None,
        )

        llm_row = MagicMock(
            spec=orm.LLMCallLog,
            id=1,
            event_id="evt-1",
            agent_name="triage_agent",
            prompt_key="triage",
            model_name="mock",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            latency_ms=200,
            fallback_level=0,
            status="success",
            created_at=t2,
        )

        state_row = MagicMock(
            spec=orm.EventAuditLog,
            id=1,
            event_id="evt-1",
            from_status="new",
            to_status="triaging",
            operator="SuperAgent",
            reason=None,
            created_at=t3,
        )

        def _scalar_side_effect(rows: list[Any]) -> MagicMock:
            return MagicMock(__iter__=lambda self: iter(rows))

        async def _execute_side_effect(stmt: Any) -> MagicMock:
            result = MagicMock()
            # Figure out which table is being queried from the stmt
            stmt_str = str(stmt)
            if "agent_trace" in stmt_str:
                result.scalars = lambda: _scalar_side_effect([agent_row])
            elif "llm_call_log" in stmt_str:
                result.scalars = lambda: _scalar_side_effect([llm_row])
            elif "event_audit_log" in stmt_str:
                result.scalars = lambda: _scalar_side_effect([state_row])
            else:
                result.scalars = lambda: _scalar_side_effect([])
            return result

        mock_session = AsyncMock()
        mock_session.execute = _execute_side_effect
        mock_sf = MagicMock()
        mock_sf.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

        service = DecisionTraceService(mock_sf)
        trace = await service.get_decision_trace("evt-1")

        assert len(trace.entries) == 3
        # Should be sorted: t1 (agent), t2 (llm), t3 (state)
        assert trace.entries[0].entry_type == "agent_execution"
        assert trace.entries[1].entry_type == "llm_call"
        assert trace.entries[2].entry_type == "state_transition"

    @pytest.mark.asyncio
    async def test_source_failure_is_recorded_not_fatal(self) -> None:
        """When one source fails, it's recorded in missing_sources and others return."""
        from app.db import models as orm

        agent_row = MagicMock(
            spec=orm.AgentTrace,
            trace_id="tr-2",
            event_id="evt-2",
            agent_name="triage_agent",
            status="success",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            completed_at=None,
            duration_ms=0,
            llm_model=None,
            llm_tokens_used=None,
        )

        async def _failing_execute(stmt: Any) -> MagicMock:
            stmt_str = str(stmt)
            if "llm_call_log" in stmt_str:
                raise RuntimeError("simulated DB error")
            result = MagicMock()
            if "agent_trace" in stmt_str:
                result.scalars = lambda: MagicMock(__iter__=lambda self: iter([agent_row]))
            else:
                result.scalars = lambda: MagicMock(__iter__=lambda self: iter([]))
            return result

        mock_session = AsyncMock()
        mock_session.execute = _failing_execute
        mock_sf = MagicMock()
        mock_sf.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

        service = DecisionTraceService(mock_sf)
        trace = await service.get_decision_trace("evt-2")

        assert "llm_call" in trace.missing_sources
        assert len(trace.entries) == 1
        assert trace.entries[0].entry_type == "agent_execution"

    @pytest.mark.asyncio
    async def test_summary_matches_entries(self) -> None:
        """Summary counts are derived from actual entries."""
        from app.db import models as orm

        t = datetime(2026, 1, 1, tzinfo=UTC)
        agent_row = MagicMock(
            spec=orm.AgentTrace,
            trace_id="tr-3",
            event_id="evt-3",
            agent_name="triage",
            status="success",
            started_at=t,
            completed_at=None,
            duration_ms=100,
            llm_model=None,
            llm_tokens_used=None,
        )

        async def _execute(stmt: Any) -> MagicMock:
            result = MagicMock()
            if "agent_trace" in str(stmt):
                result.scalars = lambda: MagicMock(__iter__=lambda self: iter([agent_row]))
            else:
                result.scalars = lambda: MagicMock(__iter__=lambda self: iter([]))
            return result

        mock_session = AsyncMock()
        mock_session.execute = _execute
        mock_sf = MagicMock()
        mock_sf.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

        service = DecisionTraceService(mock_sf)
        trace = await service.get_decision_trace("evt-3")

        assert trace.summary.agent_count == 1
        assert trace.summary.llm_call_count == 0


__all__ = [
    "TestSortKey",
    "TestComputeSummary",
    "TestDecisionTraceService",
]
