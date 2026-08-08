"""ISSUE-266: authoritative analysis_only_complete persistence."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.models.enums import DispositionPolicy, EventStatus
from app.services.analysis_only_complete_persistence import (
    persist_analysis_only_complete_authoritative,
)
from app.services.event_context_snapshot_projection import (
    merge_analysis_only_complete_into_snapshot,
)
from app.services.investigation_guidance import (
    derive_investigation_guidance,
    resolve_analysis_only_complete,
)


def test_merge_analysis_only_complete_monotonic_true() -> None:
    snapshot = merge_analysis_only_complete_into_snapshot(
        {"analysis_only_complete": True},
        False,
    )
    assert snapshot["analysis_only_complete"] is True


def test_resolve_analysis_only_complete_journal_overlay() -> None:
    assert resolve_analysis_only_complete(
        context_snapshot={"analysis_only_complete": False},
        journal_value=True,
    )


def test_guidance_closed_uses_journal_overlay_for_analysis_only_complete() -> None:
    guidance = derive_investigation_guidance(
        status=EventStatus.CLOSED,
        disposition_policy=DispositionPolicy.NOT_REQUIRED,
        context_snapshot={"analysis_only_complete": False},
        orchestration_mode="graph",
        journal_analysis_only_complete=True,
    )
    assert guidance.analysis_only_complete is True
    assert guidance.response_phase_state.value == "complete"


@pytest.mark.asyncio
async def test_persist_analysis_only_complete_redis_degraded_still_merges_snapshot() -> None:
    """Redis failure must not drop durable snapshot truth."""
    event_id = "evt-aoc-redis-mock"
    store = AsyncMock()
    store.get = AsyncMock(return_value=False)
    store.set = AsyncMock(side_effect=RuntimeError("redis down"))
    store.refresh_closed_snapshot = AsyncMock()

    event_service = AsyncMock()
    event_service.get_event = AsyncMock(return_value=None)
    event_service.merge_analysis_only_complete_context_snapshot = AsyncMock()
    degraded = AsyncMock()
    degraded.set_flag = AsyncMock(return_value=["redis_context_unavailable"])

    ok = await persist_analysis_only_complete_authoritative(
        event_id,
        context_store=store,
        event_service=event_service,
        degraded_flags=degraded,
        refresh_closed_snapshot=False,
    )
    assert ok is False
    degraded.set_flag.assert_awaited()
    event_service.merge_analysis_only_complete_context_snapshot.assert_awaited_once_with(
        event_id,
        True,
    )


@pytest.mark.asyncio
async def test_persist_analysis_only_complete_concurrent_old_write_cannot_downgrade() -> None:
    """Established journal true skips rewrite; snapshot merge stays monotonic."""
    event_id = "evt-aoc-cas-mock"
    store = AsyncMock()
    store.get = AsyncMock(return_value=True)
    store.set = AsyncMock()
    store.refresh_closed_snapshot = AsyncMock()

    event_service = AsyncMock()
    event_service.merge_analysis_only_complete_context_snapshot = AsyncMock()

    ok = await persist_analysis_only_complete_authoritative(
        event_id,
        context_store=store,
        event_service=event_service,
        refresh_closed_snapshot=False,
    )
    assert ok is True
    store.set.assert_not_awaited()
    event_service.merge_analysis_only_complete_context_snapshot.assert_awaited_once_with(
        event_id,
        True,
    )

    merged = merge_analysis_only_complete_into_snapshot(
        {"analysis_only_complete": True},
        False,
    )
    assert merged["analysis_only_complete"] is True
