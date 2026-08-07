"""ISSUE-211 — classification_source derive + ORM rewrite decision helpers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.config import get_settings
from app.models.enums import EventStatus, EventType
from app.services.classification_source import (
    EVENT_TYPE_ORM_REWRITE_FAILED_FLAG,
    EVENT_TYPE_ORM_REWRITE_SKIPPED_FLAG,
    ORM_REWRITE_SKIP_HINT,
    ORM_REWRITE_SKIP_HUMAN_HINT,
    OrmEventTypeRewriteOutcome,
    derive_classification_source,
    should_skip_orm_event_type_rewrite,
    snapshot_has_human_classification_override,
)
from app.services.event_service import EventService


def test_derive_classification_source_priority() -> None:
    assert (
        derive_classification_source(
            classification_override={"source": "human"},
            degraded_flags=["event_type_from_llm_fallback=true"],
        ).value
        == "human"
    )
    assert (
        derive_classification_source(degraded_flags=["event_type_from_llm_fallback=true"]).value
        == "llm_fallback"
    )
    assert (
        derive_classification_source(degraded_flags=["event_type_from_heuristic=true"]).value
        == "heuristic"
    )
    assert derive_classification_source(degraded_flags=[]).value == "source"
    assert (
        derive_classification_source(
            event_context_snapshot={
                "classification_override": {"source": "human", "event_type": "other"}
            },
            degraded_flags=["event_type_from_heuristic=true"],
        ).value
        == "human"
    )


def test_should_skip_orm_event_type_rewrite_locked_statuses() -> None:
    assert should_skip_orm_event_type_rewrite(EventStatus.EXECUTING_RESPONSE) is True
    assert should_skip_orm_event_type_rewrite(EventStatus.VERIFYING) is True
    assert should_skip_orm_event_type_rewrite(EventStatus.ANALYZING) is False
    assert should_skip_orm_event_type_rewrite("executing_response") is True
    assert should_skip_orm_event_type_rewrite("analyzing") is False


def test_snapshot_has_human_classification_override() -> None:
    assert (
        snapshot_has_human_classification_override(
            {"classification_override": {"source": "human", "event_type": "other"}}
        )
        is True
    )
    assert (
        snapshot_has_human_classification_override(
            {"classification_override": {"source": "heuristic"}}
        )
        is False
    )
    assert snapshot_has_human_classification_override(None) is False
    assert snapshot_has_human_classification_override({}) is False


class _AsyncCM:
    """Minimal async context manager for session / begin mocks."""

    def __init__(self, value: object | None = None) -> None:
        self._value = value if value is not None else self

    async def __aenter__(self) -> object:
        return self._value

    async def __aexit__(self, *args: object) -> None:
        return None


def _make_row(
    *,
    event_id: str,
    event_type: str,
    status: str,
    row_version: int = 1,
    event_context_snapshot: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        event_id=event_id,
        event_type=event_type,
        status=status,
        row_version=row_version,
        event_context_snapshot=event_context_snapshot,
        title="t",
        description="",
        severity="medium",
        risk_score=0,
        confidence=0.0,
        final_verdict="none",
        entities=None,
        creation_source_ref=None,
        source_reference_snapshots=None,
        current_primary_source_record_id=None,
        disposition_source_ref=None,
        disposition_policy="not_required",
        raw_alert_ids=None,
        raw_alert_snapshot=None,
        source_type=None,
        occurred_at=None,
        created_at=None,
        updated_at=None,
        closed_at=None,
        replan_count=0,
        degraded_flags=[],
        escalated=False,
        external_unsynced=False,
    )


@pytest.mark.asyncio
async def test_rewrite_event_type_skipped_when_gate_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIAGE_REWRITE_EVENT_TYPE", "false")
    get_settings.cache_clear()

    service = EventService(
        session_factory=MagicMock(),
        store=MagicMock(),
        degraded_flags=MagicMock(),
    )
    outcome = await service.rewrite_event_type_from_triage(
        "evt-gate-off",
        event_type=EventType.DATA_EXFILTRATION,
    )
    assert outcome is OrmEventTypeRewriteOutcome.SKIPPED_GATE
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rewrite_event_type_applied_updates_orm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRIAGE_REWRITE_EVENT_TYPE", "true")
    get_settings.cache_clear()

    row = _make_row(
        event_id="evt-211-apply",
        event_type=EventType.OTHER.value,
        status=EventStatus.ANALYZING.value,
        row_version=1,
    )

    session = AsyncMock()
    session.get = AsyncMock(side_effect=[row, row])
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.begin = MagicMock(return_value=_AsyncCM())

    session_factory = MagicMock(return_value=_AsyncCM(session))
    store = AsyncMock()
    store.set = AsyncMock(return_value=SimpleNamespace(redis_ok=True))

    service = EventService(
        session_factory=session_factory,
        store=store,
        degraded_flags=AsyncMock(),
    )

    fake_event = SimpleNamespace(row_version=2)
    fake_summary = SimpleNamespace()
    with (
        patch(
            "app.services.event_service._security_event_from_row",
            return_value=fake_event,
        ),
        patch(
            "app.services.event_service.event_summary_from_security_event",
            return_value=fake_summary,
        ),
    ):
        outcome = await service.rewrite_event_type_from_triage(
            "evt-211-apply",
            event_type=EventType.DATA_EXFILTRATION,
        )

    assert outcome is OrmEventTypeRewriteOutcome.APPLIED
    assert row.event_type == EventType.DATA_EXFILTRATION.value
    assert row.row_version == 2
    assert session.add.called
    store.set.assert_awaited()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rewrite_event_type_skipped_when_executing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRIAGE_REWRITE_EVENT_TYPE", "true")
    get_settings.cache_clear()

    row = _make_row(
        event_id="evt-211-locked",
        event_type=EventType.OTHER.value,
        status=EventStatus.EXECUTING_RESPONSE.value,
        row_version=3,
    )

    session = AsyncMock()
    session.get = AsyncMock(return_value=row)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.begin = MagicMock(return_value=_AsyncCM())

    session_factory = MagicMock(return_value=_AsyncCM(session))
    degraded = AsyncMock()
    degraded.set_flag = AsyncMock(return_value=[])

    service = EventService(
        session_factory=session_factory,
        store=AsyncMock(),
        degraded_flags=degraded,
    )
    outcome = await service.rewrite_event_type_from_triage(
        "evt-211-locked",
        event_type=EventType.DATA_EXFILTRATION,
    )
    assert outcome is OrmEventTypeRewriteOutcome.SKIPPED_LOCKED
    assert row.event_type == EventType.OTHER.value  # unchanged
    degraded.set_flag.assert_awaited()
    flag_call = degraded.set_flag.await_args
    assert flag_call.args[1] == EVENT_TYPE_ORM_REWRITE_SKIPPED_FLAG
    assert flag_call.args[2] == ORM_REWRITE_SKIP_HINT
    assert session.add.called
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rewrite_event_type_skipped_when_verifying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRIAGE_REWRITE_EVENT_TYPE", "true")
    get_settings.cache_clear()

    row = _make_row(
        event_id="evt-211-verify",
        event_type=EventType.OTHER.value,
        status=EventStatus.VERIFYING.value,
    )
    session = AsyncMock()
    session.get = AsyncMock(return_value=row)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.begin = MagicMock(return_value=_AsyncCM())
    degraded = AsyncMock()
    degraded.set_flag = AsyncMock(return_value=[])

    service = EventService(
        session_factory=MagicMock(return_value=_AsyncCM(session)),
        store=AsyncMock(),
        degraded_flags=degraded,
    )
    outcome = await service.rewrite_event_type_from_triage(
        "evt-211-verify",
        event_type=EventType.INSIDER_THREAT,
    )
    assert outcome is OrmEventTypeRewriteOutcome.SKIPPED_LOCKED
    assert row.event_type == EventType.OTHER.value
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rewrite_event_type_skipped_when_human_override_in_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Blocker fix: never clobber ISSUE-209 human PATCH via machine rewrite."""
    monkeypatch.setenv("TRIAGE_REWRITE_EVENT_TYPE", "true")
    get_settings.cache_clear()

    row = _make_row(
        event_id="evt-211-human",
        event_type=EventType.DATA_EXFILTRATION.value,
        status=EventStatus.ANALYZING.value,
        event_context_snapshot={
            "classification_override": {
                "source": "human",
                "event_type": "data_exfiltration",
                "reason": "analyst override",
            }
        },
    )
    session = AsyncMock()
    session.get = AsyncMock(return_value=row)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.begin = MagicMock(return_value=_AsyncCM())

    service = EventService(
        session_factory=MagicMock(return_value=_AsyncCM(session)),
        store=AsyncMock(),
        degraded_flags=AsyncMock(),
    )
    outcome = await service.rewrite_event_type_from_triage(
        "evt-211-human",
        event_type=EventType.MALICIOUS_PROCESS,
    )
    assert outcome is OrmEventTypeRewriteOutcome.SKIPPED_HUMAN
    assert row.event_type == EventType.DATA_EXFILTRATION.value
    assert session.add.called
    audit = session.add.call_args.args[0]
    assert "event_type_orm_rewrite_skipped_human" in (audit.reason or "")
    assert ORM_REWRITE_SKIP_HUMAN_HINT in (audit.reason or "")
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rewrite_event_type_noop_when_already_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRIAGE_REWRITE_EVENT_TYPE", "true")
    get_settings.cache_clear()

    row = _make_row(
        event_id="evt-211-noop",
        event_type=EventType.DATA_EXFILTRATION.value,
        status=EventStatus.ANALYZING.value,
    )
    session = AsyncMock()
    session.get = AsyncMock(return_value=row)
    session.add = MagicMock()
    session.begin = MagicMock(return_value=_AsyncCM())

    service = EventService(
        session_factory=MagicMock(return_value=_AsyncCM(session)),
        store=AsyncMock(),
        degraded_flags=AsyncMock(),
    )
    outcome = await service.rewrite_event_type_from_triage(
        "evt-211-noop",
        event_type=EventType.DATA_EXFILTRATION,
    )
    assert outcome is OrmEventTypeRewriteOutcome.NOOP
    assert not session.add.called
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rewrite_event_type_failed_sets_degraded_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRIAGE_REWRITE_EVENT_TYPE", "true")
    get_settings.cache_clear()

    session = AsyncMock()
    session.get = AsyncMock(side_effect=RuntimeError("db down"))
    session.begin = MagicMock(return_value=_AsyncCM())
    session.add = MagicMock()
    session_factory = MagicMock(return_value=_AsyncCM(session))
    degraded = AsyncMock()
    degraded.set_flag = AsyncMock(return_value=[])

    service = EventService(
        session_factory=session_factory,
        store=AsyncMock(),
        degraded_flags=degraded,
    )
    outcome = await service.rewrite_event_type_from_triage(
        "evt-211-fail",
        event_type=EventType.DATA_EXFILTRATION,
    )
    assert outcome is OrmEventTypeRewriteOutcome.FAILED
    degraded.set_flag.assert_awaited()
    flag_call = degraded.set_flag.await_args
    assert flag_call.args[1] == EVENT_TYPE_ORM_REWRITE_FAILED_FLAG
    get_settings.cache_clear()
