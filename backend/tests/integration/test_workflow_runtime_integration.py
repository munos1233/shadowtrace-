"""WorkflowRuntimeService integration tests (ISSUE-048)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
)
from app.models.source import SourceReference
from app.orchestration.workflow_runtime import WorkflowRuntimeService
from app.services.context_service import EventContextStore, append_context_journal_in_session
from app.services.event_service import EventService, IngestableSource

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("clean_state"),
]


def _ref(object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-workflow-runtime",
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_begin_disposition_only_db_atomic(
    event_service: EventService,
    context_store: EventContextStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Verdict, confidence, and intent persist atomically via EventService."""
    created = await event_service.ingest_source_object(
        IngestableSource(
            reference=_ref("INC-workflow-runtime-fp"),
            title="disposition-only",
            event_type=EventType.OTHER,
            severity=Severity.MEDIUM,
            source_type="mock_xdr",
        )
    )
    assert created.event_id
    event_id = created.event_id

    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.SecurityEvent, event_id, with_for_update=True)
            assert row is not None
            row.status = EventStatus.TRIAGING.value
            row.disposition_policy = DispositionPolicy.REQUIRED.value
            await append_context_journal_in_session(
                session,
                event_id,
                "false_positive_match",
                {"recommendation": "close_as_fp", "max_score": 0.88},
            )

    runtime = WorkflowRuntimeService(
        session_factory,
        event_service=event_service,
        context_store=context_store,
    )
    await runtime.begin_disposition_only(event_id)

    async with session_factory() as session:
        row = await session.get(orm.SecurityEvent, event_id)
        assert row is not None
        assert row.final_verdict == FinalVerdict.FALSE_POSITIVE.value
        assert float(row.confidence) >= 0.88

        intent_row = await session.scalar(
            select(orm.EventContextJournal)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "disposition_only_intent",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        assert intent_row is not None
        assert intent_row.value == {"_scalar": True}

    assert await runtime.read_disposition_only_intent(event_id) is True
    assert await context_store.get(event_id, "disposition_only_intent") is True
