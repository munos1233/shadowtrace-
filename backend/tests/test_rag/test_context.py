"""RetrievalContext validation tests (ISSUE-138)."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.models.agent_io import CollectionStatus, EvidenceOutput, RAGAgentInput, TriageResult
from app.models.enums import EventType, Severity
from app.rag.context import RetrievalContext
from tests.test_support.production_settings import production_settings


def _rag_input(**overrides: object) -> RAGAgentInput:
    base = RAGAgentInput(
        event_id="evt-test-001",
        triage_result=TriageResult(
            event_type=EventType.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            need_investigation=True,
        ),
        evidence_output=EvidenceOutput(collection_status=CollectionStatus.COMPLETED),
    )
    return base.model_copy(update=overrides)


def test_retrieval_context_rejects_nil_uuid_tenant() -> None:
    with pytest.raises(ValueError, match="nil UUID"):
        RetrievalContext(
            tenant_id="00000000-0000-0000-0000-000000000000",
            principal="investigation:rag_agent",
            event_id="evt-1",
            trace_id="trace-1",
        )


def test_retrieval_context_rejects_empty_event_id() -> None:
    with pytest.raises(ValueError, match="event_id"):
        RetrievalContext(
            tenant_id="local",
            principal="investigation:rag_agent",
            event_id="  ",
            trace_id="trace-1",
        )


def test_from_rag_input_uses_explicit_fields() -> None:
    ctx = RetrievalContext.from_rag_input(
        _rag_input(
            tenant_id="tenant-a",
            principal="investigation:super_agent",
            trace_id="abc123",
        )
    )
    assert ctx.tenant_id == "tenant-a"
    assert ctx.principal == "investigation:super_agent"
    assert ctx.event_id == "evt-test-001"
    assert ctx.trace_id == "abc123"


def test_from_rag_input_falls_back_to_settings_default_tenant() -> None:
    settings = Settings(retrieval_default_tenant_id="configured-tenant")
    ctx = RetrievalContext.from_rag_input(_rag_input(), settings=settings)
    assert ctx.tenant_id == "configured-tenant"
    assert ctx.trace_id == "evt:evt-test-001"


def test_from_rag_input_requires_tenant_in_production() -> None:
    settings = production_settings(
        retrieval_default_tenant_id="local",
    )
    with pytest.raises(ValueError, match="tenant_id is required"):
        RetrievalContext.from_rag_input(_rag_input(), settings=settings)


def test_for_investigation_resolves_tenant_from_source_snapshot() -> None:
    ctx = RetrievalContext.for_investigation(
        event_id="evt-42",
        source_snapshot={
            "creation_source_ref": {"source_tenant_id": "tenant-from-snapshot"},
        },
        principal="investigation:workflow_graph",
        trace_id="trace-42",
    )
    assert ctx.tenant_id == "tenant-from-snapshot"
    assert ctx.principal == "investigation:workflow_graph"
    assert ctx.trace_id == "trace-42"


def test_for_investigation_requires_tenant_in_production() -> None:
    settings = production_settings()
    with pytest.raises(ValueError, match="tenant_id is required"):
        RetrievalContext.for_investigation(
            event_id="evt-prod",
            settings=settings,
        )
