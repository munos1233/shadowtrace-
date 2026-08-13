"""run_rag_stage retrieval context propagation tests (ISSUE-138)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    RAGAgentInput,
    RAGOutput,
    TriageResult,
)
from app.models.enums import EventType, Severity
from app.services.rag_stage import run_rag_stage


def _triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
    )


def _evidence() -> EvidenceOutput:
    return EvidenceOutput(collection_status=CollectionStatus.COMPLETED)


class _CapturingRAGAgent:
    def __init__(self) -> None:
        self.inputs: list[RAGAgentInput] = []

    async def execute(self, input: RAGAgentInput) -> RAGOutput:
        self.inputs.append(input)
        return RAGOutput(degraded=True)


@pytest.mark.asyncio
async def test_run_rag_stage_propagates_explicit_context_fields() -> None:
    agent = _CapturingRAGAgent()
    await run_rag_stage(
        agent,
        event_id="evt-001",
        triage_result=_triage(),
        evidence_output=_evidence(),
        tenant_id="tenant-alpha",
        principal="investigation:super_agent",
        trace_id="trace-xyz",
    )
    assert len(agent.inputs) == 1
    captured = agent.inputs[0]
    assert captured.tenant_id == "tenant-alpha"
    assert captured.principal == "investigation:super_agent"
    assert captured.trace_id == "trace-xyz"


@pytest.mark.asyncio
async def test_run_rag_stage_resolves_tenant_from_source_snapshot() -> None:
    agent = _CapturingRAGAgent()
    await run_rag_stage(
        agent,
        event_id="evt-002",
        triage_result=_triage(),
        evidence_output=_evidence(),
        source_snapshot={
            "creation_source_ref": {"source_tenant_id": "tenant-from-snapshot"},
        },
        principal="investigation:workflow_graph",
    )
    assert agent.inputs[0].tenant_id == "tenant-from-snapshot"
    assert agent.inputs[0].principal == "investigation:workflow_graph"


def test_run_investigation_finally_releases_loop_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.app.task import Context

    release_mock = MagicMock()
    monkeypatch.setattr(
        "app.tasks.investigation_tasks._release_celery_task_loop_resources",
        release_mock,
    )
    monkeypatch.setattr(
        "app.tasks.investigation_tasks._run_investigation_body",
        AsyncMock(return_value={"status": "ok"}),
    )

    from app.tasks import investigation_tasks as tasks

    ctx = Context(id="task-release-test", delivery_info={}, retries=0)
    tasks.run_investigation.request_stack.push(ctx)
    try:
        result = tasks.run_investigation.run("evt-release-test")
    finally:
        tasks.run_investigation.request_stack.pop()
    assert result["status"] == "ok"
    release_mock.assert_called_once()
