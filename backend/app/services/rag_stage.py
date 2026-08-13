"""Shared RAG stage helper for analysis-only pipeline and workflow graph (ISSUE-047/970).

Extracted from ``analysis_only_pipeline`` to break the import cycle:
``analysis_only_pipeline`` → ``orchestration.__init__`` → ``workflow_graph`` → RAG stage.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from celery.exceptions import SoftTimeLimitExceeded

from app.models.agent_io import EvidenceOutput, RAGAgentInput, RAGOutput, TriageResult
from app.services.tenant_resolution import resolve_tenant_id

logger = logging.getLogger(__name__)


class _AgentProtocol(Protocol):
    async def execute(self, input: Any) -> Any: ...


async def run_rag_stage(
    rag_agent: _AgentProtocol,
    *,
    event_id: str,
    triage_result: TriageResult,
    evidence_output: EvidenceOutput,
    tenant_id: str | None = None,
    principal: str | None = None,
    trace_id: str | None = None,
    source_snapshot: dict[str, Any] | None = None,
) -> tuple[RAGOutput | None, bool]:
    """Invoke RAGAgent between evidence and risk; never raise to callers."""
    resolved_tenant = tenant_id or resolve_tenant_id(source_snapshot)
    try:
        output = await rag_agent.execute(
            RAGAgentInput(
                event_id=event_id,
                triage_result=triage_result,
                evidence_output=evidence_output,
                tenant_id=resolved_tenant,
                principal=principal,
                trace_id=trace_id,
            )
        )
        if not isinstance(output, RAGOutput):
            logger.warning(
                "RAGAgent returned unexpected type %s for event=%s; degrading",
                type(output).__name__,
                event_id,
            )
            return None, True
        return output, bool(output.degraded)
    except SoftTimeLimitExceeded:
        # ISSUE-314: soft-limit ownership is task/intent; do not swallow.
        raise
    except Exception:
        logger.warning(
            "RAGAgent failed for event=%s; continuing without RAG enhancement",
            event_id,
            exc_info=True,
        )
        return None, True


__all__ = ["run_rag_stage"]
