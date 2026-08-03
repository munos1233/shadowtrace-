"""Read-only mock query adapter for shadow ReAct pivot (ISSUE-135 / #641 Phase A).

Routes authorized retrieval through ``RetrievalPipeline`` with a validated
``KnowledgeQueryPlan``. Never writes production stores.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.models.knowledge_release import KnowledgeQueryPlanHints
from app.rag.context import RetrievalContext
from app.rag.pipeline import RetrievalPipeline
from app.services.knowledge_query_plan_service import resolve_active_knowledge_query_plan
from app.services.knowledge_query_plan_validator import validate_knowledge_query_plan
from app.services.knowledge_release_service import KnowledgeReleaseService

logger = logging.getLogger(__name__)

MOCK_QUERY_AGENT_NAME = "mock_query_retrieval"


@dataclass(frozen=True, slots=True)
class ReactMockQueryContext:
    """Trusted execution context injected by the shadow pivot service."""

    event_id: str
    tenant_id: str
    principal: str
    trace_id: str
    shadow_run_id: str


class ReactMockQueryAdapter:
    """``call_agent`` adapter: validated plan + RetrievalPipeline only."""

    def __init__(
        self,
        pipeline: RetrievalPipeline,
        *,
        knowledge_release_service: KnowledgeReleaseService | None,
        settings: Settings,
    ) -> None:
        self._pipeline = pipeline
        self._knowledge_release_service = knowledge_release_service
        self._settings = settings

    async def execute(
        self, params: dict[str, Any], *, ctx: ReactMockQueryContext
    ) -> dict[str, Any]:
        query = str(params.get("query", "")).strip()
        if not query:
            return {"status": "denied", "reason": "missing_query", "data": {}}

        if params.get("tenant_id") and str(params["tenant_id"]).strip() != ctx.tenant_id:
            return {"status": "denied", "reason": "cross_tenant_denied", "data": {}}

        kb_names_raw = params.get("kb_names") or ["attack_kb"]
        if not isinstance(kb_names_raw, list):
            return {"status": "denied", "reason": "invalid_kb_names", "data": {}}
        kb_names = [str(name).strip() for name in kb_names_raw if str(name).strip()]
        if not kb_names:
            return {"status": "denied", "reason": "empty_kb_names", "data": {}}

        top_k = int(params.get("top_k", 3))
        if top_k < 1 or top_k > 20:
            return {"status": "denied", "reason": "top_k_out_of_bounds", "data": {}}

        base_plan = None
        if self._knowledge_release_service is not None:
            base_plan = await resolve_active_knowledge_query_plan(
                self._knowledge_release_service,
                self._settings,
                trace_id=ctx.trace_id,
            )
        if base_plan is None:
            return {
                "status": "degraded",
                "reason": "no_active_knowledge_release",
                "data": {},
            }

        active_embedding = build_embedding_release(self._settings).release_id
        hints = KnowledgeQueryPlanHints(
            source_ids=[str(s) for s in params.get("source_ids", []) if str(s).strip()],
            content_types=[str(c) for c in params.get("content_types", []) if str(c).strip()],
            top_k=top_k if top_k <= base_plan.budget.top_k else None,
        )
        outcome = validate_knowledge_query_plan(
            base_plan,
            tenant_id=ctx.tenant_id,
            principal=ctx.principal,
            kb_names=kb_names,
            active_embedding_release_id=active_embedding,
            hints=hints,
        )
        if not outcome.accepted or outcome.plan is None:
            return {
                "status": "denied",
                "reason": "plan_rejected",
                "rejected_reasons": outcome.rejected_reasons,
                "data": {},
            }

        planned_kb = outcome.plan.kb_name
        if set(kb_names) != {planned_kb}:
            return {
                "status": "denied",
                "reason": "kb_scope_mismatch",
                "rejected_reasons": ["plan_kb_scope_mismatch"],
                "data": {},
            }

        context = RetrievalContext(
            tenant_id=ctx.tenant_id,
            principal=ctx.principal,
            event_id=ctx.event_id,
            trace_id=ctx.trace_id,
            query_plan=outcome.plan,
        )
        result = await self._pipeline.retrieve(
            query,
            [planned_kb],
            top_k=min(top_k, outcome.plan.budget.top_k),
            context=context,
            plan_hints=hints,
        )
        plan_payload = result.knowledge_query_plan
        if isinstance(plan_payload, dict) and plan_payload.get("rejected_reasons"):
            return {
                "status": "denied",
                "reason": "plan_rejected",
                "rejected_reasons": list(plan_payload["rejected_reasons"]),
                "data": {},
            }
        if "knowledge_query_plan_rejected" in result.degraded_steps:
            rejected = [
                step for step in result.degraded_steps if step != "knowledge_query_plan_rejected"
            ]
            return {
                "status": "denied",
                "reason": "plan_rejected",
                "rejected_reasons": rejected or ["knowledge_query_plan_rejected"],
                "data": {},
            }

        chunks = [
            {
                "chunk_id": chunk.chunk_id,
                "kb_name": chunk.kb_name,
                "score": chunk.score,
                "retrieval_method": chunk.retrieval_method,
                "metadata": {
                    key: chunk.metadata.get(key)
                    for key in ("source_id", "content_type", "release_id", "tenant_id")
                    if key in chunk.metadata
                },
            }
            for chunk in result.chunks[:top_k]
        ]
        return {
            "status": "success",
            "agent_name": MOCK_QUERY_AGENT_NAME,
            "data": {
                "query": query,
                "kb_names": [planned_kb],
                "chunk_count": len(chunks),
                "chunks": chunks,
                "plan_hash": outcome.sanitized_plan_hash,
                "degraded_steps": list(result.degraded_steps),
            },
        }


def build_mock_query_agent_callable(
    adapter: ReactMockQueryAdapter,
    ctx: ReactMockQueryContext,
):
    async def _call(params: dict[str, Any]) -> dict[str, Any]:
        return await adapter.execute(params, ctx=ctx)

    return _call


__all__ = [
    "MOCK_QUERY_AGENT_NAME",
    "ReactMockQueryAdapter",
    "ReactMockQueryContext",
    "build_mock_query_agent_callable",
]
