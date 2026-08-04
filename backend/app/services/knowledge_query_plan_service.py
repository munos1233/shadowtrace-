"""Resolve request-scoped KnowledgeQueryPlan at retrieval entry (ISSUE-128 / #634)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.models.knowledge_release import (
    ATTACK_CORPUS_ID,
    ATTACK_KB_NAME,
    KnowledgeQueryPlan,
)
from app.services.knowledge_release_resolver import corpus_to_kb_name
from app.services.knowledge_release_service import KnowledgeReleaseService
from app.services.knowledge_store import KnowledgeStore

logger = logging.getLogger(__name__)


def resolve_knowledge_query_plan(
    *,
    corpus_id: str,
    active_release_id: str,
    embedding_release_id: str,
    trace_id: str,
    kb_name: str | None = None,
    tenant_id: str = "",
    principal: str = "",
) -> KnowledgeQueryPlan:
    """Build an immutable query plan pinned to explicit release ids."""
    resolved_kb = kb_name or corpus_to_kb_name(corpus_id)
    if resolved_kb is None:
        raise ValueError(f"no kb mapping for corpus_id={corpus_id}")
    return KnowledgeQueryPlan(
        corpus_id=corpus_id,
        kb_name=resolved_kb,
        active_release_id=active_release_id,
        embedding_release_id=embedding_release_id,
        trace_id=trace_id,
        tenant_id=tenant_id.strip(),
        principal=principal.strip(),
        pinned_at=datetime.now(UTC),
    )


async def resolve_active_knowledge_query_plan(
    service: KnowledgeReleaseService,
    settings: Settings,
    *,
    corpus_id: str = ATTACK_CORPUS_ID,
    trace_id: str,
) -> KnowledgeQueryPlan | None:
    """Pin the currently active knowledge + embedding releases for one request."""
    active = await service.get_active_release(corpus_id)
    if active is None:
        logger.debug("no active knowledge release for corpus=%s", corpus_id)
        return None
    if active.vector_ready and active.embedding_release_id:
        embedding_release_id = active.embedding_release_id
    else:
        embedding_release_id = build_embedding_release(settings).release_id
    return resolve_knowledge_query_plan(
        corpus_id=corpus_id,
        active_release_id=active.release_id,
        embedding_release_id=embedding_release_id,
        trace_id=trace_id,
        kb_name=corpus_to_kb_name(corpus_id) or ATTACK_KB_NAME,
    )


def build_release_service(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    store: KnowledgeStore | None = None,
    settings: Settings | None = None,
) -> KnowledgeReleaseService:
    return KnowledgeReleaseService(session_factory, store=store, settings=settings)


__all__ = [
    "build_release_service",
    "resolve_active_knowledge_query_plan",
    "resolve_knowledge_query_plan",
]
