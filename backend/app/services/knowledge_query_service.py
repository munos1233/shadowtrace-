"""Knowledge catalog query service for ``GET /api/v1/knowledge`` (ISSUE-279)."""

from __future__ import annotations

from typing import Any

from app.core.errors import ValidationError
from app.models.knowledge import KNOWLEDGE_KB_NAMES, ListedKnowledgeChunk, RetrievedChunk
from app.services.knowledge_store import KnowledgeStore


def _listed_item(chunk: ListedKnowledgeChunk) -> dict[str, Any]:
    return {
        "chunk_id": chunk.chunk_id,
        "kb_name": chunk.kb_name,
        "content": chunk.content,
        "metadata": chunk.metadata,
        "created_at": chunk.created_at.isoformat(),
    }


def _retrieved_item(chunk: RetrievedChunk) -> dict[str, Any]:
    return {
        "chunk_id": chunk.chunk_id,
        "kb_name": chunk.kb_name,
        "content": chunk.content,
        "metadata": chunk.metadata,
        "score": chunk.score,
        "retrieval_method": chunk.retrieval_method,
    }


class KnowledgeQueryService:
    """Paginated knowledge catalog backed by ``KnowledgeStore``."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    @staticmethod
    def _validate_kb_name(kb_name: str | None) -> None:
        if kb_name is not None and kb_name not in KNOWLEDGE_KB_NAMES:
            raise ValidationError(
                "invalid kb_name",
                details={
                    "kb_name": kb_name,
                    "allowed": sorted(KNOWLEDGE_KB_NAMES),
                },
            )

    async def list_knowledge(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        kb_name: str | None = None,
        q: str | None = None,
        tenant_id: str | None = None,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Return ``(total, items)`` from the real knowledge store."""
        self._validate_kb_name(kb_name)
        query = q.strip() if q is not None else ""
        if query:
            total, hits = await self._store.keyword_search_paginated(
                query,
                kb_name=kb_name,
                page=page,
                page_size=page_size,
                tenant_id=tenant_id,
            )
            return total, [_retrieved_item(hit) for hit in hits]

        total = await self._store.count_chunks(kb_name=kb_name, tenant_id=tenant_id)
        chunks = await self._store.list_chunks(
            kb_name=kb_name,
            page=page,
            page_size=page_size,
            tenant_id=tenant_id,
        )
        return total, [_listed_item(chunk) for chunk in chunks]


__all__ = ["KnowledgeQueryService"]
