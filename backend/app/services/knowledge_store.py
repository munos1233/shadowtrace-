"""KnowledgeStore: pgvector-backed chunk upsert and similarity retrieval (ISSUE-041).

#636 Phase A note: tenant/release/embedding pre-filters enforced on ``vector_search`` /
``keyword_search`` when callers pass scoped parameters. ``RetrievalPipeline`` with a
validated ``KnowledgeQueryPlan`` is the supported path for release-pinned retrieval.
Legacy helpers ``vector_search_query`` / ``hybrid_search`` do not apply plan validation
(#644 production wiring). Graph retrieval is not implemented in Phase A.
"""

from __future__ import annotations

from pgvector.sqlalchemy import Vector
from sqlalchemy import Integer, String, bindparam, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.embedding.service import EmbeddingService
from app.db.orm.knowledge import KnowledgeChunkORM
from app.models.knowledge import (
    GLOBAL_KB_TENANT_ID,
    KnowledgeChunk,
    ListedKnowledgeChunk,
    RetrievedChunk,
)
from app.models.knowledge_release import KnowledgeTypedFilter
from app.services.knowledge_store_prefilter import (
    assert_knowledge_chunk_keyword_prefilter_in_sql,
    assert_knowledge_chunk_prefilter_in_sql,
    embedding_release_filter_clause,
    typed_filter_clause,
)


def _merge_hybrid_results(
    vector_hits: list[RetrievedChunk],
    keyword_hits: list[RetrievedChunk],
    top_k: int,
) -> list[RetrievedChunk]:
    """Merge vector and keyword hits by chunk_id, keeping the best score."""
    merged: dict[str, RetrievedChunk] = {}
    for hit in vector_hits:
        merged[hit.chunk_id] = hit
    for hit in keyword_hits:
        existing = merged.get(hit.chunk_id)
        if existing is None:
            merged[hit.chunk_id] = hit
            continue
        merged[hit.chunk_id] = RetrievedChunk(
            chunk_id=existing.chunk_id,
            kb_name=existing.kb_name,
            content=existing.content,
            metadata=existing.metadata,
            score=max(existing.score, hit.score),
            retrieval_method="hybrid",
        )
    return sorted(merged.values(), key=lambda row: row.score, reverse=True)[:top_k]


class KnowledgeStore:
    """Persist knowledge chunks and serve vector / keyword search.

    Chunks are idempotent by *chunk_id* across upsert calls.  Vector search
    uses pgvector cosine distance (``<=>``); keyword search uses PostgreSQL
    full-text search with the ``simple`` configuration.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        embed_service: EmbeddingService,
        *,
        tenant_isolation_strict: bool = False,
    ) -> None:
        self._session_factory = session_factory
        self._embed = embed_service
        self._tenant_isolation_strict = tenant_isolation_strict

    @staticmethod
    def _tenant_filter_clause(
        tenant_id: str | None,
        *,
        tenant_isolation_strict: bool,
    ) -> tuple[str, dict[str, str]]:
        if tenant_id is None:
            return "", {}
        if tenant_isolation_strict:
            clause = (
                " AND (metadata->>'tenant_id' = :tenant_id"
                " OR metadata->>'tenant_id' = :global_tenant_id)"
            )
            return clause, {
                "tenant_id": tenant_id,
                "global_tenant_id": GLOBAL_KB_TENANT_ID,
            }
        clause = " AND (metadata->>'tenant_id' IS NULL OR metadata->>'tenant_id' = :tenant_id)"
        return clause, {"tenant_id": tenant_id}

    @staticmethod
    def _release_filter_clause(release_id: str | None) -> tuple[str, dict[str, str]]:
        if release_id is None:
            return "", {}
        clause = " AND metadata->>'release_id' = :release_id"
        return clause, {"release_id": release_id}

    @classmethod
    def compose_vector_search_sql(
        cls,
        *,
        tenant_id: str | None,
        tenant_isolation_strict: bool,
        release_id: str | None,
        embedding_release_id: str | None,
        typed_filters: tuple[KnowledgeTypedFilter, ...] | list[KnowledgeTypedFilter] = (),
    ) -> str:
        """Return the vector_search SQL body for backend pre-filter proof (#636)."""
        tenant_clause, _ = cls._tenant_filter_clause(
            tenant_id,
            tenant_isolation_strict=tenant_isolation_strict,
        )
        release_clause, _ = cls._release_filter_clause(release_id)
        embedding_clause, _ = embedding_release_filter_clause(embedding_release_id)
        filter_clause, _ = typed_filter_clause(typed_filters)
        return f"""
            SELECT chunk_id, kb_name, content, metadata,
                   1.0 - (embedding <=> :q) AS score
            FROM knowledge_chunk
            WHERE kb_name = :kb_name{tenant_clause}{release_clause}{embedding_clause}{filter_clause}
            ORDER BY embedding <=> :q
            LIMIT :top_k
            """

    @classmethod
    def compose_keyword_search_sql(
        cls,
        *,
        tenant_id: str | None,
        tenant_isolation_strict: bool,
        release_id: str | None,
        embedding_release_id: str | None,
        typed_filters: tuple[KnowledgeTypedFilter, ...] | list[KnowledgeTypedFilter] = (),
    ) -> str:
        """Return the keyword_search SQL body for backend pre-filter proof (#636)."""
        tenant_clause, _ = cls._tenant_filter_clause(
            tenant_id,
            tenant_isolation_strict=tenant_isolation_strict,
        )
        release_clause, _ = cls._release_filter_clause(release_id)
        embedding_clause, _ = embedding_release_filter_clause(embedding_release_id)
        filter_clause, _ = typed_filter_clause(typed_filters)
        return f"""
            SELECT chunk_id, kb_name, content, metadata,
                   GREATEST(
                       ts_rank(to_tsvector('simple', content),
                               plainto_tsquery('simple', :q)),
                       0.5
                   ) AS score
            FROM knowledge_chunk
            WHERE kb_name = :kb_name
              AND to_tsvector('simple', content) @@ plainto_tsquery('simple', :q)
              {tenant_clause}{release_clause}{embedding_clause}{filter_clause}
            ORDER BY ts_rank(to_tsvector('simple', content),
                             plainto_tsquery('simple', :q)) DESC
            LIMIT :top_k
            """

    @property
    def semantic_search_enabled(self) -> bool:
        """Whether callers should prefer pure vector search over hybrid keyword fallback."""
        return self._embed.semantic_search_enabled

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def upsert_chunks(
        self,
        kb_name: str,
        chunks: list[KnowledgeChunk],
        *,
        session: AsyncSession | None = None,
    ) -> None:
        """Insert or update chunks, optionally joining a caller-owned transaction."""
        if not chunks:
            return
        contents: list[str] = []
        for c in chunks:
            if c.kb_name != kb_name:
                raise ValueError(f"chunk {c.chunk_id} kb_name={c.kb_name} != {kb_name}")
            contents.append(c.content)
        vectors = await self._embed.embed_texts(contents)
        if session is not None:
            await self._execute_upserts(session, kb_name, chunks, vectors)
            return
        async with self._session_factory() as owned_session:
            async with owned_session.begin():
                await self._execute_upserts(owned_session, kb_name, chunks, vectors)

    @staticmethod
    async def _execute_upserts(
        session: AsyncSession,
        kb_name: str,
        chunks: list[KnowledgeChunk],
        vectors: list[list[float]],
    ) -> None:
        for chunk, vec in zip(chunks, vectors, strict=True):
            stmt = (
                pg_insert(KnowledgeChunkORM)
                .values(
                    chunk_id=chunk.chunk_id,
                    kb_name=kb_name,
                    content=chunk.content,
                    chunk_metadata=chunk.metadata,
                    embedding=vec,
                )
                .on_conflict_do_update(
                    index_elements=["chunk_id"],
                    set_={
                        "kb_name": kb_name,
                        "content": chunk.content,
                        "metadata": chunk.metadata,
                        "embedding": vec,
                    },
                )
            )
            await session.execute(stmt)

    async def vector_search(
        self,
        kb_name: str,
        query_embedding: list[float],
        top_k: int = 10,
        *,
        tenant_id: str | None = None,
        release_id: str | None = None,
        embedding_release_id: str | None = None,
        typed_filters: tuple[KnowledgeTypedFilter, ...] | list[KnowledgeTypedFilter] = (),
    ) -> list[RetrievedChunk]:
        """Cosine-similarity search across vectors in *kb_name*."""
        tenant_clause, tenant_params = self._tenant_filter_clause(
            tenant_id,
            tenant_isolation_strict=self._tenant_isolation_strict,
        )
        release_clause, release_params = self._release_filter_clause(release_id)
        embedding_clause, embedding_params = embedding_release_filter_clause(embedding_release_id)
        filter_clause, filter_params = typed_filter_clause(typed_filters)
        params: dict[str, object] = {
            "kb_name": kb_name,
            "q": query_embedding,
            "top_k": top_k,
            **tenant_params,
            **release_params,
            **embedding_params,
            **filter_params,
        }
        sql_body = self.compose_vector_search_sql(
            tenant_id=tenant_id,
            tenant_isolation_strict=self._tenant_isolation_strict,
            release_id=release_id,
            embedding_release_id=embedding_release_id,
            typed_filters=typed_filters,
        )
        if release_id is not None or embedding_release_id is not None:
            assert_knowledge_chunk_prefilter_in_sql(sql_body)
        sql = text(sql_body).bindparams(
            bindparam("q", type_=Vector),
            bindparam("kb_name", type_=String),
            bindparam("top_k", type_=Integer),
        )
        async with self._session_factory() as session:
            result = await session.execute(
                sql,
                params,
            )
            return [
                RetrievedChunk(
                    chunk_id=row.chunk_id,
                    kb_name=row.kb_name,
                    content=row.content,
                    metadata=row.metadata or {},
                    score=float(row.score),
                    retrieval_method="vector",
                )
                for row in result.fetchall()
            ]

    async def vector_search_query(
        self,
        kb_name: str,
        query_text: str,
        top_k: int = 10,
        *,
        release_id: str | None = None,
    ) -> list[RetrievedChunk]:
        """Embed *query_text* and run cosine-similarity search (ISSUE-522)."""
        query_vec = await self._embed.embed_query(query_text)
        return await self.vector_search(kb_name, query_vec, top_k=top_k, release_id=release_id)

    async def keyword_search(
        self,
        kb_name: str,
        query_text: str,
        top_k: int = 10,
        *,
        tenant_id: str | None = None,
        release_id: str | None = None,
        embedding_release_id: str | None = None,
        typed_filters: tuple[KnowledgeTypedFilter, ...] | list[KnowledgeTypedFilter] = (),
    ) -> list[RetrievedChunk]:
        """PostgreSQL full-text search across chunks in *kb_name*."""
        tenant_clause, tenant_params = self._tenant_filter_clause(
            tenant_id,
            tenant_isolation_strict=self._tenant_isolation_strict,
        )
        release_clause, release_params = self._release_filter_clause(release_id)
        embedding_clause, embedding_params = embedding_release_filter_clause(embedding_release_id)
        filter_clause, filter_params = typed_filter_clause(typed_filters)
        params: dict[str, object] = {
            "kb_name": kb_name,
            "q": query_text,
            "top_k": top_k,
            **tenant_params,
            **release_params,
            **embedding_params,
            **filter_params,
        }
        sql_body = self.compose_keyword_search_sql(
            tenant_id=tenant_id,
            tenant_isolation_strict=self._tenant_isolation_strict,
            release_id=release_id,
            embedding_release_id=embedding_release_id,
            typed_filters=typed_filters,
        )
        if release_id is not None or embedding_release_id is not None:
            assert_knowledge_chunk_keyword_prefilter_in_sql(sql_body)
        sql = text(sql_body)
        async with self._session_factory() as session:
            result = await session.execute(
                sql,
                params,
            )
            return [
                RetrievedChunk(
                    chunk_id=row.chunk_id,
                    kb_name=row.kb_name,
                    content=row.content,
                    metadata=row.metadata or {},
                    score=float(row.score),
                    retrieval_method="keyword",
                )
                for row in result.fetchall()
            ]

    async def hybrid_search(
        self,
        kb_name: str,
        query_text: str,
        *,
        keyword_query: str | None = None,
        top_k: int = 10,
        tenant_id: str | None = None,
        release_id: str | None = None,
    ) -> list[RetrievedChunk]:
        """Vector search plus keyword fallback, merged by chunk_id."""
        query_vec = await self._embed.embed_query(query_text)
        vector_hits = await self.vector_search(
            kb_name,
            query_vec,
            top_k=top_k,
            tenant_id=tenant_id,
            release_id=release_id,
        )
        keyword_hits = await self.keyword_search(
            kb_name,
            keyword_query if keyword_query is not None else query_text,
            top_k=top_k,
            tenant_id=tenant_id,
            release_id=release_id,
        )
        return _merge_hybrid_results(vector_hits, keyword_hits, top_k)

    async def count_chunks(
        self,
        *,
        kb_name: str | None = None,
        tenant_id: str | None = None,
    ) -> int:
        """Count chunks, optionally scoped to *kb_name* and tenant metadata."""
        tenant_clause, tenant_params = self._tenant_filter_clause(
            tenant_id,
            tenant_isolation_strict=self._tenant_isolation_strict,
        )
        kb_clause = " AND kb_name = :kb_name" if kb_name is not None else ""
        params: dict[str, object] = {**tenant_params}
        if kb_name is not None:
            params["kb_name"] = kb_name
        sql = text(
            f"SELECT COUNT(*) AS cnt FROM knowledge_chunk WHERE 1=1{kb_clause}{tenant_clause}"
        )
        async with self._session_factory() as session:
            result = await session.execute(sql, params)
            row = result.fetchone()
            return int(row.cnt) if row else 0

    async def list_chunks(
        self,
        *,
        kb_name: str | None = None,
        page: int = 1,
        page_size: int = 20,
        tenant_id: str | None = None,
    ) -> list[ListedKnowledgeChunk]:
        """Paginated catalog listing with stable ``kb_name``, ``chunk_id`` ordering."""
        tenant_clause, tenant_params = self._tenant_filter_clause(
            tenant_id,
            tenant_isolation_strict=self._tenant_isolation_strict,
        )
        kb_clause = " AND kb_name = :kb_name" if kb_name is not None else ""
        offset = max(page - 1, 0) * page_size
        params: dict[str, object] = {
            "limit": page_size,
            "offset": offset,
            **tenant_params,
        }
        if kb_name is not None:
            params["kb_name"] = kb_name
        sql = text(
            f"""
            SELECT chunk_id, kb_name, content, metadata, created_at
            FROM knowledge_chunk
            WHERE 1=1{kb_clause}{tenant_clause}
            ORDER BY kb_name ASC, chunk_id ASC
            LIMIT :limit OFFSET :offset
            """
        )
        async with self._session_factory() as session:
            result = await session.execute(sql, params)
            return [
                ListedKnowledgeChunk(
                    chunk_id=row.chunk_id,
                    kb_name=row.kb_name,
                    content=row.content,
                    metadata=row.metadata or {},
                    created_at=row.created_at,
                )
                for row in result.fetchall()
            ]

    async def keyword_search_paginated(
        self,
        query_text: str,
        *,
        kb_name: str | None = None,
        page: int = 1,
        page_size: int = 20,
        tenant_id: str | None = None,
    ) -> tuple[int, list[RetrievedChunk]]:
        """Full-text search with total hit count and stable score ordering."""
        tenant_clause, tenant_params = self._tenant_filter_clause(
            tenant_id,
            tenant_isolation_strict=self._tenant_isolation_strict,
        )
        kb_clause = " AND kb_name = :kb_name" if kb_name is not None else ""
        params: dict[str, object] = {
            "q": query_text,
            **tenant_params,
        }
        if kb_name is not None:
            params["kb_name"] = kb_name
        count_sql = text(
            f"""
            SELECT COUNT(*) AS cnt
            FROM knowledge_chunk
            WHERE to_tsvector('simple', content) @@ plainto_tsquery('simple', :q)
              {kb_clause}{tenant_clause}
            """
        )
        offset = max(page - 1, 0) * page_size
        search_params = {**params, "limit": page_size, "offset": offset}
        search_sql = text(
            f"""
            SELECT chunk_id, kb_name, content, metadata,
                   GREATEST(
                       ts_rank(to_tsvector('simple', content),
                               plainto_tsquery('simple', :q)),
                       0.5
                   ) AS score
            FROM knowledge_chunk
            WHERE to_tsvector('simple', content) @@ plainto_tsquery('simple', :q)
              {kb_clause}{tenant_clause}
            ORDER BY score DESC, kb_name ASC, chunk_id ASC
            LIMIT :limit OFFSET :offset
            """
        )
        async with self._session_factory() as session:
            count_row = (await session.execute(count_sql, params)).fetchone()
            total = int(count_row.cnt) if count_row else 0
            rows = (await session.execute(search_sql, search_params)).fetchall()
            hits = [
                RetrievedChunk(
                    chunk_id=row.chunk_id,
                    kb_name=row.kb_name,
                    content=row.content,
                    metadata=row.metadata or {},
                    score=float(row.score),
                    retrieval_method="keyword",
                )
                for row in rows
            ]
            return total, hits

    async def count(self, kb_name: str) -> int:
        """Return the number of chunks stored in *kb_name*."""
        sql = text("SELECT COUNT(*) AS cnt FROM knowledge_chunk WHERE kb_name = :kb_name")
        async with self._session_factory() as session:
            result = await session.execute(sql, {"kb_name": kb_name})
            row = result.fetchone()
            return int(row.cnt) if row else 0
