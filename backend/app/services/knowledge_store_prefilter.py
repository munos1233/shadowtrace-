"""SQL pre-filter builders and proof helpers for KnowledgeStore (#636)."""

from __future__ import annotations

import re

from app.core.embedding.base import EmbeddingPrefilterError
from app.models.knowledge_release import KnowledgeFilterKind, KnowledgeTypedFilter

_KNOWLEDGE_CHUNK_PREFILTER_FRAGMENT = re.compile(
    r"kb_name\s*=\s*:kb_name[\s\S]*"
    r"(metadata->>'release_id'\s*=\s*:release_id|metadata->>'embedding_release_id'\s*=\s*:embedding_release_id)",
    re.IGNORECASE,
)


def typed_filter_clause(
    filters: tuple[KnowledgeTypedFilter, ...] | list[KnowledgeTypedFilter],
) -> tuple[str, dict[str, str]]:
    """Build metadata predicates for supported typed filters."""
    clauses: list[str] = []
    params: dict[str, str] = {}
    for index, filt in enumerate(filters):
        if filt.kind == KnowledgeFilterKind.SOURCE_ID:
            key = f"source_id_{index}"
            clauses.append(f" AND metadata->>'source_id' = :{key}")
            params[key] = filt.value
        elif filt.kind == KnowledgeFilterKind.CONTENT_TYPE:
            key = f"content_type_{index}"
            clauses.append(f" AND metadata->>'content_type' = :{key}")
            params[key] = filt.value
    return "".join(clauses), params


def embedding_release_filter_clause(embedding_release_id: str | None) -> tuple[str, dict[str, str]]:
    if embedding_release_id is None:
        return "", {}
    clause = " AND metadata->>'embedding_release_id' = :embedding_release_id"
    return clause, {"embedding_release_id": embedding_release_id}


_KNOWLEDGE_CHUNK_KEYWORD_PREFILTER_FRAGMENT = re.compile(
    r"kb_name\s*=\s*:kb_name[\s\S]*"
    r"(metadata->>'release_id'\s*=\s*:release_id|metadata->>'embedding_release_id'\s*=\s*:embedding_release_id)",
    re.IGNORECASE,
)


def build_knowledge_chunk_keyword_sql(
    *,
    include_tenant: bool = True,
    include_release: bool = True,
    include_embedding_release: bool = True,
    include_typed_filters: bool = False,
) -> str:
    """Return the KnowledgeStore keyword_search SQL template for pre-filter proof."""
    tenant_clause = (
        " AND (metadata->>'tenant_id' IS NULL OR metadata->>'tenant_id' = :tenant_id)"
        if include_tenant
        else ""
    )
    release_clause = " AND metadata->>'release_id' = :release_id" if include_release else ""
    embedding_clause = (
        " AND metadata->>'embedding_release_id' = :embedding_release_id"
        if include_embedding_release
        else ""
    )
    typed_clause = " AND metadata->>'source_id' = :source_id_0" if include_typed_filters else ""
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
              {tenant_clause}{release_clause}{embedding_clause}{typed_clause}
            ORDER BY ts_rank(to_tsvector('simple', content),
                             plainto_tsquery('simple', :q)) DESC
            LIMIT :top_k
            """


def assert_knowledge_chunk_keyword_prefilter_in_sql(sql: str) -> None:
    """Backend proof that kb/release scope precedes keyword ranking."""
    if "ts_rank(to_tsvector('simple', content)" not in sql:
        raise EmbeddingPrefilterError(
            message="knowledge_chunk keyword SQL missing ts_rank ordering clause",
            error_code="embedding_prefilter_required",
            details={"sql_excerpt": sql.strip()[:240]},
        )
    order_pos = sql.upper().find("ORDER BY")
    where_pos = sql.upper().find("WHERE")
    if where_pos < 0 or order_pos < where_pos:
        raise EmbeddingPrefilterError(
            message="knowledge_chunk keyword SQL missing WHERE before ORDER BY",
            error_code="embedding_prefilter_required",
            details={"sql_excerpt": sql.strip()[:240]},
        )
    pre_order = sql[:order_pos]
    if not _KNOWLEDGE_CHUNK_KEYWORD_PREFILTER_FRAGMENT.search(pre_order):
        raise EmbeddingPrefilterError(
            message="knowledge_chunk keyword SQL missing mandatory release pre-filter",
            error_code="embedding_prefilter_required",
            details={"sql_excerpt": sql.strip()[:240]},
        )


def build_knowledge_chunk_vector_sql(
    *,
    include_tenant: bool = True,
    include_release: bool = True,
    include_embedding_release: bool = True,
    include_typed_filters: bool = False,
) -> str:
    """Return the KnowledgeStore vector_search SQL template for pre-filter proof."""
    tenant_clause = (
        " AND (metadata->>'tenant_id' IS NULL OR metadata->>'tenant_id' = :tenant_id)"
        if include_tenant
        else ""
    )
    release_clause = " AND metadata->>'release_id' = :release_id" if include_release else ""
    embedding_clause = (
        " AND metadata->>'embedding_release_id' = :embedding_release_id"
        if include_embedding_release
        else ""
    )
    typed_clause = " AND metadata->>'source_id' = :source_id_0" if include_typed_filters else ""
    return f"""
            SELECT chunk_id, kb_name, content, metadata,
                   1.0 - (embedding <=> :q) AS score
            FROM knowledge_chunk
            WHERE kb_name = :kb_name{tenant_clause}{release_clause}{embedding_clause}{typed_clause}
            ORDER BY embedding <=> :q
            LIMIT :top_k
            """


def assert_knowledge_chunk_prefilter_in_sql(sql: str) -> None:
    """Backend proof that kb/release scope precedes vector ordering."""
    if "ORDER BY embedding <=>" not in sql:
        raise EmbeddingPrefilterError(
            message="knowledge_chunk SQL missing vector ordering clause",
            error_code="embedding_prefilter_required",
            details={"sql_excerpt": sql.strip()[:240]},
        )
    order_pos = sql.upper().find("ORDER BY")
    where_pos = sql.upper().find("WHERE")
    if where_pos < 0 or order_pos < where_pos:
        raise EmbeddingPrefilterError(
            message="knowledge_chunk SQL missing WHERE before ORDER BY",
            error_code="embedding_prefilter_required",
            details={"sql_excerpt": sql.strip()[:240]},
        )
    pre_order = sql[:order_pos]
    if not _KNOWLEDGE_CHUNK_PREFILTER_FRAGMENT.search(pre_order):
        raise EmbeddingPrefilterError(
            message="knowledge_chunk SQL missing mandatory release pre-filter",
            error_code="embedding_prefilter_required",
            details={"sql_excerpt": sql.strip()[:240]},
        )


__all__ = [
    "assert_knowledge_chunk_keyword_prefilter_in_sql",
    "assert_knowledge_chunk_prefilter_in_sql",
    "build_knowledge_chunk_keyword_sql",
    "build_knowledge_chunk_vector_sql",
    "embedding_release_filter_clause",
    "typed_filter_clause",
]
