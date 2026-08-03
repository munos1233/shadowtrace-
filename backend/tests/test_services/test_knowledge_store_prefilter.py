"""KnowledgeStore pre-filter SQL proof tests (ISSUE-130 / #636 Phase A)."""

from __future__ import annotations

import pytest

from app.core.embedding.base import EmbeddingPrefilterError
from app.models.knowledge_release import KnowledgeFilterKind, KnowledgeTypedFilter
from app.services.knowledge_store_prefilter import (
    assert_knowledge_chunk_prefilter_in_sql,
    build_knowledge_chunk_vector_sql,
    typed_filter_clause,
)


def test_build_knowledge_chunk_vector_sql_has_prefilter_before_order() -> None:
    sql = build_knowledge_chunk_vector_sql(
        include_tenant=True,
        include_release=True,
        include_embedding_release=True,
        include_typed_filters=True,
    )
    assert_knowledge_chunk_prefilter_in_sql(sql)
    order_pos = sql.upper().index("ORDER BY")
    release_pos = sql.index("metadata->>'release_id'")
    assert release_pos < order_pos


def test_assert_knowledge_chunk_prefilter_rejects_unscoped_sql() -> None:
    sql = """
        SELECT chunk_id FROM knowledge_chunk
        WHERE kb_name = :kb_name
        ORDER BY embedding <=> :q
        LIMIT :top_k
    """
    with pytest.raises(EmbeddingPrefilterError, match="missing mandatory release"):
        assert_knowledge_chunk_prefilter_in_sql(sql)


def test_typed_filter_clause_builds_metadata_predicates() -> None:
    clause, params = typed_filter_clause(
        [
            KnowledgeTypedFilter(kind=KnowledgeFilterKind.SOURCE_ID, value="mitre_attack_stix"),
            KnowledgeTypedFilter(kind=KnowledgeFilterKind.CONTENT_TYPE, value="technique"),
        ]
    )
    assert "metadata->>'source_id'" in clause
    assert "metadata->>'content_type'" in clause
    assert params["source_id_0"] == "mitre_attack_stix"
    assert params["content_type_1"] == "technique"


def test_knowledge_store_compose_vector_search_sql_passes_prefilter_proof() -> None:
    from app.services.knowledge_store import KnowledgeStore

    sql = KnowledgeStore.compose_vector_search_sql(
        tenant_id="tenant-a",
        tenant_isolation_strict=True,
        release_id="krel-test",
        embedding_release_id="emb-v1",
        typed_filters=[
            KnowledgeTypedFilter(kind=KnowledgeFilterKind.SOURCE_ID, value="mitre_attack_stix"),
        ],
    )
    assert_knowledge_chunk_prefilter_in_sql(sql)
    order_pos = sql.upper().index("ORDER BY")
    tenant_pos = sql.index("metadata->>'tenant_id'")
    assert tenant_pos < order_pos


def test_knowledge_store_compose_keyword_search_sql_passes_prefilter_proof() -> None:
    from app.services.knowledge_store import KnowledgeStore
    from app.services.knowledge_store_prefilter import (
        assert_knowledge_chunk_keyword_prefilter_in_sql,
    )

    sql = KnowledgeStore.compose_keyword_search_sql(
        tenant_id="tenant-a",
        tenant_isolation_strict=True,
        release_id="krel-test",
        embedding_release_id="emb-v1",
        typed_filters=[
            KnowledgeTypedFilter(kind=KnowledgeFilterKind.SOURCE_ID, value="mitre_attack_stix"),
        ],
    )
    assert_knowledge_chunk_keyword_prefilter_in_sql(sql)
    order_pos = sql.upper().index("ORDER BY")
    release_pos = sql.index("metadata->>'release_id'")
    assert release_pos < order_pos


def test_build_knowledge_chunk_keyword_sql_has_prefilter_before_order() -> None:
    from app.services.knowledge_store_prefilter import (
        assert_knowledge_chunk_keyword_prefilter_in_sql,
        build_knowledge_chunk_keyword_sql,
    )

    sql = build_knowledge_chunk_keyword_sql(
        include_tenant=True,
        include_release=True,
        include_embedding_release=True,
        include_typed_filters=True,
    )
    assert_knowledge_chunk_keyword_prefilter_in_sql(sql)
