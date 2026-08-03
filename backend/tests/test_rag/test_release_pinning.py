"""Retrieval release pinning tests (ISSUE-128 / #634)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.db import models as orm
from app.models.knowledge import KnowledgeChunk
from app.rag.context import RetrievalContext
from app.services.knowledge_query_plan_service import resolve_knowledge_query_plan
from app.services.knowledge_release_resolver import default_attack_provenance
from app.services.knowledge_release_service import KnowledgeReleaseService
from app.services.knowledge_store import KnowledgeStore
from app.services.stix_bundle_builder import build_bundle_from_techniques_json

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
DATA_FILE = REPO_ROOT / "data" / "knowledge" / "attack_techniques.json"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated_database() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_tables(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.KnowledgeStixObjectORM))
            await session.execute(delete(orm.KnowledgeReleaseORM))
    yield


@pytest.mark.asyncio
async def test_release_filter_prevents_cross_release_reads(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    settings = Settings(EMBEDDING_MODE="mock", EMBEDDING_MAX_BATCH_SIZE=128)
    embed = EmbeddingService(settings)
    store = KnowledgeStore(session_factory, embed)
    service = KnowledgeReleaseService(session_factory, store=store, settings=settings)

    bundle = build_bundle_from_techniques_json(DATA_FILE)
    version = str(bundle["x_shadowtrace_attack_version"])
    staged = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=default_attack_provenance("fixture://attack"),
    )
    activated = await service.activate_release(staged.release_id)

    await store.upsert_chunks(
        "attack_kb",
        [
            KnowledgeChunk(
                chunk_id="atk-legacy-no-release",
                kb_name="attack_kb",
                content="Technique: Legacy\nID: T9999",
                metadata={"technique_id": "T9999", "technique_name": "Legacy"},
            )
        ],
    )

    plan = resolve_knowledge_query_plan(
        corpus_id="attack_enterprise",
        active_release_id=activated.release_id,
        embedding_release_id=settings.embedding_release_id,
        trace_id="trace-pinning-test",
    )
    context = RetrievalContext(
        tenant_id="tenant-a",
        principal="test",
        event_id="evt-pinning",
        trace_id="trace-pinning-test",
        query_plan=plan,
    )
    hits = await store.keyword_search(
        "attack_kb",
        "Valid Accounts",
        top_k=5,
        release_id=context.release_id_for_kb("attack_kb"),
    )
    assert hits
    assert all(row.metadata.get("release_id") == activated.release_id for row in hits)
    assert all(row.chunk_id != "atk-legacy-no-release" for row in hits)

    legacy_hits = await store.keyword_search("attack_kb", "Legacy", top_k=5)
    assert any(row.chunk_id == "atk-legacy-no-release" for row in legacy_hits)

    await embed.close()


@pytest.mark.asyncio
async def test_citations_carry_pinned_release_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from app.core.llm.base import InMemoryLLMCallAuditRecorder
    from app.core.llm.mock_client import MockLLMClient
    from app.rag.hybrid_retriever import HybridRetriever
    from app.rag.pipeline import RetrievalPipeline
    from app.rag.query_rewriter import QueryRewriter
    from app.rag.reranker import MockReranker

    settings = Settings(EMBEDDING_MODE="mock", EMBEDDING_MAX_BATCH_SIZE=128)
    embed = EmbeddingService(settings)
    store = KnowledgeStore(session_factory, embed)
    service = KnowledgeReleaseService(session_factory, store=store, settings=settings)

    bundle = build_bundle_from_techniques_json(DATA_FILE)
    version = str(bundle["x_shadowtrace_attack_version"])
    staged = await service.stage_stix_bundle(
        bundle,
        release_version=version,
        provenance=default_attack_provenance("fixture://attack-citation"),
    )
    activated = await service.activate_release(staged.release_id)

    plan = resolve_knowledge_query_plan(
        corpus_id="attack_enterprise",
        active_release_id=activated.release_id,
        embedding_release_id=settings.embedding_release_id,
        trace_id="trace-citation-test",
    )
    context = RetrievalContext(
        tenant_id="tenant-a",
        principal="test",
        event_id="evt-citation",
        trace_id="trace-citation-test",
        query_plan=plan,
    )
    pipeline = RetrievalPipeline(
        rewriter=QueryRewriter(
            MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
            agent_name="test",
        ),
        retriever=HybridRetriever(store, embed),
        reranker=MockReranker(),
        settings=settings,
    )
    result = await pipeline.retrieve(
        "Valid Accounts credential access",
        ["attack_kb"],
        top_k=3,
        context=context,
    )
    assert result.citations
    assert all(cit.release_id == activated.release_id for cit in result.citations)
    assert all(cit.corpus_id == "attack_enterprise" for cit in result.citations)
    assert all(cit.object_id for cit in result.citations)

    await embed.close()
