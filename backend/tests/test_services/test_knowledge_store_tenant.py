"""KnowledgeStore tenant isolation tests (ISSUE-138)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.models.knowledge import GLOBAL_KB_TENANT_ID, KnowledgeChunk
from app.services.knowledge_store import KnowledgeStore

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _postgres_reachable() -> bool:
    import asyncio

    from app.db.session_provider import SessionProvider

    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    try:
        return asyncio.run(provider.ping_postgres())
    except Exception:
        return False
    finally:
        asyncio.run(provider.dispose())


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


@pytest.fixture(scope="module")
def migrated() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_knowledge(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await session.execute(text("DELETE FROM knowledge_chunk"))
        await session.commit()


@pytest_asyncio.fixture
def embed_service() -> EmbeddingService:
    return EmbeddingService(Settings(embedding_mode="mock"))


def _chunk(chunk_id: str, kb_name: str, content: str, **meta: object) -> KnowledgeChunk:
    return KnowledgeChunk(chunk_id=chunk_id, kb_name=kb_name, content=content, metadata=dict(meta))


def test_tenant_filter_permissive_includes_null_metadata() -> None:
    clause, params = KnowledgeStore._tenant_filter_clause(
        "tenant-a",
        tenant_isolation_strict=False,
    )
    assert "IS NULL" in clause
    assert params == {"tenant_id": "tenant-a"}


def test_tenant_filter_strict_requires_metadata_match() -> None:
    clause, params = KnowledgeStore._tenant_filter_clause(
        "tenant-a",
        tenant_isolation_strict=True,
    )
    assert "IS NULL" not in clause
    assert "global_tenant_id" in clause
    assert params == {"tenant_id": "tenant-a", "global_tenant_id": GLOBAL_KB_TENANT_ID}


def test_tenant_filter_absent_when_tenant_id_none() -> None:
    clause, params = KnowledgeStore._tenant_filter_clause(
        None,
        tenant_isolation_strict=True,
    )
    assert clause == ""
    assert params == {}


@pytest.mark.skipif(not _postgres_reachable(), reason="PostgreSQL not reachable")
class TestKnowledgeStoreTenantIsolation:
    @pytest.mark.asyncio
    async def test_vector_search_strict_isolation(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        embed_service: EmbeddingService,
        clean_knowledge: None,
    ) -> None:
        store = KnowledgeStore(
            session_factory,
            embed_service,
            tenant_isolation_strict=True,
        )
        await store.upsert_chunks(
            "attack_kb",
            [
                _chunk(
                    "chk-tenant-a",
                    "attack_kb",
                    "alpha tenant secret document",
                    tenant_id="tenant-a",
                ),
                _chunk(
                    "chk-tenant-b", "attack_kb", "beta tenant secret document", tenant_id="tenant-b"
                ),
            ],
        )

        query_vec = await embed_service.embed_query("alpha tenant secret document")
        hits_a = await store.vector_search(
            "attack_kb",
            query_vec,
            top_k=5,
            tenant_id="tenant-a",
        )
        assert {hit.chunk_id for hit in hits_a} == {"chk-tenant-a"}

        hits_b = await store.vector_search(
            "attack_kb",
            query_vec,
            top_k=5,
            tenant_id="tenant-b",
        )
        assert hits_b == [] or hits_b[0].chunk_id == "chk-tenant-b"

    @pytest.mark.asyncio
    async def test_vector_search_strict_includes_global_corpus_chunks(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        embed_service: EmbeddingService,
        clean_knowledge: None,
    ) -> None:
        store = KnowledgeStore(
            session_factory,
            embed_service,
            tenant_isolation_strict=True,
        )
        await store.upsert_chunks(
            "playbook_kb",
            [
                _chunk(
                    "chk-playbook-global",
                    "playbook_kb",
                    "shared playbook guidance",
                    tenant_id=GLOBAL_KB_TENANT_ID,
                    release_id="krel-global00001",
                ),
                _chunk(
                    "chk-tenant-private",
                    "playbook_kb",
                    "tenant private playbook",
                    tenant_id="tenant-a",
                    release_id="krel-tenant00001",
                ),
            ],
        )

        query_vec = await embed_service.embed_query("shared playbook guidance")
        hits_a = await store.vector_search(
            "playbook_kb",
            query_vec,
            top_k=5,
            tenant_id="tenant-a",
        )
        chunk_ids = {hit.chunk_id for hit in hits_a}
        assert "chk-playbook-global" in chunk_ids
        assert "chk-tenant-private" in chunk_ids

        hits_b = await store.vector_search(
            "playbook_kb",
            query_vec,
            top_k=5,
            tenant_id="tenant-b",
        )
        chunk_ids_b = {hit.chunk_id for hit in hits_b}
        assert "chk-playbook-global" in chunk_ids_b
        assert "chk-tenant-private" not in chunk_ids_b

    @pytest.mark.asyncio
    async def test_vector_search_permissive_includes_global_chunks(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        embed_service: EmbeddingService,
        clean_knowledge: None,
    ) -> None:
        store = KnowledgeStore(
            session_factory,
            embed_service,
            tenant_isolation_strict=False,
        )
        await store.upsert_chunks(
            "attack_kb",
            [
                _chunk("chk-global", "attack_kb", "shared global playbook guidance"),
                _chunk(
                    "chk-tenant-a",
                    "attack_kb",
                    "tenant scoped alpha guidance",
                    tenant_id="tenant-a",
                ),
                _chunk(
                    "chk-tenant-b", "attack_kb", "tenant scoped beta guidance", tenant_id="tenant-b"
                ),
            ],
        )

        query_vec = await embed_service.embed_query("shared global playbook guidance")
        hits = await store.vector_search(
            "attack_kb",
            query_vec,
            top_k=10,
            tenant_id="tenant-a",
        )
        chunk_ids = {hit.chunk_id for hit in hits}
        assert "chk-global" in chunk_ids
        assert "chk-tenant-a" in chunk_ids
        assert "chk-tenant-b" not in chunk_ids
