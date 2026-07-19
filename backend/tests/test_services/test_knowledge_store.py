"""Tests for KnowledgeStore: upsert, vector search, keyword search, isolation (ISSUE-041)."""

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
from app.models.knowledge import KnowledgeChunk
from app.services.knowledge_store import KnowledgeStore

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------


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
    """Truncate knowledge_chunk before each test for isolation."""
    async with session_factory() as session:
        await session.execute(text("DELETE FROM knowledge_chunk"))
        await session.commit()


@pytest_asyncio.fixture
def embed_service() -> EmbeddingService:
    return EmbeddingService(Settings(embedding_mode="mock"))


@pytest_asyncio.fixture
def store(
    session_factory: async_sessionmaker[AsyncSession],
    embed_service: EmbeddingService,
) -> KnowledgeStore:
    return KnowledgeStore(session_factory, embed_service)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chunk(chunk_id: str, kb_name: str, content: str, **meta: object) -> KnowledgeChunk:
    return KnowledgeChunk(chunk_id=chunk_id, kb_name=kb_name, content=content, metadata=dict(meta))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUpsertChunks:
    @pytest.mark.asyncio
    async def test_inserts_new_chunks(self, store: KnowledgeStore, clean_knowledge: None) -> None:
        chunks = [
            _chunk("chk-00000001", "attack_kb", "Spear phishing campaign"),
            _chunk("chk-00000002", "attack_kb", "Ransomware deployment via CVE-2024"),
            _chunk("chk-00000003", "attack_kb", "Credential dumping with Mimikatz"),
        ]
        await store.upsert_chunks("attack_kb", chunks)
        assert await store.count("attack_kb") == 3

    @pytest.mark.asyncio
    async def test_upsert_is_idempotent(self, store: KnowledgeStore, clean_knowledge: None) -> None:
        c1 = _chunk("chk-0000000a", "playbook_kb", "Initial content")
        await store.upsert_chunks("playbook_kb", [c1])
        assert await store.count("playbook_kb") == 1

        c2 = _chunk("chk-0000000a", "playbook_kb", "Updated content", version=2)
        await store.upsert_chunks("playbook_kb", [c2])
        assert await store.count("playbook_kb") == 1
        results = await store.keyword_search("playbook_kb", "Updated", top_k=1)
        assert results and results[0].content == "Updated content"
        assert results[0].metadata.get("version") == 2

    @pytest.mark.asyncio
    async def test_kb_name_mismatch_raises(
        self, store: KnowledgeStore, clean_knowledge: None
    ) -> None:
        c = _chunk("chk-0000000b", "attack_kb", "content")
        with pytest.raises(ValueError, match="kb_name"):
            await store.upsert_chunks("history_case_kb", [c])

    @pytest.mark.asyncio
    async def test_empty_chunks_noop(self, store: KnowledgeStore, clean_knowledge: None) -> None:
        await store.upsert_chunks("attack_kb", [])
        assert await store.count("attack_kb") == 0


class TestVectorSearch:
    @pytest.mark.asyncio
    async def test_same_text_ranks_highest(
        self, store: KnowledgeStore, clean_knowledge: None
    ) -> None:
        chunks = [
            _chunk("chk-00000010", "attack_kb", "Distributed denial of service attack"),
            _chunk("chk-00000011", "attack_kb", "SQL injection via query parameter"),
            _chunk("chk-00000012", "attack_kb", "Cross-site scripting in form field"),
            _chunk("chk-00000013", "attack_kb", "Phishing email with malicious attachment"),
            _chunk("chk-00000014", "attack_kb", "Brute force login attempt on SSH"),
        ]
        await store.upsert_chunks("attack_kb", chunks)

        query_vec = await store._embed.embed_query("SQL injection via query parameter")
        results = await store.vector_search("attack_kb", query_vec, top_k=3)
        assert len(results) == 3
        assert results[0].chunk_id == "chk-00000011"
        assert results[0].retrieval_method == "vector"
        assert results[0].score > 0.9  # same text → near-identical mock vector

    @pytest.mark.asyncio
    async def test_respects_top_k(self, store: KnowledgeStore, clean_knowledge: None) -> None:
        chunks = [
            _chunk(f"chk-{i:08x}", "fp_case_kb", f"False positive case number {i}")
            for i in range(10)
        ]
        await store.upsert_chunks("fp_case_kb", chunks)

        query_vec = await store._embed.embed_query("false positive case number 5")
        results = await store.vector_search("fp_case_kb", query_vec, top_k=3)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_empty_kb_returns_empty(
        self, store: KnowledgeStore, clean_knowledge: None
    ) -> None:
        query_vec = await store._embed.embed_query("anything")
        results = await store.vector_search("attack_kb", query_vec, top_k=10)
        assert results == []


class TestKeywordSearch:
    @pytest.mark.asyncio
    async def test_finds_matching_content(
        self, store: KnowledgeStore, clean_knowledge: None
    ) -> None:
        chunks = [
            _chunk("chk-00000020", "playbook_kb", "Isolate compromised host from network"),
            _chunk("chk-00000021", "playbook_kb", "Reset all domain admin passwords"),
            _chunk("chk-00000022", "playbook_kb", "Collect memory dump from affected endpoint"),
        ]
        await store.upsert_chunks("playbook_kb", chunks)

        results = await store.keyword_search("playbook_kb", "isolate host", top_k=10)
        assert len(results) >= 1
        assert results[0].chunk_id == "chk-00000020"
        assert results[0].retrieval_method == "keyword"

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(
        self, store: KnowledgeStore, clean_knowledge: None
    ) -> None:
        chunks = [
            _chunk("chk-00000030", "playbook_kb", "Standard incident response playbook"),
        ]
        await store.upsert_chunks("playbook_kb", chunks)

        results = await store.keyword_search("playbook_kb", "zzzxnonexistentzzz", top_k=10)
        assert results == []


class TestKbNameIsolation:
    @pytest.mark.asyncio
    async def test_cross_kb_data_not_visible(
        self, store: KnowledgeStore, clean_knowledge: None
    ) -> None:
        await store.upsert_chunks(
            "attack_kb", [_chunk("chk-00000040", "attack_kb", "APT lateral movement")]
        )
        await store.upsert_chunks(
            "fp_case_kb", [_chunk("chk-00000041", "fp_case_kb", "Benign admin tool usage")]
        )

        assert await store.count("attack_kb") == 1
        assert await store.count("fp_case_kb") == 1
        assert await store.count("history_case_kb") == 0

        query_vec = await store._embed.embed_query("APT lateral movement")
        results = await store.vector_search("fp_case_kb", query_vec, top_k=10)
        # attack_kb chunk should never appear in fp_case_kb results
        for r in results:
            assert r.kb_name == "fp_case_kb"
            assert r.chunk_id != "chk-00000040"


class TestBulkOperations:
    @pytest.mark.asyncio
    async def test_upsert_100_chunks_and_vector_search(
        self, store: KnowledgeStore, clean_knowledge: None
    ) -> None:
        chunks = [
            _chunk(
                f"chk-{i:08x}",
                "history_case_kb",
                f"Historical incident report number {i}: security breach investigation",
            )
            for i in range(100)
        ]
        await store.upsert_chunks("history_case_kb", chunks)
        assert await store.count("history_case_kb") == 100

        query_vec = await store._embed.embed_query("incident report number 42")
        results = await store.vector_search("history_case_kb", query_vec, top_k=5)
        assert len(results) == 5
        # results must be ordered by score descending
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)
