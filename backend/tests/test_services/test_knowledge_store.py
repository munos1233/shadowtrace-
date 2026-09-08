"""Tests for KnowledgeStore: upsert, vector search, keyword search, isolation (ISSUE-041)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.models.knowledge import KnowledgeChunk
from app.services.knowledge_store import KnowledgeStore
from tests.helpers.knowledge_isolation import TEST_OWNED_CHUNK_DELETE

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def _run_migrations() -> None:
    """Alembic env.py reads get_settings().database_url — sync test URL first."""
    os.environ["DATABASE_URL"] = DATABASE_URL
    from app.core.config import get_settings

    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def migrated() -> None:
    _run_migrations()


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
    """Remove this module's prefixed rows before each test."""
    async with session_factory() as session:
        await session.execute(TEST_OWNED_CHUNK_DELETE)
        await session.commit()


@pytest.fixture
def kb_tenant() -> str:
    return f"tenant-ks-{uuid4().hex[:8]}"


@pytest_asyncio.fixture
def embed_service() -> EmbeddingService:
    return EmbeddingService(Settings(embedding_mode="mock", embedding_max_batch_size=128))


@pytest_asyncio.fixture
def store(
    session_factory: async_sessionmaker[AsyncSession],
    embed_service: EmbeddingService,
) -> KnowledgeStore:
    return KnowledgeStore(session_factory, embed_service, tenant_isolation_strict=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chunk(
    chunk_id: str, kb_name: str, content: str, *, tenant_id: str, **meta: object
) -> KnowledgeChunk:
    metadata = dict(meta)
    metadata["tenant_id"] = tenant_id
    return KnowledgeChunk(chunk_id=chunk_id, kb_name=kb_name, content=content, metadata=metadata)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUpsertChunks:
    @pytest.mark.asyncio
    async def test_inserts_new_chunks(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        chunks = [
            _chunk("chk-00000001", "attack_kb", "Spear phishing campaign", tenant_id=kb_tenant),
            _chunk(
                "chk-00000002",
                "attack_kb",
                "Ransomware deployment via CVE-2024",
                tenant_id=kb_tenant,
            ),
            _chunk(
                "chk-00000003", "attack_kb", "Credential dumping with Mimikatz", tenant_id=kb_tenant
            ),
        ]
        await store.upsert_chunks("attack_kb", chunks)
        assert await store.count("attack_kb", tenant_id=kb_tenant) == 3

    @pytest.mark.asyncio
    async def test_upsert_is_idempotent(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        c1 = _chunk("chk-0000000a", "playbook_kb", "Initial content", tenant_id=kb_tenant)
        await store.upsert_chunks("playbook_kb", [c1])
        assert await store.count("playbook_kb", tenant_id=kb_tenant) == 1

        c2 = _chunk(
            "chk-0000000a", "playbook_kb", "Updated content", tenant_id=kb_tenant, version=2
        )
        await store.upsert_chunks("playbook_kb", [c2])
        assert await store.count("playbook_kb", tenant_id=kb_tenant) == 1
        results = await store.keyword_search("playbook_kb", "Updated", top_k=1, tenant_id=kb_tenant)
        assert results and results[0].content == "Updated content"
        assert results[0].metadata.get("version") == 2

    @pytest.mark.asyncio
    async def test_kb_name_mismatch_raises(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        c = _chunk("chk-0000000b", "attack_kb", "content", tenant_id=kb_tenant)
        with pytest.raises(ValueError, match="kb_name"):
            await store.upsert_chunks("history_case_kb", [c])

    @pytest.mark.asyncio
    async def test_empty_chunks_noop(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        await store.upsert_chunks("attack_kb", [])
        assert await store.count("attack_kb", tenant_id=kb_tenant) == 0

    @pytest.mark.asyncio
    async def test_upsert_chunks_batches_above_embed_limit(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        clean_knowledge: None,
        kb_tenant: str,
    ) -> None:
        embed = EmbeddingService(Settings(embedding_mode="mock", embedding_max_batch_size=2))
        store = KnowledgeStore(session_factory, embed, tenant_isolation_strict=True)
        batches: list[int] = []
        original = embed.embed_texts

        async def _spy(texts: list[str]) -> list[list[float]]:
            batches.append(len(texts))
            return await original(texts)

        embed.embed_texts = _spy  # type: ignore[method-assign]
        chunks = [
            _chunk("chk-000000a1", "attack_kb", "batch chunk one", tenant_id=kb_tenant),
            _chunk("chk-000000a2", "attack_kb", "batch chunk two", tenant_id=kb_tenant),
            _chunk("chk-000000a3", "attack_kb", "batch chunk three", tenant_id=kb_tenant),
        ]
        await store.upsert_chunks("attack_kb", chunks)
        assert await store.count("attack_kb", tenant_id=kb_tenant) == 3
        assert batches == [2, 1]


class TestVectorSearch:
    @pytest.mark.asyncio
    async def test_same_text_ranks_highest(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        chunks = [
            _chunk(
                "chk-00000010",
                "attack_kb",
                "Distributed denial of service attack",
                tenant_id=kb_tenant,
            ),
            _chunk(
                "chk-00000011",
                "attack_kb",
                "SQL injection via query parameter",
                tenant_id=kb_tenant,
            ),
            _chunk(
                "chk-00000012",
                "attack_kb",
                "Cross-site scripting in form field",
                tenant_id=kb_tenant,
            ),
            _chunk(
                "chk-00000013",
                "attack_kb",
                "Phishing email with malicious attachment",
                tenant_id=kb_tenant,
            ),
            _chunk(
                "chk-00000014", "attack_kb", "Brute force login attempt on SSH", tenant_id=kb_tenant
            ),
        ]
        await store.upsert_chunks("attack_kb", chunks)

        query_vec = await store._embed.embed_query("SQL injection via query parameter")
        results = await store.vector_search("attack_kb", query_vec, top_k=3, tenant_id=kb_tenant)
        assert len(results) == 3
        assert results[0].chunk_id == "chk-00000011"
        assert results[0].retrieval_method == "vector"
        assert results[0].score > 0.9  # same text → near-identical mock vector

    @pytest.mark.asyncio
    async def test_respects_top_k(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        chunks = [
            _chunk(
                f"chk-{i:08x}",
                "fp_case_kb",
                f"False positive case number {i}",
                tenant_id=kb_tenant,
            )
            for i in range(10)
        ]
        await store.upsert_chunks("fp_case_kb", chunks)

        query_vec = await store._embed.embed_query("false positive case number 5")
        results = await store.vector_search("fp_case_kb", query_vec, top_k=3, tenant_id=kb_tenant)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_empty_kb_returns_empty(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        query_vec = await store._embed.embed_query("anything")
        results = await store.vector_search("attack_kb", query_vec, top_k=10, tenant_id=kb_tenant)
        assert results == []


class TestKeywordSearch:
    @pytest.mark.asyncio
    async def test_finds_matching_content(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        chunks = [
            _chunk(
                "chk-00000020",
                "playbook_kb",
                "Isolate compromised host from network",
                tenant_id=kb_tenant,
            ),
            _chunk(
                "chk-00000021",
                "playbook_kb",
                "Reset all domain admin passwords",
                tenant_id=kb_tenant,
            ),
            _chunk(
                "chk-00000022",
                "playbook_kb",
                "Collect memory dump from affected endpoint",
                tenant_id=kb_tenant,
            ),
        ]
        await store.upsert_chunks("playbook_kb", chunks)

        results = await store.keyword_search(
            "playbook_kb", "isolate host", top_k=10, tenant_id=kb_tenant
        )
        assert len(results) >= 1
        assert results[0].chunk_id == "chk-00000020"
        assert results[0].retrieval_method == "keyword"

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        chunks = [
            _chunk(
                "chk-00000030",
                "playbook_kb",
                "Standard incident response playbook",
                tenant_id=kb_tenant,
            ),
        ]
        await store.upsert_chunks("playbook_kb", chunks)

        results = await store.keyword_search(
            "playbook_kb", "zzzxnonexistentzzz", top_k=10, tenant_id=kb_tenant
        )
        assert results == []


class TestKbNameIsolation:
    @pytest.mark.asyncio
    async def test_cross_kb_data_not_visible(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        await store.upsert_chunks(
            "attack_kb",
            [_chunk("chk-00000040", "attack_kb", "APT lateral movement", tenant_id=kb_tenant)],
        )
        await store.upsert_chunks(
            "fp_case_kb",
            [_chunk("chk-00000041", "fp_case_kb", "Benign admin tool usage", tenant_id=kb_tenant)],
        )

        assert await store.count("attack_kb", tenant_id=kb_tenant) == 1
        assert await store.count("fp_case_kb", tenant_id=kb_tenant) == 1
        assert await store.count("history_case_kb", tenant_id=kb_tenant) == 0

        query_vec = await store._embed.embed_query("APT lateral movement")
        results = await store.vector_search("fp_case_kb", query_vec, top_k=10, tenant_id=kb_tenant)
        for r in results:
            assert r.kb_name == "fp_case_kb"
            assert r.chunk_id != "chk-00000040"

    @pytest.mark.asyncio
    async def test_tenant_scope_hides_other_tenants(
        self, store: KnowledgeStore, clean_knowledge: None
    ) -> None:
        tenant_a = f"tenant-a-{uuid4().hex[:8]}"
        tenant_b = f"tenant-b-{uuid4().hex[:8]}"
        await store.upsert_chunks(
            "attack_kb",
            [_chunk("chk-00000050", "attack_kb", "tenant A spear phish", tenant_id=tenant_a)],
        )
        await store.upsert_chunks(
            "attack_kb",
            [_chunk("chk-00000051", "attack_kb", "tenant B ransomware", tenant_id=tenant_b)],
        )
        assert await store.count("attack_kb", tenant_id=tenant_a) == 1
        query_vec = await store._embed.embed_query("tenant B ransomware")
        results = await store.vector_search("attack_kb", query_vec, top_k=10, tenant_id=tenant_a)
        assert all(hit.chunk_id != "chk-00000051" for hit in results)


class TestBulkOperations:
    @pytest.mark.asyncio
    async def test_upsert_100_chunks_and_vector_search(
        self, store: KnowledgeStore, clean_knowledge: None, kb_tenant: str
    ) -> None:
        chunks = [
            _chunk(
                f"chk-{i:08x}",
                "history_case_kb",
                f"Historical incident report number {i}: security breach investigation",
                tenant_id=kb_tenant,
            )
            for i in range(100)
        ]
        await store.upsert_chunks("history_case_kb", chunks)
        assert await store.count("history_case_kb", tenant_id=kb_tenant) == 100

        query_vec = await store._embed.embed_query("incident report number 42")
        results = await store.vector_search(
            "history_case_kb", query_vec, top_k=5, tenant_id=kb_tenant
        )
        assert len(results) == 5
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)
