"""Tests for AttackKBService: load, get_technique, search, idempotency (ISSUE-042)."""

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
from app.core.embedding.mock_embedder import MockEmbedder
from app.core.embedding.service import EmbeddingService
from app.services.attack_kb_service import (
    CHINESE_SOC_QUERY_BENCHMARKS,
    KB_NAME,
    AttackKBService,
    _format_content,
)
from app.services.knowledge_store import KnowledgeStore

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
def embed_service() -> EmbeddingService:
    return EmbeddingService(Settings(embedding_mode="mock"))


@pytest_asyncio.fixture
def store(
    session_factory: async_sessionmaker[AsyncSession],
    embed_service: EmbeddingService,
) -> KnowledgeStore:
    return KnowledgeStore(session_factory, embed_service)


@pytest_asyncio.fixture
def service(
    store: KnowledgeStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> AttackKBService:
    return AttackKBService(store, session_factory)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _clean(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await session.execute(text("DELETE FROM knowledge_chunk"))
        await session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLoadFromFile:
    @pytest.mark.asyncio
    async def test_loads_at_least_60_techniques(
        self,
        service: AttackKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        count = await service.load_from_file(DATA_FILE)
        assert count >= 60

    @pytest.mark.asyncio
    async def test_upsert_is_idempotent(
        self,
        service: AttackKBService,
        store: KnowledgeStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        first = await service.load_from_file(DATA_FILE)
        second = await service.load_from_file(DATA_FILE)
        assert first == second
        assert await store.count(KB_NAME) == first

    @pytest.mark.asyncio
    async def test_missing_file_raises(
        self,
        service: AttackKBService,
    ) -> None:
        with pytest.raises(FileNotFoundError):
            await service.load_from_file("/nonexistent/path.json")


class TestGetTechnique:
    @pytest.mark.asyncio
    async def test_t1078_returns_full_entry(
        self,
        service: AttackKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)

        result = await service.get_technique("T1078")
        assert result is not None
        assert result["technique_id"] == "T1078"
        assert result["technique_name"] == "Valid Accounts"
        assert "Defense Evasion" in result["tactics"]
        assert result["attack_version"] == "v15.1"
        assert len(result["description"]) > 0
        assert len(result["detection"]) > 0

    @pytest.mark.asyncio
    async def test_unknown_technique_returns_none(
        self,
        service: AttackKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)

        result = await service.get_technique("T9999")
        assert result is None


class TestSearchTechniques:
    @pytest.mark.asyncio
    async def test_vector_search_ranks_exact_content_highest(
        self,
        service: AttackKBService,
        store: KnowledgeStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """With mock (deterministic) embeddings, same text → score near 1.0."""
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)

        # Retrieve the exact stored content for T1078 to guarantee mock-embedder match
        t1078 = await service.get_technique("T1078")
        assert t1078 is not None

        query_text = _format_content(t1078)
        results = await service.search_techniques(query_text, top_k=3)
        assert len(results) >= 1
        assert results[0].retrieval_method in {"vector", "hybrid"}
        assert results[0].score > 0.9

    @pytest.mark.asyncio
    async def test_search_数据外泄_hits_exfiltration_via_hybrid(
        self,
        service: AttackKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """ISSUE-042: hybrid search maps 数据外泄 → exfiltration under mock embeddings."""
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)

        results = await service.search_techniques("数据外泄", top_k=5)
        assert len(results) >= 1
        assert any("Exfiltration" in (r.metadata.get("tactics") or []) for r in results)
        assert any(r.retrieval_method in {"keyword", "hybrid"} for r in results)

    @pytest.mark.asyncio
    async def test_exfiltration_metadata_includes_bilingual_fields(
        self,
        service: AttackKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)

        t1567 = await service.get_technique("T1567")
        assert t1567 is not None
        assert "数据外泄" in (t1567.get("aliases") or [])
        assert "exfiltration" in " ".join(t1567.get("keywords") or []).lower()


class TestSemanticSearchRemoteMode:
    @pytest_asyncio.fixture
    def semantic_embed_service(self) -> EmbeddingService:
        return EmbeddingService(
            Settings(embedding_mode="remote", embedding_api_base_url="http://stub")
        )

    @pytest_asyncio.fixture
    def semantic_store(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        semantic_embed_service: EmbeddingService,
    ) -> KnowledgeStore:
        return KnowledgeStore(session_factory, semantic_embed_service)

    @pytest_asyncio.fixture
    def semantic_service(
        self,
        semantic_store: KnowledgeStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> AttackKBService:
        return AttackKBService(semantic_store, session_factory)

    @pytest.mark.asyncio
    async def test_remote_mode_uses_vector_only_without_alias_map(
        self,
        semantic_service: AttackKBService,
        semantic_embed_service: EmbeddingService,
        session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ISSUE-522: remote/local embeddings search via vector-only path."""
        assert semantic_embed_service.semantic_search_enabled is True
        await _clean(session_factory)
        mock = MockEmbedder()

        async def stub_remote(texts: list[str]) -> list[list[float]]:
            return await mock.embed(texts)

        monkeypatch.setattr(semantic_embed_service, "_embed_remote", stub_remote)

        await semantic_service.load_from_file(DATA_FILE)

        t1567 = await semantic_service.get_technique("T1567")
        assert t1567 is not None
        anchor_content = _format_content(t1567)

        async def stub_query(text: str) -> list[float]:
            if text.strip() == "数据外泄":
                return (await mock.embed([anchor_content]))[0]
            return (await mock.embed([text]))[0]

        monkeypatch.setattr(semantic_embed_service, "embed_query", stub_query)

        results = await semantic_service.search_techniques("数据外泄", top_k=5)
        assert results
        assert all(r.retrieval_method == "vector" for r in results)
        assert results[0].metadata.get("technique_id") == "T1567"
        assert "Exfiltration" in (results[0].metadata.get("tactics") or [])
        assert results[0].score > 0.9

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("query_text", "expected_technique_id", "expected_tactic"),
        CHINESE_SOC_QUERY_BENCHMARKS,
    )
    async def test_chinese_soc_query_benchmarks(
        self,
        semantic_service: AttackKBService,
        semantic_embed_service: EmbeddingService,
        session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
        query_text: str,
        expected_technique_id: str,
        expected_tactic: str,
    ) -> None:
        """Routing regression: vector-only path ranks the aligned exfiltration technique."""
        await _clean(session_factory)
        mock = MockEmbedder()

        async def stub_remote(texts: list[str]) -> list[list[float]]:
            return await mock.embed(texts)

        monkeypatch.setattr(semantic_embed_service, "_embed_remote", stub_remote)
        await semantic_service.load_from_file(DATA_FILE)

        anchor = await semantic_service.get_technique(expected_technique_id)
        assert anchor is not None
        anchor_content = _format_content(anchor)

        async def stub_query(text: str) -> list[float]:
            if text.strip() == query_text:
                return (await mock.embed([anchor_content]))[0]
            return (await mock.embed([text]))[0]

        monkeypatch.setattr(semantic_embed_service, "embed_query", stub_query)

        results = await semantic_service.search_techniques(query_text, top_k=8)
        hit_ids = {row.metadata.get("technique_id") for row in results}
        assert expected_technique_id in hit_ids
        top = results[0]
        assert top.metadata.get("technique_id") == expected_technique_id
        assert expected_tactic in (top.metadata.get("tactics") or [])
        assert top.score > 0.9
        assert all(row.retrieval_method == "vector" for row in results)


class TestSearchTechniquesContinued:
    @pytest.mark.asyncio
    async def test_respects_top_k(
        self,
        service: AttackKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        await service.load_from_file(DATA_FILE)

        results = await service.search_techniques("lateral movement", top_k=3)
        assert len(results) <= 3

    @pytest.mark.asyncio
    async def test_empty_kb_returns_empty(
        self,
        service: AttackKBService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _clean(session_factory)
        results = await service.search_techniques("anything", top_k=5)
        assert results == []
