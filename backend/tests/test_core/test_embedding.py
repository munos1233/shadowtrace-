"""Tests for MockEmbedder and EmbeddingService (ISSUE-041)."""

from __future__ import annotations

import math

import pytest

from app.core.config import Settings
from app.core.embedding.mock_embedder import MockEmbedder
from app.core.embedding.service import EmbeddingService


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    return dot / (norm_a * norm_b) if norm_a and norm_b else 0.0


class TestMockEmbedder:
    @pytest.mark.asyncio
    async def test_deterministic_same_text_same_vector(self) -> None:
        emb = MockEmbedder()
        v1 = await emb.embed(["hello world"])
        v2 = await emb.embed(["hello world"])
        assert v1 == v2

    @pytest.mark.asyncio
    async def test_different_texts_different_vectors(self) -> None:
        emb = MockEmbedder()
        results = await emb.embed(["alpha", "beta", "gamma"])
        v0, v1, v2 = results
        assert _cosine_similarity(v0, v1) < 0.99
        assert _cosine_similarity(v0, v2) < 0.99
        assert _cosine_similarity(v1, v2) < 0.99

    @pytest.mark.asyncio
    async def test_output_dimension_is_1024(self) -> None:
        emb = MockEmbedder()
        results = await emb.embed(["test"])
        assert len(results) == 1
        assert len(results[0]) == 1024

    @pytest.mark.asyncio
    async def test_unit_vector_norm(self) -> None:
        emb = MockEmbedder()
        results = await emb.embed(["unit test"])
        norm = math.sqrt(sum(v * v for v in results[0]))
        assert abs(norm - 1.0) < 1e-6

    @pytest.mark.asyncio
    async def test_batch_returns_same_as_single(self) -> None:
        emb = MockEmbedder()
        texts = ["a", "b", "c"]
        batch = await emb.embed(texts)
        singles = [await emb.embed([t]) for t in texts]
        for i in range(3):
            assert batch[i] == singles[i][0]

    @pytest.mark.asyncio
    async def test_empty_input(self) -> None:
        emb = MockEmbedder()
        results = await emb.embed([])
        assert results == []


class TestEmbeddingService:
    @pytest.mark.asyncio
    async def test_mock_mode_uses_mock_embedder(self) -> None:
        settings = Settings(embedding_mode="mock")
        svc = EmbeddingService(settings)
        results = await svc.embed_texts(["hello", "world"])
        assert len(results) == 2
        assert len(results[0]) == 1024
        await svc.close()

    @pytest.mark.asyncio
    async def test_embed_query_returns_single_vector(self) -> None:
        settings = Settings(embedding_mode="mock")
        svc = EmbeddingService(settings)
        vec = await svc.embed_query("single query")
        assert len(vec) == 1024
        # embed_query is equivalent to embed_texts([text])[0]
        batch = await svc.embed_texts(["single query"])
        assert vec == batch[0]
        await svc.close()

    @pytest.mark.asyncio
    async def test_empty_texts(self) -> None:
        settings = Settings(embedding_mode="mock")
        svc = EmbeddingService(settings)
        results = await svc.embed_texts([])
        assert results == []
        await svc.close()

    @pytest.mark.asyncio
    async def test_local_mode_dispatches_to_remote_handler(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(embedding_mode="local", embedding_api_base_url="http://test")
        svc = EmbeddingService(settings)
        called = False

        async def fake_remote(texts: list[str]) -> list[list[float]]:
            nonlocal called
            called = True
            return [[0.0] * 1024 for _ in texts]

        monkeypatch.setattr(svc, "_embed_remote", fake_remote)
        vectors = await svc.embed_texts(["local probe"])
        assert called is True
        assert len(vectors[0]) == 1024
        await svc.close()

    def test_unknown_mode_raises(self) -> None:
        settings = Settings(embedding_mode="bogus")
        svc = EmbeddingService(settings)

        async def _call() -> None:
            await svc.embed_texts(["x"])

        with pytest.raises(ValueError, match="Unknown embedding_mode"):
            import asyncio

            asyncio.run(_call())
