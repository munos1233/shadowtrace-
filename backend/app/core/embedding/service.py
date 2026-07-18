"""EmbeddingService: unified embedding with mock and remote backends."""

from __future__ import annotations

import httpx

from app.core.config import Settings
from app.core.embedding.mock_embedder import EMBEDDING_DIM, MockEmbedder


class EmbeddingService:
    """Unified embedding service dispatching on ``embedding_mode``.

    Modes:
      - ``mock``: deterministic MockEmbedder (no network)
      - ``remote``: OpenAI-compatible ``/v1/embeddings`` endpoint via httpx
    """

    EMBEDDING_DIM = EMBEDDING_DIM

    def __init__(self, settings: Settings) -> None:
        self._mode = settings.embedding_mode.strip().lower()
        self._mock = MockEmbedder()
        self._http: httpx.AsyncClient | None = None
        self._base_url = settings.embedding_api_base_url.rstrip("/")
        self._api_key = settings.embedding_api_key

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            headers: dict[str, str] = {}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            self._http = httpx.AsyncClient(base_url=self._base_url, headers=headers)
        return self._http

    async def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of texts.  Returns one 1024-dim vector per text."""
        if not texts:
            return []
        if self._mode == "mock":
            return await self._mock.embed(texts)
        if self._mode == "remote":
            return await self._embed_remote(texts)
        raise ValueError(f"Unknown embedding_mode: {self._mode}")

    async def embed_query(self, text: str) -> list[float]:
        """Convenience: embed a single query text."""
        results = await self.embed_texts([text])
        return results[0]

    async def _embed_remote(self, texts: list[str]) -> list[list[float]]:
        http = await self._get_http()
        resp = await http.post(
            "/v1/embeddings",
            json={"input": texts, "model": "text-embedding-3-small"},
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        vectors: list[list[float]] = []
        for item in data["data"]:
            vec = item["embedding"]
            if len(vec) != self.EMBEDDING_DIM:
                raise ValueError(
                    f"Remote embedding returned dim={len(vec)}, expected {self.EMBEDDING_DIM}"
                )
            vectors.append(vec)
        if len(vectors) != len(texts):
            raise ValueError(
                f"Remote returned {len(vectors)} embeddings for {len(texts)} inputs"
            )
        return vectors

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None
