"""EmbeddingService: release-aware embedding with mock and remote backends (ISSUE-140)."""

from __future__ import annotations

import time

from app.core.config import Settings
from app.core.embedding.base import EmbeddingCompatibilityError, EmbeddingUnavailableError
from app.core.embedding.compat import validate_vector_dimension
from app.core.embedding.mock_embedder import MockEmbedder
from app.core.embedding.release import build_embedding_release
from app.core.embedding.remote_embedder import RemoteEmbedder
from app.db.orm.knowledge import KNOWLEDGE_CHUNK_VECTOR_DIM
from app.models.embedding import EmbeddingProviderHealth, EmbeddingProviderMode, EmbeddingRelease


class EmbeddingService:
    """Unified embedding service bound to one ``EmbeddingRelease`` per process."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._release = build_embedding_release(settings)
        self._mode = self._release.provider_mode
        self._mock = MockEmbedder(release=self._release)
        self._remote: RemoteEmbedder | None = None
        if self._mode in {EmbeddingProviderMode.LOCAL, EmbeddingProviderMode.REMOTE}:
            self._remote = RemoteEmbedder(settings, release=self._release)

    @property
    def release(self) -> EmbeddingRelease:
        return self._release

    @property
    def max_batch_size(self) -> int:
        """Configured embed batch cap (``EMBEDDING_MAX_BATCH_SIZE``)."""
        return max(1, int(self._settings.embedding_max_batch_size))

    @property
    def embedding_mode(self) -> str:
        return self._mode.value

    @property
    def semantic_search_enabled(self) -> bool:
        """True when real embeddings can support cross-lingual vector recall (ISSUE-522)."""
        return self._mode in {EmbeddingProviderMode.REMOTE, EmbeddingProviderMode.LOCAL}

    async def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of texts; enforce batch limits and release dimension."""
        if not texts:
            return []
        if len(texts) > self._settings.embedding_max_batch_size:
            raise EmbeddingCompatibilityError(
                message="embedding batch exceeds configured limit",
                error_code="capacity_limit_exceeded",
                details={
                    "batch_size": len(texts),
                    "max_batch_size": self._settings.embedding_max_batch_size,
                },
            )
        if self._mode == EmbeddingProviderMode.MOCK:
            vectors = await self._mock.embed(texts)
        elif self._remote is not None:
            vectors = await self._remote.embed(texts)
        else:
            raise EmbeddingUnavailableError(
                message=f"embedding provider unavailable for mode={self._mode.value}",
                error_code="embedding_provider_unavailable",
            )
        for index, vector in enumerate(vectors):
            validate_vector_dimension(
                vector,
                expected_dimension=self._release.dimension,
                context=f"embed_texts[{index}]",
            )
        return vectors

    async def embed_query(self, text: str) -> list[float]:
        """Convenience: embed a single query text."""
        results = await self.embed_texts([text])
        return results[0]

    async def health_probe(self) -> EmbeddingProviderHealth:
        """Return sanitized provider readiness (no secrets)."""
        started = time.perf_counter()
        status = "ok"
        error_code: str | None = None
        if self._mode == EmbeddingProviderMode.MOCK:
            try:
                await self._mock.embed(["health probe"])
            except Exception:  # noqa: BLE001 — health must classify, not raise
                status = "error"
                error_code = "embedding_provider_error"
        elif self._remote is not None:
            status, error_code = await self._remote.health_check()
        else:
            status = "error"
            error_code = "embedding_provider_unavailable"

        store_dim = KNOWLEDGE_CHUNK_VECTOR_DIM
        index_schema_ok = self._release.dimension == store_dim
        if not index_schema_ok:
            if status == "ok":
                status = "degraded"
            error_code = error_code or "embedding_schema_drift"

        return EmbeddingProviderHealth(
            status=status,
            mode=self._mode,
            release_id=self._release.release_id,
            model_id=self._release.model_id,
            dimension=self._release.dimension,
            store_vector_dimension=store_dim,
            index_schema_ok=index_schema_ok,
            distance_metric=self._release.distance_metric,
            normalization=self._release.normalization,
            config_hash=self._release.config_hash,
            error_code=error_code,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    async def close(self) -> None:
        if self._remote is not None:
            await self._remote.close()
