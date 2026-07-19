"""Embedding service layer (ISSUE-041)."""

from app.core.embedding.mock_embedder import EMBEDDING_DIM, MockEmbedder
from app.core.embedding.service import EmbeddingService

__all__ = ["EmbeddingService", "MockEmbedder", "EMBEDDING_DIM"]
