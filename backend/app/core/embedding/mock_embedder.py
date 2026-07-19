"""MockEmbedder: deterministic pseudo-random 1024-dim unit vectors from SHA-256."""

from __future__ import annotations

import hashlib
import math

EMBEDDING_DIM = 1024

# Large primes for the pseudo-random projection
_PRIME_A = 2654435761
_PRIME_B = 2246822519
_PRIME_C = 3266489917
_PRIME_D = 668265263


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _pseudo_random_float(seed: int, index: int) -> float:
    """Deterministic pseudo-random float in [-1, 1) driven by seed + component index."""
    x = (seed + index * _PRIME_A) & 0xFFFFFFFF
    x = (x ^ (x >> 13)) * _PRIME_B
    x = (x ^ (x >> 16)) * _PRIME_C
    x = (x ^ (x >> 17)) * _PRIME_D
    return ((x & 0xFFFFFFFF) / 2147483648.0) - 1.0


class MockEmbedder:
    """Deterministic embedder: SHA-256(text) → seeded pseudo-random unit vector.

    Same text always produces the same 1024-dim unit vector.  Zero network I/O,
    zero external dependencies beyond stdlib.
    """

    def __init__(self) -> None:
        self.dim = EMBEDDING_DIM

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Produce deterministic unit vectors for *texts*."""
        vectors: list[list[float]] = []
        for text in texts:
            digest = _sha256_hex(text)
            # Use the first 8 hex chars (32 bits) as the seed
            seed = int(digest[:8], 16)
            raw = [_pseudo_random_float(seed, i) for i in range(self.dim)]
            norm = math.sqrt(sum(v * v for v in raw))
            if norm == 0.0:
                vectors.append([0.0] * self.dim)
            else:
                vectors.append([v / norm for v in raw])
        return vectors
