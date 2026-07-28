"""Async OpenSearch client wrapper (ISSUE-084).

Provides lazy-initialised connection, index management, document indexing
(fire-and-forget with warning on failure), and multi-index full-text search.

When ``OPENSEARCH_ENABLED=false`` the client never connects — all public
methods are safe no-ops that log at debug level.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.config import Settings

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Index name helpers
# --------------------------------------------------------------------------- #

TOOL_CALLS_SUFFIX = "tool-calls"
AUDIT_LOGS_SUFFIX = "audit-logs"
EVIDENCE_SUFFIX = "evidence"

ALL_SUFFIXES = (TOOL_CALLS_SUFFIX, AUDIT_LOGS_SUFFIX, EVIDENCE_SUFFIX)

# --------------------------------------------------------------------------- #
# Index mappings — standard analyser, text fields for full-text, keyword for
# exact-match / filtering.
# --------------------------------------------------------------------------- #

_BASE_TEXT = {"type": "text"}
_KEYWORD = {"type": "keyword"}
_DATE = {"type": "date"}

_INDEX_MAPPINGS: dict[str, dict[str, Any]] = {
    TOOL_CALLS_SUFFIX: {
        "mappings": {
            "properties": {
                "call_id": _KEYWORD,
                "event_id": _KEYWORD,
                "action_id": _KEYWORD,
                "tool_name": {**_BASE_TEXT, "fields": {"raw": _KEYWORD}},
                "tool_category": _KEYWORD,
                "status": _KEYWORD,
                "error_detail": _BASE_TEXT,
                "started_at": _DATE,
                "completed_at": _DATE,
            }
        }
    },
    AUDIT_LOGS_SUFFIX: {
        "mappings": {
            "properties": {
                "id": _KEYWORD,
                "event_id": _KEYWORD,
                "from_status": _KEYWORD,
                "to_status": _KEYWORD,
                "operator": _KEYWORD,
                "reason": _BASE_TEXT,
                "created_at": _DATE,
            }
        }
    },
    EVIDENCE_SUFFIX: {
        "mappings": {
            "properties": {
                "evidence_id": _KEYWORD,
                "event_id": _KEYWORD,
                "source": _KEYWORD,
                "evidence_type": _KEYWORD,
                "description": _BASE_TEXT,
                "mitre_technique": _KEYWORD,
                "created_at": _DATE,
            }
        }
    },
}


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class OpenSearchClient:
    """Lazy async OpenSearch client.

    The underlying ``AsyncOpenSearch`` connection is created on first use so
    that the ``opensearch-py`` import is never triggered when
    ``OPENSEARCH_ENABLED=false``.
    """

    def __init__(self, settings: Settings) -> None:
        self._enabled: bool = settings.opensearch_enabled
        self._url: str = settings.opensearch_url
        self._prefix: str = settings.opensearch_index_prefix
        self._client: Any = None  # AsyncOpenSearch | None

    # ------------------------------------------------------------------ #
    # Public properties
    # ------------------------------------------------------------------ #

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def url(self) -> str:
        return self._url

    def index_name(self, suffix: str) -> str:
        """Return the full index name, e.g. ``shadowtrace-tool-calls``."""
        return f"{self._prefix}-{suffix}"

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def _get_client(self) -> Any:
        """Lazily create and return the ``AsyncOpenSearch`` instance."""
        if self._client is None:
            # Import is deferred so that opensearch-py is only required when
            # OPENSEARCH_ENABLED=true.
            from opensearchpy import AsyncOpenSearch  # type: ignore[import-untyped,unused-ignore]

            self._client = AsyncOpenSearch(
                [self._url],
                # Disable SSL verification for local dev; production should
                # use proper TLS config via OPENSEARCH_URL and additional env
                # vars when needed.
                verify_certs=False,
                ssl_show_warn=False,
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying transport."""
        client = self._client
        if client is not None:
            await client.close()
            self._client = None

    # ------------------------------------------------------------------ #
    # Health
    # ------------------------------------------------------------------ #

    async def health_check(self) -> bool:
        """Return ``True`` when OpenSearch is reachable."""
        if not self._enabled:
            return False
        try:
            client = await self._get_client()
            return bool(await client.ping())
        except Exception:
            logger.debug("OpenSearch health check failed", exc_info=True)
            return False

    # ------------------------------------------------------------------ #
    # Index management
    # ------------------------------------------------------------------ #

    async def initialize_indices(self) -> None:
        """Create indices with mappings when they do not already exist.

        Called once at application startup.  No-op when disabled.
        """
        if not self._enabled:
            return
        client = await self._get_client()
        for suffix, mapping in _INDEX_MAPPINGS.items():
            index_name = self.index_name(suffix)
            try:
                exists = await client.indices.exists(index=index_name)
                if not exists:
                    await client.indices.create(index=index_name, body=mapping)
                    logger.info("Created OpenSearch index %s", index_name)
            except Exception:
                logger.warning("Failed to create OpenSearch index %s", index_name, exc_info=True)

    # ------------------------------------------------------------------ #
    # Document indexing (fire-and-forget safe)
    # ------------------------------------------------------------------ #

    async def index_document(self, index_suffix: str, doc_id: str, body: dict[str, Any]) -> None:
        """Index a single document.  Logs warning on failure — never raises.

        No-op when ``enabled=False``.
        """
        if not self._enabled:
            return
        index_name = self.index_name(index_suffix)
        try:
            client = await self._get_client()
            await client.index(index=index_name, id=doc_id, body=body, refresh=False)
            logger.debug("Indexed %s/%s", index_name, doc_id)
        except Exception:
            logger.warning("OpenSearch index failed for %s/%s", index_name, doc_id, exc_info=True)

    # ------------------------------------------------------------------ #
    # Search
    # ------------------------------------------------------------------ #

    async def search(
        self,
        query: str,
        indices: list[str],
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """Execute a multi-index full-text search.

        Returns the raw OpenSearch response dict.
        """
        index_names = [self.index_name(s) for s in indices if s in ALL_SUFFIXES]
        if not index_names:
            return {"hits": {"total": {"value": 0}, "hits": []}}

        from_val = (page - 1) * page_size
        client = await self._get_client()
        body: dict[str, Any] = {
            "query": {
                "multi_match": {
                    "query": query,
                    "type": "best_fields",
                    "lenient": True,
                }
            },
            "highlight": {
                "fields": {"*": {}},
                "pre_tags": ["<em>"],
                "post_tags": ["</em>"],
                "fragment_size": 150,
                "number_of_fragments": 1,
            },
            "from": from_val,
            "size": page_size,
        }
        result: dict[str, Any] = await client.search(index=index_names, body=body)
        return result
