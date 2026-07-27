"""Async Neo4j client with connection pool and health check (ISSUE-082).

Follows the same thin-wrapper pattern as ``RedisClient`` (ISSUE-013).
Neo4j is an optional P2 enhancement — when ``NEO4J_ENABLED=false``
the client is never instantiated and the graph stays PostgreSQL-only.
"""

from __future__ import annotations

import logging

from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.exceptions import Neo4jError, ServiceUnavailable

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Thin async Neo4j wrapper: driver + health check.

    Instantiation is gated by the caller — when ``NEO4J_ENABLED=false``
    the ``GraphSyncService`` skips sync entirely and this client is
    never constructed.
    """

    def __init__(
        self,
        uri: str | None = None,
        *,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        settings = get_settings()
        self._uri = uri or settings.neo4j_uri
        self._user = user or settings.neo4j_user
        self._password = password or settings.neo4j_password
        self._driver = AsyncGraphDatabase.driver(
            self._uri,
            auth=(self._user, self._password),
        )
        self._constraints_ensured: bool = False

    # ------------------------------------------------------------------
    # Schema initialisation (ISSUE-082 §统一命名 point 2 — node_id unique)
    # ------------------------------------------------------------------

    # Six entity labels whose :node_id must be unique.
    _ENTITY_LABELS: tuple[str, ...] = (
        "Account",
        "Host",
        "IP",
        "Domain",
        "Process",
        "File",
    )

    async def ensure_constraints(self) -> None:
        """Create uniqueness constraints on first use; no-op thereafter.

        Idempotent and guarded by ``_constraints_ensured`` so repeated
        calls are cheap.  Only ``node_id`` uniqueness is created — it is
        required by MERGE for index-based lookup.  Property indexes on
        ``(entity_value, event_id)`` are intentionally omitted because the
        current ``_SHORTEST_PATH`` Cypher uses label-less MATCH which
        cannot leverage per-label indexes (future optimisation: make the
        query label-aware).
        """
        if self._constraints_ensured:
            return
        for label in self._ENTITY_LABELS:
            await self._driver.execute_query(
                f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:`{label}`) REQUIRE n.node_id IS UNIQUE",
            )
        self._constraints_ensured = True
        logger.info(
            "Neo4j uniqueness constraints verified for %d entity labels", len(self._ENTITY_LABELS)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_driver(self) -> AsyncDriver:
        """Return the shared async Neo4j driver."""
        return self._driver

    async def ping(self) -> bool:
        """Return True when Neo4j is reachable; False on any failure."""
        try:
            await self._driver.verify_connectivity()
            return True
        except (ServiceUnavailable, Neo4jError, OSError, TimeoutError):
            return False

    async def aclose(self) -> None:
        """Close the driver and release all connections."""
        await self._driver.close()

    async def run_cypher(
        self,
        query: str,
        parameters: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        """Execute a Cypher query and return the collected records as dicts.

        Each record is a plain dict keyed by the alias in the RETURN clause.
        Uses a short-lived session (auto-closed).
        """
        records: list[dict[str, object]] = []
        async with self._driver.session() as session:
            result = await session.run(query, parameters or {})
            async for record in result:
                records.append(dict(record))
        return records
