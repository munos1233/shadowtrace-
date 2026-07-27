"""GraphSyncService: mirror PostgreSQL graph to Neo4j (ISSUE-082).

Idempotent MERGE-based sync with zero-impact fallback when
``NEO4J_ENABLED=false``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.neo4j_client import Neo4jClient
from app.db.orm.graph import GraphEdgeORM, GraphNodeORM

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Neo4j Cypher templates
# ---------------------------------------------------------------------------

_MERGE_NODE = """
MERGE (n:{label} {{node_id: $node_id}})
SET n.event_id = $event_id,
    n.entity_type = $entity_type,
    n.entity_value = $entity_value,
    n += $properties
"""

_MERGE_EDGE = """
MATCH (a {{node_id: $source_node_id}})
MATCH (b {{node_id: $target_node_id}})
MERGE (a)-[r:{rel_type}]->(b)
SET r.event_id = $event_id,
    r.evidence_id = $evidence_id,
    r.occurred_at = $occurred_at
RETURN r
"""

_SHORTEST_PATH = """
MATCH (start {{entity_value: $start_value, event_id: $event_id}}),
      (end {{entity_value: $end_value, event_id: $event_id}}),
      p = shortestPath((start)-[*..{max_depth}]-(end))
RETURN [n in nodes(p) | n.node_id] AS node_ids,
       [n in nodes(p) | labels(n)[0]] AS node_labels,
       [r in relationships(p) | type(r)] AS edge_types,
       length(p) AS path_length
LIMIT 1
"""

# Six entity types per spec §统一命名 point 1 (ISSUE-050 / ISSUE-082).
_ENTITY_TYPES: frozenset[str] = frozenset({"account", "host", "ip", "domain", "process", "file"})

# Eight relation types from GraphAgent.
_RELATION_TYPES: frozenset[str] = frozenset(
    {
        "logged_in_from",
        "connected_to",
        "resolves_to",
        "owns",
        "member_of",
        "communicated_with",
        "executed_on",
        "accessed",
    }
)


# Explicit mapping per ISSUE-082 §统一命名 point 1 — ensures acronyms like
# "ip" → "IP" (not "Ip") and provides a lookup guard for Cypher formatting.
# Keep in sync with ``Neo4jClient._ENTITY_LABELS`` (app/core/neo4j_client.py).
_ENTITY_LABEL_MAP: dict[str, str] = {
    "account": "Account",
    "host": "Host",
    "ip": "IP",
    "domain": "Domain",
    "process": "Process",
    "file": "File",
}


def _neo4j_label(entity_type: str) -> str:
    """Map PostgreSQL entity_type to Neo4j label (PascalCase)."""
    label = _ENTITY_LABEL_MAP.get(entity_type)
    if label is not None:
        return label
    # Fallback for any future entity types not in the original six.
    return "".join(part.capitalize() for part in entity_type.split("_"))


def _neo4j_rel_type(relation_type: str) -> str:
    """Map PostgreSQL relation_type to Neo4j relationship type (SCREAMING_SNAKE_CASE)."""
    return relation_type.upper()


# ---------------------------------------------------------------------------
# Public model
# ---------------------------------------------------------------------------


@dataclass
class SyncResult:
    """Outcome of a ``sync_event_graph`` call."""

    nodes_synced: int = 0
    edges_synced: int = 0
    skipped: bool = False


@dataclass
class PathResult:
    """A single shortest path returned by ``query_paths``."""

    node_ids: list[str]
    node_labels: list[str]
    edge_types: list[str]
    path_length: int


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class GraphSyncService:
    """Mirror PostgreSQL ``graph_node`` / ``graph_edge`` rows into Neo4j.

    When ``NEO4J_ENABLED=false`` every method short-circuits with
    ``skipped=True`` / empty results — no Neo4j connection is ever
    attempted (ISSUE-082 §验收标准 point 1).
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        client: Neo4jClient | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._client = client
        self._enabled = get_settings().neo4j_enabled and client is not None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def sync_event_graph(self, event_id: str) -> SyncResult:
        """Sync all nodes and edges for *event_id* into Neo4j.

        Uses MERGE semantics — repeated calls for the same event are
        idempotent (ISSUE-082 §验收标准 point 2).
        """
        if not self._enabled:
            logger.debug("Neo4j sync skipped for %s (NEO4J_ENABLED=false)", event_id)
            return SyncResult(skipped=True)

        # Health-check: skip when Neo4j is unreachable (ISSUE-082 §降级策略).
        assert self._client is not None  # guaranteed by _enabled check
        if not await self._client.ping():
            logger.warning(
                "Neo4j unreachable — sync skipped for event %s",
                event_id,
            )
            return SyncResult(skipped=True)

        # Ensure schema constraints exist before first sync (ISSUE-082 §统一命名 point 2).
        # Best-effort: a failure here is logged but does not block the sync —
        # MERGE still functions without the uniqueness constraint, just slower.
        try:
            await self._client.ensure_constraints()
        except Exception:
            logger.warning(
                "Neo4j constraint initialisation failed for event %s — "
                "proceeding without index guarantees",
                event_id,
                exc_info=True,
            )

        async with self._session_factory() as session:
            nodes = list(
                await session.scalars(select(GraphNodeORM).where(GraphNodeORM.event_id == event_id))
            )
            edges = list(
                await session.scalars(select(GraphEdgeORM).where(GraphEdgeORM.event_id == event_id))
            )

        if not nodes:
            logger.debug("No graph nodes found for event %s; skipping Neo4j sync", event_id)
            return SyncResult()

        nodes_synced = 0
        edges_synced = 0

        for node in nodes:
            if node.entity_type not in _ENTITY_TYPES:
                logger.warning(
                    "Skipping Neo4j node %s: unknown entity_type %r",
                    node.node_id,
                    node.entity_type,
                )
                continue
            label = _neo4j_label(node.entity_type)
            try:
                await self._client.run_cypher(  # type: ignore[union-attr]
                    _MERGE_NODE.format(label=label),
                    {
                        "node_id": node.node_id,
                        "event_id": node.event_id,
                        "entity_type": node.entity_type,
                        "entity_value": node.entity_value,
                        "properties": node.properties or {},
                    },
                )
                nodes_synced += 1
            except Exception:
                logger.exception(
                    "Neo4j node sync failed: %s (event %s)",
                    node.node_id,
                    event_id,
                )

        for edge in edges:
            if edge.relation_type not in _RELATION_TYPES:
                logger.warning(
                    "Skipping Neo4j edge %s: unknown relation_type %r",
                    edge.edge_id,
                    edge.relation_type,
                )
                continue
            rel_type = _neo4j_rel_type(edge.relation_type)
            try:
                records = await self._client.run_cypher(  # type: ignore[union-attr]
                    _MERGE_EDGE.format(rel_type=rel_type),
                    {
                        "source_node_id": edge.source_node_id,
                        "target_node_id": edge.target_node_id,
                        "event_id": edge.event_id,
                        "evidence_id": edge.evidence_id,
                        "occurred_at": edge.occurred_at,
                    },
                )
                # Only count when MERGE actually executed (MATCH found both
                # nodes).  An empty result means one or both nodes don't
                # exist in Neo4j yet — e.g. the node sync step failed or
                # skipped them.
                if records:
                    edges_synced += 1
                else:
                    logger.warning(
                        "Neo4j edge sync skipped: source or target node not "
                        "in Neo4j (edge=%s, source=%s, target=%s, event=%s)",
                        edge.edge_id,
                        edge.source_node_id,
                        edge.target_node_id,
                        event_id,
                    )
            except Exception:
                logger.exception(
                    "Neo4j edge sync failed: %s (event %s)",
                    edge.edge_id,
                    event_id,
                )

        logger.info(
            "Neo4j sync complete for event %s: %d nodes, %d edges",
            event_id,
            nodes_synced,
            edges_synced,
        )
        return SyncResult(nodes_synced=nodes_synced, edges_synced=edges_synced)

    async def query_paths(
        self,
        event_id: str,
        start_value: str,
        end_value: str,
        max_depth: int = 6,
    ) -> list[PathResult]:
        """Return shortest paths between two entity values.

        Uses Neo4j Cypher when enabled; falls back to PostgreSQL BFS
        on ``graph_node`` / ``graph_edge`` tables when Neo4j is disabled
        (ISSUE-082 §降级策略).
        """
        if not self._enabled:
            logger.debug("Neo4j disabled — query_paths falling back to PG for event %s", event_id)
            return await self._pg_query_paths(event_id, start_value, end_value, max_depth)

        # Fast health-check before query (consistent with sync_event_graph).
        assert self._client is not None  # guaranteed by _enabled check
        if not await self._client.ping():
            logger.warning(
                "Neo4j unreachable — query_paths falling back to PG for event %s",
                event_id,
            )
            return await self._pg_query_paths(event_id, start_value, end_value, max_depth)

        try:
            records = await self._client.run_cypher(  # type: ignore[union-attr]
                _SHORTEST_PATH.format(max_depth=int(max_depth)),
                {
                    "start_value": start_value,
                    "end_value": end_value,
                    "event_id": event_id,
                },
            )
        except Exception:
            logger.exception(
                "Neo4j path query failed, falling back to PG: %s → %s (event %s)",
                start_value,
                end_value,
                event_id,
            )
            return await self._pg_query_paths(event_id, start_value, end_value, max_depth)

        results: list[PathResult] = []
        for rec in records:
            results.append(
                PathResult(
                    node_ids=list(rec.get("node_ids", [])),
                    node_labels=list(rec.get("node_labels", [])),
                    edge_types=list(rec.get("edge_types", [])),
                    path_length=int(rec.get("path_length", 0)),
                )
            )
        return results

    # ------------------------------------------------------------------
    # Internal: PG fallback for query_paths
    # ------------------------------------------------------------------

    async def _pg_query_paths(
        self,
        event_id: str,
        start_value: str,
        end_value: str,
        max_depth: int,
    ) -> list[PathResult]:
        """BFS shortest-path on PostgreSQL ``graph_node`` / ``graph_edge``.

        Used when Neo4j is disabled or unavailable (§降级策略).
        """
        async with self._session_factory() as session:
            nodes = list(
                await session.scalars(select(GraphNodeORM).where(GraphNodeORM.event_id == event_id))
            )
            edges = list(
                await session.scalars(select(GraphEdgeORM).where(GraphEdgeORM.event_id == event_id))
            )

        if not nodes:
            return []

        # Build lookup: entity_value → node, node_id → node
        value_to_node: dict[str, GraphNodeORM] = {}
        id_to_node: dict[str, GraphNodeORM] = {}
        for n in nodes:
            value_to_node[n.entity_value] = n
            id_to_node[n.node_id] = n

        # Adjacency list (undirected, consistent with Cypher `-[*]-`)
        adj: dict[str, list[tuple[str, str]]] = {n.node_id: [] for n in nodes}
        for e in edges:
            if e.source_node_id in adj and e.target_node_id in adj:
                adj[e.source_node_id].append((e.target_node_id, e.relation_type))
                adj[e.target_node_id].append((e.source_node_id, e.relation_type))

        start_node = value_to_node.get(start_value)
        end_node = value_to_node.get(end_value)
        if start_node is None or end_node is None:
            return []

        start_id = start_node.node_id
        end_id = end_node.node_id

        # BFS
        from collections import deque

        queue: deque[tuple[str, list[str], list[str]]] = deque()
        queue.append((start_id, [start_id], []))
        visited: set[str] = {start_id}

        while queue:
            current, path_nodes, path_edges = queue.popleft()
            if len(path_edges) > max_depth:
                continue
            if current == end_id:
                return [
                    PathResult(
                        node_ids=[id_to_node[nid].node_id for nid in path_nodes],
                        node_labels=[
                            _neo4j_label(id_to_node[nid].entity_type) for nid in path_nodes
                        ],
                        edge_types=list(path_edges),
                        path_length=len(path_edges),
                    )
                ]
            for neighbor, rel_type in adj.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(
                        (
                            neighbor,
                            [*path_nodes, neighbor],
                            [*path_edges, _neo4j_rel_type(rel_type)],
                        )
                    )

        return []
