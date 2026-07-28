"""GraphAgent: entity-relationship graph from evidence (ISSUE-050).

Builds a PostgreSQL-backed graph from EvidenceOutput, computes centrality
and attack-path candidates, persists nodes/edges, and writes ``graph_output``
to EventContext via WorkingMemory.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.base import BaseAgent
from app.agents.graph_builder import GraphBuilder
from app.core.errors import ShadowTraceError
from app.db.orm.graph import GraphEdgeORM, GraphNodeORM
from app.models.agent_io import GraphAgentInput, GraphOutput
from app.models.evidence import Evidence
from app.services.graph_projection import (
    compute_central_entities as _compute_central_entities,
)
from app.services.graph_projection import find_attack_paths as _find_attack_paths

logger = logging.getLogger(__name__)


class GraphAgent(BaseAgent[GraphAgentInput, GraphOutput]):
    """Transform evidence into an entity-relationship graph.

    Persists nodes and edges to PostgreSQL (graph_node / graph_edge tables),
    computes degree-based centrality (top 3), and discovers time-monotonic
    attack path candidates.  Graph construction failure records a degraded
    flag but does not block the investigation pipeline (降级策略).
    """

    agent_name: str = "graph_agent"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        tool_executor: Any | None = None,
        working_memory: Any | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            tool_executor=tool_executor,
            working_memory=working_memory,
            budget_service=budget_service,
            output_guard=output_guard,
            trace_service=trace_service,
            audit_service=audit_service,
            event_bus=event_bus,
        )
        self._session_factory = session_factory
        self.last_persist_error: str | None = None
        self.last_persist_ok: bool = False
        self.last_degraded_reason: str | None = None

    # ------------------------------------------------------------------ #
    # Public entry-point
    # ------------------------------------------------------------------ #

    async def _run(self, input: GraphAgentInput) -> GraphOutput:
        event_id = input.event_id
        evidence_list: list[Evidence] = input.evidence_output.evidence_list
        self.last_degraded_reason = None

        # 1. Build graph from evidence (pure in-memory transformation)
        try:
            nodes, edges = GraphBuilder.build(evidence_list)
        except Exception:
            logger.exception("GraphBuilder failed for event=%s", event_id)
            output = self._empty_degraded()
            await self._mark_degraded(event_id, reason="graph_builder_failed")
            await self._write_context(event_id, output)
            return output

        # 2. Compute centrality (top 3 entities by degree)
        central_entities = _compute_central_entities(nodes, edges)

        # 3. Compute attack-path candidates (time-monotonic, depth ≤ 6, max 3)
        attack_path_candidates = _find_attack_paths(nodes, edges)

        # 4. Build output
        output = GraphOutput(
            nodes=nodes,
            edges=edges,
            central_entities=central_entities,
            attack_path_candidates=attack_path_candidates,
        )

        # 5. Persist to PostgreSQL (best-effort; degrades on failure)
        await self._persist_graph(event_id, nodes, edges)
        if self.last_persist_error is not None:
            await self._mark_degraded(
                event_id,
                reason=f"graph_persist_failed: {self.last_persist_error}",
            )

        # 6. Write to EventContext via WorkingMemory
        await self._write_context(event_id, output)

        return output

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    async def _persist_graph(
        self,
        event_id: str,
        nodes: list[Any],
        edges: list[Any],
    ) -> None:
        """Upsert nodes and edges into PostgreSQL.  Best-effort: failure sets
        ``last_persist_error`` and logs the degraded state but does NOT raise."""
        if self._session_factory is None:
            self.last_persist_error = "no session_factory configured"
            logger.warning("GraphAgent persist skipped: %s", self.last_persist_error)
            return

        self.last_persist_error = None
        self.last_persist_ok = False
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    await self._upsert_nodes(session, event_id, nodes)
                    await self._upsert_edges(session, event_id, edges)
            self.last_persist_ok = True
        except Exception as exc:
            self.last_persist_error = str(exc)
            logger.exception("GraphAgent persist failed for event=%s", event_id)

    @staticmethod
    async def _upsert_nodes(
        session: AsyncSession,
        event_id: str,
        nodes: list[Any],
    ) -> None:
        if not nodes:
            return
        rows = [
            {
                "node_id": n.node_id,
                "event_id": n.event_id,
                "entity_type": n.entity_type,
                "entity_value": n.entity_value,
                "properties": n.properties,
            }
            for n in nodes
        ]
        stmt = pg_insert(GraphNodeORM).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_graph_node_identity",
            set_={"properties": stmt.excluded.properties},
        )
        await session.execute(stmt)

    @staticmethod
    async def _upsert_edges(
        session: AsyncSession,
        event_id: str,
        edges: list[Any],
    ) -> None:
        if not edges:
            return
        rows = [
            {
                "edge_id": e.edge_id,
                "event_id": e.event_id,
                "source_node_id": e.source_node_id,
                "target_node_id": e.target_node_id,
                "relation_type": e.relation_type.value
                if hasattr(e.relation_type, "value")
                else str(e.relation_type),
                "evidence_id": e.evidence_id,
                "occurred_at": e.occurred_at,
            }
            for e in edges
        ]
        # Edge dedup: ON CONFLICT DO NOTHING (edge_id is PK, derived deterministically)
        stmt = (
            pg_insert(GraphEdgeORM)
            .values(rows)
            .on_conflict_do_nothing(
                index_elements=["edge_id"],
            )
        )
        await session.execute(stmt)

    # ------------------------------------------------------------------ #
    # WorkingMemory
    # ------------------------------------------------------------------ #

    async def _write_context(self, event_id: str, output: GraphOutput) -> None:
        if self.working_memory is None:
            return
        try:
            await self.working_memory.write(
                event_id,
                "graph_output",
                output.model_dump(mode="json"),
            )
        except Exception:
            logger.warning("GraphAgent WM write failed event=%s", event_id, exc_info=True)

    async def _mark_degraded(self, event_id: str, *, reason: str) -> None:
        """Best-effort degraded marker for graph build/persist failures."""
        self.last_degraded_reason = reason
        if self.working_memory is None:
            return
        try:
            await self.working_memory.write(
                event_id,
                "graph_degraded",
                {
                    "degraded": True,
                    "reason": reason,
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            )
        except ShadowTraceError:
            logger.exception(
                "Failed to persist graph_degraded flag for event=%s",
                event_id,
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _empty_degraded() -> GraphOutput:
        return GraphOutput(
            nodes=[],
            edges=[],
            central_entities=[],
            attack_path_candidates=[],
        )
