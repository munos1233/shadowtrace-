"""Entity relationship graph endpoint (ISSUE-071)."""

from __future__ import annotations

from typing import Annotated, Protocol

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import _get_session_factory, get_event_service
from app.api.v1.errors import EventNotFoundError
from app.core.auth import CurrentPrincipal
from app.core.errors import DependencyUnavailableError
from app.db.orm.graph import GraphEdgeORM, GraphNodeORM
from app.models.agent_io import (
    GraphEdge,
    GraphNode,
    GraphOutput,
    GraphRelationType,
)
from app.services.graph_projection import compute_central_entities, find_attack_paths

router = APIRouter(tags=["graph"])


class _EventReader(Protocol):
    async def get_event(self, event_id: str) -> object | None: ...


class _GraphReader(Protocol):
    async def read_graph(self, event_id: str) -> GraphOutput: ...


class GraphRepository:
    """Read the persisted graph and rebuild its derived projections."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def read_graph(self, event_id: str) -> GraphOutput:
        try:
            async with self._session_factory() as session:
                node_rows = (
                    await session.scalars(
                        select(GraphNodeORM)
                        .where(GraphNodeORM.event_id == event_id)
                        .order_by(GraphNodeORM.node_id)
                    )
                ).all()
                edge_rows = (
                    await session.scalars(
                        select(GraphEdgeORM)
                        .where(GraphEdgeORM.event_id == event_id)
                        .order_by(
                            GraphEdgeORM.occurred_at.asc().nullslast(),
                            GraphEdgeORM.edge_id,
                        )
                    )
                ).all()
        except (SQLAlchemyError, OSError) as exc:
            raise DependencyUnavailableError(
                "database query failed",
                error_code="dependency_unavailable",
                details={"table": "graph_node,graph_edge", "event_id": event_id},
            ) from exc

        nodes = [
            GraphNode(
                node_id=row.node_id,
                event_id=row.event_id,
                entity_type=row.entity_type,
                entity_value=row.entity_value,
                properties=row.properties,
            )
            for row in node_rows
        ]
        edges: list[GraphEdge] = []
        for row in edge_rows:
            try:
                relation_type = GraphRelationType(row.relation_type)
            except ValueError:
                continue
            edges.append(
                GraphEdge(
                    edge_id=row.edge_id,
                    event_id=row.event_id,
                    source_node_id=row.source_node_id,
                    target_node_id=row.target_node_id,
                    relation_type=relation_type,
                    evidence_id=row.evidence_id,
                    occurred_at=row.occurred_at,
                )
            )
        return GraphOutput(
            nodes=nodes,
            edges=edges,
            central_entities=compute_central_entities(nodes, edges),
            attack_path_candidates=find_attack_paths(nodes, edges),
        )


def _get_graph_reader() -> GraphRepository:
    return GraphRepository(_get_session_factory())


@router.get("/events/{event_id}/graph", response_model=GraphOutput)
async def get_graph(
    event_id: str,
    principal: CurrentPrincipal,
    event_service: Annotated[_EventReader, Depends(get_event_service)],
    graph_reader: Annotated[_GraphReader, Depends(_get_graph_reader)],
) -> GraphOutput:
    """Return the persisted entity graph for an event.

    A known event without graph rows is a valid, not-yet-generated graph and
    therefore returns four empty arrays rather than a 404.
    """

    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(
            f"event {event_id} not found",
            details={"event_id": event_id},
        )
    return await graph_reader.read_graph(event_id)
