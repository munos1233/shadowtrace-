"""Entity relationship graph API tests (ISSUE-071)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import get_event_service
from app.api.v1.graph import GraphRepository, _get_graph_reader
from app.core.auth import Principal, get_principal
from app.db.orm.graph import GraphEdgeORM, GraphNodeORM
from app.main import app
from app.models.agent_io import GraphOutput


class _EventService:
    def __init__(self, *, exists: bool = True) -> None:
        self._exists = exists

    async def get_event(self, event_id: str) -> object | None:
        return object() if self._exists else None


class _GraphReader:
    def __init__(self, output: GraphOutput) -> None:
        self.output = output
        self.calls: list[str] = []

    async def read_graph(self, event_id: str) -> GraphOutput:
        self.calls.append(event_id)
        return self.output


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _client(
    output: GraphOutput,
    *,
    event_exists: bool = True,
) -> tuple[TestClient, _GraphReader]:
    reader = _GraphReader(output)

    async def _principal() -> Principal:
        return Principal(subject="analyst-1", roles=["analyst"])

    async def _event_service() -> _EventService:
        return _EventService(exists=event_exists)

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_event_service] = _event_service
    app.dependency_overrides[_get_graph_reader] = lambda: reader
    return TestClient(app), reader


def _graph_output() -> GraphOutput:
    return GraphOutput.model_validate(
        {
            "nodes": [
                {
                    "node_id": "node-account",
                    "event_id": "evt-071",
                    "entity_type": "account",
                    "entity_value": "alice",
                    "properties": {"department": "finance"},
                },
                {
                    "node_id": "node-host",
                    "event_id": "evt-071",
                    "entity_type": "host",
                    "entity_value": "workstation-01",
                    "properties": {},
                },
            ],
            "edges": [
                {
                    "edge_id": "edge-login",
                    "event_id": "evt-071",
                    "source_node_id": "node-account",
                    "target_node_id": "node-host",
                    "relation_type": "logged_in_to",
                    "evidence_id": "ev-login",
                    "occurred_at": "2026-07-28T01:00:00Z",
                }
            ],
            "central_entities": ["alice"],
            "attack_path_candidates": [["node-account", "node-host"]],
        }
    )


def test_graph_returns_persisted_projection() -> None:
    client, reader = _client(_graph_output())

    response = client.get("/api/v1/events/evt-071/graph")

    assert response.status_code == 200
    payload = response.json()
    assert payload["nodes"][0]["properties"]["department"] == "finance"
    assert payload["edges"][0]["evidence_id"] == "ev-login"
    assert payload["central_entities"] == ["alice"]
    assert payload["attack_path_candidates"] == [["node-account", "node-host"]]
    assert reader.calls == ["evt-071"]


def test_graph_returns_empty_arrays_when_not_generated() -> None:
    client, _ = _client(GraphOutput())

    response = client.get("/api/v1/events/evt-071/graph")

    assert response.status_code == 200
    assert response.json() == {
        "nodes": [],
        "edges": [],
        "central_entities": [],
        "attack_path_candidates": [],
    }


def test_graph_returns_event_not_found_before_reading_graph() -> None:
    client, reader = _client(_graph_output(), event_exists=False)

    response = client.get("/api/v1/events/missing/graph")

    assert response.status_code == 404
    assert response.json()["error_code"] == "event_not_found"
    assert reader.calls == []


class _ScalarRows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Session:
    def __init__(self, results: list[list[Any]]) -> None:
        self._results = iter(results)

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def scalars(self, statement: object) -> _ScalarRows:
        _ = statement
        return _ScalarRows(next(self._results))


async def test_repository_rebuilds_central_entities_and_monotonic_paths() -> None:
    occurred_at = datetime(2026, 7, 28, 1, 0, tzinfo=UTC)
    nodes = [
        GraphNodeORM(
            node_id="node-a",
            event_id="evt-071",
            entity_type="account",
            entity_value="alice",
            properties={},
        ),
        GraphNodeORM(
            node_id="node-b",
            event_id="evt-071",
            entity_type="host",
            entity_value="host-01",
            properties={},
        ),
        GraphNodeORM(
            node_id="node-c",
            event_id="evt-071",
            entity_type="ip",
            entity_value="203.0.113.8",
            properties={},
        ),
    ]
    edges = [
        GraphEdgeORM(
            edge_id="edge-a-b",
            event_id="evt-071",
            source_node_id="node-a",
            target_node_id="node-b",
            relation_type="logged_in_to",
            evidence_id="ev-1",
            occurred_at=occurred_at,
        ),
        GraphEdgeORM(
            edge_id="edge-b-c",
            event_id="evt-071",
            source_node_id="node-b",
            target_node_id="node-c",
            relation_type="connected_to",
            evidence_id="ev-2",
            occurred_at=occurred_at,
        ),
    ]
    session = _Session([nodes, edges])
    repository = GraphRepository(cast(Any, lambda: session))

    output = await repository.read_graph("evt-071")

    assert output.central_entities[0] == "host-01"
    assert ["node-a", "node-b", "node-c"] in output.attack_path_candidates


async def test_repository_skips_edges_with_unknown_relation_type() -> None:
    nodes = [
        GraphNodeORM(
            node_id="node-a",
            event_id="evt-071",
            entity_type="account",
            entity_value="alice",
            properties={},
        ),
        GraphNodeORM(
            node_id="node-b",
            event_id="evt-071",
            entity_type="host",
            entity_value="host-01",
            properties={},
        ),
    ]
    edges = [
        GraphEdgeORM(
            edge_id="edge-invalid",
            event_id="evt-071",
            source_node_id="node-a",
            target_node_id="node-b",
            relation_type="unknown_relation",
            evidence_id="ev-bad",
            occurred_at=None,
        ),
        GraphEdgeORM(
            edge_id="edge-valid",
            event_id="evt-071",
            source_node_id="node-a",
            target_node_id="node-b",
            relation_type="logged_in_to",
            evidence_id="ev-good",
            occurred_at=None,
        ),
    ]
    session = _Session([nodes, edges])
    repository = GraphRepository(cast(Any, lambda: session))

    output = await repository.read_graph("evt-071")

    assert len(output.edges) == 1
    assert output.edges[0].edge_id == "edge-valid"
