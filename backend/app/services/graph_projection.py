"""Pure derived projections for persisted entity graphs."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

MAX_PATH_DEPTH = 6
MAX_ATTACK_PATHS = 3


def compute_central_entities(
    nodes: list[Any],
    edges: list[Any],
    top_n: int = 3,
) -> list[str]:
    """Return the top-N entity values ranked by undirected degree."""

    degree: dict[str, int] = defaultdict(int)
    node_value_by_id = {node.node_id: node.entity_value for node in nodes}

    for edge in edges:
        source = node_value_by_id.get(edge.source_node_id, edge.source_node_id)
        target = node_value_by_id.get(edge.target_node_id, edge.target_node_id)
        degree[source] += 1
        degree[target] += 1

    for node in nodes:
        degree.setdefault(node.entity_value, 0)

    ranked = sorted(degree.items(), key=lambda item: (-item[1], item[0]))
    return [label for label, _ in ranked[:top_n]]


def find_attack_paths(
    nodes: list[Any],
    edges: list[Any],
    max_depth: int = MAX_PATH_DEPTH,
    max_paths: int = MAX_ATTACK_PATHS,
) -> list[list[str]]:
    """Discover time-monotonic attack paths with depth-limited DFS."""

    if not edges:
        return []

    adjacency: dict[str, list[tuple[str, Any]]] = defaultdict(list)
    for edge in edges:
        adjacency[edge.source_node_id].append((edge.target_node_id, edge))
    for source in adjacency:
        adjacency[source].sort(key=lambda item: _timestamp_or_min(item[1].occurred_at))

    paths: list[list[str]] = []
    for node in nodes:
        for path in _dfs_chain(node.node_id, adjacency, [], max_depth):
            if len(path) >= 2:
                paths.append(path)
            if len(paths) >= max_paths * 3:
                break

    seen: set[str] = set()
    unique: list[list[str]] = []
    for path in sorted(paths, key=lambda item: (-len(item), str(item))):
        key = "|".join(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique[:max_paths]


def _dfs_chain(
    current: str,
    adjacency: dict[str, list[tuple[str, Any]]],
    visited: list[str],
    max_depth: int,
    last_timestamp: datetime | None = None,
) -> list[list[str]]:
    if len(visited) >= max_depth:
        return []

    next_visited = [*visited, current]
    results = [next_visited]
    for neighbor, edge in adjacency.get(current, []):
        if neighbor in next_visited:
            continue
        edge_timestamp = edge.occurred_at
        if (
            last_timestamp is not None
            and edge_timestamp is not None
            and edge_timestamp < last_timestamp
        ):
            continue
        results.extend(
            _dfs_chain(
                neighbor,
                adjacency,
                next_visited,
                max_depth,
                edge_timestamp or last_timestamp,
            )
        )
    return results


def _timestamp_or_min(timestamp: datetime | None) -> datetime:
    return timestamp if timestamp is not None else datetime.min.replace(tzinfo=UTC)
