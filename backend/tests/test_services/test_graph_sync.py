"""GraphSyncService tests (ISSUE-082).

``NEO4J_ENABLED=false`` tests run in the normal suite (no Neo4j required).
Neo4j integration tests are gated behind ``@pytest.mark.neo4j`` and are
skipped by default.

Run (disabled path, always safe):
    pytest tests/test_services/test_graph_sync.py -v

Run (Neo4j required):
    docker compose --profile optional up -d neo4j
    NEO4J_ENABLED=true \\
        NEO4J_URI=bolt://localhost:7687 \\
        pytest tests/test_services/test_graph_sync.py -m neo4j -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.db import models as orm
from app.db.orm.graph import GraphEdgeORM, GraphNodeORM
from app.services.graph_sync_service import GraphSyncService, SyncResult

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace"


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def migrated() -> None:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)

    async def _probe() -> None:
        try:
            async with engine.connect() as conn:
                await conn.execute(select(1))
        except Exception as exc:  # noqa: BLE001
            await engine.dispose()
            pytest.skip(f"PostgreSQL not reachable: {exc}")

    import asyncio

    asyncio.run(_probe())
    command.upgrade(_alembic_config(), "head")
    asyncio.run(engine.dispose())


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(select(1))
    except Exception as exc:  # noqa: BLE001
        await engine.dispose()
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def cleanup(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    yield
    async with session_factory() as session:
        async with session.begin():
            for table in (
                orm.EventAuditLog,
                orm.ActionTargetResult,
                orm.ActionExecutionJob,
                orm.DispositionReceipt,
                orm.DispositionOutbox,
                orm.Action,
                orm.Evidence,
                orm.Report,
                orm.SourceEventLink,
                orm.SourceObject,
                orm.SourceConnector,
                orm.SecurityEvent,
                GraphEdgeORM,
                GraphNodeORM,
            ):
                await session.execute(delete(table))


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


async def _seed_event(session_factory: async_sessionmaker[AsyncSession]) -> str:
    from app.models.enums import EventStatus, EventType, Severity
    from app.models.ids import new_event_id

    eid = new_event_id(identity=f"test-graph-sync:{_sfx()}", occurred_at=_utc_now())
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=eid,
                    title="test-graph-sync",
                    event_type=EventType.INSIDER_THREAT.value,
                    severity=Severity.MEDIUM.value,
                    status=EventStatus.VERIFYING.value,
                    occurred_at=_utc_now(),
                    creation_source_ref={
                        "source_product": "mock_xdr",
                        "source_tenant_id": "tenant-test",
                    },
                )
            )
            await session.flush()
    return eid


async def _seed_graph_data(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> dict[str, Any]:
    """Insert a minimal graph: 2 nodes + 1 edge.  Returns node/edge ids."""
    node_a_id = f"node-{_sfx()}"
    node_b_id = f"node-{_sfx()}"
    edge_id = f"edge-{_sfx()}"

    async with session_factory() as session:
        async with session.begin():
            session.add(
                GraphNodeORM(
                    node_id=node_a_id,
                    event_id=event_id,
                    entity_type="account",
                    entity_value="zhangsan@test.com",
                    properties={"role": "admin"},
                )
            )
            session.add(
                GraphNodeORM(
                    node_id=node_b_id,
                    event_id=event_id,
                    entity_type="ip",
                    entity_value="203.0.113.100",
                    properties={"location": "external"},
                )
            )
            session.add(
                GraphEdgeORM(
                    edge_id=edge_id,
                    event_id=event_id,
                    source_node_id=node_a_id,
                    target_node_id=node_b_id,
                    relation_type="logged_in_from",
                    evidence_id=f"ev-{_sfx()}",
                )
            )
            await session.flush()
    return {"node_a": node_a_id, "node_b": node_b_id, "edge": edge_id}


# ---------------------------------------------------------------------------
# Tests: NEO4J_ENABLED=false (zero-impact, always run)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_skipped_when_disabled(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
) -> None:
    """When NEO4J_ENABLED=false, sync_event_graph returns skipped=True
    without attempting any Neo4j connection."""
    event_id = await _seed_event(session_factory)
    await _seed_graph_data(session_factory, event_id)

    svc = GraphSyncService(session_factory)  # No client → disabled
    result = await svc.sync_event_graph(event_id)

    assert isinstance(result, SyncResult)
    assert result.skipped is True
    assert result.nodes_synced == 0
    assert result.edges_synced == 0


@pytest.mark.asyncio
async def test_query_paths_pg_fallback_when_disabled(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
) -> None:
    """When NEO4J_ENABLED=false, query_paths falls back to PostgreSQL BFS
    on graph_node/graph_edge tables (ISSUE-082 §降级策略)."""
    event_id = await _seed_event(session_factory)
    await _seed_graph_data(session_factory, event_id)

    svc = GraphSyncService(session_factory)  # No client → disabled → PG fallback
    results = await svc.query_paths(
        event_id,
        start_value="zhangsan@test.com",
        end_value="203.0.113.100",
    )

    assert len(results) == 1
    path = results[0]
    assert path.path_length == 1
    assert len(path.node_ids) == 2
    assert "IP" in path.node_labels


@pytest.mark.asyncio
async def test_query_paths_pg_fallback_no_graph_data(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
) -> None:
    """PG fallback returns empty list when no graph data exists."""
    event_id = await _seed_event(session_factory)
    # Do NOT seed graph data

    svc = GraphSyncService(session_factory)
    results = await svc.query_paths(
        event_id,
        start_value="zhangsan@test.com",
        end_value="203.0.113.100",
    )

    assert results == []


@pytest.mark.asyncio
async def test_sync_empty_graph_returns_zero_counts(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
) -> None:
    """When event has no graph nodes, disabled service returns zero counts."""
    event_id = await _seed_event(session_factory)
    # Do NOT seed any graph data

    svc = GraphSyncService(session_factory)
    result = await svc.sync_event_graph(event_id)

    assert result.skipped is True
    assert result.nodes_synced == 0

    # Verify no graph rows exist
    async with session_factory() as session:
        node_count = await session.scalar(
            select(GraphNodeORM).where(GraphNodeORM.event_id == event_id)
        )
        assert node_count is None


# ---------------------------------------------------------------------------
# Tests: label / rel_type mapping helpers
# ---------------------------------------------------------------------------


def test_neo4j_label_maps_to_pascal_case() -> None:
    """Entity types are mapped to Neo4j PascalCase labels.

    Two-letter acronyms (IP) stay all-caps per spec §统一命名 point 1.
    """
    from app.services.graph_sync_service import _neo4j_label

    assert _neo4j_label("account") == "Account"
    assert _neo4j_label("host") == "Host"
    assert _neo4j_label("ip") == "IP"
    assert _neo4j_label("domain") == "Domain"
    assert _neo4j_label("process") == "Process"
    assert _neo4j_label("file") == "File"


def test_neo4j_label_fallback_for_unknown_type() -> None:
    """Unknown entity types fall back to capitalised split."""
    from app.services.graph_sync_service import _neo4j_label

    assert _neo4j_label("mobile_device") == "MobileDevice"


def test_neo4j_rel_type_maps_to_upper() -> None:
    """Relation types are mapped to Neo4j SCREAMING_SNAKE_CASE."""
    from app.services.graph_sync_service import _neo4j_rel_type

    assert _neo4j_rel_type("logged_in_from") == "LOGGED_IN_FROM"
    assert _neo4j_rel_type("connected_to") == "CONNECTED_TO"
    assert _neo4j_rel_type("communicated_with") == "COMMUNICATED_WITH"
    assert _neo4j_rel_type("executed_on") == "EXECUTED_ON"


# ---------------------------------------------------------------------------
# Tests: SyncResult model
# ---------------------------------------------------------------------------


def test_sync_result_defaults() -> None:
    """SyncResult has sensible zero defaults."""
    r = SyncResult()
    assert r.nodes_synced == 0
    assert r.edges_synced == 0
    assert r.skipped is False


def test_sync_result_skipped() -> None:
    """SyncResult(skipped=True) carries the flag correctly."""
    r = SyncResult(nodes_synced=3, edges_synced=2, skipped=True)
    assert r.nodes_synced == 3
    assert r.edges_synced == 2
    assert r.skipped is True


# ---------------------------------------------------------------------------
# Tests: Neo4j integration (skipped by default)
# ---------------------------------------------------------------------------


def _neo4j_required() -> None:
    """Skip when NEO4J_ENABLED is not true — avoids FAIL when the user
    runs the full suite without the required env var and Neo4j service."""
    if os.environ.get("NEO4J_ENABLED", "").strip().lower() != "true":
        pytest.skip("NEO4J_ENABLED not set to 'true'")


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_sync_event_graph_persists_to_neo4j(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
) -> None:
    """With NEO4J_ENABLED=true, sync writes nodes+edges to Neo4j, then
    repeats idempotently with the same counts."""
    _neo4j_required()
    from app.core.neo4j_client import Neo4jClient

    event_id = await _seed_event(session_factory)
    await _seed_graph_data(session_factory, event_id)

    client = Neo4jClient()
    svc = GraphSyncService(session_factory, client=client)

    # First sync
    result1 = await svc.sync_event_graph(event_id)
    assert result1.skipped is False
    assert result1.nodes_synced == 2
    assert result1.edges_synced == 1

    # Second sync — idempotent (MERGE), same counts
    result2 = await svc.sync_event_graph(event_id)
    assert result2.nodes_synced == 2
    assert result2.edges_synced == 1

    await client.aclose()


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_query_paths_returns_shortest_path(
    session_factory: async_sessionmaker[AsyncSession],
    cleanup: None,
) -> None:
    """After syncing a simple graph, query_paths finds the shortest path
    between two entity values."""
    _neo4j_required()
    from app.core.neo4j_client import Neo4jClient

    event_id = await _seed_event(session_factory)
    await _seed_graph_data(session_factory, event_id)

    client = Neo4jClient()
    svc = GraphSyncService(session_factory, client=client)
    await svc.sync_event_graph(event_id)

    results = await svc.query_paths(
        event_id,
        start_value="zhangsan@test.com",
        end_value="203.0.113.100",
    )

    assert len(results) >= 1
    path = results[0]
    # Seeded graph: account "zhangsan@test.com" → IP "203.0.113.100" (1 edge)
    assert path.path_length == 1
    assert len(path.node_ids) == 2
    # Verify the labels match our two entity types
    assert "Account" in path.node_labels
    assert "IP" in path.node_labels

    await client.aclose()
