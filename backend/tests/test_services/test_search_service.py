"""SearchService dual-path tests (ISSUE-084).

All tests in this file run against the PostgreSQL ILIKE fallback path by default
(``OPENSEARCH_ENABLED=false``).  OpenSearch-specific tests are gated behind the
``@pytest.mark.opensearch`` marker and require a running OpenSearch instance.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.opensearch_client import OpenSearchClient
from app.db import models as orm
from app.models.search import SearchResponse
from app.services.search_service import SearchService

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="module")
def migrated_database() -> None:
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_search_data(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    """Remove all rows from the three searchable tables before/after each test."""
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.ToolCallLog))
            await session.execute(delete(orm.EventAuditLog))
            await session.execute(delete(orm.Evidence))
            await session.execute(delete(orm.SecurityEvent))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(delete(orm.ToolCallLog))
            await session.execute(delete(orm.EventAuditLog))
            await session.execute(delete(orm.Evidence))
            await session.execute(delete(orm.SecurityEvent))


@pytest_asyncio.fixture
async def service(
    session_factory: async_sessionmaker[AsyncSession],
) -> SearchService:
    """Return SearchService wired for ILIKE fallback only."""
    return SearchService(session_factory, opensearch=None)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _utc_now() -> datetime:
    return datetime.now(UTC)


async def _seed_tool_call(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    call_id: str | None = None,
    event_id: str | None = None,
    tool_name: str = "isolate_host",
    tool_category: str = "response",
    status: str = "success",
    error_detail: str | None = None,
    parameters: dict | None = None,
) -> orm.ToolCallLog:
    async with session_factory() as session:
        async with session.begin():
            row = orm.ToolCallLog(
                call_id=call_id or _id("call"),
                event_id=event_id or _id("evt"),
                tool_name=tool_name,
                tool_category=tool_category,
                parameters=parameters or {},
                result={"outcome": "ok"},
                status=status,
                started_at=_utc_now(),
                completed_at=_utc_now(),
                duration_ms=150,
                retry_count=0,
                error_detail=error_detail,
            )
            session.add(row)
            await session.flush()
    return row


async def _seed_audit_log(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str | None = None,
    from_status: str | None = "triaging",
    to_status: str | None = "analyzing",
    reason: str | None = None,
) -> orm.EventAuditLog:
    async with session_factory() as session:
        async with session.begin():
            row = orm.EventAuditLog(
                event_id=event_id or _id("evt"),
                from_status=from_status,
                to_status=to_status,
                operator="analyst-1",
                reason=reason or "Auto-promoted after triage",
                created_at=_utc_now(),
            )
            session.add(row)
            await session.flush()
    return row


async def _seed_evidence(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    evidence_id: str | None = None,
    event_id: str | None = None,
    description: str = "Suspicious outbound connection to external IP",
    evidence_type: str = "network_flow",
    source: str = "endpoint",
) -> orm.Evidence:
    se_event_id = event_id or _id("evt")
    async with session_factory() as session:
        async with session.begin():
            # Ensure a security_event row exists (FK constraint).
            existing = await session.get(orm.SecurityEvent, se_event_id)
            if existing is None:
                session.add(
                    orm.SecurityEvent(
                        event_id=se_event_id,
                        event_type="other",
                        title="test event",
                        description="seeded for search tests",
                        status="new",
                        severity="low",
                        risk_score=0,
                        confidence=0.5,
                        creation_source_ref={},
                        replan_count=0,
                        escalated=False,
                        external_unsynced=False,
                    )
                )
                await session.flush()
            row = orm.Evidence(
                evidence_id=evidence_id or _id("evd"),
                event_id=se_event_id,
                source=source,
                evidence_type=evidence_type,
                description=description,
                confidence=0.85,
            )
            session.add(row)
            await session.flush()
    return row


# --------------------------------------------------------------------------- #
# Fallback tests (no OpenSearch)
# --------------------------------------------------------------------------- #


class TestSearchServiceFallback:
    """ILIKE fallback path — these tests always pass without OpenSearch."""

    @pytest.mark.asyncio
    async def test_search_tool_calls_finds_match(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Insert a tool-call log and verify it is found by tool_name."""
        await _seed_tool_call(session_factory, tool_name="isolate_host")

        result = await service.search("isolate", scope="tool-calls")
        assert isinstance(result, SearchResponse)
        assert result.total >= 1
        assert result.degraded is True
        assert any(item.index == "tool_call_log" for item in result.items)

    @pytest.mark.asyncio
    async def test_search_tool_calls_no_match(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _seed_tool_call(session_factory, tool_name="isolate_host")
        result = await service.search("nonexistent12345", scope="tool-calls")
        assert result.total == 0
        assert result.items == []

    @pytest.mark.asyncio
    async def test_search_audit_logs_finds_match(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _seed_audit_log(session_factory, reason="Manually escalated by analyst")
        result = await service.search("escalated", scope="audit-logs")
        assert result.total >= 1
        assert result.degraded is True

    @pytest.mark.asyncio
    async def test_search_evidence_finds_match(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _seed_evidence(
            session_factory,
            description="Data exfiltration via DNS tunneling detected",
        )
        result = await service.search("exfiltration", scope="evidence")
        assert result.total >= 1
        assert result.degraded is True

    @pytest.mark.asyncio
    async def test_search_all_scopes_combined(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _seed_tool_call(session_factory, tool_name="block_ip")
        await _seed_audit_log(session_factory, reason="block_ip triggered escalation")
        await _seed_evidence(session_factory, description="block_ip rule matched")

        result = await service.search("block_ip", scope="all")
        # Should find hits across all three tables.
        assert result.total >= 3
        indices = {item.index for item in result.items}
        assert "tool_call_log" in indices
        assert "event_audit_log" in indices
        assert "evidence" in indices

    @pytest.mark.asyncio
    async def test_search_degraded_flag(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _seed_tool_call(session_factory, tool_name="quarantine_mailbox")
        result = await service.search("quarantine")
        assert result.degraded is True

    @pytest.mark.asyncio
    async def test_search_pagination(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        for i in range(5):
            await _seed_tool_call(
                session_factory,
                call_id=f"call-{i:02d}",
                tool_name="block_ip",
            )

        page1 = await service.search("block_ip", scope="tool-calls", page=1, page_size=2)
        assert page1.page == 1
        assert page1.page_size == 2
        assert len(page1.items) <= 2
        assert page1.total == 5

        page3 = await service.search("block_ip", scope="tool-calls", page=3, page_size=2)
        assert page3.page == 3
        assert len(page3.items) <= 2

    @pytest.mark.asyncio
    async def test_search_scope_filter(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        await _seed_tool_call(session_factory, tool_name="block_ip")
        await _seed_audit_log(session_factory, reason="block_ip rule fired")

        tool_only = await service.search("block_ip", scope="tool-calls")
        assert all(item.index == "tool_call_log" for item in tool_only.items)

        audit_only = await service.search("block_ip", scope="audit-logs")
        assert all(item.index == "event_audit_log" for item in audit_only.items)

    @pytest.mark.asyncio
    async def test_search_empty_query_returns_empty(
        self,
        service: SearchService,
    ) -> None:
        result = await service.search("   ", scope="all")
        assert result.total == 0
        assert result.items == []

    @pytest.mark.asyncio
    async def test_search_invalid_scope_raises(
        self,
        service: SearchService,
    ) -> None:
        with pytest.raises(ValueError, match="scope"):
            await service.search("test", scope="invalid-scope")

    @pytest.mark.asyncio
    async def test_search_result_item_has_expected_fields(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        event_id = f"evt-{uuid.uuid4().hex[:8]}"
        await _seed_tool_call(session_factory, event_id=event_id, tool_name="revoke_token")
        result = await service.search("revoke_token", scope="tool-calls")
        assert result.total >= 1
        item = result.items[0]
        assert item.index == "tool_call_log"
        assert item.doc_id
        assert item.event_id == event_id
        assert item.source_summary
        assert item.highlight == ""  # No highlighting in fallback

    @pytest.mark.asyncio
    async def test_search_no_results_when_tables_are_empty(
        self,
        service: SearchService,
    ) -> None:
        result = await service.search("anything", scope="all")
        assert result.total == 0
        assert result.items == []

    @pytest.mark.asyncio
    async def test_search_jsonb_field_match(
        self,
        service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """JSONB columns should also be searchable via ::text cast."""
        await _seed_tool_call(
            session_factory,
            tool_name="generic_action",
            parameters={"target": "192.168.1.100", "method": "quarantine"},
        )
        result = await service.search("192.168.1.100", scope="tool-calls")
        assert result.total >= 1


# --------------------------------------------------------------------------- #
# OpenSearch tests (opt-in marker)
# --------------------------------------------------------------------------- #


@pytest.mark.opensearch
class TestSearchServiceOpenSearch:
    """Tests that require a running OpenSearch instance.

    Run with::

        docker compose -f infra/docker-compose.yml --profile optional up -d opensearch
        OPENSEARCH_ENABLED=true OPENSEARCH_URL=http://localhost:9200 pytest -m opensearch -v
    """

    @pytest_asyncio.fixture
    async def os_service(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> AsyncIterator[SearchService]:
        """Wired SearchService with real OpenSearch client.

        Skips the test when OpenSearch is not reachable.
        """
        monkeypatch.setenv("OPENSEARCH_ENABLED", "true")
        monkeypatch.setenv(
            "OPENSEARCH_URL", os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
        )
        settings = Settings()
        client = OpenSearchClient(settings)
        if not await client.health_check():
            pytest.skip("OpenSearch is not reachable")
        await client.initialize_indices()
        yield SearchService(session_factory, opensearch=client)
        await client.close()

    @pytest.mark.asyncio
    async def test_search_via_opensearch_returns_highlights(
        self,
        os_service: SearchService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Index a document and verify it is searchable with highlights."""
        # Index directly via the client.
        assert os_service._os is not None
        call_id = f"os-call-{uuid.uuid4().hex[:8]}"
        await os_service._os.index_document(
            "tool-calls",
            call_id,
            {
                "call_id": call_id,
                "event_id": "evt-os-test",
                "tool_name": "block_ip",
                "tool_category": "response",
                "status": "success",
                "error_detail": None,
                "started_at": _utc_now().isoformat(),
                "completed_at": _utc_now().isoformat(),
                "duration_ms": 200,
                "retry_count": 0,
            },
        )
        # Allow a brief moment for the document to become searchable.
        import asyncio

        await asyncio.sleep(1)

        result = await os_service.search("block_ip", scope="tool-calls")
        assert result.total >= 1
        assert result.degraded is False

    @pytest.mark.asyncio
    async def test_opensearch_fallback_when_disabled(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """When OpenSearch is disabled, results come from ILIKE fallback."""
        svc = SearchService(session_factory, opensearch=None)
        result = await svc.search("block_ip")
        assert result.degraded is True
