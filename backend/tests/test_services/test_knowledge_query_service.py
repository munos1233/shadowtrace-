"""KnowledgeQueryService unit tests (ISSUE-279)."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.core.errors import ValidationError
from app.models.knowledge import KnowledgeChunk
from app.services.knowledge_query_service import KnowledgeQueryService
from app.services.knowledge_store import KnowledgeStore
from tests.helpers.knowledge_isolation import TEST_OWNED_CHUNK_DELETE

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)


def _postgres_reachable() -> bool:
    from app.db.session_provider import SessionProvider

    provider = SessionProvider(DATABASE_URL, pool="nullpool")
    try:
        return asyncio.run(provider.ping_postgres())
    except Exception:
        return False
    finally:
        asyncio.run(provider.dispose())


requires_postgres = pytest.mark.skipif(
    not _postgres_reachable(),
    reason="PostgreSQL not reachable",
)


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


def test_rejects_unknown_kb_name() -> None:
    service = KnowledgeQueryService(store=object())  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="invalid kb_name"):
        asyncio.run(service.list_knowledge(kb_name="unknown_kb"))


def test_rejects_missing_tenant_when_required() -> None:
    service = KnowledgeQueryService(store=object(), require_tenant=True)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="tenant_id is required"):
        asyncio.run(service.list_knowledge())


def test_rejects_blank_query() -> None:
    service = KnowledgeQueryService(store=object())  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="non-whitespace"):
        asyncio.run(service.list_knowledge(q="   "))


def test_catalog_item_shape_includes_created_at_for_list_and_search() -> None:
    from datetime import UTC, datetime

    from app.models.knowledge import ListedKnowledgeChunk, RetrievedChunk
    from app.services.knowledge_query_service import _listed_item, _retrieved_item

    listed = _listed_item(
        ListedKnowledgeChunk(
            chunk_id="chk-list0001",
            kb_name="attack_kb",
            content="list body",
            metadata={},
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    retrieved = _retrieved_item(
        RetrievedChunk(
            chunk_id="chk-search01",
            kb_name="attack_kb",
            content="search body",
            metadata={},
            score=0.9,
            retrieval_method="keyword",
            created_at=datetime(2026, 1, 2, tzinfo=UTC),
        )
    )
    assert listed["created_at"] is not None
    assert retrieved["created_at"] is not None
    assert "score" in retrieved
    assert "score" not in listed
    assert {"chunk_id", "kb_name", "content", "metadata", "created_at"} <= set(listed)
    assert {"chunk_id", "kb_name", "content", "metadata", "created_at"} <= set(retrieved)


@pytest.fixture(scope="module")
def migrated() -> None:
    if not _postgres_reachable():
        pytest.skip("PostgreSQL not reachable")
    command.upgrade(_alembic_config(), "head")


@pytest_asyncio.fixture
async def session_factory(
    migrated: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_knowledge(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        await session.execute(TEST_OWNED_CHUNK_DELETE)
        await session.commit()


@pytest_asyncio.fixture
def query_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> KnowledgeQueryService:
    embed_service = EmbeddingService(Settings(embedding_mode="mock"))
    store = KnowledgeStore(session_factory, embed_service, tenant_isolation_strict=True)
    return KnowledgeQueryService(store)


@pytest.mark.asyncio
@requires_postgres
async def test_pagination_is_stable(
    clean_knowledge: None,
    query_service: KnowledgeQueryService,
) -> None:
    tenant_id = f"tenant-kq-{uuid4().hex[:8]}"
    store = query_service._store
    await store.upsert_chunks(
        "playbook_kb",
        [
            KnowledgeChunk(
                chunk_id=f"chk-playbook{i:02d}",
                kb_name="playbook_kb",
                content=f"Playbook step {i}",
                metadata={"step": i, "tenant_id": tenant_id},
            )
            for i in range(3)
        ],
    )

    total, page_one = await query_service.list_knowledge(
        page=1,
        page_size=2,
        kb_name="playbook_kb",
        tenant_id=tenant_id,
    )
    _, page_two = await query_service.list_knowledge(
        page=2,
        page_size=2,
        kb_name="playbook_kb",
        tenant_id=tenant_id,
    )

    assert total == 3
    assert [item["chunk_id"] for item in page_one] == ["chk-playbook00", "chk-playbook01"]
    assert [item["chunk_id"] for item in page_two] == ["chk-playbook02"]
