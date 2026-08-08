"""KnowledgeQueryService unit tests (ISSUE-279)."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.core.errors import ValidationError
from app.models.knowledge import KnowledgeChunk
from app.services.knowledge_query_service import KnowledgeQueryService
from app.services.knowledge_store import KnowledgeStore

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
        await session.execute(text("DELETE FROM knowledge_chunk"))
        await session.commit()


@pytest_asyncio.fixture
def query_service(
    session_factory: async_sessionmaker[AsyncSession],
) -> KnowledgeQueryService:
    embed_service = EmbeddingService(Settings(embedding_mode="mock"))
    store = KnowledgeStore(session_factory, embed_service)
    return KnowledgeQueryService(store)


@pytest.mark.asyncio
@requires_postgres
async def test_pagination_is_stable(
    clean_knowledge: None,
    query_service: KnowledgeQueryService,
) -> None:
    store = query_service._store
    await store.upsert_chunks(
        "playbook_kb",
        [
            KnowledgeChunk(
                chunk_id=f"chk-playbook{i:02d}",
                kb_name="playbook_kb",
                content=f"Playbook step {i}",
                metadata={"step": i},
            )
            for i in range(3)
        ],
    )

    total, page_one = await query_service.list_knowledge(
        page=1,
        page_size=2,
        kb_name="playbook_kb",
    )
    _, page_two = await query_service.list_knowledge(
        page=2,
        page_size=2,
        kb_name="playbook_kb",
    )

    assert total == 3
    assert [item["chunk_id"] for item in page_one] == ["chk-playbook00", "chk-playbook01"]
    assert [item["chunk_id"] for item in page_two] == ["chk-playbook02"]
