"""Knowledge list API tests (ISSUE-279)."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.deps import get_knowledge_query_service
from app.core.config import Settings
from app.core.embedding.service import EmbeddingService
from app.main import app
from app.models.knowledge import KnowledgeChunk
from app.services.knowledge_query_service import KnowledgeQueryService
from app.services.knowledge_store import KnowledgeStore

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
    }
)


def _postgres_reachable() -> bool:
    import asyncio

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


class _RecordingKnowledgeQueryService:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def list_knowledge(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        kb_name: str | None = None,
        q: str | None = None,
        tenant_id: str | None = None,
    ) -> tuple[int, list[dict[str, Any]]]:
        self.calls.append(
            {
                "page": page,
                "page_size": page_size,
                "kb_name": kb_name,
                "q": q,
                "tenant_id": tenant_id,
            }
        )
        return 1, [
            {
                "chunk_id": "chk-delegated01",
                "kb_name": "attack_kb",
                "content": "Delegated chunk body",
                "metadata": {"source": "service"},
            }
        ]


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer analyst-token"}


def _client(service: Any) -> TestClient:
    app.dependency_overrides[get_knowledge_query_service] = lambda: service
    return TestClient(app)


def test_knowledge_list_requires_auth() -> None:
    response = TestClient(app).get("/api/v1/knowledge")
    assert response.status_code == 401


def test_knowledge_list_delegates_to_query_service() -> None:
    service = _RecordingKnowledgeQueryService()
    client = _client(service)

    response = client.get(
        "/api/v1/knowledge?page=2&page_size=10&kb_name=attack_kb",
        headers=_hdr(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["page"] == 2
    assert payload["page_size"] == 10
    assert payload["items"][0]["chunk_id"] == "chk-delegated01"
    assert service.calls == [
        {
            "page": 2,
            "page_size": 10,
            "kb_name": "attack_kb",
            "q": None,
            "tenant_id": None,
        }
    ]


def test_knowledge_openapi_declares_catalog_query_params() -> None:
    params = {
        p["name"]
        for p in app.openapi()["paths"]["/api/v1/knowledge"]["get"].get("parameters", [])
    }
    assert {"page", "page_size", "kb_name", "q"} <= params


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


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
def knowledge_stack(
    session_factory: async_sessionmaker[AsyncSession],
) -> tuple[KnowledgeStore, KnowledgeQueryService]:
    embed_service = EmbeddingService(Settings(embedding_mode="mock"))
    store = KnowledgeStore(session_factory, embed_service)
    return store, KnowledgeQueryService(store)


@pytest.mark.asyncio
@requires_postgres
async def test_knowledge_list_reads_real_store_rows(
    clean_knowledge: None,
    knowledge_stack: tuple[KnowledgeStore, KnowledgeQueryService],
) -> None:
    store, query_service = knowledge_stack
    await store.upsert_chunks(
        "attack_kb",
        [
            KnowledgeChunk(
                chunk_id="chk-alpha001",
                kb_name="attack_kb",
                content="Alpha technique description",
                metadata={"technique_id": "T1001"},
            ),
            KnowledgeChunk(
                chunk_id="chk-beta0002",
                kb_name="attack_kb",
                content="Beta technique description",
                metadata={"technique_id": "T1002"},
            ),
        ],
    )

    total, items = await query_service.list_knowledge(
        page=1,
        page_size=1,
        kb_name="attack_kb",
    )

    assert total == 2
    assert len(items) == 1
    assert items[0]["chunk_id"] == "chk-alpha001"
    assert items[0]["metadata"]["technique_id"] == "T1001"


@pytest.mark.asyncio
@requires_postgres
async def test_knowledge_list_empty_when_store_has_no_rows(
    clean_knowledge: None,
    knowledge_stack: tuple[KnowledgeStore, KnowledgeQueryService],
) -> None:
    _, query_service = knowledge_stack
    total, items = await query_service.list_knowledge(page=1, page_size=20)
    assert total == 0
    assert items == []


@pytest.mark.asyncio
@requires_postgres
async def test_knowledge_keyword_query_filters_store(
    clean_knowledge: None,
    knowledge_stack: tuple[KnowledgeStore, KnowledgeQueryService],
) -> None:
    store, query_service = knowledge_stack
    await store.upsert_chunks(
        "fp_case_kb",
        [
            KnowledgeChunk(
                chunk_id="chk-fp-alpha",
                kb_name="fp_case_kb",
                content="Backup service login false positive",
                metadata={"case_id": "fp-1"},
            ),
            KnowledgeChunk(
                chunk_id="chk-fp-beta0",
                kb_name="fp_case_kb",
                content="Scheduled maintenance window",
                metadata={"case_id": "fp-2"},
            ),
        ],
    )

    total, items = await query_service.list_knowledge(
        page=1,
        page_size=10,
        kb_name="fp_case_kb",
        q="false positive",
    )

    assert total == 1
    assert items[0]["chunk_id"] == "chk-fp-alpha"
    assert "score" in items[0]


@pytest.mark.asyncio
@requires_postgres
async def test_knowledge_api_integration_with_real_store(
    clean_knowledge: None,
    knowledge_stack: tuple[KnowledgeStore, KnowledgeQueryService],
) -> None:
    store, query_service = knowledge_stack
    await store.upsert_chunks(
        "history_case_kb",
        [
            KnowledgeChunk(
                chunk_id="chk-hist0001",
                kb_name="history_case_kb",
                content="Prior ransomware investigation",
                metadata={"case_id": "hist-1"},
            )
        ],
    )
    app.dependency_overrides[get_knowledge_query_service] = lambda: query_service
    client = TestClient(app)

    response = client.get(
        "/api/v1/knowledge?kb_name=history_case_kb",
        headers=_hdr(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["chunk_id"] == "chk-hist0001"
