"""Health endpoint loaded_resources block tests (ISSUE-138)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.embedding.service import EmbeddingService
from app.core.llm.base import InMemoryLLMCallAuditRecorder
from app.core.llm.mock_client import MockLLMClient
from app.main import app


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_check_loaded_resources_reports_pipeline_attached() -> None:
    from app.rag.pipeline import RetrievalPipeline
    from app.rag.resources import LoadedRetrievalResources, check_loaded_resources

    mock_pipeline = MagicMock(spec=RetrievalPipeline)
    mock_provider = MagicMock()
    mock_provider.pool_policy = "pooled"
    mock_provider.ping_postgres = AsyncMock(return_value=True)

    with (
        patch(
            "app.rag.resources.peek_loaded_retrieval_resources",
            return_value=LoadedRetrievalResources(
                status="ready",
                mode="mock",
                pipeline=mock_pipeline,
            ),
        ),
        patch(
            "app.rag.resources.peek_session_provider",
            return_value=mock_provider,
        ),
        patch(
            "app.rag.resources._probe_corpus_status",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.core.embedding.factory.get_embedding_client",
        ) as mock_embed,
    ):
        mock_embed.return_value.health_probe = AsyncMock(
            return_value=MagicMock(
                model_dump=lambda *, mode: {
                    "status": "ok",
                    "mode": "mock",
                    "release_id": "mock-v1",
                }
            )
        )
        payload = await check_loaded_resources(Settings())
    assert payload["pipeline_attached"] is True
    assert payload["status"] == "ready"


@pytest.mark.asyncio
async def test_health_response_includes_loaded_resources(client: AsyncClient) -> None:
    with (
        patch(
            "app.api.v1.health.check_postgres",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.api.v1.health.check_redis",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.api.v1.health.check_embedding_provider",
            new_callable=AsyncMock,
            return_value={"status": "ok", "mode": "mock", "release_id": "mock-v1"},
        ),
        patch(
            "app.api.v1.health.check_llm_provider",
            new_callable=AsyncMock,
            return_value={"status": "ok", "mode": "mock"},
        ),
        patch(
            "app.api.v1.health._check_loaded_resources",
            new_callable=AsyncMock,
            return_value={"status": "ready", "pipeline_attached": True, "reasons": []},
        ),
        patch(
            "app.api.v1.health._check_playbook_resources",
            new_callable=AsyncMock,
            return_value={
                "status": "ready",
                "mode": "production",
                "active_release_id": "krel-playbook-test01",
                "reasons": [],
            },
        ),
        patch(
            "app.api.v1.health.build_celery_health",
            new_callable=AsyncMock,
            return_value={
                "task_mode": "background",
                "broker": "ok",
                "worker": {"status": "not_applicable", "workers": 0, "worker_ids": []},
            },
        ),
    ):
        response = await client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert "loaded_resources" in body
    assert body["loaded_resources"]["status"] == "ready"


@pytest.mark.asyncio
async def test_lifespan_invokes_retrieval_warmup(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import FastAPI

    from app.main import _lifespan

    called: list[bool] = []

    def _warmup() -> None:
        called.append(True)

    monkeypatch.setattr("app.rag.resources.warmup_retrieval_resources", _warmup)
    monkeypatch.setattr(
        "app.core.socketio_manager.SocketIOManager.start",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(
        "app.core.socketio_manager.SocketIOManager.stop",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr("app.api.v1.health.shutdown_health_clients", AsyncMock())
    monkeypatch.setattr("app.db.session.dispose_session_provider", AsyncMock())

    async with _lifespan(FastAPI()):
        pass

    assert called == [True]


@pytest.mark.asyncio
async def test_health_pipeline_stable_across_multiple_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated loaded_resources probes must keep the same attached pipeline."""
    from app.rag.resources import (
        check_loaded_resources,
        peek_loaded_retrieval_resources,
        reset_loaded_retrieval_resources,
        warmup_retrieval_resources,
    )

    reset_loaded_retrieval_resources()
    session_factory = MagicMock(spec=async_sessionmaker[AsyncSession])
    mock_provider = MagicMock()
    mock_provider.pool_policy = "pooled"
    mock_provider.ping_postgres = AsyncMock(return_value=True)
    mock_provider.session_factory = MagicMock(return_value=session_factory)
    monkeypatch.setattr("app.rag.resources.peek_session_provider", lambda: mock_provider)
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: session_factory)
    monkeypatch.setattr("app.api.v1.deps._get_redis", lambda: MagicMock())
    monkeypatch.setattr(
        "app.core.llm.factory.get_llm_client",
        lambda **kwargs: MockLLMClient(audit_recorder=InMemoryLLMCallAuditRecorder()),
    )
    monkeypatch.setattr(
        "app.core.embedding.factory.get_embedding_client",
        lambda **kwargs: EmbeddingService(Settings()),
    )

    warmup_retrieval_resources()
    first_loaded = peek_loaded_retrieval_resources()
    assert first_loaded is not None and first_loaded.pipeline is not None

    with (
        patch(
            "app.rag.resources._probe_corpus_status",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.core.embedding.factory.get_embedding_client",
        ) as mock_embed,
    ):
        mock_embed.return_value.health_probe = AsyncMock(
            return_value=MagicMock(
                model_dump=lambda *, mode: {
                    "status": "ok",
                    "mode": "mock",
                    "release_id": "mock-v1",
                }
            )
        )
        payloads = [await check_loaded_resources(Settings()) for _ in range(3)]

    assert all(payload["pipeline_attached"] is True for payload in payloads)
    assert all(payload["status"] == "ready" for payload in payloads)
    assert peek_loaded_retrieval_resources() is first_loaded
