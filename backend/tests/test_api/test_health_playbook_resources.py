"""Health endpoint playbook_resources block tests (ISSUE-139 / #645)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings, get_settings
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
async def test_check_playbook_resources_reports_active_release() -> None:
    from unittest.mock import MagicMock

    from app.playbook.resources import LoadedPlaybookResources, check_playbook_resources

    mock_provider = MagicMock()
    mock_provider.pool_policy = "pooled"
    mock_provider.ping_postgres = AsyncMock(return_value=True)
    mock_provider.session_factory = MagicMock()

    loaded = LoadedPlaybookResources(
        status="ready",
        mode="production",
        playbook_kb_service=MagicMock(),
        playbook_release_service=MagicMock(),
        active_release_id="krel-playbook-test01",
    )

    with (
        patch(
            "app.playbook.resources.peek_session_provider",
            return_value=mock_provider,
        ),
        patch(
            "app.core.embedding.factory.get_embedding_client",
        ) as mock_embed,
        patch(
            "app.playbook.resources.get_loaded_playbook_resources",
            return_value=loaded,
        ),
        patch(
            "app.playbook.resources.probe_playbook_resources",
            new_callable=AsyncMock,
            return_value=loaded,
        ),
    ):
        mock_embed.return_value = MagicMock()
        payload = await check_playbook_resources(Settings())

    assert payload["status"] == "ready"
    assert payload["active_release_id"] == "krel-playbook-test01"
    assert payload["fixture_fallback_enabled"] is False


@pytest.mark.asyncio
async def test_health_response_includes_playbook_resources(client: AsyncClient) -> None:
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
                "postgres": "ok",
                "session_pool": "pooled",
                "fixture_fallback_enabled": False,
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
    assert "playbook_resources" in body
    assert body["playbook_resources"]["status"] == "ready"
    assert body["playbook_resources"]["active_release_id"] == "krel-playbook-test01"


@pytest.mark.asyncio
async def test_health_playbook_required_flag_unavailable_returns_503(
    client: AsyncClient,
) -> None:
    """PLAYBOOK_REQUIRED (demo gate) hard-fails health only — not investigations."""
    settings = Settings(playbook_required=True)
    app.dependency_overrides[get_settings] = lambda: settings

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
                "status": "degraded",
                "mode": "production",
                "active_release_id": "",
                "postgres": "ok",
                "session_pool": "pooled",
                "fixture_fallback_enabled": False,
                "reasons": ["no_active_playbook_release"],
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

    app.dependency_overrides.clear()
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["playbook_resources"]["status"] == "degraded"


@pytest.mark.asyncio
async def test_health_playbook_required_unavailable_returns_503(client: AsyncClient) -> None:
    settings = Settings(playbook_release_require_active=True)
    app.dependency_overrides[get_settings] = lambda: settings

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
                "status": "unavailable",
                "mode": "production",
                "active_release_id": "",
                "postgres": "ok",
                "session_pool": "pooled",
                "fixture_fallback_enabled": False,
                "reasons": ["no_active_playbook_release"],
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

    app.dependency_overrides.clear()
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["playbook_resources"]["status"] == "unavailable"


@pytest.mark.asyncio
async def test_health_playbook_degraded_does_not_cause_503_in_development(
    client: AsyncClient,
) -> None:
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
                "status": "degraded",
                "mode": "production",
                "active_release_id": "",
                "postgres": "ok",
                "session_pool": "pooled",
                "fixture_fallback_enabled": False,
                "reasons": ["no_active_playbook_release"],
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
    assert body["playbook_resources"]["status"] == "degraded"
