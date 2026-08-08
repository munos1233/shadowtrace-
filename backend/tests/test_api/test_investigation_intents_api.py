"""Sync auto-investigate dispatch API tests (ISSUE-108 / #612)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from kombu.exceptions import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1.deps import reset_deps
from app.core.config import get_settings
from app.db import models as orm
from app.main import app
from app.models.enums import EventStatus, InvestigationIntentStatus, Severity
from tests.support.fake_redis import InMemoryFakeRedis, patch_redis_client

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
    }
)


@pytest.fixture(autouse=True)
def _api_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)
    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "true")
    monkeypatch.setenv("SOURCE_MODE", "mock_xdr")
    monkeypatch.setenv("LLM_MODE", "mock")
    get_settings.cache_clear()
    reset_deps()
    yield
    get_settings.cache_clear()
    reset_deps()


@pytest.fixture
def fake_redis_store(monkeypatch: pytest.MonkeyPatch) -> InMemoryFakeRedis:
    return patch_redis_client(monkeypatch)


def _hdr() -> dict[str, str]:
    return {"Authorization": "Bearer analyst-token"}


@pytest.mark.asyncio
async def test_dispatch_api_returns_202_when_broker_accepts(
    session_factory: async_sessionmaker[AsyncSession],
    fake_redis_store: InMemoryFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from uuid import uuid4

    intent_id = f"iin-api-{uuid4().hex[:8]}"
    event_id = f"evt-api-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                )
            )

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        lambda **_kwargs: MagicMock(id="task-api"),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/investigation-intents/dispatch",
            headers=_hdr(),
        )

    assert response.status_code == 202
    body = response.json()
    assert body["claimed"] >= 1
    assert body["published"] >= 1


@pytest.mark.asyncio
async def test_dispatch_api_returns_503_when_broker_rejects(
    session_factory: async_sessionmaker[AsyncSession],
    fake_redis_store: InMemoryFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from uuid import uuid4

    intent_id = f"iin-api-fail-{uuid4().hex[:8]}"
    event_id = f"evt-api-fail-{uuid4().hex[:8]}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type="malicious_process",
                    title="Suspicious process",
                    description="",
                    status=EventStatus.NEW.value,
                    severity=Severity.HIGH.value,
                    final_verdict="none",
                    creation_source_ref={"source_product": "mock_xdr"},
                    source_reference_snapshots=[],
                    disposition_policy="not_required",
                    raw_alert_ids=[],
                    source_type="mock_xdr",
                )
            )
            await session.flush()
            session.add(
                orm.InvestigationIntent(
                    intent_id=intent_id,
                    event_id=event_id,
                    intent_kind="auto_investigate",
                    intent_version="issue108_v1",
                    status=InvestigationIntentStatus.PENDING.value,
                    revision=1,
                    attempt=0,
                )
            )

    def _boom(**_kwargs: object) -> None:
        raise OperationalError("broker unavailable")

    monkeypatch.setattr(
        "app.tasks.investigation_tasks.run_investigation.apply_async",
        _boom,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/investigation-intents/dispatch",
            headers=_hdr(),
        )

    assert response.status_code == 503
    assert response.json()["error_code"] == "dependency_unavailable"


@pytest.mark.asyncio
async def test_dispatch_api_rejects_when_feature_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTO_INVESTIGATE_ENABLED", "false")
    get_settings.cache_clear()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/investigation-intents/dispatch",
            headers=_hdr(),
        )

    assert response.status_code == 422
    assert response.json()["error_code"] == "feature_disabled"
