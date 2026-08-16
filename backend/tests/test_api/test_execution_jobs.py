"""Execution job API + query service tests (ISSUE-271)."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.auth import Principal
from app.core.config import Settings
from app.core.errors import DependencyUnavailableError, ResourceNotFoundError
from app.db import models as orm
from app.main import app
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    EventType,
    ExecutionJobStatus,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.source import SourceReference
from app.services.execution_job_query_service import (
    DEMO_FIXTURE_TENANT_ID,
    ExecutionJobQueryService,
    project_execution_job_response,
)

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://shadowtrace:shadowtrace@localhost:5432/shadowtrace",
)

_DEV_TOKENS = json.dumps(
    {
        "analyst-token": {
            "subject": "analyst-1",
            "roles": ["analyst"],
            "tenant_id": "tenant-a",
        },
        "approver-token": {"subject": "approver-1", "roles": ["approver"]},
        "operator-token": {"subject": "op-1", "roles": ["disposition_operator"]},
        "admin-token": {"subject": "admin-1", "roles": ["admin"]},
        "norole-token": {"subject": "norole-1", "roles": []},
    }
)


def _sfx() -> str:
    return uuid.uuid4().hex[:8]


def _hdr(role: str = "analyst") -> dict[str, str]:
    return {"Authorization": f"Bearer {role}-token"}


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


@pytest.fixture(scope="session")
def migrated_database() -> None:
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
    migrated_database: None,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def clean_state(session_factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[None]:
    from sqlalchemy import text

    from app.db.base import Base

    quoted = ", ".join(f'"{table}"' for table in sorted(Base.metadata.tables))
    async with session_factory() as session:
        async with session.begin():
            await session.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))
    yield
    async with session_factory() as session:
        async with session.begin():
            await session.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))


def _source_ref(*, tenant_id: str = "tenant-a") -> dict[str, Any]:
    return SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id=tenant_id,
        connector_id="conn-mock-1",
        source_object_type="incident",
        source_object_id=f"INC-{_sfx()}",
        source_status_raw="open",
        schema_version="1",
    ).model_dump(mode="json")


async def _seed_execution_job(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: str = "tenant-a",
    with_targets: bool = True,
    raw_result: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    event_id = f"evt-{_sfx()}"
    action_id = f"act-{_sfx()}"
    job_id = f"job-{_sfx()}"
    async with session_factory() as session:
        async with session.begin():
            session.add(
                orm.SecurityEvent(
                    event_id=event_id,
                    event_type=EventType.MALICIOUS_PROCESS.value,
                    title="execution job test",
                    status="executing",
                    severity=Severity.HIGH.value,
                    final_verdict=FinalVerdict.NONE.value,
                    creation_source_ref=_source_ref(tenant_id=tenant_id),
                    source_reference_snapshots=[_source_ref(tenant_id=tenant_id)],
                )
            )
            await session.flush()
            session.add(
                orm.Action(
                    action_id=action_id,
                    event_id=event_id,
                    plan_revision=1,
                    action_fingerprint=f"fp-{action_id}",
                    action_category=ActionCategory.RESPONSE.value,
                    action_name="block ip",
                    tool_name="block_ip",
                    action_level=ActionLevel.L2.value,
                    execution_owner=ExecutionOwner.DIRECT_TOOL.value,
                    execution_phase=ActionExecutionPhase.IMMEDIATE.value,
                    status=ActionStatus.SUCCESS.value,
                    target_type="ip",
                    target="203.0.113.9",
                    parameters={"target_type": "ip", "target": "203.0.113.9"},
                    writeback_required=False,
                    writeback_applicable=False,
                    writeback_readiness=WritebackReadiness.NOT_REQUIRED.value,
                    execution_job_id=job_id,
                    idempotency_key=f"idem-{action_id}",
                )
            )
            await session.flush()
            session.add(
                orm.ActionExecutionJob(
                    job_id=job_id,
                    event_id=event_id,
                    action_id=action_id,
                    provider_name="mock_tool_provider",
                    idempotency_key=f"idem-{job_id}",
                    status=ExecutionJobStatus.PARTIAL_SUCCESS.value,
                    attempt=2,
                    raw_result=raw_result
                    or {
                        "outcome": "partial_success",
                        "provider_secret": "must-not-leak",
                    },
                )
            )
            await session.flush()
            if with_targets:
                session.add(
                    orm.ActionTargetResult(
                        job_id=job_id,
                        attempt=2,
                        canonical_target="ip:203.0.113.9",
                        status="success",
                        code="applied",
                        message="applied",
                        raw_result={"provider_payload": "secret"},
                    )
                )
                session.add(
                    orm.ActionTargetResult(
                        job_id=job_id,
                        attempt=2,
                        canonical_target="ip:203.0.113.10",
                        status="failed",
                        code="permission_denied",
                        message="permission_denied",
                        raw_result={"token": "secret"},
                    )
                )
    return event_id, action_id, job_id


@pytest.fixture(autouse=True)
def _dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_TOKENS)


def test_project_execution_job_response_redacts_raw_provider_fields() -> None:
    job_row = orm.ActionExecutionJob(
        job_id="job-test",
        event_id="evt-test",
        action_id="act-test",
        provider_name="mock_tool_provider",
        idempotency_key="idem-test",
        status=ExecutionJobStatus.SUCCESS.value,
        attempt=1,
        raw_result={"provider_secret": "must-not-leak"},
    )
    target_rows = [
        orm.ActionTargetResult(
            job_id="job-test",
            canonical_target="ip:203.0.113.9",
            status="success",
            code="applied",
            message="applied",
            raw_result={"nested_secret": "value"},
        )
    ]
    response = project_execution_job_response(job_row, target_rows)
    assert response.status == "success"
    assert len(response.target_results) == 1
    assert "raw_result" not in response.target_results[0]
    assert "nested_secret" not in json.dumps(response.model_dump(mode="json"))


@pytest.mark.asyncio
@pytest.mark.integration
async def test_query_service_returns_real_job(
    session_factory: async_sessionmaker[AsyncSession],
    clean_state: None,
) -> None:
    _event_id, _action_id, job_id = await _seed_execution_job(session_factory)
    service = ExecutionJobQueryService(session_factory, fixture_enabled=False)
    principal = Principal(subject="analyst-1", roles=["analyst"], tenant_id="tenant-a")

    response = await service.get_execution_job(job_id, principal=principal)

    assert response.job_id == job_id
    assert response.status == "partial_success"
    assert response.attempt == 2
    statuses = {item["status"] for item in response.target_results}
    assert statuses == {"success", "failed"}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_query_service_unknown_job_is_stable_not_found(
    session_factory: async_sessionmaker[AsyncSession],
    clean_state: None,
) -> None:
    service = ExecutionJobQueryService(session_factory, fixture_enabled=False)
    principal = Principal(subject="analyst-1", roles=["analyst"], tenant_id="tenant-a")

    with pytest.raises(ResourceNotFoundError, match="not found"):
        await service.get_execution_job("job-missing", principal=principal)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_query_service_tenant_mismatch_is_not_found(
    session_factory: async_sessionmaker[AsyncSession],
    clean_state: None,
) -> None:
    _event_id, _action_id, job_id = await _seed_execution_job(session_factory, tenant_id="tenant-a")
    service = ExecutionJobQueryService(session_factory, fixture_enabled=False)
    principal = Principal(subject="analyst-1", roles=["analyst"], tenant_id="tenant-b")

    with pytest.raises(ResourceNotFoundError):
        await service.get_execution_job(job_id, principal=principal)


class _BrokenSession:
    """Session stub that fails on first ORM get after read-only begin."""

    def begin(self) -> _BrokenSession:
        return self

    async def execute(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def get(self, *_args: Any, **_kwargs: Any) -> None:
        from sqlalchemy.exc import OperationalError

        raise OperationalError("SELECT 1", {}, Exception("db down"))

    async def __aenter__(self) -> _BrokenSession:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None


class _BrokenFactory:
    def __call__(self) -> _BrokenSession:
        return _BrokenSession()


@pytest.mark.asyncio
async def test_query_service_db_error_does_not_fallback_to_fixture() -> None:
    service = ExecutionJobQueryService(_BrokenFactory(), fixture_enabled=True)  # type: ignore[arg-type]
    principal = Principal(
        subject="analyst-1",
        roles=["analyst"],
        tenant_id=DEMO_FIXTURE_TENANT_ID,
    )

    with pytest.raises(DependencyUnavailableError, match="execution job store unavailable"):
        await service.get_execution_job("job-0a1b2c3d", principal=principal)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_fixture_only_when_explicitly_enabled(
    session_factory: async_sessionmaker[AsyncSession],
    clean_state: None,
) -> None:
    disabled = ExecutionJobQueryService(session_factory, fixture_enabled=False)
    enabled = ExecutionJobQueryService(session_factory, fixture_enabled=True)
    principal = Principal(
        subject="analyst-1",
        roles=["analyst"],
        tenant_id=DEMO_FIXTURE_TENANT_ID,
    )

    with pytest.raises(ResourceNotFoundError):
        await disabled.get_execution_job("job-0a1b2c3d", principal=principal)

    fixture = await enabled.get_execution_job("job-0a1b2c3d", principal=principal)
    assert fixture.status == "partial_success"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_fixture_requires_tenant_scope(
    session_factory: async_sessionmaker[AsyncSession],
    clean_state: None,
) -> None:
    enabled = ExecutionJobQueryService(session_factory, fixture_enabled=True)
    principal = Principal(subject="analyst-1", roles=["analyst"], tenant_id="other-tenant")

    with pytest.raises(ResourceNotFoundError):
        await enabled.get_execution_job("job-0a1b2c3d", principal=principal)


def test_production_rejects_execution_job_fixture_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("EXECUTION_JOB_FIXTURE_ENABLED", "true")
    with pytest.raises(Exception, match="execution_job_fixture_enabled=true"):
        Settings()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_api_returns_real_execution_job(
    session_factory: async_sessionmaker[AsyncSession],
    clean_state: None,
) -> None:
    from app.api.v1.deps import get_execution_job_query_service as _real_get_execution_job_query

    service = ExecutionJobQueryService(session_factory, fixture_enabled=False)

    async def _service() -> ExecutionJobQueryService:
        return service

    app.dependency_overrides[_real_get_execution_job_query] = _service
    try:
        _event_id, _action_id, job_id = await _seed_execution_job(session_factory)
        client = TestClient(app)
        resp = client.get(f"/api/v1/execution-jobs/{job_id}", headers=_hdr("analyst"))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["job_id"] == job_id
        assert body["status"] == "partial_success"
        assert "raw_result" not in body
        assert "provider_secret" not in resp.text
    finally:
        app.dependency_overrides.pop(_real_get_execution_job_query, None)


def test_api_zero_role_is_forbidden() -> None:
    from app.api.v1.deps import get_execution_job_query_service as _real_get_execution_job_query
    from tests.test_api.test_contracts import _MockExecutionJobQueryService

    async def _mock_query() -> _MockExecutionJobQueryService:
        return _MockExecutionJobQueryService()

    app.dependency_overrides[_real_get_execution_job_query] = _mock_query
    try:
        client = TestClient(app)
        resp = client.get("/api/v1/execution-jobs/job-0a1b2c3d", headers=_hdr("norole"))
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "forbidden"
    finally:
        app.dependency_overrides.pop(_real_get_execution_job_query, None)


def test_api_db_error_returns_503_not_fixture() -> None:
    from app.api.v1.deps import get_execution_job_query_service as _real_get_execution_job_query

    class _FailingQuery:
        async def get_execution_job(self, job_id: str, *, principal: Principal) -> Any:
            raise DependencyUnavailableError(
                "execution job store unavailable",
                details={"job_id": job_id, "dependency": "postgresql"},
            )

    async def _failing() -> _FailingQuery:
        return _FailingQuery()

    app.dependency_overrides[_real_get_execution_job_query] = _failing
    try:
        client = TestClient(app)
        resp = client.get("/api/v1/execution-jobs/job-0a1b2c3d", headers=_hdr("analyst"))
        assert resp.status_code == 503
        body = resp.json()
        assert body["error_code"] == "dependency_unavailable"
        assert "provider_secret" not in resp.text
    finally:
        app.dependency_overrides.pop(_real_get_execution_job_query, None)


@pytest.mark.asyncio
async def test_binding_allows_unset_execution_job_pointer() -> None:
    """action/event match is authoritative; unset execution_job_id is a write race."""
    from datetime import UTC, datetime

    event_id = "evt-bind-unset"
    action_id = "act-bind-unset"
    job_id = "job-bind-unset"
    job = orm.ActionExecutionJob(
        job_id=job_id,
        event_id=event_id,
        action_id=action_id,
        provider_name="mock_tool_provider",
        idempotency_key=f"idem-{job_id}",
        status=ExecutionJobStatus.SUCCESS.value,
        attempt=1,
        raw_result={},
    )
    action = orm.Action(
        action_id=action_id,
        event_id=event_id,
        plan_revision=1,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE.value,
        action_name="block ip",
        tool_name="block_ip",
        action_level=ActionLevel.L2.value,
        execution_owner=ExecutionOwner.DIRECT_TOOL.value,
        execution_phase=ActionExecutionPhase.IMMEDIATE.value,
        status=ActionStatus.SUCCESS.value,
        target_type="ip",
        target="203.0.113.9",
        parameters={},
        writeback_required=False,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.READY.value,
        execution_job_id=None,
        idempotency_key=f"idem-{action_id}",
    )
    event = orm.SecurityEvent(
        event_id=event_id,
        event_type=EventType.MALICIOUS_PROCESS.value,
        title="bind",
        status="executing",
        severity=Severity.HIGH.value,
        final_verdict=FinalVerdict.NONE.value,
        creation_source_ref=_source_ref(tenant_id="tenant-a"),
        source_reference_snapshots=[_source_ref(tenant_id="tenant-a")],
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    class _Session:
        def begin(self) -> _Session:
            return self

        async def execute(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        async def get(self, model: Any, key: Any) -> Any:
            if model is orm.ActionExecutionJob and key == job_id:
                return job
            if model is orm.Action and key == action_id:
                return action
            if model is orm.SecurityEvent and key == event_id:
                return event
            return None

        async def scalars(self, *_args: Any, **_kwargs: Any) -> Any:
            class _Result:
                def __iter__(self) -> Any:
                    return iter(())

            return _Result()

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class _Factory:
        def __call__(self) -> _Session:
            return _Session()

    service = ExecutionJobQueryService(_Factory(), fixture_enabled=False)  # type: ignore[arg-type]
    principal = Principal(subject="analyst-1", roles=["analyst"], tenant_id="tenant-a")
    response = await service.get_execution_job(job_id, principal=principal)
    assert response.job_id == job_id
    assert response.event_id == event_id


@pytest.mark.asyncio
async def test_binding_rejects_conflicting_execution_job_pointer() -> None:
    event_id = "evt-bind-conflict"
    action_id = "act-bind-conflict"
    job_id = "job-bind-conflict"
    job = orm.ActionExecutionJob(
        job_id=job_id,
        event_id=event_id,
        action_id=action_id,
        provider_name="mock_tool_provider",
        idempotency_key=f"idem-{job_id}",
        status=ExecutionJobStatus.SUCCESS.value,
        attempt=1,
        raw_result={},
    )
    action = orm.Action(
        action_id=action_id,
        event_id=event_id,
        plan_revision=1,
        action_fingerprint=f"fp-{action_id}",
        action_category=ActionCategory.RESPONSE.value,
        action_name="block ip",
        tool_name="block_ip",
        action_level=ActionLevel.L2.value,
        execution_owner=ExecutionOwner.DIRECT_TOOL.value,
        execution_phase=ActionExecutionPhase.IMMEDIATE.value,
        status=ActionStatus.SUCCESS.value,
        target_type="ip",
        target="203.0.113.9",
        parameters={},
        writeback_required=False,
        writeback_applicable=False,
        writeback_readiness=WritebackReadiness.READY.value,
        execution_job_id="job-other",
        idempotency_key=f"idem-{action_id}",
    )

    class _Session:
        def begin(self) -> _Session:
            return self

        async def execute(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        async def get(self, model: Any, key: Any) -> Any:
            if model is orm.ActionExecutionJob and key == job_id:
                return job
            if model is orm.Action and key == action_id:
                return action
            return None

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class _Factory:
        def __call__(self) -> _Session:
            return _Session()

    service = ExecutionJobQueryService(_Factory(), fixture_enabled=False)  # type: ignore[arg-type]
    principal = Principal(subject="analyst-1", roles=["analyst"], tenant_id="tenant-a")
    with pytest.raises(ResourceNotFoundError):
        await service.get_execution_job(job_id, principal=principal)


def test_project_sanitizes_unsafe_target_code_and_message() -> None:
    job_row = orm.ActionExecutionJob(
        job_id="job-safe",
        event_id="evt-safe",
        action_id="act-safe",
        provider_name="mock_tool_provider",
        idempotency_key="idem-safe",
        status=ExecutionJobStatus.SUCCESS.value,
        attempt=1,
        raw_result={},
    )
    target_rows = [
        orm.ActionTargetResult(
            job_id="job-safe",
            canonical_target="ip:203.0.113.9",
            status="failed",
            code="api_key=sk-abcdefghijklmnopqrstuvwxyz",
            message="Bearer sk-abcdefghijklmnopqrstuvwxyz012345",
            raw_result={},
        )
    ]
    response = project_execution_job_response(job_row, target_rows)
    blob = json.dumps(response.model_dump(mode="json"))
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in blob
    assert response.target_results[0]["code"] == "message_truncated"
    assert response.target_results[0]["message"] == "message_truncated"
