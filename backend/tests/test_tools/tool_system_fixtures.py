"""ISSUE-025 tool-system fixtures (mock cleanup + deterministic mode).

Loaded once via ``tests/conftest.py`` ``pytest_plugins`` so both
``tests/test_tools/`` and ``tests/integration/test_tool_system.py`` share
fixtures without double-registering a package ``conftest``.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from app.models.enums import ExecutionOwner
from app.providers.tools.mock_provider import (
    MockToolProvider,
    MockToolProviderConfig,
    bind_mock_tool_provider,
)
from app.services.evidence_projection import (
    EvidenceProjection,
    EvidenceQueryScope,
)
from app.tools.circuit_breaker import CircuitBreakerRegistry
from app.tools.executor import InMemoryExecutionJobStore, ToolExecutor
from app.tools.mock_state import MockEnvironmentState
from app.tools.query.fixture_loader import load_fixture_records
from app.tools.registry import ToolRegistry
from app.tools.retry import RetryPolicy
from app.tools.verify._common import (
    MockVerificationRuntime,
    bind_mock_verification_runtime,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
MOCK_DATA = REPO_ROOT / "data" / "mock"

WINDOW = {
    "start": "2024-06-15T08:00:00Z",
    "end": "2024-06-15T10:00:00Z",
}

DEFAULT_SCOPE = EvidenceQueryScope(
    source_tenant_id="test-tenant",
    connector_ids=frozenset({"fixture-evidence"}),
)

# Seven fixture-backed query tools used by the concurrent gather chain.
CONCURRENT_QUERY_CALLS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("query_account_login", {"account": "zhangsan", "time_range": WINDOW}),
    ("query_edr_process", {"host_id": "PC-FIN-023", "time_range": WINDOW}),
    ("query_file_access", {"account": "zhangsan", "time_range": WINDOW}),
    ("query_network_flow", {"src_ip": "10.20.30.23", "time_range": WINDOW}),
    ("query_dns", {"domain": "unknown-upload-example.com", "time_range": WINDOW}),
    ("query_asset_info", {"ip": "10.20.30.23"}),
    ("query_threat_intel", {"indicator": "203.0.113.88"}),
)


def new_sfx() -> str:
    return uuid.uuid4().hex[:8]


class RecordingAuditService:
    """In-memory audit sink compatible with ToolExecutor."""

    def __init__(self) -> None:
        self.starts = 0
        self.finishes = 0
        self.rows: dict[str, dict[str, Any]] = {}

    async def log_start(
        self,
        call_id: str,
        event_id: str,
        action_id: str | None,
        tool_name: str,
        tool_category: str,
        parameters: dict[str, Any] | None,
    ) -> str:
        self.starts += 1
        self.rows[call_id] = {
            "event_id": event_id,
            "action_id": action_id,
            "tool_name": tool_name,
            "tool_category": tool_category,
            "parameters": parameters or {},
        }
        return call_id

    async def log_finish(
        self,
        call_id: str,
        status: str,
        result: dict[str, Any] | None,
        error_detail: str | None,
        retry_count: int,
    ) -> None:
        self.finishes += 1
        row = self.rows.setdefault(call_id, {})
        row.update(
            {
                "status": status,
                "result": result or {},
                "error_detail": error_detail,
                "retry_count": retry_count,
            }
        )

    def rows_for_event(self, event_id: str) -> list[dict[str, Any]]:
        return [row for row in self.rows.values() if row.get("event_id") == event_id]


class _EventScopeService:
    def __init__(self, scope: EvidenceQueryScope) -> None:
        self.scope = scope

    async def get_evidence_query_scope(self, event_id: str) -> EvidenceQueryScope:
        return self.scope


@pytest_asyncio.fixture
async def mock_state() -> AsyncIterator[MockEnvironmentState]:
    """Fresh in-memory mock environment; cleared before and after each test."""
    state = MockEnvironmentState.in_memory()
    await state.clear_all()
    yield state
    await state.clear_all()


@pytest_asyncio.fixture
async def evidence_projection() -> EvidenceProjection:
    """ISSUE-011 fixture data loaded into an in-memory evidence projection."""
    projection = EvidenceProjection.in_memory()
    loaded = await load_fixture_records(projection, MOCK_DATA)
    assert loaded > 0
    return projection


@pytest.fixture
def evidence_scope() -> EvidenceQueryScope:
    return DEFAULT_SCOPE


@pytest.fixture
def event_scope_service(evidence_scope: EvidenceQueryScope) -> _EventScopeService:
    return _EventScopeService(evidence_scope)


@pytest.fixture
def tool_registry() -> ToolRegistry:
    """Isolated registry with baseline tools (no process-global singleton)."""
    registry = ToolRegistry()
    registry.auto_discover()
    return registry


@pytest.fixture
def mock_provider(mock_state: MockEnvironmentState) -> MockToolProvider:
    return MockToolProvider(
        mock_state,
        config=MockToolProviderConfig(observation_delay_ms=0),
    )


@pytest.fixture
def verification_runtime(mock_state: MockEnvironmentState) -> MockVerificationRuntime:
    return MockVerificationRuntime(
        mock_state,
        wait_timeout_ms=100,
        poll_interval_ms=5,
    )


@pytest.fixture
def audit() -> RecordingAuditService:
    return RecordingAuditService()


@pytest.fixture
def job_store() -> InMemoryExecutionJobStore:
    return InMemoryExecutionJobStore()


@pytest.fixture
def deterministic_breaker() -> CircuitBreakerRegistry:
    """Circuit breaker with injectable clock for deterministic recovery tests."""
    clock = {"now": 0.0}

    def monotonic() -> float:
        return clock["now"]

    registry = CircuitBreakerRegistry(
        failure_threshold=5,
        recovery_timeout_s=60.0,
        clock=monotonic,
    )
    # Expose clock for tests that need to advance time.
    registry.clock_state = clock  # type: ignore[attr-defined]
    return registry


@pytest.fixture
def tool_executor(
    tool_registry: ToolRegistry,
    mock_provider: MockToolProvider,
    audit: RecordingAuditService,
    job_store: InMemoryExecutionJobStore,
    verification_runtime: MockVerificationRuntime,
) -> Iterator[ToolExecutor]:
    """Deterministic executor: mock provider bound, zero observation delay, no real sleep."""
    mock_provider.register_bindings(tool_registry)

    async def instant_sleep(_delay: float) -> None:
        return None

    executor = ToolExecutor(
        registry=tool_registry,
        audit_service=audit,
        job_store=job_store,
        sleep=instant_sleep,
        provider_context=lambda: bind_mock_tool_provider(mock_provider),
    )
    with bind_mock_verification_runtime(verification_runtime):
        yield executor


@pytest.fixture
def default_retry() -> RetryPolicy:
    return RetryPolicy(max_retries=3)


__all__ = [
    "CONCURRENT_QUERY_CALLS",
    "DEFAULT_SCOPE",
    "MOCK_DATA",
    "WINDOW",
    "ExecutionOwner",
    "RecordingAuditService",
    "new_sfx",
]
