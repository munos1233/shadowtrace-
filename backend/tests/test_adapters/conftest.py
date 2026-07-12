"""Fixtures for adapter contract tests (ISSUE-012)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport

from app.data_generators.scenarios import build_scenario
from app.mock_xdr.api import create_app
from app.mock_xdr.state import MockXDRState
from app.models.disposition import (
    DispositionCommand,
    SetEventDispositionParams,
    SourceObjectLocator,
)
from app.models.enums import (
    DispositionIntentKind,
    ExecutionOwner,
    SourceDisposition,
    SourceObjectKind,
)


@pytest.fixture
def mock_state() -> MockXDRState:
    state = MockXDRState()
    state.load_scenario(build_scenario("insider_data_exfiltration", seed=42))
    return state


@pytest.fixture
def mock_app(mock_state: MockXDRState):
    return create_app(state=mock_state)


@pytest_asyncio.fixture
async def mock_client(mock_app) -> AsyncIterator[httpx.AsyncClient]:
    transport = ASGITransport(app=mock_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://mock-xdr",
        timeout=30.0,
    ) as client:
        yield client


def event_disposition_command(
    *,
    object_id: str = "88442201",
    idempotency_key: str = "idem-adapter-1",
    token: str | None = None,
    disposition_id: str = "disp-adapter-1",
) -> DispositionCommand:
    return DispositionCommand(
        disposition_id=disposition_id,
        action_id="act-adapter-1",
        closure_cycle=1,
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-demo",
            connector_id="conn-disposition",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id=object_id,
        ),
        operation_code="set_event_disposition",
        operation_params=SetEventDispositionParams(target_disposition=SourceDisposition.CONTAINED),
        operator_id="analyst-1",
        idempotency_key=idempotency_key,
        source_concurrency_token=token,
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )
