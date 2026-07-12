"""Shared fixtures for Mock XDR tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.mock_xdr.api import create_app
from app.mock_xdr.models import MockFailureProfile, MockXDRScenario
from app.mock_xdr.state import MockXDRState
from app.models.disposition import (
    DispositionCommand,
    SetEventDispositionParams,
    SourceObjectLocator,
    SubmitEntityActionParams,
    TargetDispositionResult,
)
from app.models.enums import (
    CapabilityState,
    ConnectorCapability,
    ConnectorStatus,
    DispositionIntentKind,
    DispositionPolicy,
    ExecutionOwner,
    SourceDisposition,
    SourceObjectKind,
    TargetExecutionStatus,
)
from app.models.source import (
    SourceAlert,
    SourceAsset,
    SourceConnector,
    SourceIncident,
    SourceLog,
    SourceReference,
)


@pytest.fixture
def base_time() -> datetime:
    return datetime(2024, 6, 1, 8, 0, 0, tzinfo=UTC)


def make_ref(
    kind: SourceObjectKind,
    object_id: str,
    *,
    tenant: str = "tenant-a",
    connector_id: str = "conn-1",
    parent: str | None = None,
    disposition: SourceDisposition = SourceDisposition.PENDING,
) -> SourceReference:
    return SourceReference(
        source_kind=kind,
        source_product="mock_xdr",
        source_tenant_id=tenant,
        connector_id=connector_id,
        source_object_id=object_id,
        parent_source_object_id=parent,
        source_disposition=disposition,
        schema_version="1",
    )


@pytest.fixture
def sample_scenario(base_time: datetime) -> MockXDRScenario:
    connector = SourceConnector(
        connector_id="conn-1",
        source_product="mock_xdr",
        display_name="Mock Conn",
        status=ConnectorStatus.ONLINE,
        capabilities={
            ConnectorCapability.QUERY: CapabilityState.SUPPORTED,
            ConnectorCapability.EVENT_DISPOSITION: CapabilityState.SUPPORTED,
            ConnectorCapability.ENTITY_RESPONSE: CapabilityState.SUPPORTED,
        },
        disposition_policy_default=DispositionPolicy.REQUIRED,
    )
    asset_ref = make_ref(SourceObjectKind.ASSET, "9001")
    asset = SourceAsset(reference=asset_ref, numeric_asset_id="9001", hostname="pc-1")
    log_ref = make_ref(SourceObjectKind.LOG, "LOG-1", parent="ALERT-1")
    log = SourceLog(reference=log_ref, category="endpoint")
    alert_ref = make_ref(SourceObjectKind.ALERT, "ALERT-1")
    alert = SourceAlert(reference=alert_ref, related_log_refs=[log_ref])
    incident_ref = make_ref(SourceObjectKind.INCIDENT, "INC-1")
    incident = SourceIncident(
        reference=incident_ref,
        title="sample",
        related_alert_refs=[alert_ref],
        impacted_asset_refs=[asset_ref],
    )
    alert = alert.model_copy(update={"incident_ref": incident_ref})
    return MockXDRScenario(
        scenario_id="sample",
        name="sample",
        base_time=base_time,
        source_tenant_id="tenant-a",
        incidents=[incident],
        alerts=[alert],
        assets=[asset],
        logs=[log],
        connectors=[connector],
        failure_profile=MockFailureProfile(seed=7, control_plane_enabled=True),
        expected_outcome={"disposition_policy": "required"},
    )


@pytest.fixture
def state(sample_scenario: MockXDRScenario) -> MockXDRState:
    st = MockXDRState()
    st.load_scenario(sample_scenario)
    return st


@pytest.fixture
def client(state: MockXDRState) -> TestClient:
    app = create_app(state=state)
    return TestClient(app)


def disposition_command(
    *,
    disposition_id: str = "disp-1",
    action_id: str = "act-1",
    closure_cycle: int = 1,
    object_id: str = "INC-1",
    target: SourceDisposition = SourceDisposition.CONTAINED,
    idempotency_key: str = "idem-1",
    token: str | None = None,
    supersedes: str | None = None,
    intent: DispositionIntentKind = DispositionIntentKind.EVENT_STATUS_UPDATE,
) -> DispositionCommand:
    if intent is DispositionIntentKind.EVENT_STATUS_UPDATE:
        params: SetEventDispositionParams | SubmitEntityActionParams = SetEventDispositionParams(
            target_disposition=target
        )
        op = "set_event_disposition"
        owner = ExecutionOwner.XDR_MANAGED
        targets: list[TargetDispositionResult] = []
    else:
        params = SubmitEntityActionParams(
            entity_action_code="isolate_host",
            canonical_target="host:pc-1",
        )
        op = "submit_entity_action"
        owner = ExecutionOwner.XDR_MANAGED
        targets = [
            TargetDispositionResult(
                canonical_target="host:pc-1",
                status=TargetExecutionStatus.SUCCESS,
            )
        ]
    return DispositionCommand(
        disposition_id=disposition_id,
        action_id=action_id,
        closure_cycle=closure_cycle,
        intent_kind=intent,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-a",
            connector_id="conn-1",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id=object_id,
        ),
        operation_code=op,
        operation_params=params,
        target_results=targets,
        operator_id="analyst-1",
        idempotency_key=idempotency_key,
        source_concurrency_token=token,
        execution_owner=owner,
        supersedes_disposition_id=supersedes,
    )
