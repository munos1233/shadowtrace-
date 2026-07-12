"""Pagination, cursor idempotency, updated_after (ISSUE-010 §验收2)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.mock_xdr.models import MockFailureProfile, MockXDRScenario
from app.mock_xdr.state import MockXDRState
from app.models.enums import (
    CapabilityState,
    ConnectorCapability,
    ConnectorStatus,
    DispositionPolicy,
    SourceDisposition,
    SourceObjectKind,
)
from app.models.source import SourceConnector, SourceIncident
from tests.test_mock_xdr.conftest import make_ref


def _bulk_incident_scenario(n: int = 1000) -> MockXDRScenario:
    base = datetime(2024, 1, 1, tzinfo=UTC)
    connector = SourceConnector(
        connector_id="conn-bulk",
        source_product="mock_xdr",
        display_name="bulk",
        status=ConnectorStatus.ONLINE,
        capabilities={ConnectorCapability.QUERY: CapabilityState.SUPPORTED},
        disposition_policy_default=DispositionPolicy.NOT_REQUIRED,
    )
    incidents: list[SourceIncident] = []
    for i in range(n):
        oid = f"INC-{i:04d}"
        ref = make_ref(
            SourceObjectKind.INCIDENT,
            oid,
            connector_id="conn-bulk",
            disposition=SourceDisposition.PENDING,
        )
        incidents.append(SourceIncident(reference=ref, title=f"t-{i}"))
    return MockXDRScenario(
        scenario_id="bulk",
        name="bulk",
        base_time=base,
        source_tenant_id="tenant-a",
        incidents=incidents,
        connectors=[connector],
        failure_profile=MockFailureProfile(seed=99),
    )


def test_paginate_1000_no_loss_no_dup() -> None:
    st = MockXDRState()
    st.load_scenario(_bulk_incident_scenario(1000))
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        page = st.list_page("incident", page_size=100, cursor=cursor)
        ids = [item["_mock"]["external_id"] for item in page["items"]]
        seen.extend(ids)
        pages += 1
        # Idempotent retry of same cursor
        again = st.list_page("incident", page_size=100, cursor=page["cursor"])
        assert [i["_mock"]["external_id"] for i in again["items"]] == ids
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert pages == 10
    assert len(seen) == 1000
    assert len(set(seen)) == 1000


def test_updated_after_discovers_mutations(state: MockXDRState) -> None:
    before = state.clock
    # Mutate after advancing clock
    state.advance_clock(10)
    body = dict(state.objects[("incident", "INC-1")].body)
    body["title"] = "updated-title"
    state.upsert_object("incident", "INC-1", body)

    page_all = state.list_page("incident", page_size=10)
    assert any(i["_mock"]["external_id"] == "INC-1" for i in page_all["items"])

    page_delta = state.list_page("incident", page_size=10, updated_after=before)
    ids = [i["_mock"]["external_id"] for i in page_delta["items"]]
    assert ids == ["INC-1"]
    assert page_delta["items"][0]["title"] == "updated-title"


def test_watermark_only_advances_on_commit(state: MockXDRState) -> None:
    page = state.list_page("incident", page_size=10, commit_watermark=False)
    assert state.watermarks.get("incident") is None
    state.list_page("incident", page_size=10, cursor=page["cursor"], commit_watermark=True)
    assert state.watermarks.get("incident") == page["cursor"]
