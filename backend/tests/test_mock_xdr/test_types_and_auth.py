"""Mock XDR scenario consistency and type isolation (ISSUE-010 §验收1)."""

from __future__ import annotations

import pytest

from app.mock_xdr.models import MockXDRScenario
from app.mock_xdr.state import MockXDRState
from app.models.enums import SourceObjectKind
from tests.test_mock_xdr.conftest import make_ref


def test_scenario_rejects_missing_alert_ref(sample_scenario: MockXDRScenario) -> None:
    bad_incident = sample_scenario.incidents[0].model_copy(deep=True)
    orphan = make_ref(SourceObjectKind.ALERT, "MISSING-ALERT")
    bad_incident = bad_incident.model_copy(
        update={"related_alert_refs": list(bad_incident.related_alert_refs) + [orphan]}
    )
    payload = sample_scenario.model_dump(mode="python")
    payload["incidents"] = [bad_incident.model_dump(mode="python")]
    with pytest.raises(ValueError, match="missing alert"):
        MockXDRScenario.model_validate(payload)


def test_scenario_rejects_alert_pointing_to_missing_incident(
    sample_scenario: MockXDRScenario,
) -> None:
    alert = sample_scenario.alerts[0]
    bad_ref = make_ref(SourceObjectKind.INCIDENT, "NO-SUCH-INC")
    bad_alert = alert.model_copy(update={"incident_ref": bad_ref})
    payload = sample_scenario.model_dump(mode="python")
    payload["alerts"] = [bad_alert.model_dump(mode="python")]
    with pytest.raises(ValueError, match="missing incident"):
        MockXDRScenario.model_validate(payload)


def test_types_isolated_and_external_ids_preserved(state: MockXDRState, client) -> None:
    headers = {"Authorization": f"Bearer {state.read_token}"}
    incidents = client.get("/mock-xdr/v1/incidents", headers=headers).json()["items"]
    alerts = client.get("/mock-xdr/v1/alerts", headers=headers).json()["items"]
    assets = client.get("/mock-xdr/v1/assets", headers=headers).json()["items"]
    logs = client.get("/mock-xdr/v1/logs", headers=headers).json()["items"]

    assert {i["_mock"]["external_id"] for i in incidents} == {"INC-1"}
    assert {a["_mock"]["external_id"] for a in alerts} == {"ALERT-1"}
    assert {a["_mock"]["external_id"] for a in assets} == {"9001"}
    assert {log["_mock"]["external_id"] for log in logs} == {"LOG-1"}

    # Type isolation: each list only contains its kind
    assert all(i["reference"]["source_kind"] == "incident" for i in incidents)
    assert all(a["reference"]["source_kind"] == "alert" for a in alerts)
    assert all(a["reference"]["source_kind"] == "asset" for a in assets)
    assert all(log["reference"]["source_kind"] == "log" for log in logs)

    # Opaque external IDs returned as-is (numeric asset stays string "9001")
    assert assets[0]["reference"]["source_object_id"] == "9001"
    assert isinstance(assets[0]["reference"]["source_object_id"], str)


def test_read_and_write_clients_differ(state: MockXDRState, client) -> None:
    # Read token cannot write
    r = client.post(
        "/mock-xdr/v1/dispositions",
        headers={"Authorization": f"Bearer {state.read_token}"},
        json={"disposition_id": "x"},
    )
    assert r.status_code == 401
    # Write token can hit write route (validation may 422 but not 401)
    r2 = client.post(
        "/mock-xdr/v1/dispositions",
        headers={"Authorization": f"Bearer {state.write_token}"},
        json={"disposition_id": "x"},
    )
    assert r2.status_code != 401
