"""ID generation tests (ISSUE-002 acceptance 3)."""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from app.models.ids import (
    canonical_source_identity,
    new_action_id,
    new_event_id,
    new_report_id,
    report_id_for_event,
)

_EVENT_ID_RE = re.compile(r"^evt-\d{8}-[0-9a-f]{8}$")


def _identity(object_id: str = "INC-1", tenant: str = "t1") -> str:
    return canonical_source_identity(
        source_product="mock_xdr",
        source_tenant_id=tenant,
        connector_id="conn-1",
        source_kind="incident",
        source_object_id=object_id,
    )


def test_new_event_id_format() -> None:
    eid = new_event_id(_identity(), datetime(2026, 7, 12, tzinfo=UTC))
    assert _EVENT_ID_RE.match(eid), eid
    assert eid.startswith("evt-20260712-")


def test_new_event_id_is_idempotent_for_same_input() -> None:
    occurred = datetime(2026, 7, 12, 8, 30, tzinfo=UTC)
    assert new_event_id(_identity(), occurred) == new_event_id(_identity(), occurred)


def test_new_event_id_differs_for_different_identity() -> None:
    occurred = datetime(2026, 7, 12, tzinfo=UTC)
    assert new_event_id(_identity("INC-1"), occurred) != new_event_id(
        _identity("INC-2"), occurred
    )


def test_new_event_id_no_cross_tenant_collision() -> None:
    occurred = datetime(2026, 7, 12, tzinfo=UTC)
    assert new_event_id(_identity(tenant="t1"), occurred) != new_event_id(
        _identity(tenant="t2"), occurred
    )


def test_report_id_is_stable_derivation() -> None:
    eid = "evt-20260712-deadbeef"
    assert report_id_for_event(eid) == report_id_for_event(eid)
    assert report_id_for_event(eid).startswith("rpt-")
    assert new_report_id(eid) == report_id_for_event(eid)


def test_new_report_id_requires_event_id() -> None:
    with pytest.raises(TypeError):
        new_report_id()  # type: ignore[call-arg]


def test_random_ids_have_prefix_and_are_unique() -> None:
    a, b = new_action_id(), new_action_id()
    assert a.startswith("act-") and b.startswith("act-")
    assert a != b
