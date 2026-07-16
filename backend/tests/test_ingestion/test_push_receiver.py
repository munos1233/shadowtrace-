"""Push delivery/object idempotency and partial acceptance tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import models as orm
from app.ingestion.push_receiver import PushBatchEnvelope, PushReceiver
from app.ingestion.source_ingester import SourceIngester
from app.models.enums import ConnectorStatus, SourceObjectKind
from app.models.source import SourceIncident, SourceReference
from app.services.event_service import EventService


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


def _incident_payload(connector_id: str, object_id: str) -> dict:
    incident = SourceIncident(
        reference=SourceReference(
            source_kind=SourceObjectKind.INCIDENT,
            source_product="mock_xdr",
            source_tenant_id="tenant-push",
            connector_id=connector_id,
            source_object_id=object_id,
            source_updated_at=datetime.now(UTC),
            schema_version="1",
        ),
        title="push incident",
    )
    return incident.model_dump(mode="json")


@pytest.mark.asyncio
async def test_push_partial_acceptance_delivery_and_object_idempotency(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-push-{suffix}"
    ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="mock_xdr",
    )
    receiver = PushReceiver(ingester, event_service, session_factory)
    valid = _incident_payload(connector_id, f"INC-{suffix}")
    envelope = PushBatchEnvelope(
        connector_id=connector_id,
        delivery_id=f"delivery-{suffix}-1",
        source_product="mock_xdr",
        objects=[
            {"source_kind": "incident", "payload": valid},
            {
                "source_kind": "incident",
                "payload": {
                    "reference": {
                        **valid["reference"],
                        "connector_id": "different-connector",
                    }
                },
            },
        ],
    )

    first = await receiver.receive(envelope)
    assert first.accepted == 1
    assert first.duplicate == 0
    assert first.rejected == 1
    assert first.degraded is True

    same_delivery = await receiver.receive(envelope)
    assert same_delivery.accepted == 0
    assert same_delivery.duplicate == 2
    assert same_delivery.rejected == 0

    new_delivery = envelope.model_copy(
        update={
            "delivery_id": f"delivery-{suffix}-2",
            "objects": [{"source_kind": "incident", "payload": valid}],
        }
    )
    object_replay = await receiver.receive(new_delivery)
    assert object_replay.accepted == 0
    assert object_replay.duplicate == 1
    assert object_replay.rejected == 0

    async with session_factory() as session:
        connector = await session.get(orm.SourceConnector, connector_id)
        assert connector is not None
        assert connector.connector_metadata["ingestion_adapter"] == "mock_xdr"
        deliveries = connector.connector_metadata["processed_delivery_ids"]
        assert f"delivery-{suffix}-1" in deliveries
        assert f"delivery-{suffix}-2" in deliveries
        quality = (
            await session.scalars(
                select(orm.DataQualityError).where(
                    orm.DataQualityError.stage == "push_validation",
                    orm.DataQualityError.detail["connector_id"].as_string() == connector_id,
                )
            )
        ).all()
        assert len(quality) == 1


@pytest.mark.asyncio
async def test_push_rejects_schema_incompatible_object_but_marks_delivery(
    event_service: EventService,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    suffix = _suffix()
    connector_id = f"conn-push-schema-{suffix}"
    ingester = SourceIngester(
        event_service,
        session_factory,
        source_mode="mock_xdr",
    )
    receiver = PushReceiver(ingester, event_service, session_factory)
    payload = _incident_payload(connector_id, f"INC-{suffix}")
    payload["reference"]["schema_version"] = "99"
    envelope = PushBatchEnvelope(
        connector_id=connector_id,
        delivery_id=f"delivery-schema-{suffix}",
        source_product="mock_xdr",
        objects=[{"source_kind": "incident", "payload": payload}],
    )

    result = await receiver.receive(envelope)
    assert result.accepted == 0
    assert result.rejected == 1
    assert result.errors[0]["detail"]["reason"] == "schema_unsupported"
    async with session_factory() as session:
        connector = await session.get(orm.SourceConnector, connector_id)
        assert connector is not None
        assert connector.status == ConnectorStatus.ONLINE.value

    replay = await receiver.receive(envelope)
    assert replay.duplicate == 1
