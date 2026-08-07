"""Shared helpers for adversarial audit tests."""

from __future__ import annotations

from app.ingestion.source_ingester import SourceIngester
from app.models.enums import EventStatus, SourceObjectKind
from app.services.event_service import EventService
from tests.adversarial.scenario_credential_db_staging_exfil import GROUND_TRUTH, INCIDENT_ID

ALL_SOURCE_KINDS = [
    SourceObjectKind.INCIDENT,
    SourceObjectKind.ALERT,
    SourceObjectKind.ASSET,
    SourceObjectKind.LOG,
]


def _source_object_id(ref) -> str:
    if ref is None:
        return ""
    if hasattr(ref, "source_object_id"):
        return str(ref.source_object_id or "")
    if hasattr(ref, "model_dump"):
        return str(ref.model_dump(mode="json").get("source_object_id") or "")
    if isinstance(ref, dict):
        return str(ref.get("source_object_id") or "")
    return ""


async def ingest_true_positive_event(
    source_adapter,
    source_ingester: SourceIngester,
    event_service: EventService,
    *,
    batch_size: int = 50,
) -> str:
    """Poll the noisy adversarial scenario and return the true-positive event_id."""
    summary = await source_ingester.poll(source_adapter, ALL_SOURCE_KINDS, batch_size=batch_size)
    if summary.rejected:
        raise AssertionError(f"adversarial ingest rejected rows: {summary.errors}")

    listed = await event_service.list_events(status=EventStatus.NEW)
    if listed.total < 1:
        raise AssertionError("expected at least one NEW event from adversarial poll")

    true_incident_id = str(GROUND_TRUTH.get("true_positive_incident_id") or INCIDENT_ID)
    for item in listed.items:
        if _source_object_id(item.creation_source_ref) == true_incident_id:
            return item.event_id

    required = [item for item in listed.items if item.disposition_policy.value == "required"]
    pool = required or list(listed.items)
    event = max(pool, key=lambda row: (row.severity.value, row.risk_score or 0))
    return event.event_id


def response_plan_targets(
    actions: list[dict[str, object]] | tuple[dict[str, object], ...],
) -> set[str]:
    """Normalize response-plan action targets for GROUND_TRUTH alignment checks."""
    targets: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        target = action.get("target")
        if isinstance(target, str) and target.strip():
            targets.add(target.strip().lower())
    return targets


def missing_response_targets(
    *,
    ground_truth: dict[str, object],
    actions: list[dict[str, object]] | tuple[dict[str, object], ...],
) -> list[str]:
    """Return required containment targets absent from the response plan."""
    required = [
        str(item) for item in (ground_truth.get("must_response_targets") or []) if str(item).strip()
    ]
    if not required:
        required = [
            str(item)
            for item in (ground_truth.get("must_identify_entities") or [])
            if str(item).strip()
        ]
    present = response_plan_targets(actions)
    return [item for item in required if item.lower() not in present]
