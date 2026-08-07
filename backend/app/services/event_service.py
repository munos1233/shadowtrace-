"""EventService — unified internal event creation & query (ISSUE-015).

Does **not** call external systems and does **not** set ``Action.writeback_required``.
Status mutations are delegated exclusively to ``StateMachineService.transition``
(ISSUE-037); this service never writes ``security_event.status`` directly.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

import orjson
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, case, delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.errors import (
    ClassificationConflictError,
    DependencyUnavailableError,
    EventNotFoundError,
    ValidationError,
)
from app.core.event_bus import EventBus
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import ResponsePlan
from app.models.detection_promotion import (
    SourceIngestCorrelationOutcome,
    SourceIngestLinkDisposition,
    TypedIngestResult,
)
from app.models.disposition import SourceObjectLocator
from app.models.entities import EntitySet
from app.models.enums import (
    ClassificationSource,
    DispositionPolicy,
    EventStatus,
    EventType,
    FinalVerdict,
    Severity,
    SourceObjectKind,
)
from app.models.ids import canonical_source_identity, new_action_id, new_event_id
from app.models.report import (
    InvestigationReport,
    observability_from_sections,
    stamp_report_observability_in_sections,
)
from app.models.security_event import EventSummary, SecurityEvent
from app.models.source import SourceReference
from app.models.tool_meta import TERMINAL_DISPOSITION_TOOL
from app.models.workflow import TransitionContext, validate_verdict_status
from app.services.classification import (
    CLASSIFICATION_OVERRIDE_KEY,
    TRIAGE_RESULT_KEY,
    apply_event_type_to_triage_payload,
    build_human_classification_override,
)
from app.services.classification_source import (
    CLASSIFICATION_LOCKED_STATUSES,
    EVENT_TYPE_ORM_REWRITE_FAILED_FLAG,
    EVENT_TYPE_ORM_REWRITE_SKIPPED_FLAG,
    ORM_REWRITE_SKIP_HINT,
    ORM_REWRITE_SKIP_HUMAN_HINT,
    OrmEventTypeRewriteOutcome,
    derive_classification_source,
    should_skip_orm_event_type_rewrite,
    snapshot_has_human_classification_override,
)
from app.services.context_service import (
    EventContextStore,
    append_context_journal_in_session,
    event_summary_from_security_event,
)
from app.services.degraded_flag_service import DegradedFlagService
from app.services.entity_validator import validate_entity_set
from app.services.evidence_projection import EvidenceQueryScope
from app.services.source_entity_enricher import enrich_entities_from_source
from app.services.source_policy_resolver import (
    SourcePolicyResolver,
    connector_policy_from_row,
)

logger = logging.getLogger(__name__)

FILE_DEDUP_WINDOW = timedelta(hours=1)
LINK_ROLE_PRIMARY = "primary"
LINK_ROLE_RELATED = "related"
LINK_ROLE_PROVISIONAL = "provisional"
PROMOTION_NONE = "none"
PROMOTION_PROMOTED = "promoted"

# ISSUE-209/211: classification PATCH locked; machine ORM rewrite skips same set.
_CLASSIFICATION_LOCKED_STATUSES = CLASSIFICATION_LOCKED_STATUSES

_SOCKET_VERDICT: dict[FinalVerdict, str] = {
    FinalVerdict.NONE: "inconclusive",
    FinalVerdict.POSSIBLE_FALSE_POSITIVE: "uncertain",
    FinalVerdict.FALSE_POSITIVE: "false_positive",
    FinalVerdict.CONFIRMED_THREAT: "true_positive",
}


def should_apply_source_update(
    *,
    stored_updated_at: datetime | None,
    stored_token: str | None,
    incoming_updated_at: datetime | None,
    incoming_token: str | None,
) -> bool:
    """Accept only demonstrably newer mutable source state."""
    if stored_updated_at is not None and incoming_updated_at is not None:
        stored = (
            stored_updated_at.astimezone(UTC)
            if stored_updated_at.tzinfo is not None
            else stored_updated_at.replace(tzinfo=UTC)
        )
        incoming = (
            incoming_updated_at.astimezone(UTC)
            if incoming_updated_at.tzinfo is not None
            else incoming_updated_at.replace(tzinfo=UTC)
        )
        if incoming != stored:
            return incoming > stored
        return stored_token is None and incoming_token is not None
    if stored_updated_at is not None:
        return False
    if incoming_updated_at is not None:
        return True
    return stored_token is None and incoming_token is not None


class StateMachinePort(Protocol):
    """ISSUE-037 surface used by EventService (injected when available)."""

    async def transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: TransitionContext | None = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> SecurityEvent: ...


class IngestableSource(BaseModel):
    """Normalized ingest envelope for one external source object."""

    model_config = ConfigDict(extra="forbid")

    reference: SourceReference
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    normalized: dict[str, Any] = Field(default_factory=dict)
    title: str | None = None
    description: str = ""
    event_type: EventType | None = None
    severity: Severity | None = None
    occurred_at: datetime | None = None
    # Explicit Adapter-verified associations only (never inferred).
    incident_ref: SourceReference | None = None
    related_alert_refs: list[SourceReference] = Field(default_factory=list)
    source_type: str | None = None  # mock_xdr / file / manual / …


@dataclass(frozen=True, slots=True)
class IngestResult:
    source_record_id: str
    event_id: str | None
    accepted: bool = True
    created: bool = False
    promoted: bool = False
    related_only: bool = False
    idempotent: bool = False
    source_object_id: str | None = None
    source_revision: int | None = None
    correlation_outcome: SourceIngestCorrelationOutcome | None = None
    event_revision: int | None = None
    link_disposition: SourceIngestLinkDisposition | None = None
    error_code: str | None = None
    error_message: str | None = None

    @property
    def duplicate(self) -> bool:
        return self.idempotent


def ingest_result_to_typed(result: IngestResult) -> TypedIngestResult:
    return TypedIngestResult(
        source_record_id=result.source_record_id,
        event_id=result.event_id,
        accepted=result.accepted,
        created=result.created,
        promoted=result.promoted,
        related_only=result.related_only,
        idempotent=result.idempotent,
        duplicate=result.duplicate,
        source_object_id=result.source_object_id,
        source_revision=result.source_revision,
        correlation_outcome=result.correlation_outcome,
        event_revision=result.event_revision,
        link_disposition=result.link_disposition,
        error_code=result.error_code,
        error_message=result.error_message,
    )


def _link_role_to_disposition(link_role: str | None) -> SourceIngestLinkDisposition | None:
    if link_role == LINK_ROLE_PROVISIONAL:
        return SourceIngestLinkDisposition.PROVISIONAL
    if link_role == LINK_ROLE_PRIMARY:
        return SourceIngestLinkDisposition.PRIMARY
    if link_role == LINK_ROLE_RELATED:
        return SourceIngestLinkDisposition.RELATED
    return None


def _bundle_correlation_outcome(bundle: _CreateBundle) -> SourceIngestCorrelationOutcome:
    if bundle.idempotent:
        return SourceIngestCorrelationOutcome.IDEMPOTENT
    if bundle.promoted:
        return SourceIngestCorrelationOutcome.PROMOTED
    if bundle.related_only:
        return SourceIngestCorrelationOutcome.RELATED_ONLY
    if bundle.created:
        return SourceIngestCorrelationOutcome.CREATED
    if bundle.link_role == LINK_ROLE_RELATED:
        return SourceIngestCorrelationOutcome.MERGED
    return SourceIngestCorrelationOutcome.DUPLICATE


def _source_record_id_for(source: IngestableSource) -> str:
    ref = source.reference
    identity = canonical_source_identity(
        source_product=ref.source_product,
        source_tenant_id=ref.source_tenant_id,
        connector_id=ref.connector_id,
        source_kind=ref.source_kind.value,
        source_object_id=ref.source_object_id,
    )
    return stable_source_record_id(identity=identity)


def _failed_ingest_result(exc: ValidationError, source: IngestableSource) -> IngestResult:
    return IngestResult(
        source_record_id=_source_record_id_for(source),
        event_id=None,
        accepted=False,
        error_code=exc.error_code,
        error_message=exc.message,
    )


def _ingest_result_from_bundle(bundle: _CreateBundle) -> IngestResult:
    return IngestResult(
        source_record_id=bundle.source_record_id,
        event_id=bundle.event.event_id,
        accepted=True,
        created=bundle.created,
        promoted=bundle.promoted,
        related_only=bundle.related_only,
        idempotent=bundle.idempotent,
        source_object_id=bundle.source_object_id,
        source_revision=bundle.source_revision,
        correlation_outcome=_bundle_correlation_outcome(bundle),
        event_revision=int(bundle.event.row_version or 1),
        link_disposition=_link_role_to_disposition(bundle.link_role),
    )


@dataclass(frozen=True, slots=True)
class EventListResult:
    items: list[SecurityEvent]
    total: int
    page: int
    page_size: int


@dataclass
class _CreateBundle:
    event: orm.SecurityEvent
    source_record_id: str
    created: bool
    promoted: bool = False
    related_only: bool = False
    idempotent: bool = False
    merged_event_ids: tuple[str, ...] = ()
    intent_ids: tuple[str, ...] = ()
    source_object_id: str | None = None
    source_revision: int | None = None
    link_role: str | None = None


def stable_source_record_id(*, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    return f"src-{digest}"


def locator_from_reference(ref: SourceReference) -> SourceObjectLocator:
    return SourceObjectLocator(
        source_product=ref.source_product,
        source_tenant_id=ref.source_tenant_id,
        connector_id=ref.connector_id,
        source_kind=ref.source_kind,
        source_object_type=ref.source_object_type,
        source_object_id=ref.source_object_id,
    )


def _ref_dump(ref: SourceReference) -> dict[str, Any]:
    return ref.model_dump(mode="json")


def _ref_from_source_object(obj: orm.SourceObject) -> SourceReference:
    """Reconstruct the identity ``SourceReference`` for a persisted SourceObject row."""
    return SourceReference(
        source_kind=SourceObjectKind(obj.source_kind),
        source_product=obj.source_product,
        source_tenant_id=obj.source_tenant_id,
        connector_id=obj.connector_id,
        source_object_id=obj.source_object_id,
        source_object_type=obj.source_object_type,
        parent_source_object_id=obj.parent_source_object_id,
    )


def _entities_from_source_ref(
    ref: SourceReference,
    normalized: dict[str, Any],
) -> dict[str, Any]:
    """Project validated structured source fields into SecurityEvent.entities JSON."""
    if not normalized:
        return {}
    enrichment = enrich_entities_from_source([(ref, normalized)])
    validated = validate_entity_set(enrichment.entity_set, provenance="source")
    if validated.entity_set == EntitySet():
        return {}
    return validated.entity_set.model_dump(mode="json")


def _normalized_baseline_from_dict(
    normalized: dict[str, Any] | None,
    *,
    event_type: str | None = None,
) -> dict[str, Any] | None:
    """Project immutable source baseline fields for ISSUE-102 risk floor."""
    baseline: dict[str, Any] = {}
    if isinstance(normalized, dict):
        raw_score = normalized.get("risk_score")
        if raw_score is not None:
            try:
                baseline["risk_score"] = max(0, min(100, int(raw_score)))
            except (TypeError, ValueError):
                pass
        for key in ("event_type", "alert_type", "scenario"):
            value = normalized.get(key)
            if value is not None:
                baseline[key] = value
    if event_type and "event_type" not in baseline:
        baseline["event_type"] = event_type
    return baseline or None


def _snapshot_has_risk_baseline(snapshot: dict[str, Any] | None) -> bool:
    """True when frozen snapshot carries a usable ``normalized.risk_score``."""
    if not isinstance(snapshot, dict):
        return False
    normalized = snapshot.get("normalized")
    if not isinstance(normalized, dict):
        return False
    raw_score = normalized.get("risk_score")
    if raw_score is None:
        return False
    try:
        int(raw_score)
    except (TypeError, ValueError):
        return False
    return True


def _source_snapshot_from_row(row: orm.SecurityEvent) -> dict[str, Any]:
    """Return immutable source evidence only; never include mutable current_* state."""
    snapshot: dict[str, Any] = {
        "creation_source_ref": dict(row.creation_source_ref),
        "source_reference_snapshots": [
            dict(item) for item in (row.source_reference_snapshots or [])
        ],
        "raw_alert_snapshot": (
            dict(row.raw_alert_snapshot) if row.raw_alert_snapshot is not None else None
        ),
    }
    if row.event_type:
        snapshot["alert_type"] = row.event_type
    if row.title:
        snapshot["title"] = row.title
    if row.description:
        snapshot["description"] = row.description
    if row.severity:
        snapshot["severity"] = row.severity
    raw_alert = row.raw_alert_snapshot
    if isinstance(raw_alert, dict):
        nested = raw_alert.get("normalized")
        if isinstance(nested, dict) and nested:
            snapshot["normalized"] = dict(nested)
    if "normalized" not in snapshot:
        fallback = _normalized_baseline_from_dict(None, event_type=row.event_type)
        if fallback:
            snapshot["normalized"] = fallback
    return snapshot


def _security_event_from_row(row: orm.SecurityEvent) -> SecurityEvent:
    creation = SourceReference.model_validate(row.creation_source_ref)
    snapshots = [SourceReference.model_validate(s) for s in (row.source_reference_snapshots or [])]
    disposition = None
    if row.disposition_source_ref:
        disposition = SourceObjectLocator.model_validate(row.disposition_source_ref)
    entities_raw = row.entities or {}
    try:
        entities = EntitySet.model_validate(entities_raw)
    except Exception:  # noqa: BLE001 — tolerate sparse ORM JSON
        entities = EntitySet()
    return SecurityEvent(
        event_id=row.event_id,
        event_type=EventType(row.event_type),
        title=row.title,
        description=row.description or "",
        status=EventStatus(row.status),
        severity=Severity(row.severity),
        risk_score=int(row.risk_score or 0),
        confidence=float(row.confidence or 0.0),
        final_verdict=FinalVerdict(row.final_verdict),
        entities=entities,
        creation_source_ref=creation,
        source_reference_snapshots=snapshots,
        current_primary_source_record_id=row.current_primary_source_record_id,
        disposition_source_ref=disposition,
        disposition_policy=DispositionPolicy(row.disposition_policy),
        raw_alert_ids=list(row.raw_alert_ids or []),
        raw_alert_snapshot=row.raw_alert_snapshot,
        source_type=row.source_type,
        occurred_at=row.occurred_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        closed_at=row.closed_at,
        replan_count=int(row.replan_count or 0),
        degraded_flags=[str(f) for f in (row.degraded_flags or [])],
        escalated=bool(row.escalated),
        external_unsynced=bool(row.external_unsynced),
        event_context_snapshot=row.event_context_snapshot,
        row_version=int(row.row_version or 1),
        classification_source=derive_classification_source(
            degraded_flags=[str(f) for f in (row.degraded_flags or [])],
            event_context_snapshot=(
                dict(row.event_context_snapshot)
                if isinstance(row.event_context_snapshot, dict)
                else None
            ),
        ),
    )


class EventService:
    """Create / query SecurityEvent records; never mutate status directly."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        store: EventContextStore,
        *,
        degraded_flags: DegradedFlagService,
        event_bus: EventBus | None = None,
        policy_resolver: SourcePolicyResolver | None = None,
        state_machine: StateMachinePort | None = None,
        investigation_intent: Any | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._store = store
        self._bus = event_bus
        self._degraded = degraded_flags
        self._policy = policy_resolver or SourcePolicyResolver()
        self._state_machine = state_machine
        self._investigation_intent = investigation_intent

    async def _attach_auto_investigate_intent(
        self,
        session: AsyncSession,
        event: orm.SecurityEvent,
        source: IngestableSource,
        *,
        link_role: str,
        created_or_promoted: bool,
    ) -> str | None:
        if self._investigation_intent is None:
            return None
        ref = source.reference
        return cast(
            str | None,
            await self._investigation_intent.maybe_create_pending_in_session(
                session,
                event,
                link_role=link_role,
                source_product=ref.source_product,
                created_or_promoted=created_or_promoted,
            ),
        )

    # ------------------------------------------------------------------ #
    # Ingest / create
    # ------------------------------------------------------------------ #

    async def ingest_source_object(
        self,
        source_object: IngestableSource,
        *,
        fail_soft: bool = False,
    ) -> IngestResult:
        """Upsert source_object and attach / create / promote an internal event."""
        try:
            bundle = await self._ingest_with_unique_retry(source_object)
        except ValidationError as exc:
            if fail_soft:
                return _failed_ingest_result(exc, source_object)
            raise
        await self._post_create_side_effects(
            bundle.event,
            force_context_refresh=not bundle.idempotent,
            publish_event=bundle.created or bundle.promoted,
        )
        if bundle.intent_ids and self._investigation_intent is not None:
            self._investigation_intent.schedule_dispatch()
        for merged_event_id in bundle.merged_event_ids:
            await self._store.delete_cached_context(merged_event_id)
        return _ingest_result_from_bundle(bundle)

    async def create_event_from_source(
        self, primary_ref: SourceReference, **kwargs: Any
    ) -> SecurityEvent:
        """Create (or idempotently return) an event for a primary source reference."""
        ingest = IngestableSource(reference=primary_ref, **kwargs)
        bundle = await self._ingest_with_unique_retry(ingest)
        await self._post_create_side_effects(
            bundle.event,
            force_context_refresh=not bundle.idempotent,
            publish_event=bundle.created or bundle.promoted,
        )
        if bundle.intent_ids and self._investigation_intent is not None:
            self._investigation_intent.schedule_dispatch()
        for merged_event_id in bundle.merged_event_ids:
            await self._store.delete_cached_context(merged_event_id)
        return _security_event_from_row(bundle.event)

    async def create_event(
        self,
        raw_alert: dict[str, Any],
        source_type: str = "file",
        *,
        title: str | None = None,
        event_type: EventType = EventType.OTHER,
        severity: Severity = Severity.LOW,
        occurred_at: datetime | None = None,
        primary_entity: str | None = None,
    ) -> SecurityEvent:
        """File / manual fallback create path (no stable external source ID)."""
        now = occurred_at or datetime.now(UTC)
        payload_hash = hashlib.sha256(
            orjson.dumps(raw_alert, option=orjson.OPT_SORT_KEYS)
        ).hexdigest()
        entity_key = primary_entity or str(raw_alert.get("entity") or "unknown")
        identity = f"file|{entity_key}|{payload_hash}"
        event_id = new_event_id(identity, now)

        lock_material = f"{source_type}|{entity_key}|{payload_hash}".encode()
        advisory_lock_key = int.from_bytes(
            hashlib.sha256(lock_material).digest()[:8], byteorder="big", signed=True
        )
        created = False
        async with self._session_factory() as session:
            async with session.begin():
                # Serialize the file/manual soft-dedup key across workers. Unlike a
                # process lock, this also covers multiple API workers and midnight
                # crossings where deterministic event IDs can differ.
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {"lock_key": advisory_lock_key},
                )
                row = await session.get(orm.SecurityEvent, event_id)
                if row is None:
                    # Soft dedup: same payload_hash + primary entity within 1h.
                    window_start = now - FILE_DEDUP_WINDOW
                    candidates = (
                        await session.scalars(
                            select(orm.SecurityEvent).where(
                                orm.SecurityEvent.source_type == source_type,
                                orm.SecurityEvent.occurred_at >= window_start,
                                orm.SecurityEvent.occurred_at <= now + timedelta(seconds=1),
                            )
                        )
                    ).all()
                    row = next(
                        (
                            candidate
                            for candidate in candidates
                            if (candidate.raw_alert_snapshot or {}).get("payload_hash")
                            == payload_hash
                            and (candidate.raw_alert_snapshot or {}).get("primary_entity")
                            == entity_key
                        ),
                        None,
                    )

                if row is None:
                    creation_ref = SourceReference(
                        source_kind=SourceObjectKind.ALERT,
                        source_product="file",
                        source_tenant_id="local",
                        connector_id="file-local",
                        source_object_id=f"file-{payload_hash[:12]}",
                        raw_payload_hash=payload_hash,
                        ingested_at=now,
                    )
                    row = orm.SecurityEvent(
                        event_id=event_id,
                        event_type=event_type.value,
                        title=title or str(raw_alert.get("title") or "file alert"),
                        description=str(raw_alert.get("description") or ""),
                        status=EventStatus.NEW.value,
                        severity=severity.value,
                        final_verdict=FinalVerdict.NONE.value,
                        entities={},
                        creation_source_ref=_ref_dump(creation_ref),
                        source_reference_snapshots=[_ref_dump(creation_ref)],
                        disposition_source_ref=None,
                        disposition_policy=DispositionPolicy.NOT_REQUIRED.value,
                        raw_alert_ids=[creation_ref.source_object_id],
                        raw_alert_snapshot={
                            "payload_hash": payload_hash,
                            "primary_entity": entity_key,
                            "raw": raw_alert,
                        },
                        source_type=source_type,
                        occurred_at=now,
                    )
                    session.add(row)
                    session.add(
                        orm.EventAuditLog(
                            event_id=event_id,
                            from_status=None,
                            to_status=EventStatus.NEW.value,
                            operator="EventService",
                            reason="event_created",
                        )
                    )
                    await session.flush()
                    await session.refresh(row)
                    created = True

        await self._post_create_side_effects(
            row,
            force_context_refresh=created,
            publish_event=created,
        )
        return _security_event_from_row(row)

    # ------------------------------------------------------------------ #
    # Query
    # ------------------------------------------------------------------ #

    async def get_event(self, event_id: str) -> SecurityEvent | None:
        persisted_report_quality: str | None = None
        async with self._session_factory() as session:
            row = await session.get(orm.SecurityEvent, event_id)
            if row is None:
                return None
            event = _security_event_from_row(row)
            # ISSUE-250: DB report row is authoritative for GET /report readability.
            persisted_report_quality = await session.scalar(
                select(orm.Report.report_quality)
                .where(orm.Report.event_id == event_id)
                .order_by(orm.Report.updated_at.desc())
                .limit(1)
            )

        if not event.event_context_snapshot:
            try:
                from app.services.context_service import _context_as_dict, _to_jsonable
                from app.services.event_context_snapshot_projection import (
                    merge_evidence_summary_into_snapshot,
                    merge_report_generated_into_snapshot,
                    merge_storyline_summary_into_snapshot,
                )

                ctx = await self._store.get_full_context(event_id)
                raw = {key: _to_jsonable(value) for key, value in _context_as_dict(ctx).items()}
                # ISSUE-254: do not return the full EventContext dump on GET.
                # Project bounded observability fields; full state stays in WM/trace.
                snapshot: dict[str, Any] = {}
                if isinstance(raw.get("risk_assessment"), dict):
                    snapshot["risk_assessment"] = raw["risk_assessment"]
                if raw.get("analysis_only_complete") is not None:
                    snapshot["analysis_only_complete"] = bool(raw["analysis_only_complete"])
                if raw.get("report_generated") is not None:
                    snapshot = merge_report_generated_into_snapshot(
                        snapshot, bool(raw["report_generated"])
                    )
                elif raw.get("report") is not None:
                    snapshot = merge_report_generated_into_snapshot(snapshot, True)
                if isinstance(raw.get("evidence_output"), dict):
                    snapshot = merge_evidence_summary_into_snapshot(
                        snapshot, raw["evidence_output"]
                    )
                if isinstance(raw.get("storyline"), dict):
                    snapshot = merge_storyline_summary_into_snapshot(snapshot, raw["storyline"])
                if isinstance(raw.get("classification_override"), dict):
                    snapshot["classification_override"] = raw["classification_override"]
                if raw.get("execution_substate") is not None:
                    snapshot["execution_substate"] = raw["execution_substate"]
                event = event.model_copy(update={"event_context_snapshot": snapshot})
            except Exception:
                logger.debug(
                    "hydrate event_context_snapshot failed event_id=%s",
                    event_id,
                    exc_info=True,
                )

        snapshot = dict(event.event_context_snapshot or {})
        changed = False

        try:
            aoc = await self._store.get(event_id, "analysis_only_complete")
            if aoc is not None and snapshot.get("analysis_only_complete") != bool(aoc):
                snapshot["analysis_only_complete"] = bool(aoc)
                changed = True
        except Exception:
            logger.debug(
                "overlay analysis_only_complete failed event_id=%s",
                event_id,
                exc_info=True,
            )

        try:
            report_generated = await self._store.get(event_id, "report_generated")
            if report_generated is not None and snapshot.get("report_generated") != bool(
                report_generated
            ):
                snapshot["report_generated"] = bool(report_generated)
                changed = True
        except Exception:
            logger.debug(
                "overlay report_generated failed event_id=%s",
                event_id,
                exc_info=True,
            )

        if persisted_report_quality is not None:
            # Readable report exists even when Redis/snapshot flags lag behind.
            if snapshot.get("report_generated") is not True:
                snapshot["report_generated"] = True
                changed = True
            if snapshot.get("report_quality") != persisted_report_quality:
                snapshot["report_quality"] = persisted_report_quality
                changed = True
        elif snapshot.get("report_generated") is True and snapshot.get("report") is None:
            # DB has no report row: do not let a stale Redis/snapshot flag claim
            # readability while GET /report would 404 (ISSUE-250 review).
            snapshot["report_generated"] = False
            changed = True

        if changed:
            event = event.model_copy(update={"event_context_snapshot": snapshot})
        return event

    async def get_evidence_query_scope(self, event_id: str) -> EvidenceQueryScope:
        """Derive the only permitted evidence tenant/connectors from trusted event state."""
        event = await self.get_event(event_id)
        if event is None:
            raise EventNotFoundError(
                f"security_event not found: {event_id}",
                details={"event_id": event_id},
            )
        tenant_id = event.creation_source_ref.source_tenant_id
        references = [event.creation_source_ref, *event.source_reference_snapshots]
        products_by_connector: dict[str, str] = {}
        for reference in references:
            if reference.source_tenant_id != tenant_id:
                raise ValidationError(
                    "event source references span multiple source tenants",
                    error_code="adapter_validation_error",
                    details={
                        "event_id": event_id,
                        "expected_source_tenant_id": tenant_id,
                        "conflicting_source_tenant_id": reference.source_tenant_id,
                        "connector_id": reference.connector_id,
                    },
                )
            existing_product = products_by_connector.get(reference.connector_id)
            if existing_product not in (None, reference.source_product):
                raise ValidationError(
                    "event connector has conflicting source product ownership",
                    error_code="adapter_validation_error",
                    details={
                        "event_id": event_id,
                        "connector_id": reference.connector_id,
                        "existing_source_product": existing_product,
                        "conflicting_source_product": reference.source_product,
                    },
                )
            products_by_connector[reference.connector_id] = reference.source_product

        connector_ids = frozenset(products_by_connector)
        async with self._session_factory() as session:
            connectors = (
                await session.scalars(
                    select(orm.SourceConnector).where(
                        orm.SourceConnector.connector_id.in_(connector_ids)
                    )
                )
            ).all()
        for connector in connectors:
            expected_product = products_by_connector[connector.connector_id]
            metadata_tenant = (connector.connector_metadata or {}).get("source_tenant_id")
            if connector.source_product != expected_product or metadata_tenant not in (
                None,
                tenant_id,
            ):
                raise ValidationError(
                    "event connector ownership conflicts with trusted event scope",
                    error_code="adapter_validation_error",
                    details={
                        "event_id": event_id,
                        "connector_id": connector.connector_id,
                        "expected_source_product": expected_product,
                        "existing_source_product": connector.source_product,
                        "expected_source_tenant_id": tenant_id,
                        "existing_source_tenant_id": metadata_tenant,
                    },
                )
        return EvidenceQueryScope(
            source_tenant_id=tenant_id,
            connector_ids=connector_ids,
        )

    # Whitelist of columns allowed for sort_by in list_events.
    _SORT_COLUMN_MAP: dict[str, Any] = {
        "created_at": orm.SecurityEvent.created_at,
        "updated_at": orm.SecurityEvent.updated_at,
        "occurred_at": orm.SecurityEvent.occurred_at,
        "severity": orm.SecurityEvent.severity,
        "risk_score": orm.SecurityEvent.risk_score,
        "status": orm.SecurityEvent.status,
        "event_type": orm.SecurityEvent.event_type,
    }

    async def list_events(
        self,
        *,
        status: EventStatus | str | None = None,
        severity: Severity | str | None = None,
        event_type: EventType | str | None = None,
        final_verdict: FinalVerdict | str | None = None,
        keyword: str | None = None,
        occurred_after: datetime | None = None,
        occurred_before: datetime | None = None,
        page: int = 1,
        page_size: int = 20,
        sort_by: str | None = None,
        sort_order: str | None = None,
    ) -> EventListResult:
        page = max(1, page)
        page_size = min(max(1, page_size), 200)
        filters: list[Any] = []
        if status is not None:
            filters.append(
                orm.SecurityEvent.status
                == (status.value if isinstance(status, EventStatus) else status)
            )
        if severity is not None:
            filters.append(
                orm.SecurityEvent.severity
                == (severity.value if isinstance(severity, Severity) else severity)
            )
        if event_type is not None:
            filters.append(
                orm.SecurityEvent.event_type
                == (event_type.value if isinstance(event_type, EventType) else event_type)
            )
        if final_verdict is not None:
            filters.append(
                orm.SecurityEvent.final_verdict
                == (
                    final_verdict.value
                    if isinstance(final_verdict, FinalVerdict)
                    else final_verdict
                )
            )
        if keyword:
            like = f"%{keyword}%"
            filters.append(
                or_(
                    orm.SecurityEvent.title.ilike(like),
                    orm.SecurityEvent.description.ilike(like),
                )
            )
        if occurred_after is not None:
            filters.append(orm.SecurityEvent.occurred_at >= occurred_after)
        if occurred_before is not None:
            filters.append(orm.SecurityEvent.occurred_at <= occurred_before)

        # Resolve sort column (whitelist only; default to created_at).
        sort_col = self._SORT_COLUMN_MAP.get(sort_by or "created_at", orm.SecurityEvent.created_at)
        descending = (sort_order or "desc") != "asc"

        async with self._session_factory() as session:
            count_stmt = select(func.count()).select_from(orm.SecurityEvent)
            list_stmt = select(orm.SecurityEvent).order_by(
                sort_col.desc() if descending else sort_col.asc()
            )
            if filters:
                count_stmt = count_stmt.where(and_(*filters))
                list_stmt = list_stmt.where(and_(*filters))
            total = int(await session.scalar(count_stmt) or 0)
            rows = (
                await session.scalars(list_stmt.offset((page - 1) * page_size).limit(page_size))
            ).all()
            items = [_security_event_from_row(r) for r in rows]
        return EventListResult(items=items, total=total, page=page, page_size=page_size)

    # ------------------------------------------------------------------ #
    # Verdict / status (status via StateMachineService only)
    # ------------------------------------------------------------------ #

    async def set_final_verdict(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
        context: TransitionContext | None = None,
    ) -> SecurityEvent:
        """Sole path for writing ``final_verdict`` + publishing ``final_verdict_updated``."""
        # ``context`` remains in the public signature for compatibility, but trusted
        # gate projections are always rebuilt below from PostgreSQL.
        _ = context
        async with self._session_factory() as session:
            async with session.begin():
                changed, result, summary = await self.apply_final_verdict_in_session(
                    session,
                    event_id,
                    verdict,
                    operator=operator,
                )

        if changed:
            await self.publish_final_verdict_mutation(
                event_id,
                verdict,
                result=result,
                summary=summary,
            )
        return result

    async def apply_final_verdict_in_session(
        self,
        session: AsyncSession,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
    ) -> tuple[bool, SecurityEvent, EventSummary]:
        """Apply a verdict inside the caller's transaction.

        WorkflowRuntimeService uses this API so the verdict, confidence floor,
        and trusted disposition-only intent commit atomically. After the caller
        commits, you must still invoke one of:

        - ``publish_final_verdict_mutation`` when ``changed`` is True
        - ``sync_event_summary_mutation`` when only non-verdict fields changed
        """
        row = await session.get(
            orm.SecurityEvent,
            event_id,
            with_for_update=True,
        )
        if row is None:
            raise KeyError(f"security_event not found: {event_id}")

        ctx = await self._authoritative_verdict_context(session, event_id)
        validate_verdict_status(verdict, EventStatus(row.status), ctx)

        previous = row.final_verdict
        changed = previous != verdict.value
        if changed:
            row.final_verdict = verdict.value
            row.row_version = int(row.row_version or 1) + 1
            session.add(
                orm.EventAuditLog(
                    event_id=event_id,
                    from_status=row.status,
                    to_status=row.status,
                    operator=operator or "EventService",
                    reason=f"final_verdict:{previous}->{verdict.value}",
                )
            )
            await session.flush()
            await session.refresh(row)

        return (
            changed,
            _security_event_from_row(row),
            event_summary_from_security_event(row),
        )

    async def publish_final_verdict_mutation(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        result: SecurityEvent,
        summary: EventSummary,
    ) -> None:
        """Publish mirrors for a verdict mutation after its transaction commits."""
        await self.sync_event_summary_mutation(
            event_id,
            result=result,
            summary=summary,
        )
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "final_verdict_updated",
                {"verdict": _SOCKET_VERDICT[verdict]},
            )

    async def sync_event_summary_mutation(
        self,
        event_id: str,
        *,
        result: SecurityEvent,
        summary: EventSummary,
    ) -> None:
        """Synchronize EventContext after a committed event-row mutation."""
        await self._sync_event_summary_after_mutation(
            event_id,
            committed_version=result.row_version,
            summary=summary,
        )

    async def update_risk_fields(
        self,
        event_id: str,
        *,
        risk_score: int,
        severity: Severity,
        confidence: float,
        operator: str | None = None,
        factor_names: list[str] | None = None,
        risk_assessment: dict[str, Any] | None = None,
    ) -> SecurityEvent:
        """Persist RiskAgent score fields onto ``security_event`` (ISSUE-035).

        Does **not** write ``final_verdict`` — that remains ``set_final_verdict`` only.
        Publishes ``risk_updated`` (locked Socket payload: ``RiskUpdatedPayload``).

        When ``risk_assessment`` is provided, merge it into
        ``event_context_snapshot.risk_assessment`` so list/detail can project
        ``evidence_limited`` / ``scoring_mode`` / ``verdict_reason_codes`` (ISSUE-241).
        """
        from app.services.risk_verdict_projection import merge_risk_assessment_into_snapshot

        score = max(0, min(100, int(risk_score)))
        conf = max(0.0, min(1.0, float(confidence)))
        previous_score = 0
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.SecurityEvent,
                    event_id,
                    with_for_update=True,
                )
                if row is None:
                    raise KeyError(f"security_event not found: {event_id}")
                previous_score = int(row.risk_score or 0)
                row.risk_score = score
                row.severity = severity.value if isinstance(severity, Severity) else str(severity)
                row.confidence = conf
                if isinstance(risk_assessment, dict) and risk_assessment:
                    row.event_context_snapshot = merge_risk_assessment_into_snapshot(
                        (
                            dict(row.event_context_snapshot)
                            if isinstance(row.event_context_snapshot, dict)
                            else None
                        ),
                        risk_assessment,
                    )
                row.row_version = int(row.row_version or 1) + 1
                reason_codes = []
                if isinstance(risk_assessment, dict):
                    raw_codes = risk_assessment.get("verdict_reason_codes")
                    if isinstance(raw_codes, list):
                        reason_codes = [str(c) for c in raw_codes[:5] if c is not None]
                audit_reason = (
                    f"risk_fields:score={score},severity={row.severity},confidence={conf:.4f}"
                )
                if risk_assessment and risk_assessment.get("evidence_limited"):
                    audit_reason = f"{audit_reason},evidence_limited=true"
                if reason_codes:
                    audit_reason = f"{audit_reason},verdict_reason_codes={','.join(reason_codes)}"
                session.add(
                    orm.EventAuditLog(
                        event_id=event_id,
                        from_status=row.status,
                        to_status=row.status,
                        operator=operator or "RiskAgent",
                        reason=audit_reason,
                    )
                )
                await session.flush()
                await session.refresh(row)
                result = _security_event_from_row(row)
                summary = event_summary_from_security_event(row)

        await self._sync_event_summary_after_mutation(
            event_id,
            committed_version=result.row_version,
            summary=summary,
        )
        if self._bus is not None:
            payload: dict[str, Any] = {"risk_score": score}
            if previous_score != score:
                payload["previous_score"] = previous_score
            if factor_names:
                payload["factors"] = list(factor_names)
            await self._bus.publish_event(event_id, "risk_updated", payload)
        return result

    async def merge_evidence_context_snapshot(
        self,
        event_id: str,
        evidence_output: Any,
    ) -> None:
        """Merge bounded evidence summary into ``event_context_snapshot`` (ISSUE-254)."""
        from app.services.event_context_snapshot_projection import (
            merge_evidence_summary_into_snapshot,
        )

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    row = await session.get(
                        orm.SecurityEvent,
                        event_id,
                        with_for_update=True,
                    )
                    if row is None:
                        return
                    payload = (
                        evidence_output.model_dump(mode="json")
                        if hasattr(evidence_output, "model_dump")
                        else evidence_output
                    )
                    if not isinstance(payload, dict):
                        return
                    row.event_context_snapshot = merge_evidence_summary_into_snapshot(
                        (
                            dict(row.event_context_snapshot)
                            if isinstance(row.event_context_snapshot, dict)
                            else None
                        ),
                        payload,
                    )
                    await session.flush()
        except Exception:
            logger.warning(
                "merge_evidence_context_snapshot failed event_id=%s",
                event_id,
                exc_info=True,
            )

    async def merge_storyline_context_snapshot(
        self,
        event_id: str,
        storyline: Any,
    ) -> None:
        """Merge bounded storyline summary into ``event_context_snapshot`` (ISSUE-254)."""
        from app.services.event_context_snapshot_projection import (
            merge_storyline_summary_into_snapshot,
        )

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    row = await session.get(
                        orm.SecurityEvent,
                        event_id,
                        with_for_update=True,
                    )
                    if row is None:
                        return
                    payload = (
                        storyline.model_dump(mode="json")
                        if hasattr(storyline, "model_dump")
                        else storyline
                    )
                    if not isinstance(payload, dict):
                        return
                    row.event_context_snapshot = merge_storyline_summary_into_snapshot(
                        (
                            dict(row.event_context_snapshot)
                            if isinstance(row.event_context_snapshot, dict)
                            else None
                        ),
                        payload,
                    )
                    await session.flush()
        except Exception:
            logger.warning(
                "merge_storyline_context_snapshot failed event_id=%s",
                event_id,
                exc_info=True,
            )

    async def merge_report_generated_context_snapshot(
        self,
        event_id: str,
        generated: bool,
    ) -> None:
        """Persist ``report_generated`` onto the durable snapshot (ISSUE-254)."""
        from app.services.event_context_snapshot_projection import (
            merge_report_generated_into_snapshot,
        )

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    row = await session.get(
                        orm.SecurityEvent,
                        event_id,
                        with_for_update=True,
                    )
                    if row is None:
                        return
                    row.event_context_snapshot = merge_report_generated_into_snapshot(
                        (
                            dict(row.event_context_snapshot)
                            if isinstance(row.event_context_snapshot, dict)
                            else None
                        ),
                        generated,
                    )
                    await session.flush()
        except Exception:
            logger.warning(
                "merge_report_generated_context_snapshot failed event_id=%s",
                event_id,
                exc_info=True,
            )

    async def update_classification(
        self,
        event_id: str,
        *,
        event_type: EventType,
        reason: str,
        operator: str,
        reinvestigate: bool = False,
    ) -> SecurityEvent:
        """Persist analyst event_type override with audit + human marker (ISSUE-209).

        Writes:
        - ``security_event.event_type``
        - ``EventAuditLog`` (same status, classification reason)
        - durable ``classification_override`` in context store + snapshot mirror
        """
        cleaned_reason = (reason or "").strip()
        if not cleaned_reason:
            raise ValidationError(
                "classification reason is required",
                error_code="validation_error",
                details={"field": "reason"},
            )
        if not isinstance(event_type, EventType):
            try:
                event_type = EventType(str(event_type))
            except ValueError as exc:
                raise ValidationError(
                    f"illegal event_type: {event_type!r}",
                    error_code="validation_error",
                    details={"field": "event_type"},
                ) from exc

        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.SecurityEvent,
                    event_id,
                    with_for_update=True,
                )
                if row is None:
                    raise EventNotFoundError(
                        f"event {event_id} not found",
                        details={"event_id": event_id},
                    )
                current_status = EventStatus(row.status)
                if current_status in _CLASSIFICATION_LOCKED_STATUSES:
                    raise ClassificationConflictError(
                        "classification cannot change while response execution "
                        "or verification is active; wait for the stage to finish "
                        "or abort/complete the current disposition first",
                        details={
                            "event_id": event_id,
                            "status": current_status.value,
                            "locked_statuses": sorted(
                                s.value for s in _CLASSIFICATION_LOCKED_STATUSES
                            ),
                        },
                    )

                previous_type = str(row.event_type)
                new_type = event_type.value
                override = build_human_classification_override(
                    event_type=new_type,
                    reason=cleaned_reason,
                    operator=operator,
                    previous_event_type=previous_type,
                    updated_at=now.isoformat(),
                    reinvestigate=reinvestigate,
                )
                row.event_type = new_type
                row.row_version = int(row.row_version or 1) + 1
                snapshot = (
                    dict(row.event_context_snapshot)
                    if isinstance(row.event_context_snapshot, dict)
                    else {}
                )
                snapshot[CLASSIFICATION_OVERRIDE_KEY] = override
                triage_synced = False
                snap_triage, triage_changed = apply_event_type_to_triage_payload(
                    snapshot.get(TRIAGE_RESULT_KEY),
                    new_type,
                )
                if triage_changed and isinstance(snap_triage, dict):
                    snapshot[TRIAGE_RESULT_KEY] = snap_triage
                    triage_synced = True
                row.event_context_snapshot = snapshot
                audit_reason = (
                    f"classification_override:{previous_type}->{new_type}: {cleaned_reason}"
                )
                if triage_synced:
                    audit_reason = f"{audit_reason}; triage_result_event_type_synced"
                session.add(
                    orm.EventAuditLog(
                        event_id=event_id,
                        from_status=row.status,
                        to_status=row.status,
                        operator=operator,
                        reason=audit_reason,
                    )
                )
                await session.flush()
                await session.refresh(row)
                result = _security_event_from_row(row)
                summary = event_summary_from_security_event(row)

        await self._sync_event_summary_after_mutation(
            event_id,
            committed_version=result.row_version,
            summary=summary,
        )
        # Persist human marker as a first-class EventContext field.
        try:
            await self._store.set(event_id, "classification_override", override)
        except Exception:
            logger.warning(
                "classification_override context write failed event_id=%s",
                event_id,
                exc_info=True,
            )
        # Keep ResponseAgent rule selection aligned when reinvestigate is skipped.
        try:
            triage = await self._store.get(event_id, TRIAGE_RESULT_KEY)
            updated_triage, triage_changed = apply_event_type_to_triage_payload(
                triage,
                new_type,
            )
            if triage_changed and updated_triage is not None:
                await self._store.set(event_id, TRIAGE_RESULT_KEY, updated_triage)
        except Exception:
            logger.warning(
                "triage_result event_type sync failed event_id=%s",
                event_id,
                exc_info=True,
            )
        if self._bus is not None:
            await self._bus.publish_event(
                event_id,
                "classification_updated",
                {
                    "event_type": new_type,
                    "previous_event_type": previous_type,
                    "classification_source": ClassificationSource.HUMAN.value,
                    "reinvestigate": bool(reinvestigate),
                },
            )
        return result

    async def rewrite_event_type_from_triage(
        self,
        event_id: str,
        *,
        event_type: EventType | str,
        operator: str = "TriageAgent",
    ) -> OrmEventTypeRewriteOutcome:
        """Rewrite ORM ``event_type`` to match triage_result (ISSUE-211).

        Called after triage successfully persists ``triage_result``. Never raises
        to the investigation main path: lock / gate / missing / I/O failures
        return an outcome and record audit + degraded when appropriate.
        """
        settings = get_settings()
        if not bool(settings.triage_rewrite_event_type):
            return OrmEventTypeRewriteOutcome.SKIPPED_GATE

        if isinstance(event_type, EventType):
            new_type = event_type.value
        else:
            try:
                new_type = EventType(str(event_type)).value
            except ValueError:
                logger.warning(
                    "triage ORM rewrite skipped: illegal event_type=%r event_id=%s",
                    event_type,
                    event_id,
                )
                return OrmEventTypeRewriteOutcome.FAILED

        try:
            previous_type: str | None = None
            current_status: EventStatus | None = None
            result: SecurityEvent | None = None
            summary: EventSummary | None = None
            applied = False
            skipped_human = False

            async with self._session_factory() as session:
                async with session.begin():
                    row = await session.get(
                        orm.SecurityEvent,
                        event_id,
                        with_for_update=True,
                    )
                    if row is None:
                        return OrmEventTypeRewriteOutcome.SKIPPED_MISSING

                    current_status = EventStatus(row.status)
                    previous_type = str(row.event_type)
                    snapshot = (
                        dict(row.event_context_snapshot)
                        if isinstance(row.event_context_snapshot, dict)
                        else None
                    )

                    if should_skip_orm_event_type_rewrite(current_status):
                        session.add(
                            orm.EventAuditLog(
                                event_id=event_id,
                                from_status=row.status,
                                to_status=row.status,
                                operator=operator,
                                reason=(
                                    f"event_type_orm_rewrite_skipped:"
                                    f"{previous_type}->{new_type}: {ORM_REWRITE_SKIP_HINT}"
                                ),
                            )
                        )
                        await session.flush()
                    elif (
                        snapshot_has_human_classification_override(snapshot)
                        and previous_type != new_type
                    ):
                        # Never clobber ISSUE-209 human PATCH on the list column.
                        skipped_human = True
                        session.add(
                            orm.EventAuditLog(
                                event_id=event_id,
                                from_status=row.status,
                                to_status=row.status,
                                operator=operator,
                                reason=(
                                    f"event_type_orm_rewrite_skipped_human:"
                                    f"{previous_type}->{new_type}: "
                                    f"{ORM_REWRITE_SKIP_HUMAN_HINT}"
                                ),
                            )
                        )
                        await session.flush()
                    elif previous_type == new_type:
                        return OrmEventTypeRewriteOutcome.NOOP
                    else:
                        row.event_type = new_type
                        row.row_version = int(row.row_version or 1) + 1
                        session.add(
                            orm.EventAuditLog(
                                event_id=event_id,
                                from_status=row.status,
                                to_status=row.status,
                                operator=operator,
                                reason=(f"event_type_orm_rewrite:{previous_type}->{new_type}"),
                            )
                        )
                        await session.flush()
                        await session.refresh(row)
                        result = _security_event_from_row(row)
                        summary = event_summary_from_security_event(row)
                        applied = True

            if current_status is not None and should_skip_orm_event_type_rewrite(current_status):
                try:
                    await self._degraded.set_flag(
                        event_id,
                        EVENT_TYPE_ORM_REWRITE_SKIPPED_FLAG,
                        ORM_REWRITE_SKIP_HINT,
                        writer="EventService",
                    )
                except Exception:
                    logger.warning(
                        "failed to set %s for event_id=%s",
                        EVENT_TYPE_ORM_REWRITE_SKIPPED_FLAG,
                        event_id,
                        exc_info=True,
                    )
                return OrmEventTypeRewriteOutcome.SKIPPED_LOCKED

            if skipped_human:
                return OrmEventTypeRewriteOutcome.SKIPPED_HUMAN

            if applied and result is not None and summary is not None:
                await self._sync_event_summary_after_mutation(
                    event_id,
                    committed_version=result.row_version,
                    summary=summary,
                )
                if self._bus is not None:
                    await self._bus.publish_event(
                        event_id,
                        "event_type_rewritten",
                        {
                            "event_type": new_type,
                            "previous_event_type": previous_type,
                            "operator": operator,
                        },
                    )
                return OrmEventTypeRewriteOutcome.APPLIED

            return OrmEventTypeRewriteOutcome.NOOP
        except Exception:
            logger.warning(
                "triage ORM event_type rewrite failed event_id=%s",
                event_id,
                exc_info=True,
            )
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        session.add(
                            orm.EventAuditLog(
                                event_id=event_id,
                                from_status=None,
                                to_status=None,
                                operator=operator,
                                reason=f"event_type_orm_rewrite_failed:{new_type}",
                            )
                        )
            except Exception:
                logger.warning(
                    "audit write for ORM rewrite failure also failed event_id=%s",
                    event_id,
                    exc_info=True,
                )
            try:
                await self._degraded.set_flag(
                    event_id,
                    EVENT_TYPE_ORM_REWRITE_FAILED_FLAG,
                    True,
                    writer="EventService",
                )
            except Exception:
                logger.warning(
                    "failed to set %s for event_id=%s",
                    EVENT_TYPE_ORM_REWRITE_FAILED_FLAG,
                    event_id,
                    exc_info=True,
                )
            return OrmEventTypeRewriteOutcome.FAILED

    async def upsert_report(
        self,
        report: InvestigationReport,
    ) -> InvestigationReport:
        """Idempotent upsert of InvestigationReport by stable ``report_id`` (ISSUE-036).

        ISSUE-212: persists ``report_quality`` as stamped by the caller. Complete→
        degraded refusal (HTTP 409) is enforced only on ``POST /report``, not here,
        so ReportAgent / graph regeneration can honestly rewrite quality grades.
        """
        from app.services.report_quality import report_quality_from_row

        now = datetime.now(UTC)
        stamped_sections = stamp_report_observability_in_sections(
            report.sections,
            warnings=list(report.warnings),
            error_detail=report.error_detail,
        )
        sections_payload = [section.model_dump(mode="json") for section in stamped_sections]
        quality_value = (
            report.report_quality.value
            if hasattr(report.report_quality, "value")
            else str(report.report_quality or "complete")
        )
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.Report,
                    report.report_id,
                    with_for_update=True,
                )
                if row is None:
                    row = orm.Report(
                        report_id=report.report_id,
                        event_id=report.event_id,
                        title=report.title,
                        summary=report.summary,
                        sections=sections_payload,
                        final_verdict=report.final_verdict.value,
                        risk_score=int(report.risk_score),
                        severity=report.severity.value,
                        version=1,
                        generated_by=report.generated_by,
                        report_quality=quality_value,
                        generated_at=report.generated_at or now,
                        updated_at=now,
                    )
                    session.add(row)
                else:
                    if row.event_id != report.event_id:
                        raise ValidationError(
                            "report_id already bound to a different event_id",
                            details={
                                "report_id": report.report_id,
                                "existing_event_id": row.event_id,
                                "incoming_event_id": report.event_id,
                            },
                        )
                    row.title = report.title
                    row.summary = report.summary
                    row.sections = sections_payload
                    row.final_verdict = report.final_verdict.value
                    row.risk_score = int(report.risk_score)
                    row.severity = report.severity.value
                    row.version = int(row.version or 1) + 1
                    row.generated_by = report.generated_by
                    row.report_quality = quality_value
                    if report.generated_at is not None:
                        row.generated_at = report.generated_at
                    row.updated_at = now
                await session.flush()
                await session.refresh(row)
                return InvestigationReport(
                    report_id=row.report_id,
                    event_id=row.event_id,
                    title=row.title,
                    summary=row.summary,
                    sections=stamped_sections,
                    final_verdict=FinalVerdict(row.final_verdict),
                    risk_score=int(row.risk_score),
                    severity=Severity(row.severity),
                    version=int(row.version),
                    generated_by=row.generated_by,
                    generated_at=row.generated_at,
                    updated_at=row.updated_at,
                    warnings=list(report.warnings),
                    error_detail=report.error_detail,
                    report_quality=report_quality_from_row(getattr(row, "report_quality", None)),
                )

    async def get_report(
        self,
        *,
        report_id: str | None = None,
        event_id: str | None = None,
    ) -> InvestigationReport | None:
        """Load a persisted report by ``report_id`` or ``event_id``."""
        if report_id is None and event_id is None:
            raise ValidationError("get_report requires report_id or event_id")
        async with self._session_factory() as session:
            row: orm.Report | None = None
            if report_id is not None:
                row = await session.get(orm.Report, report_id)
            elif event_id is not None:
                row = await session.scalar(
                    select(orm.Report)
                    .where(orm.Report.event_id == event_id)
                    .order_by(orm.Report.updated_at.desc())
                    .limit(1)
                )
            if row is None:
                return None
            from app.models.report import ReportSection
            from app.services.report_quality import report_quality_from_row

            sections = [ReportSection.model_validate(item) for item in (row.sections or [])]
            warnings, error_detail = observability_from_sections(sections)
            return InvestigationReport(
                report_id=row.report_id,
                event_id=row.event_id,
                title=row.title,
                summary=row.summary,
                sections=sections,
                final_verdict=FinalVerdict(row.final_verdict),
                risk_score=int(row.risk_score),
                severity=Severity(row.severity),
                version=int(row.version),
                generated_by=row.generated_by,
                generated_at=row.generated_at,
                updated_at=row.updated_at,
                warnings=warnings,
                error_detail=error_detail,
                report_quality=report_quality_from_row(getattr(row, "report_quality", None)),
            )

    async def upsert_generate_report_action(
        self,
        event_id: str,
        *,
        plan_revision: int = 1,
    ) -> str:
        """Idempotent system Action for local report generation (ISSUE-036)."""
        now = datetime.now(UTC)
        material = f"{event_id}|{int(plan_revision)}|generate_report|system|system||immediate|"
        fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()
        async with self._session_factory() as session:
            async with session.begin():
                existing = await session.scalar(
                    select(orm.Action).where(orm.Action.action_fingerprint == fingerprint)
                )
                if existing is not None:
                    existing.status = "success"
                    existing.executed_at = now
                    existing.updated_at = now
                    existing.reason = "报告自动生成"
                    await session.flush()
                    return existing.action_id

                action_id = new_action_id()
                session.add(
                    orm.Action(
                        action_id=action_id,
                        event_id=event_id,
                        plan_revision=int(plan_revision),
                        action_fingerprint=fingerprint,
                        action_category="system",
                        action_name="generate_report",
                        tool_name="generate_report",
                        action_level="l0",
                        target_type="system",
                        target="system",
                        parameters={},
                        status="success",
                        auto_execute=True,
                        reason="报告自动生成",
                        impact_assessment=None,
                        execution_owner=None,
                        writeback_required=False,
                        writeback_applicable=False,
                        writeback_readiness="not_required",
                        writeback_status=None,
                        executed_at=now,
                        source_action_id=None,
                    )
                )
                await session.flush()
                return action_id

    async def upsert_response_plan_actions(
        self,
        event_id: str,
        *,
        plan_revision: int,
        actions: list[Action],
        response_plan: ResponsePlan | None = None,
    ) -> list[Action]:
        """Idempotent upsert of ResponsePlan actions by ``action_fingerprint`` (ISSUE-057)."""
        from app.agents.response_agent import _upsert_action_row

        persisted: list[Action] = []
        async with self._session_factory() as session:
            async with session.begin():
                for action in actions:
                    if action.event_id != event_id:
                        raise ValidationError(
                            "action.event_id mismatch",
                            details={"expected": event_id, "actual": action.event_id},
                        )
                    action_id = await _upsert_action_row(session, action)
                    persisted.append(action.model_copy(update={"action_id": action_id}))
                if response_plan is not None:
                    await append_context_journal_in_session(
                        session,
                        event_id,
                        "response_plan",
                        response_plan.model_dump(mode="json"),
                    )
        return persisted

    async def supersede_undeployed_deferred(
        self,
        event_id: str,
        *,
        old_revision: int,
        new_revision: int,
    ) -> int:
        """Mark undeployed deferred actions SUPERSEDED when replanning (ISSUE-057)."""
        from app.agents.response_agent import _supersede_undeployed_deferred

        async with self._session_factory() as session:
            async with session.begin():
                return await _supersede_undeployed_deferred(
                    session,
                    event_id=event_id,
                    old_revision=int(old_revision),
                    new_revision=int(new_revision),
                )

    async def transition_status(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: TransitionContext | None = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> SecurityEvent:
        """Delegate status change to StateMachineService (ISSUE-037).

        EventService never writes ``security_event.status`` itself.  All
        validation — including the CLOSED writeback gate — happens inside
        ``StateMachineService.transition()`` under ``SELECT … FOR UPDATE``.
        No pre-validation is done here; the single authoritative path avoids
        TOCTOU windows, duplicate DB queries, and stale context projections.
        """
        if self._state_machine is None:
            raise DependencyUnavailableError(
                "StateMachineService is required for status transitions",
                details={"event_id": event_id, "target": target.value},
            )
        return await self._state_machine.transition(
            event_id,
            target,
            context=context,
            operator=operator,
            reason=reason,
        )

    # Intentionally NO update_event_status — status writes live in ISSUE-037 only.

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _sync_event_summary_after_mutation(
        self,
        event_id: str,
        *,
        committed_version: int,
        summary: EventSummary,
    ) -> None:
        """Sync Context, then reconcile if a newer event commit won the race."""
        context_result = await self._store.set(event_id, "event", summary)
        redis_ok = context_result.redis_ok

        # Another transaction may commit after this caller releases its row lock
        # but before this Context write. Re-read PG and make the newest row win.
        async with self._session_factory() as session:
            latest = await session.get(orm.SecurityEvent, event_id)
        if latest is not None and int(latest.row_version or 1) != committed_version:
            latest_result = await self._store.set(
                event_id,
                "event",
                event_summary_from_security_event(latest),
            )
            redis_ok = redis_ok and latest_result.redis_ok

        if not redis_ok:
            logger.warning(
                "Redis context event sync failed for event_id=%s; marking degraded",
                event_id,
            )
            await self._degraded.set_flag(
                event_id,
                "redis_context_unavailable",
                True,
                writer="EventService",
            )

    async def _authoritative_verdict_context(
        self, session: AsyncSession, event_id: str
    ) -> TransitionContext:
        """Build trusted verdict gates from PostgreSQL, never caller input."""
        journal_value = await session.scalar(
            select(orm.EventContextJournal.value)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name == "disposition_only_intent",
            )
            .order_by(orm.EventContextJournal.version.desc())
            .limit(1)
        )
        if isinstance(journal_value, dict) and set(journal_value) == {"_scalar"}:
            journal_value = journal_value["_scalar"]
        disposition_only_intent = journal_value is True

        current_revision = await session.scalar(
            select(func.max(orm.Action.plan_revision)).where(orm.Action.event_id == event_id)
        )
        response_actions: list[orm.Action] = []
        if current_revision is not None:
            response_actions = list(
                (
                    await session.scalars(
                        select(orm.Action).where(
                            orm.Action.event_id == event_id,
                            orm.Action.plan_revision == current_revision,
                            orm.Action.action_category == "response",
                            orm.Action.superseded_by_revision.is_(None),
                        )
                    )
                ).all()
            )

        response_actions_are_disposition_only: bool | None = None
        has_entity_side_effect_actions = False
        if response_actions:
            response_actions_are_disposition_only = all(
                action.action_name == TERMINAL_DISPOSITION_TOOL for action in response_actions
            )
            has_entity_side_effect_actions = any(
                action.action_name != TERMINAL_DISPOSITION_TOOL for action in response_actions
            )

        return TransitionContext(
            disposition_only_intent=disposition_only_intent,
            response_actions_are_disposition_only=response_actions_are_disposition_only,
            has_entity_side_effect_actions=has_entity_side_effect_actions,
        )

    async def _post_create_side_effects(
        self,
        row: orm.SecurityEvent,
        *,
        force_context_refresh: bool,
        publish_event: bool,
    ) -> None:
        """Idempotently ensure Context after the authoritative event commit.

        An earlier request may have committed ``security_event`` and then failed
        before ``init_context``. Repeated delivery must repair that partial state
        rather than returning a permanently context-less event.

        ``event_created`` is published only for created/promoted paths — never for
        context-repair / idempotent losers — to avoid duplicate bus events.
        """
        summary = event_summary_from_security_event(row)
        init_result = await self._store.init_context(row.event_id, summary)
        initialized_now = init_result.initialized
        redis_ok = init_result.redis_ok
        if not initialized_now and force_context_refresh:
            set_result = await self._store.set(row.event_id, "event", summary)
            redis_ok = redis_ok and set_result.redis_ok

        snapshot_result = await self._ensure_source_snapshot(
            row,
            overwrite=force_context_refresh,
        )
        redis_ok = redis_ok and snapshot_result

        if not redis_ok:
            logger.warning(
                "Redis context sync failed for event_id=%s; marking degraded",
                row.event_id,
            )
            await self._degraded.set_flag(
                row.event_id,
                "redis_context_unavailable",
                True,
                writer="EventService",
            )
        if self._bus is not None and publish_event:
            await self._bus.publish_event(
                row.event_id,
                "event_created",
                {
                    "status": row.status,
                    "event_type": row.event_type,
                    "title": row.title,
                },
            )

    async def _ensure_source_snapshot(
        self,
        row: orm.SecurityEvent,
        *,
        overwrite: bool,
    ) -> bool:
        """Write immutable source evidence; repair when the field was never initialized.

        ``overwrite=True`` (create/promote) refreshes snapshots after association
        changes. ``overwrite=False`` (idempotent replay) only fills a missing
        field so a crash between ``event`` init and snapshot write can heal.
        """
        snapshot = _source_snapshot_from_row(row)
        if not _snapshot_has_risk_baseline(snapshot):
            async with self._session_factory() as session:
                source_record_id = row.current_primary_source_record_id
                if source_record_id:
                    source_obj = await session.get(orm.SourceObject, source_record_id)
                    if source_obj is not None and source_obj.normalized:
                        baseline = _normalized_baseline_from_dict(
                            dict(source_obj.normalized),
                            event_type=row.event_type,
                        )
                        if baseline:
                            existing_norm = (
                                dict(snapshot["normalized"])
                                if isinstance(snapshot.get("normalized"), dict)
                                else {}
                            )
                            snapshot = {
                                **snapshot,
                                "normalized": {**existing_norm, **baseline},
                            }
        if not overwrite:
            async with self._session_factory() as session:
                exists = await session.scalar(
                    select(orm.EventContextFieldVersion.current_version).where(
                        orm.EventContextFieldVersion.event_id == row.event_id,
                        orm.EventContextFieldVersion.field_name == "source_snapshot",
                    )
                )
            if exists is not None:
                # Heal incomplete snapshots that predate ISSUE-102 baseline fields.
                if _snapshot_has_risk_baseline(snapshot):
                    existing = await self._store.get(row.event_id, "source_snapshot")
                    if isinstance(existing, dict) and not _snapshot_has_risk_baseline(existing):
                        repaired = {
                            **existing,
                            "normalized": dict(snapshot["normalized"]),
                        }
                        if existing.get("severity") is None and snapshot.get("severity"):
                            repaired["severity"] = snapshot["severity"]
                        result = await self._store.set(
                            row.event_id,
                            "source_snapshot",
                            repaired,
                        )
                        return result.redis_ok
                return True
        result = await self._store.set(row.event_id, "source_snapshot", snapshot)
        return result.redis_ok

    async def _ingest_with_unique_retry(self, source: IngestableSource) -> _CreateBundle:
        """Resolve concurrent delivery races by rereading the canonical row/link."""
        try:
            return await self._ingest(source)
        except IntegrityError as exc:
            if getattr(exc.orig, "sqlstate", None) != "23505":
                raise
            logger.info(
                "Concurrent source ingest won by another transaction; rereading "
                "canonical link connector_id=%s source_object_id=%s",
                source.reference.connector_id,
                source.reference.source_object_id,
            )
            return await self._ingest(source)

    @staticmethod
    def _validate_explicit_associations(source: IngestableSource) -> None:
        """Reject malformed or cross-connector explicit associations."""
        primary = source.reference
        associations: list[tuple[SourceReference, SourceObjectKind]] = []
        if source.incident_ref is not None:
            associations.append((source.incident_ref, SourceObjectKind.INCIDENT))
        associations.extend(
            (related, SourceObjectKind.ALERT) for related in source.related_alert_refs
        )
        primary_scope = (
            primary.source_product,
            primary.source_tenant_id,
            primary.connector_id,
        )
        for related, expected_kind in associations:
            if related.source_kind is not expected_kind:
                raise ValidationError(
                    "explicit source association has invalid kind or source scope",
                    error_code="adapter_validation_error",
                    details={
                        "source_object_id": primary.source_object_id,
                        "related_source_object_id": related.source_object_id,
                        "expected_kind": expected_kind.value,
                    },
                )
            if expected_kind is SourceObjectKind.INCIDENT:
                # Logs/assets may arrive on a different connector than the parent incident.
                if (
                    related.source_product != primary.source_product
                    or related.source_tenant_id != primary.source_tenant_id
                ):
                    raise ValidationError(
                        "explicit source association has invalid kind or source scope",
                        error_code="adapter_validation_error",
                        details={
                            "source_object_id": primary.source_object_id,
                            "related_source_object_id": related.source_object_id,
                            "expected_kind": expected_kind.value,
                        },
                    )
                continue
            related_scope = (
                related.source_product,
                related.source_tenant_id,
                related.connector_id,
            )
            if related_scope != primary_scope:
                raise ValidationError(
                    "explicit source association has invalid kind or source scope",
                    error_code="adapter_validation_error",
                    details={
                        "source_object_id": primary.source_object_id,
                        "related_source_object_id": related.source_object_id,
                        "expected_kind": expected_kind.value,
                    },
                )

    async def _ingest(self, source: IngestableSource) -> _CreateBundle:
        self._validate_explicit_associations(source)
        ref = source.reference
        identity = canonical_source_identity(
            source_product=ref.source_product,
            source_tenant_id=ref.source_tenant_id,
            connector_id=ref.connector_id,
            source_kind=ref.source_kind.value,
            source_object_id=ref.source_object_id,
        )
        source_record_id = stable_source_record_id(identity=identity)
        occurred = source.occurred_at or ref.source_updated_at or datetime.now(UTC)

        async with self._session_factory() as session:
            async with session.begin():
                await self._ensure_connector(session, source)
                obj = await self._upsert_source_object(session, source, source_record_id)

                # Idempotent: same source object already linked.
                existing_link = await session.scalar(
                    select(orm.SourceEventLink)
                    .where(orm.SourceEventLink.source_record_id == source_record_id)
                    .order_by(
                        case(
                            (orm.SourceEventLink.role == LINK_ROLE_PRIMARY, 0),
                            (orm.SourceEventLink.role == LINK_ROLE_PROVISIONAL, 1),
                            else_=2,
                        ),
                        orm.SourceEventLink.id,
                    )
                )
                if existing_link is not None:
                    event = await session.get(orm.SecurityEvent, existing_link.event_id)
                    assert event is not None
                    return _CreateBundle(
                        event=event,
                        source_record_id=source_record_id,
                        created=False,
                        idempotent=True,
                        source_object_id=ref.source_object_id,
                        source_revision=int(obj.current_state_version),
                        link_role=existing_link.role,
                    )

                # Related Alert/Log/Asset with verified incident_ref → link to parent event.
                if source.incident_ref is not None and ref.source_kind in (
                    SourceObjectKind.ALERT,
                    SourceObjectKind.LOG,
                    SourceObjectKind.ASSET,
                ):
                    parent_bundle = await self._link_related_source_to_incident_event(
                        session, source, obj, source_record_id
                    )
                    if parent_bundle is not None:
                        return parent_bundle

                # Incident with verified related alerts → promote provisional children.
                if ref.source_kind is SourceObjectKind.INCIDENT and source.related_alert_refs:
                    promoted = await self._promote_or_relate_alerts(
                        session, source, obj, source_record_id, occurred
                    )
                    if promoted is not None:
                        return promoted

                # Fresh event (provisional for orphan alert; primary for incident/other).
                event = await self._create_new_event(
                    session, source, obj, source_record_id, occurred
                )
                link_role = (
                    LINK_ROLE_PROVISIONAL
                    if ref.source_kind is SourceObjectKind.ALERT
                    else LINK_ROLE_PRIMARY
                )
                intent_id = await self._attach_auto_investigate_intent(
                    session,
                    event,
                    source,
                    link_role=link_role,
                    created_or_promoted=True,
                )
                return _CreateBundle(
                    event=event,
                    source_record_id=source_record_id,
                    created=True,
                    intent_ids=(intent_id,) if intent_id else (),
                    source_object_id=ref.source_object_id,
                    source_revision=int(obj.current_state_version),
                    link_role=link_role,
                )

    async def _ensure_connector(
        self, session: AsyncSession, source: IngestableSource
    ) -> orm.SourceConnector:
        ref = source.reference
        connector = await session.get(orm.SourceConnector, ref.connector_id)
        if connector is not None:
            metadata = dict(connector.connector_metadata or {})
            metadata_tenant = metadata.get("source_tenant_id")
            if metadata_tenant is None:
                existing_tenants = set(
                    (
                        await session.scalars(
                            select(orm.SourceObject.source_tenant_id)
                            .where(orm.SourceObject.connector_id == ref.connector_id)
                            .distinct()
                        )
                    ).all()
                )
            else:
                existing_tenants = {str(metadata_tenant)}
            if connector.source_product != ref.source_product or existing_tenants - {
                ref.source_tenant_id
            }:
                raise ValidationError(
                    "connector tenant or product ownership conflicts with source reference",
                    error_code="adapter_validation_error",
                    details={
                        "connector_id": ref.connector_id,
                        "existing_source_product": connector.source_product,
                        "incoming_source_product": ref.source_product,
                        "existing_source_tenant_ids": sorted(existing_tenants),
                        "incoming_source_tenant_id": ref.source_tenant_id,
                    },
                )
            metadata["source_tenant_id"] = ref.source_tenant_id
            if source.source_type:
                existing_adapter = metadata.get("ingestion_adapter")
                if existing_adapter not in (None, source.source_type):
                    raise ValidationError(
                        "connector cannot be reassigned to a different ingestion adapter",
                        error_code="adapter_validation_error",
                        details={
                            "connector_id": ref.connector_id,
                            "existing_adapter": existing_adapter,
                            "incoming_adapter": source.source_type,
                        },
                    )
                metadata["ingestion_adapter"] = source.source_type
            connector.connector_metadata = metadata
            return connector
        settings = get_settings()
        is_mock = ref.source_product == "mock_xdr" or settings.source_mode == "mock_xdr"
        is_file_or_manual = (source.source_type or "").strip().lower() in {
            "file",
            "manual",
        }
        is_live = (source.source_type or "").strip().lower() == "live" or (
            settings.source_mode == "live" and not is_mock and not is_file_or_manual
        )
        if is_live:
            raise ValidationError(
                "live connector must be provisioned with explicit disposition_policy_default",
                error_code="adapter_validation_error",
                details={
                    "connector_id": ref.connector_id,
                    "source_product": ref.source_product,
                },
            )
        connector = orm.SourceConnector(
            connector_id=ref.connector_id,
            source_product=ref.source_product,
            display_name=ref.connector_id,
            disposition_policy_default=(
                DispositionPolicy.REQUIRED.value
                if is_mock
                else DispositionPolicy.NOT_REQUIRED.value
            ),
            connector_metadata=(
                {
                    **({"ingestion_adapter": source.source_type} if source.source_type else {}),
                    "source_tenant_id": ref.source_tenant_id,
                }
            ),
        )
        session.add(connector)
        await session.flush()
        return connector

    async def _upsert_source_object(
        self,
        session: AsyncSession,
        source: IngestableSource,
        source_record_id: str,
    ) -> orm.SourceObject:
        ref = source.reference
        existing = await session.scalar(
            select(orm.SourceObject)
            .where(
                orm.SourceObject.source_product == ref.source_product,
                orm.SourceObject.source_tenant_id == ref.source_tenant_id,
                orm.SourceObject.connector_id == ref.connector_id,
                orm.SourceObject.source_kind == ref.source_kind.value,
                orm.SourceObject.source_object_id == ref.source_object_id,
            )
            .with_for_update()
        )
        if existing is not None:
            if not should_apply_source_update(
                stored_updated_at=existing.current_source_updated_at,
                stored_token=existing.current_concurrency_token,
                incoming_updated_at=ref.source_updated_at,
                incoming_token=ref.source_concurrency_token,
            ):
                return existing
            # Mutable current_* only — never overwrite investigation snapshot.
            existing.current_source_status_raw = ref.source_status_raw
            existing.current_source_disposition = ref.source_disposition.value
            existing.current_concurrency_token = ref.source_concurrency_token
            existing.current_source_updated_at = ref.source_updated_at
            existing.current_state_version += 1
            if source.normalized:
                existing.normalized = source.normalized
            await session.flush()
            return existing

        obj = orm.SourceObject(
            source_record_id=source_record_id,
            source_product=ref.source_product,
            source_tenant_id=ref.source_tenant_id,
            connector_id=ref.connector_id,
            source_kind=ref.source_kind.value,
            source_object_id=ref.source_object_id,
            source_object_type=ref.source_object_type,
            parent_source_object_id=ref.parent_source_object_id,
            source_status_raw=ref.source_status_raw,
            source_disposition=ref.source_disposition.value,
            source_concurrency_token=ref.source_concurrency_token,
            source_updated_at=ref.source_updated_at,
            schema_version=ref.schema_version,
            ingested_at=ref.ingested_at or datetime.now(UTC),
            raw_payload_hash=ref.raw_payload_hash,
            normalized=source.normalized or {},
            raw_payload=source.raw_payload or {},
            current_source_status_raw=ref.source_status_raw,
            current_source_disposition=ref.source_disposition.value,
            current_concurrency_token=ref.source_concurrency_token,
            current_source_updated_at=ref.source_updated_at,
            current_state_version=1,
        )
        session.add(obj)
        await session.flush()
        return obj

    async def _resolve_policy(
        self, session: AsyncSession, source: IngestableSource
    ) -> DispositionPolicy:
        connector = await session.get(orm.SourceConnector, source.reference.connector_id)
        settings = get_settings()
        source_type = source.source_type
        if source_type is None and source.reference.source_product == "file":
            source_type = "file"
        normalized_type = (source_type or "").strip().lower()
        product = (source.reference.source_product or "").strip().lower()
        mode = (settings.source_mode or "").strip().lower()
        is_mock = product == "mock_xdr" or mode == "mock_xdr"
        is_file_or_manual = normalized_type in {"file", "manual"}
        is_live = normalized_type == "live" or (
            mode == "live" and not is_mock and not is_file_or_manual
        )
        connector_policy = connector_policy_from_row(connector)
        try:
            policy = self._policy.resolve(
                source_type=source_type,
                source_kind=source.reference.source_kind,
                source_product=source.reference.source_product,
                connector_policy_default=connector_policy,
                source_mode=settings.source_mode,
                live_configured=is_live and connector_policy is None,
            )
        except ValueError as exc:
            raise ValidationError(
                str(exc),
                error_code="adapter_validation_error",
                details={
                    "connector_id": source.reference.connector_id,
                    "source_product": source.reference.source_product,
                    "source_mode": settings.source_mode,
                },
            ) from exc
        return policy

    async def _create_new_event(
        self,
        session: AsyncSession,
        source: IngestableSource,
        obj: orm.SourceObject,
        source_record_id: str,
        occurred: datetime,
    ) -> orm.SecurityEvent:
        ref = source.reference
        identity = canonical_source_identity(
            source_product=ref.source_product,
            source_tenant_id=ref.source_tenant_id,
            connector_id=ref.connector_id,
            source_kind=ref.source_kind.value,
            source_object_id=ref.source_object_id,
        )
        event_id = new_event_id(identity, occurred)
        existing = await session.get(orm.SecurityEvent, event_id)
        if existing is not None:
            # Rare: event_id collision with different source — attach related link.
            session.add(
                orm.SourceEventLink(
                    source_record_id=source_record_id,
                    event_id=event_id,
                    role=LINK_ROLE_RELATED,
                    promotion_status=PROMOTION_NONE,
                )
            )
            await session.flush()
            return existing

        policy = await self._resolve_policy(session, source)
        role = (
            LINK_ROLE_PROVISIONAL
            if ref.source_kind is SourceObjectKind.ALERT
            else LINK_ROLE_PRIMARY
        )
        disposition_ref: dict[str, Any] | None
        if ref.source_kind is SourceObjectKind.INCIDENT:
            disposition_ref = locator_from_reference(ref).model_dump(mode="json")
        elif ref.source_kind is SourceObjectKind.ALERT:
            disposition_ref = locator_from_reference(ref).model_dump(mode="json")
        else:
            disposition_ref = None

        title = source.title or f"{ref.source_kind.value}:{ref.source_object_id}"
        event_type = source.event_type or EventType.OTHER
        severity = source.severity or Severity.LOW
        raw_alert_ids = [ref.source_object_id] if ref.source_kind is SourceObjectKind.ALERT else []
        raw_alert_snapshot: dict[str, Any] | None = None
        normalized = source.normalized or {}
        fp_meta: dict[str, Any] = {}
        fp_rule = normalized.get("fp_rule")
        if isinstance(fp_rule, str) and fp_rule:
            fp_meta["fp_rule"] = fp_rule
        scenario_id = normalized.get("scenario")
        if isinstance(scenario_id, str) and scenario_id:
            fp_meta["scenario"] = scenario_id
        normalized_baseline = _normalized_baseline_from_dict(
            normalized,
            event_type=event_type.value,
        )
        if fp_meta or normalized_baseline:
            raw_alert_snapshot = dict(fp_meta)
            if normalized_baseline:
                raw_alert_snapshot["normalized"] = normalized_baseline

        row = orm.SecurityEvent(
            event_id=event_id,
            event_type=event_type.value,
            title=title,
            description=source.description,
            status=EventStatus.NEW.value,
            severity=severity.value,
            final_verdict=FinalVerdict.NONE.value,
            entities=_entities_from_source_ref(ref, source.normalized or {}),
            creation_source_ref=_ref_dump(ref),
            source_reference_snapshots=[_ref_dump(ref)],
            current_primary_source_record_id=source_record_id,
            disposition_source_ref=disposition_ref,
            disposition_policy=policy.value,
            raw_alert_ids=raw_alert_ids,
            raw_alert_snapshot=raw_alert_snapshot,
            source_type=source.source_type or ref.source_product,
            occurred_at=occurred,
        )
        session.add(row)
        session.add(
            orm.SourceEventLink(
                source_record_id=source_record_id,
                event_id=event_id,
                role=role,
                promotion_status=PROMOTION_NONE,
            )
        )
        session.add(
            orm.EventAuditLog(
                event_id=event_id,
                from_status=None,
                to_status=EventStatus.NEW.value,
                operator="EventService",
                reason="event_created",
            )
        )
        await session.flush()
        await session.refresh(row)
        return row

    async def _find_source_by_ref(
        self, session: AsyncSession, ref: SourceReference
    ) -> orm.SourceObject | None:
        obj: orm.SourceObject | None = await session.scalar(
            select(orm.SourceObject).where(
                orm.SourceObject.source_product == ref.source_product,
                orm.SourceObject.source_tenant_id == ref.source_tenant_id,
                orm.SourceObject.connector_id == ref.connector_id,
                orm.SourceObject.source_kind == ref.source_kind.value,
                orm.SourceObject.source_object_id == ref.source_object_id,
            )
        )
        return obj

    async def _link_related_source_to_incident_event(
        self,
        session: AsyncSession,
        source: IngestableSource,
        related_obj: orm.SourceObject,
        related_record_id: str,
    ) -> _CreateBundle | None:
        """When a related source carries verified incident_ref → link to parent event."""
        assert source.incident_ref is not None
        parent_obj = await self._find_source_by_ref(session, source.incident_ref)
        if parent_obj is None:
            return None
        parent_link = await session.scalar(
            select(orm.SourceEventLink).where(
                orm.SourceEventLink.source_record_id == parent_obj.source_record_id,
                orm.SourceEventLink.role.in_([LINK_ROLE_PRIMARY, LINK_ROLE_PROVISIONAL]),
            )
        )
        if parent_link is None:
            return None
        event = await session.get(orm.SecurityEvent, parent_link.event_id)
        if event is None:
            return None

        snapshots = list(event.source_reference_snapshots or [])
        snapshots.append(_ref_dump(source.reference))
        event.source_reference_snapshots = snapshots
        if source.reference.source_kind is SourceObjectKind.ALERT:
            alert_ids = list(event.raw_alert_ids or [])
            if source.reference.source_object_id not in alert_ids:
                alert_ids.append(source.reference.source_object_id)
                event.raw_alert_ids = alert_ids
        event.row_version = int(event.row_version or 1) + 1

        await self._refresh_event_entities_from_sources(session, event)

        session.add(
            orm.SourceEventLink(
                source_record_id=related_record_id,
                event_id=event.event_id,
                role=LINK_ROLE_RELATED,
                promotion_status=PROMOTION_NONE,
            )
        )
        session.add(
            orm.EventAuditLog(
                event_id=event.event_id,
                from_status=event.status,
                to_status=event.status,
                operator="EventService",
                reason="related_source_linked_to_incident_event",
            )
        )
        await session.flush()
        await session.refresh(event)
        return _CreateBundle(
            event=event,
            source_record_id=related_record_id,
            created=False,
            idempotent=False,
            source_object_id=source.reference.source_object_id,
            source_revision=int(related_obj.current_state_version),
            link_role=LINK_ROLE_RELATED,
        )

    async def _event_has_merge_blockers(self, session: AsyncSession, event_id: str) -> bool:
        action = await session.scalar(
            select(orm.Action.action_id).where(orm.Action.event_id == event_id).limit(1)
        )
        if action is not None:
            return True

        # Do not destructively merge an event once investigation artifacts exist.
        activity_queries = (
            select(orm.Evidence.evidence_id).where(orm.Evidence.event_id == event_id).limit(1),
            select(orm.Report.report_id).where(orm.Report.event_id == event_id).limit(1),
            select(orm.AgentTrace.trace_id).where(orm.AgentTrace.event_id == event_id).limit(1),
            select(orm.ToolCallLog.call_id).where(orm.ToolCallLog.event_id == event_id).limit(1),
            select(orm.LLMCallLog.id).where(orm.LLMCallLog.event_id == event_id).limit(1),
        )
        for query in activity_queries:
            if await session.scalar(query) is not None:
                return True

        # ``event`` and ``source_snapshot`` are ingestion initialization records.
        # Any other context field means an Agent/Service has started work
        # (including approval_records).
        context_activity = await session.scalar(
            select(orm.EventContextJournal.id)
            .where(
                orm.EventContextJournal.event_id == event_id,
                orm.EventContextJournal.field_name.not_in(("event", "source_snapshot")),
            )
            .limit(1)
        )
        return context_activity is not None

    async def _merge_provisional_event(
        self,
        session: AsyncSession,
        *,
        target: orm.SecurityEvent,
        secondary: orm.SecurityEvent,
    ) -> None:
        """Move a pristine provisional event into ``target`` and remove it."""
        snapshots = list(target.source_reference_snapshots or [])
        seen_snapshots = {
            (
                str(item.get("source_product")),
                str(item.get("source_tenant_id")),
                str(item.get("connector_id")),
                str(item.get("source_kind")),
                str(item.get("source_object_id")),
            )
            for item in snapshots
        }
        for item in secondary.source_reference_snapshots or []:
            identity = (
                str(item.get("source_product")),
                str(item.get("source_tenant_id")),
                str(item.get("connector_id")),
                str(item.get("source_kind")),
                str(item.get("source_object_id")),
            )
            if identity not in seen_snapshots:
                seen_snapshots.add(identity)
                snapshots.append(item)
        target.source_reference_snapshots = snapshots
        target.raw_alert_ids = list(
            dict.fromkeys([*(target.raw_alert_ids or []), *(secondary.raw_alert_ids or [])])
        )
        await self._refresh_event_entities_from_sources(session, target)

        links = (
            await session.scalars(
                select(orm.SourceEventLink).where(
                    orm.SourceEventLink.event_id == secondary.event_id
                )
            )
        ).all()
        for link in links:
            duplicate = await session.scalar(
                select(orm.SourceEventLink.id).where(
                    orm.SourceEventLink.source_record_id == link.source_record_id,
                    orm.SourceEventLink.event_id == target.event_id,
                )
            )
            if duplicate is not None:
                await session.delete(link)
            else:
                link.event_id = target.event_id
                link.role = LINK_ROLE_RELATED
                link.promotion_status = PROMOTION_PROMOTED

        # Preserve audit/data-quality history under the surviving event.
        await session.execute(
            update(orm.EventAuditLog)
            .where(orm.EventAuditLog.event_id == secondary.event_id)
            .values(event_id=target.event_id)
        )
        await session.execute(
            update(orm.DataQualityError)
            .where(orm.DataQualityError.event_id == secondary.event_id)
            .values(event_id=target.event_id)
        )
        await session.execute(
            delete(orm.EventContextJournal).where(
                orm.EventContextJournal.event_id == secondary.event_id
            )
        )
        await session.execute(
            delete(orm.EventContextFieldVersion).where(
                orm.EventContextFieldVersion.event_id == secondary.event_id
            )
        )
        if self._investigation_intent is not None:
            await self._investigation_intent.skip_active_intents_for_event_in_session(
                session,
                secondary.event_id,
                reason="event_merged",
            )
        await session.delete(secondary)

    async def _promote_or_relate_alerts(
        self,
        session: AsyncSession,
        source: IngestableSource,
        incident_obj: orm.SourceObject,
        incident_record_id: str,
        occurred: datetime,
    ) -> _CreateBundle | None:
        """Incident arrives with verified related_alert_refs → promote or relate."""
        provisional_events: list[orm.SecurityEvent] = []
        seen_source_records: set[str] = set()
        seen_event_ids: set[str] = set()
        for alert_ref in source.related_alert_refs:
            alert_obj = await self._find_source_by_ref(session, alert_ref)
            if alert_obj is None or alert_obj.source_record_id in seen_source_records:
                continue
            seen_source_records.add(alert_obj.source_record_id)
            link = await session.scalar(
                select(orm.SourceEventLink).where(
                    orm.SourceEventLink.source_record_id == alert_obj.source_record_id
                )
            )
            if link is None:
                continue
            event = await session.get(orm.SecurityEvent, link.event_id)
            if event is None:
                continue
            if link.role == LINK_ROLE_PROVISIONAL and event.event_id not in seen_event_ids:
                seen_event_ids.add(event.event_id)
                provisional_events.append(event)

        if not provisional_events:
            return None

        # Promote one pristine event, merge other pristine provisional events,
        # and keep only events with investigation state as separate related cases.
        target: orm.SecurityEvent | None = None
        blocked: list[orm.SecurityEvent] = []
        mergeable: list[orm.SecurityEvent] = []
        for event in provisional_events:
            if await self._event_has_merge_blockers(session, event.event_id):
                blocked.append(event)
            elif target is None:
                target = event
            else:
                mergeable.append(event)

        if target is None:
            # All provisional children blocked — create new incident event + related links.
            created = await self._create_new_event(
                session, source, incident_obj, incident_record_id, occurred
            )
            for event in blocked:
                await self._add_related_link_if_missing(session, incident_record_id, event.event_id)
                # Also link child event ↔ keep separate; mark related between events via audit.
                session.add(
                    orm.EventAuditLog(
                        event_id=event.event_id,
                        from_status=event.status,
                        to_status=event.status,
                        operator="EventService",
                        reason=f"related_to_incident_event:{created.event_id}",
                    )
                )
            await session.flush()
            return _CreateBundle(
                event=created,
                source_record_id=incident_record_id,
                created=True,
                related_only=True,
            )

        merged_event_ids: list[str] = []
        for secondary in mergeable:
            merged_event_ids.append(secondary.event_id)
            await self._merge_provisional_event(
                session,
                target=target,
                secondary=secondary,
            )

        # Atomic promotion: keep event_id / creation_source_ref; append Incident snapshot.
        snapshots = list(target.source_reference_snapshots or [])
        snapshots.append(_ref_dump(source.reference))
        target.source_reference_snapshots = snapshots
        target.current_primary_source_record_id = incident_record_id
        target.disposition_source_ref = locator_from_reference(source.reference).model_dump(
            mode="json"
        )
        policy = await self._resolve_policy(session, source)
        target.disposition_policy = policy.value
        if source.title:
            target.title = source.title
        target.row_version = int(target.row_version or 1) + 1

        await self._refresh_event_entities_from_sources(session, target)

        session.add(
            orm.SourceEventLink(
                source_record_id=incident_record_id,
                event_id=target.event_id,
                role=LINK_ROLE_PRIMARY,
                promotion_status=PROMOTION_PROMOTED,
            )
        )
        # Flip original provisional alert link promotion marker.
        alert_links = (
            await session.scalars(
                select(orm.SourceEventLink).where(
                    orm.SourceEventLink.event_id == target.event_id,
                    orm.SourceEventLink.role == LINK_ROLE_PROVISIONAL,
                )
            )
        ).all()
        for link in alert_links:
            link.promotion_status = PROMOTION_PROMOTED

        for other in blocked:
            session.add(
                orm.SourceEventLink(
                    source_record_id=incident_record_id,
                    event_id=other.event_id,
                    role=LINK_ROLE_RELATED,
                    promotion_status=PROMOTION_NONE,
                )
            )
            session.add(
                orm.EventAuditLog(
                    event_id=other.event_id,
                    from_status=other.status,
                    to_status=other.status,
                    operator="EventService",
                    reason=f"related_not_merged:{target.event_id}",
                )
            )

        session.add(
            orm.EventAuditLog(
                event_id=target.event_id,
                from_status=target.status,
                to_status=target.status,
                operator="EventService",
                reason="promoted_to_incident",
            )
        )
        await session.flush()
        await session.refresh(target)
        intent_id = await self._attach_auto_investigate_intent(
            session,
            target,
            source,
            link_role=LINK_ROLE_PRIMARY,
            created_or_promoted=True,
        )
        return _CreateBundle(
            event=target,
            source_record_id=incident_record_id,
            created=False,
            promoted=True,
            merged_event_ids=tuple(merged_event_ids),
            intent_ids=(intent_id,) if intent_id else (),
        )

    async def _refresh_event_entities_from_sources(
        self,
        session: AsyncSession,
        event: orm.SecurityEvent,
    ) -> None:
        """Project linked SourceObject normalized fields into ``SecurityEvent.entities``.

        Incident/alert refs come from ``creation_source_ref`` + ``source_reference_snapshots``.
        Supporting objects (asset/log) are folded in via the adapter-recorded
        ``parent_source_object_id`` back-reference so their structured host/account/process
        fields enrich entities without polluting the incident/alert snapshot set or creating
        a synthetic link. Associations are read, never inferred.
        """
        refs: list[SourceReference] = []
        creation = event.creation_source_ref
        if isinstance(creation, dict):
            refs.append(SourceReference.model_validate(creation))
        for item in event.source_reference_snapshots or []:
            if isinstance(item, dict):
                refs.append(SourceReference.model_validate(item))

        seen: set[tuple[str, str, str, str, str]] = set()
        sources: list[tuple[SourceReference, dict[str, Any]]] = []
        for ref in refs:
            if ref.identity in seen:
                continue
            seen.add(ref.identity)
            obj = await self._find_source_by_ref(session, ref)
            if obj is not None and obj.normalized:
                sources.append((ref, dict(obj.normalized)))

        for child_ref, child_normalized in await self._supporting_sources_for_refs(session, refs):
            if child_ref.identity in seen:
                continue
            seen.add(child_ref.identity)
            sources.append((child_ref, child_normalized))

        if not sources:
            return

        enrichment = enrich_entities_from_source(sources)
        validated = validate_entity_set(enrichment.entity_set, provenance="source")
        if validated.entity_set == EntitySet():
            return

        event.entities = validated.entity_set.model_dump(mode="json")

    @staticmethod
    async def _supporting_sources_for_refs(
        session: AsyncSession,
        refs: list[SourceReference],
    ) -> list[tuple[SourceReference, dict[str, Any]]]:
        """Resolve asset/log SourceObjects that declare one of ``refs`` as their parent.

        Supporting objects (assets, logs) carry the structured host/account/process fields
        that enrich entities but are ingested standalone. The adapter records their
        ``parent_source_object_id`` back to the owning incident/alert; we read that
        relationship rather than inferring one. Child objects may use a different
        connector than the parent (e.g. log-only vs disposition connectors).
        """
        parent_ids = {
            ref.source_object_id
            for ref in refs
            if ref.source_kind in (SourceObjectKind.INCIDENT, SourceObjectKind.ALERT)
        }
        if not parent_ids:
            return []
        products = {ref.source_product for ref in refs}
        tenants = {ref.source_tenant_id for ref in refs}
        children = (
            await session.scalars(
                select(orm.SourceObject).where(
                    orm.SourceObject.parent_source_object_id.in_(parent_ids),
                    orm.SourceObject.source_product.in_(products),
                    orm.SourceObject.source_tenant_id.in_(tenants),
                    orm.SourceObject.source_kind.in_(
                        [SourceObjectKind.LOG.value, SourceObjectKind.ASSET.value]
                    ),
                )
            )
        ).all()
        resolved: list[tuple[SourceReference, dict[str, Any]]] = []
        for obj in children:
            if obj.normalized:
                resolved.append((_ref_from_source_object(obj), dict(obj.normalized)))
        return resolved

    @staticmethod
    async def _resolve_linked_parent_for_supporting_ref(
        session: AsyncSession,
        ref: SourceReference,
        parent_id: str,
    ) -> tuple[orm.SourceObject, orm.SourceEventLink] | None:
        """Resolve a parent incident/alert when ``parent_id`` repeats across connectors.

        Supporting logs/assets may reference a parent by ``source_object_id`` alone while
        using a different ``connector_id``. When multiple parent rows share that id within
        the same product/tenant, prefer the candidate that already has an event link, with
        PRIMARY links winning over PROVISIONAL/related roles.
        """
        candidates = (
            await session.scalars(
                select(orm.SourceObject)
                .where(
                    orm.SourceObject.source_product == ref.source_product,
                    orm.SourceObject.source_tenant_id == ref.source_tenant_id,
                    orm.SourceObject.source_object_id == parent_id,
                    orm.SourceObject.source_kind.in_(
                        [SourceObjectKind.ALERT.value, SourceObjectKind.INCIDENT.value]
                    ),
                )
                .order_by(orm.SourceObject.source_record_id)
            )
        ).all()
        if not candidates:
            return None

        best: tuple[orm.SourceObject, orm.SourceEventLink] | None = None
        best_rank: tuple[int, str, int] | None = None
        for obj in candidates:
            link = await session.scalar(
                select(orm.SourceEventLink)
                .where(orm.SourceEventLink.source_record_id == obj.source_record_id)
                .order_by(
                    case(
                        (orm.SourceEventLink.role == LINK_ROLE_PRIMARY, 0),
                        (orm.SourceEventLink.role == LINK_ROLE_PROVISIONAL, 1),
                        else_=2,
                    ),
                    orm.SourceEventLink.id,
                )
            )
            if link is None:
                continue
            role_rank = (
                0
                if link.role == LINK_ROLE_PRIMARY
                else 1
                if link.role == LINK_ROLE_PROVISIONAL
                else 2
            )
            rank = (role_rank, obj.source_record_id, int(link.id or 0))
            if best_rank is None or rank < best_rank:
                best_rank = rank
                best = (obj, link)
        return best

    async def refresh_events_for_supporting_ref(self, ref: SourceReference) -> None:
        """Re-enrich the parent event once a supporting object (asset/log) is ingested.

        Supporting objects are persisted on their own poll pass with no direct event
        link. When the object declares a verified ``parent_source_object_id`` we resolve
        the parent incident/alert's event and recompute its source-derived entities so the
        supporting fields fold in. No link or snapshot is created — enrichment reads the
        parent relationship the adapter already recorded (never inferred).
        """
        parent_id = ref.parent_source_object_id
        if parent_id is None:
            return
        refreshed: orm.SecurityEvent | None = None
        async with self._session_factory() as session:
            async with session.begin():
                resolved = await self._resolve_linked_parent_for_supporting_ref(
                    session, ref, parent_id
                )
                if resolved is None:
                    return
                _parent_obj, parent_link = resolved
                event = await session.get(orm.SecurityEvent, parent_link.event_id)
                if event is None:
                    return
                before = event.entities
                await self._refresh_event_entities_from_sources(session, event)
                if event.entities != before:
                    event.row_version = int(event.row_version or 1) + 1
                    session.add(
                        orm.EventAuditLog(
                            event_id=event.event_id,
                            from_status=event.status,
                            to_status=event.status,
                            operator="EventService",
                            reason="supporting_source_entities_refreshed",
                        )
                    )
                    refreshed = event
            # Session stays open (expire_on_commit=False) so the committed row remains
            # attached while we refresh derived context/redis state.
            if refreshed is not None:
                await session.refresh(refreshed)
                await self._post_create_side_effects(
                    refreshed, force_context_refresh=True, publish_event=False
                )

    async def _add_related_link_if_missing(
        self, session: AsyncSession, source_record_id: str, event_id: str
    ) -> None:
        existing = await session.scalar(
            select(orm.SourceEventLink).where(
                orm.SourceEventLink.source_record_id == source_record_id,
                orm.SourceEventLink.event_id == event_id,
            )
        )
        if existing is None:
            session.add(
                orm.SourceEventLink(
                    source_record_id=source_record_id,
                    event_id=event_id,
                    role=LINK_ROLE_RELATED,
                    promotion_status=PROMOTION_NONE,
                )
            )
