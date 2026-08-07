"""EvidenceAgent: sequential/concurrent 7-source evidence collection (ISSUE-033/034).

ISSUE-033 provides the serial path, scope/time-range/persist/trace behaviors.
ISSUE-034 adds concurrent collection (asyncio.wait), ConflictDetector, and
force conflict field sync.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.base import BaseAgent
from app.agents.conflict_detector import ConflictDetector
from app.agents.evidence_parser import (
    TOOL_SOURCE_MAP,
    EvidenceParser,
    truncate_timestamp_to_second,
)
from app.agents.evidence_tools import EVIDENCE_QUERY_ORDER
from app.agents.rules.entity_validation import (
    EntityRejection,
    EntityValidationResult,
    validate_entity_set,
)
from app.db import models as orm
from app.models.agent_io import CollectionStatus, EvidenceAgentInput, EvidenceOutput, TriageResult
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.enums import EvidenceSource, ToolCategory
from app.models.evidence import Evidence, EvidenceConflict, EvidenceGap
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.models.workflow import GLOBAL_EVIDENCE_TIMEOUT_S, SINGLE_SOURCE_TIMEOUT_S
from app.services.evidence_projection import (
    EvidenceQueryScope,
    bind_evidence_query_scope,
)
from app.services.evidence_query_plan_service import (
    EvidenceQueryPlan,
    allowlisted_query_tools_from_manifest,
    build_query_dedupe_key,
    resolve_evidence_query_plan,
    snapshot_cutoff_from_source,
)

logger = logging.getLogger(__name__)

# Re-export for existing imports (planner/default plans/tests).
__all__ = ["EVIDENCE_QUERY_ORDER", "EvidenceAgent", "EvidenceRepository"]

# Default window when TriageResult has no explicit time range (ISSUE-005 has none).
DEFAULT_TIME_RANGE: dict[str, str] = {
    "start": "2024-06-15T08:00:00Z",
    "end": "2024-06-15T10:00:00Z",
}

_SUCCESS_STATUSES = frozenset(
    {
        ToolResultStatus.SUCCESS,
        ToolResultStatus.PARTIAL_SUCCESS,
        ToolResultStatus.ACCEPTED,
    }
)

_STATUS_PENALTY: dict[CollectionStatus, float] = {
    CollectionStatus.COMPLETED: 0.0,
    CollectionStatus.PARTIAL_DONE: 0.10,
    CollectionStatus.DEGRADED: 0.25,
    CollectionStatus.FAILED: 0.0,
}

_MISSING_SCOPE_ERROR = "missing_evidence_query_scope"

# collection_status thresholds (ISSUE-101): count parser-success sources only.
_COLLECTION_STATUS_COMPLETED = 5
_COLLECTION_STATUS_PARTIAL_DONE = 3
_COLLECTION_STATUS_DEGRADED = 1

# Tool-layer observability outcomes (ISSUE-249). Orthogonal to collection_status:
# HTTP/tool SUCCESS with zero parsed rows is tool_ok_empty, not a success_source.
TOOL_OUTCOME_OK = "tool_ok"
TOOL_OUTCOME_OK_EMPTY = "tool_ok_empty"
TOOL_OUTCOME_FAILED = "tool_failed"
TOOL_OUTCOME_SKIPPED = "source_skipped"

_SKIP_GAP_REASONS = frozenset({"source_skipped", "invalid_entity", "triage_degraded"})
_FAILED_GAP_REASONS = frozenset({"tool_failed", "global_timeout", "missing_scope"})


def resolve_tool_outcome(
    *,
    success: bool,
    failed: bool,
    gap_reason: str | None,
) -> str:
    """Map a query outcome to tool-layer semantics (ISSUE-249).

    Distinguishes provider-success empty results from hard failures and skips.
    Never promotes empty/tool HTTP success into collection success_sources.
    """
    if success:
        return TOOL_OUTCOME_OK
    if gap_reason == "no_records":
        return TOOL_OUTCOME_OK_EMPTY
    if gap_reason in _SKIP_GAP_REASONS:
        return TOOL_OUTCOME_SKIPPED
    if gap_reason in _FAILED_GAP_REASONS or failed:
        return TOOL_OUTCOME_FAILED
    if gap_reason:
        return TOOL_OUTCOME_FAILED
    return TOOL_OUTCOME_FAILED


def _entity_provenance(entity: Any) -> str:
    return "source" if getattr(entity, "source_refs", None) else "llm"


def _has_source_enriched_entities(triage: TriageResult) -> bool:
    """True when triage entities carry SourceAdapter-backed source_refs."""
    entities = triage.entities
    for collection in (
        entities.accounts,
        entities.hosts,
        entities.ips,
        entities.domains,
        entities.processes,
        entities.files,
    ):
        for entity in collection:
            if entity.source_refs:
                return True
    return False


def _should_skip_all_queries(triage: TriageResult) -> bool:
    """Fail-closed when triage is degraded and no source-enriched entities exist."""
    return triage.degraded and not _has_source_enriched_entities(triage)


def _validate_entities_for_evidence(
    entities: EntitySet,
    *,
    alert_text: str = "",
) -> EntityValidationResult:
    """Validate triage entities per-entity provenance before tool calls (ISSUE-100)."""
    rejections: list[EntityRejection] = []
    accounts: list[AccountEntity] = []
    hosts: list[HostEntity] = []
    ips: list[IPEntity] = []
    domains: list[DomainEntity] = []
    processes: list[ProcessEntity] = []
    files: list[FileEntity] = []

    for account in entities.accounts:
        result = validate_entity_set(
            EntitySet(accounts=[account]),
            provenance=_entity_provenance(account),  # type: ignore[arg-type]
            alert_text=alert_text,
        )
        accounts.extend(result.entity_set.accounts)
        rejections.extend(result.rejections)

    for host in entities.hosts:
        result = validate_entity_set(
            EntitySet(hosts=[host]),
            provenance=_entity_provenance(host),  # type: ignore[arg-type]
            alert_text=alert_text,
        )
        hosts.extend(result.entity_set.hosts)
        rejections.extend(result.rejections)

    for ip_entity in entities.ips:
        result = validate_entity_set(
            EntitySet(ips=[ip_entity]),
            provenance=_entity_provenance(ip_entity),  # type: ignore[arg-type]
            alert_text=alert_text,
        )
        ips.extend(result.entity_set.ips)
        rejections.extend(result.rejections)

    for domain in entities.domains:
        result = validate_entity_set(
            EntitySet(domains=[domain]),
            provenance=_entity_provenance(domain),  # type: ignore[arg-type]
            alert_text=alert_text,
        )
        domains.extend(result.entity_set.domains)
        rejections.extend(result.rejections)

    for process in entities.processes:
        result = validate_entity_set(
            EntitySet(processes=[process]),
            provenance=_entity_provenance(process),  # type: ignore[arg-type]
            alert_text=alert_text,
        )
        processes.extend(result.entity_set.processes)
        rejections.extend(result.rejections)

    for file_entity in entities.files:
        result = validate_entity_set(
            EntitySet(files=[file_entity]),
            provenance=_entity_provenance(file_entity),  # type: ignore[arg-type]
            alert_text=alert_text,
        )
        files.extend(result.entity_set.files)
        rejections.extend(result.rejections)

    return EntityValidationResult(
        entity_set=EntitySet(
            accounts=accounts,
            hosts=hosts,
            ips=ips,
            domains=domains,
            processes=processes,
            files=files,
        ),
        rejections=tuple(rejections),
    )


def _validate_ioc_list(iocs: list[str]) -> tuple[list[str], list[str]]:
    """Validate triage IOC strings before threat_intel queries (ISSUE-101)."""
    valid: list[str] = []
    rejected: list[str] = []
    for raw in iocs:
        item = raw.strip()
        if not item:
            continue
        if _indicator_is_valid(item):
            valid.append(item)
        else:
            rejected.append(item)
    return valid, rejected


def _indicator_is_valid(indicator: str) -> bool:
    """Return True when *indicator* is a valid IP literal or domain syntax."""
    text = indicator.strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return True
    domain_result = validate_entity_set(
        EntitySet(domains=[DomainEntity(entity_id="ioc-check", fqdn=text)]),
        provenance="llm",
    )
    return bool(domain_result.entity_set.domains)


def _threat_intel_indicator_keys(
    entities: EntitySet,
    iocs: list[str],
) -> set[str]:
    external_ips = {ip.address for ip in entities.ips if ip.address and ip.scope == "external"}
    domains = {d.fqdn for d in entities.domains if d.fqdn}
    return set(iocs) | external_ips | domains


def _skip_reason_for_tool(
    tool_name: str,
    *,
    raw: EntitySet,
    validated: EntitySet,
    raw_iocs: list[str] | None = None,
    valid_iocs: list[str] | None = None,
) -> str:
    """Distinguish invalid_entity (rejected by validator) from source_skipped."""
    if tool_name in {"query_account_login", "query_file_access"}:
        raw_values = {a.username for a in raw.accounts if a.username}
        valid_values = {a.username for a in validated.accounts if a.username}
    elif tool_name == "query_edr_process":
        raw_values = {h.hostname for h in raw.hosts if h.hostname}
        valid_values = {h.hostname for h in validated.hosts if h.hostname}
    elif tool_name == "query_network_flow":
        raw_values = {ip.address for ip in raw.ips if ip.address}
        valid_values = {ip.address for ip in validated.ips if ip.address}
    elif tool_name == "query_dns":
        raw_values = {d.fqdn for d in raw.domains if d.fqdn}
        valid_values = {d.fqdn for d in validated.domains if d.fqdn}
    elif tool_name == "query_asset_info":
        raw_values = {value for host in raw.hosts for value in (host.hostname, host.ip) if value}
        valid_values = {
            value for host in validated.hosts for value in (host.hostname, host.ip) if value
        }
    elif tool_name == "query_threat_intel":
        raw_values = _threat_intel_indicator_keys(raw, list(raw_iocs or []))
        valid_values = _threat_intel_indicator_keys(validated, list(valid_iocs or []))
    else:
        return "source_skipped"

    if raw_values - valid_values:
        return "invalid_entity"
    return "source_skipped"


def _impact_for_skip_reason(reason: str) -> str:
    if reason in {"invalid_entity", "triage_degraded", "source_skipped"}:
        return reason
    return "source_skipped"


def resolve_evidence_mode() -> str:
    """Resolve ``EVIDENCE_MODE`` env (``concurrent`` | ``sequential``; default concurrent)."""
    raw = (os.environ.get("EVIDENCE_MODE") or "concurrent").strip().lower()
    if raw in {"concurrent", "sequential"}:
        return raw
    logger.warning("unknown EVIDENCE_MODE=%r; defaulting to concurrent", raw)
    return "concurrent"


def _format_time_range_value(value: datetime) -> str:
    """Render a UTC timestamp for query tool ``time_range`` fields."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_occurred_at(event_blob: Any) -> datetime | None:
    """Extract ``occurred_at`` from EventContext.event (dict or model-like)."""
    if event_blob is None:
        return None
    raw = event_blob.get("occurred_at") if isinstance(event_blob, dict) else None
    if raw is None and not isinstance(event_blob, dict):
        raw = getattr(event_blob, "occurred_at", None)
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw.astimezone(UTC) if raw.tzinfo is not None else raw.replace(tzinfo=UTC)
    text = str(raw).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def time_range_around_occurred_at(
    occurred_at: datetime,
    *,
    hours_before: float = 1.0,
    hours_after: float = 1.0,
) -> dict[str, str]:
    """Build a symmetric investigation window around ``occurred_at``."""
    anchor = (
        occurred_at.astimezone(UTC)
        if occurred_at.tzinfo is not None
        else occurred_at.replace(tzinfo=UTC)
    )
    start = anchor - timedelta(hours=hours_before)
    end = anchor + timedelta(hours=hours_after)
    return {
        "start": _format_time_range_value(start),
        "end": _format_time_range_value(end),
    }


class EvidenceRepository(Protocol):
    """Persistence port for Evidence rows (conflict on evidence_id)."""

    async def upsert_batch(self, evidence_list: list[Evidence]) -> None: ...

    async def list_by_event(self, event_id: str) -> list[Evidence]: ...

    async def apply_conflict_updates(self, evidence_list: list[Evidence]) -> None: ...


class InMemoryEvidenceRepository:
    """Test / degraded store: keep higher-confidence row on evidence_id conflict."""

    def __init__(self) -> None:
        self._rows: dict[str, Evidence] = {}

    async def upsert_batch(self, evidence_list: list[Evidence]) -> None:
        for item in evidence_list:
            existing = self._rows.get(item.evidence_id)
            if existing is None or item.confidence > existing.confidence:
                self._rows[item.evidence_id] = item

    async def list_by_event(self, event_id: str) -> list[Evidence]:
        return [row for row in self._rows.values() if row.event_id == event_id]

    async def apply_conflict_updates(self, evidence_list: list[Evidence]) -> None:
        """Force-update confidence / is_conflicting (upsert will not lower confidence)."""
        for item in evidence_list:
            existing = self._rows.get(item.evidence_id)
            if existing is None:
                self._rows[item.evidence_id] = item
                continue
            self._rows[item.evidence_id] = existing.model_copy(
                update={
                    "confidence": item.confidence,
                    "is_conflicting": item.is_conflicting,
                }
            )


class SqlAlchemyEvidenceRepository:
    """Postgres upsert for ``evidence`` table (ISSUE-033 step 5)."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def upsert_batch(self, evidence_list: list[Evidence]) -> None:
        if not evidence_list:
            return
        async with self._session_factory() as session:
            async with session.begin():
                for item in evidence_list:
                    values = {
                        "evidence_id": item.evidence_id,
                        "event_id": item.event_id,
                        "source": item.source.value
                        if isinstance(item.source, EvidenceSource)
                        else str(item.source),
                        "evidence_type": item.evidence_type,
                        "description": item.description,
                        "confidence": item.confidence,
                        "timestamp": item.timestamp,
                        "related_entities": list(item.related_entities),
                        "source_ref": (
                            item.source_ref.model_dump(mode="json")
                            if item.source_ref is not None
                            else None
                        ),
                        "raw_data": dict(item.raw_data),
                        "mitre_technique": item.mitre_technique,
                        "is_conflicting": item.is_conflicting,
                    }
                    stmt = pg_insert(orm.Evidence).values(**values)
                    excluded = stmt.excluded
                    # Keep the higher-confidence row on evidence_id conflict.
                    stmt = stmt.on_conflict_do_update(
                        index_elements=["evidence_id"],
                        set_={
                            "event_id": excluded.event_id,
                            "source": excluded.source,
                            "evidence_type": excluded.evidence_type,
                            "description": excluded.description,
                            "confidence": excluded.confidence,
                            "timestamp": excluded.timestamp,
                            "related_entities": excluded.related_entities,
                            "source_ref": excluded.source_ref,
                            "raw_data": excluded.raw_data,
                            "mitre_technique": excluded.mitre_technique,
                            "is_conflicting": excluded.is_conflicting,
                        },
                        where=(orm.Evidence.confidence < excluded.confidence),
                    )
                    await session.execute(stmt)

    async def apply_conflict_updates(self, evidence_list: list[Evidence]) -> None:
        """Force-update confidence / is_conflicting after ConflictDetector penalties."""
        if not evidence_list:
            return
        async with self._session_factory() as session:
            async with session.begin():
                for item in evidence_list:
                    await session.execute(
                        update(orm.Evidence)
                        .where(orm.Evidence.evidence_id == item.evidence_id)
                        .values(
                            confidence=item.confidence,
                            is_conflicting=item.is_conflicting,
                        )
                    )

    async def list_by_event(self, event_id: str) -> list[Evidence]:
        from sqlalchemy import select

        from app.models.source import SourceReference

        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(orm.Evidence).where(orm.Evidence.event_id == event_id)
                    )
                )
                .scalars()
                .all()
            )
            result: list[Evidence] = []
            for row in rows:
                source_ref = None
                if isinstance(row.source_ref, dict):
                    try:
                        source_ref = SourceReference.model_validate(row.source_ref)
                    except Exception:
                        source_ref = None
                result.append(
                    Evidence(
                        evidence_id=row.evidence_id,
                        event_id=row.event_id,
                        source=EvidenceSource(row.source),
                        evidence_type=row.evidence_type,
                        description=row.description,
                        confidence=row.confidence,
                        timestamp=row.timestamp,
                        related_entities=list(row.related_entities or []),
                        source_ref=source_ref,
                        raw_data=dict(row.raw_data or {}),
                        mitre_technique=row.mitre_technique,
                        is_conflicting=bool(row.is_conflicting),
                    )
                )
            return result


class EvidenceAgent(BaseAgent[EvidenceAgentInput, EvidenceOutput]):
    """EvidenceAgent with sequential/concurrent modes and conflict detection."""

    agent_name = "evidence_agent"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        tool_executor: Any | None = None,
        working_memory: Any | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
        event_service: Any | None = None,
        evidence_repository: EvidenceRepository | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        evidence_parser: EvidenceParser | None = None,
        conflict_detector: ConflictDetector | None = None,
        default_time_range: dict[str, str] | None = None,
        window_hours_before: float = 1.0,
        window_hours_after: float = 1.0,
        evidence_mode: str | None = None,
        global_timeout_s: float | None = None,
        query_timeout_s: float | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            tool_executor=tool_executor,
            working_memory=working_memory,
            budget_service=budget_service,
            output_guard=output_guard,
            trace_service=trace_service,
            audit_service=audit_service,
            event_bus=event_bus,
        )
        self.event_service = event_service
        if evidence_repository is not None:
            self.evidence_repository: EvidenceRepository | None = evidence_repository
        elif session_factory is not None:
            self.evidence_repository = SqlAlchemyEvidenceRepository(session_factory)
        else:
            self.evidence_repository = InMemoryEvidenceRepository()
        self.parser = evidence_parser or EvidenceParser()
        self.conflict_detector = conflict_detector or ConflictDetector()
        self.default_time_range = dict(default_time_range or DEFAULT_TIME_RANGE)
        self.window_hours_before = window_hours_before
        self.window_hours_after = window_hours_after
        mode = (evidence_mode or resolve_evidence_mode()).strip().lower()
        self.evidence_mode = mode if mode in {"concurrent", "sequential"} else "concurrent"
        self.global_timeout_s = (
            GLOBAL_EVIDENCE_TIMEOUT_S if global_timeout_s is None else global_timeout_s
        )
        self.query_timeout_s = (
            SINGLE_SOURCE_TIMEOUT_S if query_timeout_s is None else query_timeout_s
        )
        # Populated each run for agent_trace / acceptance checks.
        self.last_query_timings: list[dict[str, Any]] = []
        self.last_query_plan: EvidenceQueryPlan | None = None
        self.last_persist_error: str | None = None
        self.last_collection_elapsed_s: float | None = None
        self.last_snapshot_cutoff: str = ""

    async def _run(self, input: EvidenceAgentInput) -> EvidenceOutput:
        if self.tool_executor is None:
            raise RuntimeError("EvidenceAgent requires tool_executor")

        self.last_query_timings = []
        self.last_query_plan = None
        self.last_persist_error = None
        self.last_collection_elapsed_s = None
        self.last_snapshot_cutoff = ""
        time_range = await self._resolve_time_range(input)

        scope = await self._resolve_scope(input.event_id)
        if scope is None and self.event_service is None:
            logger.warning(
                "EvidenceAgent event_service is not configured; "
                "evidence queries require a trusted EventService scope"
            )

        execution_plan = self._execution_plan_from_input(input)
        if execution_plan is None:
            execution_plan = await self._read_execution_plan(input.event_id)
        snapshot_cutoff = await self._resolve_snapshot_cutoff(input.event_id)
        self.last_snapshot_cutoff = snapshot_cutoff
        allowlisted = self._available_query_tools()
        query_plan = resolve_evidence_query_plan(
            input.triage_result,
            planned_tools=list(input.required_tools),
            execution_plan=execution_plan,
            allowlisted=allowlisted,
        )
        self.last_query_plan = query_plan
        query_tools = tuple(query_plan.tools)

        mode = self.evidence_mode
        alert_text = input.alert_text.strip()
        if not alert_text:
            alert_text = await self._resolve_alert_text(input.event_id)
        if _should_skip_all_queries(input.triage_result):
            (
                collected,
                success_sources,
                failed_sources,
                gaps,
            ) = await self._collect_all_triage_degraded(input, query_tools=query_tools)
        elif mode == "concurrent":
            collected, success_sources, failed_sources, gaps = await self._collect_concurrent(
                input,
                time_range=time_range,
                scope=scope,
                alert_text=alert_text,
                query_tools=query_tools,
            )
        else:
            collected, success_sources, failed_sources, gaps = await self._collect_sequential(
                input,
                time_range=time_range,
                scope=scope,
                alert_text=alert_text,
                query_tools=query_tools,
            )

        evidence_list = self._dedup_and_sort(collected)
        await self._persist_evidence(evidence_list)

        conflicts: list[EvidenceConflict] = []
        try:
            evidence_list, conflicts = self.conflict_detector.detect_and_penalize(evidence_list)
        except Exception:
            logger.warning(
                "conflict detection failed; skipping penalties for event=%s",
                input.event_id,
                exc_info=True,
            )
        await self._sync_conflict_updates(evidence_list, conflicts)

        collection_status = self._collection_status(len(success_sources))
        overall_confidence = self._overall_confidence(evidence_list, collection_status)

        output = EvidenceOutput(
            evidence_list=evidence_list,
            conflicts=conflicts,
            gaps=gaps,
            success_sources=success_sources,
            failed_sources=failed_sources,
            overall_confidence=overall_confidence,
            collection_status=collection_status,
        )

        await self._write_context(input.event_id, output)
        return output

    async def _collect_sequential(
        self,
        input: EvidenceAgentInput,
        *,
        time_range: dict[str, str],
        scope: EvidenceQueryScope | None,
        alert_text: str = "",
        query_tools: tuple[str, ...] = EVIDENCE_QUERY_ORDER,
    ) -> tuple[list[Evidence], list[str], list[str], list[EvidenceGap]]:
        collected: list[Evidence] = []
        success_sources: list[str] = []
        failed_sources: list[str] = []
        gaps: list[EvidenceGap] = []
        started = time.perf_counter()
        raw_entities = input.triage_result.entities
        validated_entities = _validate_entities_for_evidence(
            raw_entities,
            alert_text=alert_text,
        ).entity_set
        raw_iocs = [item for item in input.triage_result.ioc_list if item]
        valid_iocs, _rejected_iocs = _validate_ioc_list(raw_iocs)
        dedupe_cache: dict[str, dict[str, Any]] = {}

        for tool_name in query_tools:
            source = TOOL_SOURCE_MAP[tool_name]
            params = self._build_params(
                tool_name,
                validated_entities,
                time_range,
                ioc_list=valid_iocs,
            )
            if params is None:
                skip_reason = _skip_reason_for_tool(
                    tool_name,
                    raw=raw_entities,
                    validated=validated_entities,
                    raw_iocs=raw_iocs,
                    valid_iocs=valid_iocs,
                )
                outcome = self._skipped_entity_outcome(
                    tool_name,
                    source,
                    input.event_id,
                    reason=skip_reason,
                )
            else:
                outcome = await self._run_one_query_deduped(
                    tool_name,
                    params,
                    input.event_id,
                    scope=scope,
                    time_range=time_range,
                    dedupe_cache=dedupe_cache,
                )
            await self._merge_outcome(
                outcome,
                collected=collected,
                success_sources=success_sources,
                failed_sources=failed_sources,
                gaps=gaps,
            )

        self.last_collection_elapsed_s = time.perf_counter() - started
        return collected, success_sources, failed_sources, gaps

    async def _collect_all_triage_degraded(
        self,
        input: EvidenceAgentInput,
        *,
        query_tools: tuple[str, ...] = EVIDENCE_QUERY_ORDER,
    ) -> tuple[list[Evidence], list[str], list[str], list[EvidenceGap]]:
        """Skip all seven queries when triage is degraded without source entities."""
        collected: list[Evidence] = []
        success_sources: list[str] = []
        failed_sources: list[str] = []
        gaps: list[EvidenceGap] = []
        started = time.perf_counter()

        for tool_name in query_tools:
            source = TOOL_SOURCE_MAP[tool_name]
            outcome = self._skipped_entity_outcome(
                tool_name,
                source,
                input.event_id,
                reason="triage_degraded",
                description=(
                    f"triage degraded without source-enriched entities; skipped {tool_name}"
                ),
            )
            await self._merge_outcome(
                outcome,
                collected=collected,
                success_sources=success_sources,
                failed_sources=failed_sources,
                gaps=gaps,
            )

        self.last_collection_elapsed_s = time.perf_counter() - started
        return collected, success_sources, failed_sources, gaps

    async def _collect_concurrent(
        self,
        input: EvidenceAgentInput,
        *,
        time_range: dict[str, str],
        scope: EvidenceQueryScope | None,
        alert_text: str = "",
        query_tools: tuple[str, ...] = EVIDENCE_QUERY_ORDER,
    ) -> tuple[list[Evidence], list[str], list[str], list[EvidenceGap]]:
        """Run queries concurrently; ``asyncio.wait`` keeps completed work on global timeout."""
        collected: list[Evidence] = []
        success_sources: list[str] = []
        failed_sources: list[str] = []
        gaps: list[EvidenceGap] = []
        started = time.perf_counter()

        pending_tasks: dict[asyncio.Task[dict[str, Any]], str] = {}
        pending_tasks_dedupe: dict[asyncio.Task[dict[str, Any]], str] = {}
        raw_entities = input.triage_result.entities
        validated_entities = _validate_entities_for_evidence(
            raw_entities,
            alert_text=alert_text,
        ).entity_set
        raw_iocs = [item for item in input.triage_result.ioc_list if item]
        valid_iocs, _rejected_iocs = _validate_ioc_list(raw_iocs)
        dedupe_cache: dict[str, dict[str, Any]] = {}
        for tool_name in query_tools:
            source = TOOL_SOURCE_MAP[tool_name]
            params = self._build_params(
                tool_name,
                validated_entities,
                time_range,
                ioc_list=valid_iocs,
            )
            if params is None:
                skip_reason = _skip_reason_for_tool(
                    tool_name,
                    raw=raw_entities,
                    validated=validated_entities,
                    raw_iocs=raw_iocs,
                    valid_iocs=valid_iocs,
                )
                outcome = self._skipped_entity_outcome(
                    tool_name,
                    source,
                    input.event_id,
                    reason=skip_reason,
                )
                await self._merge_outcome(
                    outcome,
                    collected=collected,
                    success_sources=success_sources,
                    failed_sources=failed_sources,
                    gaps=gaps,
                )
                continue
            dedupe_key = build_query_dedupe_key(
                tool_name,
                params,
                time_range,
                scope,
                snapshot_cutoff=self.last_snapshot_cutoff,
            )
            cached = dedupe_cache.get(dedupe_key)
            if cached is not None:
                await self._merge_outcome(
                    {
                        **cached,
                        "tool_name": tool_name,
                        "dedupe_reused": True,
                    },
                    collected=collected,
                    success_sources=success_sources,
                    failed_sources=failed_sources,
                    gaps=gaps,
                )
                continue
            task = asyncio.create_task(
                self._run_one_query(
                    tool_name,
                    params,
                    input.event_id,
                    scope=scope,
                    dedupe_key=dedupe_key,
                ),
                name=f"evidence:{tool_name}",
            )
            pending_tasks[task] = tool_name
            pending_tasks_dedupe[task] = dedupe_key

        if pending_tasks:
            done, pending = await asyncio.wait(
                set(pending_tasks.keys()),
                timeout=self.global_timeout_s,
                return_when=asyncio.ALL_COMPLETED,
            )

            completed_by_tool = {
                pending_tasks[task]: task for task in done if task in pending_tasks
            }
            for tool_name in query_tools:
                completed_task = completed_by_tool.get(tool_name)
                if completed_task is None:
                    continue
                try:
                    outcome = completed_task.result()
                except Exception as exc:
                    source = TOOL_SOURCE_MAP[tool_name]
                    outcome = {
                        "tool_name": tool_name,
                        "source": source,
                        "parsed": [],
                        "gap": self._gap(
                            event_id=input.event_id,
                            source=source,
                            reason="tool_failed",
                            impact="source_unavailable",
                            description=f"concurrent task error for {tool_name}",
                            tool_name=tool_name,
                            error=str(exc),
                        ),
                        "failed": True,
                        "success": False,
                        "timing_ms": 0,
                        "status_text": f"error:{exc}",
                        "dedupe_key": pending_tasks_dedupe.get(completed_task),
                    }
                else:
                    completed_dedupe_key = pending_tasks_dedupe.get(completed_task)
                    if completed_dedupe_key:
                        outcome.setdefault("dedupe_key", completed_dedupe_key)
                        dedupe_cache.setdefault(completed_dedupe_key, dict(outcome))
                await self._merge_outcome(
                    outcome,
                    collected=collected,
                    success_sources=success_sources,
                    failed_sources=failed_sources,
                    gaps=gaps,
                )

            for task in pending:
                tool_name = pending_tasks[task]
                source = TOOL_SOURCE_MAP[tool_name]
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass
                await self._merge_outcome(
                    {
                        "tool_name": tool_name,
                        "source": source,
                        "parsed": [],
                        "gap": self._gap(
                            event_id=input.event_id,
                            source=source,
                            reason="global_timeout",
                            impact="partial_collection",
                            description=(
                                f"global evidence timeout ({self.global_timeout_s}s) "
                                f"before {tool_name} completed"
                            ),
                            tool_name=tool_name,
                            timeout_s=self.global_timeout_s,
                        ),
                        "failed": True,
                        "success": False,
                        "timing_ms": int(self.global_timeout_s * 1000),
                        "status_text": "global_timeout",
                    },
                    collected=collected,
                    success_sources=success_sources,
                    failed_sources=failed_sources,
                    gaps=gaps,
                )

        self.last_collection_elapsed_s = time.perf_counter() - started
        return collected, success_sources, failed_sources, gaps

    def _skipped_entity_outcome(
        self,
        tool_name: str,
        source: EvidenceSource,
        event_id: str,
        *,
        reason: str,
        description: str | None = None,
    ) -> dict[str, Any]:
        if description is None:
            description = f"required entity missing or invalid for {tool_name}"
        return {
            "tool_name": tool_name,
            "source": source,
            "parsed": [],
            "gap": self._gap(
                event_id=event_id,
                source=source,
                reason=reason,
                impact=_impact_for_skip_reason(reason),
                description=description,
                tool_name=tool_name,
            ),
            "failed": True,
            "success": False,
            "timing_ms": 0,
            "status_text": f"skipped_{reason}",
        }

    async def _run_one_query_deduped(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        *,
        scope: EvidenceQueryScope | None,
        time_range: dict[str, str],
        dedupe_cache: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        dedupe_key = build_query_dedupe_key(
            tool_name,
            params,
            time_range,
            scope,
            snapshot_cutoff=self.last_snapshot_cutoff,
        )
        cached = dedupe_cache.get(dedupe_key)
        if cached is not None:
            return {
                **cached,
                "tool_name": tool_name,
                "dedupe_key": dedupe_key,
                "dedupe_reused": True,
            }
        outcome = await self._run_one_query(
            tool_name,
            params,
            event_id,
            scope=scope,
            dedupe_key=dedupe_key,
        )
        dedupe_cache[dedupe_key] = dict(outcome)
        return outcome

    async def _run_one_query(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        *,
        scope: EvidenceQueryScope | None,
        dedupe_key: str | None = None,
    ) -> dict[str, Any]:
        source = TOOL_SOURCE_MAP[tool_name]
        tool_result, timing_ms, call_error = await self._call_query(
            tool_name,
            params,
            event_id,
            scope=scope,
        )
        status_text = tool_result.status.value if tool_result is not None else f"error:{call_error}"

        if tool_result is None or tool_result.status not in _SUCCESS_STATUSES:
            gap_reason = "missing_scope" if call_error == _MISSING_SCOPE_ERROR else "tool_failed"
            return {
                "tool_name": tool_name,
                "source": source,
                "parsed": [],
                "gap": self._gap(
                    event_id=event_id,
                    source=source,
                    reason=gap_reason,
                    impact="source_unavailable",
                    description=f"query {tool_name} did not succeed",
                    tool_name=tool_name,
                    execution_time_ms=timing_ms,
                    error=call_error or (tool_result.error_detail if tool_result else None),
                    status=(tool_result.status.value if tool_result is not None else None),
                ),
                "failed": True,
                "success": False,
                "timing_ms": timing_ms,
                "status_text": status_text,
                "dedupe_key": dedupe_key,
            }

        parsed = self.parser.parse(
            tool_name,
            tool_result,
            event_id=event_id,
        )
        if not parsed:
            return {
                "tool_name": tool_name,
                "source": source,
                "parsed": [],
                "gap": self._gap(
                    event_id=event_id,
                    source=source,
                    reason="no_records",
                    impact="empty_result",
                    description=f"query {tool_name} returned no usable evidence",
                    tool_name=tool_name,
                    execution_time_ms=timing_ms,
                ),
                "failed": False,
                "success": False,
                "timing_ms": timing_ms,
                "status_text": status_text,
                "dedupe_key": dedupe_key,
            }

        return {
            "tool_name": tool_name,
            "source": source,
            "parsed": parsed,
            "gap": None,
            "failed": False,
            "success": True,
            "timing_ms": timing_ms,
            "status_text": status_text,
            "dedupe_key": dedupe_key,
        }

    async def _merge_outcome(
        self,
        outcome: dict[str, Any],
        *,
        collected: list[Evidence],
        success_sources: list[str],
        failed_sources: list[str],
        gaps: list[EvidenceGap],
    ) -> None:
        tool_name = str(outcome["tool_name"])
        source: EvidenceSource = outcome["source"]
        source_value = source.value
        timing_ms = int(outcome.get("timing_ms") or 0)
        provider_status = str(outcome.get("status_text") or "")
        parsed: list[Evidence] = list(outcome.get("parsed") or [])
        gap = outcome.get("gap")
        gap_reason = gap.reason if gap is not None else None
        records_count = len(parsed)
        dedupe_key = outcome.get("dedupe_key")
        tool_outcome = resolve_tool_outcome(
            success=bool(outcome.get("success")),
            failed=bool(outcome.get("failed")),
            gap_reason=gap_reason,
        )
        # Surface tool_ok_empty in status so traces/UI cannot misread provider
        # SUCCESS + zero records as a healthy collection contribution.
        status_text = (
            TOOL_OUTCOME_OK_EMPTY
            if tool_outcome == TOOL_OUTCOME_OK_EMPTY
            else provider_status
        )

        self.last_query_timings.append(
            {
                "tool_name": tool_name,
                "source": source_value,
                "status": status_text,
                "provider_status": provider_status,
                "tool_outcome": tool_outcome,
                "execution_time_ms": timing_ms,
                "records_count": records_count,
                "gap_reason": gap_reason,
                "dedupe_key": dedupe_key,
                "dedupe_reused": bool(outcome.get("dedupe_reused")),
            }
        )
        event_id = ""
        if outcome.get("gap") is not None:
            event_id = outcome["gap"].event_id
        elif outcome.get("parsed"):
            event_id = outcome["parsed"][0].event_id
        await self._note_timing(
            event_id,
            tool_name,
            status=status_text,
            execution_time_ms=timing_ms,
        )

        gap = outcome.get("gap")
        if gap is not None:
            gaps.append(gap)
        if outcome.get("failed"):
            if source_value not in failed_sources:
                failed_sources.append(source_value)
        if parsed:
            collected.extend(parsed)
        if outcome.get("success") and source_value not in success_sources:
            success_sources.append(source_value)

    @staticmethod
    def _gap(
        *,
        event_id: str,
        source: EvidenceSource,
        reason: str,
        impact: str | None = None,
        description: str | None = None,
        **extra: Any,
    ) -> EvidenceGap:
        """Build EvidenceGap; map Issue prose source/impact/description into detail."""
        detail: dict[str, Any] = {"source": source.value}
        if impact is not None:
            detail["impact"] = impact
        if description is not None:
            detail["description"] = description
        detail.update(extra)
        return EvidenceGap(
            event_id=event_id,
            missing_source=source,
            reason=reason,
            detail=detail,
        )

    async def _sync_conflict_updates(
        self,
        evidence_list: list[Evidence],
        conflicts: list[EvidenceConflict],
    ) -> None:
        if self.evidence_repository is None or not evidence_list or not conflicts:
            return
        dirty = [item for item in evidence_list if item.is_conflicting]
        if not dirty:
            if conflicts:
                logger.warning("conflicts present but no penalized evidence rows; skipping DB sync")
            return
        try:
            await self.evidence_repository.apply_conflict_updates(dirty)
        except Exception as exc:
            logger.error(
                "evidence conflict field sync failed: %s",
                exc,
                exc_info=True,
            )
            self.last_persist_error = (
                f"{self.last_persist_error}; conflict_sync:{exc}"
                if self.last_persist_error
                else f"conflict_sync:{exc}"
            )

    async def _resolve_scope(self, event_id: str) -> EvidenceQueryScope | None:
        if self.event_service is None:
            return None
        try:
            scope: EvidenceQueryScope = cast(
                EvidenceQueryScope,
                await self.event_service.get_evidence_query_scope(event_id),
            )
            return scope
        except Exception:
            logger.warning(
                "failed to resolve evidence query scope for event=%s",
                event_id,
                exc_info=True,
            )
            return None

    async def _call_query(
        self,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
        *,
        scope: EvidenceQueryScope | None,
    ) -> tuple[ToolResult | None, int, str | None]:
        assert self.tool_executor is not None
        if scope is None:
            return None, 0, _MISSING_SCOPE_ERROR
        started = time.perf_counter()
        try:
            with bind_evidence_query_scope(scope):
                result = await self.tool_executor.call(
                    tool_name,
                    params,
                    event_id,
                    timeout=self.query_timeout_s,
                    agent_name=self.agent_name,
                )
            tool_result = (
                result if isinstance(result, ToolResult) else ToolResult.model_validate(result)
            )
            wall_ms = max(0, int((time.perf_counter() - started) * 1000))
            reported = int(tool_result.execution_time_ms or 0)
            timing = reported if reported > 0 else wall_ms
            return tool_result, timing, None
        except Exception as exc:
            wall_ms = max(0, int((time.perf_counter() - started) * 1000))
            logger.info(
                "evidence query failed tool=%s event=%s err=%s",
                tool_name,
                event_id,
                exc,
            )
            return None, wall_ms, str(exc)

    async def _note_timing(
        self,
        event_id: str,
        tool_name: str,
        *,
        status: str,
        execution_time_ms: int,
    ) -> None:
        if self.working_memory is None or not event_id:
            return
        note = (
            f"evidence_query tool={tool_name} status={status} execution_time_ms={execution_time_ms}"
        )
        try:
            await self.working_memory.append_scratchpad(event_id, note)
        except Exception:
            logger.debug("scratchpad timing note failed", exc_info=True)

    async def _persist_evidence(self, evidence_list: list[Evidence]) -> None:
        if self.evidence_repository is None or not evidence_list:
            return
        try:
            await self.evidence_repository.upsert_batch(evidence_list)
            self.last_persist_error = None
        except Exception as exc:
            self.last_persist_error = str(exc)
            logger.error(
                "evidence upsert failed; EventContext kept but evidence table may be incomplete",
                exc_info=True,
            )
            self.last_query_timings.append(
                {
                    "tool_name": "evidence_upsert",
                    "source": "persist",
                    "status": "persist_failed",
                    "execution_time_ms": 0,
                    "error": str(exc),
                }
            )
            event_id = evidence_list[0].event_id
            await self._note_timing(
                event_id,
                "evidence_upsert",
                status=f"persist_failed:{exc}",
                execution_time_ms=0,
            )

    async def _write_context(self, event_id: str, output: EvidenceOutput) -> None:
        if self.working_memory is None:
            return
        try:
            await self.working_memory.write(
                event_id,
                "evidence_output",
                output.model_dump(mode="json"),
            )
        except Exception:
            logger.warning(
                "failed to write evidence_output to working memory event=%s",
                event_id,
                exc_info=True,
            )

    async def _record_trace(
        self,
        *,
        input: EvidenceAgentInput,
        output: EvidenceOutput | None,
        status: str,
        started_at: datetime,
        completed_at: datetime | None,
        error_detail: str | None = None,
    ) -> None:
        """Persist agent_trace including per-query timings (ISSUE-033 acceptance)."""
        if self.trace_service is None:
            return
        if output is not None:
            envelope: dict[str, Any] = {
                **output.model_dump(mode="json"),
                "query_timings": list(self.last_query_timings),
                "persist_ok": self.last_persist_error is None,
            }
            if self.last_query_plan is not None:
                envelope["query_plan"] = self.last_query_plan.model_dump(mode="json")
            if self.last_snapshot_cutoff:
                envelope["snapshot_cutoff"] = self.last_snapshot_cutoff
            plan_step_goal = getattr(input, "plan_step_goal", "")
            if isinstance(plan_step_goal, str) and plan_step_goal.strip():
                envelope["plan_step_goal"] = plan_step_goal.strip()
            if self.last_persist_error is not None:
                envelope["persist_error"] = self.last_persist_error
        else:
            envelope = {
                "query_timings": list(self.last_query_timings),
                "persist_ok": self.last_persist_error is None,
                "persist_error": self.last_persist_error,
            }
            if self.last_query_plan is not None:
                envelope["query_plan"] = self.last_query_plan.model_dump(mode="json")
            if self.last_snapshot_cutoff:
                envelope["snapshot_cutoff"] = self.last_snapshot_cutoff
            plan_step_goal = getattr(input, "plan_step_goal", "")
            if isinstance(plan_step_goal, str) and plan_step_goal.strip():
                envelope["plan_step_goal"] = plan_step_goal.strip()
        try:
            await self.trace_service.log_trace(
                event_id=input.event_id,
                agent_name=self.agent_name,
                input_data=input,
                output_data=envelope,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                error_detail=error_detail,
                llm_model=(
                    getattr(self.llm_client, "model_name", None) if self.llm_client else None
                ),
                llm_tokens_used=None,
            )
        except Exception:
            logger.warning(
                "AgentTraceService write failed for event=%s agent=%s",
                input.event_id,
                self.agent_name,
                exc_info=True,
            )

    @staticmethod
    def _execution_plan_from_input(input: EvidenceAgentInput) -> dict[str, Any] | None:
        plan = input.execution_plan
        return plan if isinstance(plan, dict) else None

    def _available_query_tools(self) -> frozenset[str] | None:
        if self.tool_executor is None:
            return None
        registry = getattr(self.tool_executor, "registry", None)
        if registry is None:
            return None
        available = {meta.tool_name for meta in registry.list_available_tools(ToolCategory.QUERY)}
        return allowlisted_query_tools_from_manifest(available)

    async def _resolve_snapshot_cutoff(self, event_id: str) -> str:
        if self.working_memory is None:
            return ""
        try:
            blob = await self.working_memory.read(event_id, "source_snapshot")
        except Exception:
            logger.debug(
                "failed to read source_snapshot for evidence dedupe event=%s",
                event_id,
                exc_info=True,
            )
            return ""
        return snapshot_cutoff_from_source(blob if isinstance(blob, dict) else None)

    async def _read_execution_plan(self, event_id: str) -> dict[str, Any] | None:
        if self.working_memory is None:
            return None
        try:
            data = await self.working_memory.read(event_id, "execution_plan")
        except Exception:
            logger.debug(
                "failed to read execution_plan for evidence query budget event=%s",
                event_id,
                exc_info=True,
            )
            return None
        return data if isinstance(data, dict) else None

    async def _resolve_time_range(self, input: EvidenceAgentInput) -> dict[str, str]:
        """Prefer EventContext.event.occurred_at; fall back to configured default."""
        if self.working_memory is not None:
            try:
                event_blob = await self.working_memory.read(input.event_id, "event")
                occurred_at = _parse_occurred_at(event_blob)
                if occurred_at is not None:
                    return time_range_around_occurred_at(
                        occurred_at,
                        hours_before=self.window_hours_before,
                        hours_after=self.window_hours_after,
                    )
            except Exception:
                logger.debug(
                    "failed to derive time_range from EventContext.event for event=%s",
                    input.event_id,
                    exc_info=True,
                )
        return dict(self.default_time_range)

    async def _resolve_alert_text(self, event_id: str) -> str:
        """Prefer EventContext.event description/title for ISSUE-100 alert context."""
        if self.working_memory is None:
            return ""
        try:
            event_blob = await self.working_memory.read(event_id, "event")
        except Exception:
            logger.debug(
                "failed to read EventContext.event for alert_text event=%s",
                event_id,
                exc_info=True,
            )
            return ""
        if not isinstance(event_blob, dict):
            return ""
        title = event_blob.get("title")
        description = event_blob.get("description")
        parts = [
            part.strip()
            for part in (
                str(title) if title is not None else "",
                str(description) if description is not None else "",
            )
            if part and part.strip()
        ]
        return ". ".join(parts)

    def _build_params(
        self,
        tool_name: str,
        entities: EntitySet,
        time_range: dict[str, str],
        *,
        ioc_list: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """Build tool params from triage entities — no hardcoded demo identities."""
        account = next((a.username for a in entities.accounts if a.username), None)
        host = next((h for h in entities.hosts if h.hostname or h.ip), None)
        hostname = host.hostname if host else None
        host_ip = host.ip if host else None
        internal_ip = next(
            (ip.address for ip in entities.ips if ip.address and ip.scope == "internal"),
            host_ip,
        )
        external_ip = next(
            (ip.address for ip in entities.ips if ip.address and ip.scope == "external"),
            None,
        )
        domain = next((d.fqdn for d in entities.domains if d.fqdn), None)
        iocs = [item for item in (ioc_list or []) if item]
        indicator = next(iter(iocs), None) or external_ip or domain

        if tool_name == "query_account_login":
            if not account:
                return None
            return {"account": account, "time_range": time_range}
        if tool_name == "query_edr_process":
            if not hostname:
                return None
            return {"host_id": hostname, "time_range": time_range}
        if tool_name == "query_file_access":
            if not account:
                return None
            return {"account": account, "time_range": time_range}
        if tool_name == "query_network_flow":
            if not internal_ip and not external_ip:
                return None
            params: dict[str, Any] = {"time_range": time_range}
            if internal_ip:
                params["src_ip"] = internal_ip
            elif external_ip:
                params["dst_ip"] = external_ip
            return params
        if tool_name == "query_dns":
            if not domain:
                return None
            return {"domain": domain, "time_range": time_range}
        if tool_name == "query_asset_info":
            if not host_ip and not hostname:
                return None
            params = {}
            if host_ip:
                params["ip"] = host_ip
            if hostname:
                params["hostname"] = hostname
            return params
        if tool_name == "query_threat_intel":
            if not indicator:
                return None
            return {"indicator": indicator}
        return None

    @staticmethod
    def _dedup_and_sort(items: list[Evidence]) -> list[Evidence]:
        best: dict[tuple[str, str, datetime | None], Evidence] = {}
        for item in items:
            ts = truncate_timestamp_to_second(item.timestamp)
            key = (
                item.source.value if isinstance(item.source, EvidenceSource) else str(item.source),
                item.evidence_type,
                ts,
            )
            existing = best.get(key)
            if existing is None or item.confidence > existing.confidence:
                if ts != item.timestamp:
                    item = item.model_copy(update={"timestamp": ts})
                best[key] = item

        def sort_key(ev: Evidence) -> tuple[int, datetime]:
            if ev.timestamp is None:
                return (1, datetime.min.replace(tzinfo=UTC))
            return (0, ev.timestamp)

        return sorted(best.values(), key=sort_key)

    @staticmethod
    def _collection_status(success_count: int) -> CollectionStatus:
        """Map parser-success source count to collection_status (ISSUE-101).

        Thresholds: COMPLETED >=5, PARTIAL_DONE 3-4, DEGRADED 1-2, FAILED 0.
        """
        if success_count >= _COLLECTION_STATUS_COMPLETED:
            return CollectionStatus.COMPLETED
        if success_count >= _COLLECTION_STATUS_PARTIAL_DONE:
            return CollectionStatus.PARTIAL_DONE
        if success_count >= _COLLECTION_STATUS_DEGRADED:
            return CollectionStatus.DEGRADED
        return CollectionStatus.FAILED

    @staticmethod
    def _overall_confidence(
        evidence_list: list[Evidence],
        collection_status: CollectionStatus,
    ) -> float:
        if not evidence_list:
            return 0.0
        avg_conf = sum(item.confidence for item in evidence_list) / len(evidence_list)
        unique_sources = {item.source for item in evidence_list}
        diversity = min(len(unique_sources), 5) / 5.0 * 0.15
        quantity = min(len(evidence_list), 6) / 6.0 * 0.1
        penalty = _STATUS_PENALTY[collection_status]
        score = avg_conf * 0.75 + diversity + quantity - penalty
        return min(1.0, max(0.0, score))
