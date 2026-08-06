"""TriageAgent — alert parsing, entity extraction, event typing, IOC list (ISSUE-032).

LLM primary path + regex fallback. Severity is assigned via deterministic
``SEVERITY_RULES``; ``need_investigation`` is ``True`` when severity >= medium.
Two hook lists (``pre_triage_hooks``, ``post_triage_hooks``) alias the base
``pre_hooks`` / ``post_hooks`` lists. The vector-based ``FalsePositiveMatcherHook``
runs as a post-triage hook so it has access to the LLM-extracted entities in
``triage_result`` and writes advisory ``false_positive_match`` metadata only
(``investigate_with_flag`` at most — ISSUE-114). Typed FP closure happens only
after evidence via :class:`PostEvidenceFpAdjudicator`.
"""

from __future__ import annotations

import ipaddress
import logging
import re as _re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.agents.base import BaseAgent
from app.agents.prompts.triage_prompt import TriageLLMResponse, build_triage_messages
from app.agents.rules.entity_extraction_rules import (
    IP_PATTERN,
    extract_entities_regex,
)
from app.agents.rules.entity_validation import EntityValidationResult, validate_entity_set
from app.core.config import get_settings
from app.core.errors import (
    DependencyUnavailableError,
    GuardrailViolationError,
    LLMError,
    ShadowTraceError,
)
from app.core.llm.base import LLMResponse
from app.core.llm.scenario_context import resolve_llm_scenario_id
from app.core.network_utils import is_internal_ip
from app.models.agent_io import (
    EntityConflictRecord,
    EntityProvenanceRecord,
    TriageAgentInput,
    TriageResult,
)
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.enums import EventType, Severity
from app.services.classification import human_override_event_type
from app.services.entity_merge import EntityMergeResult, merge_entity_sets
from app.services.working_memory import BoundWorkingMemory

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# SEVERITY_RULES — deterministic severity based on event_type
# --------------------------------------------------------------------------- #

SEVERITY_RULES: dict[str, list[tuple[str, str]]] = {
    # data_exfiltration with an external IP present → HIGH (ISSUE-032 spec:
    # "数据外泄类加外部 IP 为 high").  Without an external IP (e.g. pure
    # internal server-to-server exfiltration) severity is MEDIUM — the check
    # is applied in _apply_severity_rules via _external_ip_in_text().
    "high": [
        ("event_type", "data_exfiltration"),
        ("event_type", "malicious_process"),
        ("event_type", "host_compromise"),
        ("event_type", "lateral_movement"),
    ],
    # data_exfiltration + lateral_movement co-occurrence → critical (checked
    # in _apply_severity_rules via alert_text word-boundary match on
    # "lateral" so words like "bilateral"/"collateral" are excluded).
    "critical": [
        ("event_type", "data_exfiltration"),
    ],
    "low": [
        ("event_type", "account_anomaly"),
    ],
}

# --------------------------------------------------------------------------- #
# IOC extraction helpers
# --------------------------------------------------------------------------- #

# IP_PATTERN is imported from entity_extraction_rules to avoid duplication.
_IOC_DOMAIN_PATTERN: _re.Pattern[str] = _re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)
_IOC_HASH_PATTERN: _re.Pattern[str] = _re.compile(
    r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
)
_IOC_URL_PATTERN: _re.Pattern[str] = _re.compile(r"https?://[^\s,;\"'<>]+")

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #


def _apply_severity_rules(
    event_type: EventType,
    alert_text: str = "",
) -> tuple[Severity, bool]:
    """Assign severity and need_investigation via SEVERITY_RULES.

    Returns:
        (severity, need_investigation) — need_investigation is True when
        severity is medium or higher.
    """
    severity = Severity.LOW
    event_type_value = event_type.value if isinstance(event_type, EventType) else event_type

    # Check critical rules first — highest priority.
    for rule_key, rule_val in SEVERITY_RULES.get("critical", []):
        if rule_key == "event_type" and rule_val == event_type_value:
            # Critical: data_exfiltration with lateral movement co-occurrence.
            # Use word-boundary match to avoid false positives on "bilateral",
            # "collateral", etc.
            if alert_text and _re.search(r"\blateral\b", alert_text.lower()):
                severity = Severity.CRITICAL
                return severity, True

    # Check high rules.
    for rule_key, rule_val in SEVERITY_RULES.get("high", []):
        if rule_key == "event_type" and rule_val == event_type_value:
            # ISSUE-032 spec: data_exfiltration → HIGH only when an external
            # IP is present in the alert text.  Pure internal exfiltration
            # (no external IP) → MEDIUM.
            if event_type_value == "data_exfiltration":
                if alert_text and _external_ip_in_text(alert_text):
                    severity = Severity.HIGH
                    return severity, True
                severity = Severity.MEDIUM
                return severity, True
            severity = Severity.HIGH
            return severity, True

    # Check low rules.
    for rule_key, rule_val in SEVERITY_RULES.get("low", []):
        if rule_key == "event_type" and rule_val == event_type_value:
            # P0 simplification: all account_anomaly → LOW per ISSUE-032.
            # Upgrade to MEDIUM when alert_text suggests bulk/mass activity,
            # privilege escalation, or geo-anomaly (to be refined in ISSUE-078).
            if event_type_value == "account_anomaly" and alert_text:
                _at = alert_text.lower()
                if any(
                    kw in _at
                    for kw in (
                        "bulk",
                        "mass",
                        "privilege escalation",
                        "地域异常",
                        "geo-anomaly",
                        "impossible travel",
                        "brute force",
                        "password spray",
                    )
                ):
                    severity = Severity.MEDIUM
                    return severity, True
            severity = Severity.LOW
            return severity, False

    # Default for unlisted event types: medium.
    severity = Severity.MEDIUM
    return severity, True


def _external_ip_in_text(alert_text: str) -> bool:
    """Return True when *alert_text* contains at least one external (non-internal) IP.

    Used by ``_apply_severity_rules`` to decide whether a data_exfiltration
    event qualifies for HIGH severity per ISSUE-032.
    """
    for ip_match in IP_PATTERN.findall(alert_text):
        if not is_internal_ip(ip_match):
            return True
    return False


def _extract_iocs(
    alert_text: str,
    entities: EntitySet | None = None,
) -> list[str]:
    """Extract IoC strings from raw alert text and entity IPs.

    Only external (non-internal) IPs are included.
    """
    iocs: set[str] = set()

    # Extract from raw text.
    for ip in IP_PATTERN.findall(alert_text):
        if not is_internal_ip(ip):
            iocs.add(ip)
    for domain in _IOC_DOMAIN_PATTERN.findall(alert_text):
        iocs.add(domain)
    for hash_val in _IOC_HASH_PATTERN.findall(alert_text):
        iocs.add(hash_val)
    for url in _IOC_URL_PATTERN.findall(alert_text):
        iocs.add(url)

    # Include external IPs from entities.
    if entities is not None:
        for ip_entity in entities.ips:
            addr = ip_entity.address or ""
            if addr and not is_internal_ip(addr):
                iocs.add(addr)

    # Sort: IPs via ipaddress for natural ordering, everything else
    # lexicographically.  This avoids "8.8.8.8" < "10.0.0.1" in string sort.
    def _ioc_sort_key(value: str) -> tuple[int, object]:
        try:
            addr = ipaddress.ip_address(value)
            return (0, addr)  # IP addresses sorted numerically
        except ValueError:
            return (1, value)  # domains, hashes, URLs sorted lexicographically

    return sorted(iocs, key=_ioc_sort_key)


def _resolve_alert_type_from_snapshot(snapshot: dict[str, Any] | None) -> str | None:
    """Resolve ``alert_type`` from frozen ``source_snapshot``.

    Primary path: top-level ``alert_type`` on the normalized snapshot.
    File fallback only: read the compatible ``raw_alert_snapshot`` field when
    the normalized snapshot has no ``alert_type`` (ISSUE-032 unified naming).
    """
    if not isinstance(snapshot, dict):
        return None

    top_level = snapshot.get("alert_type")
    if top_level:
        return str(top_level)

    raw_snap = snapshot.get("raw_alert_snapshot")
    if not isinstance(raw_snap, dict):
        return None

    nested_type = raw_snap.get("alert_type")
    if nested_type:
        return str(nested_type)

    raw_payload = raw_snap.get("raw")
    if isinstance(raw_payload, dict):
        payload_type = raw_payload.get("alert_type")
        if payload_type:
            return str(payload_type)

    return None


def _source_event_type_authoritative(raw_type: str | None) -> EventType | None:
    """Return a concrete source-mapped type; treat OTHER/missing as unresolved."""
    if not raw_type:
        return None
    try:
        mapped = EventType(raw_type.lower())
    except ValueError:
        return None
    if mapped is EventType.OTHER:
        return None
    return mapped


def _heuristic_event_type(alert_text: str) -> EventType | None:
    """Keyword/type inference when source type is missing or only OTHER."""
    text = alert_text.lower()
    if not text.strip():
        return None
    if any(
        kw in text
        for kw in (
            "exfil",
            "upload",
            "data export",
            "bulk export",
            "export monitor",
            "exported to",
            "外传",
            "外泄",
            "数据外",
            "schema-export",
            "staging area",
        )
    ):
        return EventType.DATA_EXFILTRATION
    if "login fail" in text or "failed to login" in text or "login attempt" in text:
        return EventType.ACCOUNT_ANOMALY
    if "process" in text or "executed" in text or "malware" in text or "powershell" in text:
        return EventType.MALICIOUS_PROCESS
    if "domain" in text or "dns" in text:
        return EventType.SUSPICIOUS_DOMAIN
    if "lateral" in text or "pivot" in text:
        return EventType.LATERAL_MOVEMENT
    if "host" in text or "compromise" in text or "infected" in text:
        return EventType.HOST_COMPROMISE
    if "insider" in text or "privilege" in text or _re.search(r"(?<!de-)escalation\b", text):
        return EventType.INSIDER_THREAT
    return None


def _map_event_type(
    raw_type: str | None,
    alert_text: str = "",
) -> EventType:
    """Map source alert_type to EventType with auditable heuristic fallback.

    Explicit non-OTHER source labels remain authoritative (ISSUE-032). When
    ingestion only supplies OTHER or the field is missing, keyword heuristics
    on alert text may upgrade the classification (ISSUE-197).
    """
    authoritative = _source_event_type_authoritative(raw_type)
    if authoritative is not None:
        return authoritative
    heuristic = _heuristic_event_type(alert_text)
    if heuristic is not None:
        return heuristic
    return EventType.OTHER


def _provenance_from_hint_entities(hint_entities: EntitySet) -> list[EntityProvenanceRecord]:
    """Summarize structured source refs on hint entities (no raw payload)."""
    records: list[EntityProvenanceRecord] = []
    seen: set[tuple[str, str, str]] = set()
    for category in EntitySet.model_fields:
        for entity in getattr(hint_entities, category):
            for ref in entity.source_refs or []:
                key = (ref.source_kind.value, ref.source_object_id, category)
                if key in seen:
                    continue
                seen.add(key)
                records.append(
                    EntityProvenanceRecord(
                        source_kind=ref.source_kind.value,
                        source_object_id=ref.source_object_id,
                        connector_id=ref.connector_id,
                        entity_category=category,
                    )
                )
    return records


def _conflicts_to_records(merge_result: EntityMergeResult) -> list[EntityConflictRecord]:
    return [
        EntityConflictRecord(
            entity_type=item.entity_type,
            semantic_key=item.semantic_key,
            kept_source=item.kept_source,
            discarded_source=item.discarded_source,
            reason=item.reason,
        )
        for item in merge_result.conflicts
    ]


def _aggregate_rejection_summaries(
    *parts: dict[str, Any] | EntityValidationResult | None,
) -> dict[str, Any]:
    """Merge truncated rejection counts for decision trace (no raw values)."""
    counts: dict[str, int] = {}
    total = 0
    for part in parts:
        if part is None:
            continue
        summary = part.rejection_summary if isinstance(part, EntityValidationResult) else part
        if not summary:
            continue
        total += int(summary.get("total_rejected", 0))
        for code, count in summary.get("rejection_counts", {}).items():
            counts[str(code)] = counts.get(str(code), 0) + int(count)
    if not total:
        return {}
    return {"rejection_counts": counts, "total_rejected": total}


def _build_triage_decision_summary(
    *,
    event_type: EventType,
    severity: Severity,
    need_investigation: bool,
    notes: list[str],
) -> str:
    base = (
        f"event_type={event_type.value}, severity={severity.value}, "
        f"need_investigation={need_investigation}"
    )
    if not notes:
        return base[:512]
    joined = "; ".join(note.strip() for note in notes if note.strip())
    return f"{base}; {joined}"[:512]


@dataclass(frozen=True, slots=True)
class TextExtractionResult:
    """LLM/regex text extraction output with validation rejection counts."""

    llm_entities: EntitySet
    regex_entities: EntitySet
    text_degraded: bool
    decision_summary: str
    rejection_summary: dict[str, Any]
    llm_event_type: EventType | None = None


# --------------------------------------------------------------------------- #
# TriageAgent
# --------------------------------------------------------------------------- #


class TriageAgent(BaseAgent[TriageAgentInput, TriageResult]):
    """Stage 1 Agent: parse alert → entities, event_type, severity, IoCs.

    Primary path: LLM (JSON mode) → EntitySet.
    Fallback path: regex when LLM is unavailable or fails.
    """

    agent_name: str = "triage_agent"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        tool_executor: Any | None = None,
        working_memory: BoundWorkingMemory | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
        fp_matcher: Any | None = None,
        scenario_id: str | None = None,
        degraded_flags: Any | None = None,
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
        self.scenario_id = scenario_id
        self.degraded_flags = degraded_flags

        # Convenience aliases matching the Issue-032 naming convention.
        self.pre_triage_hooks = self.pre_hooks
        self.post_triage_hooks = self.post_hooks

        # Install the ISSUE-078 FalsePositiveMatcherHook (vector-based FP matching).
        # Runs as a POST-triage hook so it has access to the LLM-extracted
        # (and hint-merged) entities in triage_result — fixing the ISSUE-078
        # spec requirement that FP matching uses the final EntitySet.
        # ISSUE-114: pre-evidence vector similarity is advisory only; no rule hook.
        if working_memory is not None and fp_matcher is not None:
            from app.services.false_positive_matcher import FalsePositiveMatcherHook

            fp_matcher_memory = working_memory.for_writer("FalsePositiveMatcher")
            self.post_triage_hooks.append(
                FalsePositiveMatcherHook(
                    matcher=fp_matcher,
                    working_memory=fp_matcher_memory,
                )
            )

    # ------------------------------------------------------------------ #
    # _run
    # ------------------------------------------------------------------ #

    async def _run(self, input: TriageAgentInput) -> TriageResult:
        """Execute the full triage pipeline."""
        degraded = False
        summary_notes: list[str] = []

        # 1. Map event type from source_snapshot (file fallback via raw_alert_snapshot).
        # ISSUE-209: durable human override wins over source/heuristic/LLM remapping
        # so reinvestigate keeps ResponseAgent rules aligned with the analyst type.
        human_type_value = await self._read_human_override_event_type(input.event_id)
        snapshot = await self._read_source_snapshot(input.event_id)
        raw_type = _resolve_alert_type_from_snapshot(snapshot)
        authoritative_type = _source_event_type_authoritative(raw_type)
        if human_type_value is not None:
            try:
                event_type = EventType(human_type_value)
            except ValueError:
                event_type = _map_event_type(raw_type, input.raw_event_summary)
                human_type_value = None
            else:
                summary_notes.append(
                    f"Event type retained from human classification override: {event_type.value}."
                )
        else:
            event_type = _map_event_type(raw_type, input.raw_event_summary)

        # 2. Entity extraction — LLM primary, regex fallback; merge with source hints.
        extraction = await self._extract_entities(
            input.raw_event_summary,
            input.event_id,
            source_snapshot=snapshot,
        )
        source_validated = validate_entity_set(
            input.hint_entities,
            provenance="source",
            alert_text=input.raw_event_summary,
        )
        merge_result = merge_entity_sets(
            source=source_validated.entity_set
            if source_validated.entity_set != EntitySet()
            else None,
            llm=extraction.llm_entities if extraction.llm_entities != EntitySet() else None,
            regex=extraction.regex_entities if extraction.regex_entities != EntitySet() else None,
        )
        entities = merge_result.entities
        degradation_reasons = list(merge_result.degradation_reasons)
        degraded = extraction.text_degraded and source_validated.entity_set == EntitySet()

        if human_type_value is None:
            if authoritative_type is None and event_type is not EventType.OTHER:
                degradation_reasons.append("event_type_from_heuristic")
                await self._persist_event_type_audit_flag(
                    input.event_id,
                    "event_type_from_heuristic",
                    event_type.value,
                )

            if (
                event_type is EventType.OTHER
                and extraction.llm_event_type is not None
                and extraction.llm_event_type is not EventType.OTHER
                and get_settings().triage_llm_event_type_fallback
            ):
                event_type = extraction.llm_event_type
                degradation_reasons.append("event_type_from_llm_fallback")
                summary_notes.append(f"Event type adopted from LLM fallback: {event_type.value}.")
                await self._persist_event_type_audit_flag(
                    input.event_id,
                    "event_type_from_llm_fallback",
                    event_type.value,
                )

        if extraction.text_degraded and not degraded:
            summary_notes.append("Text entity extraction empty; using structured source entities.")
        elif extraction.text_degraded:
            degraded = True
            summary_notes.append("Entity extraction degraded to regex fallback.")
        if extraction.decision_summary:
            summary_notes.append(extraction.decision_summary)
        if merge_result.conflicts:
            summary_notes.append(
                f"Resolved {len(merge_result.conflicts)} entity conflict(s) with source priority."
            )
        entity_rejection_summary = _aggregate_rejection_summaries(
            extraction.rejection_summary,
            source_validated,
        )
        text_rejected = int((extraction.rejection_summary or {}).get("total_rejected", 0))
        source_rejected = int(source_validated.rejection_summary.get("total_rejected", 0))
        if text_rejected:
            summary_notes.append(
                f"Rejected {text_rejected} invalid text-derived entity candidate(s)."
            )
        if source_rejected:
            summary_notes.append(f"Rejected {source_rejected} invalid source entity candidate(s).")
        if source_validated.rejection_summary["total_rejected"]:
            degradation_reasons.append("source_enrichment_partial")

        # 4. Severity + need_investigation.
        severity, need_investigation = _apply_severity_rules(
            event_type, alert_text=input.raw_event_summary
        )

        # 5. IOC extraction.
        ioc_list = _extract_iocs(input.raw_event_summary, entities)

        decision_summary = _build_triage_decision_summary(
            event_type=event_type,
            severity=severity,
            need_investigation=need_investigation,
            notes=summary_notes,
        )

        # 6. Build result.
        result = TriageResult(
            event_type=event_type,
            severity=severity,
            need_investigation=need_investigation,
            entities=entities,
            ioc_list=ioc_list,
            decision_summary=decision_summary,
            reasoning="",
            degraded=degraded,
            degradation_reasons=degradation_reasons,
            entity_provenance_summary=_provenance_from_hint_entities(input.hint_entities),
            entity_conflicts=_conflicts_to_records(merge_result),
            entity_rejection_summary=entity_rejection_summary,
        )

        # 7. Persist to EventContext.
        await self._write_triage_result(input, result)

        return result

    # ------------------------------------------------------------------ #
    # Entity extraction (LLM primary → regex fallback)
    # ------------------------------------------------------------------ #

    async def _extract_entities(
        self,
        alert_text: str,
        event_id: str,
        *,
        source_snapshot: dict[str, Any] | None = None,
    ) -> TextExtractionResult:
        """Extract entities via LLM (JSON mode) with optional regex fallback."""
        empty = EntitySet()
        empty_summary: dict[str, Any] = {}
        if self.llm_client is None:
            regex_result = await self._regex_fallback(alert_text)
            return TextExtractionResult(
                llm_entities=empty,
                regex_entities=regex_result.entity_set,
                text_degraded=True,
                decision_summary="",
                rejection_summary=regex_result.rejection_summary,
            )

        if not alert_text.strip():
            return TextExtractionResult(
                llm_entities=empty,
                regex_entities=empty,
                text_degraded=False,
                decision_summary="",
                rejection_summary=empty_summary,
            )

        try:
            messages = build_triage_messages(alert_text)
            response: LLMResponse = await self.llm_client.chat(
                messages,
                event_id=event_id,
                agent_name=self.agent_name,
                prompt_key="triage_extract",
                scenario_id=resolve_llm_scenario_id(
                    override=self.scenario_id,
                    source_snapshot=source_snapshot,
                ),
                json_mode=True,
                response_model=TriageLLMResponse,
                temperature=0.3,
                max_tokens=4096,
                timeout=15.0,
            )

            if response.parsed is not None and isinstance(response.parsed, TriageLLMResponse):
                parsed: TriageLLMResponse = response.parsed
                llm_validated = validate_entity_set(
                    parsed.entities,
                    provenance="llm",
                    alert_text=alert_text,
                )
                if any(
                    (
                        llm_validated.entity_set.accounts,
                        llm_validated.entity_set.hosts,
                        llm_validated.entity_set.ips,
                        llm_validated.entity_set.domains,
                        llm_validated.entity_set.processes,
                        llm_validated.entity_set.files,
                    )
                ):
                    summary = parsed.decision_summary or ""
                    rejected = llm_validated.rejection_summary["total_rejected"]
                    if rejected:
                        summary = (
                            f"{summary} LLM validation rejected {rejected} entity candidate(s)."
                        ).strip()
                    return TextExtractionResult(
                        llm_entities=llm_validated.entity_set,
                        regex_entities=empty,
                        text_degraded=False,
                        decision_summary=summary[:512],
                        rejection_summary=llm_validated.rejection_summary,
                        llm_event_type=parsed.event_type,
                    )

                regex_result = await self._regex_fallback(alert_text)
                return TextExtractionResult(
                    llm_entities=empty,
                    regex_entities=regex_result.entity_set,
                    text_degraded=True,
                    decision_summary=(parsed.decision_summary or "")[:512],
                    rejection_summary=_aggregate_rejection_summaries(
                        llm_validated,
                        regex_result,
                    ),
                    llm_event_type=parsed.event_type,
                )

            regex_result = await self._regex_fallback(alert_text)
            return TextExtractionResult(
                llm_entities=empty,
                regex_entities=regex_result.entity_set,
                text_degraded=True,
                decision_summary="",
                rejection_summary=regex_result.rejection_summary,
            )

        except (TimeoutError, OSError) as exc:
            logger.warning(
                "LLM transport/timeout error for event=%s: %s",
                event_id,
                exc,
                exc_info=True,
            )
            regex_result = await self._regex_fallback(alert_text)
            return TextExtractionResult(
                llm_entities=empty,
                regex_entities=regex_result.entity_set,
                text_degraded=True,
                decision_summary="",
                rejection_summary=regex_result.rejection_summary,
            )

        except ShadowTraceError as exc:
            if isinstance(exc, LLMError):
                logger.warning(
                    "LLM entity extraction failed for event=%s: %s",
                    event_id,
                    exc,
                    exc_info=True,
                )
            else:
                logger.warning(
                    "ShadowTrace error during entity extraction for event=%s: %s",
                    event_id,
                    exc,
                    exc_info=True,
                )
            regex_result = await self._regex_fallback(alert_text)
            return TextExtractionResult(
                llm_entities=empty,
                regex_entities=regex_result.entity_set,
                text_degraded=True,
                decision_summary="",
                rejection_summary=regex_result.rejection_summary,
            )

        except Exception as exc:
            logger.warning(
                "Unexpected LLM entity extraction error for event=%s: %s",
                event_id,
                exc,
                exc_info=True,
            )
            regex_result = await self._regex_fallback(alert_text)
            return TextExtractionResult(
                llm_entities=empty,
                regex_entities=regex_result.entity_set,
                text_degraded=True,
                decision_summary="",
                rejection_summary=regex_result.rejection_summary,
            )

    async def _regex_fallback(self, alert_text: str) -> EntityValidationResult:
        """Run regex extraction, validate, and return accepted entities + rejections."""
        raw = extract_entities_regex(alert_text)
        candidates = EntitySet(
            accounts=[
                AccountEntity(
                    entity_id=f"acct-{i}",
                    entity_type="account",
                    username=a,
                )
                for i, a in enumerate(raw.accounts, 1)
            ],
            hosts=[
                HostEntity(
                    entity_id=f"host-{i}",
                    entity_type="host",
                    hostname=h,
                )
                for i, h in enumerate(raw.hostnames, 1)
            ],
            ips=[
                IPEntity(
                    entity_id=f"ip-{i}",
                    entity_type="ip",
                    address=ip,
                    scope="internal" if is_internal_ip(ip) else "external",
                )
                for i, ip in enumerate(raw.ips, 1)
            ],
            domains=[
                DomainEntity(
                    entity_id=f"dom-{i}",
                    entity_type="domain",
                    fqdn=d,
                )
                for i, d in enumerate(raw.domains, 1)
            ],
            processes=[
                ProcessEntity(
                    entity_id=f"proc-{i}",
                    entity_type="process",
                    name=p,
                )
                for i, p in enumerate(raw.processes, 1)
            ],
            files=[
                FileEntity(
                    entity_id=f"file-{i}",
                    entity_type="file",
                    name=f,
                )
                for i, f in enumerate(raw.files, 1)
            ],
        )
        return validate_entity_set(
            candidates,
            provenance="regex",
            alert_text=alert_text,
        )

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    async def _write_triage_result(self, input: TriageAgentInput, result: TriageResult) -> None:
        """Persist ``triage_result`` to ``EventContext``.

        GuardrailViolationError (FIELD_OWNERSHIP mismatch) is always
        propagated — it indicates a code defect that must be fixed.
        Transient I/O failures are logged AND reflected on the result
        (``degraded=True``, degradation_reason annotation).  A lightweight
        ``triage_degraded`` flag is written separately so that downstream
        agents / recovery logic can detect the persistence gap even if the
        full result was not durably stored.
        """
        wm = self.working_memory
        if wm is None:
            return
        try:
            await wm.write(
                input.event_id,
                "triage_result",
                result.model_dump(mode="json"),
            )
        except GuardrailViolationError:
            # FIELD_OWNERSHIP violation is a code defect — must propagate.
            logger.exception(
                "GuardrailViolationError writing triage_result for event=%s",
                input.event_id,
            )
            raise
        except (DependencyUnavailableError, ConnectionError, TimeoutError):
            # Transient I/O failure (Redis, DB) — mark degraded so the
            # caller / downstream agents know this result is not durable.
            logger.warning(
                "Transient failure writing triage_result to EventContext for event=%s",
                input.event_id,
                exc_info=True,
            )
            result.degraded = True
            result.degradation_reasons.append(
                "triage_result persistence failed: working memory unavailable"
            )
            # Best-effort persistence of the degraded flag so recovery /
            # downstream agents can detect the gap.
            await self._try_persist_degraded_flag(input.event_id)
        except ShadowTraceError as exc:
            if exc.retryable:
                logger.warning(
                    "Retryable error writing triage_result for event=%s: %s",
                    input.event_id,
                    exc.error_code,
                    exc_info=True,
                )
                result.degraded = True
                result.degradation_reasons.append(
                    f"triage_result persistence failed: {exc.error_code}"
                )
                await self._try_persist_degraded_flag(input.event_id)
            else:
                raise

    async def _persist_event_type_audit_flag(
        self,
        event_id: str,
        flag_name: str,
        value: str,
    ) -> None:
        """Mirror ISSUE-197 fallback reasons into security_event.degraded_flags."""
        if self.degraded_flags is None:
            return
        try:
            await self.degraded_flags.set_flag(
                event_id,
                flag_name,
                value,
                writer="TriageAgent",
            )
        except Exception:
            logger.warning(
                "Failed to persist degraded flag %s for event=%s",
                flag_name,
                event_id,
                exc_info=True,
            )

    async def _try_persist_degraded_flag(self, event_id: str) -> None:
        """Best-effort write of a lightweight ``triage_degraded`` flag.

        Called when the main ``triage_result`` write fails transiently.
        If even this lightweight write fails the error is logged but never
        propagated — the in-memory ``result.degraded=True`` is the final
        fallback for the immediate caller.
        """
        wm = self.working_memory
        if wm is None:
            return
        try:
            await wm.write(
                event_id,
                "triage_degraded",
                {
                    "degraded": True,
                    "reason": "triage_result persistence failed",
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            )
        except ShadowTraceError:
            # All expected working-memory failures (connection errors,
            # GuardrailViolationError, DependencyUnavailableError, etc.)
            # are ShadowTraceError subclasses.  Programming errors
            # (AttributeError, TypeError, …) are intentionally allowed to
            # propagate so they surface in tests / monitoring rather than
            # being silently masked by an overly broad ``except Exception``.
            logger.exception(
                "Failed to persist triage_degraded flag for event=%s",
                event_id,
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    async def _read_human_override_event_type(self, event_id: str) -> str | None:
        """Read durable ISSUE-209 human classification override, if present."""
        wm = self.working_memory
        if wm is None:
            return None
        try:
            value = await wm.read(event_id, "classification_override")
        except GuardrailViolationError:
            logger.exception(
                "GuardrailViolationError reading classification_override for event=%s",
                event_id,
            )
            raise
        except (DependencyUnavailableError, ConnectionError, TimeoutError):
            return None
        except Exception:
            logger.warning(
                "classification_override read failed event=%s",
                event_id,
                exc_info=True,
            )
            return None
        return human_override_event_type(value if isinstance(value, dict) else None)

    async def _read_source_snapshot(self, event_id: str) -> dict[str, Any] | None:
        """Read the ``source_snapshot`` field from working memory.

        Transient I/O failures return None so the agent can continue with
        fallback keyword matching.  ``GuardrailViolationError`` is propagated
        because it indicates a code defect (e.g. FIELD_OWNERSHIP mismatch)
        that must be surfaced, consistent with ``_write_triage_result``.
        """
        wm = self.working_memory
        if wm is None:
            return None
        try:
            value = await wm.read(event_id, "source_snapshot")
            return value if isinstance(value, dict) else None
        except GuardrailViolationError:
            logger.exception(
                "GuardrailViolationError reading source_snapshot for event=%s",
                event_id,
            )
            raise
        except (DependencyUnavailableError, ConnectionError, TimeoutError):
            return None


__all__ = [
    "SEVERITY_RULES",
    "TriageAgent",
    "_apply_severity_rules",
    "_extract_iocs",
    "_external_ip_in_text",
    "_map_event_type",
    "_resolve_alert_type_from_snapshot",
]
