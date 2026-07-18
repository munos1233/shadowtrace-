"""Agent output and outbound disposition guard rails (ISSUE-030 / intro §4.13)."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.config import Settings, get_settings
from app.core.errors import GuardrailViolationError
from app.core.sanitization import is_sensitive_key, redact_sensitive_text, sanitize_data
from app.models.action import Action
from app.models.agent_io import EvidenceOutput, GraphOutput, RAGOutput, ResponsePlan, RiskAssessment
from app.models.disposition import DispositionCommand, SourceObjectLocator
from app.models.entities import EntitySet
from app.models.enums import GuardRailDimension
from app.models.report import InvestigationReport

logger = logging.getLogger(__name__)

GuardSeverity = Literal["block", "warn"]

_EVIDENCE_ID_RE = re.compile(r"\bevd-[A-Za-z0-9_-]+\b")
_CITATION_ID_RE = re.compile(r"\bcit-[A-Za-z0-9_-]+\b")

_ANALYSIS_KEY_FRAGMENTS = frozenset(
    {
        "report",
        "prompt",
        "decision_trace",
        "decisiontrace",
        "evidence",
        "evidence_list",
        "evidence_output",
        "reasoning",
        "analysis",
        "narrative",
        "raw_result",
        "raw_payload",
        "storyline",
        "trace",
    }
)

_DISPOSITION_ALLOWED_TOP_LEVEL = frozenset(DispositionCommand.model_fields.keys())


class GuardrailMode(StrEnum):
    ENFORCE = "enforce"
    WARN_ONLY = "warn_only"


class GuardViolation(BaseModel):
    """One guard-rail finding."""

    model_config = ConfigDict(extra="forbid")

    dimension: GuardRailDimension
    rule_name: str
    severity: GuardSeverity
    detail: str


class GuardResult(BaseModel):
    """Aggregated validation outcome for one output or outbound payload."""

    model_config = ConfigDict(extra="forbid")

    passed: bool
    violations: list[GuardViolation] = Field(default_factory=list)
    sanitized_output: Any | None = None


@dataclass(frozen=True, slots=True)
class GuardRule:
    """Named rule binding applied to selected agents."""

    rule_name: str
    dimension: GuardRailDimension
    severity: GuardSeverity = "block"
    downgradable: bool = True


RuleChecker = Callable[[str, Any, Mapping[str, Any], GuardRule], list[GuardViolation]]


def _as_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, BaseModel):
        return value.model_dump(mode="python")
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _collect_strings(value: Any, *, depth: int = 0) -> list[str]:
    if depth > 24 or value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, BaseModel):
        return _collect_strings(value.model_dump(mode="python"), depth=depth + 1)
    if isinstance(value, Mapping):
        out: list[str] = []
        for item in value.values():
            out.extend(_collect_strings(item, depth=depth + 1))
        return out
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        collected: list[str] = []
        for item in value:
            collected.extend(_collect_strings(item, depth=depth + 1))
        return collected
    return []


def _walk_keys(value: Any, *, depth: int = 0) -> list[tuple[str, Any]]:
    if depth > 24 or value is None:
        return []
    if isinstance(value, BaseModel):
        return _walk_keys(value.model_dump(mode="python"), depth=depth + 1)
    if isinstance(value, Mapping):
        found: list[tuple[str, Any]] = []
        for key, item in value.items():
            found.append((str(key), item))
            found.extend(_walk_keys(item, depth=depth + 1))
        return found
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        found = []
        for item in value:
            found.extend(_walk_keys(item, depth=depth + 1))
        return found
    return []


def entity_identity_values(entities: EntitySet | Mapping[str, Any] | None) -> set[str]:
    """Flatten EntitySet into comparable identity strings."""

    if entities is None:
        return set()
    model = entities if isinstance(entities, EntitySet) else EntitySet.model_validate(entities)
    values: set[str] = set()
    for account in model.accounts:
        values.add(account.entity_id)
        if account.username:
            values.add(account.username)
    for host in model.hosts:
        values.add(host.entity_id)
        if host.hostname:
            values.add(host.hostname)
        if host.ip:
            values.add(host.ip)
    for ip in model.ips:
        values.add(ip.entity_id)
        if ip.address:
            values.add(ip.address)
    for domain in model.domains:
        values.add(domain.entity_id)
        if domain.fqdn:
            values.add(domain.fqdn)
    for process in model.processes:
        values.add(process.entity_id)
        if process.name:
            values.add(process.name)
        if process.hash:
            values.add(process.hash)
    for file_entity in model.files:
        values.add(file_entity.entity_id)
        if file_entity.path:
            values.add(file_entity.path)
        if file_entity.name:
            values.add(file_entity.name)
        if file_entity.hash:
            values.add(file_entity.hash)
    return {item for item in values if item}


def evidence_ids_from_context(context: Mapping[str, Any]) -> set[str]:
    raw = context.get("evidence_ids")
    if isinstance(raw, (set, list, tuple)):
        return {str(item) for item in raw if item}
    evidence_output = context.get("evidence_output")
    payload = _as_mapping(evidence_output)
    ids: set[str] = set()
    for item in payload.get("evidence_list") or []:
        evidence_id = _as_mapping(item).get("evidence_id")
        if evidence_id:
            ids.add(str(evidence_id))
    return ids


def citation_ids_from_context(context: Mapping[str, Any]) -> set[str]:
    raw = context.get("citation_ids")
    if isinstance(raw, (set, list, tuple)):
        return {str(item) for item in raw if item}
    rag = _as_mapping(context.get("rag_output"))
    return {
        str(item.get("citation_id"))
        for item in (rag.get("citations") or [])
        if isinstance(item, Mapping) and item.get("citation_id")
    }


def _referenced_evidence_ids(output: Any) -> set[str]:
    refs: set[str] = set()
    for key, value in _walk_keys(output):
        lowered = key.lower()
        if lowered == "evidence_id" and isinstance(value, str) and value:
            refs.add(value)
        elif lowered == "evidence_ids" and isinstance(value, Sequence):
            refs.update(str(item) for item in value if item)
    for text in _collect_strings(output):
        refs.update(_EVIDENCE_ID_RE.findall(text))
    return refs


def _referenced_citation_ids(output: Any) -> set[str]:
    refs: set[str] = set()
    for key, value in _walk_keys(output):
        if key.lower() == "citation_id" and isinstance(value, str) and value:
            refs.add(value)
    for text in _collect_strings(output):
        refs.update(_CITATION_ID_RE.findall(text))
    return refs


def _check_schema(
    agent_name: str,
    output: Any,
    context: Mapping[str, Any],
    rule: GuardRule,
) -> list[GuardViolation]:
    del context
    expected = {
        "evidence_agent": EvidenceOutput,
        "graph_agent": GraphOutput,
        "rag_agent": RAGOutput,
        "risk_agent": RiskAssessment,
        "response_agent": ResponsePlan,
        "report_agent": InvestigationReport,
    }.get(agent_name)
    if expected is None:
        if isinstance(output, BaseModel):
            return []
        return [
            GuardViolation(
                dimension=rule.dimension,
                rule_name=rule.rule_name,
                severity=rule.severity,
                detail=f"{agent_name} output must be a structured model",
            )
        ]
    if isinstance(output, expected):
        return []
    if isinstance(output, BaseModel):
        return [
            GuardViolation(
                dimension=rule.dimension,
                rule_name=rule.rule_name,
                severity=rule.severity,
                detail=f"{agent_name} output type {type(output).__name__} != {expected.__name__}",
            )
        ]
    try:
        cast(type[BaseModel], expected).model_validate(output)
    except ValidationError as exc:
        return [
            GuardViolation(
                dimension=rule.dimension,
                rule_name=rule.rule_name,
                severity=rule.severity,
                detail=(
                    f"{agent_name} output failed schema validation: {exc.error_count()} error(s)"
                ),
            )
        ]
    return []


def _check_grounding(
    agent_name: str,
    output: Any,
    context: Mapping[str, Any],
    rule: GuardRule,
) -> list[GuardViolation]:
    del agent_name
    known = evidence_ids_from_context(context)
    refs = _referenced_evidence_ids(output)
    if not known and context.get("evidence_ids") is None and context.get("evidence_output") is None:
        return []
    missing = sorted(refs - known)
    if isinstance(output, EvidenceOutput) or (
        isinstance(output, Mapping) and "evidence_list" in output
    ):
        produced = {
            str(_as_mapping(item).get("evidence_id"))
            for item in (_as_mapping(output).get("evidence_list") or [])
            if _as_mapping(item).get("evidence_id")
        }
        missing = [item for item in missing if item not in produced]
    if not missing:
        return []
    return [
        GuardViolation(
            dimension=rule.dimension,
            rule_name=rule.rule_name,
            severity=rule.severity,
            detail=f"referenced evidence ids are unknown: {', '.join(missing)}",
        )
    ]


def _check_entity_target_exists(
    agent_name: str,
    output: Any,
    context: Mapping[str, Any],
    rule: GuardRule,
) -> list[GuardViolation]:
    del agent_name
    entities_raw = context.get("entities")
    if entities_raw is None:
        triage = _as_mapping(context.get("triage_result"))
        entities_raw = triage.get("entities")
    known = entity_identity_values(
        entities_raw if isinstance(entities_raw, (EntitySet, Mapping)) else None
    )
    if not known and entities_raw is None:
        return []

    if isinstance(output, ResponsePlan):
        actions = output.actions
    elif isinstance(output, Mapping) and "actions" in output:
        actions = output.get("actions") or []
    else:
        actions = []
    targets: list[str] = []
    for action in actions:
        payload = action if isinstance(action, Action) else Action.model_validate(action)
        if payload.target:
            targets.append(payload.target)
        for key in ("canonical_target", "target", "ip", "hostname", "username", "fqdn"):
            value = payload.parameters.get(key)
            if isinstance(value, str) and value:
                targets.append(value)

    missing = sorted({target for target in targets if target not in known})
    if not missing:
        return []
    return [
        GuardViolation(
            dimension=rule.dimension,
            rule_name=rule.rule_name,
            severity=rule.severity,
            detail=f"action targets not present in EntitySet: {', '.join(missing)}",
        )
    ]


def _check_citation_present(
    agent_name: str,
    output: Any,
    context: Mapping[str, Any],
    rule: GuardRule,
) -> list[GuardViolation]:
    violations: list[GuardViolation] = []
    known = citation_ids_from_context(context)
    payload_map = _as_mapping(output)
    if isinstance(output, RAGOutput) or "citations" in payload_map:
        payload = output if isinstance(output, RAGOutput) else RAGOutput.model_validate(output)
        local_citations = {item.citation_id for item in payload.citations}
        needs_citation = bool(
            payload.attack_techniques or payload.similar_cases or payload.playbook_refs
        )
        if needs_citation and not payload.citations:
            violations.append(
                GuardViolation(
                    dimension=rule.dimension,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    detail="rag_agent output that cites knowledge must include citations",
                )
            )
        referenced = {item.citation_id for item in payload.attack_techniques if item.citation_id}
        missing = sorted(referenced - local_citations)
        if missing:
            violations.append(
                GuardViolation(
                    dimension=rule.dimension,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    detail=f"citation ids missing from citations list: {', '.join(missing)}",
                )
            )
        return violations

    if agent_name == "report_agent":
        refs = _referenced_citation_ids(output)
        if not refs:
            return []
        if known:
            missing = sorted(refs - known)
            if missing:
                violations.append(
                    GuardViolation(
                        dimension=rule.dimension,
                        rule_name=rule.rule_name,
                        severity=rule.severity,
                        detail=f"report citations are unknown: {', '.join(missing)}",
                    )
                )
        elif not context.get("rag_output"):
            violations.append(
                GuardViolation(
                    dimension=rule.dimension,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    detail="report references citations but context has no citation catalog",
                )
            )
    return violations


def _check_no_pii_leak(
    agent_name: str,
    output: Any,
    context: Mapping[str, Any],
    rule: GuardRule,
) -> list[GuardViolation]:
    del agent_name, context
    leaked_fields: list[str] = []
    for key, value in _walk_keys(output):
        if is_sensitive_key(key):
            leaked_fields.append(key)
            continue
        if isinstance(value, str) and redact_sensitive_text(value) != value:
            leaked_fields.append(key)
    if not leaked_fields:
        return []
    unique = ", ".join(sorted(set(leaked_fields))[:12])
    return [
        GuardViolation(
            dimension=rule.dimension,
            rule_name=rule.rule_name,
            severity=rule.severity,
            detail=f"potential secret/PII leakage in fields: {unique}",
        )
    ]


_RULE_CHECKERS: dict[str, RuleChecker] = {
    "schema": _check_schema,
    "grounding": _check_grounding,
    "entity_target_exists": _check_entity_target_exists,
    "citation_present": _check_citation_present,
    "no_pii_leak": _check_no_pii_leak,
}


def _quality_rules(*names: str, severity: GuardSeverity = "block") -> list[GuardRule]:
    dimension_by_name = {
        "schema": GuardRailDimension.SCHEMA,
        "grounding": GuardRailDimension.GROUNDING,
        "entity_target_exists": GuardRailDimension.POLICY,
        "citation_present": GuardRailDimension.GROUNDING,
        "no_pii_leak": GuardRailDimension.SANITIZATION,
    }
    return [
        GuardRule(
            rule_name=name,
            dimension=dimension_by_name[name],
            severity=severity,
            downgradable=True,
        )
        for name in names
    ]


GUARD_RULES: dict[str, list[GuardRule]] = {
    "evidence_agent": _quality_rules("schema", "grounding", "entity_target_exists"),
    "risk_agent": _quality_rules("schema", "grounding", "entity_target_exists"),
    "response_agent": _quality_rules("schema", "grounding", "entity_target_exists"),
    "graph_agent": _quality_rules("schema", "grounding", "entity_target_exists"),
    "report_agent": _quality_rules(
        "schema",
        "grounding",
        "entity_target_exists",
        "citation_present",
        "no_pii_leak",
    ),
    "rag_agent": _quality_rules("schema", "citation_present", "no_pii_leak"),
}


@dataclass
class InMemoryGuardViolationWriter:
    """In-memory EventContext.guard_violations sink for unit tests."""

    by_event: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    async def write_guard_violations(
        self, event_id: str, violations: Sequence[GuardViolation]
    ) -> None:
        bucket = self.by_event.setdefault(event_id, [])
        bucket.extend(item.model_dump(mode="json") for item in violations)


class WorkingMemoryGuardViolationWriter:
    """Persist guard_violations through WorkingMemory as owner OutputGuard."""

    def __init__(self, working_memory: Any) -> None:
        self._bound = working_memory.for_writer("OutputGuard")

    async def write_guard_violations(
        self, event_id: str, violations: Sequence[GuardViolation]
    ) -> None:
        existing = await self._bound.read(event_id, "guard_violations")
        current = list(existing) if isinstance(existing, list) else []
        current.extend(item.model_dump(mode="json") for item in violations)
        await self._bound.write(event_id, "guard_violations", current)


class OutputGuard:
    """Four-dimension Agent output validation engine."""

    def __init__(
        self,
        *,
        mode: GuardrailMode | str | None = None,
        rules: Mapping[str, Sequence[GuardRule]] | None = None,
        violation_writer: Any | None = None,
        settings: Settings | None = None,
    ) -> None:
        config = settings or get_settings()
        raw_mode = mode if mode is not None else config.guardrail_mode
        normalized = str(raw_mode).strip().lower()
        self.mode = (
            GuardrailMode.WARN_ONLY
            if normalized == GuardrailMode.WARN_ONLY.value
            else GuardrailMode.ENFORCE
        )
        self.rules = {
            agent: list(agent_rules) for agent, agent_rules in (rules or GUARD_RULES).items()
        }
        self._violation_writer = violation_writer

    async def validate(
        self,
        agent_name: str,
        output: Any,
        context: Mapping[str, Any] | None = None,
    ) -> GuardResult:
        ctx = dict(context or {})
        violations: list[GuardViolation] = []
        for rule in self.rules.get(agent_name, []):
            checker = _RULE_CHECKERS.get(rule.rule_name)
            if checker is None:
                continue
            effective = rule
            if (
                self.mode is GuardrailMode.WARN_ONLY
                and rule.downgradable
                and rule.severity == "block"
            ):
                effective = GuardRule(
                    rule_name=rule.rule_name,
                    dimension=rule.dimension,
                    severity="warn",
                    downgradable=rule.downgradable,
                )
            violations.extend(checker(agent_name, output, ctx, effective))

        if isinstance(output, BaseModel):
            sanitized = sanitize_data(output.model_dump(mode="python"))
            try:
                sanitized_output: Any = type(output).model_validate(sanitized)
            except ValidationError:
                sanitized_output = sanitized
        else:
            sanitized_output = sanitize_data(output)

        blocking = [item for item in violations if item.severity == "block"]
        result = GuardResult(
            passed=not blocking,
            violations=violations,
            sanitized_output=sanitized_output,
        )
        if blocking:
            await self._record(ctx.get("event_id"), blocking)
            raise GuardrailViolationError(
                f"output guard blocked {agent_name}",
                error_code="guardrail_violation",
                details={
                    "agent_name": agent_name,
                    "violations": [item.model_dump(mode="json") for item in blocking],
                },
            )
        if violations:
            await self._record(ctx.get("event_id"), violations)
        return result

    async def _record(self, event_id: Any, violations: Sequence[GuardViolation]) -> None:
        if not event_id or self._violation_writer is None or not violations:
            return
        try:
            await self._violation_writer.write_guard_violations(str(event_id), violations)
        except Exception:  # noqa: BLE001 — recording must not hide the guard decision
            logger.warning(
                "failed to persist guard_violations event_id=%s",
                event_id,
                exc_info=True,
            )


def _is_analysis_key(key: str) -> bool:
    cleaned = re.sub(r"[^a-z0-9_]", "", key.lower())
    if cleaned in _ANALYSIS_KEY_FRAGMENTS:
        return True
    tokens = set(cleaned.split("_"))
    # Token match avoids false positives like source_concurrency_token → "token".
    return bool(
        tokens
        & {
            "report",
            "prompt",
            "evidence",
            "reasoning",
            "analysis",
            "narrative",
            "trace",
            "password",
            "secret",
            "authorization",
            "cookie",
            "raw",
        }
    )


def _scan_analysis_content(
    value: Any,
    *,
    path: str = "",
    skip_key_check_for: frozenset[str] | None = None,
) -> list[str]:
    findings: list[str] = []
    if isinstance(value, BaseModel):
        return _scan_analysis_content(
            value.model_dump(mode="python"),
            path=path,
            skip_key_check_for=skip_key_check_for,
        )
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_s = str(key)
            child = f"{path}.{key_s}" if path else key_s
            skip_this_key = (
                skip_key_check_for is not None and key_s in skip_key_check_for and path == ""
            )
            if not skip_this_key and _is_analysis_key(key_s):
                findings.append(child)
            findings.extend(
                _scan_analysis_content(
                    item,
                    path=child,
                    skip_key_check_for=None,
                )
            )
        return findings
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            child = f"{path}[{index}]"
            findings.extend(_scan_analysis_content(item, path=child))
        return findings
    if isinstance(value, str):
        lowered = value.lower()
        if (
            any(
                marker in lowered
                for marker in (
                    "decision_trace",
                    "investigation report",
                    "system prompt",
                    "api_key",
                    "api key",
                    "bearer ",
                )
            )
            or redact_sensitive_text(value) != value
        ):
            findings.append(path or "<value>")
    return findings


class OutboundDispositionGuard:
    """Fail-closed outbound disposition / outbox guard (never warn-only)."""

    def __init__(self, *, violation_writer: Any | None = None) -> None:
        self._violation_writer = violation_writer

    async def validate(
        self,
        payload: DispositionCommand | Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> GuardResult:
        ctx = dict(context or {})
        try:
            violations = self._evaluate(payload, ctx)
        except GuardrailViolationError:
            raise
        except Exception as exc:  # noqa: BLE001 — fail closed
            raise GuardrailViolationError(
                "outbound disposition guard failed closed",
                error_code="guardrail_violation",
                details={"rule_name": "outbound_guard_internal_error"},
            ) from exc

        blocking = [item for item in violations if item.severity == "block"]
        result = GuardResult(passed=not blocking, violations=violations, sanitized_output=None)
        if blocking:
            await self._record(ctx.get("event_id"), blocking)
            raise GuardrailViolationError(
                "outbound disposition guard blocked writeback payload",
                error_code="guardrail_violation",
                details={
                    "violations": [item.model_dump(mode="json") for item in blocking],
                },
            )
        return result

    def _evaluate(
        self,
        payload: DispositionCommand | Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> list[GuardViolation]:
        violations: list[GuardViolation] = []
        raw = _as_mapping(payload)

        unknown = sorted(set(raw) - _DISPOSITION_ALLOWED_TOP_LEVEL)
        if unknown:
            violations.append(
                GuardViolation(
                    dimension=GuardRailDimension.POLICY,
                    rule_name="disposition_field_allowlist",
                    severity="block",
                    detail=(
                        "outbound payload contains non-allowlisted fields: " + ", ".join(unknown)
                    ),
                )
            )

        command: DispositionCommand | None
        try:
            command = (
                payload
                if isinstance(payload, DispositionCommand)
                else DispositionCommand.model_validate(
                    {key: raw[key] for key in raw if key in _DISPOSITION_ALLOWED_TOP_LEVEL}
                )
            )
        except ValidationError as exc:
            violations.append(
                GuardViolation(
                    dimension=GuardRailDimension.SCHEMA,
                    rule_name="disposition_field_allowlist",
                    severity="block",
                    detail=(
                        "outbound payload failed DispositionCommand schema: "
                        f"{exc.error_count()} error(s)"
                    ),
                )
            )
            command = None

        trusted = context.get("source_locator")
        if command is not None and trusted is not None:
            trusted_locator = (
                trusted
                if isinstance(trusted, SourceObjectLocator)
                else SourceObjectLocator.model_validate(trusted)
            )
            actual = command.source_locator
            if (
                actual.source_product != trusted_locator.source_product
                or actual.source_tenant_id != trusted_locator.source_tenant_id
                or actual.connector_id != trusted_locator.connector_id
                or actual.source_object_id != trusted_locator.source_object_id
            ):
                violations.append(
                    GuardViolation(
                        dimension=GuardRailDimension.POLICY,
                        rule_name="disposition_source_match",
                        severity="block",
                        detail="source_locator does not match trusted event source locator",
                    )
                )

        approved = context.get("approved_action_ids")
        if command is not None and approved is not None:
            approved_ids = {str(item) for item in approved}
            if command.action_id not in approved_ids:
                violations.append(
                    GuardViolation(
                        dimension=GuardRailDimension.POLICY,
                        rule_name="disposition_approved_action",
                        severity="block",
                        detail=f"action_id {command.action_id!r} is not in the approved action set",
                    )
                )

        analysis_hits = _scan_analysis_content(
            raw,
            skip_key_check_for=_DISPOSITION_ALLOWED_TOP_LEVEL,
        )
        if analysis_hits:
            violations.append(
                GuardViolation(
                    dimension=GuardRailDimension.SANITIZATION,
                    rule_name="no_analysis_content_outbound",
                    severity="block",
                    detail=(
                        "analysis/secret content is forbidden on outbound disposition payload: "
                        + ", ".join(analysis_hits[:12])
                    ),
                )
            )
        return violations

    async def _record(self, event_id: Any, violations: Sequence[GuardViolation]) -> None:
        if not event_id or self._violation_writer is None or not violations:
            return
        try:
            await self._violation_writer.write_guard_violations(str(event_id), violations)
        except Exception:  # noqa: BLE001
            logger.warning(
                "failed to persist outbound guard_violations event_id=%s",
                event_id,
                exc_info=True,
            )


__all__ = [
    "GUARD_RULES",
    "GuardResult",
    "GuardRule",
    "GuardSeverity",
    "GuardViolation",
    "GuardrailMode",
    "InMemoryGuardViolationWriter",
    "OutboundDispositionGuard",
    "OutputGuard",
    "WorkingMemoryGuardViolationWriter",
    "entity_identity_values",
]
