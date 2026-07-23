"""ResponseAgent: structured disposition plan generation (ISSUE-057)."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.base import BaseAgent
from app.agents.prompts.response_prompt import build_response_plan_messages
from app.agents.rules.default_response_rules import ResponseRuleAction, get_rule_actions
from app.core.errors import LLMError
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import (
    ResponseAgentInput,
    ResponsePlan,
    ResponsePlanGeneratedBy,
    TriageResult,
)
from app.models.disposition import SourceObjectLocator
from app.models.entities import EntitySet
from app.models.enums import (
    TERMINAL_SOURCE_DISPOSITIONS,
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    CapabilityState,
    DispositionIntentKind,
    DispositionPolicy,
    EventType,
    ExecutionOwner,
    FinalVerdict,
    Severity,
    SourceDisposition,
    SourceObjectKind,
    WritebackReadiness,
)
from app.models.playbook import Playbook
from app.models.tool_meta import (
    TERMINAL_DISPOSITION_TOOL as VIRTUAL_DISPOSITION_TOOL,
)
from app.models.tool_meta import (
    CapabilityManifest,
)
from app.models.workflow import FP_HIGH_THRESHOLD
from app.services.context_service import append_context_journal_in_session
from app.services.source_policy_resolver import SourcePolicyResolver
from app.tools.inputs import TOOL_INPUT_MODELS
from app.tools.specs import baseline_tool_index

logger = logging.getLogger(__name__)

_QUERY_TOOL_PREFIX = "query_"
_NON_TARGET_TOOLS = frozenset({"create_ticket", "notify_security_team"})
_TICKET_TARGET = "ticket"
_CHANNEL_TARGET = "security_team"


def generate_response_plan_id(event_id: str, plan_revision: int) -> str:
    digest = hashlib.sha256(f"{event_id}|response|{plan_revision}".encode()).hexdigest()[:8]
    return f"rsp-{digest}"


def compute_normalized_params_hash(parameters: dict[str, Any]) -> str:
    payload = json.dumps(parameters or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_source_locator_hash(locator: SourceObjectLocator | None) -> str:
    if locator is None:
        return ""
    material = "|".join(
        (
            locator.source_product,
            locator.source_tenant_id,
            locator.connector_id,
            locator.source_kind.value,
            locator.source_object_id,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def compute_template_hash(approved: list[SourceDisposition]) -> str:
    if not approved:
        return ""
    material = "|".join(sorted(item.value for item in approved))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def compute_action_fingerprint(
    *,
    event_id: str,
    plan_revision: int,
    tool_name: str,
    target_type: str | None,
    canonical_target: str | None,
    normalized_params_hash: str,
    execution_owner: ExecutionOwner | None,
    source_locator_hash: str,
    execution_phase: ActionExecutionPhase,
    approved_template_hash: str,
) -> str:
    material = "|".join(
        (
            event_id,
            str(int(plan_revision)),
            tool_name,
            target_type or "",
            canonical_target or "",
            normalized_params_hash,
            execution_owner.value if execution_owner else "",
            source_locator_hash,
            execution_phase.value,
            approved_template_hash,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def derive_stable_action_id(fingerprint: str) -> str:
    return f"act-{hashlib.sha256(fingerprint.encode()).hexdigest()[:8]}"


def derive_disposition_idempotency_key(
    *,
    action_id: str,
    plan_revision: int,
    intent_kind: DispositionIntentKind,
    logical_slot: str = "terminal",
) -> str:
    material = f"{action_id}|{plan_revision}|{intent_kind.value}|{logical_slot}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_mock_capability_manifest(
    *, disabled_tools: frozenset[str] | None = None
) -> CapabilityManifest:
    """Full Mock P0 manifest for ResponseAgent filtering tests."""
    from app.models.tool_meta import CapabilityBindingEntry, ExecutionChannel

    disabled = disabled_tools or frozenset()
    index = baseline_tool_index()
    response_ops = sorted(
        name
        for name, meta in index.items()
        if meta.tool_category.value == "response"
        and name not in disabled
        and not name.startswith(_QUERY_TOOL_PREFIX)
    )
    return CapabilityManifest(
        provider_name="mock_xdr",
        online=True,
        source_read=CapabilityState.SUPPORTED,
        event_disposition=CapabilityState.SUPPORTED,
        entity_response=CapabilityState.SUPPORTED,
        allowed_intents=[
            DispositionIntentKind.EVENT_STATUS_UPDATE,
            DispositionIntentKind.ENTITY_ACTION_SUBMIT,
            DispositionIntentKind.EXECUTION_RESULT_RECORD,
        ],
        allowed_operations=response_ops + [VIRTUAL_DISPOSITION_TOOL],
        allowed_target_types=sorted(
            {target for name in response_ops for target in index[name].target_types}
            | {"source_object"}
        ),
        allowed_source_kinds=[SourceObjectKind.INCIDENT, SourceObjectKind.ALERT],
        allowed_native_source_object_types=["xdr_incident"],
        supports_status_query=True,
        supports_lookup_by_idempotency=True,
        supports_idempotency=True,
        supports_concurrency_control=True,
        supports_fencing=True,
        allowed_execution_channels=[
            ExecutionChannel.TOOL_PROVIDER,
            ExecutionChannel.DISPOSITION_ADAPTER,
        ],
        bindings=[
            CapabilityBindingEntry(
                intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
                operation_code="set_event_disposition",
                source_kind=SourceObjectKind.INCIDENT,
                native_source_object_type="xdr_incident",
                state=CapabilityState.SUPPORTED,
            ),
            *[
                CapabilityBindingEntry(
                    intent_kind=DispositionIntentKind.EXECUTION_RESULT_RECORD,
                    operation_code=name,
                    state=CapabilityState.SUPPORTED,
                )
                for name in response_ops
                if name != VIRTUAL_DISPOSITION_TOOL
            ],
        ],
    )


@dataclass(frozen=True)
class ActionCandidate:
    tool_name: str
    target_type: str | None
    target: str | None
    parameters: dict[str, Any]
    reason: str
    step_order: int = 0
    playbook_id: str | None = None


class ResponsePolicyFilter:
    """Validate candidates against manifest, locator, schema, and owner rules."""

    def __init__(
        self,
        *,
        manifest: CapabilityManifest,
        entities: EntitySet,
        disposition_policy: DispositionPolicy,
        source_locator: SourceObjectLocator | None,
        policy_resolver: SourcePolicyResolver | None = None,
    ) -> None:
        self.manifest = manifest
        self.entities = entities
        self.disposition_policy = disposition_policy
        self.source_locator = source_locator
        self.policy_resolver = policy_resolver or SourcePolicyResolver()
        self._tool_index = baseline_tool_index()

    def filter_candidates(self, candidates: list[ActionCandidate]) -> list[ActionCandidate]:
        accepted: list[ActionCandidate] = []
        for candidate in candidates:
            filtered = self._filter_one(candidate)
            if filtered is not None:
                accepted.append(filtered)
        return accepted

    def _filter_one(self, candidate: ActionCandidate) -> ActionCandidate | None:
        tool_name = candidate.tool_name
        if tool_name.startswith(_QUERY_TOOL_PREFIX):
            logger.debug("PolicyFilter: reject query tool %s", tool_name)
            return None

        meta = self._tool_index.get(tool_name)
        if meta is None:
            logger.debug("PolicyFilter: unknown tool %s", tool_name)
            return None

        if tool_name != VIRTUAL_DISPOSITION_TOOL:
            if tool_name not in self.manifest.allowed_operations:
                logger.debug("PolicyFilter: tool %s not in manifest", tool_name)
                return None
            if not meta.executable:
                logger.debug("PolicyFilter: non-executable tool %s", tool_name)
                return None

        if not self._validate_parameters(tool_name, candidate):
            return None

        if tool_name in _NON_TARGET_TOOLS:
            return candidate

        if candidate.target_type is None or candidate.target is None:
            logger.debug("PolicyFilter: missing target for %s", tool_name)
            return None

        if meta is not None and candidate.target_type not in meta.target_types:
            logger.debug(
                "PolicyFilter: target_type %s not allowed for %s",
                candidate.target_type,
                tool_name,
            )
            return None

        if not self._entity_exists(candidate.target_type, candidate.target):
            logger.debug(
                "PolicyFilter: target %s:%s not grounded in EntitySet",
                candidate.target_type,
                candidate.target,
            )
            return None

        return candidate

    def _validate_parameters(self, tool_name: str, candidate: ActionCandidate) -> bool:
        model = TOOL_INPUT_MODELS.get(tool_name)
        if model is None:
            return False
        try:
            if tool_name in _NON_TARGET_TOOLS:
                model.model_validate(candidate.parameters)
            else:
                model.model_validate(
                    {
                        "target_type": candidate.target_type,
                        "target": candidate.target,
                        "parameters": candidate.parameters,
                    }
                )
        except ValidationError:
            logger.debug("PolicyFilter: schema validation failed for %s", tool_name, exc_info=True)
            return False
        return True

    def _entity_exists(self, target_type: str, target: str) -> bool:
        if target_type == _TICKET_TARGET or target_type == "channel":
            return True
        if target_type == "account":
            return any(
                (entity.username or entity.entity_id) == target for entity in self.entities.accounts
            )
        if target_type == "ip":
            return any(
                (entity.address or entity.entity_id) == target for entity in self.entities.ips
            )
        if target_type == "domain":
            return any(
                (entity.fqdn or entity.entity_id) == target for entity in self.entities.domains
            )
        if target_type == "host":
            return any(
                (entity.hostname or entity.ip or entity.entity_id) == target
                for entity in self.entities.hosts
            )
        if target_type == "file":
            return any(
                (entity.path or entity.name or entity.entity_id) == target
                for entity in self.entities.files
            )
        if target_type == "process":
            return any(
                (entity.name or entity.entity_id) == target for entity in self.entities.processes
            )
        if target_type == "source_object":
            return self.source_locator is not None
        return False

    def resolve_execution_owner(self, tool_name: str) -> ExecutionOwner | None:
        meta = self._tool_index[tool_name]
        if tool_name == VIRTUAL_DISPOSITION_TOOL:
            return ExecutionOwner.XDR_MANAGED
        owners = list(meta.supported_execution_owners)
        if ExecutionOwner.XDR_MANAGED in owners:
            return ExecutionOwner.XDR_MANAGED
        if ExecutionOwner.DIRECT_TOOL in owners:
            return ExecutionOwner.DIRECT_TOOL
        return None

    def writeback_fields(
        self,
        *,
        tool_name: str,
        execution_owner: ExecutionOwner,
    ) -> tuple[bool, bool, WritebackReadiness, str | None]:
        writeback_required = self.disposition_policy is DispositionPolicy.REQUIRED
        if not writeback_required:
            return False, False, WritebackReadiness.NOT_REQUIRED, None

        if tool_name == VIRTUAL_DISPOSITION_TOOL:
            readiness_raw = self.manifest.writeback_readiness_for_required()
            readiness = WritebackReadiness(readiness_raw)
            block = self.policy_resolver.readiness_when_required_but_blocked(
                has_writable_locator=self.source_locator is not None,
                capability_state=self.manifest.event_disposition.value,
            )
            applicable = True
            if block:
                readiness = WritebackReadiness(block)
            return True, applicable, readiness, block

        # Entity side-effect actions inherit event policy but do not carry terminal writeback.
        return True, False, WritebackReadiness.NOT_REQUIRED, None


def resolve_entity_targets(
    tool_name: str,
    entities: EntitySet,
    *,
    prefer_external_ip: bool = True,
) -> list[tuple[str, str]]:
    """Map a tool to zero or more (target_type, canonical_target) pairs."""
    meta = baseline_tool_index().get(tool_name)
    if meta is None:
        return []

    if tool_name == "create_ticket":
        return [(_TICKET_TARGET, _TICKET_TARGET)]
    if tool_name == "notify_security_team":
        return [("channel", _CHANNEL_TARGET)]

    targets: list[tuple[str, str]] = []
    for target_type in meta.target_types:
        if target_type == "account":
            targets.extend(
                ("account", acct.username or acct.entity_id) for acct in entities.accounts
            )
        elif target_type == "ip":
            ips = list(entities.ips)
            if prefer_external_ip:
                ips.sort(key=lambda item: 0 if item.scope == "external" else 1)
            targets.extend(
                ("ip", ip.address or ip.entity_id) for ip in ips if ip.address or ip.entity_id
            )
        elif target_type == "domain":
            targets.extend(("domain", dom.fqdn or dom.entity_id) for dom in entities.domains)
        elif target_type == "host":
            targets.extend(
                ("host", host.hostname or host.ip or host.entity_id)
                for host in entities.hosts
                if host.hostname or host.ip or host.entity_id
            )
        elif target_type == "file":
            targets.extend(
                ("file", file.path or file.name or file.entity_id)
                for file in entities.files
                if file.path or file.name or file.entity_id
            )
        elif target_type == "process":
            targets.extend(
                ("process", proc.name or proc.entity_id)
                for proc in entities.processes
                if proc.name or proc.entity_id
            )
    # Deduplicate while preserving order.
    seen: set[tuple[str, str]] = set()
    ordered: list[tuple[str, str]] = []
    for item in targets:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def expand_rule_candidates(
    rule_actions: list[ResponseRuleAction],
    entities: EntitySet,
) -> list[ActionCandidate]:
    candidates: list[ActionCandidate] = []
    for rule in rule_actions:
        if rule.tool_name in _NON_TARGET_TOOLS:
            params = (
                {
                    "title": "Security investigation follow-up",
                    "description": "Auto-generated ticket",
                }
                if rule.tool_name == "create_ticket"
                else {"message": "Automated response plan notification", "channels": ["email"]}
            )
            target_type = _TICKET_TARGET if rule.tool_name == "create_ticket" else "channel"
            target = _TICKET_TARGET if rule.tool_name == "create_ticket" else _CHANNEL_TARGET
            candidates.append(
                ActionCandidate(
                    tool_name=rule.tool_name,
                    target_type=target_type,
                    target=target,
                    parameters=params,
                    reason="rule fallback",
                    step_order=rule.step_order,
                )
            )
            continue

        pairs = resolve_entity_targets(rule.tool_name, entities)
        if not pairs:
            continue
        for target_type, target in pairs:
            candidates.append(
                ActionCandidate(
                    tool_name=rule.tool_name,
                    target_type=target_type,
                    target=target,
                    parameters={},
                    reason="rule fallback",
                    step_order=rule.step_order,
                )
            )
    return candidates


def candidates_from_playbook(playbook: Playbook, entities: EntitySet) -> list[ActionCandidate]:
    candidates: list[ActionCandidate] = []
    for step in playbook.steps:
        if step.tool_name.startswith(_QUERY_TOOL_PREFIX):
            continue
        if step.tool_name not in baseline_tool_index():
            continue
        if step.tool_name in _NON_TARGET_TOOLS:
            params = (
                {"title": step.action_name, "description": step.expected_outcome}
                if step.tool_name == "create_ticket"
                else {"message": step.action_name, "channels": ["email"]}
            )
            target_type = _TICKET_TARGET if step.tool_name == "create_ticket" else "channel"
            target = _TICKET_TARGET if step.tool_name == "create_ticket" else _CHANNEL_TARGET
            candidates.append(
                ActionCandidate(
                    tool_name=step.tool_name,
                    target_type=target_type,
                    target=target,
                    parameters=params,
                    reason=step.action_name,
                    step_order=step.step_order,
                    playbook_id=playbook.playbook_id,
                )
            )
            continue
        pairs = resolve_entity_targets(step.tool_name, entities)
        if not pairs:
            continue
        for target_type, target in pairs:
            candidates.append(
                ActionCandidate(
                    tool_name=step.tool_name,
                    target_type=target_type,
                    target=target,
                    parameters={},
                    reason=step.action_name,
                    step_order=step.step_order,
                    playbook_id=playbook.playbook_id,
                )
            )
    return candidates


def approved_terminal_for_context(
    *,
    disposition_only: bool,
    final_verdict: FinalVerdict | None,
) -> list[SourceDisposition]:
    if disposition_only or final_verdict is FinalVerdict.FALSE_POSITIVE:
        return [SourceDisposition.IGNORED]
    return [SourceDisposition.CONTAINED, SourceDisposition.COMPLETED]


def sort_candidates(candidates: list[ActionCandidate]) -> list[ActionCandidate]:
    index = baseline_tool_index()

    def sort_key(item: ActionCandidate) -> tuple[int, int, str]:
        meta = index.get(item.tool_name)
        level = meta.action_level if meta is not None else ActionLevel.L0
        level_order = int(level.value[1]) if level.value.startswith("l") else 99
        return (level_order, item.step_order, item.tool_name)

    return sorted(candidates, key=sort_key)


def _cap_low_severity_candidates(
    candidates: list[ActionCandidate],
    severity: Severity,
    *,
    disposition_only: bool,
) -> list[ActionCandidate]:
    """Issue-057: ordinary low-severity investigations cap at create_ticket."""
    if disposition_only or severity is not Severity.LOW:
        return candidates
    return [candidate for candidate in candidates if candidate.tool_name == "create_ticket"]


def _enforce_execution_owner_consistency(
    candidates: list[ActionCandidate],
    policy_filter: ResponsePolicyFilter,
) -> list[ActionCandidate]:
    """Drop DIRECT_TOOL candidates when XDR_MANAGED actions are also planned."""
    owners = {
        policy_filter.resolve_execution_owner(candidate.tool_name)
        for candidate in candidates
        if candidate.tool_name != VIRTUAL_DISPOSITION_TOOL
    }
    owners.discard(None)
    if ExecutionOwner.XDR_MANAGED not in owners or ExecutionOwner.DIRECT_TOOL not in owners:
        return candidates
    return [
        candidate
        for candidate in candidates
        if candidate.tool_name == VIRTUAL_DISPOSITION_TOOL
        or policy_filter.resolve_execution_owner(candidate.tool_name)
        is not ExecutionOwner.DIRECT_TOOL
    ]


class ResponseAgent(BaseAgent[ResponseAgentInput, ResponsePlan]):
    """Generate ResponsePlan and persist idempotent PENDING Actions."""

    agent_name = "response_agent"

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
        playbook_kb_service: Any | None = None,
        capability_manifest: CapabilityManifest | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        scenario_id: str | None = None,
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
        self.playbook_kb_service = playbook_kb_service
        self.capability_manifest = capability_manifest or build_mock_capability_manifest()
        self.session_factory = session_factory
        self.scenario_id = scenario_id
        self.last_generated_by: ResponsePlanGeneratedBy = ResponsePlanGeneratedBy.TEMPLATE

    async def _run(self, input: ResponseAgentInput) -> ResponsePlan:
        ctx = await self._load_context(input)
        plan_revision = int(ctx.get("plan_revision") or 1)
        disposition_only = bool(ctx.get("disposition_only_intent"))
        disposition_policy = ctx.get("disposition_policy") or DispositionPolicy.REQUIRED
        if isinstance(disposition_policy, str):
            disposition_policy = DispositionPolicy(disposition_policy)

        triage = await self._load_triage(input, ctx)
        entities = triage.entities if triage is not None else EntitySet()
        severity = input.risk_assessment.severity
        if triage is not None:
            severity = max(severity, triage.severity, key=_severity_rank)
        event_type = triage.event_type if triage is not None else EventType.OTHER

        source_locator = ctx.get("source_locator")
        policy_filter = ResponsePolicyFilter(
            manifest=self.capability_manifest,
            entities=entities,
            disposition_policy=disposition_policy,
            source_locator=source_locator,
        )

        candidates: list[ActionCandidate] = []
        generated_by = ResponsePlanGeneratedBy.TEMPLATE
        strategy = ""

        if disposition_only:
            candidates = []
            generated_by = ResponsePlanGeneratedBy.TEMPLATE
            strategy = "disposition-only: deferred terminal writeback only"
        else:
            candidates, generated_by, strategy = await self._generate_candidates(
                input=input,
                triage=triage,
                entities=entities,
                event_type=event_type,
                severity=severity,
                ctx=ctx,
            )

        candidates = policy_filter.filter_candidates(candidates)
        candidates = sort_candidates(candidates)
        candidates = _cap_low_severity_candidates(
            candidates,
            severity,
            disposition_only=disposition_only,
        )
        candidates = _enforce_execution_owner_consistency(candidates, policy_filter)

        if disposition_policy is DispositionPolicy.REQUIRED:
            deferred = self._build_deferred_candidate(
                source_locator=source_locator,
                approved=approved_terminal_for_context(
                    disposition_only=disposition_only,
                    final_verdict=ctx.get("final_verdict"),
                ),
            )
            candidates = [c for c in candidates if c.tool_name != VIRTUAL_DISPOSITION_TOOL]
            candidates.append(deferred)

        if disposition_only:
            candidates = [c for c in candidates if c.tool_name == VIRTUAL_DISPOSITION_TOOL]

        actions = self._materialize_actions(
            event_id=input.event_id,
            plan_revision=plan_revision,
            candidates=candidates,
            policy_filter=policy_filter,
            disposition_policy=disposition_policy,
            source_locator=source_locator,
        )

        plan = ResponsePlan(
            plan_id=generate_response_plan_id(input.event_id, plan_revision),
            actions=actions,
            strategy_summary=strategy or "response plan generated",
            generated_by=generated_by,
        )
        self.last_generated_by = generated_by

        if self.session_factory is not None:
            await self._persist_actions(input.event_id, plan_revision, actions, plan)
        elif self.event_service is not None:
            old_revision = int(plan_revision) - 1
            if old_revision >= 1:
                supersede = getattr(self.event_service, "supersede_undeployed_deferred", None)
                if supersede is not None:
                    await supersede(
                        input.event_id,
                        old_revision=old_revision,
                        new_revision=plan_revision,
                    )
            upsert = getattr(self.event_service, "upsert_response_plan_actions", None)
            if upsert is not None:
                actions = await upsert(
                    input.event_id,
                    plan_revision=plan_revision,
                    actions=actions,
                    response_plan=plan,
                )
                plan = ResponsePlan(
                    plan_id=plan.plan_id,
                    actions=actions,
                    strategy_summary=plan.strategy_summary,
                    generated_by=plan.generated_by,
                )

        await self._write_response_plan(input.event_id, plan)
        return plan

    async def _generate_candidates(
        self,
        *,
        input: ResponseAgentInput,
        triage: TriageResult | None,
        entities: EntitySet,
        event_type: EventType,
        severity: Severity,
        ctx: dict[str, Any],
    ) -> tuple[list[ActionCandidate], ResponsePlanGeneratedBy, str]:
        rag_output = ctx.get("rag_output")
        playbook_refs = []
        if isinstance(rag_output, dict):
            playbook_refs = list(rag_output.get("playbook_refs") or [])

        if playbook_refs and self.playbook_kb_service is not None:
            playbook = await self._load_playbook(playbook_refs[0])
            if playbook is not None:
                return (
                    candidates_from_playbook(playbook, entities),
                    ResponsePlanGeneratedBy.TEMPLATE,
                    f"playbook {playbook.playbook_id}",
                )

        if self.llm_client is not None and triage is not None:
            try:
                llm_candidates = await self._generate_with_llm(
                    input=input,
                    triage=triage,
                    entities=entities,
                )
                if llm_candidates:
                    return (
                        llm_candidates,
                        ResponsePlanGeneratedBy.LLM,
                        "LLM proposed candidate actions",
                    )
            except Exception as exc:
                logger.warning(
                    "ResponseAgent LLM path failed event=%s err=%s",
                    input.event_id,
                    exc,
                )

        rule_actions = get_rule_actions(event_type, severity)
        return (
            expand_rule_candidates(rule_actions, entities),
            ResponsePlanGeneratedBy.TEMPLATE,
            "DEFAULT_RESPONSE_RULES fallback",
        )

    async def _generate_with_llm(
        self,
        *,
        input: ResponseAgentInput,
        triage: TriageResult,
        entities: EntitySet,
    ) -> list[ActionCandidate]:
        assert self.llm_client is not None
        available = sorted(
            name
            for name in self.capability_manifest.allowed_operations
            if not name.startswith(_QUERY_TOOL_PREFIX) and name != VIRTUAL_DISPOSITION_TOOL
        )
        messages = build_response_plan_messages(
            triage_result=triage,
            risk_assessment=input.risk_assessment,
            evidence_output=input.evidence_output,
            available_tools=available,
            entities_summary=_entities_summary(entities),
        )
        response = await self.llm_client.chat(
            messages,
            event_id=input.event_id,
            agent_name=self.agent_name,
            prompt_key="response_plan",
            scenario_id=self.scenario_id,
            json_mode=True,
        )
        payload = response.parsed
        if payload is not None and hasattr(payload, "model_dump"):
            data = payload.model_dump(mode="json")
        else:
            data = json.loads(response.content)
        if not isinstance(data, dict):
            raise LLMError("response_plan LLM response is not an object")
        raw_actions = data.get("actions") or []
        if not isinstance(raw_actions, list):
            raise LLMError("response_plan actions must be a list")

        candidates: list[ActionCandidate] = []
        for idx, item in enumerate(raw_actions):
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("tool_name") or "")
            if not tool_name or tool_name == VIRTUAL_DISPOSITION_TOOL:
                continue
            candidates.append(
                ActionCandidate(
                    tool_name=tool_name,
                    target_type=item.get("target_type"),
                    target=item.get("target"),
                    parameters=dict(item.get("parameters") or {}),
                    reason=str(item.get("reason") or "llm proposal"),
                    step_order=idx + 1,
                )
            )
        return candidates

    def _build_deferred_candidate(
        self,
        *,
        source_locator: SourceObjectLocator | None,
        approved: list[SourceDisposition],
    ) -> ActionCandidate:
        return ActionCandidate(
            tool_name=VIRTUAL_DISPOSITION_TOOL,
            target_type="source_object",
            target=source_locator.source_object_id if source_locator else None,
            parameters={
                "approved_terminal_dispositions": [item.value for item in approved],
            },
            reason="deferred EVENT_STATUS_UPDATE after effect verification",
            step_order=9999,
        )

    def _materialize_actions(
        self,
        *,
        event_id: str,
        plan_revision: int,
        candidates: list[ActionCandidate],
        policy_filter: ResponsePolicyFilter,
        disposition_policy: DispositionPolicy,
        source_locator: SourceObjectLocator | None,
    ) -> list[Action]:
        index = baseline_tool_index()
        locator_hash = compute_source_locator_hash(source_locator)
        actions: list[Action] = []
        for candidate in candidates:
            meta = index.get(candidate.tool_name)
            if meta is None:
                continue
            owner = policy_filter.resolve_execution_owner(candidate.tool_name)
            if owner is None:
                continue

            approved = [
                SourceDisposition(value)
                for value in candidate.parameters.get("approved_terminal_dispositions", [])
                if value in {item.value for item in TERMINAL_SOURCE_DISPOSITIONS}
            ]
            if candidate.tool_name == VIRTUAL_DISPOSITION_TOOL and not approved:
                approved = approved_terminal_for_context(
                    disposition_only=True,
                    final_verdict=None,
                )
            template_hash = compute_template_hash(approved)

            params = dict(candidate.parameters)
            if (
                candidate.tool_name not in _NON_TARGET_TOOLS
                and candidate.tool_name != VIRTUAL_DISPOSITION_TOOL
            ):
                params = dict(candidate.parameters)

            normalized_hash = compute_normalized_params_hash(params)
            phase = (
                ActionExecutionPhase.POST_VERIFY
                if candidate.tool_name == VIRTUAL_DISPOSITION_TOOL
                else ActionExecutionPhase.IMMEDIATE
            )
            fingerprint = compute_action_fingerprint(
                event_id=event_id,
                plan_revision=plan_revision,
                tool_name=candidate.tool_name,
                target_type=candidate.target_type,
                canonical_target=candidate.target,
                normalized_params_hash=normalized_hash,
                execution_owner=owner,
                source_locator_hash=locator_hash,
                execution_phase=phase,
                approved_template_hash=template_hash,
            )
            action_id = derive_stable_action_id(fingerprint)
            wb_required, wb_applicable, wb_readiness, wb_block = policy_filter.writeback_fields(
                tool_name=candidate.tool_name,
                execution_owner=owner,
            )
            idempotency_key = None
            if candidate.tool_name == VIRTUAL_DISPOSITION_TOOL:
                idempotency_key = derive_disposition_idempotency_key(
                    action_id=action_id,
                    plan_revision=plan_revision,
                    intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
                )

            action = Action(
                action_id=action_id,
                event_id=event_id,
                plan_revision=plan_revision,
                action_fingerprint=fingerprint,
                action_category=ActionCategory.RESPONSE,
                action_name=meta.description or candidate.tool_name,
                tool_name=candidate.tool_name,
                action_level=meta.action_level,
                execution_phase=phase,
                activation_condition=(
                    "after_effect_resolution"
                    if candidate.tool_name == VIRTUAL_DISPOSITION_TOOL
                    else None
                ),
                approved_operation_template_hash=template_hash or None,
                approved_terminal_dispositions=approved,
                target_type=candidate.target_type,
                target=candidate.target,
                parameters=params,
                status=ActionStatus.PENDING,
                reason=candidate.reason,
                playbook_id=candidate.playbook_id,
                provider_name=self.capability_manifest.provider_name,
                execution_owner=owner,
                idempotency_key=idempotency_key,
                writeback_required=wb_required,
                writeback_applicable=wb_applicable,
                writeback_readiness=wb_readiness,
                writeback_block_reason=wb_block,
                disposition_source_ref=source_locator,
            )
            actions.append(action)
        return actions

    async def _persist_actions(
        self,
        event_id: str,
        plan_revision: int,
        actions: list[Action],
        response_plan: ResponsePlan,
    ) -> None:
        assert self.session_factory is not None
        old_revision = int(plan_revision) - 1
        async with self.session_factory() as session:
            async with session.begin():
                if old_revision >= 1:
                    await _supersede_undeployed_deferred(
                        session,
                        event_id=event_id,
                        old_revision=old_revision,
                        new_revision=int(plan_revision),
                    )
                for action in actions:
                    await _upsert_action_row(session, action)
                await append_context_journal_in_session(
                    session,
                    event_id,
                    "response_plan",
                    response_plan.model_dump(mode="json"),
                )

    async def _load_playbook(self, playbook_id: str) -> Playbook | None:
        if self.playbook_kb_service is None:
            return None
        getter = getattr(self.playbook_kb_service, "get_playbook", None)
        if getter is None:
            return None
        try:
            result = await getter(playbook_id)
        except Exception:
            logger.debug("playbook lookup failed id=%s", playbook_id, exc_info=True)
            return None
        if isinstance(result, Playbook):
            return result
        return None

    async def _load_context(self, input: ResponseAgentInput) -> dict[str, Any]:
        ctx: dict[str, Any] = {"plan_revision": 1}
        if self.working_memory is None:
            return ctx
        for key in (
            "triage_result",
            "execution_plan",
            "rag_output",
            "disposition_only_intent",
            "false_positive_match",
            "event",
        ):
            try:
                value = await self.working_memory.read(input.event_id, key)
            except Exception:
                value = None
            if value is not None:
                ctx[key] = value

        execution_plan = ctx.get("execution_plan")
        if isinstance(execution_plan, dict):
            ctx["plan_revision"] = int(execution_plan.get("revision") or 0) + 1

        event_summary = ctx.get("event")
        if isinstance(event_summary, dict):
            ctx["disposition_policy"] = event_summary.get("disposition_policy")
            ctx["final_verdict"] = event_summary.get("final_verdict")
            ref = event_summary.get("creation_source_ref") or event_summary.get(
                "primary_source_ref"
            )
            if isinstance(ref, dict):
                ctx["source_locator"] = SourceObjectLocator(
                    source_product=str(ref.get("source_product") or "mock_xdr"),
                    source_tenant_id=str(ref.get("source_tenant_id") or "tenant-1"),
                    connector_id=str(ref.get("connector_id") or "conn-mock"),
                    source_kind=SourceObjectKind(
                        str(ref.get("source_kind") or SourceObjectKind.INCIDENT.value)
                    ),
                    source_object_type=ref.get("source_object_type"),
                    source_object_id=str(ref.get("source_object_id") or "INC-UNKNOWN"),
                )

        if self.event_service is not None:
            getter = getattr(self.event_service, "get_event", None)
            if getter is not None:
                try:
                    event = await getter(input.event_id)
                    if event is not None:
                        ctx.setdefault(
                            "disposition_policy",
                            getattr(event, "disposition_policy", None),
                        )
                        verdict = getattr(event, "final_verdict", None)
                        if verdict is not None and not isinstance(verdict, FinalVerdict):
                            ctx["final_verdict"] = FinalVerdict(verdict)
                        else:
                            ctx["final_verdict"] = verdict
                        ref = getattr(event, "creation_source_ref", None)
                        if ref is not None and "source_locator" not in ctx:
                            dumped = (
                                ref.model_dump(mode="json") if hasattr(ref, "model_dump") else ref
                            )
                            if isinstance(dumped, dict):
                                ctx["source_locator"] = SourceObjectLocator(
                                    source_product=str(dumped.get("source_product") or "mock_xdr"),
                                    source_tenant_id=str(
                                        dumped.get("source_tenant_id") or "tenant-1"
                                    ),
                                    connector_id=str(dumped.get("connector_id") or "conn-mock"),
                                    source_kind=SourceObjectKind(
                                        str(
                                            dumped.get("source_kind")
                                            or SourceObjectKind.INCIDENT.value
                                        )
                                    ),
                                    source_object_type=dumped.get("source_object_type"),
                                    source_object_id=str(
                                        dumped.get("source_object_id") or "INC-UNKNOWN"
                                    ),
                                )
                except Exception:
                    logger.debug("event_service.get_event failed", exc_info=True)

        if ctx.get("disposition_only_intent") is None:
            ctx["disposition_only_intent"] = False
        return ctx

    async def _load_triage(
        self,
        input: ResponseAgentInput,
        ctx: dict[str, Any],
    ) -> TriageResult | None:
        raw = ctx.get("triage_result")
        if isinstance(raw, dict):
            return TriageResult.model_validate(raw)
        return None

    async def _write_response_plan(self, event_id: str, plan: ResponsePlan) -> None:
        if self.working_memory is None:
            return
        try:
            await self.working_memory.write(
                event_id,
                "response_plan",
                plan.model_dump(mode="json"),
            )
        except Exception:
            logger.warning(
                "failed to write response_plan to working memory event=%s",
                event_id,
                exc_info=True,
            )


def approval_confidence_for_disposition_only(
    *,
    event_confidence: float | None,
    false_positive_match: dict[str, Any] | None,
) -> float:
    """Compute approval confidence when RiskAgent was skipped (ISSUE-057)."""
    fp_score = 0.0
    if isinstance(false_positive_match, dict):
        try:
            fp_score = float(false_positive_match.get("max_score") or 0.0)
        except (TypeError, ValueError):
            fp_score = 0.0
    base = float(event_confidence or 0.0)
    combined = max(base, fp_score)
    recommendation = (false_positive_match or {}).get("recommendation")
    if recommendation == "close_as_fp" and fp_score >= FP_HIGH_THRESHOLD:
        return max(combined, FP_HIGH_THRESHOLD)
    return combined


def _severity_rank(severity: Severity) -> int:
    order = {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }
    return order.get(severity, 0)


def _entities_summary(entities: EntitySet) -> dict[str, Any]:
    return {
        "accounts": [entity.username or entity.entity_id for entity in entities.accounts],
        "hosts": [entity.hostname or entity.ip or entity.entity_id for entity in entities.hosts],
        "ips": [entity.address or entity.entity_id for entity in entities.ips],
        "domains": [entity.fqdn or entity.entity_id for entity in entities.domains],
        "processes": [entity.name or entity.entity_id for entity in entities.processes],
        "files": [entity.path or entity.name or entity.entity_id for entity in entities.files],
    }


async def _upsert_action_row(session: AsyncSession, action: Action) -> str:
    existing = await session.scalar(
        select(orm.Action).where(orm.Action.action_fingerprint == action.action_fingerprint)
    )
    payload = action.model_dump(mode="json")
    if existing is not None:
        existing.status = payload["status"]
        existing.reason = payload.get("reason")
        existing.updated_at = datetime.now(UTC)
        await session.flush()
        return existing.action_id

    row = orm.Action(
        action_id=action.action_id,
        event_id=action.event_id,
        plan_revision=action.plan_revision,
        action_fingerprint=action.action_fingerprint,
        action_category=payload["action_category"],
        action_name=payload["action_name"],
        tool_name=payload["tool_name"],
        action_level=payload["action_level"],
        execution_phase=payload.get("execution_phase"),
        activation_condition=payload.get("activation_condition"),
        approved_operation_template_hash=payload.get("approved_operation_template_hash"),
        approved_terminal_dispositions=payload.get("approved_terminal_dispositions"),
        target_type=payload.get("target_type"),
        target=payload.get("target"),
        parameters=payload.get("parameters"),
        status=payload["status"],
        auto_execute=payload.get("auto_execute", False),
        reason=payload.get("reason"),
        impact_assessment=payload.get("impact_assessment"),
        playbook_id=payload.get("playbook_id"),
        provider_name=payload.get("provider_name"),
        execution_owner=payload.get("execution_owner"),
        execution_job_id=payload.get("execution_job_id"),
        tool_call_id=payload.get("tool_call_id"),
        idempotency_key=payload.get("idempotency_key"),
        writeback_required=payload.get("writeback_required", False),
        writeback_applicable=payload.get("writeback_applicable", False),
        writeback_readiness=payload.get("writeback_readiness"),
        writeback_block_reason=payload.get("writeback_block_reason"),
        writeback_status=payload.get("writeback_status"),
        disposition_source_ref=payload.get("disposition_source_ref"),
        superseded_by_revision=payload.get("superseded_by_revision"),
        executed_at=payload.get("executed_at"),
        effect_verification_status=payload.get("effect_verification_status"),
        rollback_status=payload.get("rollback_status"),
        source_action_id=payload.get("source_action_id"),
    )
    session.add(row)
    await session.flush()
    return action.action_id


async def _supersede_undeployed_deferred(
    session: AsyncSession,
    *,
    event_id: str,
    old_revision: int,
    new_revision: int,
) -> int:
    """Mark undeployed deferred actions SUPERSEDED when replanning."""
    result = await session.execute(
        update(orm.Action)
        .where(
            orm.Action.event_id == event_id,
            orm.Action.plan_revision == old_revision,
            orm.Action.tool_name == VIRTUAL_DISPOSITION_TOOL,
            orm.Action.execution_job_id.is_(None),
            orm.Action.status.in_(
                (
                    ActionStatus.PENDING.value,
                    ActionStatus.WAITING_APPROVAL.value,
                    ActionStatus.APPROVED.value,
                )
            ),
        )
        .values(
            status=ActionStatus.SUPERSEDED.value,
            writeback_applicable=False,
            superseded_by_revision=new_revision,
            updated_at=datetime.now(UTC),
        )
    )
    rowcount = getattr(result, "rowcount", 0) or 0
    return int(rowcount)


__all__ = [
    "ActionCandidate",
    "ResponseAgent",
    "ResponsePolicyFilter",
    "approval_confidence_for_disposition_only",
    "build_mock_capability_manifest",
    "compute_action_fingerprint",
    "derive_stable_action_id",
    "expand_rule_candidates",
    "generate_response_plan_id",
]
