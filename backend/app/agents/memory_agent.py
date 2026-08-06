"""Memory knowledge consolidation agent with per-candidate-type gates (ISSUE-080 / ISSUE-208).

Candidate enqueue gates (ISSUE-208): ``profile`` candidates may be enqueued after
analysis-only completion (``REPORTING`` + ``analysis_only_complete``/generated report)
when ``early_enqueue_enabled``; ``fp_rule`` / ``history_case`` candidates always require
``CLOSED``. Only ``pending`` candidates are enqueued — promotion to retrieval stores
stays manual via the knowledge review flow.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.agents.base import BaseAgent
from app.core.llm.base import LLMMessage
from app.models.agent_io import (
    CaseRecordSummary,
    FpRuleCandidate,
    GraphOutput,
    MemoryAgentInput,
    MemoryOutput,
    ProfileUpdate,
)
from app.models.context import EventContext
from app.models.enums import EventStatus, FinalVerdict
from app.models.memory import MemoryCandidate
from app.services.case_kb_service import FP_KB_NAME, HISTORY_KB_NAME, CaseKBService
from app.services.memory_governance import PROFILE_KB_NAME, MemoryGovernance
from app.services.profile_service import ProfileService

logger = logging.getLogger(__name__)
_ENQUEUE_RETRY_DELAYS = (0.05, 0.1)


class _FpRuleDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_summary: str
    alert_signature: str
    confidence: float = Field(ge=0.0, le=1.0)


class MemoryAgent(BaseAgent[MemoryAgentInput, MemoryOutput]):
    """Derive reviewable knowledge artifacts from a completed investigation.

    Per-candidate-type enqueue gates (ISSUE-208):
    - ``profile``: allowed after analysis-only completion (REPORTING +
      analysis_only_complete or generated report) when ``early_enqueue_enabled``,
      and after CLOSED.
    - ``fp_rule`` / ``history_case``: CLOSED only (they carry closure semantics).
    Nothing is auto-promoted to retrieval stores; review approval stays mandatory.
    """

    agent_name = "memory_agent"

    def __init__(
        self,
        *,
        case_kb_service: CaseKBService,
        profile_service: ProfileService,
        memory_governance: MemoryGovernance,
        context_store: Any,
        llm_client: Any | None = None,
        working_memory: Any | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
        degraded_flags: Any | None = None,
        early_enqueue_enabled: bool = True,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            working_memory=working_memory,
            budget_service=budget_service,
            output_guard=output_guard,
            trace_service=trace_service,
            audit_service=audit_service,
            event_bus=event_bus,
        )
        self.case_kb_service = case_kb_service
        self.profile_service = profile_service
        self.memory_governance = memory_governance
        self.context_store: Any = context_store
        self.degraded_flags: Any = degraded_flags
        # ISSUE-208: allow profile-only enqueue after analysis completion (REPORTING).
        self.early_enqueue_enabled = early_enqueue_enabled

    async def _run(self, input: MemoryAgentInput) -> MemoryOutput:
        final_status = input.investigation_result.final_status
        is_closed = final_status is EventStatus.CLOSED
        if not is_closed:
            if not self.early_enqueue_enabled:
                raise ValueError("MemoryAgent only accepts CLOSED investigations")
            if final_status is not EventStatus.REPORTING:
                raise ValueError(
                    "MemoryAgent accepts CLOSED or REPORTING (analysis-complete) investigations"
                )

        context = await self.context_store.get_full_context(input.event_id)
        if context.memory_output is not None:
            return MemoryOutput.model_validate(context.memory_output)

        # ISSUE-208: early enqueue requires an analysis-complete snapshot. This
        # also guards the CLOSED path when a REPORTING snapshot races a close.
        is_early_analysis = not is_closed and (
            context.analysis_only_complete or context.report is not None
        )
        if not is_closed and not is_early_analysis:
            raise ValueError(
                "MemoryAgent: REPORTING requires analysis_only_complete or a "
                "generated report for profile-only early enqueue"
            )

        # ISSUE-208: an earlier early pass already ran and persisted its output —
        # short-circuit so repeated triggers do not re-enqueue profile candidates.
        if is_early_analysis and context.memory_output_early is not None:
            return MemoryOutput.model_validate(context.memory_output_early)

        output = MemoryOutput()
        queued: list[MemoryCandidate] = []
        if input.investigation_result.external_unsynced or (
            context.event is not None and context.event.external_unsynced
        ):
            logger.info(
                "MemoryAgent consolidation skipped for externally unsynced event=%s",
                input.event_id,
            )
            return await self._persist_output(
                input.event_id,
                output,
                key="memory_output_early" if is_early_analysis else "memory_output",
            )

        # history_case: closure semantics — CLOSED only (ISSUE-208 gate).
        if is_closed:
            try:
                history_case = await self.case_kb_service.prepare_history_case(input.event_id)
                record = CaseRecordSummary(
                    case_id=history_case.case_id,
                    event_id=input.event_id,
                    summary=history_case.summary,
                    archived=False,
                    pending_review=True,
                )
                candidate = MemoryCandidate(
                    kb_name=HISTORY_KB_NAME,
                    candidate_type="history_case",
                    payload=history_case.model_dump(mode="json"),
                    confidence=_candidate_confidence(context),
                )
                record.review_id = await self._queue_candidate(input.event_id, candidate)
                if record.review_id is None:
                    record.pending_review = False
                output.case_records.append(record)
                queued.append(candidate)
            except ValueError as exc:
                logger.info(
                    "MemoryAgent case archival ineligible event=%s reason=%s",
                    input.event_id,
                    exc,
                )
            except Exception:
                logger.warning(
                    "MemoryAgent case archival failed event=%s",
                    input.event_id,
                    exc_info=True,
                )

        # fp_rule: closure semantics — CLOSED only (ISSUE-208 gate).
        if is_closed and input.investigation_result.final_verdict is FinalVerdict.FALSE_POSITIVE:
            try:
                fp_rule = await self._build_fp_rule(input.event_id, context)
                candidate = MemoryCandidate(
                    kb_name=FP_KB_NAME,
                    candidate_type="fp_rule",
                    payload=fp_rule.model_dump(mode="json"),
                    confidence=fp_rule.confidence,
                )
                fp_rule.review_id = await self._queue_candidate(input.event_id, candidate)
                if fp_rule.review_id is None:
                    fp_rule.pending_review = False
                output.fp_rules.append(fp_rule)
                queued.append(candidate)
            except Exception:
                logger.warning(
                    "MemoryAgent false-positive rule skipped event=%s",
                    input.event_id,
                    exc_info=True,
                )

        try:
            profile_updates = _profile_updates(input.event_id, context)
        except Exception:
            logger.warning(
                "MemoryAgent profile extraction skipped event=%s",
                input.event_id,
                exc_info=True,
            )
            profile_updates = []
        for update in profile_updates:
            try:
                update.pending_review = True
                candidate = MemoryCandidate(
                    kb_name=PROFILE_KB_NAME,
                    candidate_type="profile",
                    payload=update.model_dump(mode="json"),
                    confidence=_candidate_confidence(context),
                )
                update.review_id = await self._queue_candidate(input.event_id, candidate)
                if update.review_id is None:
                    update.pending_review = False
                output.profile_updates.append(update)
                queued.append(candidate)
            except Exception:
                logger.warning(
                    "MemoryAgent profile update skipped event=%s entity=%s:%s",
                    input.event_id,
                    update.entity_type,
                    update.entity_value,
                    exc_info=True,
                )

        await self._maintain_governance(input.event_id, queued)

        if input.investigation_result.final_verdict is FinalVerdict.CONFIRMED_THREAT:
            try:
                output.sigma_drafts.append(_build_sigma_draft(input.event_id, context))
            except Exception:
                logger.warning(
                    "MemoryAgent Sigma draft skipped event=%s",
                    input.event_id,
                    exc_info=True,
                )

        return await self._persist_output(
            input.event_id,
            output,
            # ISSUE-208: the early (REPORTING, profile-only) pass writes a
            # separate key so a later CLOSED pass is not short-circuited by
            # ``memory_output`` — history_case / fp_rule must still enqueue.
            key="memory_output_early" if is_early_analysis else "memory_output",
        )

    async def _queue_candidate(self, event_id: str, candidate: MemoryCandidate) -> str | None:
        for attempt in range(len(_ENQUEUE_RETRY_DELAYS) + 1):
            try:
                return await self.memory_governance.ingest_candidate(candidate)
            except Exception:
                logger.warning(
                    "MemoryAgent review enqueue failed candidate_type=%s attempt=%s",
                    candidate.candidate_type,
                    attempt + 1,
                    exc_info=True,
                )
                if attempt < len(_ENQUEUE_RETRY_DELAYS):
                    await asyncio.sleep(_ENQUEUE_RETRY_DELAYS[attempt])
        try:
            return await self.memory_governance.persist_pending_fallback(candidate)
        except Exception:
            logger.error(
                "MemoryAgent review fallback persistence failed; candidate retained only "
                "in working memory candidate_type=%s event=%s",
                candidate.candidate_type,
                event_id,
                exc_info=True,
            )
            await self._set_degraded_flag(
                event_id,
                "memory_review_enqueue_failed",
                candidate.candidate_type,
            )
            return None

    async def _maintain_governance(
        self,
        event_id: str,
        candidates: list[MemoryCandidate],
    ) -> None:
        if not candidates:
            return
        by_kb: dict[str, list[MemoryCandidate]] = {}
        for candidate in candidates:
            by_kb.setdefault(candidate.kb_name, []).append(candidate)
        for kb_name, kb_candidates in by_kb.items():
            try:
                await self.memory_governance.dedupe(kb_name)
                for candidate in kb_candidates:
                    await self.memory_governance.resolve_conflict(
                        kb_name,
                        self.memory_governance.fingerprint(candidate),
                    )
                await self.memory_governance.apply_retention(kb_name)
            except Exception:
                logger.warning(
                    "MemoryAgent governance maintenance failed kb_name=%s event=%s",
                    kb_name,
                    event_id,
                    exc_info=True,
                )
                await self._set_degraded_flag(
                    event_id,
                    "memory_governance_maintenance_failed",
                    kb_name,
                )

    async def _set_degraded_flag(self, event_id: str, flag_name: str, value: Any) -> None:
        if self.degraded_flags is None:
            return
        try:
            await self.degraded_flags.set_flag(
                event_id,
                flag_name,
                value,
                writer="MemoryAgent",
            )
        except Exception:
            logger.warning(
                "MemoryAgent failed to record degraded flag=%s event=%s",
                flag_name,
                event_id,
                exc_info=True,
            )

    async def _persist_output(
        self,
        event_id: str,
        output: MemoryOutput,
        *,
        key: str = "memory_output",
    ) -> MemoryOutput:
        if self.working_memory is None:
            raise RuntimeError("MemoryAgent requires working_memory")
        await self.working_memory.write(
            event_id,
            key,
            output.model_dump(mode="json"),
        )
        return output

    async def _build_fp_rule(self, event_id: str, context: EventContext) -> FpRuleCandidate:
        signature = _alert_signature(context)
        fallback = _FpRuleDraft(
            rule_summary=(
                f"Review alerts matching {signature} as a potential false positive "
                f"when the validated context matches event {event_id}."
            ),
            alert_signature=signature,
            confidence=0.75,
        )
        draft = fallback
        if self.llm_client is not None:
            try:
                response = await self.llm_client.chat(
                    [
                        LLMMessage(
                            role="system",
                            content=(
                                "Create a concise false-positive rule candidate. "
                                "Return JSON only. The result is advisory and must be reviewed."
                            ),
                        ),
                        LLMMessage(
                            role="user",
                            content=json.dumps(
                                {
                                    "event_id": event_id,
                                    "alert_signature": signature,
                                    "report_summary": _case_summary(context),
                                },
                                ensure_ascii=False,
                                sort_keys=True,
                            ),
                        ),
                    ],
                    event_id=event_id,
                    agent_name=self.agent_name,
                    prompt_key="memory_fp_rule",
                    json_mode=True,
                    response_model=_FpRuleDraft,
                )
                if isinstance(response.parsed, _FpRuleDraft):
                    draft = response.parsed
            except Exception:
                logger.warning(
                    "MemoryAgent LLM unavailable; using FP rule template event=%s",
                    event_id,
                    exc_info=True,
                )
        # Keep the match key deterministic; the LLM may only refine summary/confidence.
        return FpRuleCandidate(
            rule_summary=draft.rule_summary,
            alert_signature=signature,
            confidence=draft.confidence,
            source_event_id=event_id,
            pending_review=True,
        )


def _case_summary(context: EventContext) -> str:
    if context.report is not None and context.report.summary:
        return context.report.summary
    if context.event is not None:
        return context.event.title
    return ""


def _candidate_confidence(context: EventContext) -> float:
    if context.event is None:
        return 0.0
    return max(0.0, min(1.0, float(context.event.risk_score) / 100.0))


def _alert_signature(context: EventContext) -> str:
    if context.event is None:
        return "unknown-alert"
    return f"{context.event.event_type.value}:{context.event.title}"[:500]


def _profile_updates(event_id: str, context: EventContext) -> list[ProfileUpdate]:
    entities: dict[tuple[str, str], None] = {}
    if context.graph_output:
        graph = GraphOutput.model_validate(context.graph_output)
        for node in graph.nodes:
            if node.entity_type and node.entity_value:
                entities[(node.entity_type, node.entity_value)] = None

    triage_entities = (context.triage_result or {}).get("entities", {})
    if isinstance(triage_entities, dict):
        for plural, values in triage_entities.items():
            entity_type = {
                "accounts": "account",
                "hosts": "host",
                "ips": "ip",
                "domains": "domain",
                "processes": "process",
                "files": "file",
            }.get(plural) or plural
            if not isinstance(values, list):
                continue
            for value in values:
                rendered = _entity_value(value)
                if rendered:
                    entities[(entity_type, rendered)] = None

    risk_score = context.event.risk_score if context.event is not None else None
    tags = _behavior_tags(context)
    return [
        ProfileUpdate(
            entity_type=entity_type,
            entity_value=entity_value,
            event_id=event_id,
            risk_score=risk_score,
            behavior_tags=tags,
        )
        for entity_type, entity_value in sorted(entities)
    ]


def _entity_value(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in (
            "username",
            "hostname",
            "address",
            "fqdn",
            "name",
            "path",
            "entity_id",
        ):
            rendered = value.get(key)
            if rendered:
                return str(rendered)
    return None


def _behavior_tags(context: EventContext) -> list[str]:
    tags: set[str] = set()
    if context.event is not None:
        tags.update(
            {
                f"event_type:{context.event.event_type.value}",
                f"verdict:{context.event.final_verdict.value}",
            }
        )
    storyline = context.storyline or {}
    phases = storyline.get("phases", []) if isinstance(storyline, dict) else []
    for phase in phases:
        if isinstance(phase, dict) and phase.get("phase_name"):
            tags.add(f"phase:{phase['phase_name']}")
    return sorted(tags)


def _build_sigma_draft(event_id: str, context: EventContext) -> str:
    """Return YAML without adding a runtime YAML dependency (JSON scalars are YAML-safe)."""
    title = f"ShadowTrace confirmed threat {event_id}"
    evidence_types: list[str] = []
    techniques: list[str] = []
    for item in (context.evidence_output or {}).get("evidence_list", []):
        if not isinstance(item, dict):
            continue
        if item.get("evidence_type"):
            evidence_types.append(str(item["evidence_type"]))
        if item.get("mitre_technique"):
            techniques.append(str(item["mitre_technique"]))
    sigma_id = uuid.uuid5(uuid.NAMESPACE_URL, f"shadowtrace:sigma:{event_id}")
    lines = [
        f"title: {json.dumps(title, ensure_ascii=False)}",
        f"id: {sigma_id}",
        "status: experimental",
        f"description: {json.dumps(_case_summary(context), ensure_ascii=False)}",
        "references:",
        f"  - {json.dumps(f'shadowtrace:event:{event_id}')}",
        "tags:",
    ]
    if techniques:
        technique_tags = [_sigma_attack_tag(item) for item in sorted(set(techniques))]
        lines.extend(technique_tags)
    else:
        lines.append("  - attack.discovery")
    lines.extend(
        [
            "logsource:",
            "  product: shadowtrace",
            "  category: security_event",
            "detection:",
            "  selection:",
            f"    event_id: {json.dumps(event_id)}",
        ]
    )
    if evidence_types:
        lines.append("    evidence_type:")
        lines.extend(f"      - {json.dumps(item)}" for item in sorted(set(evidence_types)))
    lines.extend(
        [
            "  condition: selection",
            "falsepositives:",
            "  - Requires analyst validation before promotion",
            "level: high",
        ]
    )
    return "\n".join(lines) + "\n"


def _sigma_attack_tag(technique: str) -> str:
    return f"  - {json.dumps(f'attack.{technique.lower()}')}"
