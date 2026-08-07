"""DecisionRecord persistence with idempotency and sanitized hashing (ISSUE-131)."""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any, cast

import orjson
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ValidationError
from app.core.sanitization import redact_sensitive_text
from app.db import models as orm
from app.models.decision_record import (
    DecisionRecord,
    DecisionRecordCandidate,
    DecisionStage,
)
from app.models.react import ReActUncertaintyCode
from app.services.agent_trace_service import TraceProjection

logger = logging.getLogger(__name__)

DECISION_RECORD_SCHEMA_VERSION = "1.0"
PROMPT_POLICY_VERSION = "cot-safe-v1"
_DISPOSITION_BLOCKING_STAGES = frozenset(
    {
        DecisionStage.TRIAGE.value,
        DecisionStage.VERIFY.value,
        DecisionStage.RESPONSE.value,
        DecisionStage.PLANNER.value,
        DecisionStage.RISK.value,
    }
)
_REF_ID_PATTERN = re.compile(
    r"^(evt|evd|act|trc|dec|wbk|disp|case|plan|report|pb|krel)-[0-9a-fA-F]{4,32}$",
    re.IGNORECASE,
)


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def _record_hash(canonical: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def _validate_ref_id(ref_id: str) -> bool:
    return bool(_REF_ID_PATTERN.match(ref_id.strip()))


def _to_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return dict(value)
    return {}


def _coerce_candidates(raw: Any) -> list[DecisionRecordCandidate]:
    if not isinstance(raw, list):
        return []
    candidates: list[DecisionRecordCandidate] = []
    for item in raw[:50]:
        if isinstance(item, str):
            candidates.append(
                DecisionRecordCandidate(candidate_type="unknown", name=item[:256], candidate_id="")
            )
            continue
        if not isinstance(item, dict):
            continue
        candidate_type = str(item.get("candidate_type") or item.get("action_type") or "unknown")
        name = str(item.get("name") or item.get("target_name") or "")[:256]
        if not name:
            continue
        candidates.append(
            DecisionRecordCandidate(
                candidate_type=candidate_type,
                name=name,
                candidate_id=str(item.get("candidate_id") or "")[:128],
            )
        )
    return candidates


def _collect_input_refs(input_data: Any) -> tuple[list[dict[str, str]], list[str]]:
    refs: list[dict[str, str]] = []
    unresolved: list[str] = []
    if not isinstance(input_data, dict):
        return refs, unresolved

    event_id = input_data.get("event_id")
    if isinstance(event_id, str) and event_id.strip():
        refs.append({"ref_type": "event_id", "ref_id": event_id.strip()})

    for key in ("evidence_id", "action_id", "trace_id", "plan_id"):
        value = input_data.get(key)
        if isinstance(value, str) and value.strip():
            ref_id = value.strip()
            if _validate_ref_id(ref_id):
                refs.append({"ref_type": key, "ref_id": ref_id})
            else:
                unresolved.append(ref_id)

    evidence_refs = input_data.get("evidence_refs")
    if isinstance(evidence_refs, list):
        for item in evidence_refs[:50]:
            evidence_ref_id: str | None = None
            if isinstance(item, str):
                evidence_ref_id = item
            elif isinstance(item, dict):
                raw_ref_id = item.get("evidence_id")
                evidence_ref_id = raw_ref_id if isinstance(raw_ref_id, str) else None
            if not isinstance(evidence_ref_id, str) or not evidence_ref_id.strip():
                continue
            ref_id = evidence_ref_id.strip()
            if _validate_ref_id(ref_id):
                refs.append({"ref_type": "evidence_id", "ref_id": ref_id})
            else:
                unresolved.append(ref_id)
    return refs, unresolved


def _collect_enriched_input_refs(
    output_data: dict[str, Any],
) -> tuple[list[dict[str, str]], list[str]]:
    """Merge agent-enriched refs (e.g. playbook pins) into durable input_refs."""
    refs: list[dict[str, str]] = []
    unresolved: list[str] = []
    raw = output_data.get("input_refs")
    if not isinstance(raw, list):
        return refs, unresolved
    seen: set[tuple[str, str]] = set()
    for item in raw[:50]:
        if not isinstance(item, dict):
            continue
        ref_type = item.get("ref_type")
        ref_id = item.get("ref_id")
        if not isinstance(ref_type, str) or not isinstance(ref_id, str):
            continue
        ref_type = ref_type.strip()
        ref_id = ref_id.strip()
        if not ref_type or not ref_id:
            continue
        key = (ref_type, ref_id)
        if key in seen:
            continue
        seen.add(key)
        if _validate_ref_id(ref_id):
            refs.append({"ref_type": ref_type, "ref_id": ref_id})
        else:
            unresolved.append(ref_id)
    return refs, unresolved


def _infer_stage(agent_name: str, output_data: dict[str, Any]) -> DecisionStage:
    explicit = output_data.get("stage")
    if isinstance(explicit, str) and explicit.strip():
        try:
            return DecisionStage(explicit.strip())
        except ValueError:
            logger.debug("unknown decision stage %r for agent=%s", explicit, agent_name)
    mapping = {
        "planner_agent": DecisionStage.PLANNER,
        "risk_agent": DecisionStage.RISK,
        "response_agent": DecisionStage.RESPONSE,
        "triage_agent": DecisionStage.TRIAGE,
        "evidence_agent": DecisionStage.EVIDENCE,
        "verify_agent": DecisionStage.VERIFY,
    }
    return mapping.get(agent_name, DecisionStage.OTHER)


def _idempotency_key(
    event_id: str,
    stage: DecisionStage,
    agent_name: str,
    input_data: dict[str, Any],
    output_data: dict[str, Any],
) -> str:
    round_index = input_data.get("round_index")
    if isinstance(round_index, int):
        return f"{event_id}:{stage.value}:{agent_name}:round{round_index}:r1"
    plan_id = output_data.get("plan_id")
    if isinstance(plan_id, str) and plan_id.strip():
        revision = output_data.get("revision", 0)
        return f"{event_id}:{stage.value}:{agent_name}:{plan_id.strip()}:rev{revision}"
    return f"{event_id}:{stage.value}:{agent_name}:r1"


def _enrich_agent_output(
    agent_name: str,
    input_data: dict[str, Any],
    output_data: dict[str, Any],
) -> dict[str, Any]:
    """Project typed agent outputs into DecisionRecord-friendly structured fields."""
    enriched = dict(output_data)
    if agent_name == "triage_agent":
        enriched.setdefault(
            "decision_summary",
            (
                output_data.get("decision_summary")
                or (
                    f"event_type={output_data.get('event_type')}, "
                    f"severity={output_data.get('severity')}, "
                    f"need_investigation={output_data.get('need_investigation')}"
                )
            )[:512],
        )
        severity = output_data.get("severity")
        if severity is not None:
            enriched.setdefault("reason_code", str(severity))
        enriched.setdefault("selected_action", f"triage:{output_data.get('event_type')}")
    elif agent_name == "risk_agent":
        reason_codes = output_data.get("verdict_reason_codes")
        reason_codes_text = ""
        if isinstance(reason_codes, list) and reason_codes:
            reason_codes_text = ",".join(str(code) for code in reason_codes[:10] if code)
            # Prefer demotion / adjudication codes over scoring_mode for DecisionRecord.
            enriched.setdefault("reason_code", str(reason_codes[0]))
            enriched.setdefault(
                "reason_codes",
                [str(code) for code in reason_codes[:20] if code is not None],
            )
        enriched.setdefault(
            "decision_summary",
            (
                f"risk_score={output_data.get('risk_score')} "
                f"severity={output_data.get('severity')} "
                f"mode={output_data.get('scoring_mode')} "
                f"evidence_limited={bool(output_data.get('evidence_limited'))}"
                + (f" verdict_reason_codes={reason_codes_text}" if reason_codes_text else "")
            )[:512],
        )
        if output_data.get("confidence") is not None:
            enriched.setdefault("confidence", output_data.get("confidence"))
        enriched.setdefault("reason_code", str(output_data.get("scoring_mode", "unspecified")))
        enriched.setdefault("selected_action", f"severity:{output_data.get('severity')}")
    elif agent_name == "planner_agent":
        steps = output_data.get("steps") or []
        if isinstance(steps, list):
            enriched["candidate_actions"] = [
                {
                    "candidate_type": "plan_step",
                    "name": str(step.get("assigned_agent", "")),
                    "candidate_id": str(step.get("step_order", "")),
                }
                for step in steps[:50]
                if isinstance(step, dict) and step.get("assigned_agent")
            ]
        plan_id = output_data.get("plan_id")
        if isinstance(plan_id, str) and plan_id.strip():
            enriched.setdefault("selected_action", f"plan:{plan_id.strip()}")
        if steps and isinstance(steps[0], dict):
            enriched.setdefault("decision_summary", str(steps[0].get("step_goal", ""))[:512])
        enriched.setdefault("reason_code", f"plan_rev_{output_data.get('revision', 0)}")
    elif agent_name == "response_agent":
        actions = output_data.get("actions") or []
        if isinstance(actions, list):
            enriched["candidate_actions"] = [
                {
                    "candidate_type": "response_action",
                    "name": str(action.get("action_name") or action.get("tool_name", "")),
                    "candidate_id": str(action.get("action_id", "")),
                }
                for action in actions[:50]
                if isinstance(action, dict)
                and (action.get("action_name") or action.get("tool_name"))
            ]
            playbook_refs = []
            for action in actions[:50]:
                if not isinstance(action, dict):
                    continue
                ref = action.get("playbook_ref")
                if isinstance(ref, dict) and ref.get("release_id") and ref.get("playbook_id"):
                    release_id = str(ref["release_id"]).strip()
                    playbook_id = str(ref["playbook_id"]).strip()
                    playbook_refs.append(
                        {"ref_type": "playbook_release_id", "ref_id": release_id},
                    )
                    playbook_refs.append(
                        {"ref_type": "playbook_id", "ref_id": playbook_id},
                    )
            if playbook_refs:
                enriched.setdefault("input_refs", [])
                if isinstance(enriched["input_refs"], list):
                    enriched["input_refs"].extend(playbook_refs[:20])
                first_ref = actions[0].get("playbook_ref") if actions else None
                if isinstance(first_ref, dict):
                    enriched["kb_version"] = str(
                        first_ref.get("release_version") or first_ref.get("release_id") or ""
                    )[:128]
        plan_id = output_data.get("plan_id")
        if isinstance(plan_id, str) and plan_id.strip():
            enriched.setdefault("selected_action", f"response_plan:{plan_id.strip()}")
        action_count = len(actions) if isinstance(actions, list) else 0
        generated = output_data.get("generated_by")
        enriched.setdefault(
            "decision_summary",
            (
                f"response_plan actions={action_count} "
                f"plan_id={plan_id or 'none'} generated_by={generated or 'unknown'}"
            )[:512],
        )
        if generated is not None:
            enriched.setdefault("reason_code", str(generated))
    elif agent_name == "evidence_agent":
        query_timings = output_data.get("query_timings") or []
        if isinstance(query_timings, list):
            enriched["candidate_actions"] = [
                {
                    "candidate_type": "evidence_query",
                    "name": str(row.get("tool_name") or ""),
                    "candidate_id": str(row.get("dedupe_key") or row.get("tool_name") or ""),
                }
                for row in query_timings[:50]
                if isinstance(row, dict) and row.get("tool_name")
            ]
        evidence_list = output_data.get("evidence_list") or []
        if isinstance(evidence_list, list):
            enriched["evidence_refs"] = [
                str(item.get("evidence_id"))
                for item in evidence_list[:50]
                if isinstance(item, dict) and item.get("evidence_id")
            ]
        gaps = output_data.get("gaps") or []
        if isinstance(gaps, list):
            enriched["gap_refs"] = [
                {
                    "source": str(item.get("missing_source") or ""),
                    "reason": str(item.get("reason") or ""),
                }
                for item in gaps[:50]
                if isinstance(item, dict)
            ]
        query_plan = output_data.get("query_plan") or {}
        if isinstance(query_plan, dict):
            step_orders = query_plan.get("plan_step_orders") or []
            if step_orders:
                enriched.setdefault("reason_code", f"plan_steps:{','.join(map(str, step_orders))}")
            degraded = query_plan.get("degraded_reasons") or []
            if degraded:
                enriched.setdefault(
                    "decision_summary",
                    ",".join(str(item) for item in degraded)[:512],
                )
        enriched.setdefault(
            "decision_summary",
            (
                f"collection_status={output_data.get('collection_status')} "
                f"queries={len(query_timings) if isinstance(query_timings, list) else 0}"
            )[:512],
        )
        enriched.setdefault("selected_action", f"evidence:{output_data.get('collection_status')}")
    elif agent_name == "verify_agent":
        overall_status = output_data.get("overall_status")
        verification_phase = output_data.get("verification_phase")
        results = output_data.get("results") or []
        failed_actions = output_data.get("failed_actions") or []
        failed_writebacks = output_data.get("failed_writebacks") or []
        blocked_writebacks = output_data.get("blocked_writebacks") or []

        if output_data.get("need_manual_resolution"):
            reason_code = "need_manual_resolution"
        elif output_data.get("need_writeback_recovery"):
            reason_code = "need_writeback_recovery"
        elif output_data.get("need_action_replan"):
            reason_code = "need_action_replan"
        elif overall_status is not None:
            reason_code = str(overall_status)
        else:
            reason_code = "unspecified"
        enriched.setdefault("reason_code", reason_code)

        phase_label = str(verification_phase or "unknown")
        status_label = str(overall_status or "unknown")
        result_count = len(results) if isinstance(results, list) else 0
        failed_count = len(failed_actions) if isinstance(failed_actions, list) else 0
        enriched.setdefault(
            "decision_summary",
            (
                f"overall_status={status_label} "
                f"verification_phase={phase_label} "
                f"results={result_count} failed_actions={failed_count}"
            )[:512],
        )
        enriched.setdefault("selected_action", f"verify:{phase_label}:{status_label}")

        if isinstance(results, list):
            enriched["candidate_actions"] = [
                {
                    "candidate_type": "verification_action",
                    "name": str(item.get("effect_status") or item.get("writeback_status") or ""),
                    "candidate_id": str(item.get("action_id") or ""),
                }
                for item in results[:50]
                if isinstance(item, dict) and item.get("action_id")
            ]
        if isinstance(failed_writebacks, list) and failed_writebacks:
            enriched.setdefault(
                "gap_refs",
                [
                    {"source": "writeback", "reason": str(action_id)}
                    for action_id in failed_writebacks[:20]
                ],
            )
        if isinstance(blocked_writebacks, list) and blocked_writebacks:
            enriched.setdefault("gap_refs", [])
            if isinstance(enriched["gap_refs"], list):
                enriched["gap_refs"].extend(
                    [
                        {"source": "writeback_blocked", "reason": str(action_id)}
                        for action_id in blocked_writebacks[:20]
                    ]
                )
    if isinstance(input_data.get("event_id"), str):
        enriched.setdefault("event_id", input_data["event_id"])
    return enriched


def _sanitize_record_output(output_data: dict[str, Any]) -> dict[str, Any]:
    """Project agent output before building durable DecisionRecord payloads."""
    if not output_data:
        return output_data
    projected = TraceProjection.project(output_data)
    if isinstance(projected, dict) and not projected.get("_truncated"):
        return projected
    sanitized = dict(output_data)
    summary = sanitized.get("decision_summary")
    if isinstance(summary, str):
        sanitized["decision_summary"] = redact_sensitive_text(summary.strip())[:512]
    return sanitized


def _build_record_payload(
    *,
    event_id: str,
    agent_name: str,
    trace_id: str,
    input_data: dict[str, Any],
    output_data: dict[str, Any],
    llm_model: str | None,
) -> DecisionRecord | None:
    output_data = _enrich_agent_output(agent_name, input_data, output_data)

    summary = output_data.get("decision_summary")
    if not isinstance(summary, str):
        summary = ""
    summary = redact_sensitive_text(summary.strip())[:512]

    reason_codes: list[str] = []
    for key in ("reason_code", "gap_code", "uncertainty_code"):
        value = output_data.get(key)
        if isinstance(value, str) and value.strip():
            reason_codes.append(value.strip())
    # ISSUE-241: prefer explicit structured lists from RiskAssessment / enrichment.
    for key in ("reason_codes", "verdict_reason_codes"):
        raw_list = output_data.get(key)
        if not isinstance(raw_list, list):
            continue
        for item in raw_list:
            if item is None:
                continue
            text = str(item).strip()
            if text and text not in reason_codes:
                reason_codes.append(text)
            if len(reason_codes) >= 20:
                break

    selected: dict[str, Any] = {}
    selected_action = output_data.get("selected_action")
    if isinstance(selected_action, str) and selected_action.strip():
        selected["selected_action"] = selected_action.strip()[:256]

    confidence = output_data.get("confidence")
    if confidence is None and agent_name == "risk_agent":
        confidence = output_data.get("overall_confidence")
    confidence_value = float(confidence) if isinstance(confidence, (int, float)) else None

    input_refs, unresolved_from_input = _collect_input_refs(input_data)
    enriched_refs, enriched_unresolved = _collect_enriched_input_refs(output_data)
    input_refs.extend(enriched_refs)
    unresolved_from_input.extend(enriched_unresolved)
    candidates = _coerce_candidates(output_data.get("candidate_actions"))

    evidence_refs = output_data.get("evidence_refs")
    if isinstance(evidence_refs, list):
        for item in evidence_refs[:50]:
            ref_id = item.get("evidence_id") if isinstance(item, dict) else item
            if not isinstance(ref_id, str) or not ref_id.strip():
                continue
            ref_id = ref_id.strip()
            if _validate_ref_id(ref_id):
                input_refs.append({"ref_type": "evidence_id", "ref_id": ref_id})
            else:
                unresolved_from_input.append(ref_id)

    if (
        not summary
        and not reason_codes
        and not selected
        and not candidates
        and confidence_value is None
    ):
        return None

    stage = _infer_stage(agent_name, output_data)
    try:
        revision = max(1, int(output_data.get("revision", 1)))
    except (TypeError, ValueError):
        revision = 1

    rule_version = output_data.get("rule_version")
    if rule_version is None and agent_name == "risk_agent":
        scoring_mode = output_data.get("scoring_mode")
        if scoring_mode is not None:
            rule_version = str(scoring_mode)
    kb_version = output_data.get("kb_version")
    if kb_version is not None:
        kb_version = str(kb_version)[:128]

    idempotency_key = _idempotency_key(event_id, stage, agent_name, input_data, output_data)
    if revision > 1 and agent_name == "planner_agent":
        plan_id = output_data.get("plan_id")
        if isinstance(plan_id, str) and plan_id.strip():
            idempotency_key = (
                f"{event_id}:{stage.value}:{agent_name}:{plan_id.strip()}:rev{revision}"
            )

    record_id = f"dec-{uuid.uuid4().hex[:12]}"

    record = DecisionRecord(
        record_id=record_id,
        event_id=event_id,
        stage=stage,
        actor=agent_name,
        input_refs=input_refs[:100],
        candidates=candidates,
        selected=selected,
        reason_codes=reason_codes[:20],
        decision_summary=summary,
        rule_version=str(rule_version)[:128] if rule_version is not None else None,
        model_version=llm_model,
        prompt_policy_version=PROMPT_POLICY_VERSION,
        kb_version=kb_version,
        confidence=confidence_value,
        uncertainty_codes=[
            code
            for code in (output_data.get("uncertainty_code"),)
            if isinstance(code, str) and code.strip() and code != ReActUncertaintyCode.NONE.value
        ],
        guardrail_flags=[
            str(item)[:128]
            for item in (output_data.get("warnings") or [])
            if isinstance(item, str) and item.strip()
        ][:20],
        degraded=bool(output_data.get("degraded")),
        trace_ref=trace_id,
        schema_version=DECISION_RECORD_SCHEMA_VERSION,
        idempotency_key=idempotency_key,
        revision=revision,
        retention_policy="standard",
        unresolved_refs=sorted(set(unresolved_from_input))[:50],
        owner=agent_name,
        created_at=datetime.now(UTC),
    )
    canonical = TraceProjection.project(record.model_dump(mode="json", exclude={"record_hash"}))
    assert isinstance(canonical, dict)
    canonical.pop("created_at", None)
    record.record_hash = _record_hash(canonical)
    return record


def _orm_from_record(record: DecisionRecord) -> orm.DecisionRecord:
    return orm.DecisionRecord(
        record_id=record.record_id,
        event_id=record.event_id,
        stage=record.stage.value,
        actor=record.actor,
        input_refs=record.input_refs,
        candidates=[item.model_dump(mode="json") for item in record.candidates],
        selected=record.selected,
        reason_codes=record.reason_codes,
        decision_summary=record.decision_summary,
        rule_version=record.rule_version,
        model_version=record.model_version,
        prompt_policy_version=record.prompt_policy_version,
        kb_version=record.kb_version,
        confidence=record.confidence,
        uncertainty_codes=record.uncertainty_codes,
        guardrail_flags=record.guardrail_flags,
        degraded=record.degraded,
        trace_ref=record.trace_ref,
        schema_version=record.schema_version,
        record_hash=record.record_hash,
        idempotency_key=record.idempotency_key,
        revision=record.revision,
        parent_record_id=record.parent_record_id,
        supersedes_record_id=record.supersedes_record_id,
        retention_policy=record.retention_policy,
        unresolved_refs=record.unresolved_refs,
        owner=record.owner,
        created_at=record.created_at or datetime.now(UTC),
    )


class DecisionRecordService:
    """Writes durable DecisionRecord rows with idempotent replay semantics."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        degraded_flag_service: Any | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._degraded_flags = degraded_flag_service

    async def _mark_audit_degraded(self, event_id: str) -> None:
        if self._degraded_flags is None:
            return
        try:
            await self._degraded_flags.set_flag(
                event_id,
                "decision_audit_degraded",
                True,
                writer="DecisionRecordService",
            )
        except Exception:  # noqa: BLE001 - degraded annotation must not break persistence
            logger.exception("Failed to set decision_audit_degraded event=%s", event_id)

    async def _finalize_existing_record(
        self,
        existing: orm.DecisionRecord,
        record: DecisionRecord,
    ) -> str:
        if existing.record_hash != record.record_hash:
            logger.warning(
                "DecisionRecord idempotency replay hash mismatch key=%s existing=%s new=%s",
                record.idempotency_key,
                existing.record_hash,
                record.record_hash,
            )
            await self._mark_audit_degraded(record.event_id)
        return existing.record_id

    async def persist_in_session(
        self,
        session: AsyncSession,
        record: DecisionRecord,
    ) -> str:
        existing = await session.scalar(
            select(orm.DecisionRecord).where(
                orm.DecisionRecord.idempotency_key == record.idempotency_key
            )
        )
        if existing is not None:
            return await self._finalize_existing_record(existing, record)

        if record.stage is DecisionStage.PLANNER and record.revision > 1:
            selected_action = str(record.selected.get("selected_action", ""))
            if selected_action.startswith("plan:"):
                plan_id = selected_action.removeprefix("plan:")
                prev_key = (
                    f"{record.event_id}:{DecisionStage.PLANNER.value}:"
                    f"planner_agent:{plan_id}:rev{record.revision - 1}"
                )
                prev = await session.scalar(
                    select(orm.DecisionRecord).where(orm.DecisionRecord.idempotency_key == prev_key)
                )
                if prev is not None:
                    record = record.model_copy(
                        update={
                            "parent_record_id": prev.record_id,
                            "supersedes_record_id": prev.record_id,
                        }
                    )

        row = _orm_from_record(record)
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(orm.DecisionRecord).where(
                    orm.DecisionRecord.idempotency_key == record.idempotency_key
                )
            )
            if existing is None:
                raise
            return await self._finalize_existing_record(existing, record)
        return row.record_id

    async def persist_from_agent_trace(
        self,
        *,
        event_id: str,
        agent_name: str,
        trace_id: str,
        input_data: Any,
        output_data: Any,
        llm_model: str | None = None,
        session: AsyncSession | None = None,
    ) -> str | None:
        if output_data is None:
            return None
        input_dict = _to_mapping(input_data)
        output_dict = _sanitize_record_output(_to_mapping(output_data))
        record = _build_record_payload(
            event_id=event_id,
            agent_name=agent_name,
            trace_id=trace_id,
            input_data=input_dict,
            output_data=output_dict,
            llm_model=llm_model,
        )
        if record is None:
            return None

        if session is not None:
            return await self.persist_in_session(session, record)

        async with self._session_factory() as owned_session:
            async with owned_session.begin():
                return await self.persist_in_session(owned_session, record)

    async def list_by_event(
        self,
        event_id: str,
        *,
        session: AsyncSession | None = None,
    ) -> list[orm.DecisionRecord]:
        if session is not None:
            rows = await session.scalars(
                select(orm.DecisionRecord)
                .where(orm.DecisionRecord.event_id == event_id)
                .order_by(orm.DecisionRecord.created_at.asc())
            )
            return list(rows)
        async with self._session_factory() as owned_session:
            rows = await owned_session.scalars(
                select(orm.DecisionRecord)
                .where(orm.DecisionRecord.event_id == event_id)
                .order_by(orm.DecisionRecord.created_at.asc())
            )
            return list(rows)

    async def ensure_fp_disposition_audit(
        self,
        session: AsyncSession,
        *,
        event_id: str,
        fp_match: dict[str, Any],
    ) -> str:
        """Create the minimum durable audit record for disposition-only FP auto paths."""
        idempotency_key = f"{event_id}:triage:disposition_only_fp:r1"
        existing = await session.scalar(
            select(orm.DecisionRecord).where(orm.DecisionRecord.idempotency_key == idempotency_key)
        )
        if existing is not None:
            return existing.record_id
        try:
            fp_score = max(0.0, min(1.0, float(fp_match.get("max_score") or 0.0)))
        except (TypeError, ValueError):
            fp_score = 0.0
        record = DecisionRecord(
            record_id=f"dec-{uuid.uuid4().hex[:12]}",
            event_id=event_id,
            stage=DecisionStage.TRIAGE,
            actor="workflow_runtime",
            input_refs=[{"ref_type": "event_id", "ref_id": event_id}],
            selected={"recommendation": "close_as_fp"},
            reason_codes=["close_as_fp"],
            decision_summary="false_positive disposition-only close_as_fp recommendation",
            prompt_policy_version=PROMPT_POLICY_VERSION,
            confidence=fp_score,
            trace_ref=f"trc-fp-{event_id[-8:]}",
            schema_version=DECISION_RECORD_SCHEMA_VERSION,
            idempotency_key=idempotency_key,
            owner="workflow_runtime",
            created_at=datetime.now(UTC),
        )
        canonical = TraceProjection.project(record.model_dump(mode="json", exclude={"record_hash"}))
        assert isinstance(canonical, dict)
        canonical.pop("created_at", None)
        record.record_hash = _record_hash(canonical)
        return await self.persist_in_session(session, record)

    async def assert_auto_disposition_allowed(
        self,
        event_id: str,
        *,
        session: AsyncSession | None = None,
    ) -> None:
        if self._degraded_flags is not None and await self._degraded_flags.has_flag(
            event_id,
            "decision_audit_degraded",
        ):
            raise ValidationError(
                "auto disposition blocked by degraded decision audit",
                details={"event_id": event_id},
            )
        records = await self.list_by_event(event_id, session=session)
        if not records:
            raise ValidationError(
                "auto disposition requires decision audit records",
                details={"event_id": event_id},
            )
        material_records = [
            row
            for row in records
            if str(getattr(row, "stage", "") or "") in _DISPOSITION_BLOCKING_STAGES
        ]
        if not material_records:
            raise ValidationError(
                "auto disposition requires material decision audit records",
                details={"event_id": event_id},
            )
        blocking = [row.record_id for row in material_records if self.blocks_auto_disposition(row)]
        if blocking:
            raise ValidationError(
                "auto disposition blocked by decision audit",
                details={"event_id": event_id, "blocking_record_ids": blocking},
            )

    async def get_by_trace_ref(self, trace_id: str) -> orm.DecisionRecord | None:
        async with self._session_factory() as session:
            return cast(
                orm.DecisionRecord | None,
                await session.scalar(
                    select(orm.DecisionRecord)
                    .where(orm.DecisionRecord.trace_ref == trace_id)
                    .order_by(orm.DecisionRecord.created_at.desc())
                    .limit(1)
                ),
            )

    @staticmethod
    def blocks_auto_disposition(record: DecisionRecord | orm.DecisionRecord) -> bool:
        stage = getattr(record, "stage", None)
        stage_value = stage.value if isinstance(stage, DecisionStage) else str(stage or "")
        if stage_value not in _DISPOSITION_BLOCKING_STAGES:
            return False
        unresolved = getattr(record, "unresolved_refs", None) or []
        if unresolved:
            return True
        summary = str(getattr(record, "decision_summary", "") or "").strip()
        reason_codes = getattr(record, "reason_codes", None) or []
        confidence = getattr(record, "confidence", None)
        selected = getattr(record, "selected", None) or {}
        has_basis = bool(summary) or bool(reason_codes)
        has_outcome = confidence is not None or bool(selected)
        return not (has_basis and has_outcome)


__all__ = [
    "DECISION_RECORD_SCHEMA_VERSION",
    "PROMPT_POLICY_VERSION",
    "DecisionRecordService",
]
