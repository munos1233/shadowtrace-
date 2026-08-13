"""Post-PolicyFilter response-plan quality gates.

ISSUE-198: containment alignment — high-confidence investigations must not
silently degrade to ticket-only after PolicyFilter.

ISSUE-248: evidence sufficiency — collection failed / zero-evidence
``evidence_limited`` must not plan L2+ high-impact actions. Evidence gate
takes priority over containment encouragement (orthogonal concerns).

ISSUE-328: containment coverage — when containment exists but EntitySet
hosts/accounts/external IPs remain uncovered, merge missing targets scoped
to EntitySet only (never asset-inventory expansion).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import fields, replace
from typing import Any, Protocol, TypeVar

from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ResponsePlanGeneratedBy,
    RiskAssessment,
)
from app.models.entities import AccountEntity, EntitySet, HostEntity, IPEntity
from app.models.enums import ActionLevel, FinalVerdict, Severity

# Tools that materially contain/affect identified threat entities.
CONTAINMENT_TOOLS = frozenset(
    {
        "block_ip",
        "block_domain",
        "isolate_host",
        "disable_account",
        "quarantine_file",
        "block_process",
        "force_logout",
        "reset_password",
        "revoke_token",
    }
)

_NON_CONTAINMENT_TOOLS = frozenset({"create_ticket", "notify_security_team"})

# Align with HIGH severity floor in RiskAgent / intro defaults.
RISK_CONTAINMENT_THRESHOLD = 70

# ISSUE-248: when evidence is insufficient, only L0/L1 may remain in the plan.
MAX_ACTION_LEVEL_WHEN_EVIDENCE_INSUFFICIENT = ActionLevel.L1

_CandidateT = TypeVar("_CandidateT", bound="ActionCandidateLike")


class ActionCandidateLike(Protocol):
    # Read-only property so frozen dataclasses (e.g. ActionCandidate) structurally match.
    @property
    def tool_name(self) -> str: ...

    @property
    def target(self) -> str | None: ...


def has_actionable_containment_targets(entities: EntitySet) -> bool:
    """Return True when EntitySet exposes at least one containable target."""
    if (
        entities.accounts
        or entities.hosts
        or entities.domains
        or entities.processes
        or entities.files
    ):
        return True
    return any((ip.address or ip.entity_id) for ip in entities.ips)


def evidence_blocks_high_impact_actions(
    *,
    evidence_output: EvidenceOutput | None,
    risk_assessment: RiskAssessment | None = None,
    evidence_limited: bool | None = None,
) -> bool:
    """Hard gate predicate for ISSUE-248.

    Blocks L2+ planning when:
    - ``collection_status == failed``, or
    - ``evidence_limited`` and evidence item count is 0.

    Does **not** key off ``final_verdict=none`` (common after evidence_limited
    demotion and would over-block real threats with usable evidence).
    """
    limited = (
        bool(evidence_limited)
        if evidence_limited is not None
        else bool(risk_assessment.evidence_limited)
        if risk_assessment is not None
        else False
    )
    if evidence_output is None:
        # No evidence payload: only block when risk already marked limited.
        return limited

    if evidence_output.collection_status is CollectionStatus.FAILED:
        return True
    if limited and len(evidence_output.evidence_list) == 0:
        return True
    return False


def evidence_insufficiency_reason_code(
    *,
    evidence_output: EvidenceOutput | None,
    risk_assessment: RiskAssessment | None = None,
    evidence_limited: bool | None = None,
) -> str | None:
    """Stable reason code when :func:`evidence_blocks_high_impact_actions` is true."""
    if not evidence_blocks_high_impact_actions(
        evidence_output=evidence_output,
        risk_assessment=risk_assessment,
        evidence_limited=evidence_limited,
    ):
        return None
    if evidence_output is not None and evidence_output.collection_status is CollectionStatus.FAILED:
        return "collection_failed"
    return "zero_evidence_limited"


def _action_level_rank(level: ActionLevel) -> int:
    raw = level.value
    if raw.startswith("l") and raw[1:].isdigit():
        return int(raw[1:])
    return 99


def resolve_candidate_action_level(
    candidate: ActionCandidateLike,
    *,
    resolve_tool_level: Callable[[str], ActionLevel] | None = None,
) -> ActionLevel:
    """Resolve action level for a candidate (tool catalog, else conservative L2)."""
    if resolve_tool_level is not None:
        return resolve_tool_level(candidate.tool_name)
    # Unknown tools without a resolver are treated as high-impact so the
    # evidence gate fails closed rather than admitting uncatalogued L2+.
    return ActionLevel.L2


def apply_evidence_sufficiency_gate(
    *,
    candidates: list[_CandidateT],
    generated_by: ResponsePlanGeneratedBy,
    strategy: str,
    evidence_output: EvidenceOutput | None,
    risk_assessment: RiskAssessment,
    disposition_only: bool,
    resolve_tool_level: Callable[[str], ActionLevel] | None = None,
    fallback_safe_candidates: list[_CandidateT] | None = None,
) -> tuple[list[_CandidateT], ResponsePlanGeneratedBy, str]:
    """Strip L2+ actions when evidence is insufficient (ISSUE-248).

    Priority: runs as a hard plan-quality constraint. Callers should skip
    containment encouragement when this gate applies (see ResponseAgent).
    """
    if disposition_only:
        return candidates, generated_by, strategy
    if not evidence_blocks_high_impact_actions(
        evidence_output=evidence_output,
        risk_assessment=risk_assessment,
    ):
        return candidates, generated_by, strategy

    max_rank = _action_level_rank(MAX_ACTION_LEVEL_WHEN_EVIDENCE_INSUFFICIENT)
    kept = [
        item
        for item in candidates
        if _action_level_rank(
            resolve_candidate_action_level(item, resolve_tool_level=resolve_tool_level)
        )
        <= max_rank
    ]
    removed = len(kept) != len(candidates)

    if not kept and fallback_safe_candidates:
        kept = [
            item
            for item in fallback_safe_candidates
            if _action_level_rank(
                resolve_candidate_action_level(item, resolve_tool_level=resolve_tool_level)
            )
            <= max_rank
        ]
        removed = removed or bool(kept)

    reason = (
        evidence_insufficiency_reason_code(
            evidence_output=evidence_output,
            risk_assessment=risk_assessment,
        )
        or "evidence_insufficient"
    )
    note = f"evidence_sufficiency_gate: high_impact_blocked:{reason}"
    if removed or note not in strategy:
        strategy = f"{strategy}; {note}" if strategy else note
    if removed and generated_by is ResponsePlanGeneratedBy.LLM:
        generated_by = ResponsePlanGeneratedBy.TEMPLATE
    return kept, generated_by, strategy


def _containment_candidates(candidates: list[_CandidateT]) -> list[_CandidateT]:
    return [item for item in candidates if item.tool_name in CONTAINMENT_TOOLS]


def _canonical_account_target(account: AccountEntity) -> str | None:
    return account.username or account.entity_id or None


def _canonical_host_target(host: HostEntity) -> str | None:
    return host.hostname or host.ip or host.entity_id or None


def _canonical_external_ip_target(ip: IPEntity) -> str | None:
    if ip.scope != "external":
        return None
    return ip.address or ip.entity_id or None


def required_containment_targets(entities: EntitySet) -> list[tuple[str, str, str]]:
    """Return (tool_name, target_type, canonical_target) pairs for EntitySet coverage.

  ISSUE-328 contract: accounts → disable_account, hosts → isolate_host,
  external IPs → block_ip. Only entities already in EntitySet are considered —
  never expand to full asset inventory (red herrings stay out).
    """
    required: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    for account in entities.accounts:
        target = _canonical_account_target(account)
        if target and ("disable_account", target) not in seen:
            seen.add(("disable_account", target))
            required.append(("disable_account", "account", target))

    for host in entities.hosts:
        target = _canonical_host_target(host)
        if target and ("isolate_host", target) not in seen:
            seen.add(("isolate_host", target))
            required.append(("isolate_host", "host", target))

    for ip in entities.ips:
        target = _canonical_external_ip_target(ip)
        if target and ("block_ip", target) not in seen:
            seen.add(("block_ip", target))
            required.append(("block_ip", "ip", target))

    return required


def _covered_containment_pairs(candidates: list[_CandidateT]) -> set[tuple[str, str]]:
    covered: set[tuple[str, str]] = set()
    for item in candidates:
        if item.tool_name not in CONTAINMENT_TOOLS:
            continue
        target = item.target
        if target:
            covered.add((item.tool_name, target))
    return covered


def _candidate_template(
    candidates: list[_CandidateT],
    rule_fallback_candidates: list[_CandidateT],
) -> _CandidateT | None:
    for pool in (candidates, rule_fallback_candidates):
        if pool:
            return pool[0]
    return None


def _synthesize_containment_candidate(
    template: _CandidateT,
    *,
    tool_name: str,
    target_type: str,
    target: str,
) -> _CandidateT:
    field_names = {field.name for field in fields(template)}
    updates: dict[str, Any] = {"tool_name": tool_name}
    if "target_type" in field_names:
        updates["target_type"] = target_type
    if "target" in field_names:
        updates["target"] = target
    if "parameters" in field_names:
        updates["parameters"] = {}
    if "reason" in field_names:
        updates["reason"] = "containment_quality_gate: entity coverage"
    return replace(template, **updates)


def _resolve_missing_containment_candidates(
    missing: list[tuple[str, str, str]],
    *,
    candidates: list[_CandidateT],
    rule_fallback_candidates: list[_CandidateT],
) -> list[_CandidateT]:
    rule_by_pair = {
        (item.tool_name, item.target or ""): item
        for item in rule_fallback_candidates
        if item.tool_name in CONTAINMENT_TOOLS and item.target
    }
    allowed_tools = {
        item.tool_name
        for item in rule_fallback_candidates
        if item.tool_name in CONTAINMENT_TOOLS
    }
    template = _candidate_template(candidates, rule_fallback_candidates)
    if template is None:
        return []

    additions: list[_CandidateT] = []
    for tool_name, target_type, target in missing:
        existing = rule_by_pair.get((tool_name, target))
        if existing is not None:
            additions.append(existing)
            continue
        if tool_name not in allowed_tools:
            continue
        additions.append(
            _synthesize_containment_candidate(
                template,
                tool_name=tool_name,
                target_type=target_type,
                target=target,
            )
        )
    return additions


def _dedupe_candidates(candidates: list[_CandidateT]) -> list[_CandidateT]:
    seen: set[tuple[str, str]] = set()
    ordered: list[_CandidateT] = []
    for item in candidates:
        key = (item.tool_name, item.target or "")
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    return ordered


def _merge_rule_fallback_when_ungrounded(
    candidates: list[_CandidateT],
    rule_fallback_candidates: list[_CandidateT],
) -> list[_CandidateT]:
    """ISSUE-198: replace ticket-only LLM output with grounded rule containment."""
    rule_containment = _containment_candidates(rule_fallback_candidates)
    if not rule_containment:
        return candidates

    rule_non_containment = [
        item for item in rule_fallback_candidates if item.tool_name in _NON_CONTAINMENT_TOOLS
    ]
    rule_tool_names = {item.tool_name for item in rule_fallback_candidates}
    preserved_notify = [
        item
        for item in candidates
        if item.tool_name in _NON_CONTAINMENT_TOOLS and item.tool_name not in rule_tool_names
    ]
    return [*rule_containment, *rule_non_containment, *preserved_notify]


def requires_threat_aligned_containment(
    *,
    severity: Severity,
    risk_assessment: RiskAssessment,
    final_verdict: FinalVerdict | str | None,
    entities: EntitySet,
    disposition_only: bool,
    evidence_output: EvidenceOutput | None = None,
) -> bool:
    """High-confidence investigations with known entities need grounded containment.

    Evidence sufficiency (ISSUE-248) has priority: when collection failed or
    zero-evidence ``evidence_limited``, do **not** encourage containment even
    if severity / risk_score floors would otherwise trigger this gate.
    """
    if disposition_only:
        return False
    if evidence_blocks_high_impact_actions(
        evidence_output=evidence_output,
        risk_assessment=risk_assessment,
    ):
        return False
    if not has_actionable_containment_targets(entities):
        return False

    verdict: FinalVerdict | None = None
    if final_verdict is not None:
        try:
            verdict = (
                final_verdict
                if isinstance(final_verdict, FinalVerdict)
                else FinalVerdict(str(final_verdict))
            )
        except ValueError:
            verdict = None
    if verdict is FinalVerdict.FALSE_POSITIVE:
        return False

    if verdict is FinalVerdict.CONFIRMED_THREAT:
        return True
    if _severity_rank(severity) >= _severity_rank(Severity.HIGH):
        return True
    return int(risk_assessment.risk_score) >= RISK_CONTAINMENT_THRESHOLD


def apply_containment_quality_gate(
    *,
    candidates: list[_CandidateT],
    rule_fallback_candidates: list[_CandidateT],
    generated_by: ResponsePlanGeneratedBy,
    strategy: str,
    severity: Severity,
    risk_assessment: RiskAssessment,
    final_verdict: FinalVerdict | str | None,
    entities: EntitySet,
    disposition_only: bool,
    evidence_output: EvidenceOutput | None = None,
) -> tuple[list[_CandidateT], ResponsePlanGeneratedBy, str]:
    """Ensure high-confidence plans include grounded containment or rule fallback.

    ISSUE-328: when containment exists but EntitySet hosts/accounts/external IPs
    remain uncovered, merge missing isolate/disable/block targets from the
    EntitySet (rule fallback pool first, then synthesis). ISSUE-198 still
    applies when the plan has zero containment actions.
    """
    if not requires_threat_aligned_containment(
        severity=severity,
        risk_assessment=risk_assessment,
        final_verdict=final_verdict,
        entities=entities,
        disposition_only=disposition_only,
        evidence_output=evidence_output,
    ):
        return candidates, generated_by, strategy

    required = required_containment_targets(entities)
    if not required:
        return candidates, generated_by, strategy

    working = list(candidates)
    used_rule_fallback = False

    if not _containment_candidates(working):
        merged = _merge_rule_fallback_when_ungrounded(working, rule_fallback_candidates)
        if merged is working:
            note = (
                "containment_quality_gate_unsatisfied: "
                "no grounded containment after PolicyFilter"
            )
            if generated_by is ResponsePlanGeneratedBy.LLM:
                generated_by = ResponsePlanGeneratedBy.TEMPLATE
            strategy = f"{strategy}; {note}" if strategy else note
            return candidates, generated_by, strategy
        working = merged
        used_rule_fallback = True

    covered = _covered_containment_pairs(working)
    missing = [
        (tool_name, target_type, target)
        for tool_name, target_type, target in required
        if (tool_name, target) not in covered
    ]

    if not missing:
        if used_rule_fallback:
            note = "containment_quality_gate: rule fallback after ungrounded LLM filter"
            if generated_by is ResponsePlanGeneratedBy.LLM:
                generated_by = ResponsePlanGeneratedBy.TEMPLATE
            strategy = f"{strategy}; {note}" if strategy else note
            return working, generated_by, strategy
        return candidates, generated_by, strategy

    additions = _resolve_missing_containment_candidates(
        missing,
        candidates=working,
        rule_fallback_candidates=rule_fallback_candidates,
    )
    if not additions:
        note = "containment_quality_gate_unsatisfied: incomplete entity coverage"
        if generated_by is ResponsePlanGeneratedBy.LLM:
            generated_by = ResponsePlanGeneratedBy.TEMPLATE
        strategy = f"{strategy}; {note}" if strategy else note
        return working, generated_by, strategy

    merged = _dedupe_candidates([*working, *additions])
    if used_rule_fallback:
        note = "containment_quality_gate: rule fallback and entity coverage merge"
    else:
        note = "containment_quality_gate: entity coverage merge"
    if generated_by is ResponsePlanGeneratedBy.LLM:
        generated_by = ResponsePlanGeneratedBy.TEMPLATE
    strategy = f"{strategy}; {note}" if strategy else note
    return merged, generated_by, strategy


def _severity_rank(severity: Severity) -> int:
    order = {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }
    return order.get(severity, 0)


__all__ = [
    "CONTAINMENT_TOOLS",
    "MAX_ACTION_LEVEL_WHEN_EVIDENCE_INSUFFICIENT",
    "RISK_CONTAINMENT_THRESHOLD",
    "apply_containment_quality_gate",
    "apply_evidence_sufficiency_gate",
    "evidence_blocks_high_impact_actions",
    "evidence_insufficiency_reason_code",
    "has_actionable_containment_targets",
    "required_containment_targets",
    "requires_threat_aligned_containment",
    "resolve_candidate_action_level",
]
