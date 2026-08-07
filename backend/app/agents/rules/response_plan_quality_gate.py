"""Post-PolicyFilter response-plan quality gates.

ISSUE-198: containment alignment — high-confidence investigations must not
silently degrade to ticket-only after PolicyFilter.

ISSUE-248: evidence sufficiency — collection failed / zero-evidence
``evidence_limited`` must not plan L2+ high-impact actions. Evidence gate
takes priority over containment encouragement (orthogonal concerns).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeVar

from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ResponsePlanGeneratedBy,
    RiskAssessment,
)
from app.models.entities import EntitySet
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

    reason = evidence_insufficiency_reason_code(
        evidence_output=evidence_output,
        risk_assessment=risk_assessment,
    ) or "evidence_insufficient"
    note = f"evidence_sufficiency_gate: high_impact_blocked:{reason}"
    if removed or note not in strategy:
        strategy = f"{strategy}; {note}" if strategy else note
    if removed and generated_by is ResponsePlanGeneratedBy.LLM:
        generated_by = ResponsePlanGeneratedBy.TEMPLATE
    return kept, generated_by, strategy


def _containment_candidates(candidates: list[_CandidateT]) -> list[_CandidateT]:
    return [item for item in candidates if item.tool_name in CONTAINMENT_TOOLS]


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
    """Ensure high-confidence plans include grounded containment or rule fallback."""
    if not requires_threat_aligned_containment(
        severity=severity,
        risk_assessment=risk_assessment,
        final_verdict=final_verdict,
        entities=entities,
        disposition_only=disposition_only,
        evidence_output=evidence_output,
    ):
        return candidates, generated_by, strategy

    if _containment_candidates(candidates):
        return candidates, generated_by, strategy

    rule_containment = _containment_candidates(rule_fallback_candidates)
    if not rule_containment:
        note = "containment_quality_gate_unsatisfied: no grounded containment after PolicyFilter"
        if generated_by is ResponsePlanGeneratedBy.LLM:
            generated_by = ResponsePlanGeneratedBy.TEMPLATE
        strategy = f"{strategy}; {note}" if strategy else note
        return candidates, generated_by, strategy

    rule_non_containment = [
        item for item in rule_fallback_candidates if item.tool_name in _NON_CONTAINMENT_TOOLS
    ]
    rule_tool_names = {item.tool_name for item in rule_fallback_candidates}
    preserved_notify = [
        item
        for item in candidates
        if item.tool_name in _NON_CONTAINMENT_TOOLS and item.tool_name not in rule_tool_names
    ]
    merged = [*rule_containment, *rule_non_containment, *preserved_notify]

    note = "containment_quality_gate: rule fallback after ungrounded LLM filter"
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
    "requires_threat_aligned_containment",
    "resolve_candidate_action_level",
]
