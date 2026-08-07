"""Post-PolicyFilter containment alignment gate (ISSUE-198).

When investigation confidence is high but LLM candidates lose grounding during
PolicyFilter, plans must not silently degrade to ticket-only while claiming
LLM success.
"""

from __future__ import annotations

from typing import Protocol, TypeVar

from app.models.agent_io import ResponsePlanGeneratedBy, RiskAssessment
from app.models.entities import EntitySet
from app.models.enums import FinalVerdict, Severity

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

_CandidateT = TypeVar("_CandidateT", bound="ActionCandidateLike")


class ActionCandidateLike(Protocol):
    tool_name: str


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


def _containment_candidates(candidates: list[_CandidateT]) -> list[_CandidateT]:
    return [item for item in candidates if item.tool_name in CONTAINMENT_TOOLS]


def requires_threat_aligned_containment(
    *,
    severity: Severity,
    risk_assessment: RiskAssessment,
    final_verdict: FinalVerdict | str | None,
    entities: EntitySet,
    disposition_only: bool,
) -> bool:
    """High-confidence investigations with known entities need grounded containment."""
    if disposition_only:
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
) -> tuple[list[_CandidateT], ResponsePlanGeneratedBy, str]:
    """Ensure high-confidence plans include grounded containment or rule fallback."""
    if not requires_threat_aligned_containment(
        severity=severity,
        risk_assessment=risk_assessment,
        final_verdict=final_verdict,
        entities=entities,
        disposition_only=disposition_only,
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
    "RISK_CONTAINMENT_THRESHOLD",
    "apply_containment_quality_gate",
    "has_actionable_containment_targets",
    "requires_threat_aligned_containment",
]
