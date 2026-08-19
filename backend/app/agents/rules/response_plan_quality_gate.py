"""Post-PolicyFilter response-plan quality gates.

ISSUE-198: containment alignment — high-confidence investigations must not
silently degrade to ticket-only after PolicyFilter.

ISSUE-248: evidence sufficiency — collection failed / zero-evidence
``evidence_limited`` must not plan L2+ high-impact actions. Evidence gate
takes priority over containment encouragement (orthogonal concerns).

ISSUE-328: containment *coverage* — any single CONTAINMENT_TOOLS item is not
enough. When :func:`requires_threat_aligned_containment` is true, the plan
must cover EntitySet-grounded containable entities by tool type:

- account → ``disable_account``
- host → ``isolate_host``
- external destination IP → ``block_ip`` (ISSUE-339: not RFC1918, not ``src_ip``)

Missing pairs are merged from already-filtered rule fallback when the target
matches, otherwise synthesized from EntitySet **only if that tool was already
admitted** (present on the LLM plan or the filtered fallback pool). Never
expand the asset inventory; never isolate hosts that are not already in
EntitySet; never re-introduce a tool PolicyFilter rejected.

ISSUE-359: identity containment dedup — same account must not stack
``disable_account`` + ``force_logout`` + ``revoke_token``. Collapse to the
highest-priority identity tool per account; never cap ``isolate_host`` count.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar

from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    ResponsePlanGeneratedBy,
    RiskAssessment,
)
from app.models.entities import EntitySet, IPEntity
from app.models.enums import ActionLevel, FinalVerdict, Severity

# Align with response_agent._filter_block_ip_entities (ISSUE-339). Duplicated
# here to avoid a circular import; coverage must not require blocking VPN src.
_BLOCK_IP_SOURCE_FIELDS = frozenset({"src_ip", "source_ip"})

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

# ISSUE-359: identity containment chain — one account should not stack disable +
# force_logout + revoke_token (L4). Priority keeps disable_account; redundant
# siblings on the same account target are dropped after PolicyFilter / coverage merge.
IDENTITY_CONTAINMENT_TOOLS = frozenset(
    {
        "disable_account",
        "force_logout",
        "reset_password",
        "revoke_token",
    }
)

_IDENTITY_CONTAINMENT_PRIORITY: dict[str, int] = {
    "disable_account": 0,
    "force_logout": 1,
    "reset_password": 2,
    "revoke_token": 3,
}

# Align with HIGH severity floor in RiskAgent / intro defaults.
RISK_CONTAINMENT_THRESHOLD = 70

# ISSUE-248: when evidence is insufficient, only L0/L1 may remain in the plan.
MAX_ACTION_LEVEL_WHEN_EVIDENCE_INSUFFICIENT = ActionLevel.L1

_CandidateT = TypeVar("_CandidateT", bound="ActionCandidateLike")


class ActionCandidateLike(Protocol):
    # Read-only property so frozen dataclasses (e.g. ActionCandidate) structurally match.
    @property
    def tool_name(self) -> str: ...


@dataclass(frozen=True)
class EntityCoverageNeed:
    """One EntitySet-grounded containment obligation (ISSUE-328)."""

    tool_name: str
    target_type: str
    canonical_target: str
    aliases: frozenset[str]


def _normalized_token(value: str | None) -> str:
    return str(value or "").strip().lower()


def _candidate_target(item: ActionCandidateLike) -> str:
    return str(getattr(item, "target", "") or "").strip()


def _alias_set(*values: str | None) -> frozenset[str]:
    return frozenset(token for token in (_normalized_token(item) for item in values) if token)


def _block_ip_coverage_entities(entities: EntitySet) -> list[IPEntity]:
    """External exfil/C2 destinations only — same contract as ISSUE-339 rule expansion."""
    covered: list[IPEntity] = []
    for ip in entities.ips:
        if ip.scope != "external":
            continue
        field = _normalized_token(str((ip.attributes or {}).get("normalized_field") or ""))
        if field in _BLOCK_IP_SOURCE_FIELDS:
            continue
        if not (ip.address or ip.entity_id):
            continue
        covered.append(ip)
    return covered


def entity_containment_coverage_needs(entities: EntitySet) -> tuple[EntityCoverageNeed, ...]:
    """ISSUE-328 coverage contract: EntitySet hosts/accounts/external dest IPs only.

    Does **not** scan the asset inventory. A host that is not already in
    ``entities.hosts`` (e.g. bait ``BACKUP-SRV-01``) is never required.
    """
    needs: list[EntityCoverageNeed] = []

    def _add(need: EntityCoverageNeed) -> None:
        if not need.canonical_target.strip() or not need.aliases:
            return
        for index, existing in enumerate(needs):
            if existing.tool_name != need.tool_name:
                continue
            if existing.aliases & need.aliases:
                needs[index] = EntityCoverageNeed(
                    tool_name=existing.tool_name,
                    target_type=existing.target_type,
                    canonical_target=existing.canonical_target,
                    aliases=existing.aliases | need.aliases,
                )
                return
        needs.append(need)

    for account in entities.accounts:
        canonical = (account.username or account.entity_id or "").strip()
        aliases = _alias_set(account.username, account.entity_id)
        if canonical and aliases:
            _add(
                EntityCoverageNeed(
                    tool_name="disable_account",
                    target_type="account",
                    canonical_target=canonical,
                    aliases=aliases,
                )
            )
    for host in entities.hosts:
        canonical = (host.hostname or host.ip or host.entity_id or "").strip()
        aliases = _alias_set(host.hostname, host.ip, host.entity_id)
        if canonical and aliases:
            _add(
                EntityCoverageNeed(
                    tool_name="isolate_host",
                    target_type="host",
                    canonical_target=canonical,
                    aliases=aliases,
                )
            )
    for ip in _block_ip_coverage_entities(entities):
        canonical = (ip.address or ip.entity_id or "").strip()
        aliases = _alias_set(ip.address, ip.entity_id)
        if canonical and aliases:
            _add(
                EntityCoverageNeed(
                    tool_name="block_ip",
                    target_type="ip",
                    canonical_target=canonical,
                    aliases=aliases,
                )
            )
    return tuple(needs)


def _item_covers_need(item: ActionCandidateLike, need: EntityCoverageNeed) -> bool:
    if item.tool_name != need.tool_name:
        return False
    return _normalized_token(_candidate_target(item)) in need.aliases


def _build_coverage_candidate(prototype: _CandidateT, need: EntityCoverageNeed) -> _CandidateT:
    """Construct a candidate of the same type as *prototype* for a missing need."""
    cls = type(prototype)
    reason = "entity coverage merge"
    attempts: tuple[dict[str, object], ...] = (
        {
            "tool_name": need.tool_name,
            "target_type": need.target_type,
            "target": need.canonical_target,
            "parameters": {},
            "reason": reason,
        },
        {"tool_name": need.tool_name, "target": need.canonical_target},
        {"tool_name": need.tool_name},
    )
    for kwargs in attempts:
        try:
            return cls(**kwargs)
        except TypeError:
            continue
    raise TypeError(f"cannot construct coverage candidate for {need.tool_name} from {cls.__name__}")


def _isolate_host_targets(candidates: list[_CandidateT]) -> list[str]:
    """Collect ``isolate_host`` targets from final candidates (stable order, deduped)."""
    seen: set[str] = set()
    targets: list[str] = []
    for item in candidates:
        if item.tool_name != "isolate_host":
            continue
        target = str(getattr(item, "target", "") or "").strip()
        if not target:
            continue
        key = _normalized_token(target)
        if key in seen:
            continue
        seen.add(key)
        targets.append(target)
    return targets


_ONLINE_CLAIM_VERBS = re.compile(
    r"(?i)\b(?:remain(?:s|ing)?|leave|leaving|keep|keeping|stay|stays|still)\b"
)
_ONLINE_WORD = re.compile(r"(?i)\bonline\b")
_CLAUSE_SPLIT = re.compile(r"\s*;\s*|(?<=\.)\s+")
_AND_OR_SPLIT = re.compile(r"\s+(?:and|or)\s+", re.IGNORECASE)


def _host_token_in_text(text: str, host: str) -> bool:
    if not host:
        return False
    return (
        re.search(
            rf"(?i)(?<![A-Za-z0-9_]){re.escape(host)}(?![A-Za-z0-9_])",
            text,
        )
        is not None
    )


def _is_online_claim(clause: str) -> bool:
    return bool(_ONLINE_WORD.search(clause) and _ONLINE_CLAIM_VERBS.search(clause))


def _isolated_host_match_tokens(
    candidates: list[_CandidateT],
    entities: EntitySet,
) -> list[str]:
    """Candidate isolate targets plus EntitySet hostname/IP aliases (ISSUE-357)."""
    tokens = _isolate_host_targets(candidates)
    seen = {_normalized_token(item) for item in tokens}
    isolated = set(seen)
    for need in entity_containment_coverage_needs(entities):
        if need.tool_name != "isolate_host":
            continue
        if not (need.aliases & isolated):
            continue
        for alias in need.aliases:
            if alias not in seen:
                seen.add(alias)
                tokens.append(alias)
        canonical = need.canonical_target.strip()
        key = _normalized_token(canonical)
        if canonical and key not in seen:
            seen.add(key)
            tokens.append(canonical)
    return tokens


def _isolate_host_display_targets(
    candidates: list[_CandidateT],
    entities: EntitySet,
) -> list[str]:
    """Prefer EntitySet canonical hostnames in the approval appendix."""
    display: list[str] = []
    seen: set[str] = set()
    for target in _isolate_host_targets(candidates):
        label = target
        key = _normalized_token(target)
        for need in entity_containment_coverage_needs(entities):
            if need.tool_name != "isolate_host":
                continue
            if key in need.aliases or key == _normalized_token(need.canonical_target):
                label = need.canonical_target
                key = _normalized_token(label)
                break
        if key in seen:
            continue
        seen.add(key)
        display.append(label)
    return display


def _clause_mentions_isolated_host(clause: str, isolated_tokens: list[str]) -> bool:
    return any(_host_token_in_text(clause, token) for token in isolated_tokens if token)


def _strip_online_claims_for_isolated_hosts(
    strategy: str,
    isolated_tokens: list[str],
) -> str:
    """Drop clauses that claim an isolated host remains/leave/keep/stays online."""
    if not strategy or not isolated_tokens:
        return strategy
    kept: list[str] = []
    for clause in _CLAUSE_SPLIT.split(strategy):
        clause = clause.strip(" .;")
        if not clause:
            continue
        fragments = _AND_OR_SPLIT.split(clause) if _ONLINE_WORD.search(clause) else [clause]
        kept_fragments = [
            fragment.strip()
            for fragment in fragments
            if fragment.strip()
            and not (
                _is_online_claim(fragment)
                and _clause_mentions_isolated_host(fragment, isolated_tokens)
            )
        ]
        if kept_fragments:
            kept.append("; ".join(kept_fragments))
    text = "; ".join(kept)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip(" ;")


def _append_isolated_hosts_note(strategy: str, isolated_hosts: list[str]) -> str:
    if not isolated_hosts:
        return strategy
    note = f"isolated hosts: {', '.join(isolated_hosts)}"
    if note in strategy:
        return strategy
    return f"{strategy}; {note}" if strategy else note


def _reconcile_strategy_after_coverage_merge(
    strategy: str,
    candidates: list[_CandidateT],
    *,
    entities: EntitySet,
    force_note: bool = False,
) -> str:
    """Align approval narrative with final ``isolate_host`` targets (ISSUE-357)."""
    isolated_hosts = _isolate_host_display_targets(candidates, entities)
    if not isolated_hosts:
        return strategy
    tokens = _isolated_host_match_tokens(candidates, entities)
    stripped = _strip_online_claims_for_isolated_hosts(strategy, tokens)
    if stripped == strategy and not force_note:
        return strategy
    return _append_isolated_hosts_note(stripped, isolated_hosts)


def _merge_entity_coverage(
    candidates: list[_CandidateT],
    *,
    rule_fallback_candidates: list[_CandidateT],
    entities: EntitySet,
) -> tuple[list[_CandidateT], bool, bool]:
    """Append missing EntitySet coverage; never copy fallback targets outside EntitySet.

    Synthesis is allowed only for tools already admitted by PolicyFilter — present
    on the current plan or on the filtered rule-fallback pool. This keeps
    capability / grounding rejections intact (do not invent ``block_ip`` when
    the manifest disabled it).

    The third return flag is true when at least one EntitySet need stayed
    uncovered because the matching tool was never admitted.
    """
    merged = list(candidates)
    added = False
    incomplete = False
    admitted_tools = {item.tool_name for item in (*candidates, *rule_fallback_candidates)}
    prototype = next(iter(merged or rule_fallback_candidates), None)
    for need in entity_containment_coverage_needs(entities):
        if any(_item_covers_need(item, need) for item in merged):
            continue
        match = next(
            (item for item in rule_fallback_candidates if _item_covers_need(item, need)),
            None,
        )
        if match is not None:
            merged.append(match)
            added = True
            continue
        if need.tool_name not in admitted_tools or prototype is None:
            incomplete = True
            continue
        merged.append(_build_coverage_candidate(prototype, need))
        added = True
    return merged, added, incomplete


def has_actionable_containment_targets(entities: EntitySet) -> bool:
    """Return True when EntitySet exposes at least one containable target.

    Broader than :func:`entity_containment_coverage_needs`: ISSUE-198 still
    encourages grounded containment for domain/file/process-only sets.
    ISSUE-328 coverage merge only fills account / host / external dest IP.
    """
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


_UNCONFIRMED_HIGH_BLAST_TOOLS = frozenset({"isolate_host", "disable_account"})


def demote_unconfirmed_high_blast_actions(
    *,
    candidates: list[_CandidateT],
    generated_by: ResponsePlanGeneratedBy,
    strategy: str,
    final_verdict: FinalVerdict | str | None,
) -> tuple[list[_CandidateT], ResponsePlanGeneratedBy, str]:
    """Drop isolate/disable when the verdict is unconfirmed and containment is not required.

    Default playbooks for ``suspicious_domain`` MEDIUM are ``block_domain`` + ticket.
    The containment *injection* gate already skips ``none`` + MEDIUM + score<70;
    this demotes LLM overreach without injecting rule tools and without flipping
    ``generated_by`` to template.
    """

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
    if verdict not in {FinalVerdict.NONE, FinalVerdict.FALSE_POSITIVE}:
        return candidates, generated_by, strategy
    kept = [item for item in candidates if item.tool_name not in _UNCONFIRMED_HIGH_BLAST_TOOLS]
    if len(kept) == len(candidates):
        return candidates, generated_by, strategy
    note = "unconfirmed_verdict_blast_radius_demote"
    strategy = f"{strategy}; {note}" if strategy else note
    return kept, generated_by, strategy


def deduplicate_identity_containment(
    candidates: list[_CandidateT],
) -> tuple[list[_CandidateT], bool]:
    """Collapse redundant identity tools on the same account target (ISSUE-359).

    Per account, keeps the highest-priority identity tool only:
    ``disable_account`` > ``force_logout`` > ``reset_password`` > ``revoke_token``.
    Does not cap ``isolate_host`` count or total plan size.
    """
    if not candidates:
        return candidates, False

    identity_by_account: dict[str, list[tuple[int, _CandidateT]]] = {}
    for index, item in enumerate(candidates):
        if item.tool_name not in IDENTITY_CONTAINMENT_TOOLS:
            continue
        account = _normalized_token(_candidate_target(item))
        if not account:
            continue
        identity_by_account.setdefault(account, []).append((index, item))

    if not identity_by_account:
        return candidates, False

    drop_indices: set[int] = set()
    for entries in identity_by_account.values():
        if len(entries) <= 1:
            continue
        ranked = sorted(
            entries,
            key=lambda pair: (
                _IDENTITY_CONTAINMENT_PRIORITY.get(pair[1].tool_name, 99),
                pair[0],
            ),
        )
        for index, _ in ranked[1:]:
            drop_indices.add(index)

    if not drop_indices:
        return candidates, False
    return [item for index, item in enumerate(candidates) if index not in drop_indices], True


def apply_identity_containment_dedup_gate(
    *,
    candidates: list[_CandidateT],
    generated_by: ResponsePlanGeneratedBy,
    strategy: str,
    disposition_only: bool,
) -> tuple[list[_CandidateT], ResponsePlanGeneratedBy, str]:
    """Drop redundant identity containment tools on the same account (ISSUE-359)."""
    if disposition_only:
        return candidates, generated_by, strategy
    deduped, removed = deduplicate_identity_containment(candidates)
    if not removed:
        return candidates, generated_by, strategy
    note = "identity_containment_dedup: redundant account identity tools collapsed"
    strategy = f"{strategy}; {note}" if strategy else note
    if generated_by is ResponsePlanGeneratedBy.LLM:
        generated_by = ResponsePlanGeneratedBy.TEMPLATE
    return deduped, generated_by, strategy


def exfil_domain_containment_needs(entities: EntitySet) -> tuple[EntityCoverageNeed, ...]:
    """EntitySet domain → ``block_domain`` obligations (not ISSUE-328).

    ISSUE-328 coverage merge never injects domain tools. This helper only lists
    needs so a separate gate can demote ``generated_by`` when the LLM omitted them.
    """
    needs: list[EntityCoverageNeed] = []
    for domain in entities.domains:
        canonical = (domain.fqdn or domain.entity_id or "").strip()
        aliases = _alias_set(domain.fqdn, domain.entity_id)
        if not canonical or not aliases:
            continue
        needs.append(
            EntityCoverageNeed(
                tool_name="block_domain",
                target_type="domain",
                canonical_target=canonical,
                aliases=aliases,
            )
        )
    return tuple(needs)


def apply_exfil_domain_containment_gate(
    *,
    candidates: list[_CandidateT],
    generated_by: ResponsePlanGeneratedBy,
    strategy: str,
    severity: Severity,
    risk_assessment: RiskAssessment,
    final_verdict: FinalVerdict | str | None,
    entities: EntitySet,
    disposition_only: bool,
    evidence_output: EvidenceOutput | None = None,
) -> tuple[list[_CandidateT], ResponsePlanGeneratedBy, str]:
    """Demote LLM stamp when EntitySet domains lack ``block_domain``; never inject."""
    if disposition_only:
        return candidates, generated_by, strategy
    if not requires_threat_aligned_containment(
        severity=severity,
        risk_assessment=risk_assessment,
        final_verdict=final_verdict,
        entities=entities,
        disposition_only=disposition_only,
        evidence_output=evidence_output,
    ):
        return candidates, generated_by, strategy
    needs = exfil_domain_containment_needs(entities)
    if not needs:
        return candidates, generated_by, strategy
    missing = [
        need
        for need in needs
        if not any(_item_covers_need(item, need) for item in candidates)
    ]
    if not missing:
        return candidates, generated_by, strategy
    note = "domain_containment_missing: EntitySet domains lack block_domain"
    strategy = f"{strategy}; {note}" if strategy else note
    if generated_by is ResponsePlanGeneratedBy.LLM:
        generated_by = ResponsePlanGeneratedBy.TEMPLATE
    return candidates, generated_by, strategy


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
    """Ensure high-confidence plans include grounded containment *and* EntitySet coverage.

    ISSUE-198: ticket-only after PolicyFilter still falls back to rule containment.
    ISSUE-328: a plan that already has *some* containment is still merged until
    every EntitySet account/host/external-dest IP is covered by the matching tool.
    """
    if not requires_threat_aligned_containment(
        severity=severity,
        risk_assessment=risk_assessment,
        final_verdict=final_verdict,
        entities=entities,
        disposition_only=disposition_only,
        evidence_output=evidence_output,
    ):
        return demote_unconfirmed_high_blast_actions(
            candidates=candidates,
            generated_by=generated_by,
            strategy=strategy,
            final_verdict=final_verdict,
        )

    had_containment = bool(_containment_candidates(candidates))
    if not had_containment:
        rule_containment = _containment_candidates(rule_fallback_candidates)
        if rule_containment:
            rule_non_containment = [
                item
                for item in rule_fallback_candidates
                if item.tool_name in _NON_CONTAINMENT_TOOLS
            ]
            rule_tool_names = {item.tool_name for item in rule_fallback_candidates}
            preserved_notify = [
                item
                for item in candidates
                if item.tool_name in _NON_CONTAINMENT_TOOLS
                and item.tool_name not in rule_tool_names
            ]
            candidates = [*rule_containment, *rule_non_containment, *preserved_notify]
            note = "containment_quality_gate: rule fallback after ungrounded LLM filter"
            if generated_by is ResponsePlanGeneratedBy.LLM:
                generated_by = ResponsePlanGeneratedBy.TEMPLATE
            strategy = f"{strategy}; {note}" if strategy else note

    candidates, coverage_added, coverage_incomplete = _merge_entity_coverage(
        candidates,
        rule_fallback_candidates=rule_fallback_candidates,
        entities=entities,
    )
    if coverage_added:
        note = "containment_quality_gate: entity_coverage_merge"
        strategy = f"{strategy}; {note}" if strategy else note
        if not had_containment and generated_by is ResponsePlanGeneratedBy.LLM:
            generated_by = ResponsePlanGeneratedBy.TEMPLATE
    if coverage_incomplete:
        note = "containment_quality_gate: entity_coverage_incomplete"
        strategy = f"{strategy}; {note}" if strategy else note
    strategy = _reconcile_strategy_after_coverage_merge(
        strategy,
        candidates,
        entities=entities,
        force_note=coverage_added,
    )

    if not _containment_candidates(candidates):
        note = "containment_quality_gate_unsatisfied: no grounded containment after PolicyFilter"
        if generated_by is ResponsePlanGeneratedBy.LLM:
            generated_by = ResponsePlanGeneratedBy.TEMPLATE
        strategy = f"{strategy}; {note}" if strategy else note
        return candidates, generated_by, strategy
    return candidates, generated_by, strategy


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
    "IDENTITY_CONTAINMENT_TOOLS",
    "MAX_ACTION_LEVEL_WHEN_EVIDENCE_INSUFFICIENT",
    "RISK_CONTAINMENT_THRESHOLD",
    "EntityCoverageNeed",
    "apply_containment_quality_gate",
    "apply_evidence_sufficiency_gate",
    "apply_exfil_domain_containment_gate",
    "apply_identity_containment_dedup_gate",
    "deduplicate_identity_containment",
    "demote_unconfirmed_high_blast_actions",
    "entity_containment_coverage_needs",
    "exfil_domain_containment_needs",
    "evidence_blocks_high_impact_actions",
    "evidence_insufficiency_reason_code",
    "has_actionable_containment_targets",
    "requires_threat_aligned_containment",
    "resolve_candidate_action_level",
]
