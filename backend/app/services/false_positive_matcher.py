"""FalsePositiveMatcher: vector-based false-positive pre-filter (ISSUE-078).

Matches alert snapshots against the ``fp_case_kb`` knowledge base to produce
a recommendation (close_as_fp / investigate_with_flag / no_match) that is
written to ``EventContext.false_positive_match`` via a pre-triage hook.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.agents.rules.entity_extraction_rules import extract_entities_regex
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.workflow import FP_HIGH_THRESHOLD, FP_LOW_THRESHOLD
from app.services.case_kb_service import CaseKBService
from app.services.working_memory import BoundWorkingMemory

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# FPMatchResult
# --------------------------------------------------------------------------- #


class FPMatchResult(BaseModel):
    """Result of matching an alert snapshot against the false-positive case KB.

    Fields match the ISSUE-078 unified naming:
    - ``matched``: True when max_score >= FP_LOW_THRESHOLD
    - ``recommendation``: close_as_fp / investigate_with_flag / no_match
    """

    model_config = ConfigDict(extra="forbid")

    matched: bool
    max_score: float
    matched_case_id: str | None = None
    matched_pattern: str | None = None
    recommendation: str = Field(..., description="close_as_fp | investigate_with_flag | no_match")


# --------------------------------------------------------------------------- #
# FalsePositiveMatcher
# --------------------------------------------------------------------------- #


class FalsePositiveMatcher:
    """Vector-based false-positive matcher using the fp_case_kb.

    Builds a rich alert text from the source_snapshot + entities, searches
    the fp_case_kb via :class:`CaseKBService`, and returns an
    :class:`FPMatchResult` with a recommendation based on the top-1 score.

    Degradation strategy: when the KB is unavailable or empty, returns
    ``no_match`` so the investigation proceeds normally with zero impact.
    """

    def __init__(self, case_kb_service: CaseKBService) -> None:
        self._case_kb = case_kb_service

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def match(
        self,
        source_snapshot: dict[str, Any],
        entities: EntitySet,
    ) -> FPMatchResult:
        """Match *source_snapshot* + *entities* against the fp_case_kb.

        Args:
            source_snapshot: Frozen normalized XDR source snapshot (file
                fallback uses the compatible ``raw_alert_snapshot`` field).
            entities: Entity set for text enrichment (regex-extracted for
                the pre-triage hook path; LLM-extracted for post-triage).

        Returns:
            FPMatchResult with recommendation based on top-1 score vs
            FP_HIGH_THRESHOLD / FP_LOW_THRESHOLD.
        """
        alert_text = _build_alert_text(source_snapshot, entities)

        try:
            results = await self._case_kb.search_fp_cases(alert_text, top_k=1)
        except Exception:
            logger.warning(
                "FalsePositiveMatcher: fp_case_kb search failed; returning no_match",
                exc_info=True,
            )
            return _no_match()

        if not results:
            return _no_match()

        top = results[0]
        score = float(top.score)
        recommendation = _recommendation_for(score)

        return FPMatchResult(
            matched=score >= FP_LOW_THRESHOLD,
            max_score=score,
            matched_case_id=(top.metadata.get("case_id") if recommendation != "no_match" else None),
            matched_pattern=(
                top.metadata.get("pattern_summary") if recommendation != "no_match" else None
            ),
            recommendation=recommendation,
        )


# --------------------------------------------------------------------------- #
# FalsePositiveMatcherHook — pre-triage hook for TriageAgent
# --------------------------------------------------------------------------- #


class FalsePositiveMatcherHook:
    """Pre-triage hook that runs the :class:`FalsePositiveMatcher` and writes
    the result to ``EventContext.false_positive_match``.

    Uses its own ``BoundWorkingMemory`` bound to the ``FalsePositiveMatcher``
    writer identity (same as ``RuleBasedFalsePositiveHook`` via WRITER_ALIASES).
    Does NOT change EventStatus, call set_final_verdict, or write reports —
    those actions are owned by the orchestration layer.

    Degradation: when the KB is unavailable the hook writes nothing and the
    investigation proceeds normally (零影响).
    """

    def __init__(
        self,
        matcher: FalsePositiveMatcher,
        working_memory: BoundWorkingMemory,
    ) -> None:
        self._matcher = matcher
        self._wm = working_memory

    async def __call__(
        self,
        agent: Any,  # BaseAgent[TriageAgentInput, TriageResult]
        input: Any,  # TriageAgentInput
    ) -> None:
        wm = self._wm
        if wm is None:
            return

        # Read source_snapshot through the agent's own memory (read is not
        # ownership-gated — any bound identity can read any field).
        agent_wm = getattr(agent, "working_memory", None)
        if agent_wm is None:
            return

        snapshot = await agent_wm.read(input.event_id, "source_snapshot")
        if not isinstance(snapshot, dict):
            return

        # Build alert text and extract entities via regex for enrichment.
        alert_text = _build_alert_text(snapshot, EntitySet())
        entities = _regex_entity_set(alert_text)

        result = await self._matcher.match(snapshot, entities)

        fp_match: dict[str, Any] = {
            "matched": result.matched,
            "max_score": result.max_score,
            "matched_case_id": result.matched_case_id,
            "matched_pattern": result.matched_pattern,
            "recommendation": result.recommendation,
            "source": "FalsePositiveMatcher",
            "matched_at": datetime.now(UTC).isoformat(),
        }

        await wm.write(input.event_id, "false_positive_match", fp_match)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _build_alert_text(source_snapshot: dict[str, Any], entities: EntitySet) -> str:
    """Build a searchable alert text from snapshot + entities for vector retrieval.

    Combines alert_type, title, description, scenario, signature, and entity
    features into a single pipe-delimited string.
    """
    parts: list[str] = []

    # Alert type / event type.
    alert_type = source_snapshot.get("alert_type", "")
    if alert_type:
        parts.append(f"alert_type={alert_type}")

    # Title / subject.
    title = source_snapshot.get("title") or source_snapshot.get("subject", "")
    if title:
        parts.append(str(title))

    # Description.
    description = source_snapshot.get("description", "")
    if description:
        parts.append(str(description))

    # Scenario (fixture identifier).
    scenario = source_snapshot.get("scenario", "")
    if scenario:
        parts.append(f"scenario={scenario}")

    # Signature.
    signature = source_snapshot.get("signature", "")
    if signature:
        parts.append(f"signature={signature}")

    # Severity from snapshot.
    severity = source_snapshot.get("severity", "")
    if severity:
        parts.append(f"severity={severity}")

    # Entity features from EntitySet.
    entity_parts = _entity_features(entities)
    if entity_parts:
        parts.append(entity_parts)

    # File fallback: raw_alert_snapshot fields.
    raw_snap = source_snapshot.get("raw_alert_snapshot")
    if isinstance(raw_snap, dict):
        raw_title = raw_snap.get("title", "")
        if raw_title:
            parts.append(str(raw_title))
        raw_desc = raw_snap.get("description", "")
        if raw_desc and raw_desc != description:
            parts.append(str(raw_desc))

    return " | ".join(parts) if parts else str(source_snapshot)


def _entity_features(entities: EntitySet) -> str:
    """Render entity features as a compact string for text matching."""
    features: list[str] = []

    for acct in entities.accounts:
        label = acct.username or acct.display_name or acct.entity_id
        features.append(f"account={label}")

    for host in entities.hosts:
        label = host.hostname or host.ip or host.entity_id
        features.append(f"host={label}")

    for ip in entities.ips:
        addr = ip.address or ip.entity_id
        scope = ip.scope if ip.scope != "unknown" else ""
        features.append(f"ip={addr}" + (f" scope={scope}" if scope else ""))

    for dom in entities.domains:
        label = dom.fqdn or dom.entity_id
        features.append(f"domain={label}")

    for proc in entities.processes:
        label = proc.name or proc.entity_id
        features.append(f"process={label}")

    for file in entities.files:
        label = file.name or file.path or file.entity_id
        features.append(f"file={label}")

    return "; ".join(features) if features else ""


def _regex_entity_set(alert_text: str) -> EntitySet:
    """Run regex extraction on *alert_text* and return an ``EntitySet``.

    Used by the pre-triage hook to enrich the matcher query without depending
    on the LLM extraction path.
    """
    raw = extract_entities_regex(alert_text)
    return EntitySet(
        accounts=[
            AccountEntity(
                entity_id=f"re-acct-{i}",
                entity_type="account",
                username=a,
            )
            for i, a in enumerate(raw.accounts, 1)
        ],
        hosts=[
            HostEntity(
                entity_id=f"re-host-{i}",
                entity_type="host",
                hostname=h,
            )
            for i, h in enumerate(raw.hostnames, 1)
        ],
        ips=[
            IPEntity(
                entity_id=f"re-ip-{i}",
                entity_type="ip",
                address=ip,
                scope="internal",
            )
            for i, ip in enumerate(raw.ips, 1)
        ],
        domains=[
            DomainEntity(
                entity_id=f"re-dom-{i}",
                entity_type="domain",
                fqdn=d,
            )
            for i, d in enumerate(raw.domains, 1)
        ],
        processes=[
            ProcessEntity(
                entity_id=f"re-proc-{i}",
                entity_type="process",
                name=p,
            )
            for i, p in enumerate(raw.processes, 1)
        ],
        files=[
            FileEntity(
                entity_id=f"re-file-{i}",
                entity_type="file",
                name=f,
            )
            for i, f in enumerate(raw.files, 1)
        ],
    )


def _recommendation_for(score: float) -> str:
    """Map a similarity score to a recommendation string."""
    if score >= FP_HIGH_THRESHOLD:
        return "close_as_fp"
    if score >= FP_LOW_THRESHOLD:
        return "investigate_with_flag"
    return "no_match"


def _no_match() -> FPMatchResult:
    """Return a no-match result (degradation or empty KB)."""
    return FPMatchResult(
        matched=False,
        max_score=0.0,
        recommendation="no_match",
    )


__all__ = [
    "FPMatchResult",
    "FalsePositiveMatcher",
    "FalsePositiveMatcherHook",
]
