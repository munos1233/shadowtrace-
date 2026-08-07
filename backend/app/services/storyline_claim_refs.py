"""Storyline claim ref builder (ISSUE-116 Phase B / #621, ISSUE-244)."""

from __future__ import annotations

from app.models.agent_io import (
    AttackStoryline,
    StorylineClaimRef,
    StorylineGroundingStatus,
)


def build_storyline_claim_refs(storyline: AttackStoryline) -> list[StorylineClaimRef]:
    """Build stable claim refs from evidence-cited timeline entries only."""
    refs: list[StorylineClaimRef] = []
    ordinal = 0
    for phase in storyline.phases:
        for entry in phase.entries:
            if not entry.evidence_id:
                continue
            refs.append(
                StorylineClaimRef(
                    claim_id=f"claim-{storyline.event_id}-{ordinal}",
                    proposition_kind="timeline_entry",
                    evidence_ids=[entry.evidence_id],
                    ordinal=ordinal,
                )
            )
            ordinal += 1
    return refs


def resolve_storyline_grounding_status(
    storyline: AttackStoryline,
    *,
    claim_refs: list[StorylineClaimRef] | None = None,
) -> StorylineGroundingStatus:
    """Evidence-grounded only when phases exist and at least one claim binds evidence.

    Thin / empty storylines (``phases=[]`` or timeline entries without
    ``evidence_id``) must not advertise ``evidence_grounded`` (ISSUE-244).
    """
    refs = claim_refs if claim_refs is not None else build_storyline_claim_refs(storyline)
    if storyline.phases and refs:
        return StorylineGroundingStatus.EVIDENCE_GROUNDED
    return StorylineGroundingStatus.UNGROUNDED


def attach_storyline_claim_refs(
    storyline: AttackStoryline,
    *,
    grounding_status: StorylineGroundingStatus,
) -> AttackStoryline:
    claim_refs = build_storyline_claim_refs(storyline)
    status = grounding_status
    # Defence-in-depth: never allow evidence_grounded without bindable claims.
    if status is StorylineGroundingStatus.EVIDENCE_GROUNDED and (
        not storyline.phases or not claim_refs
    ):
        status = StorylineGroundingStatus.UNGROUNDED
    return storyline.model_copy(
        update={
            "schema_version": "2.0",
            "claim_refs": claim_refs,
            "grounding_status": status,
        }
    )


__all__ = [
    "attach_storyline_claim_refs",
    "build_storyline_claim_refs",
    "resolve_storyline_grounding_status",
]
