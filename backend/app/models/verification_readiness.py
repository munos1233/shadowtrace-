"""Verification readiness predicates shared by VerifyAgent and disposition services."""

from __future__ import annotations

from app.models.agent_io import (
    EffectStatus,
    VerificationActionResult,
    VerificationResult,
)

# IMMEDIATE actions still executing / awaiting execution — must not pass as
# effect-ready (ISSUE-216 / BLK-002). Deferred activation SKIPPED is excluded.
IMMEDIATE_PENDING_SKIP_DETAILS = frozenset(
    {
        "pending_execution",
        "approved_pending_execution",
        "action_not_executed",
    }
)


def has_immediate_effect_pending(
    verification: VerificationResult | None,
    *,
    results: list[VerificationActionResult] | None = None,
) -> bool:
    rows = results if results is not None else (verification.results if verification else [])
    return any(
        item.effect_status is EffectStatus.SKIPPED and item.detail in IMMEDIATE_PENDING_SKIP_DETAILS
        for item in rows
    )


def applicable_effect_results(
    verification: VerificationResult | None,
) -> list[VerificationActionResult]:
    if verification is None:
        return []
    return [
        item
        for item in verification.results
        if not (
            item.effect_status is EffectStatus.SKIPPED
            and item.detail == "deferred_pending_activation"
        )
    ]


def has_unverified_applicable_effects(
    verification: VerificationResult | None,
) -> bool:
    """True when any applicable effect is not VERIFIED (ISSUE-232).

    ``deferred_pending_activation`` SKIPPED rows are excluded via
    :func:`applicable_effect_results`; other SKIPPED details such as
    ``non_verifiable_action`` remain applicable and block terminal auto-resolution.
    """
    applicable = applicable_effect_results(verification)
    if not applicable:
        return False
    return not all(item.effect_status is EffectStatus.VERIFIED for item in applicable)


__all__ = [
    "IMMEDIATE_PENDING_SKIP_DETAILS",
    "applicable_effect_results",
    "has_immediate_effect_pending",
    "has_unverified_applicable_effects",
]
