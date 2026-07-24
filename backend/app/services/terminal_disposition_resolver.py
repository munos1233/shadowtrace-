"""Map investigation outcomes to terminal SourceDisposition (ISSUE-059A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.models.agent_io import EffectStatus, VerificationOverallStatus, VerificationResult
from app.models.enums import (
    DispositionPolicy,
    FinalVerdict,
    SourceDisposition,
    WritebackReadiness,
)

SkippedReason = Literal[
    "terminal_not_in_approved_set",
    "capability_blocked",
]


@dataclass(frozen=True, slots=True)
class TerminalDispositionResolveResult:
    """Resolver output before activation CAS."""

    disposition: SourceDisposition | None = None
    skipped_reason: SkippedReason | None = None
    need_manual_resolution: bool = False


class TerminalDispositionResolver:
    """Read-only mapping from verdict + effect verification to terminal disposition."""

    def resolve(
        self,
        *,
        final_verdict: FinalVerdict,
        verification: VerificationResult | None,
        approved_terminal_dispositions: list[SourceDisposition],
        disposition_only: bool,
        disposition_policy: DispositionPolicy,
        writeback_readiness: WritebackReadiness,
        event_disposition_supported: bool = True,
    ) -> TerminalDispositionResolveResult:
        if disposition_policy is DispositionPolicy.NOT_REQUIRED:
            return TerminalDispositionResolveResult()

        if not event_disposition_supported or writeback_readiness in {
            WritebackReadiness.CAPABILITY_UNSUPPORTED,
            WritebackReadiness.CAPABILITY_UNKNOWN,
            WritebackReadiness.NOT_CONFIGURED,
        }:
            return TerminalDispositionResolveResult(skipped_reason="capability_blocked")

        approved_set = set(approved_terminal_dispositions)
        if disposition_only:
            if final_verdict is not FinalVerdict.FALSE_POSITIVE:
                return TerminalDispositionResolveResult(need_manual_resolution=True)
            target = SourceDisposition.IGNORED
            if target not in approved_set:
                return TerminalDispositionResolveResult(
                    skipped_reason="terminal_not_in_approved_set",
                )
            return TerminalDispositionResolveResult(disposition=target)

        if final_verdict is FinalVerdict.FALSE_POSITIVE:
            target = SourceDisposition.IGNORED
        elif final_verdict is FinalVerdict.CONFIRMED_THREAT:
            target = self._threat_terminal(verification=verification, approved_set=approved_set)
            if target is None:
                return TerminalDispositionResolveResult(need_manual_resolution=True)
        else:
            return TerminalDispositionResolveResult(need_manual_resolution=True)

        if target not in approved_set:
            return TerminalDispositionResolveResult(skipped_reason="terminal_not_in_approved_set")
        return TerminalDispositionResolveResult(disposition=target)

    @staticmethod
    def _threat_terminal(
        *,
        verification: VerificationResult | None,
        approved_set: set[SourceDisposition],
    ) -> SourceDisposition | None:
        if verification is None:
            return None
        if verification.need_action_replan or verification.need_manual_resolution:
            return None
        if verification.overall_status is VerificationOverallStatus.FAILED:
            return None
        if verification.overall_status is VerificationOverallStatus.PARTIAL:
            if SourceDisposition.SUSPENDED in approved_set:
                return SourceDisposition.SUSPENDED
            return None
        if verification.overall_status is not VerificationOverallStatus.SUCCESS:
            return None

        applicable = [
            item
            for item in verification.results
            if not (
                item.effect_status is EffectStatus.SKIPPED
                and item.detail == "deferred_pending_activation"
            )
        ]
        if any(item.effect_status is EffectStatus.FAILED for item in applicable):
            if SourceDisposition.SUSPENDED in approved_set:
                return SourceDisposition.SUSPENDED
            return None
        if applicable and not all(
            item.effect_status is EffectStatus.VERIFIED for item in applicable
        ):
            if SourceDisposition.SUSPENDED in approved_set:
                return SourceDisposition.SUSPENDED
            return None

        if SourceDisposition.CONTAINED in approved_set:
            return SourceDisposition.CONTAINED
        if SourceDisposition.COMPLETED in approved_set:
            return SourceDisposition.COMPLETED
        return None


__all__ = [
    "SkippedReason",
    "TerminalDispositionResolveResult",
    "TerminalDispositionResolver",
]
