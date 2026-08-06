"""VerifyAgent — two-phase disposition effect verification (ISSUE-060).

Phase 1 (effect): independently observe every IMMEDIATE response/rollback
Action that entered an execution state. POST_VERIFY deferred Actions are
skipped with ``detail=deferred_pending_activation`` and must never appear
in ``failed_actions``.

Phase 2 (disposition): when phase 1 produces no ``need_action_replan`` or
``need_manual_resolution`` and ``disposition_policy=required``, activate
the deferred terminal writeback via ``EventDispositionService``, then
evaluate every required writeback receipt for CONFIRMED.

Routing flags (``need_action_replan`` / ``need_writeback_recovery`` /
``need_manual_resolution``) are orthogonal — only effect failures trigger
action replan; writeback problems stay in the writeback/recovery path.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select, update
from sqlalchemy.exc import InternalError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.base import BaseAgent
from app.agents.rules.verification_mapping import (
    VERIFICATION_MAPPING,
    resolve_verification_tool,
    validate_verification_tool_params,
)
from app.db import models as orm
from app.models.action import Action
from app.models.agent_io import (
    EffectStatus,
    VerificationActionResult,
    VerificationOverallStatus,
    VerificationPhase,
    VerificationResult,
    VerifyAgentInput,
)
from app.models.disposition import SourceObjectLocator
from app.models.enums import (
    ActionCategory,
    ActionExecutionPhase,
    ActionLevel,
    ActionStatus,
    ConfirmationEvidence,
    DispositionPolicy,
    ExecutionJobStatus,
    ExecutionOwner,
    WritebackReadiness,
    WritebackStatus,
)
from app.models.execution import ActionExecutionJob
from app.models.tool_meta import ToolResult, ToolResultStatus
from app.models.verification_readiness import has_immediate_effect_pending
from app.services.event_disposition_service import DispositionActivationResult
from app.services.working_memory import BoundWorkingMemory

logger = logging.getLogger(__name__)

# ── Writeback status → phase‑2 routing table (ISSUE-060 acceptance step 5) ──
# Returns (confirmed: bool, need_recovery: bool, need_manual: bool, detail_suffix)
_WRITEBACK_STATUS_ROUTING: dict[WritebackStatus, tuple[bool, bool, bool, str]] = {
    WritebackStatus.CONFIRMED: (True, False, False, "writeback_confirmed"),
    WritebackStatus.PENDING: (False, True, False, "writeback_pending_waiting"),
    WritebackStatus.SENDING: (False, True, False, "writeback_sending_waiting"),
    WritebackStatus.ACCEPTED: (False, True, False, "writeback_accepted_waiting"),
    # UNKNOWN → recovery (not manual). Per ISSUE-060 spec §4.5:
    # "UNKNOWN→先查证、无法查证时 need_manual_resolution=true".
    # WritebackRecoveryHandler (ISSUE-062) implements the provider-side
    # lookup and retry loop: it first queries the provider for the actual
    # writeback status (up to VERIFY_UNKNOWN_MAX_LOOKUPS attempts), then
    # retries the writeback if the status is recoverable (up to
    # WRITEBACK_MAX_RETRIES).  When provider-side lookup is infeasible or
    # the retry budget is exhausted, WritebackRecoveryHandler escalates to
    # need_manual_resolution=True so the writeback enters the
    # operator-facing resolution path.  The recovery flag here correctly
    # signals "don't give up yet" — the handler owns the timeout guard.
    WritebackStatus.UNKNOWN: (False, True, False, "writeback_unknown_requires_lookup"),
    # PARTIAL writebacks are routed to recovery by default.
    # WritebackRecoveryHandler (ISSUE-062) handles these with the same
    # query/retry guard: it retries sub-targets that are still recoverable
    # and escalates permanently-failed sub-targets (e.g. permission errors
    # that retries cannot fix) to need_manual_resolution=True, avoiding
    # duplicate side effects from unbounded retry loops.
    WritebackStatus.PARTIAL: (False, True, False, "writeback_partial_recovery"),
    WritebackStatus.FAILED: (False, True, False, "writeback_failed_recovery"),
    WritebackStatus.CONFLICT: (False, False, True, "writeback_conflict_manual"),
    # None key intentionally omitted — callers must handle wb_status is None
    # explicitly before consulting this table.  See _evaluate_writeback_statuses
    # for the explicit None check.
}

# Defensive check: when a new WritebackStatus value is added to the enum
# but this routing table is not updated, the .get() fallback silently
# routes the unknown value to recovery.  This assertion fails fast at
# import time so the developer is forced to make an explicit routing
# decision for the new enum member.
# (ISSUE-060 review Nit-1)
_WRITEBACK_STATUS_ROUTING_COVERS_ALL = set(_WRITEBACK_STATUS_ROUTING.keys())
_WRITEBACK_STATUS_ENUM_VALUES = set(WritebackStatus)
assert _WRITEBACK_STATUS_ROUTING_COVERS_ALL == _WRITEBACK_STATUS_ENUM_VALUES, (
    f"_WRITEBACK_STATUS_ROUTING is out of sync with WritebackStatus enum. "
    f"Missing: {_WRITEBACK_STATUS_ENUM_VALUES - _WRITEBACK_STATUS_ROUTING_COVERS_ALL}. "
    f"Extra: {_WRITEBACK_STATUS_ROUTING_COVERS_ALL - _WRITEBACK_STATUS_ENUM_VALUES}."
)


# Maximum number of UNKNOWN writeback lookup attempts before escalating
# to manual resolution.  When a required writeback status is UNKNOWN,
# _evaluate_writeback_statuses consults the ``attempt`` field on the
# action's DispositionOutbox records to determine how many times the
# writeback has been queried.  After VERIFY_UNKNOWN_MAX_LOOKUPS attempts
# without a conclusive status, the writeback is escalated to
# need_manual=True with detail "writeback_unknown_exhausted_lookups_manual".
#
# Per ISSUE-060 spec §4.5: "UNKNOWN→先查证、无法查证时 need_manual=true".
# Before this constant was introduced, UNKNOWN was hardcoded to
# need_recovery=True, need_manual=False with no path to manual escalation,
# which would trap the event in an infinite recovery loop if the Provider
# never returned a conclusive writeback status.
VERIFY_UNKNOWN_MAX_LOOKUPS: int = 3

# Exception types that indicate transient infrastructure failures rather
# than permanent logic errors.  Used by _finalize_verification_action to
# distinguish retry-eligible failures from zombie-creating ones.
_TRANSIENT_EXC_TYPES = (
    ConnectionError,
    TimeoutError,
    OperationalError,  # deadlocks, server gone away
    InternalError,  # serialization failures
)

# Error codes for exception type classification in verification detail
# strings.  Using stable codes rather than bare exception type names gives
# downstream consumers (dashboards, alerting) a reliable discriminator even
# when the exception hierarchy changes (e.g. a subclass of RuntimeError is
# introduced).  Codes are short (<16 chars) and deliberately non-descriptive
# — downstream consumers must not depend on the code's meaning beyond
# "different code = different failure class" (ISSUE-060 Nit SF-6).
_EXC_ERROR_CODES: dict[type[BaseException], str] = {
    ConnectionError: "ERR_T_CONN",
    TimeoutError: "ERR_T_TIMEOUT",
    ValueError: "ERR_T_VALUE",
    TypeError: "ERR_T_TYPE",
    KeyError: "ERR_T_KEY",
    LookupError: "ERR_T_LOOKUP",
    OSError: "ERR_T_OS",
    RuntimeError: "ERR_T_RUNTIME",
    AssertionError: "ERR_T_ASSERT",
    asyncio.CancelledError: "ERR_T_CANCEL",
}


def _error_code_for_exception(exc: BaseException) -> str:
    """Return a stable error code for *exc*, falling back to
    ``"ERR_T_UNKNOWN"`` when no specific mapping is registered."""
    for exc_type, code in _EXC_ERROR_CODES.items():
        if isinstance(exc, exc_type):
            return code
    return "ERR_T_UNKNOWN"


# Tools whose observable entity effect is not verifiable via tool observation.
# Derived dynamically from VERIFICATION_MAPPING so the two stay in sync —
# a tool is "non-verifiable" when every target_type mapping in the baseline
# resolves to None.
def _derive_skip_verification_tools() -> frozenset[str]:
    return frozenset(
        tool_name
        for tool_name, targets in VERIFICATION_MAPPING.items()
        if targets and all(v is None for v in targets.values())
    )


_EXECUTED_STATUSES: frozenset[ActionStatus] = frozenset(
    {
        ActionStatus.SUCCESS,
        ActionStatus.PARTIAL_SUCCESS,
        ActionStatus.FAILED,
    }
)

# Maximum duration in seconds an Action may remain in EXECUTING status
# before it is treated as a zombie and escalated to manual resolution.
# When the Action's execution job started_at exceeds this threshold,
# the effect_status is set to UNVERIFIABLE with detail "execution_timeout"
# and need_manual=True.  Within the threshold, the Action is skipped with
# detail "pending_execution" so the caller can wait for it to complete.
_EXECUTING_TIMEOUT_SECONDS: int = 300

_VERIFY_OPERATOR = "VerifyAgent"


# ── EventDispositionService protocol (ISSUE-059A) ──
# Not yet implemented; the agent accepts an optional callable matching this
# signature. When absent, phase 2 marks need_manual_resolution=true.


class _ActivateResult:
    """Result envelope matching EventDispositionService.DispositionActivationResult.

    Mirrors the canonical ``DispositionActivationResult`` from
    ``app.services.event_disposition_service`` so the VerifyAgent stays
    decoupled from the service module at import time.  The Protocol below
    enforces structural compatibility with the real service.
    """

    def __init__(
        self,
        *,
        activated: bool,
        action_id: str | None = None,
        skipped_reason: str | None = None,
        derived_disposition: Any | None = None,
        disposition_id: str | None = None,
        writeback_id: str | None = None,
    ) -> None:
        self.activated = activated
        self.action_id = action_id
        self.skipped_reason = skipped_reason
        self.derived_disposition = derived_disposition
        self.disposition_id = disposition_id
        self.writeback_id = writeback_id


# Import-time contract assertion: _ActivateResult must expose the same
# field names as the canonical DispositionActivationResult from
# EventDispositionService (ISSUE-059A).  If DispositionActivationResult
# adds a required field or renames an existing one, this assertion fails
# at import time rather than surfacing as a silent AttributeError at
# runtime inside the phase-2 except-Exception handler (ISSUE-060 SF-2).
_EXPECTED_EDS_FIELDS = {
    "action_id",
    "activated",
    "skipped_reason",
    "derived_disposition",
    "disposition_id",
    "writeback_id",
}
_ACTUAL_EDS_FIELDS = set(DispositionActivationResult.model_fields)
assert _EXPECTED_EDS_FIELDS.issubset(_ACTUAL_EDS_FIELDS), (
    f"DispositionActivationResult field contract changed — "
    f"_ActivateResult in verify_agent.py needs updating. "
    f"Missing expected fields: {_EXPECTED_EDS_FIELDS - _ACTUAL_EDS_FIELDS}"
)
# Reverse check: DispositionActivationResult must not have unexpected
# required fields that _ActivateResult doesn't cover (extra fields
# with defaults are safe — they won't cause AttributeError).
_EDS_REQUIRED = {
    name for name, field in DispositionActivationResult.model_fields.items() if field.is_required()
}
_UNCOVERED_REQUIRED = _EDS_REQUIRED - _EXPECTED_EDS_FIELDS
assert not _UNCOVERED_REQUIRED, (
    f"DispositionActivationResult has new required fields not covered "
    f"by _ActivateResult: {_UNCOVERED_REQUIRED}"
)


class _EventDispositionServiceProtocol(Protocol):
    """Structural interface for EventDispositionService (ISSUE-059A).

    Signature matches the real ``EventDispositionService.activate_and_submit``
    (ISSUE-059A) so that injection of the concrete service satisfies the
    Protocol without adapters.  Using Protocol instead of ``Any`` lets mypy
    catch mismatched injection objects at import/type-check time rather than
    at runtime inside the except-Exception handler.
    """

    async def activate_and_submit(
        self, *, event_id: str, plan_revision: int, principal_or_system: str
    ) -> _ActivateResult: ...


# --------------------------------------------------------------------------- #
# VerifyAgent
# --------------------------------------------------------------------------- #


class VerifyAgent(BaseAgent[VerifyAgentInput, VerificationResult]):
    """Two-phase verification of response actions and disposition writebacks."""

    agent_name = "verify_agent"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        tool_executor: Any | None = None,
        working_memory: BoundWorkingMemory | None = None,
        budget_service: Any | None = None,
        output_guard: Any | None = None,
        trace_service: Any | None = None,
        audit_service: Any | None = None,
        event_bus: Any | None = None,
        # VerifyAgent‑specific dependencies
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        event_disposition_service: _EventDispositionServiceProtocol | None = None,
        disposition_sync_service: Any | None = None,
        provider_manifest_overrides: dict[str, dict[str, str]] | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            tool_executor=tool_executor,
            working_memory=working_memory,
            budget_service=budget_service,
            output_guard=output_guard,
            trace_service=trace_service,
            audit_service=audit_service,
            event_bus=event_bus,
        )
        self._session_factory: async_sessionmaker[AsyncSession] | None = session_factory
        self._event_disposition_service: _EventDispositionServiceProtocol | None = (
            event_disposition_service
        )
        self._disposition_sync_service: Any | None = disposition_sync_service
        self._provider_manifest_overrides: dict[str, dict[str, str]] | None = (
            provider_manifest_overrides
        )

    # ------------------------------------------------------------------ #
    # _run
    # ------------------------------------------------------------------ #

    async def _run(self, input: VerifyAgentInput) -> VerificationResult:
        event_id = input.event_id
        response_plan = input.response_plan

        # 1. Load actions & execution context from the database.
        disposition_policy = await self._load_disposition_policy(event_id)
        actions, jobs_map, outbox_map = await self._load_execution_state(event_id, response_plan)

        # 2. Phase 1 — entity effect verification for IMMEDIATE actions.
        (
            phase1_results,
            phase1_failed,
            phase1_need_replan,
            phase1_need_manual,
        ) = await self._verify_phase1_effects(
            event_id=event_id,
            actions=actions,
            jobs_map=jobs_map,
        )

        # EventDispositionService.after_effect_resolution_ready reads
        # verification_result from EventContext.  Persist phase-1 outcome
        # before phase-2 activation so the first verify pass can activate
        # deferred terminal writeback (ISSUE-059A × ISSUE-060).
        if (
            not phase1_need_replan
            and not phase1_need_manual
            and disposition_policy == DispositionPolicy.REQUIRED
        ):
            await self._persist_phase1_for_eds_gate(
                event_id=event_id,
                phase1_results=phase1_results,
                phase1_failed=phase1_failed,
            )

        # Denormalize phase-1 effect outcomes onto Action rows so SOC stats /
        # rollback_service can read effect_verification_status without digging
        # into EventContext (ISSUE-085 Should-Fix).
        await self._persist_effect_verification_statuses(phase1_results)

        # 3. Phase 2 — terminal writeback activation & verification.
        (
            phase2_results,
            phase2_failed_wb,
            phase2_blocked_wb,
            overall_status,
            need_wb_recovery,
            need_manual,
        ) = await self._verify_phase2_disposition(
            event_id=event_id,
            disposition_policy=disposition_policy,
            phase1_need_replan=phase1_need_replan,
            phase1_need_manual=phase1_need_manual,
            actions=actions,
            jobs_map=jobs_map,
            outbox_map=outbox_map,
        )

        # 4. Assemble final result.
        all_results = phase1_results + phase2_results
        failed_actions = list(phase1_failed)
        failed_writebacks = list(phase2_failed_wb)
        blocked_writebacks = list(phase2_blocked_wb)

        need_action_replan = phase1_need_replan
        need_writeback_recovery = need_wb_recovery
        need_manual_resolution = phase1_need_manual or need_manual

        # ── Systemic tool unavailability check (PR#7 Blocker #2) ──────────
        # When ALL Phase 1 actions are UNVERIFIABLE with zero FAILED, the
        # verification tooling is systemically unavailable (e.g. Provider
        # completely down, tool_executor=None, every check_* call returned
        # None).  Per ISSUE-060 degradation spec this must produce
        # overall_status=FAILED — not MANUAL_RESOLUTION — so that
        # route_after_verify triggers an alert rather than quietly queuing
        # for manual triage.
        all_phase1_unverifiable = (
            len(phase1_results) > 0
            and all(r.effect_status == EffectStatus.UNVERIFIABLE for r in phase1_results)
            and len(phase1_failed) == 0
        )
        if all_phase1_unverifiable:
            # Per line ~548, every UNVERIFIABLE result sets need_manual=True,
            # so phase1_need_manual is guaranteed True here.  The assertion
            # guards against a future refactor that changes UNVERIFIABLE's
            # routing without updating this block.
            assert phase1_need_manual, (
                "Invariant violated: all Phase 1 results are UNVERIFIABLE "
                "but phase1_need_manual is False — UNVERIFIABLE routing must "
                "set need_manual"
            )
            overall_status = VerificationOverallStatus.FAILED
            # need_manual_resolution stays True per spec (escalated=true).

        # None of the routing flags may be set when overall_status=success.
        if overall_status == VerificationOverallStatus.SUCCESS:
            need_action_replan = False
            need_writeback_recovery = False
            need_manual_resolution = False
        elif overall_status == VerificationOverallStatus.PARTIAL:
            # Partial may still need replan on the failed subset.
            need_action_replan = phase1_need_replan
        elif overall_status == VerificationOverallStatus.WAITING:
            need_action_replan = False
        elif overall_status == VerificationOverallStatus.MANUAL_RESOLUTION:
            need_action_replan = False
            need_manual_resolution = True

        result = VerificationResult(
            results=all_results,
            overall_status=overall_status,
            failed_actions=failed_actions,
            failed_writebacks=failed_writebacks,
            blocked_writebacks=blocked_writebacks,
            need_action_replan=need_action_replan,
            need_writeback_recovery=need_writeback_recovery,
            need_manual_resolution=need_manual_resolution,
            verification_phase=input.verification_phase,
        )

        # 5. Persist verification result to working memory.
        await self._write_verification_result(event_id, result)

        # Phase-1 effect statuses were already denormalized above. Do NOT
        # re-persist all_results: phase-2 disposition rows reuse
        # effect_status=VERIFIED for writeback receipt confirmation and
        # would overwrite the orthogonal effect_verification_status column
        # (ISSUE-085 Blocker).

        # 6. Publish action_verified events.
        await self._publish_action_verified_events(event_id, result)

        return result

    # ------------------------------------------------------------------ #
    # Phase 1 — effect verification
    # ------------------------------------------------------------------ #

    async def _verify_phase1_effects(
        self,
        *,
        event_id: str,
        actions: list[Action],
        jobs_map: dict[str, ActionExecutionJob],
    ) -> tuple[
        list[VerificationActionResult],
        set[str],
        bool,
        bool,
    ]:
        """Verify IMMEDIATE entity effects. Returns (results, failed_ids, replan, manual)."""
        results: list[VerificationActionResult] = []
        failed_action_ids: set[str] = set()
        need_replan = False
        need_manual = False

        for action in actions:
            # POST_VERIFY deferred → skipped, never in failed_actions.
            if action.execution_phase == ActionExecutionPhase.POST_VERIFY:
                results.append(
                    _make_skipped_result(
                        action,
                        detail="deferred_pending_activation",
                    )
                )
                continue

            # Actions without execution phase = IMMEDIATE implicitly.
            # Still executing → check for zombie timeout before skipping.
            # EXECUTING may mean: (a) in progress → wait; (b) stuck/zombie → escalate.
            if action.status == ActionStatus.EXECUTING:
                job = jobs_map.get(action.action_id)
                timeout_s = _EXECUTING_TIMEOUT_SECONDS
                now_utc = datetime.now(UTC)
                if (
                    job is not None
                    and job.started_at is not None
                    and (now_utc - job.started_at).total_seconds() > timeout_s
                ):
                    # Zombie Action — stuck in EXECUTING past the timeout.
                    # The execution job may have completed but the Action
                    # status was never CAS-synced (or the runner crashed).
                    logger.warning(
                        "Action %s stuck in EXECUTING for >%ss (started_at=%s) "
                        "event=%s — escalating to manual resolution",
                        action.action_id,
                        timeout_s,
                        job.started_at.isoformat(),
                        event_id,
                    )
                    results.append(
                        VerificationActionResult(
                            action_id=action.action_id,
                            effect_status=EffectStatus.UNVERIFIABLE,
                            writeback_required=action.writeback_required,
                            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                            writeback_status=action.writeback_status,
                            writeback_ids=[],
                            detail="execution_timeout",
                            verification_phase=VerificationPhase.EFFECT,
                        )
                    )
                    need_manual = True
                    continue
                # Within timeout or no job metadata → skip, wait for completion.
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=action.writeback_required,
                        writeback_readiness=action.writeback_readiness,
                        writeback_status=action.writeback_status,
                        writeback_ids=[],
                        detail="pending_execution",
                        verification_phase=VerificationPhase.EFFECT,
                    )
                )
                continue

            # UNKNOWN execution status → direct to manual resolution.
            # The Action was submitted but its execution result cannot be
            # confirmed.  Running a verification tool on an UNKNOWN action
            # risks producing a false-positive is_verified that masks the
            # fact that we don't know whether the action actually executed.
            if action.status == ActionStatus.UNKNOWN:
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.UNVERIFIABLE,
                        writeback_required=action.writeback_required,
                        writeback_readiness=action.writeback_readiness,
                        writeback_status=action.writeback_status,
                        writeback_ids=[],
                        detail="action_execution_unknown",
                        verification_phase=VerificationPhase.EFFECT,
                    )
                )
                need_manual = True
                continue

            # WAITING_APPROVAL / APPROVED — the action has been approved
            # but not yet executed.  Distinguish from PENDING (not yet
            # submitted) with a more precise detail message.
            if action.status in (ActionStatus.WAITING_APPROVAL, ActionStatus.APPROVED):
                detail = (
                    "approved_pending_execution"
                    if action.writeback_required
                    else "action_not_executed"
                )
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=action.writeback_required,
                        writeback_readiness=action.writeback_readiness,
                        writeback_status=action.writeback_status,
                        writeback_ids=[],
                        detail=detail,
                        verification_phase=VerificationPhase.EFFECT,
                    )
                )
                continue

            # Not executed yet → skip (not an error).
            if action.status not in _EXECUTED_STATUSES:
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=action.writeback_required,
                        writeback_readiness=action.writeback_readiness,
                        writeback_status=None,
                        writeback_ids=[],
                        detail="action_not_executed",
                        verification_phase=VerificationPhase.EFFECT,
                    )
                )
                continue

            # Verification/system actions are self-verifying.
            if action.action_category in (
                ActionCategory.VERIFICATION,
                ActionCategory.SYSTEM,
            ):
                results.append(_make_self_verifying_result(action))
                continue

            # Determine the verification tool.
            verify_tool = resolve_verification_tool(
                action.tool_name,
                action.target_type,
                provider_manifest_overrides=self._provider_manifest_overrides,
            )

            # No verification tool registered → treat as non-verifiable (skipped).
            if verify_tool is None:
                # Determine skip reason via _derive_skip_verification_tools
                # so the inline logic stays in sync with the derived set
                # that the test suite independently validates.
                is_non_verifiable = action.tool_name in _derive_skip_verification_tools()
                detail = (
                    "non_verifiable_action"
                    if is_non_verifiable
                    else "no_verification_tool_registered"
                )
                results.append(_make_skipped_result(action, detail=detail))
                continue

            # Execute the verification tool (independent observation).
            job = jobs_map.get(action.action_id)
            result = await self._run_verification_tool(
                event_id=event_id,
                action=action,
                verify_tool=verify_tool,
                job=job,
            )
            results.append(result)

            # Classify effect status for routing.
            if result.effect_status == EffectStatus.VERIFIED:
                continue
            elif result.effect_status == EffectStatus.UNVERIFIABLE:
                need_manual = True
            elif result.effect_status == EffectStatus.FAILED:
                failed_action_ids.add(action.action_id)
                need_replan = True
            # SKIPPED does not trigger replan/failed.

        return results, failed_action_ids, need_replan, need_manual

    async def _run_verification_tool(
        self,
        *,
        event_id: str,
        action: Action,
        verify_tool: str,
        job: ActionExecutionJob | None,
    ) -> VerificationActionResult:
        """Run one verification tool observation and classify the result."""
        verification_action_id: str | None = None
        verification_action: Action | None = None
        detail: str = "verification_pending"
        verification_action_dirty: bool = False

        try:
            # Persist a verification Action.
            verification_action = await self._create_verification_action(
                event_id=event_id,
                source_action=action,
                verify_tool=verify_tool,
            )
            verification_action_id = verification_action.action_id

            params: dict[str, Any] = {
                "target_type": action.target_type or "",
                "target": action.target or "",
                "event_id": event_id,
            }
            if job is not None:
                params["parameters"] = {"job_id": job.job_id}

            # Validate that params match the verification tool's contract.
            # Missing required params are caught early with a clear diagnostic
            # rather than surfacing as an opaque Provider-side error.
            missing_params = validate_verification_tool_params(verify_tool, params)
            if missing_params:
                logger.warning(
                    "Verification tool %s (action=%s) missing expected params: %s",
                    verify_tool,
                    action.action_id,
                    missing_params,
                )

            tool_result: ToolResult | None = None
            if self.tool_executor is not None:
                tool_result = await self.tool_executor.call(
                    tool_name=verify_tool,
                    params=params,
                    event_id=event_id,
                )

            if tool_result is None:
                logger.warning(
                    "Verification tool %s unavailable for action %s (tool_executor=%s) event=%s",
                    verify_tool,
                    action.action_id,
                    "available" if self.tool_executor is not None else "None",
                    event_id,
                )
                effect_status = EffectStatus.UNVERIFIABLE
                detail = "verification_tool_unavailable_degraded"
                await self._finalize_verification_action(
                    verification_action,
                    target_status=ActionStatus.UNKNOWN,
                )
            elif tool_result.status == ToolResultStatus.SUCCESS:
                data = tool_result.data or {}
                if "is_verified" not in data:
                    # Provider returned SUCCESS but didn't include the
                    # is_verified key — the observation is inconclusive,
                    # not failed.  Treating it as FAILED would trigger
                    # a spurious re-plan that wastes agent budget.
                    effect_status = EffectStatus.UNVERIFIABLE
                    detail = "verification_result_missing_is_verified_field"
                elif data["is_verified"]:
                    effect_status = EffectStatus.VERIFIED
                    detail = "effect_verified"
                else:
                    effect_status = EffectStatus.FAILED
                    detail = data.get("detail", "effect_not_observed")
                await self._finalize_verification_action(
                    verification_action,
                    target_status=ActionStatus.SUCCESS,
                )
            elif tool_result.status == ToolResultStatus.FAILED:
                effect_status = EffectStatus.UNVERIFIABLE
                detail = f"verification_tool_error: {tool_result.error_detail or 'unknown'}"
                await self._finalize_verification_action(
                    verification_action,
                    target_status=ActionStatus.FAILED,
                )
            else:
                # ToolResultStatus values other than SUCCESS/FAILED
                # (e.g. DEGRADED, TIMEOUT, or future additions) are
                # all treated as UNVERIFIABLE — the observation did not
                # produce a conclusive result, so we escalate to manual
                # rather than guessing.
                effect_status = EffectStatus.UNVERIFIABLE
                detail = f"verification_tool_status_{tool_result.status.value}"
                await self._finalize_verification_action(
                    verification_action,
                    target_status=ActionStatus.UNKNOWN,
                )
        except Exception as exc:
            logger.warning(
                "Verification tool %s failed for action %s: %s",
                verify_tool,
                action.action_id,
                exc,
            )
            effect_status = EffectStatus.UNVERIFIABLE
            # Sanitise: expose a stable error code rather than the full
            # exception type name or message (which may contain IPs, paths,
            # or provider internals).  Error codes allow downstream consumers
            # to distinguish failure classes without depending on Python
            # exception hierarchy details.  The full traceback is logged
            # above for debugging (ISSUE-060 Nit SF-6).
            detail = f"verification_exception: {_error_code_for_exception(exc)}"
            try:
                if verification_action is not None:
                    await self._finalize_verification_action(
                        verification_action,
                        target_status=ActionStatus.FAILED,
                    )
            except Exception:
                # The verification Action may be left in EXECUTING status
                # (stuck as a zombie) because _finalize_verification_action
                # itself failed.  Set the structured flag so downstream
                # consumers can distinguish "correctly finalized" from
                # "state unknown" without parsing the detail string.
                # (ISSUE-060 review Nit-2)
                verification_action_dirty = True
                logger.warning(
                    "Failed to finalize verification action %s during exception"
                    " handling for source action %s",
                    verification_action_id or "N/A",
                    action.action_id,
                    exc_info=True,
                )

        # Build writeback fields for this action.
        wb_required = action.writeback_required
        wb_readiness = action.writeback_readiness
        wb_status = action.writeback_status

        if effect_status == EffectStatus.UNVERIFIABLE:
            # writeback_required preserves the business obligation — it must
            # never be reversed by technical unavailability (§4.5 item 6).
            # The model validator on VerificationActionResult permits
            # writeback_required=True + writeback_readiness=NOT_REQUIRED
            # + writeback_status=… when effect_status=UNVERIFIABLE.
            #
            # Preserve the original writeback_status — UNVERIFIABLE means
            # we couldn't observe the entity effect, not that the writeback
            # status changed.  Losing PENDING/SENDING/CONFIRMED state here
            # would silently break downstream writeback recovery paths.
            wb_readiness = WritebackReadiness.NOT_REQUIRED
            wb_status = action.writeback_status

        return VerificationActionResult(
            action_id=action.action_id,
            effect_status=effect_status,
            writeback_required=wb_required,
            writeback_readiness=wb_readiness,
            writeback_status=wb_status,
            writeback_ids=[],
            verification_action_id=verification_action_id,
            detail=detail,
            verification_phase=VerificationPhase.EFFECT,
            verification_action_dirty=verification_action_dirty,
        )

    # ------------------------------------------------------------------ #
    # Phase 2 — writeback activation & verification
    # ------------------------------------------------------------------ #

    async def _verify_phase2_disposition(
        self,
        *,
        event_id: str,
        disposition_policy: DispositionPolicy | None,
        phase1_need_replan: bool,
        phase1_need_manual: bool,
        actions: list[Action],
        jobs_map: dict[str, ActionExecutionJob],
        outbox_map: dict[str, list[Any]],
    ) -> tuple[
        list[VerificationActionResult],
        set[str],
        set[str],
        VerificationOverallStatus,
        bool,  # need_writeback_recovery
        bool,  # need_manual_resolution
    ]:
        """Phase 2: activate deferred terminal writeback, then verify receipts.

        ``EventDispositionService.activate_and_submit`` (ISSUE-059A) enqueues
        the terminal ``EVENT_STATUS_UPDATE`` outbox and returns immediately;
        DispositionSyncService delivers the command and persists receipts
        asynchronously.  This method reads the latest receipt and routes
        non-CONFIRMED or missing receipts to ``need_writeback_recovery``
        (overall ``waiting``), never to overall success.
        """
        results: list[VerificationActionResult] = []
        failed_wb: set[str] = set()
        blocked_wb: set[str] = set()
        need_wb_recovery = False
        need_manual = False
        overall_status = VerificationOverallStatus.SUCCESS

        # If phase 1 already requires replan or manual, skip activation.
        if phase1_need_replan or phase1_need_manual:
            logger.info(
                "Phase 2 skipped: phase1 need_replan=%s need_manual=%s event=%s",
                phase1_need_replan,
                phase1_need_manual,
                event_id,
            )
            if phase1_need_replan and phase1_need_manual:
                # Both effect FAILED (replan) and UNVERIFIABLE (manual)
                # conditions exist — FAILED captures the higher severity
                # while both routing flags remain independently set for
                # the caller to act on.
                overall_status = VerificationOverallStatus.FAILED
            elif phase1_need_replan:
                overall_status = VerificationOverallStatus.PARTIAL
            elif phase1_need_manual:
                overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

        # If disposition is not required, no writeback to verify.
        if disposition_policy == DispositionPolicy.NOT_REQUIRED:
            logger.info("Phase 2 skipped: disposition_policy=not_required event=%s", event_id)
            return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

        # disposition_policy is None → unknown; the event's disposition
        # requirement cannot be determined.  Escalate to manual resolution
        # rather than silently returning SUCCESS when a policy may exist.
        if disposition_policy is None:
            logger.warning(
                "disposition_policy unknown for event=%s, requiring manual resolution",
                event_id,
            )
            need_manual = True
            overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

        # disposition_policy is REQUIRED (NOT_REQUIRED and None are
        # already handled above):
        # Attempt to activate deferred terminal writeback.
        terminal_activated = False
        terminal_verify_ready = False
        activate_result: _ActivateResult | None = None
        if self._event_disposition_service is not None:
            # Derive plan_revision from the response plan's actions.
            # All actions in a single ResponsePlan share the same revision.
            # Use direct indexing instead of a truthiness loop — int(0) is
            # a valid revision but is falsy in Python, so `if a.plan_revision:`
            # would silently skip it (ISSUE-060 review B2).
            #
            # When actions is empty, fall back to loading the current plan
            # revision from the database rather than defaulting to 1.
            # A default of 1 is wrong when the real plan_revision is 0 —
            # EventDispositionService.activate_and_submit would target the
            # wrong revision, potentially activating deferred Actions from
            # a different revision or returning not_required for a revision
            # that has no deferred Actions (ISSUE-060 review SF-1).
            _plan_revision: int | None = actions[0].plan_revision if actions else None
            if _plan_revision is None:
                _plan_revision = await self._load_event_plan_revision(event_id)
            try:
                activate_result = await self._event_disposition_service.activate_and_submit(
                    event_id=event_id,
                    plan_revision=_plan_revision,
                    principal_or_system=_VERIFY_OPERATOR,
                )
                terminal_activated = activate_result.activated
                # Idempotent re-verify: a prior pass already enqueued the
                # terminal outbox — evaluate the existing receipt instead of
                # treating already_submitted as a hard activation failure.
                terminal_verify_ready = terminal_activated or (
                    not terminal_activated
                    and activate_result.skipped_reason == "already_submitted"
                    and activate_result.writeback_id is not None
                )
                if not terminal_verify_ready:
                    logger.warning(
                        "Phase 2 activation skipped: %s event=%s",
                        activate_result.skipped_reason,
                        event_id,
                    )
                    need_manual = True
                    # Use the deferred action_id (not a synthetic wb-id) so
                    # downstream resolve/retry endpoints can match the path
                    # parameter.  The synthetic f"terminal_wb_{event_id}"
                    # does not conform to the wbk-{8hex} format and would
                    # always fail lookup.  (ISSUE-060 review SF-3)
                    _blocked_ref = activate_result.action_id or activate_result.writeback_id
                    if _blocked_ref is not None:
                        blocked_wb.add(_blocked_ref)
                    overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
                elif (
                    not terminal_activated and activate_result.skipped_reason == "already_submitted"
                ):
                    logger.info(
                        "Phase 2 activation idempotent: already_submitted wb=%s event=%s",
                        activate_result.writeback_id,
                        event_id,
                    )
            except Exception as exc:
                logger.error(
                    "Phase 2 activation exception event=%s: %s",
                    event_id,
                    exc,
                )
                need_manual = True
                overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
        else:
            # No EventDispositionService available → manual resolution.
            logger.warning(
                "Phase 2 activation unavailable: no EventDispositionService event=%s",
                event_id,
            )
            need_manual = True
            overall_status = VerificationOverallStatus.MANUAL_RESOLUTION

        # Evaluate writeback statuses for all applicable required actions.
        # Run when activation succeeded or when a prior pass already
        # enqueued the terminal outbox (already_submitted).  Other activation
        # failures stay on MANUAL_RESOLUTION — evaluating stale receipts
        # there would produce misleading routing decisions.
        if terminal_verify_ready:
            assert activate_result is not None
            wb_eval = await self._evaluate_writeback_statuses(
                event_id=event_id,
                actions=actions,
                outbox_map=outbox_map,
            )
            results = wb_eval["results"]
            failed_wb = wb_eval["failed_wb"]
            blocked_wb = wb_eval["blocked_wb"]
            need_wb_recovery = wb_eval["need_recovery"]
            need_manual_from_wb = wb_eval["need_manual"]

            # Verify the terminal disposition writeback receipt that
            # activate_and_submit just enqueued.  Receipts may not exist yet
            # (outbox not delivered) or may be non-CONFIRMED — both route to
            # need_writeback_recovery rather than overall success.
            terminal_wb_eval = await self._evaluate_terminal_writeback_status(
                event_id=event_id,
                activate_result=activate_result,
            )
            if terminal_wb_eval["need_manual"]:
                need_manual_from_wb = need_manual_from_wb or terminal_wb_eval["need_manual"]
                blocked_wb.update(terminal_wb_eval["blocked_wb"])
            if terminal_wb_eval["need_recovery"]:
                need_wb_recovery = need_wb_recovery or terminal_wb_eval["need_recovery"]
                failed_wb.update(terminal_wb_eval["failed_wb"])

            # Evaluate writeback recovery first (lower priority), then
            # manual resolution (higher priority).  When both the main
            # writeback evaluation and the terminal writeback evaluation
            # flag issues, MANUAL_RESOLUTION must win over WAITING for
            # permanent failures (CONFLICT, exhausted UNKNOWN); missing or
            # in-flight receipts stay on the recovery/waiting path.
            if need_wb_recovery:
                if overall_status == VerificationOverallStatus.SUCCESS:
                    overall_status = VerificationOverallStatus.WAITING
            if need_manual_from_wb:
                need_manual = True
                if overall_status in (
                    VerificationOverallStatus.SUCCESS,
                    VerificationOverallStatus.WAITING,
                ):
                    overall_status = VerificationOverallStatus.MANUAL_RESOLUTION
            if failed_wb:
                if overall_status not in (
                    VerificationOverallStatus.MANUAL_RESOLUTION,
                    VerificationOverallStatus.FAILED,
                ):
                    overall_status = VerificationOverallStatus.PARTIAL

        return results, failed_wb, blocked_wb, overall_status, need_wb_recovery, need_manual

    async def _evaluate_writeback_statuses(
        self,
        *,
        event_id: str,
        actions: list[Action],
        outbox_map: dict[str, list[Any]],
    ) -> dict[str, Any]:
        """Evaluate writeback status for every applicable required action."""
        results: list[VerificationActionResult] = []
        failed_wb: set[str] = set()
        blocked_wb: set[str] = set()
        need_recovery = False
        need_manual = False

        for action in actions:
            if action.action_category not in (
                ActionCategory.RESPONSE,
                ActionCategory.ROLLBACK,
            ):
                continue
            if not action.writeback_required:
                continue
            if action.superseded_by_revision is not None:
                continue
            if action.status == ActionStatus.REJECTED:
                continue
            # POST_VERIFY deferred actions are handled by phase 2 activation,
            # not by direct writeback status evaluation.
            if action.execution_phase == ActionExecutionPhase.POST_VERIFY:
                continue

            wb_readiness = action.writeback_readiness
            wb_ids = await self._collect_writeback_ids(event_id, action, outbox_map)
            wb_status, evidence_raw = await self._resolve_effective_writeback_status(
                action=action,
                wb_ids=wb_ids,
            )

            if not action.writeback_applicable:
                # Obligation exists at the event level but doesn't land on
                # this specific action.  writeback_required expresses the
                # event-level business obligation and MUST NOT be rewritten
                # by writeback_applicable (§4.5 item 6).  The SKIPPED
                # effect_status is permitted by the VerificationActionResult
                # validator regardless of writeback_required; the CLOSED gate
                # separately checks the event-level obligation.
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=action.writeback_required,
                        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
                        writeback_status=None,
                        writeback_ids=wb_ids,
                        detail="writeback_not_applicable",
                        verification_phase=VerificationPhase.DISPOSITION,
                    )
                )
                continue

            # Required but not READY → blocked.
            if wb_readiness != WritebackReadiness.READY:
                blocked_wb.add(action.action_id)
                need_manual = True
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.SKIPPED,
                        writeback_required=True,
                        writeback_readiness=wb_readiness,
                        writeback_status=None,
                        writeback_ids=wb_ids,
                        detail=f"writeback_blocked_{wb_readiness.value}",
                        verification_phase=VerificationPhase.DISPOSITION,
                    )
                )
                continue

            # READY — evaluate the eight WritebackStatus values.
            if wb_status is None:
                # No writeback status recorded yet.  Distinguish two cases:
                # (a) No outbox record exists → the DispositionSyncService
                #     hasn't created the outbound command yet.  Route to
                #     recovery so the caller waits for the next DSS cycle
                #     to pick it up naturally, but use a distinct detail
                #     suffix so downstream consumers can tell this apart
                #     from "command created but not yet terminal."
                # (b) Outbox record(s) exist but no receipt → the command
                #     was dispatched but no status update has arrived yet.
                #     Route to recovery with the existing
                #     "writeback_no_status_waiting" detail.
                ob_records = outbox_map.get(action.action_id, [])
                if ob_records:
                    confirmed, rec, man, detail_suffix = (
                        False,
                        True,
                        False,
                        "writeback_no_status_waiting",
                    )
                else:
                    confirmed, rec, man, detail_suffix = (
                        False,
                        True,
                        False,
                        "writeback_not_yet_dispatched",
                    )
            elif wb_status == WritebackStatus.UNKNOWN:
                # UNKNOWN → need_recovery (not manual) on first lookup.
                # After VERIFY_UNKNOWN_MAX_LOOKUPS attempts without a
                # conclusive status, escalate to need_manual=True so the
                # event doesn't get trapped in an infinite recovery loop.
                # Lookup count is derived from the max ``attempt`` field
                # across the action's DispositionOutbox records — each
                # delivery attempt increments the counter, and each
                # recovery cycle triggers at least one delivery attempt.
                max_attempt = 0
                ob_records = outbox_map.get(action.action_id, [])
                for ob in ob_records:
                    ob_attempt = getattr(ob, "attempt", 0) or 0
                    if ob_attempt > max_attempt:
                        max_attempt = ob_attempt
                if max_attempt >= VERIFY_UNKNOWN_MAX_LOOKUPS:
                    confirmed, rec, man, detail_suffix = (
                        False,
                        False,
                        True,
                        "writeback_unknown_exhausted_lookups_manual",
                    )
                else:
                    confirmed, rec, man, detail_suffix = (
                        False,
                        True,
                        False,
                        "writeback_unknown_requires_lookup",
                    )
            else:
                routing = _WRITEBACK_STATUS_ROUTING.get(
                    wb_status,
                    (False, True, False, "writeback_status_unknown"),
                )
                confirmed, rec, man, detail_suffix = routing

            confirmed, rec, man, detail_suffix, evidence_tier = (
                self._adjust_routing_for_weak_evidence(
                    confirmed=confirmed,
                    rec=rec,
                    man=man,
                    detail_suffix=detail_suffix,
                    evidence_raw=evidence_raw,
                )
            )

            if confirmed:
                # Phase 2 writeback receipt confirmed — effect_status=VERIFIED
                # here means "writeback receipt confirmed", NOT "entity effect
                # verified" (phase 1).  Downstream consumers that route on
                # effect_status alone must also check the `detail` field
                # ("writeback_confirmed" vs "effect_verified") or the
                # verification_phase marker on the parent VerificationResult.
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.VERIFIED,
                        writeback_required=True,
                        writeback_readiness=wb_readiness,
                        writeback_status=wb_status,
                        writeback_ids=wb_ids,
                        detail=detail_suffix,
                        verification_phase=VerificationPhase.DISPOSITION,
                        confirmation_evidence=evidence_tier,
                    )
                )
            elif man:
                need_manual = True
                blocked_wb.add(action.action_id)
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.UNVERIFIABLE,
                        writeback_required=True,
                        writeback_readiness=wb_readiness,
                        writeback_status=wb_status,
                        writeback_ids=wb_ids,
                        detail=detail_suffix,
                        verification_phase=VerificationPhase.DISPOSITION,
                        confirmation_evidence=evidence_tier,
                    )
                )
            else:
                # Recovery path: PENDING / SENDING / ACCEPTED / PARTIAL / FAILED
                need_recovery = True
                if wb_status in (WritebackStatus.FAILED, WritebackStatus.PARTIAL):
                    failed_wb.add(action.action_id)
                results.append(
                    VerificationActionResult(
                        action_id=action.action_id,
                        effect_status=EffectStatus.VERIFIED,
                        writeback_required=True,
                        writeback_readiness=wb_readiness,
                        writeback_status=wb_status,
                        writeback_ids=wb_ids,
                        detail=detail_suffix,
                        verification_phase=VerificationPhase.DISPOSITION,
                        confirmation_evidence=evidence_tier,
                    )
                )

        return {
            "results": results,
            "failed_wb": failed_wb,
            "blocked_wb": blocked_wb,
            "need_recovery": need_recovery,
            "need_manual": need_manual,
        }

    # ------------------------------------------------------------------ #
    # Data loading
    # ------------------------------------------------------------------ #

    async def _load_execution_state(
        self,
        event_id: str,
        response_plan: Any,
    ) -> tuple[
        list[Action],
        dict[str, ActionExecutionJob],
        dict[str, list[Any]],
    ]:
        """Load Actions, Jobs, and Outbox records from the database."""
        if self._session_factory is None:
            actions = _plan_actions(response_plan)
            # Build minimal jobs_map from Action.execution_job_id so that
            # _run_verification_tool receives the job_id context even
            # without DB access.  Missing job metadata (provider_name,
            # status) degrades gracefully — the observation tool can still
            # use the job_id to scope its independent observation.
            jobs_map: dict[str, ActionExecutionJob] = {}
            for a in actions:
                if a.execution_job_id:
                    jobs_map[a.action_id] = ActionExecutionJob(
                        job_id=a.execution_job_id,
                        event_id=a.event_id or event_id,
                        action_id=a.action_id,
                        provider_name=getattr(a, "provider_name", None) or "",
                        idempotency_key=getattr(a, "idempotency_key", None)
                        or f"idem-{a.action_id}",
                        status=ExecutionJobStatus.UNKNOWN,
                    )
            return actions, jobs_map, {}

        async with self._session_factory() as session:
            # Load persisted Actions for this event's current plan revision.
            # Baseline from plan — DB rows patch on top so that actions
            # present in the plan but not yet persisted are NOT silently
            # dropped (PR#7 Blocker #1: partial DB hit → dropped actions).
            plan_actions_list = _plan_actions(response_plan)
            if not plan_actions_list:
                actions = []
            else:
                plan_actions_map = {a.action_id: a for a in plan_actions_list}
                action_ids = list(plan_actions_map)
                rows = (
                    await session.scalars(
                        select(orm.Action).where(orm.Action.action_id.in_(action_ids))
                    )
                ).all()
                db_actions = {r.action_id: _action_from_row(r) for r in rows}
                missing = set(plan_actions_map) - set(db_actions)
                if missing:
                    logger.warning(
                        "Actions in plan but not in DB for event=%s: %s",
                        event_id,
                        missing,
                    )
                # DB-persisted state takes priority over plan defaults for
                # non-null fields.  Merge preserves plan order — downstream
                # consumers may rely on results[0] being the first planned action.
                #
                # State fields (status, writeback_status, execution_owner, …)
                # come from the DB row when present.  The sole exception is
                # ``writeback_status``: NULL on the row means "not yet
                # denormalized from DispositionReceipt", not "no writeback".
                # In that case ``_merge_db_action_with_plan`` overlays the
                # plan snapshot when it carries a concrete status (ISSUE-564).
                # Actions present in the plan but missing from the DB keep
                # their plan-level defaults; a warning is logged for each gap.
                actions = []
                for aid in plan_actions_map:
                    if aid in db_actions:
                        actions.append(
                            _merge_db_action_with_plan(
                                db_actions[aid],
                                plan_actions_map[aid],
                            )
                        )
                    else:
                        actions.append(plan_actions_map[aid])

            # Load jobs.
            job_ids = [a.execution_job_id for a in actions if a.execution_job_id]
            jobs_map = {}
            if job_ids:
                job_rows = (
                    await session.scalars(
                        select(orm.ActionExecutionJob).where(
                            orm.ActionExecutionJob.job_id.in_(job_ids)
                        )
                    )
                ).all()
                jobs_map = {r.action_id: _job_from_row(r) for r in job_rows}

            # Load outbox records.
            outbox_map: dict[str, list[Any]] = {}
            action_ids_for_outbox = [a.action_id for a in actions]
            if action_ids_for_outbox:
                outbox_rows = (
                    await session.scalars(
                        select(orm.DispositionOutbox).where(
                            orm.DispositionOutbox.action_id.in_(action_ids_for_outbox)
                        )
                    )
                ).all()
                for r in outbox_rows:
                    outbox_map.setdefault(r.action_id, []).append(r)

            return actions, jobs_map, outbox_map

    async def _load_disposition_policy(self, event_id: str) -> DispositionPolicy | None:
        """Read disposition_policy from the SecurityEvent row.

        ``disposition_policy`` is a SecurityEvent column, **not** an
        EventContext field.  Attempting to read it via working_memory with
        key ``"disposition_policy"`` would trigger a ``GuardrailViolationError``
        because ``"disposition_policy"`` is not registered in ``FIELD_OWNERSHIP``.
        The correct path is the DB query below.
        """
        if self._session_factory is None:
            logger.debug(
                "No session_factory available — cannot load disposition_policy for event=%s",
                event_id,
            )
            return None

        async with self._session_factory() as session:
            event_row = await session.get(orm.SecurityEvent, event_id)
            if event_row is None:
                logger.debug(
                    "SecurityEvent row not found for event=%s — disposition_policy unknown",
                    event_id,
                )
                return None
            if not event_row.disposition_policy:
                logger.debug(
                    "disposition_policy is empty/falsy for event=%s — treating as unknown",
                    event_id,
                )
                return None
            try:
                return DispositionPolicy(event_row.disposition_policy)
            except ValueError:
                logger.warning(
                    "Unknown disposition_policy %r for event=%s, treating as None",
                    event_row.disposition_policy,
                    event_id,
                )
                return None

    async def _load_event_plan_revision(self, event_id: str) -> int:
        """Load the current plan_revision for *event_id* from the database.

        Used as a fallback when ``response_plan.actions`` is empty and the
        plan_revision cannot be derived from action records in memory.
        Returns the maximum ``plan_revision`` across all Actions for the
        event, or 1 if no Actions exist (a plan with zero Actions defaults
        to revision 1, matching the ORM default on the ``Action`` table).
        """
        if self._session_factory is None:
            logger.debug(
                "No session_factory — defaulting plan_revision=1 for event=%s",
                event_id,
            )
            return 1

        async with self._session_factory() as session:
            row = (
                await session.scalars(
                    select(orm.Action.plan_revision)
                    .where(orm.Action.event_id == event_id)
                    .order_by(orm.Action.plan_revision.desc())
                    .limit(1)
                )
            ).first()
            if row is not None:
                logger.debug(
                    "Loaded plan_revision=%d for event=%s from DB",
                    row,
                    event_id,
                )
                return int(row)
            logger.debug(
                "No actions in DB for event=%s — defaulting plan_revision=1",
                event_id,
            )
            return 1

    async def _collect_writeback_ids(
        self,
        event_id: str,
        action: Action,
        outbox_map: dict[str, list[Any]],
    ) -> list[str]:
        """Collect writeback IDs associated with an action."""
        wb_ids: list[str] = []
        outboxes = outbox_map.get(action.action_id, [])
        for ob in outboxes:
            # Direct attribute access — getattr(ob, "writeback_id", None)
            # silently returns [] on field renames, masking refactor bugs.
            wb_id = ob.writeback_id
            if wb_id:
                wb_ids.append(wb_id)
        return wb_ids

    async def _load_latest_writeback_receipt(
        self,
        writeback_id: str,
    ) -> orm.DispositionReceipt | None:
        if self._session_factory is None:
            return None
        async with self._session_factory() as session:
            return (
                await session.scalars(
                    select(orm.DispositionReceipt)
                    .where(orm.DispositionReceipt.writeback_id == writeback_id)
                    .order_by(orm.DispositionReceipt.sequence.desc())
                    .limit(1)
                )
            ).first()

    async def _resolve_effective_writeback_status(
        self,
        *,
        action: Action,
        wb_ids: list[str],
    ) -> tuple[WritebackStatus | None, str | None]:
        """Prefer latest DispositionReceipt over denormalized Action.writeback_status."""
        if wb_ids and self._session_factory is not None:
            for wb_id in wb_ids:
                receipt = await self._load_latest_writeback_receipt(wb_id)
                if receipt is not None:
                    try:
                        status = WritebackStatus(receipt.status)
                    except ValueError:
                        status = WritebackStatus.UNKNOWN
                    evidence = getattr(receipt, "confirmation_evidence", None)
                    return status, evidence
        return action.writeback_status, None

    @staticmethod
    def _adjust_routing_for_weak_evidence(
        *,
        confirmed: bool,
        rec: bool,
        man: bool,
        detail_suffix: str,
        evidence_raw: str | None,
    ) -> tuple[bool, bool, bool, str, str | None]:
        evidence_tier: str | None = evidence_raw
        if not confirmed:
            return confirmed, rec, man, detail_suffix, evidence_tier
        if evidence_raw is None:
            return confirmed, rec, man, detail_suffix, None
        try:
            evidence = ConfirmationEvidence(evidence_raw)
        except ValueError:
            return confirmed, rec, man, detail_suffix, evidence_raw
        evidence_tier = evidence.value
        if evidence is ConfirmationEvidence.ADAPTER_ACKNOWLEDGED:
            return (
                False,
                True,
                False,
                "writeback_confirmed_weak_evidence",
                evidence_tier,
            )
        return confirmed, rec, man, detail_suffix, evidence_tier

    async def _evaluate_terminal_writeback_status(
        self,
        *,
        event_id: str,
        activate_result: _ActivateResult,
    ) -> dict[str, Any]:
        """Evaluate the terminal disposition writeback receipt after activation.

        ``activate_and_submit`` only guarantees outbox enqueue; receipt rows
        appear after DispositionSyncService delivery.  Missing or non-CONFIRMED
        receipts route to ``need_recovery`` per ISSUE-060 §4.5.

        Returns a dict with the same shape as ``_evaluate_writeback_statuses``
        so phase 2 can merge the terminal writeback evaluation into its
        final routing decision.
        """
        failed_wb_set: set[str] = set()
        blocked_wb_set: set[str] = set()
        empty: dict[str, Any] = {
            "results": [],
            "failed_wb": failed_wb_set,
            "blocked_wb": blocked_wb_set,
            "need_recovery": False,
            "need_manual": False,
        }
        terminal_wb_id = activate_result.writeback_id
        if terminal_wb_id is None:
            # Contract anomaly: activate_and_submit returned activated=True
            # but no writeback_id — we cannot verify a writeback receipt
            # that has no identifier.  Escalate to manual resolution so an
            # operator can inspect the disposition state directly.
            # (ISSUE-060 review SF-2)
            if activate_result.activated:
                logger.error(
                    "Contract anomaly: terminal disposition activated "
                    "(activated=True) but writeback_id is None — "
                    "escalating to manual resolution event=%s",
                    event_id,
                )
                empty["need_manual"] = True
                # Use activate_result.action_id (the deferred action) rather
                # than a synthetic f"terminal_wb_{event_id}" which does not
                # conform to the wbk-{8hex} format and would fail downstream
                # resolve/retry path-parameter matching.
                # (ISSUE-060 review SF-3)
                _blocked_ref = activate_result.action_id or activate_result.writeback_id
                if _blocked_ref is not None:
                    blocked_wb_set.add(_blocked_ref)
            return empty
        if self._session_factory is None:
            logger.warning(
                "Cannot verify terminal writeback %s: no session_factory"
                " event=%s — escalating to manual resolution",
                terminal_wb_id,
                event_id,
            )
            empty["need_manual"] = True
            blocked_wb_set.add(terminal_wb_id)
            return empty

        try:
            async with self._session_factory() as session:
                # Read the latest (highest sequence) receipt for this writeback.
                receipt_row = (
                    await session.scalars(
                        select(orm.DispositionReceipt)
                        .where(orm.DispositionReceipt.writeback_id == terminal_wb_id)
                        .order_by(orm.DispositionReceipt.sequence.desc())
                        .limit(1)
                    )
                ).first()

                if receipt_row is None:
                    logger.info(
                        "Terminal writeback receipt not yet available: wb_id=%s"
                        " event=%s — awaiting DispositionSync delivery",
                        terminal_wb_id,
                        event_id,
                    )
                    empty["need_recovery"] = True
                    return empty

                # Map the receipt status string to a WritebackStatus enum value.
                try:
                    wb_status = WritebackStatus(receipt_row.status)
                except ValueError:
                    logger.warning(
                        "Unknown terminal writeback status %s for wb_id=%s event=%s",
                        receipt_row.status,
                        terminal_wb_id,
                        event_id,
                    )
                    wb_status = WritebackStatus.UNKNOWN

                routing = _WRITEBACK_STATUS_ROUTING.get(
                    wb_status,
                    (False, True, False, "writeback_status_unknown"),
                )
                confirmed, rec, man, detail_suffix = routing

                evidence_raw = getattr(receipt_row, "confirmation_evidence", None)
                confirmed, rec, man, detail_suffix, evidence_tier = (
                    self._adjust_routing_for_weak_evidence(
                        confirmed=confirmed,
                        rec=rec,
                        man=man,
                        detail_suffix=detail_suffix,
                        evidence_raw=evidence_raw,
                    )
                )
                if (
                    evidence_raw is not None
                    and evidence_tier == ConfirmationEvidence.ADAPTER_ACKNOWLEDGED.value
                ):
                    logger.info(
                        "Terminal writeback %s CONFIRMED but evidence_tier=weak"
                        " (adapter_acknowledged) event=%s",
                        terminal_wb_id,
                        event_id,
                    )
                empty["confirmation_evidence"] = evidence_tier

                if not confirmed:
                    logger.warning(
                        "Terminal writeback %s status=%s → %s event=%s",
                        terminal_wb_id,
                        wb_status.value,
                        detail_suffix,
                        event_id,
                    )
                    if man:
                        empty["need_manual"] = True
                        blocked_wb_set.add(terminal_wb_id)
                    elif rec:
                        empty["need_recovery"] = True
                        if wb_status in (WritebackStatus.FAILED, WritebackStatus.PARTIAL):
                            failed_wb_set.add(terminal_wb_id)

                return empty
        except Exception as exc:
            logger.warning(
                "Failed to evaluate terminal writeback %s event=%s: %s",
                terminal_wb_id,
                event_id,
                exc,
            )
            empty["need_manual"] = True
            if terminal_wb_id:
                blocked_wb_set.add(terminal_wb_id)
            return empty

    # ------------------------------------------------------------------ #
    # Verification action lifecycle
    # ------------------------------------------------------------------ #

    async def _create_verification_action(
        self,
        *,
        event_id: str,
        source_action: Action,
        verify_tool: str,
    ) -> Action:
        """Persist a verification Action and transition PENDING → EXECUTING.

        Verification actions: action_category=verification,
        execution_owner=null, writeback_required=false.
        """
        action_id = _deterministic_verification_action_id(
            event_id=event_id,
            source_action_id=source_action.action_id,
            verify_tool=verify_tool,
        )
        verification_action = Action(
            action_id=action_id,
            event_id=event_id,
            plan_revision=source_action.plan_revision,
            action_fingerprint=f"verify:{verify_tool}:{source_action.action_id}",
            action_category=ActionCategory.VERIFICATION,
            action_name=f"verify_{source_action.action_name}"[:255],
            tool_name=verify_tool,
            action_level=source_action.action_level,
            execution_phase=ActionExecutionPhase.IMMEDIATE,
            target_type=source_action.target_type,
            target=source_action.target,
            parameters={
                "target_type": source_action.target_type,
                "target": source_action.target,
                "source_action_id": source_action.action_id,
            },
            status=ActionStatus.EXECUTING,
            execution_owner=None,
            writeback_required=False,
            writeback_applicable=False,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            writeback_status=None,
        )

        if self._session_factory is not None:
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        row = orm.Action(
                            action_id=verification_action.action_id,
                            event_id=verification_action.event_id,
                            plan_revision=verification_action.plan_revision,
                            action_fingerprint=verification_action.action_fingerprint,
                            action_category=verification_action.action_category.value,
                            action_name=verification_action.action_name,
                            tool_name=verification_action.tool_name,
                            action_level=verification_action.action_level.value,
                            execution_phase=verification_action.execution_phase.value,
                            target_type=verification_action.target_type,
                            target=verification_action.target,
                            parameters=verification_action.parameters,
                            status=verification_action.status.value,
                            execution_owner=None,
                            writeback_required=False,
                            writeback_applicable=False,
                            writeback_readiness=verification_action.writeback_readiness.value,
                        )
                        session.add(row)
            except Exception as exc:
                # Distinguish integrity errors (idempotent re-run — the row
                # already exists, which is fine) from other DB failures
                # (connection lost, constraint violation, …) which leave an
                # audit gap.  We still return the in-memory Action so the
                # observation can proceed, but the warning now carries the
                # explicit audit-gap marker.
                from sqlalchemy.exc import IntegrityError

                if isinstance(exc, IntegrityError):
                    logger.debug(
                        "Verification action %s already persisted (idempotent re-run)",
                        action_id,
                    )
                else:
                    logger.warning(
                        "Failed to persist verification action %s — audit trail"
                        " incomplete for this verification (source_action=%s): %s",
                        action_id,
                        source_action.action_id,
                        exc,
                    )

        return verification_action

    async def _finalize_verification_action(
        self,
        action: Action,
        *,
        target_status: ActionStatus,
    ) -> None:
        """Transition a verification Action to its terminal status."""
        if self._session_factory is not None:
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        row = await session.get(
                            orm.Action,
                            action.action_id,
                            with_for_update=True,
                        )
                        if row is not None:
                            # Guard against concurrent finalization: if the
                            # Action is already in a terminal state (SUCCESS,
                            # FAILED, or UNKNOWN), another VerifyAgent instance
                            # has already finalized it — skip the update and
                            # log at info level.
                            _TERMINAL_STATUSES = {
                                ActionStatus.SUCCESS.value,
                                ActionStatus.FAILED.value,
                                ActionStatus.UNKNOWN.value,
                            }
                            if row.status in _TERMINAL_STATUSES:
                                logger.info(
                                    "Verification action %s already finalized "
                                    "by concurrent operation (current status: %s)",
                                    action.action_id,
                                    row.status,
                                )
                            else:
                                row.status = target_status.value
                                row.updated_at = datetime.now(UTC)
                # Commit succeeded — update the domain object to stay
                # consistent with the persisted row.
                action.status = target_status
            except Exception as exc:
                # Distinguish transient errors (network blip, connection
                # pool exhaustion, deadlock retry) from permanent errors
                # (schema mismatch, constraint violation).  Transient
                # failures are warnings — the caller can retry on the next
                # cycle.  Permanent failures are errors that risk leaving
                # the verification Action as a zombie in EXECUTING status.
                if isinstance(exc, _TRANSIENT_EXC_TYPES):
                    logger.warning(
                        "Transient failure finalizing verification action %s "
                        "(will retry next cycle): %s",
                        action.action_id,
                        exc,
                    )
                else:
                    logger.error(
                        "Permanent failure finalizing verification action %s "
                        "(action may be stuck in EXECUTING status): %s",
                        action.action_id,
                        exc,
                        exc_info=True,
                    )

    # ------------------------------------------------------------------ #
    # Working memory & event bus
    # ------------------------------------------------------------------ #

    async def _persist_phase1_for_eds_gate(
        self,
        *,
        event_id: str,
        phase1_results: list[VerificationActionResult],
        phase1_failed: set[str],
    ) -> None:
        """Persist phase-1-only verification so EDS can pass after_effect_resolution_ready."""
        overall_status = (
            VerificationOverallStatus.WAITING
            if has_immediate_effect_pending(None, results=phase1_results)
            else VerificationOverallStatus.SUCCESS
        )
        interim = VerificationResult(
            results=phase1_results,
            overall_status=overall_status,
            failed_actions=list(phase1_failed),
            verification_phase=VerificationPhase.EFFECT,
            need_action_replan=False,
            need_writeback_recovery=False,
            need_manual_resolution=False,
        )
        await self._write_verification_result(event_id, interim)

    async def _persist_effect_verification_statuses(
        self,
        results: list[VerificationActionResult],
    ) -> None:
        """Write per-action ``effect_status`` onto ``Action.effect_verification_status``.

        Only terminal ``VerificationPhase.EFFECT`` outcomes are persisted
        (``verified`` / ``failed`` / ``unverifiable``). Phase-2 disposition
        results reuse ``effect_status=VERIFIED`` for writeback receipt confirmation
        and must never overwrite the entity-effect column used by SOC stats.

        In-flight ``SKIPPED`` rows (pending execution, waiting approval, deferred
        activation) are not stamped so reports / KB consumers do not read a
        premature "skipped" as a finished verification.
        Failures are logged and never raise — verification routing must not
        break because a denormalized stats column could not be updated.
        """
        if self._session_factory is None or not results:
            return

        # Matches stats.py ``_EFFECT_JUDGEABLE`` — only conclusive outcomes.
        _terminal_effect = {
            EffectStatus.VERIFIED,
            EffectStatus.FAILED,
            EffectStatus.UNVERIFIABLE,
        }

        updates: dict[str, str] = {}
        for item in results:
            if item.detail == "deferred_pending_activation":
                continue
            # None is treated as EFFECT for legacy callers / unit helpers that
            # omit verification_phase; DISPOSITION must never land here.
            if item.verification_phase == VerificationPhase.DISPOSITION:
                continue
            if item.effect_status not in _terminal_effect:
                continue
            updates[item.action_id] = item.effect_status.value
        if not updates:
            return

        now = datetime.now(UTC)
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    for action_id, status in updates.items():
                        await session.execute(
                            update(orm.Action)
                            .where(orm.Action.action_id == action_id)
                            .values(
                                effect_verification_status=status,
                                updated_at=now,
                            )
                        )
        except Exception:
            logger.warning(
                "Failed to persist effect_verification_status for %d action(s)",
                len(updates),
                exc_info=True,
            )

    async def _write_verification_result(
        self,
        event_id: str,
        result: VerificationResult,
    ) -> None:
        """Persist the VerificationResult to EventContext via WorkingMemory.

        Sets ``result.wm_persisted`` to indicate whether the write succeeded
        so that downstream consumers (report generator, SuperAgent routing)
        can distinguish "verification not yet run" from "verification ran
        but its output failed to persist."
        """
        if self.working_memory is None:
            result.wm_persisted = False
            logger.debug(
                "No working_memory available — verification_result not persisted for event=%s",
                event_id,
            )
            return
        try:
            await self.working_memory.write(
                event_id,
                "verification_result",
                result.model_dump(mode="json"),
            )
            result.wm_persisted = True
        except Exception as exc:
            result.wm_persisted = False
            logger.warning(
                "Failed to write verification_result for event=%s: %s",
                event_id,
                exc,
            )

    async def _publish_action_verified_events(
        self,
        event_id: str,
        result: VerificationResult,
    ) -> None:
        """Publish action_verified SocketEvent for each per-action result.

        Publish failures are collected in ``result.publish_failures`` so the
        caller can detect gaps in the event-bus delivery without blocking the
        verification pipeline.

        .. note::

           VerifyAgent itself does **not** retry failed publishes.  The
           ``publish_failures`` list is surfaced to the caller (SuperAgent /
           orchestration layer) which owns the retry decision.  Callers
           SHOULD inspect ``result.publish_failures`` after ``execute()``
           returns and re-publish any failed action_ids.
        """
        if self.event_bus is None:
            return
        for item in result.results:
            try:
                await self.event_bus.publish_event(
                    event_id,
                    "action_verified",
                    {
                        "action_id": item.action_id,
                        "effect_status": item.effect_status.value,
                        "writeback_status": (
                            item.writeback_status.value if item.writeback_status else None
                        ),
                        "verification_action_id": item.verification_action_id,
                        "detail": item.detail,
                    },
                )
            except Exception:
                result.publish_failures.append(item.action_id)
                logger.warning(
                    "event_bus action_verified failed event=%s action=%s",
                    event_id,
                    item.action_id,
                    exc_info=True,
                )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _plan_actions(response_plan: Any) -> list[Action]:
    """Extract Action list from a ResponsePlan object or dict."""
    if hasattr(response_plan, "actions"):
        try:
            return list(response_plan.actions)
        except TypeError:
            logger.warning("response_plan.actions is not iterable — returning empty list")
            return []
    if isinstance(response_plan, dict):
        raw = response_plan.get("actions", [])
        return [Action.model_validate(a) if isinstance(a, dict) else a for a in raw]
    return []


def _make_skipped_result(
    action: Action,
    *,
    detail: str,
) -> VerificationActionResult:
    """Build a skipped VerificationActionResult with writeback fields that
    are consistent with the VerificationActionResult validator.

    For deferred POST_VERIFY actions (``detail="deferred_pending_activation"``)
    the writeback obligation is preserved even though the action has not yet
    been activated — the obligation exists at the event level; it just hasn't
    landed on this specific action yet.  The validator permits
    ``writeback_required=True + writeback_readiness=NOT_REQUIRED`` for
    SKIPPED results.
    """
    if detail == "deferred_pending_activation":
        # Preserve the business obligation — it hasn't been discharged yet,
        # it's just waiting for phase 2 activation.
        return VerificationActionResult(
            action_id=action.action_id,
            effect_status=EffectStatus.SKIPPED,
            writeback_required=action.writeback_required,
            writeback_readiness=WritebackReadiness.NOT_REQUIRED,
            writeback_status=None,
            writeback_ids=[],
            detail=detail,
            verification_phase=VerificationPhase.EFFECT,
        )
    # writeback_required expresses the event-level business obligation and
    # MUST NOT be rewritten by technical capability flags like
    # writeback_applicable (§4.5 item 6).  The SKIPPED effect_status is
    # already exempt from the Validator's writeback-consistency check,
    # so preserving the original obligation is safe.
    wb_required = action.writeback_required
    wb_readiness = WritebackReadiness.NOT_REQUIRED
    wb_status = None
    return VerificationActionResult(
        action_id=action.action_id,
        effect_status=EffectStatus.SKIPPED,
        writeback_required=wb_required,
        writeback_readiness=wb_readiness,
        writeback_status=wb_status,
        writeback_ids=[],
        detail=detail,
        verification_phase=VerificationPhase.EFFECT,
    )


def _make_self_verifying_result(action: Action) -> VerificationActionResult:
    """Verification/system actions don't need external observation."""
    return VerificationActionResult(
        action_id=action.action_id,
        effect_status=EffectStatus.VERIFIED,
        writeback_required=False,
        writeback_readiness=WritebackReadiness.NOT_REQUIRED,
        writeback_status=None,
        writeback_ids=[],
        detail="self_verifying",
        verification_phase=VerificationPhase.EFFECT,
    )


def _merge_db_action_with_plan(db_action: Action, plan_action: Action) -> Action:
    """Overlay plan writeback_status when the DB row has not denormalized it yet.

    ``_load_execution_state`` prefers persisted Action rows over plan defaults.
    A null ``writeback_status`` on the row means "not synced yet", not
    "writeback absent".  Re-verify after terminal outbox confirm must still
    see immediate-action writebacks that were confirmed before the deferred
    POST_VERIFY path ran (ISSUE-564 / ISSUE-062).
    """
    if db_action.writeback_status is not None or plan_action.writeback_status is None:
        return db_action
    return db_action.model_copy(update={"writeback_status": plan_action.writeback_status})


def _action_from_row(row: orm.Action) -> Action:
    """Reconstruct Action domain model from ORM row."""
    return Action(
        action_id=row.action_id,
        event_id=row.event_id,
        plan_revision=row.plan_revision,
        action_fingerprint=row.action_fingerprint,
        action_category=ActionCategory(row.action_category),
        action_name=row.action_name,
        tool_name=row.tool_name,
        action_level=ActionLevel(row.action_level),
        execution_phase=(
            ActionExecutionPhase(row.execution_phase)
            if row.execution_phase
            else ActionExecutionPhase.IMMEDIATE
        ),
        activation_condition=row.activation_condition,
        approved_operation_template_hash=row.approved_operation_template_hash,
        approved_terminal_dispositions=row.approved_terminal_dispositions or [],
        target_type=row.target_type,
        target=row.target,
        parameters=row.parameters or {},
        status=ActionStatus(row.status),
        auto_execute=row.auto_execute,
        reason=row.reason,
        provider_name=row.provider_name,
        execution_owner=(ExecutionOwner(row.execution_owner) if row.execution_owner else None),
        execution_job_id=row.execution_job_id,
        tool_call_id=row.tool_call_id,
        idempotency_key=row.idempotency_key,
        writeback_required=bool(row.writeback_required),
        writeback_applicable=bool(row.writeback_applicable),
        writeback_readiness=(
            WritebackReadiness(row.writeback_readiness)
            if row.writeback_readiness
            else WritebackReadiness.NOT_REQUIRED
        ),
        writeback_block_reason=row.writeback_block_reason,
        writeback_status=(WritebackStatus(row.writeback_status) if row.writeback_status else None),
        disposition_source_ref=(
            SourceObjectLocator.model_validate(row.disposition_source_ref)
            if row.disposition_source_ref
            else None
        ),
        superseded_by_revision=row.superseded_by_revision,
        executed_at=row.executed_at,
        effect_verification_status=row.effect_verification_status,
        rollback_status=(ActionStatus(row.rollback_status) if row.rollback_status else None),
        source_action_id=row.source_action_id,
        updated_at=row.updated_at,
    )


def _job_from_row(row: orm.ActionExecutionJob) -> ActionExecutionJob:
    """Reconstruct ActionExecutionJob domain model from ORM row."""
    return ActionExecutionJob(
        job_id=row.job_id,
        event_id=row.event_id,
        action_id=row.action_id,
        provider_name=row.provider_name,
        idempotency_key=row.idempotency_key,
        provider_job_id=row.provider_job_id,
        status=ExecutionJobStatus(row.status),
        claimed_by=row.claimed_by,
        lease_expires_at=row.lease_expires_at,
        poll_after_ms=row.poll_after_ms,
        attempt=row.attempt,
        provider_code=row.provider_code,
        provider_message=row.provider_message,
        raw_result=row.raw_result or {},
        created_at=row.created_at,
        updated_at=row.updated_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


__all__ = [
    "VerifyAgent",
    "_derive_skip_verification_tools",
]


def _deterministic_verification_action_id(
    *,
    event_id: str,
    source_action_id: str,
    verify_tool: str,
) -> str:
    """Derive a deterministic action_id for a verification Action.

    Uses SHA-256(event_id + source_action_id + verify_tool) so that if
    VerifyAgent crashes after writing the verification_result to
    WorkingMemory but before the trace record completes, re-execution
    produces the SAME action_id — the ORM insert becomes an idempotent
    upsert (the database layer must treat duplicate-action-id as a
    no-op or use INSERT … ON CONFLICT DO NOTHING).
    """
    digest = hashlib.sha256(
        f"verify:{event_id}:{source_action_id}:{verify_tool}".encode()
    ).hexdigest()
    # Per ISSUE-002 ID spec: Action IDs follow act-{8hex} format.
    # We truncate to the first 8 hex characters of the SHA-256 digest
    # while preserving the full input for deterministic derivation.
    # Collision probability across verification actions within one
    # event (≤50 actions, ≤20 verify tools each) is negligible with
    # 8 hex chars (32 bits, ~1 in 4 billion per pair).
    return f"act-{digest[:8]}"
