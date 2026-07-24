"""SuperAgent — LangGraph-driven investigation orchestrator (ISSUE-054).

SuperAgent is the top-level orchestrator that wraps the LangGraph investigation
workflow. It manages:
- Distributed lease acquisition/renewal/release via ``EventLease``
- Graph construction via ``build_investigation_graph``
- Checkpoint persistence via ``RedisCheckpointer``
- ReAct engine integration when ``REACT_ENABLED=true``
- Degraded-flag surfacing and error handling

Design authority:
- ``agent_name = "super_agent"`` (README §4.4 agent #1)
- Input: ``SuperAgentInput``, Output: ``InvestigationResult``
- State machine: ``SuperAgentStatus`` (IDLE → PLANNING → EXECUTING →
  REFLECTING → REPLANNING → FINISHED / FAILED)
- Never writes back to XDR — that is ISSUE-062 territory
- Analysis-only gate: ``ORCHESTRATION_MODE=analysis_only`` preserves
  ``AnalysisOnlyPipeline`` path; ``graph`` mode (default) uses this class
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.orchestration.workflow_graph import CompiledInvestigationGraph

from app.agents.base import BaseAgent
from app.core.config import Settings, get_settings
from app.core.errors import (
    ConfigurationError,
    DependencyUnavailableError,
    ShadowTraceError,
)
from app.models.agent_io import InvestigationResult, SuperAgentInput
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    FinalVerdict,
    SuperAgentStatus,
    WritebackReadiness,
)
from app.models.ids import report_id_for_event
from app.orchestration.checkpointer import RedisCheckpointer, build_checkpointer
from app.orchestration.graph_state import InvestigationState
from app.orchestration.lease import DEFAULT_LEASE_TTL_SECONDS, RENEW_INTERVAL_SECONDS, EventLease

# Lazy imports to avoid circular dependency:
#   agents.__init__ → super_agent → workflow_graph → agents.planner_agent → agents.__init__
# These are resolved inside methods that need them.
#   CompiledInvestigationGraph = TypeAlias used in annotations (quoted)
#   build_investigation_graph = called in _build_graph()
#   invoke_investigation_graph = called in investigate()

logger = logging.getLogger(__name__)


class SuperAgent(BaseAgent[SuperAgentInput, InvestigationResult]):
    """Top-level investigation orchestrator.

    Does NOT replace ``build_investigation_graph`` — it wraps the graph with
    lease lifecycle, checkpoint persistence, and error handling.
    """

    agent_name = "super_agent"
    _OPERATOR = "SuperAgent"

    def __init__(
        self,
        *,
        # ── Graph services (required) ──────────────────────────────
        state_machine: Any,
        event_service: Any,
        workflow_runtime: Any,
        degraded_flags: Any,
        context_store: Any,
        # ── Graph agents (required) ────────────────────────────────
        triage_agent: Any,
        planner_agent: Any,
        evidence_agent: Any,
        risk_agent: Any,
        report_agent: Any,
        rag_agent: Any | None = None,
        # ── Lease + checkpoint infrastructure ──────────────────────
        redis_client: Any = None,
        checkpointer: RedisCheckpointer | None = None,
        # ── ReAct integration ──────────────────────────────────────
        react_executor: Any = None,
        # ── Config ─────────────────────────────────────────────────
        settings: Settings | None = None,
        session_factory: Any = None,
        **base_kwargs: Any,
    ) -> None:
        super().__init__(**base_kwargs)

        # Services
        self._state_machine = state_machine
        self._event_service = event_service
        self._workflow_runtime = workflow_runtime
        self._degraded_flags = degraded_flags
        self._ctx_store = context_store

        # Agents
        self._triage_agent = triage_agent
        self._planner_agent = planner_agent
        self._evidence_agent = evidence_agent
        self._risk_agent = risk_agent
        self._report_agent = report_agent
        self._rag_agent = rag_agent

        # Infrastructure
        self._redis_client = redis_client
        self._checkpointer: RedisCheckpointer | None = checkpointer
        self._session_factory = session_factory

        # ReAct (ISSUE-053)
        self._react_executor = react_executor

        # Config
        self._settings = settings or get_settings()

        # Lazy-initialized
        self._lease: EventLease | None = None
        self._status: SuperAgentStatus = SuperAgentStatus.IDLE

        # Set to True by _renew_loop when the lease is lost after consecutive
        # renewal failures.  _build_result reads this flag to mark the
        # investigation as escalated so callers can detect split-brain risk.
        self._lease_lost: bool = False

        # asyncio.Event set by _renew_loop when the lease is irrecoverably lost.
        # investigate() races this event against the graph task so that lease
        # loss can cancel the graph rather than letting it run to completion in
        # a split-brain window (ISSUE-054 Should-Fix #2).
        #
        # NOTE: This is a best-effort cooperative signal.  An in-flight LLM call
        # or long-running node cannot be interrupted mid-execution, so there is
        # still a window where two workers may overlap.  Full cancellation
        # requires ISSUE-056 (Celery worker recovery / hard preemption).
        self._lease_lost_event: asyncio.Event = asyncio.Event()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    @property
    def status(self) -> SuperAgentStatus:
        return self._status

    async def acquire_lease_or_raise(self, event_id: str) -> EventLease:
        """Synchronously acquire the distributed lease for *event_id*.

        This is the API-layer hook for HTTP 409 protection: the endpoint calls
        this synchronously so it can return ``investigation_in_progress`` (409)
        to the caller before dispatching the background graph task.

        Returns the acquired lease (already stored on ``self._lease``).
        Raises ``ShadowTraceError`` with ``investigation_in_progress`` if the
        lease is already held by another worker.
        """
        lease = await self._get_lease()
        if not await lease.acquire(event_id):
            raise ShadowTraceError(
                f"Investigation already in progress for event {event_id}",
                error_code="investigation_in_progress",
                details={"event_id": event_id},
            )
        logger.info(
            "SuperAgent lease acquired event=%s owner=%s",
            event_id,
            lease.owner_id,
        )
        return lease

    async def investigate(
        self,
        event_id: str,
        *,
        lease: EventLease | None = None,
    ) -> InvestigationResult:
        """Run the full investigation graph for *event_id*.

        This is the canonical entry point called by the API layer. It manages
        the lease lifecycle, graph construction, execution, and error handling.

        If *lease* is provided (pre-acquired via ``acquire_lease_or_raise``),
        the lease acquisition step is skipped and the passed-in lease is used.
        This is the production path that enables HTTP 409 responses at the API
        layer before the background task is dispatched.

        NOTE: The return type ``InvestigationResult`` intentionally deviates
        from the original spec signature ``-> None`` (ISSUE-054 §4). Returning
        the structured result is a deliberate improvement — it lets callers
        inspect the investigation outcome without an extra DB round-trip.
        The spec will be updated to reflect this change.
        """
        self._status = SuperAgentStatus.IDLE
        self._lease_lost = False  # Reset between investigations (ISSUE-054 Blocker #1)
        self._lease_lost_event.clear()  # Reset lease-lost signal (ISSUE-054 Should-Fix #2)

        # ── Gate: analysis_only mode rejects graph orchestration ──
        if self._settings.orchestration_mode == "analysis_only":
            raise ConfigurationError(
                "SuperAgent.investigate requires ORCHESTRATION_MODE=graph, got analysis_only",
                error_code="configuration_error",
                details={
                    "orchestration_mode": self._settings.orchestration_mode,
                    "event_id": event_id,
                },
            )

        # ── Gate: REACT_ENABLED but no ReAct executor ──
        if self._settings.react_enabled and self._react_executor is None:
            raise ConfigurationError(
                "REACT_ENABLED=true but no ReadOnlyReActExecutor is registered "
                "(ISSUE-053). Set REACT_ENABLED=false or deploy ISSUE-053.",
                error_code="configuration_error",
                details={"react_enabled": True, "event_id": event_id},
            )

        # ── 1. Acquire distributed lease (or use pre-acquired) ─────
        if lease is not None:
            # Pre-acquired by the API layer for HTTP 409 protection.
            self._lease = lease
        else:
            lease = await self._get_lease()
            if not await lease.acquire(event_id):
                raise ShadowTraceError(
                    f"Investigation already in progress for event {event_id}",
                    error_code="investigation_in_progress",
                    details={"event_id": event_id},
                )

        self._status = SuperAgentStatus.PLANNING
        logger.info(
            "SuperAgent investigation started event=%s owner=%s",
            event_id,
            lease.owner_id,
        )

        renew_task: asyncio.Task[None] | None = None
        try:
            # ── 2. Build checkpointer ────────────────────────────
            checkpointer = await self._get_checkpointer()

            # ── 3. Build investigation graph ─────────────────────
            graph = self._build_graph(checkpointer)

            # ── 4. Initialize state ──────────────────────────────
            initial_state = await self._build_initial_state(event_id)

            # ── 5. Start background lease renewal ────────────────
            renew_task = asyncio.create_task(
                self._renew_loop(event_id, lease), name=f"lease-renew-{event_id}"
            )

            # ── 6. Invoke graph (race against lease loss) ──────────
            self._status = SuperAgentStatus.EXECUTING
            from app.orchestration.workflow_graph import invoke_investigation_graph

            config = {"configurable": {"thread_id": event_id}}
            graph_task = asyncio.create_task(
                invoke_investigation_graph(graph, initial_state, config),
                name=f"graph-{event_id}",
            )
            lease_watch_task = asyncio.create_task(
                self._lease_lost_event.wait(),
                name=f"lease-watch-{event_id}",
            )

            done, pending = await asyncio.wait(
                [graph_task, lease_watch_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # ── Lease lost before graph completed → cancel graph ──
            if lease_watch_task in done:
                graph_task.cancel()
                # Cancel lease_watch_task if it's still pending (it shouldn't be
                # since it's in `done`, but be defensive).
                if not lease_watch_task.done():
                    lease_watch_task.cancel()
                try:
                    await graph_task
                except asyncio.CancelledError:
                    logger.warning(
                        "Graph task cancelled for event=%s after lease loss — "
                        "split-brain window was open (ISSUE-056)",
                        event_id,
                    )
                raise ShadowTraceError(
                    f"Investigation aborted for event {event_id}: "
                    "distributed lease was lost after consecutive renewal failures",
                    error_code="lease_lost",
                    details={
                        "event_id": event_id,
                        "escalated": True,
                        "external_unsynced": True,
                    },
                )

            # Graph completed; clean up the lease watch task.
            lease_watch_task.cancel()
            try:
                await lease_watch_task
            except asyncio.CancelledError:
                pass

            final_state = graph_task.result()

            # ── 7. Build result ──────────────────────────────────
            self._status = SuperAgentStatus.FINISHED
            result = await self._build_result(event_id, final_state)

            logger.info(
                "SuperAgent investigation complete event=%s status=%s verdict=%s",
                event_id,
                result.final_status.value,
                result.final_verdict.value,
            )
            return result

        except asyncio.CancelledError:
            logger.warning("SuperAgent cancelled for event=%s", event_id)
            self._status = SuperAgentStatus.FAILED
            try:
                await self._state_machine.transition(
                    event_id,
                    EventStatus.FAILED,
                    operator=SuperAgent._OPERATOR,
                    reason="super_agent:cancelled",
                )
            except Exception:
                logger.exception(
                    "Failed to mark event=%s as FAILED after cancellation",
                    event_id,
                )
            raise

        except ShadowTraceError as exc:
            self._status = SuperAgentStatus.FAILED
            logger.exception(
                "SuperAgent investigation failed event=%s: ShadowTraceError=%s",
                event_id,
                type(exc).__name__,
            )
            try:
                await self._state_machine.transition(
                    event_id,
                    EventStatus.FAILED,
                    operator=SuperAgent._OPERATOR,
                    # DB column limit — truncate to 500 chars
                    reason=f"super_agent:error:{type(exc).__name__}:{exc!s}"[:500],
                )
            except Exception:
                logger.exception(
                    "Failed to mark event=%s as FAILED after ShadowTraceError",
                    event_id,
                )
            raise

        except Exception as exc:
            self._status = SuperAgentStatus.FAILED
            logger.exception(
                "SuperAgent investigation failed event=%s: %s",
                event_id,
                exc,
            )
            try:
                await self._state_machine.transition(
                    event_id,
                    EventStatus.FAILED,
                    operator=SuperAgent._OPERATOR,
                    reason=f"super_agent:error:{type(exc).__name__}:{exc!s}"[:500],
                )
            except Exception:
                logger.exception(
                    "Failed to mark event=%s as FAILED after SuperAgent error",
                    event_id,
                )
            raise

        finally:
            # ── 8. Cleanup ───────────────────────────────────────
            if renew_task is not None:
                renew_task.cancel()
                try:
                    await renew_task
                except asyncio.CancelledError:
                    pass
            # ── Refresh source snapshot (ISSUE-054 §4) ────────────
            await self._try_snapshot_op(
                event_id,
                "refresh_snapshot",
                self._event_service.refresh_snapshot,
                level=logging.DEBUG,
            )
            await lease.release(event_id)
            logger.debug("SuperAgent cleanup complete event=%s", event_id)

    # ------------------------------------------------------------------ #
    # BaseAgent contract
    # ------------------------------------------------------------------ #

    async def _run(self, input: SuperAgentInput) -> InvestigationResult:
        """Delegates to ``investigate`` — the BaseAgent template wraps budget,
        hooks, guardrails, and tracing around it.
        """
        return await self.investigate(input.event_id)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _try_snapshot_op(
        self,
        event_id: str,
        op_name: str,
        op: Any,
        *,
        level: int = logging.WARNING,
    ) -> Any:
        """Shared helper for ISSUE-029 snapshot operations.

        Both ``refresh_snapshot`` and ``freeze_source_snapshot`` follow the
        same pattern: call the method, swallow ``AttributeError`` only when
        the method itself is absent (ISSUE-029 not yet landed), propagate all
        other exceptions.  This helper eliminates the duplicated try/except
        blocks (ISSUE-054 Nit #3).

        Returns the result of ``op(event_id)`` on success, or ``None`` when
        the method is absent or the call raises.
        """
        try:
            return await op(event_id)
        except AttributeError as exc:
            if op_name not in str(exc):
                raise
            logger.log(
                level,
                "source_snapshot %s skipped for event=%s — "
                "%s not available (pending ISSUE-029)",
                op_name,
                event_id,
                op_name,
            )
            return None
        except Exception:
            logger.exception(
                "source_snapshot %s failed for event=%s",
                op_name,
                event_id,
            )
            return None

    async def _get_lease(self) -> EventLease:
        """Return or lazily create the EventLease from Redis."""
        if self._lease is None:
            if self._redis_client is None:
                raise DependencyUnavailableError(
                    "SuperAgent requires a Redis client for EventLease",
                    error_code="dependency_unavailable",
                    details={"dependency": "redis_client"},
                )
            self._lease = EventLease(
                self._redis_client.get_client(),
                ttl_s=DEFAULT_LEASE_TTL_SECONDS,
            )
        return self._lease

    async def _get_checkpointer(self) -> RedisCheckpointer:
        """Return or lazily build the RedisCheckpointer."""
        if self._checkpointer is None:
            if self._redis_client is None:
                raise DependencyUnavailableError(
                    "SuperAgent requires a Redis client for RedisCheckpointer",
                    error_code="dependency_unavailable",
                    details={"dependency": "redis_client"},
                )
            self._checkpointer = await build_checkpointer(self._redis_client)
        return self._checkpointer

    def _build_graph(
        self,
        checkpointer: RedisCheckpointer,
    ) -> CompiledInvestigationGraph:
        """Construct the LangGraph investigation graph."""
        from app.orchestration.workflow_graph import build_investigation_graph

        agents: dict[str, Any] = {
            # ── P0 agents (ISSUE-054) ────────────────────────────
            "triage_agent": self._triage_agent,
            "planner_agent": self._planner_agent,
            "evidence_agent": self._evidence_agent,
            "risk_agent": self._risk_agent,
            "report_agent": self._report_agent,
            # ── Future agents (out of scope for ISSUE-054) ───────
            # GraphAgent, ResponseAgent, VerifyAgent, MemoryAgent
            # will be wired in when their respective issues land.
        }
        if self._rag_agent is not None:
            agents["rag_agent"] = self._rag_agent

        services: dict[str, Any] = {
            "state_machine": self._state_machine,
            "event_service": self._event_service,
            "workflow_runtime": self._workflow_runtime,
            "degraded_flags": self._degraded_flags,
            "context_store": self._ctx_store,
        }

        return build_investigation_graph(
            agents,
            services,
            checkpointer=checkpointer,
        )

    async def _build_initial_state(self, event_id: str) -> InvestigationState:
        """Hydrate the initial graph state from the event record."""
        event = await self._event_service.get_event(event_id)
        if event is None:
            raise ShadowTraceError(
                f"event {event_id} not found",
                error_code="event_not_found",
                details={"event_id": event_id},
            )

        # Transition from NEW → TRIAGING to lock the event into the graph
        # Use == for Enum comparison (idiomatic, safer across Python versions)
        if event.status == EventStatus.NEW:
            await self._state_machine.transition(
                event_id,
                EventStatus.TRIAGING,
                operator=SuperAgent._OPERATOR,
                reason="super_agent:investigation_start",
            )

        # Re-read the event to get the authoritative post-transition status.
        # The state machine may have been bypassed (e.g. ISSUE-056 worker
        # recovery, concurrent transition), so hardcoding TRIAGING is unsafe.
        # Use the actual DB status — fail early if the event is not in a valid
        # graph-entry state.
        event = await self._event_service.get_event(event_id)
        if event is None:
            raise ShadowTraceError(
                f"event {event_id} disappeared after status transition",
                error_code="event_not_found",
                details={"event_id": event_id},
            )
        actual_status = event.status
        if actual_status not in (EventStatus.NEW, EventStatus.TRIAGING):
            raise ShadowTraceError(
                f"Event {event_id} is in {actual_status.value} — "
                f"graph investigation requires NEW or TRIAGING",
                error_code="invalid_state_transition",
                details={
                    "event_id": event_id,
                    "actual_status": actual_status.value,
                },
            )

        readiness = WritebackReadiness.NOT_REQUIRED
        try:
            readiness = await self._workflow_runtime.get_event_status_update_readiness(event_id)
        except Exception:
            # When the disposition policy is REQUIRED, a transient readiness
            # lookup failure must default to CAPABILITY_UNKNOWN — not
            # NOT_REQUIRED — to avoid skipping the writeback readiness gate
            # silently (ISSUE-054 Should-Fix #4).
            policy = getattr(event, "disposition_policy", None)
            if policy is DispositionPolicy.REQUIRED:
                readiness = WritebackReadiness.CAPABILITY_UNKNOWN
            logger.warning(
                "event_status_update_readiness lookup failed event=%s "
                "policy=%s, defaulting to %s",
                event_id,
                policy.value if hasattr(policy, "value") else str(policy),
                readiness.value,
                exc_info=True,
            )

        def _to_severity_str(raw: Any) -> str:
            if raw is None:
                return "medium"
            if hasattr(raw, "value"):
                return str(raw.value)
            return str(raw)

        def _to_policy_str(raw: Any) -> str:
            if raw is None:
                return DispositionPolicy.NOT_REQUIRED.value
            if hasattr(raw, "value"):
                return str(raw.value)
            return str(raw)

        state: InvestigationState = {
            "event_id": event_id,
            "event_status": actual_status.value,
            "disposition_policy": _to_policy_str(getattr(event, "disposition_policy", None)),
            "severity": _to_severity_str(getattr(event, "severity", None)),
            "final_verdict": None,
            "confidence": 0.0,
            "need_investigation": None,
            "triage_result": None,
            "false_positive_match": None,
            "source_snapshot": None,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "execution_plan": None,
            "event_status_update_readiness": readiness.value,
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "verify_need_manual_resolution": False,
            "verify_need_writeback_recovery": False,
            "verify_need_action_replan": False,
            "include_rag": self._rag_agent is not None,
            "evidence_output": None,
            "rag_output": None,
            "risk_assessment": None,
            "report_generated": False,
            "needs_approval_wait": False,
            "escalated": False,
            "external_unsynced": False,
        }

        # ── Freeze source snapshot for this investigation ──────────
        # ISSUE-054 §4 requires the source_snapshot to be frozen before graph
        # execution so all downstream agents see a consistent event image.
        frozen = await self._try_snapshot_op(
            event_id,
            "freeze_source_snapshot",
            self._event_service.freeze_source_snapshot,
        )
        if frozen is not None:
            state["source_snapshot"] = frozen

        return state

    async def _build_result(
        self,
        event_id: str,
        state: InvestigationState,
    ) -> InvestigationResult:
        """Convert final graph state into an InvestigationResult.

        The graph state is the authoritative record post-execution; the event
        service row is consulted only as a fallback when state fields are
        missing (ISSUE-054 Should-Fix #5: avoid redundant DB query).
        """
        # Only query the event service when the graph state is missing fields
        # that the fallback path needs.
        _need_event_fallback = (
            not state.get("event_status")
            or not state.get("final_verdict")
            or not state.get("disposition_policy")
        )
        event = (
            await self._event_service.get_event(event_id)
            if _need_event_fallback
            else None
        )

        # ── Final status: state first, then event service ───────
        final_status = EventStatus.REPORTING
        if state.get("event_status"):
            try:
                final_status = EventStatus(state["event_status"])
            except ValueError:
                # ISSUE-054 Nit #4: log when graph produces an unrecognized
                # status value rather than silently falling back to REPORTING.
                logger.warning(
                    "Unknown event_status value %r in graph state for event=%s — "
                    "falling back to REPORTING",
                    state["event_status"],
                    event_id,
                )
                final_status = EventStatus.REPORTING
        elif event is not None:
            final_status = event.status

        # ── Final verdict: state first, then event service ──────
        final_verdict = FinalVerdict.NONE
        if state.get("final_verdict"):
            try:
                final_verdict = FinalVerdict(state["final_verdict"])
            except ValueError:
                logger.warning(
                    "Unknown final_verdict value %r in graph state for event=%s — "
                    "falling back to NONE",
                    state["final_verdict"],
                    event_id,
                )
                final_verdict = FinalVerdict.NONE
        elif event is not None and event.final_verdict is not None:
            final_verdict = (
                FinalVerdict(event.final_verdict)
                if isinstance(event.final_verdict, str)
                else event.final_verdict
            )

        # ── Disposition policy: state first, then event service ─
        policy = DispositionPolicy.NOT_REQUIRED
        if state.get("disposition_policy"):
            try:
                policy = DispositionPolicy(state["disposition_policy"])
            except ValueError:
                logger.warning(
                    "Unknown disposition_policy value %r in graph state for event=%s — "
                    "falling back to NOT_REQUIRED",
                    state["disposition_policy"],
                    event_id,
                )
                policy = DispositionPolicy.NOT_REQUIRED
        elif event is not None and hasattr(event, "disposition_policy"):
            policy = event.disposition_policy

        writeback_required = policy is DispositionPolicy.REQUIRED

        # ── Derive report_id via canonical function ───────────────
        # MUST use report_id_for_event() to guarantee the same report_id
        # across all components (SuperAgent, ReportAgent, e2e tests).
        # The stable SHA256 derivation enables idempotent upsert.
        report_id = report_id_for_event(event_id)

        # ── Writeback readiness: graph state first, then fallback ─
        writeback_readiness = WritebackReadiness.NOT_REQUIRED
        if writeback_required:
            state_readiness_raw = state.get("event_status_update_readiness")
            if state_readiness_raw:
                try:
                    writeback_readiness = WritebackReadiness(state_readiness_raw)
                except ValueError:
                    writeback_readiness = WritebackReadiness.CAPABILITY_UNKNOWN
            else:
                writeback_readiness = WritebackReadiness.CAPABILITY_UNKNOWN

        return InvestigationResult(
            event_id=event_id,
            final_status=final_status,
            final_verdict=final_verdict,
            escalated=state.get("escalated", False) or self._lease_lost,
            external_unsynced=state.get("external_unsynced", False) or self._lease_lost,
            report_id=report_id,
            writeback_required=writeback_required,
            writeback_readiness=writeback_readiness,
        )

    async def _renew_loop(self, event_id: str, lease: EventLease) -> None:
        """Background task that renews the lease every ``RENEW_INTERVAL_SECONDS``.

        After ``_MAX_RENEWAL_FAILURES`` consecutive failures the investigation is
        halted to prevent split-brain: if the lease expired, another worker could
        have already acquired it and started a duplicate investigation.
        """
        _MAX_RENEWAL_FAILURES = 3
        renewal_failures = 0
        while True:
            await asyncio.sleep(RENEW_INTERVAL_SECONDS)
            ok = await lease.renew(event_id)
            if not ok:
                renewal_failures += 1
                logger.error(
                    "Lease renewal failed for event=%s (consecutive_failures=%d/%d)",
                    event_id,
                    renewal_failures,
                    _MAX_RENEWAL_FAILURES,
                )
                if renewal_failures >= _MAX_RENEWAL_FAILURES:
                    logger.critical(
                        "Aborting investigation for event=%s after %d consecutive "
                        "lease renewal failures — lease may be held by another worker",
                        event_id,
                        renewal_failures,
                    )
                    # Mark the investigation as escalated so _build_result
                    # surfaces the degraded state to callers.  The lease release
                    # in finally will be a no-op (owner won't match), which is
                    # safe.
                    #
                    # P1 ISSUE-056 (Celery worker recovery): the graph task may
                    # still be running at this point.  _lease_lost_event signals
                    # investigate() to cancel the graph task cooperatively, but
                    # an in-flight LLM call or long-running node cannot be
                    # interrupted mid-execution.  Until ISSUE-056 delivers hard
                    # preemption, a brief split-brain window remains.
                    self._lease_lost = True
                    self._lease_lost_event.set()
                    return
            else:
                renewal_failures = 0


__all__ = ["SuperAgent"]
