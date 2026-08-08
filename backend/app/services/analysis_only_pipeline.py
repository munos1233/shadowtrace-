"""Sequential analysis-only pipeline (ISSUE-038 / ISSUE-047).

Runs Triage → Evidence → RAG → Graph → Risk → Report for mock/offline development.
RAGAgent sits after Evidence and before Risk; failures degrade to ``rag_output=None``
without blocking downstream scoring or reporting.

038 lifecycle features (NEW guard, short-circuit close, disposition policy,
``analysis_only_complete`` persistence) are preserved. 047 RAG wiring is reused by
``rag_node`` in ``app.orchestration.workflow_graph``.

ISSUE-208: when a ``memory_agent`` is wired and ``MEMORY_ENQUEUE_AFTER_ANALYSIS``
is enabled, profile candidates are enqueued for review after analysis completion
(REPORTING) without blocking the pipeline; fp_rule / history_case still require
CLOSED inside MemoryAgent.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Protocol

from app.agents.evidence_agent import EvidenceAgent
from app.agents.report_agent import ReportAgent
from app.agents.risk_agent import RiskAgent
from app.agents.triage_agent import TriageAgent
from app.core.config import Settings, get_settings
from app.core.errors import (
    ConfigurationError,
    InvalidStateTransitionError,
    ShadowTraceError,
)
from app.models.agent_io import (
    CollectionStatus,
    EvidenceAgentInput,
    EvidenceOutput,
    GraphAgentInput,
    GraphOutput,
    MemoryAgentInput,
    RAGAgentInput,
    RAGOutput,
    RiskAgentInput,
    RiskAssessment,
    ScoringMode,
    TriageAgentInput,
    TriageResult,
)
from app.models.entities import EntitySet
from app.models.enums import DispositionPolicy, EventStatus, FinalVerdict
from app.models.report import InvestigationReport
from app.models.workflow import TransitionContext
from app.services.agent_task_coordinator import run_risk_score_with_ledger
from app.services.analysis_only_complete_persistence import (
    persist_analysis_only_complete_authoritative,
)
from app.services.event_service import EventService, StateMachinePort
from app.services.false_positive_matcher import build_fp_close_reason
from app.services.fp_adjudication_runner import run_post_evidence_fp_adjudication
from app.services.report_input_builder import build_report_agent_input
from app.services.tenant_resolution import resolve_tenant_id

logger = logging.getLogger(__name__)

_PIPELINE_OPERATOR = "AnalysisOnlyPipeline"


async def _read_persisted_final_verdict(
    event_service: Any | None,
    event_id: str,
) -> FinalVerdict:
    """Read verdict persisted by RiskAgent via ``EventService.set_final_verdict``."""
    if event_service is None:
        return FinalVerdict.NONE
    get_event = getattr(event_service, "get_event", None)
    if get_event is None:
        return FinalVerdict.NONE
    try:
        event = await get_event(event_id)
    except Exception:
        logger.debug(
            "failed to read persisted final_verdict for event=%s",
            event_id,
            exc_info=True,
        )
        return FinalVerdict.NONE
    if event is None:
        return FinalVerdict.NONE
    verdict = getattr(event, "final_verdict", None)
    if isinstance(verdict, FinalVerdict):
        return verdict
    if isinstance(verdict, str):
        try:
            return FinalVerdict(verdict)
        except ValueError:
            return FinalVerdict.NONE
    return FinalVerdict.NONE


class _AgentProtocol(Protocol):
    async def execute(self, input: Any) -> Any: ...


@dataclass(frozen=True)
class AnalysisOnlyPipelineResult:
    """Outcome of a single analysis-only run."""

    event_id: str
    triage_result: TriageResult
    evidence_output: EvidenceOutput | None = None
    rag_output: RAGOutput | None = None
    rag_degraded: bool = False
    risk_assessment: RiskAssessment | None = None
    report: InvestigationReport | None = None
    final_verdict: FinalVerdict = FinalVerdict.NONE
    analysis_only_complete: bool = False
    status: EventStatus | None = None
    disposition_policy: str | None = None
    short_circuit: bool = False


def assert_analysis_only_mode(settings: Settings | None = None) -> None:
    """Fail closed unless mock/offline side effects are disabled."""
    cfg = settings or get_settings()
    if cfg.allow_live_side_effects or cfg.allow_xdr_writeback:
        raise ConfigurationError(
            "AnalysisOnlyPipeline requires ALLOW_LIVE_SIDE_EFFECTS=false "
            "and ALLOW_XDR_WRITEBACK=false",
            error_code="configuration_error",
            details={
                "allow_live_side_effects": cfg.allow_live_side_effects,
                "allow_xdr_writeback": cfg.allow_xdr_writeback,
            },
        )
    source = (cfg.source_mode or "").strip().lower()
    disposition = (cfg.disposition_mode or "").strip().lower()
    if "mock" not in source or "mock" not in disposition:
        raise ConfigurationError(
            "AnalysisOnlyPipeline requires SOURCE_MODE and DISPOSITION_MODE mock modes",
            error_code="configuration_error",
            details={"source_mode": cfg.source_mode, "disposition_mode": cfg.disposition_mode},
        )


async def run_rag_stage(
    rag_agent: _AgentProtocol,
    *,
    event_id: str,
    triage_result: TriageResult,
    evidence_output: EvidenceOutput,
    tenant_id: str | None = None,
    principal: str | None = None,
    trace_id: str | None = None,
    source_snapshot: dict[str, Any] | None = None,
) -> tuple[RAGOutput | None, bool]:
    """Invoke RAGAgent between evidence and risk; never raise to callers."""
    resolved_tenant = tenant_id or resolve_tenant_id(source_snapshot)
    try:
        output = await rag_agent.execute(
            RAGAgentInput(
                event_id=event_id,
                triage_result=triage_result,
                evidence_output=evidence_output,
                tenant_id=resolved_tenant,
                principal=principal,
                trace_id=trace_id,
            )
        )
        if not isinstance(output, RAGOutput):
            logger.warning(
                "RAGAgent returned unexpected type %s for event=%s; degrading",
                type(output).__name__,
                event_id,
            )
            return None, True
        return output, bool(output.degraded)
    except Exception:
        logger.warning(
            "RAGAgent failed for event=%s; continuing without RAG enhancement",
            event_id,
            exc_info=True,
        )
        return None, True


class AnalysisOnlyPipeline:
    """Temporary sequential analysis pipeline (pre-SuperAgent, ISSUE-054).

    Only runs in dev/offline mode. High-risk required-disposition events stay at
    REPORTING; only ``disposition_policy=not_required`` events may reach CLOSED.
    """

    def __init__(
        self,
        *,
        triage_agent: TriageAgent | _AgentProtocol,
        evidence_agent: EvidenceAgent | _AgentProtocol,
        rag_agent: _AgentProtocol,
        graph_agent: _AgentProtocol | None = None,
        risk_agent: RiskAgent | _AgentProtocol,
        report_agent: ReportAgent | _AgentProtocol,
        event_service: EventService | Any | None = None,
        state_machine: StateMachinePort | None = None,
        context_store: Any | None = None,
        session_factory: Any | None = None,
        working_memory: Any | None = None,
        degraded_flags: Any | None = None,
        settings: Settings | None = None,
        memory_agent: Any | None = None,
        agent_task_service: Any | None = None,
        agent_artifact_service: Any | None = None,
        content_projection_service: Any | None = None,
        convergence_guard: Any | None = None,
        output_quality_evaluator: Any | None = None,
    ) -> None:
        self._triage = triage_agent
        self._evidence = evidence_agent
        self._rag = rag_agent
        self._graph = graph_agent
        self._risk = risk_agent
        self._report = report_agent
        self._event_service = event_service
        self._state_machine = state_machine
        self._context_store = context_store
        self._session_factory = session_factory
        self._working_memory = working_memory
        self._degraded_flags = degraded_flags
        self._settings = settings
        self._memory_agent = memory_agent
        self._memory_tasks: set[asyncio.Task[Any]] = set()
        self._agent_task_service = agent_task_service
        self._agent_artifact_service = agent_artifact_service
        self._content_projection_service = content_projection_service
        self._convergence_guard = convergence_guard
        self._output_quality_evaluator = output_quality_evaluator

        # Back-compat aliases for ISSUE-047 unit tests.
        self.triage_agent = triage_agent
        self.evidence_agent = evidence_agent
        self.rag_agent = rag_agent
        self.graph_agent = graph_agent
        self.risk_agent = risk_agent
        self.report_agent = report_agent
        self.event_service = event_service
        self.settings = settings

    async def run(
        self,
        event_id: str,
        *,
        raw_event_summary: str = "",
        hint_entities: Any | None = None,
        generate_report: bool = True,
    ) -> AnalysisOnlyPipelineResult:
        """Execute the analysis-only pipeline for *event_id*.

        ISSUE-168: the pipeline shares the production ConvergenceGuard with the
        LLM client / ToolExecutor, so the counters are released when the run
        finishes (success or failure) — matching the SuperAgent terminal-state
        reset contract (ISSUE-052), otherwise a re-investigation of the same
        event would start from stale counters and the in-process ``_states``
        dict would grow unboundedly.
        """
        try:
            return await self._run(
                event_id,
                raw_event_summary=raw_event_summary,
                hint_entities=hint_entities,
                generate_report=generate_report,
            )
        finally:
            self._reset_convergence_guard(event_id)

    def _reset_convergence_guard(self, event_id: str) -> None:
        """Release convergence counters for *event_id* after the run.

        Mirrors ``SuperAgent._reset_convergence_guard``: guard internals must
        never break the pipeline, so a failure here is only logged.
        """
        guard = self._convergence_guard
        if guard is None:
            return
        try:
            guard.reset(event_id)
        except Exception:
            logger.debug(
                "AnalysisOnlyPipeline: convergence_guard.reset failed for event=%s",
                event_id,
                exc_info=True,
            )

    async def _run(
        self,
        event_id: str,
        *,
        raw_event_summary: str = "",
        hint_entities: Any | None = None,
        generate_report: bool = True,
    ) -> AnalysisOnlyPipelineResult:
        """Internal pipeline stages (``run()`` owns guard reset in ``finally``)."""
        assert_analysis_only_mode(self._settings)

        event = None
        if self._event_service is not None and self._state_machine is not None:
            event = await self._event_service.get_event(event_id)
            if event is None:
                raise ShadowTraceError(
                    f"event {event_id} not found",
                    error_code="event_not_found",
                )
            if event.status is not EventStatus.NEW:
                raise InvalidStateTransitionError(
                    f"AnalysisOnlyPipeline requires event in NEW status, got {event.status.value}",
                    current=event.status,
                    target=EventStatus.TRIAGING,
                    details={"event_id": event_id},
                )
        elif self._event_service is not None and self._state_machine is None:
            # ISSUE-047 unit tests: event_service tracks verdicts only.
            pass

        await self._transition(
            event_id,
            EventStatus.TRIAGING,
            reason="analysis_pipeline:triage_start",
        )

        if event is not None and self._state_machine is not None and hasattr(event, "title"):
            triage_result, alert_text = await self._run_triage(event_id, event)
        else:
            alert_text = raw_event_summary
            triage_input = TriageAgentInput(
                event_id=event_id,
                raw_event_summary=raw_event_summary,
                hint_entities=hint_entities if hint_entities is not None else EntitySet(),
            )
            triage_result = await self._triage.execute(triage_input)
            if not isinstance(triage_result, TriageResult):
                raise TypeError("TriageAgent must return TriageResult")

        logger.info(
            "AnalysisOnlyPipeline triage complete event=%s type=%s severity=%s need_inv=%s",
            event_id,
            triage_result.event_type.value,
            triage_result.severity.value,
            triage_result.need_investigation,
        )

        disposition_policy = DispositionPolicy.NOT_REQUIRED
        if event is not None and hasattr(event, "disposition_policy"):
            disposition_policy = event.disposition_policy
        if (
            not triage_result.need_investigation
            and disposition_policy == DispositionPolicy.NOT_REQUIRED
            and event is not None
            and self._state_machine is not None
            and hasattr(event, "title")
        ):
            return await self._short_circuit_close(
                event_id,
                event,
                triage_result,
                generate_report=generate_report,
            )

        await self._transition(
            event_id,
            EventStatus.COLLECTING_EVIDENCE,
            context=TransitionContext(need_investigation=True),
            reason="analysis_pipeline:evidence_collect",
        )
        evidence_output = await self._run_evidence(event_id, triage_result, alert_text=alert_text)

        fp_adjudication = await self._run_fp_adjudication(
            event_id,
            triage_result,
            evidence_output,
            event=event,
        )

        await self._transition(
            event_id,
            EventStatus.ANALYZING,
            reason="analysis_pipeline:evidence_analyze",
        )
        rag_output, rag_degraded = await run_rag_stage(
            self._rag,
            event_id=event_id,
            triage_result=triage_result,
            evidence_output=evidence_output,
            tenant_id=(event.creation_source_ref.source_tenant_id if event is not None else None),
            principal="investigation:analysis_only_pipeline",
            # When ``event`` is absent, resolve tenant from persisted source snapshot.
            source_snapshot=(
                (await self._context_store.get_full_context(event_id)).source_snapshot
                if self._context_store is not None and event is None
                else None
            ),
        )

        graph_output = await self._run_graph(event_id, evidence_output)

        await self._transition(
            event_id,
            EventStatus.SCORING,
            reason="analysis_pipeline:risk_score",
        )
        tenant_id = None
        if event is not None:
            tenant_id = getattr(
                getattr(event, "creation_source_ref", None),
                "source_tenant_id",
                None,
            )
        if tenant_id is None and self._context_store is not None:
            source_snapshot = await self._context_store.get(event_id, "source_snapshot")
            tenant_id = resolve_tenant_id(source_snapshot)
        if tenant_id:
            projection_fields: dict[str, Any] = {
                "triage_result": triage_result.model_dump(mode="json"),
                "evidence_output": evidence_output.model_dump(mode="json"),
            }
            if rag_output is not None:
                projection_fields["rag_output"] = rag_output.model_dump(mode="json")
            if graph_output is not None:
                projection_fields["graph_output"] = graph_output.model_dump(mode="json")
            risk_assessment = await run_risk_score_with_ledger(
                self._agent_task_service,
                self._agent_artifact_service,
                event_id=event_id,
                tenant_id=tenant_id,
                worker_principal="investigation:analysis_only_pipeline",
                idempotency_key=f"risk-score:{event_id}",
                content_projection_service=self._content_projection_service,
                projection_fields=projection_fields,
                execute=lambda: self._run_risk(
                    event_id,
                    triage_result,
                    evidence_output,
                    rag_output,
                    graph_output,
                ),
            )
        else:
            risk_assessment = await self._run_risk(
                event_id,
                triage_result,
                evidence_output,
                rag_output,
                graph_output,
            )
        final_verdict = await _read_persisted_final_verdict(self._event_service, event_id)

        # ISSUE-242: generate/persist report *before* REPORTING so GET /report
        # cannot race a status=reporting window with no DB row.
        report: InvestigationReport | None = None
        if generate_report:
            report = await self._generate_and_mark_report(
                event_id,
                evidence_output,
                risk_assessment,
            )
        else:
            await self._persist_report_skipped(event_id)

        await self._transition(
            event_id,
            EventStatus.REPORTING,
            reason=(
                "analysis_pipeline:report_generate"
                if generate_report
                else "analysis_pipeline:analysis_complete_no_report"
            ),
        )

        if not generate_report:
            await self._persist_analysis_only_complete(event_id)
            self._schedule_memory_after_analysis(event_id)
            return AnalysisOnlyPipelineResult(
                event_id=event_id,
                triage_result=triage_result,
                evidence_output=evidence_output,
                rag_output=rag_output,
                rag_degraded=rag_degraded,
                risk_assessment=risk_assessment,
                report=None,
                final_verdict=final_verdict,
                analysis_only_complete=True,
                status=EventStatus.REPORTING,
                disposition_policy=disposition_policy.value,
            )

        if self._state_machine is not None and self._event_service is not None:
            event = await self._event_service.get_event(event_id)
            if event is None:
                raise ShadowTraceError(
                    f"event {event_id} disappeared during pipeline execution",
                    error_code="event_not_found",
                )

            if event.disposition_policy == DispositionPolicy.REQUIRED:
                logger.info(
                    "AnalysisOnlyPipeline: event=%s requires disposition, staying at REPORTING",
                    event_id,
                )
                await self._persist_analysis_only_complete(event_id)
                self._schedule_memory_after_analysis(event_id)
                return AnalysisOnlyPipelineResult(
                    event_id=event_id,
                    triage_result=triage_result,
                    evidence_output=evidence_output,
                    rag_output=rag_output,
                    rag_degraded=rag_degraded,
                    risk_assessment=risk_assessment,
                    report=report,
                    final_verdict=final_verdict,
                    analysis_only_complete=True,
                    status=EventStatus.REPORTING,
                    disposition_policy="required",
                )

            await self._transition(
                event_id,
                EventStatus.CLOSED,
                context=TransitionContext(
                    need_investigation=triage_result.need_investigation,
                    recommendation=(
                        (fp_adjudication or {}).get("recommendation")
                        if isinstance(fp_adjudication, dict)
                        else None
                    ),
                ),
                reason=build_fp_close_reason(
                    await self._read_false_positive_match(event_id),
                    fp_adjudication=fp_adjudication,
                    default="analysis_pipeline:complete_not_required",
                ),
            )
            await self._persist_analysis_only_complete(event_id)
            # ISSUE-208: analysis-only auto-close — schedule full CLOSED
            # consolidation (history_case + fp_rule + profile).
            self._schedule_memory_after_close(event_id)
            return AnalysisOnlyPipelineResult(
                event_id=event_id,
                triage_result=triage_result,
                evidence_output=evidence_output,
                rag_output=rag_output,
                rag_degraded=rag_degraded,
                risk_assessment=risk_assessment,
                report=report,
                final_verdict=final_verdict,
                analysis_only_complete=True,
                status=EventStatus.CLOSED,
                disposition_policy="not_required",
            )

        await self._persist_analysis_only_complete(event_id)
        self._schedule_memory_after_analysis(event_id)
        return AnalysisOnlyPipelineResult(
            event_id=event_id,
            triage_result=triage_result,
            evidence_output=evidence_output,
            rag_output=rag_output,
            rag_degraded=rag_degraded,
            risk_assessment=risk_assessment,
            report=report,
            final_verdict=final_verdict,
            analysis_only_complete=True,
        )

    async def _transition(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: TransitionContext | None = None,
        reason: str | None = None,
    ) -> None:
        if self._state_machine is not None:
            await self._state_machine.transition(
                event_id,
                target,
                context=context,
                operator=_PIPELINE_OPERATOR,
                reason=reason or f"analysis_only:{target.value}",
            )
            return
        if self._event_service is None:
            return
        transition = getattr(self._event_service, "transition_status", None)
        if transition is None:
            return
        await transition(
            event_id,
            target,
            context=context,
            operator=_PIPELINE_OPERATOR,
            reason=reason or f"analysis_only:{target.value}",
        )

    async def _run_triage(self, event_id: str, event: Any) -> tuple[TriageResult, str]:
        raw_summary = f"{event.title}. {event.description}"
        triage_input = TriageAgentInput(
            event_id=event_id,
            raw_event_summary=raw_summary,
            hint_entities=event.entities,
        )
        result = await self._triage.execute(triage_input)
        if not isinstance(result, TriageResult):
            raise TypeError("TriageAgent must return TriageResult")
        return result, raw_summary

    async def _run_evidence(
        self,
        event_id: str,
        triage_result: TriageResult,
        *,
        alert_text: str = "",
    ) -> EvidenceOutput:
        evidence_input = EvidenceAgentInput(
            event_id=event_id,
            triage_result=triage_result,
            alert_text=alert_text,
        )
        output = await self._evidence.execute(evidence_input)
        if not isinstance(output, EvidenceOutput):
            raise TypeError("EvidenceAgent must return EvidenceOutput")
        return output

    async def _run_graph(
        self,
        event_id: str,
        evidence_output: EvidenceOutput,
    ) -> GraphOutput | None:
        if self._graph is None:
            return None
        try:
            output = await self._graph.execute(
                GraphAgentInput(event_id=event_id, evidence_output=evidence_output)
            )
        except Exception:
            logger.warning(
                "GraphAgent failed for event=%s; continuing without graph output",
                event_id,
                exc_info=True,
            )
            return None
        if not isinstance(output, GraphOutput):
            logger.warning(
                "GraphAgent returned unexpected type %s for event=%s; degrading",
                type(output).__name__,
                event_id,
            )
            return None
        return output

    async def _run_risk(
        self,
        event_id: str,
        triage_result: TriageResult,
        evidence_output: EvidenceOutput,
        rag_output: RAGOutput | None,
        graph_output: GraphOutput | None,
    ) -> RiskAssessment:
        risk_input = RiskAgentInput(
            event_id=event_id,
            triage_result=triage_result,
            evidence_output=evidence_output,
            rag_output=rag_output,
            graph_output=graph_output,
        )
        output = await self._risk.execute(risk_input)
        if not isinstance(output, RiskAssessment):
            raise TypeError("RiskAgent must return RiskAssessment")
        return output

    async def _run_report(
        self,
        event_id: str,
        evidence_output: EvidenceOutput,
        risk_assessment: RiskAssessment,
    ) -> InvestigationReport | None:
        # ISSUE-205: the analysis-only path never executes response/verify;
        # the shared builder backfills anything already persisted for this
        # event and otherwise reports the phases as NOT_EXECUTED (never the
        # silent 「暂无…」 placeholders).
        report_input = await build_report_agent_input(
            event_id,
            evidence_output=evidence_output,
            risk_assessment=risk_assessment,
            context_store=self._context_store,
            session_factory=self._session_factory,
        )
        report = await self._report.execute(report_input)
        if report is not None and not isinstance(report, InvestigationReport):
            raise TypeError("ReportAgent must return InvestigationReport or None")
        return report

    async def _generate_and_mark_report(
        self,
        event_id: str,
        evidence_output: EvidenceOutput,
        risk_assessment: RiskAssessment,
    ) -> InvestigationReport:
        """Run ReportAgent and persist success/failure observability (ISSUE-242)."""
        try:
            report = await self._run_report(event_id, evidence_output, risk_assessment)
            if report is None:
                raise ShadowTraceError(
                    "ReportAgent returned no report while generate_report=true",
                    error_code="report_generation_failed",
                    details={"event_id": event_id},
                )
            await self._persist_report_generated(event_id, True)
            return report
        except Exception as exc:
            await self._mark_report_generation_failed(event_id, exc)
            raise

    async def _persist_report_generated(self, event_id: str, generated: bool) -> None:
        if self._context_store is not None:
            try:
                await self._context_store.set(event_id, "report_generated", generated)
            except Exception:
                logger.warning(
                    "Failed to persist report_generated=%s for event=%s",
                    generated,
                    event_id,
                    exc_info=True,
                )
        # ISSUE-254: keep durable API snapshot aligned with WM flag (assists ISSUE-250).
        if self._event_service is not None:
            try:
                await self._event_service.merge_report_generated_context_snapshot(
                    event_id, generated
                )
            except Exception:
                logger.warning(
                    "Failed to merge report_generated snapshot for event=%s",
                    event_id,
                    exc_info=True,
                )

    async def _mark_report_generation_failed(self, event_id: str, exc: Exception) -> None:
        """Make generate_report=true failures observable (never silent REPORTING)."""
        await self._persist_report_generated(event_id, False)
        if self._degraded_flags is None:
            return
        try:
            await self._degraded_flags.set_flag(
                event_id,
                "report_generation_failed",
                type(exc).__name__,
                writer=_PIPELINE_OPERATOR,
            )
        except Exception:
            logger.warning(
                "AnalysisOnlyPipeline: failed to record report_generation_failed event=%s",
                event_id,
                exc_info=True,
            )

    async def _run_fp_adjudication(
        self,
        event_id: str,
        triage_result: TriageResult,
        evidence_output: EvidenceOutput,
        *,
        event: Any | None,
    ) -> dict[str, Any] | None:
        source_snapshot = None
        occurred_at = None
        if self._context_store is not None:
            source_snapshot = await self._context_store.get(event_id, "source_snapshot")
        if event is not None:
            occurred_at = getattr(event, "occurred_at", None)
        fp_wm = None
        if self._working_memory is not None:
            fp_wm = self._working_memory.for_writer("PostEvidenceFpAdjudicator")
        result = await run_post_evidence_fp_adjudication(
            event_id=event_id,
            evidence_output=evidence_output,
            triage_result=triage_result,
            source_snapshot=source_snapshot if isinstance(source_snapshot, dict) else None,
            occurred_at=occurred_at,
            working_memory=fp_wm,
        )
        return result.model_dump(mode="json")

    async def _read_false_positive_match(self, event_id: str) -> dict[str, Any] | None:
        if self._context_store is None:
            return None
        fp_match = await self._context_store.get(event_id, "false_positive_match")
        if isinstance(fp_match, dict):
            return fp_match
        return None

    async def _persist_report_skipped(self, event_id: str) -> None:
        await self._persist_report_generated(event_id, False)

    async def _evaluate_quality_scores(self, event_id: str) -> None:
        """Run OutputQualityEvaluator at pipeline completion (ISSUE-233)."""
        if self._output_quality_evaluator is None or self._context_store is None:
            return
        from app.services.output_quality_evaluator import evaluate_investigation_quality_scores

        try:
            context = await self._context_store.get_full_context(event_id)
            await evaluate_investigation_quality_scores(
                self._output_quality_evaluator,
                context,
            )
        except Exception:
            logger.warning(
                "AnalysisOnlyPipeline: quality evaluation failed for event=%s",
                event_id,
                exc_info=True,
            )

    async def _persist_analysis_only_complete(self, event_id: str) -> None:
        await self._evaluate_quality_scores(event_id)
        await persist_analysis_only_complete_authoritative(
            event_id,
            context_store=self._context_store,
            event_service=self._event_service,
            degraded_flags=self._degraded_flags,
            writer=_PIPELINE_OPERATOR,
            refresh_closed_snapshot=True,
        )

    def _schedule_memory_after_analysis(self, event_id: str) -> asyncio.Task[Any] | None:
        """Fire-and-forget profile-only early enqueue after analysis completion.

        ISSUE-208: REPORTING snapshot → MemoryAgent enqueues profile-only
        candidates (fp_rule / history_case still require CLOSED inside
        MemoryAgent). Failures never block the analysis pipeline.
        """
        return self._spawn_memory_task(event_id, EventStatus.REPORTING)

    def _schedule_memory_after_close(self, event_id: str) -> asyncio.Task[Any] | None:
        """Fire-and-forget full consolidation for analysis-only CLOSED events.

        ISSUE-208: the analysis-only pipeline owns its CLOSED transitions (short
        circuit / auto-close), so it must schedule the full MemoryAgent pass
        (history_case + fp_rule + profile) itself — SuperAgent's close hook does
        not run on this path.
        """
        return self._spawn_memory_task(event_id, EventStatus.CLOSED)

    def _spawn_memory_task(
        self,
        event_id: str,
        expected_status: EventStatus,
    ) -> asyncio.Task[Any] | None:
        if self._memory_agent is None or self._context_store is None or self._settings is None:
            return None
        # ISSUE-208 rollback: flag=false disables only the early (REPORTING)
        # enqueue; CLOSED consolidation always stays on (matches SuperAgent).
        if (
            expected_status is EventStatus.REPORTING
            and not self._settings.memory_enqueue_after_analysis
        ):
            return None
        task = asyncio.create_task(
            self._run_memory_consolidation(event_id, expected_status),
            name=f"memory-consolidation:{event_id}",
        )
        # Hold a strong reference so the task is never GC-dropped mid-await.
        self._memory_tasks.add(task)
        task.add_done_callback(self._memory_tasks.discard)
        return task

    async def _run_memory_consolidation(
        self,
        event_id: str,
        expected_status: EventStatus,
    ) -> None:
        """Best-effort MemoryAgent pass; knowledge failures degrade."""
        context_store = self._context_store
        memory_agent = self._memory_agent
        if context_store is None or memory_agent is None:
            return
        try:
            context = await context_store.get_full_context(event_id)
            if context.event is None or context.event.status is not expected_status:
                # Snapshot moved past the scheduled status (e.g. REPORTING was
                # closed meanwhile) — the current-status path owns consolidation.
                return
            # Lazy import: super_agent pulls heavy orchestration deps that
            # create a circular import at module load time.
            from app.agents.super_agent import _investigation_result_from_context

            result = _investigation_result_from_context(context)
            await memory_agent.execute(
                MemoryAgentInput(event_id=event_id, investigation_result=result)
            )
        except Exception as exc:
            flag_name = (
                "memory_after_analysis_failed"
                if expected_status is EventStatus.REPORTING
                else "memory_after_close_failed"
            )
            logger.warning(
                "AnalysisOnlyPipeline: memory consolidation failed event=%s flag=%s: %s",
                event_id,
                flag_name,
                exc,
            )
            if self._degraded_flags is not None:
                try:
                    await self._degraded_flags.set_flag(
                        event_id,
                        flag_name,
                        type(exc).__name__,
                        writer=_PIPELINE_OPERATOR,
                    )
                except Exception:
                    logger.warning(
                        "AnalysisOnlyPipeline: failed to record degraded flag event=%s",
                        event_id,
                        exc_info=True,
                    )

    async def _short_circuit_close(
        self,
        event_id: str,
        event: Any,
        triage_result: TriageResult,
        *,
        generate_report: bool = True,
    ) -> AnalysisOnlyPipelineResult:
        logger.info(
            "AnalysisOnlyPipeline: short-circuit close event=%s severity=%s generate_report=%s",
            event_id,
            triage_result.severity.value,
            generate_report,
        )

        placeholder_evidence = EvidenceOutput(
            evidence_list=[],
            conflicts=[],
            gaps=[],
            success_sources=[],
            failed_sources=[],
            overall_confidence=0.0,
            collection_status=CollectionStatus.COMPLETED,
        )
        placeholder_risk = RiskAssessment(
            risk_score=0,
            severity=triage_result.severity,
            confidence=0.9,
            risk_factors=[],
            possible_false_positive=True,
            scoring_mode=ScoringMode.RULE_ONLY,
        )

        fp_match = await self._read_false_positive_match(event_id)

        # ISSUE-204: optional report — skip ReportAgent and stay at REPORTING.
        if not generate_report:
            await self._persist_report_skipped(event_id)
            await self._persist_analysis_only_complete(event_id)
            await self._transition(
                event_id,
                EventStatus.REPORTING,
                context=TransitionContext(
                    need_investigation=False,
                    recommendation="low_risk_no_investigation",
                ),
                reason=build_fp_close_reason(
                    fp_match,
                    default="analysis_pipeline:short_circuit_no_report",
                ),
            )
            self._schedule_memory_after_analysis(event_id)
            return AnalysisOnlyPipelineResult(
                event_id=event_id,
                triage_result=triage_result,
                evidence_output=placeholder_evidence,
                rag_output=None,
                rag_degraded=False,
                risk_assessment=placeholder_risk,
                report=None,
                final_verdict=FinalVerdict.NONE,
                analysis_only_complete=True,
                status=EventStatus.REPORTING,
                disposition_policy="not_required",
                short_circuit=True,
            )

        report = await self._generate_and_mark_report(
            event_id,
            placeholder_evidence,
            placeholder_risk,
        )

        ctx = TransitionContext(
            need_investigation=False,
            recommendation="low_risk_no_investigation",
        )
        await self._persist_analysis_only_complete(event_id)
        await self._transition(
            event_id,
            EventStatus.CLOSED,
            context=ctx,
            reason=build_fp_close_reason(
                fp_match,
                default="analysis_pipeline:short_circuit_closed",
            ),
        )

        # ISSUE-208: short-circuit close — schedule full CLOSED consolidation.
        self._schedule_memory_after_close(event_id)
        return AnalysisOnlyPipelineResult(
            event_id=event_id,
            triage_result=triage_result,
            evidence_output=placeholder_evidence,
            rag_output=None,
            rag_degraded=False,
            risk_assessment=placeholder_risk,
            report=report,
            final_verdict=FinalVerdict.NONE,
            analysis_only_complete=True,
            status=EventStatus.CLOSED,
            disposition_policy="not_required",
            short_circuit=True,
        )


__all__ = [
    "AnalysisOnlyPipeline",
    "AnalysisOnlyPipelineResult",
    "assert_analysis_only_mode",
    "run_rag_stage",
]
