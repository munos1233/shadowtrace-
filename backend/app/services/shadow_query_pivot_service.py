"""Shadow-isolated ReAct mock query pivot orchestrator (ISSUE-135 / #641 Phase A).

Runs a bounded observe→think→authorized query→reflect loop entirely inside the
shadow namespace. Production EventContext, decision_record, and grant ledgers
are never mutated.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from typing import Any

from app.core.config import Settings
from app.core.errors import ToolCallGrantUnavailableError
from app.core.llm.base import BaseLLMClient
from app.models.decision_record import DecisionRecord, DecisionStage
from app.models.react import ReActActionType, ReActRound, ReActStopReason
from app.models.shadow_run import (
    ShadowQueryArtifact,
    ShadowQueryArtifactKind,
    ShadowQueryPivotRequest,
    ShadowQueryPivotResult,
    ShadowRun,
    ShadowRunStatus,
)
from app.orchestration.react_engine import ReActEngine
from app.rag.pipeline import RetrievalPipeline
from app.services.knowledge_release_service import KnowledgeReleaseService
from app.services.react_mock_query_adapter import (
    MOCK_QUERY_AGENT_NAME,
    ReactMockQueryAdapter,
    ReactMockQueryContext,
    build_mock_query_agent_callable,
)
from app.services.shadow_run_service import ShadowRunService
from app.tools.tool_call_runtime import ReactToolExecutorFactory

logger = logging.getLogger(__name__)

_QUERY_INVOCATION_TYPES = frozenset({ReActActionType.CALL_TOOL, ReActActionType.CALL_AGENT})


def _record_hash(record: DecisionRecord) -> str:
    payload = record.model_dump(mode="json", exclude={"record_hash", "created_at"})
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_QUERY_SUCCESS_STATUSES = frozenset({"success", "ok"})


def _count_query_invocations(rounds: list[ReActRound]) -> int:
    return sum(
        1
        for round_ in rounds
        if round_.action is not None
        and round_.action.action_type in _QUERY_INVOCATION_TYPES
        and round_.action_result is not None
        and str(round_.action_result.get("status", "")).strip().lower() in _QUERY_SUCCESS_STATUSES
    )


class ShadowQueryPivotService:
    """Entry point for shadow-only mock query pivot runs."""

    def __init__(
        self,
        shadow_run_service: ShadowRunService,
        *,
        settings: Settings,
    ) -> None:
        self._shadow_runs = shadow_run_service
        self._settings = settings

    @classmethod
    def from_settings(
        cls,
        session_factory: Any,
        *,
        settings: Settings,
    ) -> ShadowQueryPivotService:
        return cls(
            ShadowRunService.from_settings(session_factory, settings),
            settings=settings,
        )

    async def run_pivot(
        self,
        request: ShadowQueryPivotRequest,
        *,
        llm_client: BaseLLMClient,
        react_factory: ReactToolExecutorFactory,
        pipeline: RetrievalPipeline,
        knowledge_release_service: KnowledgeReleaseService | None = None,
    ) -> ShadowQueryPivotResult:
        cfg = self._settings
        if not cfg.react_shadow_pivot_enabled:
            return ShadowQueryPivotResult(
                shadow_run_id="",
                status=ShadowRunStatus.REJECTED,
                rejected_reasons=["shadow_pivot_disabled"],
                degraded=True,
            )

        if not request.tenant_id.strip() or not request.principal.strip():
            return ShadowQueryPivotResult(
                shadow_run_id="",
                status=ShadowRunStatus.REJECTED,
                rejected_reasons=["missing_tenant_or_principal"],
                degraded=True,
            )

        if pipeline is None:
            return ShadowQueryPivotResult(
                shadow_run_id="",
                status=ShadowRunStatus.REJECTED,
                rejected_reasons=["retrieval_pipeline_unavailable"],
                degraded=True,
            )

        run = await self._shadow_runs.create_run(
            event_id=request.event_id,
            tenant_id=request.tenant_id,
            principal=request.principal,
            trigger="evidence_gap_pivot",
            max_steps=cfg.react_shadow_max_steps,
            max_tool_calls=cfg.react_shadow_max_tool_calls,
        )

        query_ctx = ReactMockQueryContext(
            event_id=request.event_id,
            tenant_id=request.tenant_id,
            principal=request.principal,
            trace_id=request.trace_id,
            shadow_run_id=run.shadow_run_id,
        )
        adapter = ReactMockQueryAdapter(
            pipeline,
            knowledge_release_service=knowledge_release_service,
            settings=cfg,
        )
        allowed_agents = {
            MOCK_QUERY_AGENT_NAME: build_mock_query_agent_callable(adapter, query_ctx),
        }

        try:
            react_exec = await react_factory.for_shadow_run(
                request.event_id,
                shadow_run_id=run.shadow_run_id,
                tenant_id=request.tenant_id,
                allowed_agents=allowed_agents,
                allowed_tools=request.allowed_query_tools or None,
                max_calls=cfg.react_shadow_max_tool_calls,
            )
        except ToolCallGrantUnavailableError as exc:
            await self._shadow_runs.finalize_run(
                run.shadow_run_id,
                status=ShadowRunStatus.REJECTED,
                step_count=0,
                tool_call_count=0,
                rejected_reasons=["grant_service_unavailable"],
                result_summary={"detail": str(exc)},
            )
            return ShadowQueryPivotResult(
                shadow_run_id=run.shadow_run_id,
                status=ShadowRunStatus.REJECTED,
                rejected_reasons=["grant_service_unavailable"],
                degraded=True,
            )

        context: dict[str, Any] = {
            "event_id": request.event_id,
            "tenant_id": request.tenant_id,
            "shadow_run_id": run.shadow_run_id,
            "gaps": "; ".join(request.evidence_gaps) or request.goal,
            "observation": request.observation[:2000],
        }

        engine = ReActEngine(
            llm_client,
            tool_call_budget=cfg.react_shadow_max_tool_calls,
            agent_name="shadow_query_pivot",
        )

        react_result = None
        try:
            react_result = await engine.run(
                request.goal,
                context,
                react_exec,
                max_rounds=cfg.react_shadow_max_steps,
            )

            artifacts = await self._persist_round_artifacts(run, react_result.rounds)
            record_ids = await self._persist_shadow_decision_records(
                run,
                request,
                react_result.rounds,
            )

            tool_calls = _count_query_invocations(react_result.rounds)
            status = ShadowRunStatus.COMPLETED
            if react_result.stop_reason is ReActStopReason.ERROR:
                status = ShadowRunStatus.FAILED

            finalized = await self._shadow_runs.finalize_run(
                run.shadow_run_id,
                status=status,
                step_count=len(react_result.rounds),
                tool_call_count=tool_calls,
                result_summary={
                    "stop_reason": react_result.stop_reason.value,
                    "confidence": react_result.final_confidence,
                    "artifact_count": len(artifacts),
                    "decision_record_count": len(record_ids),
                },
            )
            if finalized is None:
                return ShadowQueryPivotResult(
                    shadow_run_id=run.shadow_run_id,
                    status=ShadowRunStatus.FAILED,
                    rejected_reasons=["shadow_run_finalize_missing"],
                    degraded=True,
                )

            return ShadowQueryPivotResult(
                shadow_run_id=run.shadow_run_id,
                status=status,
                react_stop_reason=react_result.stop_reason.value,
                artifacts=artifacts,
                decision_record_ids=record_ids,
                degraded=status is not ShadowRunStatus.COMPLETED,
            )
        except Exception as exc:
            logger.exception(
                "shadow query pivot failed event=%s shadow_run=%s",
                request.event_id,
                run.shadow_run_id,
            )
            rounds = react_result.rounds if react_result is not None else []
            partial_artifacts: list[ShadowQueryArtifact] = []
            partial_record_ids: list[str] = []
            if rounds:
                try:
                    partial_artifacts = await self._persist_round_artifacts(run, rounds)
                    partial_record_ids = await self._persist_shadow_decision_records(
                        run,
                        request,
                        rounds,
                    )
                except Exception:
                    logger.exception(
                        "shadow pivot partial persistence failed event=%s shadow_run=%s",
                        request.event_id,
                        run.shadow_run_id,
                    )
            step_count = len(rounds)
            tool_calls = _count_query_invocations(rounds)
            await self._shadow_runs.finalize_run(
                run.shadow_run_id,
                status=ShadowRunStatus.FAILED,
                step_count=step_count,
                tool_call_count=tool_calls,
                rejected_reasons=["pivot_execution_error"],
                result_summary={
                    "detail": str(exc)[:512],
                    "partial_artifact_count": len(partial_artifacts),
                    "partial_decision_record_count": len(partial_record_ids),
                },
            )
            return ShadowQueryPivotResult(
                shadow_run_id=run.shadow_run_id,
                status=ShadowRunStatus.FAILED,
                rejected_reasons=["pivot_execution_error"],
                artifacts=partial_artifacts,
                decision_record_ids=partial_record_ids,
                degraded=True,
            )

    async def _persist_round_artifacts(
        self,
        run: ShadowRun,
        rounds: list[ReActRound],
    ) -> list[ShadowQueryArtifact]:
        artifacts: list[ShadowQueryArtifact] = []
        for round_ in rounds:
            action = round_.action
            if action is None:
                continue
            action_result = round_.action_result or {}
            if action.action_type is ReActActionType.CALL_AGENT:
                if action_result.get("status") == "success":
                    artifact = await self._shadow_runs.persist_artifact(
                        run,
                        kind=ShadowQueryArtifactKind.RETRIEVAL_HIT,
                        payload={
                            "round": round_.round_index,
                            "agent": action.target_name,
                            "chunk_count": action_result.get("data", {}).get("chunk_count", 0),
                            "plan_hash": action_result.get("data", {}).get("plan_hash", ""),
                            "chunks": action_result.get("data", {}).get("chunks", []),
                        },
                        provenance={"shadow_run_id": run.shadow_run_id},
                    )
                    artifacts.append(artifact)
            elif action.action_type is ReActActionType.CALL_TOOL:
                if action_result.get("status") in {"success", "ok"}:
                    artifact = await self._shadow_runs.persist_artifact(
                        run,
                        kind=ShadowQueryArtifactKind.TOOL_PROJECTION,
                        payload={
                            "round": round_.round_index,
                            "tool_name": action.target_name,
                            "projection_hash": action_result.get("projection_hash"),
                            "data": action_result.get("data", {}),
                        },
                        provenance={"shadow_run_id": run.shadow_run_id},
                    )
                    artifacts.append(artifact)
        if artifacts:
            summary = await self._shadow_runs.persist_artifact(
                run,
                kind=ShadowQueryArtifactKind.PIVOT_SUMMARY,
                payload={
                    "round_count": len(rounds),
                    "artifact_count": len(artifacts),
                },
                provenance={"shadow_run_id": run.shadow_run_id},
            )
            artifacts.append(summary)
        return artifacts

    async def _persist_shadow_decision_records(
        self,
        run: ShadowRun,
        request: ShadowQueryPivotRequest,
        rounds: list[ReActRound],
    ) -> list[str]:
        record_ids: list[str] = []
        for round_ in rounds:
            action = round_.action
            think_summary = round_.decision_summary[:512]
            if action is not None and action.target_name:
                think_summary = (
                    f"plan {action.action_type.value} {action.target_name}: "
                    f"{round_.decision_summary[:400]}"
                )[:512]

            think_id = f"sdr-{secrets.token_hex(4)}"
            think_key = f"shadow:{run.shadow_run_id}:think:round{round_.round_index}"
            think_record = DecisionRecord(
                record_id=think_id,
                event_id=request.event_id,
                stage=DecisionStage.REACT_THINK,
                actor="shadow_query_pivot",
                reason_codes=[round_.reason_code.value],
                decision_summary=think_summary,
                idempotency_key=think_key,
                retention_policy="shadow_pivot_v1",
                owner=run.namespace_key,
                selected={
                    "action_type": action.action_type.value if action else "",
                    "target_name": action.target_name if action else "",
                },
            )
            think_record = think_record.model_copy(
                update={"record_hash": _record_hash(think_record)}
            )
            record_ids.append(await self._shadow_runs.persist_decision_record(run, think_record))

            reflect_id = f"sdr-{secrets.token_hex(4)}"
            reflect_key = f"shadow:{run.shadow_run_id}:reflect:round{round_.round_index}"
            reflect_record = DecisionRecord(
                record_id=reflect_id,
                event_id=request.event_id,
                stage=DecisionStage.REACT_REFLECT,
                actor="shadow_query_pivot",
                reason_codes=[round_.gap_code.value],
                decision_summary=round_.decision_summary[:512],
                confidence=round_.confidence,
                uncertainty_codes=[round_.uncertainty_code.value],
                idempotency_key=reflect_key,
                retention_policy="shadow_pivot_v1",
                owner=run.namespace_key,
                selected={
                    "action_type": action.action_type.value if action else "",
                    "target_name": action.target_name if action else "",
                },
            )
            reflect_record = reflect_record.model_copy(
                update={"record_hash": _record_hash(reflect_record)}
            )
            record_ids.append(await self._shadow_runs.persist_decision_record(run, reflect_record))
        return record_ids


__all__ = ["ShadowQueryPivotService"]
