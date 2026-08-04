"""Phase A coordinator hooks — enqueue typed tasks from existing pipelines (ISSUE-133)."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from app.core.errors import AgentTaskDeniedError, AgentTaskUnavailableError, ValidationError
from app.models.agent_io import ResponsePlan, RiskAssessment
from app.models.agent_task import (
    TERMINAL_AGENT_TASK_STATUSES,
    AgentArtifactPersistRequest,
    AgentTask,
    AgentTaskClaim,
    AgentTaskClaimRequest,
    AgentTaskContextRef,
    AgentTaskEnqueueRequest,
    AgentTaskGoal,
    AgentTaskStatus,
    AgentTaskType,
)
from app.services.agent_artifact_service import AgentArtifactService
from app.services.agent_task_service import AgentTaskService
from app.services.content_projection_service import ContentProjectionService
from app.services.playbook_approval_binding import (
    compute_response_plan_content_hash,
    staged_artifact_hash_from_parameters,
    validate_task_retry_preserves_plan_artifact,
)

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

RISK_SCORE_CONTEXT_REFS: list[AgentTaskContextRef] = [
    AgentTaskContextRef(ref_kind="event_context_field", ref_id="triage_result"),
    AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
    AgentTaskContextRef(ref_kind="event_context_field", ref_id="rag_output"),
    AgentTaskContextRef(ref_kind="event_context_field", ref_id="graph_output"),
]

RESPONSE_PLAN_CONTEXT_REFS: list[AgentTaskContextRef] = [
    AgentTaskContextRef(ref_kind="event_context_field", ref_id="risk_assessment"),
    AgentTaskContextRef(ref_kind="event_context_field", ref_id="evidence_output"),
    AgentTaskContextRef(ref_kind="artifact", ref_id="risk_assessment"),
]

_NON_RECOVERABLE_TERMINAL: frozenset[AgentTaskStatus] = frozenset(
    {
        AgentTaskStatus.MANUAL,
        AgentTaskStatus.DEAD,
        AgentTaskStatus.CANCELLED,
    }
)


async def enqueue_risk_score_task(
    agent_task_service: AgentTaskService | None,
    *,
    event_id: str,
    tenant_id: str,
    idempotency_key: str,
    parameters: dict[str, Any] | None = None,
) -> AgentTask | None:
    """Best-effort ledger enqueue before RiskAgent execution (Phase A boundary)."""
    if agent_task_service is None:
        return None
    try:
        return await agent_task_service.enqueue(
            AgentTaskEnqueueRequest(
                event_id=event_id,
                tenant_id=tenant_id,
                goal=AgentTaskGoal(
                    task_type=AgentTaskType.RISK_SCORE,
                    context_refs=list(RISK_SCORE_CONTEXT_REFS),
                    parameters=parameters or {},
                ),
                idempotency_key=idempotency_key,
            )
        )
    except AgentTaskUnavailableError:
        logger.warning(
            "AgentTask ledger unavailable; skipping risk_score enqueue for event=%s",
            event_id,
        )
        return None


def _build_risk_projection(
    content_projection_service: ContentProjectionService | None,
    projection_fields: dict[str, Any] | None,
) -> None:
    """Validate bounded context slice before RiskAgent execution (Phase A)."""
    if content_projection_service is None or not projection_fields:
        return
    content_projection_service.build(
        projection_kind="risk_score_context",
        raw_fields=projection_fields,
        source_refs=list(RISK_SCORE_CONTEXT_REFS),
    )


async def _maybe_requeue_recoverable(
    task: AgentTask, agent_task_service: AgentTaskService, *, tenant_id: str
) -> AgentTask:
    if task.status not in {AgentTaskStatus.FAILED, AgentTaskStatus.EXPIRED}:
        return task
    try:
        return await agent_task_service.retry_to_queue(task.task_id, tenant_id=tenant_id)
    except AgentTaskDeniedError:
        return task


async def _prepare_task_for_claim(
    task: AgentTask,
    agent_task_service: AgentTaskService,
    artifact_service: AgentArtifactService | None,
    *,
    tenant_id: str,
) -> AgentTask | RiskAssessment:
    """Resolve terminal/repair states before claim; return cached result when possible."""
    if task.status in _NON_RECOVERABLE_TERMINAL:
        raise AgentTaskDeniedError(
            "terminal task cannot re-execute",
            details={"task_id": task.task_id, "status": task.status.value},
        )

    if task.status is AgentTaskStatus.COMPLETED:
        cached = await _load_completed_risk_assessment(
            artifact_service,
            task=task,
            tenant_id=tenant_id,
        )
        if cached is not None:
            return cached
        logger.warning(
            "COMPLETED AgentTask missing risk_assessment artifact; reconciling task=%s",
            task.task_id,
        )
        await agent_task_service.reconcile_completed_without_artifact(
            task.task_id, tenant_id=tenant_id
        )
        return await agent_task_service.retry_to_queue(task.task_id, tenant_id=tenant_id)

    if task.status is AgentTaskStatus.RUNNING:
        try:
            task = await agent_task_service.reconcile_stale_running(
                task.task_id, tenant_id=tenant_id
            )
        except AgentTaskDeniedError:
            pass
        if task.status is AgentTaskStatus.RUNNING:
            raise AgentTaskDeniedError(
                "task already running",
                details={"task_id": task.task_id},
            )

    if task.status in TERMINAL_AGENT_TASK_STATUSES:
        task = await _maybe_requeue_recoverable(task, agent_task_service, tenant_id=tenant_id)
        if task.status in TERMINAL_AGENT_TASK_STATUSES:
            raise AgentTaskDeniedError(
                "terminal task cannot re-execute",
                details={"task_id": task.task_id, "status": task.status.value},
            )

    return task


async def _load_completed_risk_assessment(
    artifact_service: AgentArtifactService | None,
    *,
    task: AgentTask,
    tenant_id: str,
) -> RiskAssessment | None:
    if artifact_service is None:
        return None
    try:
        artifact = await artifact_service.load_latest(
            task_id=task.task_id,
            logical_artifact_key="risk_assessment",
            tenant_id=tenant_id,
        )
    except AgentTaskUnavailableError:
        return None
    if artifact is None:
        return None
    try:
        return RiskAssessment.model_validate(artifact.payload)
    except Exception:
        logger.warning(
            "Stored risk_assessment artifact invalid for task=%s",
            task.task_id,
            exc_info=True,
        )
        return None


async def _fail_claim_quietly(
    agent_task_service: AgentTaskService,
    claim: AgentTaskClaim,
    *,
    error_summary: str,
) -> None:
    try:
        await agent_task_service.fail(claim, error_summary=error_summary[:1024])
    except Exception:
        logger.warning(
            "AgentTask fail transition failed for task=%s",
            claim.task_id,
            exc_info=True,
        )


async def _fail_claim_manual(
    agent_task_service: AgentTaskService,
    claim: AgentTaskClaim,
    *,
    error_summary: str,
) -> None:
    """Mark task MANUAL after execute succeeded but ledger persistence failed."""
    try:
        await agent_task_service.fail(
            claim,
            error_summary=error_summary[:1024],
            side_effect_unknown=True,
        )
    except Exception:
        logger.warning(
            "AgentTask manual transition failed for task=%s",
            claim.task_id,
            exc_info=True,
        )


async def run_risk_score_with_ledger(
    agent_task_service: AgentTaskService | None,
    artifact_service: AgentArtifactService | None,
    *,
    event_id: str,
    tenant_id: str,
    worker_principal: str,
    idempotency_key: str,
    execute: Callable[[], Awaitable[_T]],
    parameters: dict[str, Any] | None = None,
    content_projection_service: ContentProjectionService | None = None,
    projection_fields: dict[str, Any] | None = None,
) -> _T:
    """Run RiskAgent under a synchronous claim→start→artifact→complete ledger cycle."""
    task = await enqueue_risk_score_task(
        agent_task_service,
        event_id=event_id,
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        parameters=parameters,
    )
    if agent_task_service is None or task is None:
        _build_risk_projection(content_projection_service, projection_fields)
        return await execute()

    prepared = await _prepare_task_for_claim(
        task,
        agent_task_service,
        artifact_service,
        tenant_id=tenant_id,
    )
    if isinstance(prepared, RiskAssessment):
        return prepared  # type: ignore[return-value]
    task = prepared

    try:
        claim = await agent_task_service.claim(
            AgentTaskClaimRequest(
                task_id=task.task_id,
                worker_principal=worker_principal,
                tenant_id=tenant_id,
            )
        )
        await agent_task_service.start(claim, tenant_id=tenant_id)
    except (AgentTaskDeniedError, AgentTaskUnavailableError) as exc:
        logger.warning(
            "AgentTask claim/start degraded for event=%s: %s",
            event_id,
            exc,
        )
        _build_risk_projection(content_projection_service, projection_fields)
        return await execute()

    _build_risk_projection(content_projection_service, projection_fields)
    try:
        result = await execute()
    except Exception as exc:
        await _fail_claim_quietly(
            agent_task_service,
            claim,
            error_summary=f"execute_failed: {exc.__class__.__name__}",
        )
        raise

    if artifact_service is None:
        await agent_task_service.complete(claim)
        return result

    payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
    if not isinstance(payload, dict):
        await _fail_claim_quietly(
            agent_task_service,
            claim,
            error_summary="artifact_persist_skipped: non-dict payload",
        )
        raise AgentTaskDeniedError(
            "artifact persist requires dict payload",
            details={"task_id": task.task_id},
        )

    try:
        await artifact_service.persist(
            claim,
            AgentArtifactPersistRequest(
                logical_artifact_key="risk_assessment",
                payload=payload,
                source_refs=list(RISK_SCORE_CONTEXT_REFS),
            ),
            tenant_id=tenant_id,
            event_id=event_id,
        )
    except ValidationError:
        await _fail_claim_quietly(
            agent_task_service,
            claim,
            error_summary="artifact_persist_validation_failed",
        )
        raise
    except Exception as exc:
        logger.warning(
            "AgentArtifact persist failed for event=%s task=%s",
            event_id,
            task.task_id,
            exc_info=True,
        )
        await _fail_claim_quietly(
            agent_task_service,
            claim,
            error_summary=f"artifact_persist_failed: {exc.__class__.__name__}",
        )
        raise AgentTaskDeniedError(
            "artifact persist failed",
            details={"task_id": task.task_id, "reason": exc.__class__.__name__},
        ) from exc

    await agent_task_service.complete(claim)
    return result


async def enqueue_response_plan_task(
    agent_task_service: AgentTaskService | None,
    *,
    event_id: str,
    tenant_id: str,
    idempotency_key: str,
    plan_revision: int,
    parameters: dict[str, Any] | None = None,
) -> AgentTask | None:
    """Best-effort ledger enqueue before ResponseAgent execution (ISSUE-139 Phase B)."""
    if agent_task_service is None:
        return None
    merged_parameters = {"plan_revision": plan_revision, **(parameters or {})}
    try:
        return await agent_task_service.enqueue(
            AgentTaskEnqueueRequest(
                event_id=event_id,
                tenant_id=tenant_id,
                goal=AgentTaskGoal(
                    task_type=AgentTaskType.RESPONSE_PLAN,
                    context_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
                    parameters=merged_parameters,
                ),
                idempotency_key=idempotency_key,
            )
        )
    except AgentTaskUnavailableError:
        logger.warning(
            "AgentTask ledger unavailable; skipping response_plan enqueue for event=%s",
            event_id,
        )
        return None


def _build_response_projection(
    content_projection_service: ContentProjectionService | None,
    projection_fields: dict[str, Any] | None,
) -> None:
    if content_projection_service is None or not projection_fields:
        return
    content_projection_service.build(
        projection_kind="response_plan_context",
        raw_fields=projection_fields,
        source_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
    )


async def _prepare_response_plan_task_for_claim(
    task: AgentTask,
    agent_task_service: AgentTaskService,
    artifact_service: AgentArtifactService | None,
    *,
    tenant_id: str,
) -> AgentTask | ResponsePlan:
    if task.status in _NON_RECOVERABLE_TERMINAL:
        raise AgentTaskDeniedError(
            "terminal task cannot re-execute",
            details={"task_id": task.task_id, "status": task.status.value},
        )

    if task.status is AgentTaskStatus.COMPLETED:
        cached = await _load_completed_response_plan(
            artifact_service,
            task=task,
            tenant_id=tenant_id,
        )
        if cached is not None:
            return cached
        logger.warning(
            "COMPLETED AgentTask missing response_plan artifact; reconciling task=%s",
            task.task_id,
        )
        await agent_task_service.reconcile_completed_without_artifact(
            task.task_id, tenant_id=tenant_id
        )
        return await agent_task_service.retry_to_queue(task.task_id, tenant_id=tenant_id)

    if task.status is AgentTaskStatus.RUNNING:
        try:
            task = await agent_task_service.reconcile_stale_running(
                task.task_id, tenant_id=tenant_id
            )
        except AgentTaskDeniedError:
            pass
        if task.status is AgentTaskStatus.RUNNING:
            raise AgentTaskDeniedError(
                "task already running",
                details={"task_id": task.task_id},
            )

    if task.status in TERMINAL_AGENT_TASK_STATUSES:
        task = await _maybe_requeue_recoverable(task, agent_task_service, tenant_id=tenant_id)
        if task.status in TERMINAL_AGENT_TASK_STATUSES:
            raise AgentTaskDeniedError(
                "terminal task cannot re-execute",
                details={"task_id": task.task_id, "status": task.status.value},
            )

    return task


async def _load_completed_response_plan(
    artifact_service: AgentArtifactService | None,
    *,
    task: AgentTask,
    tenant_id: str,
) -> ResponsePlan | None:
    if artifact_service is None:
        return None
    try:
        artifact = await artifact_service.load_latest(
            task_id=task.task_id,
            logical_artifact_key="response_plan",
            tenant_id=tenant_id,
        )
    except AgentTaskUnavailableError:
        return None
    if artifact is None:
        return None
    try:
        return ResponsePlan.model_validate(artifact.payload)
    except Exception:
        logger.warning(
            "Stored response_plan artifact invalid for task=%s",
            task.task_id,
            exc_info=True,
        )
        return None


async def run_response_plan_with_ledger(
    agent_task_service: AgentTaskService | None,
    artifact_service: AgentArtifactService | None,
    *,
    event_id: str,
    tenant_id: str,
    worker_principal: str,
    idempotency_key: str,
    plan_revision: int,
    execute: Callable[[], Awaitable[ResponsePlan]],
    parameters: dict[str, Any] | None = None,
    content_projection_service: ContentProjectionService | None = None,
    projection_fields: dict[str, Any] | None = None,
) -> ResponsePlan:
    """Run ResponseAgent under claim→start→artifact→complete with immutable plan refs."""
    task = await enqueue_response_plan_task(
        agent_task_service,
        event_id=event_id,
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        plan_revision=plan_revision,
        parameters=parameters,
    )
    if agent_task_service is None:
        _build_response_projection(content_projection_service, projection_fields)
        return await execute()
    if task is None:
        raise AgentTaskUnavailableError(
            "response_plan ledger enqueue unavailable",
            details={"event_id": event_id, "reason": "enqueue_failed"},
        )

    prepared = await _prepare_response_plan_task_for_claim(
        task,
        agent_task_service,
        artifact_service,
        tenant_id=tenant_id,
    )
    if isinstance(prepared, ResponsePlan):
        return prepared
    task = prepared

    try:
        claim = await agent_task_service.claim(
            AgentTaskClaimRequest(
                task_id=task.task_id,
                worker_principal=worker_principal,
                tenant_id=tenant_id,
            )
        )
        await agent_task_service.start(claim, tenant_id=tenant_id)
    except (AgentTaskDeniedError, AgentTaskUnavailableError) as exc:
        logger.warning(
            "AgentTask claim/start denied for response_plan event=%s: %s",
            event_id,
            exc,
        )
        raise

    # Ledger enqueue without artifact persistence would COMPLETE without an
    # immutable plan anchor, allowing content drift on later redelivery.
    if artifact_service is None:
        await _fail_claim_manual(
            agent_task_service,
            claim,
            error_summary="artifact_service_unavailable",
        )
        raise AgentTaskDeniedError(
            "response_plan requires artifact service when ledger is enabled",
            details={"task_id": task.task_id, "reason": "artifact_service_unavailable"},
        )

    prior_artifact = await artifact_service.load_latest(
        task_id=task.task_id,
        logical_artifact_key="response_plan",
        tenant_id=tenant_id,
    )
    staged_hash = staged_artifact_hash_from_parameters(task.goal.parameters, "response_plan")
    prior_hash = prior_artifact.content_hash if prior_artifact is not None else None
    anchor_hash = prior_hash or staged_hash
    replay_from_artifact = claim.revision > 1 and prior_artifact is not None

    if claim.revision > 1 and anchor_hash is not None and not replay_from_artifact:
        await _fail_claim_manual(
            agent_task_service,
            claim,
            error_summary="retry_staged_without_artifact",
        )
        raise ValidationError(
            "response plan retry requires persisted artifact anchor",
            error_code="validation_error",
            details={
                "reason": "staged_hash_without_artifact",
                "task_id": task.task_id,
                "task_revision": claim.revision,
            },
        )

    if replay_from_artifact:
        assert prior_artifact is not None
        plan = ResponsePlan.model_validate(prior_artifact.payload)
        payload = prior_artifact.payload
        content_hash = prior_artifact.content_hash
    else:
        _build_response_projection(content_projection_service, projection_fields)
        try:
            plan = await execute()
        except Exception as exc:
            await _fail_claim_quietly(
                agent_task_service,
                claim,
                error_summary=f"execute_failed: {exc.__class__.__name__}",
            )
            raise

        payload = plan.model_dump(mode="json")
        if not isinstance(payload, dict):
            await _fail_claim_manual(
                agent_task_service,
                claim,
                error_summary="artifact_persist_skipped: non-dict payload",
            )
            raise AgentTaskDeniedError(
                "artifact persist requires dict payload",
                details={"task_id": task.task_id},
            )

        content_hash = compute_response_plan_content_hash(payload)
        try:
            validate_task_retry_preserves_plan_artifact(
                prior_content_hash=prior_hash,
                staged_content_hash=staged_hash,
                new_payload=payload,
                task_revision=claim.revision,
            )
        except ValidationError:
            await _fail_claim_manual(
                agent_task_service,
                claim,
                error_summary="artifact_persist_validation_failed: plan_content_drift",
            )
            raise

    try:
        await agent_task_service.record_staged_artifact_hash(
            claim,
            tenant_id=tenant_id,
            logical_artifact_key="response_plan",
            content_hash=content_hash,
        )
    except ValidationError:
        await _fail_claim_manual(
            agent_task_service,
            claim,
            error_summary="artifact_stage_validation_failed",
        )
        raise
    except Exception as exc:
        logger.warning(
            "Staged artifact hash record failed for response_plan event=%s task=%s",
            event_id,
            task.task_id,
            exc_info=True,
        )
        await _fail_claim_manual(
            agent_task_service,
            claim,
            error_summary=f"artifact_stage_failed: {exc.__class__.__name__}",
        )
        raise AgentTaskDeniedError(
            "staged artifact hash record failed",
            details={"task_id": task.task_id, "reason": exc.__class__.__name__},
        ) from exc

    try:
        await artifact_service.persist(
            claim,
            AgentArtifactPersistRequest(
                logical_artifact_key="response_plan",
                payload=payload,
                source_refs=list(RESPONSE_PLAN_CONTEXT_REFS),
            ),
            tenant_id=tenant_id,
            event_id=event_id,
        )
    except ValidationError:
        await _fail_claim_manual(
            agent_task_service,
            claim,
            error_summary="artifact_persist_validation_failed",
        )
        raise
    except Exception as exc:
        logger.warning(
            "AgentArtifact persist failed for response_plan event=%s task=%s",
            event_id,
            task.task_id,
            exc_info=True,
        )
        await _fail_claim_manual(
            agent_task_service,
            claim,
            error_summary=f"artifact_persist_failed: {exc.__class__.__name__}",
        )
        raise AgentTaskDeniedError(
            "artifact persist failed",
            details={"task_id": task.task_id, "reason": exc.__class__.__name__},
        ) from exc

    await agent_task_service.complete(claim)
    return plan


__all__ = [
    "RESPONSE_PLAN_CONTEXT_REFS",
    "RISK_SCORE_CONTEXT_REFS",
    "enqueue_response_plan_task",
    "enqueue_risk_score_task",
    "run_response_plan_with_ledger",
    "run_risk_score_with_ledger",
]
