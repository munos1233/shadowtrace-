"""AgentTask coordination ledger — enqueue, claim, terminal transitions (ISSUE-133)."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import orjson
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import (
    AgentTaskDeniedError,
    AgentTaskUnavailableError,
    ToolCallGrantDeniedError,
    ValidationError,
)
from app.db import models as orm
from app.models.agent_task import (
    DEFAULT_TASK_LEASE_SECONDS,
    MAX_GOAL_PARAMETERS_BYTES,
    TERMINAL_AGENT_TASK_STATUSES,
    AgentTask,
    AgentTaskClaim,
    AgentTaskClaimRequest,
    AgentTaskEnqueueRequest,
    AgentTaskStatus,
    SideEffectStatus,
    validate_agent_task_transition,
)

logger = logging.getLogger(__name__)


class _ToolCallGrantPort(Protocol):
    async def load_grant(self, grant_id: str, *, grant_token: str) -> Any: ...


def new_task_id() -> str:
    return f"atk-{secrets.token_hex(8)}"


def new_attempt_id() -> str:
    return f"tatt-{secrets.token_hex(8)}"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def _goal_hash(goal: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(goal)).hexdigest()


def _task_from_row(row: orm.AgentTaskORM) -> AgentTask:
    return AgentTask.model_validate(
        {
            "task_id": row.task_id,
            "event_id": row.event_id,
            "tenant_id": row.tenant_id,
            "task_type": row.task_type,
            "goal": row.goal,
            "status": row.status,
            "revision": row.revision,
            "attempt": row.attempt,
            "claim_owner": row.claim_owner,
            "fencing_token": None,
            "lease_expires_at": row.lease_expires_at,
            "side_effect_status": row.side_effect_status,
            "idempotency_key": row.idempotency_key,
            "schema_version": row.schema_version,
            "last_error": row.last_error,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
    )


def _replay_or_deny(existing: orm.AgentTaskORM, request: AgentTaskEnqueueRequest) -> AgentTask:
    if existing.tenant_id != request.tenant_id:
        raise AgentTaskDeniedError(
            "cross-tenant idempotency key collision",
            details={
                "tenant_id": request.tenant_id,
                "idempotency_key": request.idempotency_key,
            },
        )
    if existing.event_id != request.event_id:
        raise AgentTaskDeniedError(
            "idempotency key replay event_id mismatch",
            details={
                "event_id": request.event_id,
                "existing_event_id": existing.event_id,
                "idempotency_key": request.idempotency_key,
            },
        )
    existing_goal = existing.goal if isinstance(existing.goal, dict) else {}
    request_goal = request.goal.model_dump(mode="json")
    if _goal_hash(existing_goal) != _goal_hash(request_goal):
        raise AgentTaskDeniedError(
            "idempotency key replay goal mismatch",
            details={
                "idempotency_key": request.idempotency_key,
                "event_id": request.event_id,
            },
        )
    return _task_from_row(existing)


class AgentTaskService:
    """Single coordinator for typed agent tasks (Phase A — Postgres ledger only)."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None,
        *,
        available: bool = True,
        grant_service: _ToolCallGrantPort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._available = available and session_factory is not None
        self._grant_service = grant_service

    async def enqueue(self, request: AgentTaskEnqueueRequest) -> AgentTask:
        self._require_available()
        param_bytes = len(_canonical_bytes(request.goal.parameters))
        if param_bytes > MAX_GOAL_PARAMETERS_BYTES:
            raise ValidationError(
                "task goal parameters exceed size limit",
                error_code="validation_error",
                details={"byte_size": param_bytes, "max_bytes": MAX_GOAL_PARAMETERS_BYTES},
            )

        task_id = new_task_id()
        now = datetime.now(tz=UTC)
        row = orm.AgentTaskORM(
            task_id=task_id,
            event_id=request.event_id,
            tenant_id=request.tenant_id,
            task_type=request.goal.task_type.value,
            goal=request.goal.model_dump(mode="json"),
            status=AgentTaskStatus.QUEUED.value,
            revision=1,
            attempt=0,
            side_effect_status=SideEffectStatus.NONE.value,
            idempotency_key=request.idempotency_key,
            schema_version=request.goal.schema_version,
            created_at=now,
            updated_at=now,
        )
        try:
            async with self._sessions()() as session:
                async with session.begin():
                    session.add(row)
        except IntegrityError:
            async with self._sessions()() as session:
                existing = await session.scalar(
                    select(orm.AgentTaskORM).where(
                        orm.AgentTaskORM.tenant_id == request.tenant_id,
                        orm.AgentTaskORM.idempotency_key == request.idempotency_key,
                    )
                )
                if existing is not None:
                    return _replay_or_deny(existing, request)
            raise
        except Exception as exc:
            logger.exception("AgentTask enqueue failed")
            raise AgentTaskUnavailableError(
                "task ledger persistence unavailable",
                details={"reason": str(exc)},
            ) from exc
        return _task_from_row(row)

    async def claim(self, request: AgentTaskClaimRequest) -> AgentTaskClaim:
        self._require_available()
        fencing_token = secrets.token_urlsafe(32)
        token_hash = _hash_token(fencing_token)
        now = datetime.now(tz=UTC)
        lease_expires = now + timedelta(seconds=request.lease_seconds)
        next_attempt = 0
        revision = 1

        async with self._sessions()() as session:
            async with session.begin():
                row = await session.get(orm.AgentTaskORM, request.task_id, with_for_update=True)
                if row is None:
                    raise AgentTaskDeniedError(
                        "unknown task_id",
                        details={"task_id": request.task_id},
                    )
                if row.tenant_id != request.tenant_id:
                    raise AgentTaskDeniedError(
                        "cross-tenant task claim denied",
                        details={"task_id": request.task_id},
                    )
                status = AgentTaskStatus(row.status)
                if status in TERMINAL_AGENT_TASK_STATUSES:
                    raise AgentTaskDeniedError(
                        "task already terminal",
                        details={"task_id": request.task_id, "status": status.value},
                    )
                if status is AgentTaskStatus.RUNNING:
                    raise AgentTaskDeniedError(
                        "task already running",
                        details={"task_id": request.task_id},
                    )
                if status is AgentTaskStatus.CLAIMED:
                    lease_valid = row.lease_expires_at is not None and row.lease_expires_at > now
                    if lease_valid and row.claim_owner != request.worker_principal:
                        raise AgentTaskDeniedError(
                            "task claimed by another worker",
                            details={"task_id": request.task_id, "claim_owner": row.claim_owner},
                        )
                    if lease_valid and row.claim_owner == request.worker_principal:
                        raise AgentTaskDeniedError(
                            "task already claimed by this worker",
                            details={"task_id": request.task_id},
                        )

                if status is not AgentTaskStatus.QUEUED and status is not AgentTaskStatus.CLAIMED:
                    raise AgentTaskDeniedError(
                        "task not claimable",
                        details={"task_id": request.task_id, "status": status.value},
                    )

                next_attempt = row.attempt + 1
                revision = row.revision
                validate_agent_task_transition(status, AgentTaskStatus.CLAIMED)
                row.status = AgentTaskStatus.CLAIMED.value
                row.attempt = next_attempt
                row.claim_owner = request.worker_principal
                row.fencing_token_hash = token_hash
                row.lease_expires_at = lease_expires
                row.updated_at = now
                session.add(
                    orm.AgentTaskAttemptORM(
                        attempt_id=new_attempt_id(),
                        task_id=row.task_id,
                        attempt_seq=next_attempt,
                        worker_principal=request.worker_principal,
                        status=AgentTaskStatus.CLAIMED.value,
                        fencing_token_hash=token_hash,
                        started_at=now,
                    )
                )

        return AgentTaskClaim(
            task_id=request.task_id,
            fencing_token=fencing_token,
            lease_expires_at=lease_expires,
            attempt=next_attempt,
            worker_principal=request.worker_principal,
            revision=revision,
        )

    async def start(
        self,
        claim: AgentTaskClaim,
        *,
        tenant_id: str,
        grant_token: str | None = None,
    ) -> AgentTask:
        await self._validate_bound_grant(claim, tenant_id=tenant_id, grant_token=grant_token)
        return await self._transition(
            claim,
            target=AgentTaskStatus.RUNNING,
            require_status={AgentTaskStatus.CLAIMED},
        )

    async def complete(self, claim: AgentTaskClaim) -> AgentTask:
        return await self._transition(
            claim,
            target=AgentTaskStatus.COMPLETED,
            require_status={AgentTaskStatus.RUNNING},
            terminal=True,
        )

    async def record_staged_artifact_hash(
        self,
        claim: AgentTaskClaim,
        *,
        tenant_id: str,
        logical_artifact_key: str,
        content_hash: str,
    ) -> None:
        """Persist execute-time content hash before artifact write (retry immutability)."""
        self._require_available()
        if len(content_hash) != 64:
            raise ValidationError(
                "staged artifact hash must be 64 hex chars",
                error_code="validation_error",
            )
        from app.services.playbook_approval_binding import STAGED_ARTIFACT_HASHES_KEY

        async with self._sessions()() as session:
            async with session.begin():
                row = await session.get(orm.AgentTaskORM, claim.task_id, with_for_update=True)
                if row is None:
                    raise AgentTaskDeniedError(
                        "unknown task_id", details={"task_id": claim.task_id}
                    )
                if row.tenant_id != tenant_id:
                    raise AgentTaskDeniedError(
                        "cross-tenant staged hash denied",
                        details={"task_id": claim.task_id},
                    )
                if AgentTaskStatus(row.status) is not AgentTaskStatus.RUNNING:
                    raise AgentTaskDeniedError(
                        "only running tasks may record staged artifact hash",
                        details={"task_id": claim.task_id},
                    )
                if row.attempt != claim.attempt:
                    raise AgentTaskDeniedError(
                        "stale worker: attempt mismatch",
                        details={"task_id": claim.task_id},
                    )
                goal = dict(row.goal)
                parameters = dict(goal.get("parameters") or {})
                staged = dict(parameters.get(STAGED_ARTIFACT_HASHES_KEY) or {})
                staged[logical_artifact_key] = content_hash
                parameters[STAGED_ARTIFACT_HASHES_KEY] = staged
                goal["parameters"] = parameters
                row.goal = goal
                row.updated_at = datetime.now(tz=UTC)

    async def fail(
        self,
        claim: AgentTaskClaim,
        *,
        error_summary: str,
        side_effect_unknown: bool = False,
    ) -> AgentTask:
        target = AgentTaskStatus.MANUAL if side_effect_unknown else AgentTaskStatus.FAILED
        return await self._transition(
            claim,
            target=target,
            require_status={AgentTaskStatus.RUNNING},
            terminal=True,
            error_summary=error_summary[:1024],
            side_effect_status=SideEffectStatus.UNKNOWN
            if side_effect_unknown
            else SideEffectStatus.NONE,
        )

    async def cancel(self, claim: AgentTaskClaim) -> AgentTask:
        return await self._transition(
            claim,
            target=AgentTaskStatus.CANCELLED,
            require_status={AgentTaskStatus.CLAIMED, AgentTaskStatus.RUNNING},
            terminal=True,
        )

    async def expire(self, claim: AgentTaskClaim) -> AgentTask:
        return await self._transition(
            claim,
            target=AgentTaskStatus.EXPIRED,
            require_status={AgentTaskStatus.CLAIMED, AgentTaskStatus.RUNNING},
            terminal=True,
        )

    async def mark_dead(self, claim: AgentTaskClaim, *, error_summary: str) -> AgentTask:
        return await self._transition(
            claim,
            target=AgentTaskStatus.DEAD,
            require_status={AgentTaskStatus.RUNNING},
            terminal=True,
            error_summary=error_summary[:1024],
        )

    async def expire_stale_claim(self, task_id: str, *, tenant_id: str) -> AgentTask:
        """Mark a lease-expired CLAIMED task as EXPIRED (coordinator sweeper)."""
        self._require_available()
        now = datetime.now(tz=UTC)
        async with self._sessions()() as session:
            async with session.begin():
                row = await session.get(orm.AgentTaskORM, task_id, with_for_update=True)
                if row is None:
                    raise AgentTaskDeniedError("unknown task_id", details={"task_id": task_id})
                if row.tenant_id != tenant_id:
                    raise AgentTaskDeniedError(
                        "cross-tenant expire denied", details={"task_id": task_id}
                    )
                status = AgentTaskStatus(row.status)
                if status is not AgentTaskStatus.CLAIMED:
                    raise AgentTaskDeniedError(
                        "only claimed tasks may expire via sweeper",
                        details={"task_id": task_id, "status": status.value},
                    )
                if row.lease_expires_at is None or row.lease_expires_at > now:
                    raise AgentTaskDeniedError(
                        "task lease has not expired",
                        details={"task_id": task_id},
                    )
                validate_agent_task_transition(status, AgentTaskStatus.EXPIRED)
                row.status = AgentTaskStatus.EXPIRED.value
                row.claim_owner = None
                row.fencing_token_hash = None
                row.lease_expires_at = None
                row.updated_at = now
        return _task_from_row(row)

    async def reconcile_stale_running(
        self,
        task_id: str,
        *,
        tenant_id: str,
        stale_after_seconds: int = DEFAULT_TASK_LEASE_SECONDS,
    ) -> AgentTask:
        """Mark a stale RUNNING task FAILED when worker heartbeat is lost (sweeper)."""
        self._require_available()
        now = datetime.now(tz=UTC)
        cutoff = now - timedelta(seconds=stale_after_seconds)
        async with self._sessions()() as session:
            async with session.begin():
                row = await session.get(orm.AgentTaskORM, task_id, with_for_update=True)
                if row is None:
                    raise AgentTaskDeniedError("unknown task_id", details={"task_id": task_id})
                if row.tenant_id != tenant_id:
                    raise AgentTaskDeniedError(
                        "cross-tenant reconcile denied", details={"task_id": task_id}
                    )
                status = AgentTaskStatus(row.status)
                if status is not AgentTaskStatus.RUNNING:
                    raise AgentTaskDeniedError(
                        "only running tasks may reconcile via stale sweeper",
                        details={"task_id": task_id, "status": status.value},
                    )
                if row.updated_at >= cutoff:
                    raise AgentTaskDeniedError(
                        "running task is not stale yet",
                        details={"task_id": task_id},
                    )
                row.status = AgentTaskStatus.FAILED.value
                row.claim_owner = None
                row.fencing_token_hash = None
                row.lease_expires_at = None
                row.last_error = "stale_running_sweeper"
                row.updated_at = now
        return _task_from_row(row)

    async def reconcile_completed_without_artifact(
        self,
        task_id: str,
        *,
        tenant_id: str,
    ) -> AgentTask:
        """Repair COMPLETED tasks that never persisted a logical artifact (sweeper)."""
        self._require_available()
        now = datetime.now(tz=UTC)
        async with self._sessions()() as session:
            async with session.begin():
                row = await session.get(orm.AgentTaskORM, task_id, with_for_update=True)
                if row is None:
                    raise AgentTaskDeniedError("unknown task_id", details={"task_id": task_id})
                if row.tenant_id != tenant_id:
                    raise AgentTaskDeniedError(
                        "cross-tenant reconcile denied", details={"task_id": task_id}
                    )
                status = AgentTaskStatus(row.status)
                if status is not AgentTaskStatus.COMPLETED:
                    raise AgentTaskDeniedError(
                        "only completed tasks may reconcile missing artifact",
                        details={"task_id": task_id, "status": status.value},
                    )
                row.status = AgentTaskStatus.FAILED.value
                row.claim_owner = None
                row.fencing_token_hash = None
                row.lease_expires_at = None
                row.last_error = "completed_without_artifact"
                row.updated_at = now
        return _task_from_row(row)

    async def retry_to_queue(self, task_id: str, *, tenant_id: str) -> AgentTask:
        """Re-queue a failed task when side effects are known-safe."""
        self._require_available()
        now = datetime.now(tz=UTC)
        async with self._sessions()() as session:
            async with session.begin():
                row = await session.get(orm.AgentTaskORM, task_id, with_for_update=True)
                if row is None:
                    raise AgentTaskDeniedError("unknown task_id", details={"task_id": task_id})
                if row.tenant_id != tenant_id:
                    raise AgentTaskDeniedError(
                        "cross-tenant retry denied", details={"task_id": task_id}
                    )
                status = AgentTaskStatus(row.status)
                if row.side_effect_status == SideEffectStatus.UNKNOWN.value:
                    raise AgentTaskDeniedError(
                        "side_effect unknown — manual resolution required",
                        details={"task_id": task_id},
                    )
                if status not in {AgentTaskStatus.FAILED, AgentTaskStatus.EXPIRED}:
                    raise AgentTaskDeniedError(
                        "only failed or expired tasks may retry",
                        details={"task_id": task_id, "status": status.value},
                    )
                validate_agent_task_transition(status, AgentTaskStatus.QUEUED, allow_retry=True)
                row.status = AgentTaskStatus.QUEUED.value
                row.claim_owner = None
                row.fencing_token_hash = None
                row.lease_expires_at = None
                row.revision += 1
                row.updated_at = now
        return _task_from_row(row)

    async def load_task(self, task_id: str, *, tenant_id: str) -> AgentTask:
        self._require_available()
        async with self._sessions()() as session:
            row = await session.get(orm.AgentTaskORM, task_id)
            if row is None:
                raise AgentTaskDeniedError("unknown task_id", details={"task_id": task_id})
            if row.tenant_id != tenant_id:
                raise AgentTaskDeniedError("cross-tenant read denied", details={"task_id": task_id})
            return _task_from_row(row)

    async def _transition(
        self,
        claim: AgentTaskClaim,
        *,
        target: AgentTaskStatus,
        require_status: set[AgentTaskStatus],
        terminal: bool = False,
        error_summary: str | None = None,
        side_effect_status: SideEffectStatus | None = None,
    ) -> AgentTask:
        self._require_available()
        now = datetime.now(tz=UTC)
        token_hash = _hash_token(claim.fencing_token)

        async with self._sessions()() as session:
            async with session.begin():
                row = await session.get(orm.AgentTaskORM, claim.task_id, with_for_update=True)
                if row is None:
                    raise AgentTaskDeniedError(
                        "unknown task_id", details={"task_id": claim.task_id}
                    )

                current = AgentTaskStatus(row.status)
                if current in TERMINAL_AGENT_TASK_STATUSES:
                    if current is target:
                        return _task_from_row(row)
                    raise AgentTaskDeniedError(
                        "terminal transition already recorded",
                        details={"task_id": claim.task_id, "status": current.value},
                    )

                if row.claim_owner != claim.worker_principal:
                    raise AgentTaskDeniedError(
                        "stale worker: claim_owner mismatch",
                        details={"task_id": claim.task_id},
                    )
                if row.fencing_token_hash != token_hash:
                    raise AgentTaskDeniedError(
                        "stale worker: fencing token mismatch",
                        details={"task_id": claim.task_id},
                    )
                if row.attempt != claim.attempt:
                    raise AgentTaskDeniedError(
                        "stale worker: attempt mismatch",
                        details={"task_id": claim.task_id, "expected_attempt": row.attempt},
                    )
                if claim.lease_expires_at < now and target is not AgentTaskStatus.EXPIRED:
                    raise AgentTaskDeniedError(
                        "task lease expired",
                        details={"task_id": claim.task_id},
                    )
                if current not in require_status:
                    raise AgentTaskDeniedError(
                        "invalid task status for transition",
                        details={
                            "task_id": claim.task_id,
                            "status": current.value,
                            "target": target.value,
                        },
                    )

                validate_agent_task_transition(current, target)
                row.status = target.value
                row.updated_at = now
                if terminal:
                    row.claim_owner = None
                    row.fencing_token_hash = None
                    row.lease_expires_at = None
                if error_summary:
                    row.last_error = error_summary
                if side_effect_status is not None:
                    row.side_effect_status = side_effect_status.value

                attempt_row = await session.scalar(
                    select(orm.AgentTaskAttemptORM)
                    .where(
                        orm.AgentTaskAttemptORM.task_id == claim.task_id,
                        orm.AgentTaskAttemptORM.attempt_seq == claim.attempt,
                    )
                    .limit(1)
                )
                if attempt_row is not None:
                    attempt_row.status = target.value
                    attempt_row.finished_at = now
                    attempt_row.error_summary = error_summary

        return _task_from_row(row)

    async def _validate_bound_grant(
        self,
        claim: AgentTaskClaim,
        *,
        tenant_id: str,
        grant_token: str | None,
    ) -> None:
        task = await self.load_task(claim.task_id, tenant_id=tenant_id)
        grant_id = task.goal.tool_call_grant_id
        if not grant_id:
            return
        if not grant_token:
            raise AgentTaskDeniedError(
                "bound tool call grant required",
                details={"task_id": claim.task_id, "grant_id": grant_id},
            )
        if self._grant_service is None:
            raise AgentTaskDeniedError(
                "grant service unavailable for bound task",
                details={"task_id": claim.task_id, "grant_id": grant_id},
            )
        try:
            grant = await self._grant_service.load_grant(grant_id, grant_token=grant_token)
        except ToolCallGrantDeniedError as exc:
            raise AgentTaskDeniedError(
                "forged or invalid tool call grant",
                details={"task_id": claim.task_id, "grant_id": grant_id},
            ) from exc
        if grant.event_id != task.event_id:
            raise AgentTaskDeniedError(
                "grant event_id mismatch",
                details={"task_id": claim.task_id, "grant_id": grant_id},
            )
        if grant.tenant_id != tenant_id:
            raise AgentTaskDeniedError(
                "grant tenant mismatch",
                details={"task_id": claim.task_id, "grant_id": grant_id},
            )
        if grant.task_id and grant.task_id != claim.task_id:
            raise AgentTaskDeniedError(
                "grant task_id mismatch",
                details={"task_id": claim.task_id, "grant_id": grant_id},
            )

    def _require_available(self) -> None:
        if not self._available:
            raise AgentTaskUnavailableError("task ledger persistence unavailable")

    def _sessions(self) -> async_sessionmaker[AsyncSession]:
        self._require_available()
        if self._session_factory is None:
            raise AgentTaskUnavailableError("task ledger persistence unavailable")
        return self._session_factory


__all__ = ["AgentTaskService", "new_attempt_id", "new_task_id"]
