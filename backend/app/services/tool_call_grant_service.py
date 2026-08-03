"""ToolCallGrant persistence, validation, and atomic attempt ledger (ISSUE-134)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ToolCallGrantDeniedError, ToolCallGrantUnavailableError, ValidationError
from app.db import models as orm
from app.models.tool_call_grant import (
    TOOL_CALL_GRANT_SCHEMA_VERSION,
    ToolCallAttemptRecord,
    ToolCallAttemptStatus,
    ToolCallGrant,
    ToolCallGrantCreateRequest,
    ToolCallGrantIssueResult,
    ToolCallGrantScope,
    ToolCallMode,
)
from app.services.tool_call_budget_reservation import ToolCallBudgetReservationService
from app.services.tool_call_grant_resolver import (
    build_attempt_id,
    build_grant_id,
    build_namespace_key,
    build_react_idempotency_key,
    default_grant_window,
    grant_from_row,
    hash_grant_token,
    issue_grant_token,
    params_fingerprint,
)

logger = logging.getLogger(__name__)


class ToolCallGrantService:
    """Authoritative grant store with fail-closed validation."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        budget_reservation: ToolCallBudgetReservationService | None = None,
        available: bool = True,
    ) -> None:
        self._session_factory = session_factory
        self._budget_reservation = budget_reservation or ToolCallBudgetReservationService()
        self._available = available

    @property
    def available(self) -> bool:
        return self._available

    async def issue_grant(self, request: ToolCallGrantCreateRequest) -> ToolCallGrantIssueResult:
        if not self._available:
            raise ToolCallGrantUnavailableError(
                "tool call grant service unavailable",
                details={"reason": "service_disabled"},
            )
        if request.mode is ToolCallMode.COMPATIBILITY:
            raise ValidationError("compatibility mode grants are not issuable")

        valid_from, expires_at = default_grant_window(valid_for_seconds=request.valid_for_seconds)
        namespace_key = build_namespace_key(
            request.mode,
            event_id=request.event_id,
            shadow_run_id=request.shadow_run_id,
        )
        grant_token = issue_grant_token()
        grant_id = build_grant_id()

        row = orm.ToolCallGrantORM(
            grant_id=grant_id,
            mode=request.mode.value,
            namespace_key=namespace_key,
            shadow_run_id=request.shadow_run_id,
            event_id=request.event_id,
            plan_step_id=request.plan_step_id,
            task_id=request.task_id,
            tenant_id=request.tenant_id,
            scope=request.scope.model_dump(mode="json"),
            execution_principal=request.execution_principal.model_dump(mode="json"),
            max_calls=request.max_calls,
            attempt_count=0,
            valid_from=valid_from,
            expires_at=expires_at,
            policy_version=request.policy_version,
            schema_version=TOOL_CALL_GRANT_SCHEMA_VERSION,
            grant_token_hash=hash_grant_token(grant_token),
            idempotency_key=request.idempotency_key,
        )

        try:
            async with self._session_factory() as session:
                existing = await session.scalar(
                    select(orm.ToolCallGrantORM).where(
                        orm.ToolCallGrantORM.idempotency_key == request.idempotency_key
                    )
                )
                if existing is not None:
                    if existing.event_id != request.event_id:
                        raise ValidationError(
                            "idempotency_key reused for different event_id",
                            details={"idempotency_key": request.idempotency_key},
                        )
                    return ToolCallGrantIssueResult(
                        grant=grant_from_row(existing),
                        grant_token="",
                    )
                session.add(row)
                try:
                    await session.commit()
                except IntegrityError as exc:
                    await session.rollback()
                    replay = await session.scalar(
                        select(orm.ToolCallGrantORM).where(
                            orm.ToolCallGrantORM.idempotency_key == request.idempotency_key
                        )
                    )
                    if replay is not None:
                        return ToolCallGrantIssueResult(
                            grant=grant_from_row(replay),
                            grant_token="",
                        )
                    raise ValidationError("failed to issue tool call grant") from exc
                await session.refresh(row)
        except ValidationError:
            raise
        except SQLAlchemyError as exc:
            logger.exception("tool call grant issue persistence failed")
            raise ToolCallGrantUnavailableError(
                "tool call grant persistence unavailable",
                details={"reason": type(exc).__name__},
            ) from exc

        return ToolCallGrantIssueResult(grant=grant_from_row(row), grant_token=grant_token)

    async def load_grant(self, grant_id: str, *, grant_token: str) -> ToolCallGrant:
        if not self._available:
            raise ToolCallGrantUnavailableError(
                "tool call grant service unavailable",
                details={"grant_id": grant_id},
            )
        try:
            async with self._session_factory() as session:
                row = await session.get(orm.ToolCallGrantORM, grant_id)
                if row is None:
                    raise ToolCallGrantDeniedError(
                        "unknown grant_id",
                        details={"grant_id": grant_id},
                    )
                if row.grant_token_hash != hash_grant_token(grant_token):
                    raise ToolCallGrantDeniedError(
                        "grant token tampered or invalid",
                        details={"grant_id": grant_id, "reason": "token_mismatch"},
                    )
                return grant_from_row(row)
        except ToolCallGrantDeniedError:
            raise
        except SQLAlchemyError as exc:
            logger.exception("tool call grant load failed grant_id=%s", grant_id)
            raise ToolCallGrantUnavailableError(
                "tool call grant persistence unavailable",
                details={"grant_id": grant_id, "reason": type(exc).__name__},
            ) from exc

    async def load_grant_trusted(self, grant_id: str) -> ToolCallGrant:
        """Server-side grant reload for trusted wiring (no opaque token)."""

        if not self._available:
            raise ToolCallGrantUnavailableError(
                "tool call grant service unavailable",
                details={"grant_id": grant_id},
            )
        try:
            async with self._session_factory() as session:
                row = await session.get(orm.ToolCallGrantORM, grant_id)
                if row is None:
                    raise ToolCallGrantDeniedError(
                        "unknown grant_id",
                        details={"grant_id": grant_id},
                    )
                return grant_from_row(row)
        except ToolCallGrantDeniedError:
            raise
        except SQLAlchemyError as exc:
            logger.exception("tool call grant trusted load failed grant_id=%s", grant_id)
            raise ToolCallGrantUnavailableError(
                "tool call grant persistence unavailable",
                details={"grant_id": grant_id, "reason": type(exc).__name__},
            ) from exc

    async def reserve_attempt(
        self,
        grant_id: str,
        *,
        tool_name: str,
        params: dict[str, Any],
        event_id: str,
    ) -> tuple[ToolCallAttemptRecord, ToolCallGrant]:
        """Atomic reserve — denied/failed/timeout paths must still consume attempt."""

        grant = await self.load_grant_trusted(grant_id)
        self._assert_grant_live(grant, event_id=event_id)

        attempt_id = build_attempt_id()
        record = orm.ToolCallAttemptORM(
            attempt_id=attempt_id,
            grant_id=grant.grant_id,
            mode=grant.mode.value,
            namespace_key=grant.namespace_key,
            shadow_run_id=grant.shadow_run_id,
            event_id=event_id,
            tool_name=tool_name,
            attempt_seq=0,
            status=ToolCallAttemptStatus.RESERVED.value,
            params_hash=params_fingerprint(params),
        )

        try:
            async with self._session_factory() as session:
                updated = await session.execute(
                    update(orm.ToolCallGrantORM)
                    .where(
                        orm.ToolCallGrantORM.grant_id == grant.grant_id,
                        orm.ToolCallGrantORM.revoked_at.is_(None),
                        orm.ToolCallGrantORM.expires_at > datetime.now(tz=UTC),
                        orm.ToolCallGrantORM.valid_from <= datetime.now(tz=UTC),
                        orm.ToolCallGrantORM.attempt_count < orm.ToolCallGrantORM.max_calls,
                    )
                    .values(attempt_count=orm.ToolCallGrantORM.attempt_count + 1)
                    .returning(orm.ToolCallGrantORM.attempt_count)
                )
                attempt_seq = updated.scalar_one_or_none()
                if attempt_seq is None:
                    raise ToolCallGrantDeniedError(
                        "grant max_calls exhausted",
                        details={"grant_id": grant.grant_id, "max_calls": grant.max_calls},
                    )
                record.attempt_seq = int(attempt_seq)
                session.add(record)
                await session.commit()
                await session.refresh(record)
                fresh_row = await session.get(orm.ToolCallGrantORM, grant.grant_id)
                if fresh_row is None:
                    raise ToolCallGrantDeniedError(
                        "grant disappeared during reserve",
                        details={"grant_id": grant.grant_id},
                    )
                grant = grant_from_row(fresh_row)
        except ToolCallGrantDeniedError:
            raise
        except SQLAlchemyError as exc:
            logger.exception("tool call grant reserve persistence failed grant_id=%s", grant_id)
            raise ToolCallGrantUnavailableError(
                "tool call grant persistence unavailable",
                details={"grant_id": grant_id, "reason": type(exc).__name__},
            ) from exc

        try:
            reserved_seq = await self._budget_reservation.reserve(
                mode=grant.mode,
                namespace_key=grant.namespace_key,
                grant_id=grant.grant_id,
                max_calls=grant.max_calls,
            )
        except Exception as exc:
            await self._rollback_reserved_attempt(
                grant.grant_id,
                attempt_id,
                denial_reason="grant budget reservation failed",
            )
            if isinstance(exc, ValueError):
                raise ToolCallGrantDeniedError(
                    "grant max_calls exhausted",
                    details={"grant_id": grant.grant_id, "max_calls": grant.max_calls},
                ) from exc
            raise ToolCallGrantUnavailableError(
                "tool call grant budget reservation unavailable",
                details={"grant_id": grant.grant_id, "reason": type(exc).__name__},
            ) from exc

        if int(reserved_seq) != int(record.attempt_seq):
            await self._budget_reservation.release(
                mode=grant.mode,
                namespace_key=grant.namespace_key,
                grant_id=grant.grant_id,
            )
            await self._rollback_reserved_attempt(
                grant.grant_id,
                attempt_id,
                denial_reason="grant budget seq mismatch",
            )
            raise ToolCallGrantDeniedError(
                "grant budget seq mismatch",
                details={
                    "grant_id": grant.grant_id,
                    "reserved_seq": int(reserved_seq),
                    "authoritative_seq": int(record.attempt_seq),
                },
            )

        attempt_record = ToolCallAttemptRecord(
            attempt_id=record.attempt_id,
            grant_id=record.grant_id,
            mode=ToolCallMode(record.mode),
            namespace_key=record.namespace_key,
            shadow_run_id=record.shadow_run_id,
            event_id=record.event_id,
            tool_name=record.tool_name,
            attempt_seq=int(record.attempt_seq),
            status=ToolCallAttemptStatus.RESERVED,
            params_hash=record.params_hash,
            created_at=record.created_at,
        )
        return attempt_record, grant

    async def _rollback_reserved_attempt(
        self,
        grant_id: str,
        attempt_id: str,
        *,
        denial_reason: str,
    ) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(orm.ToolCallGrantORM)
                .where(
                    orm.ToolCallGrantORM.grant_id == grant_id,
                    orm.ToolCallGrantORM.attempt_count > 0,
                )
                .values(attempt_count=orm.ToolCallGrantORM.attempt_count - 1)
            )
            row = await session.get(orm.ToolCallAttemptORM, attempt_id)
            if row is not None:
                row.status = ToolCallAttemptStatus.DENIED.value
                row.denial_reason = denial_reason
            await session.commit()

    async def finalize_attempt(
        self,
        attempt_id: str,
        *,
        status: ToolCallAttemptStatus,
        denial_reason: str | None = None,
        result_status: str | None = None,
        projection_hash: str | None = None,
    ) -> None:
        async with self._session_factory() as session:
            row = await session.get(orm.ToolCallAttemptORM, attempt_id)
            if row is None:
                logger.warning("attempt_id=%s not found during finalize", attempt_id)
                return
            row.status = status.value
            row.denial_reason = denial_reason
            row.result_status = result_status
            row.projection_hash = projection_hash
            await session.commit()

    async def revoke_grant(self, grant_id: str) -> ToolCallGrant:
        async with self._session_factory() as session:
            row = await session.get(orm.ToolCallGrantORM, grant_id)
            if row is None:
                raise ToolCallGrantDeniedError("unknown grant_id", details={"grant_id": grant_id})
            row.revoked_at = datetime.now(tz=UTC)
            await session.commit()
            await session.refresh(row)
            return grant_from_row(row)

    async def count_attempts(self, grant_id: str) -> int:
        async with self._session_factory() as session:
            row = await session.get(orm.ToolCallGrantORM, grant_id)
            return int(row.attempt_count) if row is not None else 0

    async def count_production_attempts_for_event(self, event_id: str) -> int:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(orm.ToolCallAttemptORM).where(
                    orm.ToolCallAttemptORM.event_id == event_id,
                    orm.ToolCallAttemptORM.mode == ToolCallMode.PRODUCTION.value,
                )
            )
            return len(list(rows))

    async def count_production_grants_for_event(self, event_id: str) -> int:
        async with self._session_factory() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(orm.ToolCallGrantORM)
                .where(
                    orm.ToolCallGrantORM.event_id == event_id,
                    orm.ToolCallGrantORM.mode == ToolCallMode.PRODUCTION.value,
                )
            )
            return int(count or 0)

    def _assert_grant_live(self, grant: ToolCallGrant, *, event_id: str) -> None:
        now = datetime.now(tz=UTC)
        if grant.revoked_at is not None:
            raise ToolCallGrantDeniedError(
                "grant revoked",
                details={"grant_id": grant.grant_id},
            )
        if now < grant.valid_from:
            raise ToolCallGrantDeniedError(
                "grant not yet valid",
                details={"grant_id": grant.grant_id},
            )
        if now >= grant.expires_at:
            raise ToolCallGrantDeniedError(
                "grant expired",
                details={"grant_id": grant.grant_id},
            )
        if grant.event_id != event_id:
            raise ToolCallGrantDeniedError(
                "cross-event grant reuse denied",
                details={"grant_id": grant.grant_id, "expected_event_id": grant.event_id},
            )


def build_react_grant_request(
    *,
    event_id: str,
    tenant_id: str,
    allowed_tools: list[str],
    connector_ids: list[str] | None = None,
    max_calls: int = 32,
    shadow_run_id: str | None = None,
    mode: ToolCallMode = ToolCallMode.PRODUCTION,
    policy_version: str | None = None,
    plan_step_id: str | None = None,
    task_id: str | None = None,
) -> ToolCallGrantCreateRequest:
    from app.models.tool_call_grant import (
        DEFAULT_TOOL_CALL_GRANT_POLICY_VERSION,
        BoundExecutionPrincipal,
    )
    from app.services.tool_call_grant_resolver import build_principal_id

    principal_id = build_principal_id()
    return ToolCallGrantCreateRequest(
        mode=mode,
        shadow_run_id=shadow_run_id,
        event_id=event_id,
        plan_step_id=plan_step_id,
        task_id=task_id,
        tenant_id=tenant_id,
        scope=ToolCallGrantScope(
            allowed_tools=allowed_tools,
            connector_ids=list(connector_ids or []),
        ),
        execution_principal=BoundExecutionPrincipal(
            principal_id=principal_id,
            agent_name="react_engine",
            actor_type="react_engine",
        ),
        max_calls=max_calls,
        policy_version=policy_version or DEFAULT_TOOL_CALL_GRANT_POLICY_VERSION,
        idempotency_key=build_react_idempotency_key(
            event_id,
            plan_step_id=plan_step_id,
            allowed_tools=allowed_tools,
            max_calls=max_calls,
            shadow_run_id=shadow_run_id,
        ),
    )


__all__ = [
    "ToolCallGrantService",
    "build_react_grant_request",
]
