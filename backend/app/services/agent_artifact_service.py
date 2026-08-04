"""Immutable AgentArtifact persistence (ISSUE-133 / #639 Phase A)."""

from __future__ import annotations

import hashlib
import logging
import secrets
from typing import Any

import orjson
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import AgentTaskDeniedError, AgentTaskUnavailableError, ValidationError
from app.db import models as orm
from app.models.agent_task import (
    MAX_ARTIFACT_PAYLOAD_BYTES,
    AgentArtifact,
    AgentArtifactPersistRequest,
    AgentTaskClaim,
    AgentTaskStatus,
)

logger = logging.getLogger(__name__)


def new_artifact_id() -> str:
    return f"art-{secrets.token_hex(8)}"


def _canonical_bytes(value: Any) -> bytes:
    return orjson.dumps(value, option=orjson.OPT_SORT_KEYS)


def artifact_payload_content_hash(payload: dict[str, Any]) -> str:
    """Canonical SHA-256 for immutable artifact payloads (shared with approval binding)."""
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _content_hash(payload: dict[str, Any]) -> str:
    return artifact_payload_content_hash(payload)


def _validate_artifact_replay(existing: AgentArtifact, payload: dict[str, Any]) -> None:
    expected = _content_hash(payload)
    if existing.content_hash != expected:
        raise ValidationError(
            "artifact idempotent replay content_hash mismatch",
            error_code="validation_error",
            details={
                "logical_artifact_key": existing.logical_artifact_key,
                "expected_hash": expected,
                "stored_hash": existing.content_hash,
            },
        )


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _artifact_from_row(row: orm.AgentArtifactORM) -> AgentArtifact:
    return AgentArtifact.model_validate(
        {
            "artifact_id": row.artifact_id,
            "task_id": row.task_id,
            "event_id": row.event_id,
            "tenant_id": row.tenant_id,
            "logical_artifact_key": row.logical_artifact_key,
            "producer_revision": row.producer_revision,
            "producer_attempt": row.producer_attempt,
            "schema_version": row.schema_version,
            "content_hash": row.content_hash,
            "payload": row.payload,
            "source_refs": row.source_refs,
            "decision_record_refs": row.decision_record_refs,
            "created_at": row.created_at,
        }
    )


async def _load_existing_artifact(
    session: AsyncSession,
    *,
    task_id: str,
    logical_artifact_key: str,
    producer_revision: int,
) -> AgentArtifact | None:
    existing = await session.scalar(
        select(orm.AgentArtifactORM).where(
            orm.AgentArtifactORM.task_id == task_id,
            orm.AgentArtifactORM.logical_artifact_key == logical_artifact_key,
            orm.AgentArtifactORM.producer_revision == producer_revision,
        )
    )
    if existing is None:
        return None
    return _artifact_from_row(existing)


class AgentArtifactService:
    """Persist immutable artifacts with exactly-once logical identity."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None,
        *,
        available: bool = True,
    ) -> None:
        self._session_factory = session_factory
        self._available = available and session_factory is not None

    async def persist(
        self,
        claim: AgentTaskClaim,
        request: AgentArtifactPersistRequest,
        *,
        tenant_id: str,
        event_id: str,
    ) -> AgentArtifact:
        self._require_available()
        payload_bytes = len(_canonical_bytes(request.payload))
        if payload_bytes > MAX_ARTIFACT_PAYLOAD_BYTES:
            raise ValidationError(
                "artifact payload exceeds size limit",
                error_code="validation_error",
                details={"byte_size": payload_bytes, "max_bytes": MAX_ARTIFACT_PAYLOAD_BYTES},
            )

        token_hash = _hash_token(claim.fencing_token)
        content_hash = _content_hash(request.payload)
        artifact_id = new_artifact_id()
        row = orm.AgentArtifactORM(
            artifact_id=artifact_id,
            task_id=claim.task_id,
            event_id=event_id,
            tenant_id=tenant_id,
            logical_artifact_key=request.logical_artifact_key,
            producer_revision=claim.revision,
            producer_attempt=claim.attempt,
            schema_version=request.schema_version,
            content_hash=content_hash,
            payload=request.payload,
            source_refs=[ref.model_dump(mode="json") for ref in request.source_refs],
            decision_record_refs=list(request.decision_record_refs),
        )

        try:
            async with self._sessions()() as session:
                async with session.begin():
                    task_row = await session.get(
                        orm.AgentTaskORM, claim.task_id, with_for_update=True
                    )
                    if task_row is None:
                        raise AgentTaskDeniedError(
                            "unknown task_id",
                            details={"task_id": claim.task_id},
                        )
                    if task_row.tenant_id != tenant_id:
                        raise AgentTaskDeniedError(
                            "cross-tenant artifact write denied",
                            details={"task_id": claim.task_id},
                        )
                    if task_row.event_id != event_id:
                        raise AgentTaskDeniedError(
                            "artifact event_id mismatch",
                            details={"task_id": claim.task_id, "event_id": event_id},
                        )
                    status = AgentTaskStatus(task_row.status)
                    if status is not AgentTaskStatus.RUNNING:
                        raise AgentTaskDeniedError(
                            "artifact write requires running task",
                            details={"task_id": claim.task_id, "status": status.value},
                        )
                    if task_row.claim_owner != claim.worker_principal:
                        raise AgentTaskDeniedError(
                            "stale worker: claim_owner mismatch",
                            details={"task_id": claim.task_id},
                        )
                    if task_row.fencing_token_hash != token_hash:
                        raise AgentTaskDeniedError(
                            "stale worker: fencing token mismatch",
                            details={"task_id": claim.task_id},
                        )
                    if task_row.attempt != claim.attempt:
                        raise AgentTaskDeniedError(
                            "stale worker: attempt mismatch",
                            details={
                                "task_id": claim.task_id,
                                "expected_attempt": task_row.attempt,
                            },
                        )

                    existing = await _load_existing_artifact(
                        session,
                        task_id=claim.task_id,
                        logical_artifact_key=request.logical_artifact_key,
                        producer_revision=claim.revision,
                    )
                    if existing is not None:
                        _validate_artifact_replay(existing, request.payload)
                        return existing

                    session.add(row)
        except IntegrityError:
            async with self._sessions()() as session:
                existing = await _load_existing_artifact(
                    session,
                    task_id=claim.task_id,
                    logical_artifact_key=request.logical_artifact_key,
                    producer_revision=claim.revision,
                )
                if existing is not None:
                    _validate_artifact_replay(existing, request.payload)
                    return existing
            raise

        return _artifact_from_row(row)

    async def load_latest(
        self,
        *,
        task_id: str,
        logical_artifact_key: str,
        tenant_id: str,
    ) -> AgentArtifact | None:
        """Return the newest artifact revision for a task/logical key."""
        self._require_available()
        async with self._sessions()() as session:
            row = await session.scalar(
                select(orm.AgentArtifactORM)
                .where(
                    orm.AgentArtifactORM.task_id == task_id,
                    orm.AgentArtifactORM.logical_artifact_key == logical_artifact_key,
                    orm.AgentArtifactORM.tenant_id == tenant_id,
                )
                .order_by(orm.AgentArtifactORM.producer_revision.desc())
                .limit(1)
            )
            if row is None:
                return None
            return _artifact_from_row(row)

    def _require_available(self) -> None:
        if not self._available:
            raise AgentTaskUnavailableError("artifact ledger persistence unavailable")

    def _sessions(self) -> async_sessionmaker[AsyncSession]:
        self._require_available()
        if self._session_factory is None:
            raise AgentTaskUnavailableError("artifact ledger persistence unavailable")
        return self._session_factory


__all__ = ["AgentArtifactService", "artifact_payload_content_hash", "new_artifact_id"]
