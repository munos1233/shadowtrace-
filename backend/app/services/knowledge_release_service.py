"""Knowledge release persistence — staged STIX import and CAS activation (ISSUE-128 / #634)."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.embedding.release import build_embedding_release
from app.core.errors import ResourceNotFoundError, ValidationError
from app.db import models as orm
from app.models.embedding import EmbeddingRelease
from app.models.knowledge import KnowledgeChunk
from app.models.knowledge_release import (
    ATTACK_CORPUS_ID,
    ATTACK_KB_NAME,
    ATTACK_SOURCE_ID,
    KnowledgeImportStatus,
    KnowledgeRelease,
    KnowledgeReleaseLifecycleState,
    KnowledgeReleaseProvenance,
)
from app.services.knowledge_release_resolver import (
    build_idempotency_key,
    build_knowledge_release,
    compute_object_hash,
    corpus_advisory_lock_key,
)
from app.services.knowledge_store import KnowledgeStore
from app.services.stix_bundle_validator import validate_stix_bundle

logger = logging.getLogger(__name__)


def _row_to_release(row: orm.KnowledgeReleaseORM) -> KnowledgeRelease:
    return KnowledgeRelease(
        release_id=row.release_id,
        corpus_id=row.corpus_id,
        source_id=row.source_id,
        release_version=row.release_version,
        content_hash=row.content_hash,
        provenance=KnowledgeReleaseProvenance.model_validate(row.provenance),
        schema_version=row.schema_version,
        import_status=KnowledgeImportStatus(row.import_status),
        lifecycle_state=KnowledgeReleaseLifecycleState(row.lifecycle_state),
        revision=int(row.revision),
        supersedes_release_id=row.supersedes_release_id,
        object_count=int(row.object_count),
        relationship_count=int(row.relationship_count),
        vector_ready=bool(row.vector_ready),
        embedding_release_id=row.embedding_release_id,
        idempotency_key=row.idempotency_key,
        activated_at=row.activated_at,
        retired_at=row.retired_at,
        created_at=row.created_at,
        failure_reason=row.failure_reason,
    )


def _extract_external_id(obj: dict[str, Any]) -> str | None:
    if obj.get("type") != "attack-pattern":
        return None
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") != "mitre-attack":
            continue
        external_id = ref.get("external_id")
        if isinstance(external_id, str) and external_id.startswith("T"):
            return external_id
    return None


def _attack_pattern_to_chunk(
    obj: dict[str, Any],
    *,
    release: KnowledgeRelease,
    embedding_release_id: str | None = None,
) -> KnowledgeChunk | None:
    external_id = _extract_external_id(obj)
    if external_id is None:
        return None
    attack_version = str(obj.get("x_shadowtrace_attack_version") or release.release_version)
    raw = f"technique_id:{external_id}:attack_version:{attack_version}:release:{release.release_id}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    chunk_id = f"atk-{digest}"
    tactics = []
    for phase in obj.get("kill_chain_phases") or []:
        if isinstance(phase, dict) and phase.get("phase_name"):
            tactics.append(str(phase["phase_name"]))
    description = str(obj.get("description") or "")
    detection = str(obj.get("x_mitre_detection") or "")
    lines = [
        f"Technique: {obj.get('name', '')}",
        f"ID: {external_id}",
        f"Tactics: {', '.join(tactics)}",
        f"Description: {description}",
    ]
    if detection:
        lines.append(f"Detection: {detection}")
    metadata: dict[str, Any] = {
        "technique_id": external_id,
        "technique_name": obj.get("name", ""),
        "tactics": tactics,
        "description": description,
        "detection": detection,
        "attack_version": attack_version,
        "corpus_id": release.corpus_id,
        "source_id": release.source_id,
        "release_id": release.release_id,
        "object_id": external_id,
        "stix_id": obj.get("id"),
        "content_type": "technique",
    }
    if embedding_release_id:
        metadata["embedding_release_id"] = embedding_release_id
    keywords = obj.get("x_shadowtrace_keywords")
    if isinstance(keywords, list):
        metadata["keywords"] = keywords
    aliases = obj.get("x_shadowtrace_aliases")
    if isinstance(aliases, list):
        metadata["aliases"] = aliases
    return KnowledgeChunk(
        chunk_id=chunk_id,
        kb_name=ATTACK_KB_NAME,
        content="\n".join(lines),
        metadata=metadata,
    )


class KnowledgeReleaseService:
    """Offline STIX release registry with staged import and atomic activation."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        store: KnowledgeStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._store = store
        self._settings = settings

    def _active_embedding_release(self) -> EmbeddingRelease:
        if self._settings is None:
            raise ValidationError(
                "embedding release validation requires settings",
                details={"reason": "settings_not_configured"},
            )
        return build_embedding_release(self._settings)

    async def get_release(self, release_id: str) -> KnowledgeRelease | None:
        async with self._session_factory() as session:
            row = await session.get(orm.KnowledgeReleaseORM, release_id)
            if row is None:
                return None
            return _row_to_release(row)

    async def get_active_release(self, corpus_id: str) -> KnowledgeRelease | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(orm.KnowledgeReleaseORM)
                .where(
                    and_(
                        orm.KnowledgeReleaseORM.corpus_id == corpus_id,
                        orm.KnowledgeReleaseORM.lifecycle_state
                        == KnowledgeReleaseLifecycleState.ACTIVE.value,
                    )
                )
                .limit(1)
            )
            if row is None:
                return None
            return _row_to_release(row)

    async def stage_stix_bundle(
        self,
        bundle: dict[str, Any],
        *,
        corpus_id: str = ATTACK_CORPUS_ID,
        source_id: str = ATTACK_SOURCE_ID,
        release_version: str,
        provenance: KnowledgeReleaseProvenance,
        supersedes_release_id: str | None = None,
        revision: int = 1,
    ) -> KnowledgeRelease:
        validation = validate_stix_bundle(bundle)
        if not validation.ok:
            raise ValidationError(
                "invalid STIX bundle",
                details={"errors": list(validation.errors)},
            )
        if validation.attack_pattern_count == 0:
            raise ValidationError(
                "STIX bundle must contain at least one attack-pattern",
                details={"object_count": validation.object_count},
            )

        idempotency_key = build_idempotency_key(
            corpus_id=corpus_id,
            content_hash=validation.content_hash,
        )
        async with self._session_factory() as session:
            async with session.begin():
                existing = await session.scalar(
                    select(orm.KnowledgeReleaseORM)
                    .where(orm.KnowledgeReleaseORM.idempotency_key == idempotency_key)
                    .limit(1)
                )
                if existing is not None:
                    await session.refresh(existing)
                    return _row_to_release(existing)

                release = build_knowledge_release(
                    corpus_id=corpus_id,
                    source_id=source_id,
                    release_version=release_version,
                    content_hash=validation.content_hash,
                    provenance=provenance,
                    object_count=validation.object_count,
                    relationship_count=validation.relationship_count,
                    revision=revision,
                    supersedes_release_id=supersedes_release_id,
                )
                row = orm.KnowledgeReleaseORM(
                    release_id=release.release_id,
                    corpus_id=release.corpus_id,
                    source_id=release.source_id,
                    release_version=release.release_version,
                    content_hash=release.content_hash,
                    provenance=release.provenance.model_dump(mode="json"),
                    schema_version=release.schema_version,
                    import_status=KnowledgeImportStatus.VALIDATED.value,
                    lifecycle_state=KnowledgeReleaseLifecycleState.STAGED.value,
                    revision=release.revision,
                    supersedes_release_id=supersedes_release_id,
                    object_count=release.object_count,
                    relationship_count=release.relationship_count,
                    vector_ready=False,
                    embedding_release_id=None,
                    idempotency_key=release.idempotency_key,
                )
                session.add(row)
                for obj in validation.objects:
                    stix_id = str(obj["id"])
                    object_row_id = f"kobj-{uuid.uuid4().hex[:16]}"
                    session.add(
                        orm.KnowledgeStixObjectORM(
                            object_row_id=object_row_id,
                            release_id=release.release_id,
                            stix_id=stix_id,
                            stix_type=str(obj["type"]),
                            external_id=_extract_external_id(obj),
                            object_hash=compute_object_hash(obj),
                            payload=obj,
                        )
                    )
                try:
                    await session.flush()
                except IntegrityError:
                    existing_after = await session.scalar(
                        select(orm.KnowledgeReleaseORM)
                        .where(orm.KnowledgeReleaseORM.idempotency_key == idempotency_key)
                        .limit(1)
                    )
                    if existing_after is not None:
                        await session.refresh(existing_after)
                        return _row_to_release(existing_after)
                    raise ValidationError(
                        "knowledge release already exists",
                        details={"idempotency_key": idempotency_key},
                    ) from None
                await session.refresh(row)
                return _row_to_release(row)

    async def mark_import_failed(
        self,
        *,
        corpus_id: str,
        content_hash: str,
        provenance: KnowledgeReleaseProvenance,
        release_version: str,
        reason: str,
    ) -> KnowledgeRelease:
        """Record a failed import without affecting the active release."""
        idempotency_key = build_idempotency_key(
            corpus_id=corpus_id,
            content_hash=content_hash,
        )
        release = build_knowledge_release(
            corpus_id=corpus_id,
            source_id=ATTACK_SOURCE_ID,
            release_version=release_version,
            content_hash=content_hash,
            provenance=provenance,
            object_count=0,
            relationship_count=0,
            lifecycle_state=KnowledgeReleaseLifecycleState.FAILED,
            import_status=KnowledgeImportStatus.FAILED,
        )
        async with self._session_factory() as session:
            async with session.begin():
                existing = await session.scalar(
                    select(orm.KnowledgeReleaseORM)
                    .where(orm.KnowledgeReleaseORM.idempotency_key == idempotency_key)
                    .limit(1)
                )
                if existing is not None:
                    await session.refresh(existing)
                    return _row_to_release(existing)

                row = orm.KnowledgeReleaseORM(
                    release_id=release.release_id,
                    corpus_id=release.corpus_id,
                    source_id=release.source_id,
                    release_version=release.release_version,
                    content_hash=release.content_hash,
                    provenance=release.provenance.model_dump(mode="json"),
                    schema_version=release.schema_version,
                    import_status=KnowledgeImportStatus.FAILED.value,
                    lifecycle_state=KnowledgeReleaseLifecycleState.FAILED.value,
                    revision=release.revision,
                    object_count=0,
                    relationship_count=0,
                    vector_ready=False,
                    embedding_release_id=None,
                    idempotency_key=release.idempotency_key,
                    failure_reason=reason,
                )
                session.add(row)
                try:
                    await session.flush()
                except IntegrityError:
                    existing_after = await session.scalar(
                        select(orm.KnowledgeReleaseORM)
                        .where(orm.KnowledgeReleaseORM.idempotency_key == idempotency_key)
                        .limit(1)
                    )
                    if existing_after is not None:
                        await session.refresh(existing_after)
                        return _row_to_release(existing_after)
                    raise
                await session.refresh(row)
                return _row_to_release(row)

    async def activate_release(
        self,
        release_id: str,
        *,
        vector_ready: bool = False,
        embedding_release_id: str | None = None,
    ) -> KnowledgeRelease:
        if vector_ready and not embedding_release_id:
            raise ValidationError(
                "vector_ready activation requires embedding_release_id",
                details={"release_id": release_id},
            )
        if vector_ready:
            active_release = self._active_embedding_release()
            if embedding_release_id != active_release.release_id:
                raise ValidationError(
                    "embedding release incompatible with active provider release",
                    details={
                        "requested": embedding_release_id,
                        "active": active_release.release_id,
                    },
                )

        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.KnowledgeReleaseORM,
                    release_id,
                    with_for_update=True,
                )
                if row is None:
                    raise ResourceNotFoundError(
                        "knowledge release not found",
                        details={"release_id": release_id},
                    )
                if row.lifecycle_state == KnowledgeReleaseLifecycleState.FAILED.value:
                    raise ValidationError(
                        "cannot activate a failed knowledge release",
                        details={"release_id": release_id},
                    )
                if row.lifecycle_state == KnowledgeReleaseLifecycleState.RETIRED.value:
                    raise ValidationError(
                        "cannot activate a retired knowledge release",
                        details={"release_id": release_id},
                    )
                if row.import_status != KnowledgeImportStatus.VALIDATED.value:
                    raise ValidationError(
                        "release import is not validated",
                        details={"release_id": release_id, "import_status": row.import_status},
                    )
                if row.lifecycle_state == KnowledgeReleaseLifecycleState.ACTIVE.value:
                    await session.refresh(row)
                    return _row_to_release(row)

                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {"lock_key": corpus_advisory_lock_key(row.corpus_id)},
                )

                active_rows = await session.scalars(
                    select(orm.KnowledgeReleaseORM)
                    .where(
                        and_(
                            orm.KnowledgeReleaseORM.corpus_id == row.corpus_id,
                            orm.KnowledgeReleaseORM.lifecycle_state
                            == KnowledgeReleaseLifecycleState.ACTIVE.value,
                            orm.KnowledgeReleaseORM.release_id != release_id,
                        )
                    )
                    .with_for_update()
                )
                for active in active_rows:
                    active.lifecycle_state = KnowledgeReleaseLifecycleState.RETIRED.value
                    active.retired_at = now

                await session.flush()

                row.lifecycle_state = KnowledgeReleaseLifecycleState.ACTIVE.value
                row.vector_ready = vector_ready
                row.embedding_release_id = embedding_release_id if vector_ready else None
                row.activated_at = now
                row.retired_at = None
                await session.flush()

                release = _row_to_release(row)
                if self._store is not None and release.corpus_id == ATTACK_CORPUS_ID:
                    await self._materialize_attack_chunks(session, release)

                await session.refresh(row)
                return _row_to_release(row)

    async def _materialize_attack_chunks(
        self,
        session: AsyncSession,
        release: KnowledgeRelease,
    ) -> None:
        if self._store is None:
            return
        rows = await session.scalars(
            select(orm.KnowledgeStixObjectORM).where(
                and_(
                    orm.KnowledgeStixObjectORM.release_id == release.release_id,
                    orm.KnowledgeStixObjectORM.stix_type == "attack-pattern",
                )
            )
        )
        chunks: list[KnowledgeChunk] = []
        embedding_id = release.embedding_release_id
        if embedding_id is None and self._settings is not None:
            embedding_id = build_embedding_release(self._settings).release_id
        for row in rows:
            chunk = _attack_pattern_to_chunk(
                row.payload,
                release=release,
                embedding_release_id=embedding_id,
            )
            if chunk is not None:
                chunks.append(chunk)
        if chunks and self._store is not None:
            batch_size = max(1, self._store._embed._settings.embedding_max_batch_size)
            for start in range(0, len(chunks), batch_size):
                batch = chunks[start : start + batch_size]
                await self._store.upsert_chunks(ATTACK_KB_NAME, batch, session=session)

    async def list_releases(
        self,
        *,
        corpus_id: str,
        lifecycle_state: KnowledgeReleaseLifecycleState | None = None,
        limit: int = 50,
    ) -> list[KnowledgeRelease]:
        async with self._session_factory() as session:
            query = select(orm.KnowledgeReleaseORM).where(
                orm.KnowledgeReleaseORM.corpus_id == corpus_id
            )
            if lifecycle_state is not None:
                query = query.where(
                    orm.KnowledgeReleaseORM.lifecycle_state == lifecycle_state.value
                )
            query = query.order_by(orm.KnowledgeReleaseORM.created_at.desc()).limit(limit)
            rows = await session.scalars(query)
            return [_row_to_release(row) for row in rows]


__all__ = [
    "KnowledgeReleaseService",
]
