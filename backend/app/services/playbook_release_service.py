"""Playbook release persistence — staged JSON import and CAS activation (ISSUE-139 / #645)."""

from __future__ import annotations

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
from app.models.knowledge_release import (
    KnowledgeImportStatus,
    KnowledgeRelease,
    KnowledgeReleaseLifecycleState,
    KnowledgeReleaseProvenance,
)
from app.models.playbook import Playbook
from app.models.playbook_release import (
    PLAYBOOK_CORPUS_ID,
    PLAYBOOK_RELEASE_SCHEMA_VERSION,
    PLAYBOOK_SOURCE_ID,
    PlaybookRef,
    ResolvedPlaybook,
)
from app.services.knowledge_release_resolver import (
    build_knowledge_release,
    corpus_advisory_lock_key,
)
from app.services.knowledge_release_service import KnowledgeReleaseService
from app.services.playbook_kb_service import PlaybookKBService
from app.services.playbook_release_resolver import (
    build_playbook_idempotency_key,
    build_playbook_release_id,
    compute_playbook_object_hash,
    validate_playbook_bundle,
)

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


class PlaybookReleaseService:
    """Offline playbook bundle registry with staged import and atomic activation."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        playbook_kb: PlaybookKBService | None = None,
        settings: Settings | None = None,
        knowledge_release_service: KnowledgeReleaseService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._playbook_kb = playbook_kb
        self._settings = settings
        self._knowledge_release_service = knowledge_release_service or KnowledgeReleaseService(
            session_factory,
            store=playbook_kb.store if playbook_kb is not None else None,
            settings=settings,
        )

    async def get_release(self, release_id: str) -> KnowledgeRelease | None:
        release = await self._knowledge_release_service.get_release(release_id)
        if release is None or release.corpus_id != PLAYBOOK_CORPUS_ID:
            return None
        return release

    async def get_active_release(self) -> KnowledgeRelease | None:
        return await self._knowledge_release_service.get_active_release(PLAYBOOK_CORPUS_ID)

    async def stage_playbook_bundle(
        self,
        bundle: dict[str, Any],
        *,
        release_version: str,
        provenance: KnowledgeReleaseProvenance,
        supersedes_release_id: str | None = None,
        revision: int = 1,
    ) -> KnowledgeRelease:
        validation = validate_playbook_bundle(bundle)
        if not validation.ok:
            raise ValidationError(
                "invalid playbook bundle",
                details={"errors": list(validation.errors)},
            )

        idempotency_key = build_playbook_idempotency_key(
            content_hash=validation.content_hash,
            release_version=release_version,
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
                    corpus_id=PLAYBOOK_CORPUS_ID,
                    source_id=PLAYBOOK_SOURCE_ID,
                    release_version=release_version,
                    content_hash=validation.content_hash,
                    provenance=provenance,
                    object_count=validation.object_count,
                    relationship_count=0,
                    revision=revision,
                    supersedes_release_id=supersedes_release_id,
                    lifecycle_state=KnowledgeReleaseLifecycleState.STAGED,
                    import_status=KnowledgeImportStatus.VALIDATED,
                    vector_ready=False,
                    release_id=build_playbook_release_id(
                        validation.content_hash,
                        release_version,
                    ),
                    idempotency_key=idempotency_key,
                )
                row = orm.KnowledgeReleaseORM(
                    release_id=release.release_id,
                    corpus_id=release.corpus_id,
                    source_id=release.source_id,
                    release_version=release.release_version,
                    content_hash=release.content_hash,
                    provenance=release.provenance.model_dump(mode="json"),
                    schema_version=PLAYBOOK_RELEASE_SCHEMA_VERSION,
                    import_status=KnowledgeImportStatus.VALIDATED.value,
                    lifecycle_state=KnowledgeReleaseLifecycleState.STAGED.value,
                    revision=release.revision,
                    supersedes_release_id=supersedes_release_id,
                    object_count=release.object_count,
                    relationship_count=0,
                    vector_ready=False,
                    embedding_release_id=None,
                    idempotency_key=release.idempotency_key,
                )
                session.add(row)
                for playbook in validation.playbooks:
                    object_hash = compute_playbook_object_hash(playbook)
                    session.add(
                        orm.PlaybookReleaseObjectORM(
                            object_row_id=f"pobj-{uuid.uuid4().hex[:16]}",
                            release_id=release.release_id,
                            playbook_id=playbook.playbook_id,
                            object_hash=object_hash,
                            payload=playbook.model_dump(mode="json"),
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
                    raise
                await session.refresh(row)
                return _row_to_release(row)

    async def activate_release(self, release_id: str) -> KnowledgeRelease:
        if self._settings is None:
            raise ValidationError(
                "playbook activation requires settings",
                details={"reason": "settings_not_configured"},
            )
        embedding_release = build_embedding_release(self._settings)
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(
                    orm.KnowledgeReleaseORM,
                    release_id,
                    with_for_update=True,
                )
                if row is None or row.corpus_id != PLAYBOOK_CORPUS_ID:
                    raise ResourceNotFoundError(
                        "playbook release not found",
                        details={"release_id": release_id},
                    )
                if row.lifecycle_state == KnowledgeReleaseLifecycleState.FAILED.value:
                    raise ValidationError(
                        "cannot activate a failed playbook release",
                        details={"release_id": release_id},
                    )
                if row.lifecycle_state == KnowledgeReleaseLifecycleState.RETIRED.value:
                    raise ValidationError(
                        "cannot activate a retired playbook release",
                        details={"release_id": release_id},
                    )
                if row.import_status != KnowledgeImportStatus.VALIDATED.value:
                    raise ValidationError(
                        "playbook release import is not validated",
                        details={"release_id": release_id},
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
                            orm.KnowledgeReleaseORM.corpus_id == PLAYBOOK_CORPUS_ID,
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

                row.lifecycle_state = KnowledgeReleaseLifecycleState.ACTIVE.value
                row.vector_ready = True
                row.embedding_release_id = embedding_release.release_id
                row.activated_at = now
                row.retired_at = None
                await session.flush()

                release = _row_to_release(row)
                if self._playbook_kb is not None:
                    await self._playbook_kb.materialize_release(release, session=session)

                await session.refresh(row)
                return _row_to_release(row)

    async def resolve_playbook_ref(
        self,
        ref: PlaybookRef,
        *,
        allow_retired: bool = True,
    ) -> tuple[Playbook, KnowledgeRelease]:
        """Resolve an immutable ref to playbook + release; fail closed on mismatch."""
        if ref.corpus_id != PLAYBOOK_CORPUS_ID:
            raise ValidationError(
                "playbook ref corpus mismatch",
                details={"expected": PLAYBOOK_CORPUS_ID, "actual": ref.corpus_id},
            )
        release = await self.get_release(ref.release_id)
        if release is None:
            raise ValidationError(
                "playbook release not found",
                details={"release_id": ref.release_id, "reason": "release_missing"},
            )
        if ref.bundle_content_hash != release.content_hash:
            raise ValidationError(
                "playbook bundle hash mismatch",
                details={
                    "release_id": ref.release_id,
                    "expected": release.content_hash,
                    "actual": ref.bundle_content_hash,
                    "reason": "bundle_hash_mismatch",
                },
            )
        if ref.release_version != release.release_version:
            raise ValidationError(
                "playbook release version mismatch",
                details={
                    "release_id": ref.release_id,
                    "expected": release.release_version,
                    "actual": ref.release_version,
                    "reason": "release_version_mismatch",
                },
            )
        if release.lifecycle_state is KnowledgeReleaseLifecycleState.FAILED:
            raise ValidationError(
                "playbook release failed",
                details={"release_id": ref.release_id, "reason": "release_failed"},
            )
        if not allow_retired and release.lifecycle_state is KnowledgeReleaseLifecycleState.RETIRED:
            raise ValidationError(
                "playbook release retired",
                details={"release_id": ref.release_id, "reason": "release_retired"},
            )

        async with self._session_factory() as session:
            obj = await session.scalar(
                select(orm.PlaybookReleaseObjectORM).where(
                    and_(
                        orm.PlaybookReleaseObjectORM.release_id == ref.release_id,
                        orm.PlaybookReleaseObjectORM.playbook_id == ref.playbook_id,
                    )
                )
            )
        if obj is None:
            raise ValidationError(
                "playbook object not found in release",
                details={
                    "release_id": ref.release_id,
                    "playbook_id": ref.playbook_id,
                    "reason": "playbook_missing",
                },
            )
        if ref.content_hash != obj.object_hash:
            raise ValidationError(
                "playbook content hash mismatch",
                details={
                    "playbook_id": ref.playbook_id,
                    "expected": obj.object_hash,
                    "actual": ref.content_hash,
                    "reason": "content_hash_mismatch",
                },
            )
        playbook = Playbook.model_validate(obj.payload)
        return playbook, release

    async def build_ref_from_metadata(self, metadata: dict[str, Any]) -> PlaybookRef | None:
        playbook_id = metadata.get("playbook_id")
        release_id = metadata.get("release_id")
        if not isinstance(playbook_id, str) or not isinstance(release_id, str):
            return None
        content_hash = metadata.get("playbook_object_hash") or metadata.get("content_hash")
        bundle_hash = metadata.get("bundle_content_hash") or metadata.get("release_content_hash")
        release_version = metadata.get("release_version")
        if not (
            isinstance(content_hash, str)
            and content_hash
            and isinstance(bundle_hash, str)
            and bundle_hash
            and isinstance(release_version, str)
            and release_version
        ):
            return None
        lifecycle_raw = metadata.get("release_lifecycle_state")
        lifecycle = None
        if isinstance(lifecycle_raw, str) and lifecycle_raw:
            try:
                lifecycle = KnowledgeReleaseLifecycleState(lifecycle_raw)
            except ValueError:
                lifecycle = None
        revision_raw = metadata.get("revision", 1)
        revision = int(revision_raw) if isinstance(revision_raw, int) else 1
        return PlaybookRef(
            playbook_id=playbook_id,
            release_id=release_id,
            release_version=release_version,
            content_hash=content_hash,
            bundle_content_hash=bundle_hash,
            revision=revision,
            lifecycle_state=lifecycle,
        )

    async def describe_ref(self, ref: PlaybookRef) -> ResolvedPlaybook:
        playbook, release = await self.resolve_playbook_ref(ref, allow_retired=True)
        return ResolvedPlaybook(
            ref=ref,
            release_version=release.release_version,
            release_lifecycle_state=release.lifecycle_state,
            playbook_name=playbook.playbook_name,
            step_count=len(playbook.steps),
        )


__all__ = ["PlaybookReleaseService"]
