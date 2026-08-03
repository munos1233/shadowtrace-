"""PlaybookKBService: SOAR playbook knowledge base operations (ISSUE-044, ISSUE-139)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.knowledge import GLOBAL_KB_TENANT_ID, KnowledgeChunk
from app.models.knowledge_release import KnowledgeRelease
from app.models.playbook import Playbook, PlaybookStep
from app.models.playbook_release import PLAYBOOK_KB_NAME, PlaybookRef
from app.services.knowledge_store import KnowledgeStore
from app.services.playbook_release_resolver import (
    _validate_steps,
    compute_playbook_object_hash,
)

KB_NAME = PLAYBOOK_KB_NAME
_SEVERITY_ORDINAL: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _derive_chunk_id(playbook_key: str) -> str:
    digest = hashlib.sha256(f"playbook:{playbook_key}".encode()).hexdigest()[:16]
    return f"pbk-{digest}"


def _severity_ordinal(severity: str) -> int:
    return _SEVERITY_ORDINAL.get(severity, 99)


def _meta_matches_filters(meta: dict[str, Any], event_type: str, query_ordinal: int) -> bool:
    if meta.get("event_type") != event_type:
        return False
    return _severity_ordinal(str(meta.get("min_severity", ""))) <= query_ordinal


def _playbook_from_metadata(meta: dict[str, Any]) -> Playbook:
    steps_raw = meta.get("steps", [])
    steps = [PlaybookStep.model_validate(s) for s in steps_raw]
    return Playbook(
        playbook_id=meta["playbook_id"],
        playbook_name=meta["playbook_name"],
        event_type=meta["event_type"],
        min_severity=meta["min_severity"],
        description=meta.get("description", ""),
        steps=steps,
    )


def _format_content(pb: Playbook) -> str:
    step_names = "; ".join(s.action_name for s in pb.steps)
    return (
        f"Playbook: {pb.playbook_name}\n"
        f"Event Type: {pb.event_type.value}\n"
        f"Min Severity: {pb.min_severity.value}\n"
        f"Description: {pb.description}\n"
        f"Steps: {step_names}"
    )


def _chunk_metadata(
    pb: Playbook,
    *,
    release: KnowledgeRelease,
) -> dict[str, Any]:
    object_hash = compute_playbook_object_hash(pb)
    return {
        "tenant_id": GLOBAL_KB_TENANT_ID,
        "playbook_id": pb.playbook_id,
        "playbook_name": pb.playbook_name,
        "event_type": pb.event_type.value,
        "min_severity": pb.min_severity.value,
        "description": pb.description,
        "steps": [s.model_dump(mode="json") for s in pb.steps],
        "release_id": release.release_id,
        "release_version": release.release_version,
        "bundle_content_hash": release.content_hash,
        "playbook_object_hash": object_hash,
        "revision": release.revision,
        "corpus_id": release.corpus_id,
        "release_lifecycle_state": release.lifecycle_state.value,
        "schema_version": release.schema_version,
    }


def _playbook_chunk(
    pb: Playbook,
    *,
    release: KnowledgeRelease,
) -> KnowledgeChunk:
    return KnowledgeChunk(
        chunk_id=_derive_chunk_id(f"{release.release_id}:{pb.playbook_id}"),
        kb_name=KB_NAME,
        content=_format_content(pb),
        metadata=_chunk_metadata(pb, release=release),
    )


def playbook_ref_from_metadata(metadata: dict[str, Any]) -> PlaybookRef | None:
    playbook_id = metadata.get("playbook_id")
    release_id = metadata.get("release_id")
    if not isinstance(playbook_id, str) or not isinstance(release_id, str):
        return None
    content_hash = metadata.get("playbook_object_hash") or metadata.get("content_hash")
    bundle_hash = metadata.get("bundle_content_hash") or metadata.get("release_content_hash")
    release_version = metadata.get("release_version")
    if not all(
        isinstance(value, str) and value for value in (content_hash, bundle_hash, release_version)
    ):
        return None
    revision_raw = metadata.get("revision", 1)
    revision = int(revision_raw) if isinstance(revision_raw, int) else 1
    return PlaybookRef(
        playbook_id=playbook_id,
        release_id=release_id,
        release_version=release_version,
        content_hash=content_hash,
        bundle_content_hash=bundle_hash,
        revision=revision,
    )


class PlaybookKBService:
    """Manage the SOAR playbook knowledge base.

    Production paths require release-pinned chunks with immutable refs (#645).
    Playbook corpus is organization-global: materialized chunks use
    ``GLOBAL_KB_TENANT_ID`` so strict tenant isolation still retrieves them.
    Legacy file loads remain for tests and offline bootstrap only.
    """

    def __init__(
        self,
        store: KnowledgeStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._store = store
        self._session_factory = session_factory

    @property
    def store(self) -> KnowledgeStore:
        return self._store

    async def load_from_file(self, path: str | Path) -> int:
        """Load playbooks from a JSON file without release pinning (legacy/test path)."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        raw_playbooks: list[dict[str, Any]] = data["playbooks"]

        playbooks: list[Playbook] = []
        for raw in raw_playbooks:
            pb = Playbook.model_validate(raw)
            _validate_steps(pb.steps, pb.playbook_id, pb.event_type)
            playbooks.append(pb)

        chunks: list[KnowledgeChunk] = []
        for pb in playbooks:
            chunks.append(
                KnowledgeChunk(
                    chunk_id=_derive_chunk_id(pb.playbook_id),
                    kb_name=KB_NAME,
                    content=_format_content(pb),
                    metadata={
                        "playbook_id": pb.playbook_id,
                        "playbook_name": pb.playbook_name,
                        "event_type": pb.event_type.value,
                        "min_severity": pb.min_severity.value,
                        "description": pb.description,
                        "steps": [s.model_dump(mode="json") for s in pb.steps],
                    },
                )
            )

        await self._store.upsert_chunks(KB_NAME, chunks)
        return len(chunks)

    async def materialize_release(
        self,
        release: KnowledgeRelease,
        *,
        session: AsyncSession | None = None,
    ) -> int:
        """Upsert release-pinned playbook chunks from staged release objects."""
        from app.db import models as orm

        if session is not None:
            rows = await session.scalars(
                select(orm.PlaybookReleaseObjectORM).where(
                    orm.PlaybookReleaseObjectORM.release_id == release.release_id
                )
            )
            playbooks = [Playbook.model_validate(row.payload) for row in rows]
            chunks = [_playbook_chunk(pb, release=release) for pb in playbooks]
            if chunks:
                await self._store.upsert_chunks(KB_NAME, chunks, session=session)
            return len(chunks)

        async with self._session_factory() as owned_session:
            async with owned_session.begin():
                rows = await owned_session.scalars(
                    select(orm.PlaybookReleaseObjectORM).where(
                        orm.PlaybookReleaseObjectORM.release_id == release.release_id
                    )
                )
                playbooks = [Playbook.model_validate(row.payload) for row in rows]
                chunks = [_playbook_chunk(pb, release=release) for pb in playbooks]
                if chunks:
                    await self._store.upsert_chunks(KB_NAME, chunks, session=owned_session)
                return len(chunks)

    async def get_playbook_by_ref(
        self,
        ref: PlaybookRef,
        *,
        release_id: str | None = None,
    ) -> Playbook | None:
        """Look up a playbook pinned to an exact release/hash."""
        sql = text(
            """
            SELECT metadata
            FROM knowledge_chunk
            WHERE kb_name = :kb_name
              AND metadata ->> 'playbook_id' = :playbook_id
              AND metadata ->> 'release_id' = :release_id
              AND metadata ->> 'playbook_object_hash' = :content_hash
              AND metadata ->> 'bundle_content_hash' = :bundle_content_hash
            LIMIT 1
            """
        )
        async with self._session_factory() as session:
            result = await session.execute(
                sql,
                {
                    "kb_name": KB_NAME,
                    "playbook_id": ref.playbook_id,
                    "release_id": release_id or ref.release_id,
                    "content_hash": ref.content_hash,
                    "bundle_content_hash": ref.bundle_content_hash,
                },
            )
            row = result.fetchone()
            if row is None:
                return None
            return _playbook_from_metadata(row.metadata or {})

    async def get_playbook(self, playbook_id: str) -> Playbook | None:
        """Legacy lookup by playbook_id only — prefer get_playbook_by_ref in production."""
        sql = text(
            """
            SELECT metadata
            FROM knowledge_chunk
            WHERE kb_name = :kb_name
              AND metadata ->> 'playbook_id' = :playbook_id
            ORDER BY metadata ->> 'release_id' DESC NULLS LAST
            LIMIT 1
            """
        )
        async with self._session_factory() as session:
            result = await session.execute(
                sql,
                {"kb_name": KB_NAME, "playbook_id": playbook_id},
            )
            row = result.fetchone()
            if row is None:
                return None
            return _playbook_from_metadata(row.metadata or {})

    async def _search_by_severity_order(
        self,
        event_type: str,
        query_ordinal: int,
        top_k: int,
        *,
        release_id: str | None = None,
    ) -> list[Playbook]:
        release_clause = ""
        params: dict[str, Any] = {
            "kb_name": KB_NAME,
            "event_type": event_type,
            "query_ordinal": query_ordinal,
            "top_k": top_k,
        }
        if release_id is not None:
            release_clause = " AND metadata ->> 'release_id' = :release_id"
            params["release_id"] = release_id
        sql = text(
            f"""
            SELECT metadata
            FROM knowledge_chunk
            WHERE kb_name = :kb_name
              AND metadata ->> 'event_type' = :event_type
              {release_clause}
              AND (
                CASE metadata ->> 'min_severity'
                  WHEN 'low' THEN 0
                  WHEN 'medium' THEN 1
                  WHEN 'high' THEN 2
                  WHEN 'critical' THEN 3
                  ELSE 99
                END
              ) <= :query_ordinal
            ORDER BY (
              CASE metadata ->> 'min_severity'
                WHEN 'low' THEN 0
                WHEN 'medium' THEN 1
                WHEN 'high' THEN 2
                WHEN 'critical' THEN 3
                ELSE 99
              END
            ) DESC
            LIMIT :top_k
            """
        )
        async with self._session_factory() as session:
            result = await session.execute(sql, params)
            rows = result.fetchall()
        return [_playbook_from_metadata(row.metadata or {}) for row in rows]

    async def search_playbooks(
        self,
        event_type: str,
        severity: str,
        query_text: str | None = None,
        top_k: int = 3,
        *,
        release_id: str | None = None,
    ) -> list[Playbook]:
        query_ordinal = _SEVERITY_ORDINAL.get(severity)
        if query_ordinal is None:
            raise ValueError(
                f"Unknown severity '{severity}'; must be one of {sorted(_SEVERITY_ORDINAL.keys())}"
            )

        if query_text is None:
            return await self._search_by_severity_order(
                event_type,
                query_ordinal,
                top_k,
                release_id=release_id,
            )

        chunk_count = await self._store.count(KB_NAME)
        fetch_k = max(top_k * 5, chunk_count, top_k)
        hits = await self._store.hybrid_search(
            KB_NAME,
            query_text,
            top_k=fetch_k,
            release_id=release_id,
        )
        filtered = [
            hit for hit in hits if _meta_matches_filters(hit.metadata, event_type, query_ordinal)
        ]
        return [_playbook_from_metadata(hit.metadata) for hit in filtered[:top_k]]


__all__ = ["KB_NAME", "PlaybookKBService", "playbook_ref_from_metadata"]
