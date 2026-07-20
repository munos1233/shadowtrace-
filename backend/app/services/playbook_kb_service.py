"""PlaybookKBService: SOAR playbook knowledge base operations (ISSUE-044)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.knowledge import KnowledgeChunk
from app.models.playbook import Playbook, PlaybookStep
from app.models.tool_meta import ToolMeta
from app.services.knowledge_store import KnowledgeStore
from app.tools.specs import baseline_tool_index

KB_NAME = "playbook_kb"
_SEVERITY_ORDINAL: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _derive_chunk_id(playbook_id: str) -> str:
    digest = hashlib.sha256(f"playbook:{playbook_id}".encode()).hexdigest()[:16]
    return f"pbk-{digest}"


def _validate_steps(steps: list[PlaybookStep], playbook_id: str) -> None:
    """Static validation: every step's tool_name must exist and action_level must match ToolMeta."""
    index = baseline_tool_index()
    for step in steps:
        meta: ToolMeta | None = index.get(step.tool_name)
        if meta is None:
            raise ValueError(
                f"Playbook {playbook_id} step {step.step_order}: "
                f"unknown tool_name '{step.tool_name}'"
            )
        if step.action_level != meta.action_level:
            raise ValueError(
                f"Playbook {playbook_id} step {step.step_order} "
                f"({step.tool_name}): action_level {step.action_level.value} "
                f"does not match ToolMeta.action_level {meta.action_level.value}"
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


class PlaybookKBService:
    """Manage the SOAR playbook knowledge base.

    Provides file-based loading with static validation (tool_name + action_level
    against ToolMeta), idempotent upsert, lookup by playbook_id, and filtered
    search by event_type + severity with optional semantic ranking.
    """

    def __init__(
        self,
        store: KnowledgeStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._store = store
        self._session_factory = session_factory

    async def load_from_file(self, path: str | Path) -> int:
        """Load playbooks from a JSON file, validate, and upsert into playbook_kb.

        Returns the number of playbooks loaded. Repeated loads are idempotent.
        Raises ValueError if any step references an unknown tool_name or has an
        action_level that disagrees with the ToolMeta declaration.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        raw_playbooks: list[dict[str, Any]] = data["playbooks"]

        # Parse and validate
        playbooks: list[Playbook] = []
        for raw in raw_playbooks:
            pb = Playbook.model_validate(raw)
            _validate_steps(pb.steps, pb.playbook_id)
            playbooks.append(pb)

        chunks: list[KnowledgeChunk] = []
        for pb in playbooks:
            chunk_id = _derive_chunk_id(pb.playbook_id)
            content = _format_content(pb)
            metadata: dict[str, Any] = {
                "playbook_id": pb.playbook_id,
                "playbook_name": pb.playbook_name,
                "event_type": pb.event_type.value,
                "min_severity": pb.min_severity.value,
                "description": pb.description,
                "steps": [s.model_dump(mode="json") for s in pb.steps],
            }
            chunks.append(
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    kb_name=KB_NAME,
                    content=content,
                    metadata=metadata,
                )
            )

        await self._store.upsert_chunks(KB_NAME, chunks)
        return len(chunks)

    async def search_playbooks(
        self,
        event_type: str,
        severity: str,
        query_text: str | None = None,
        top_k: int = 3,
    ) -> list[Playbook]:
        """Search playbooks by event_type and min_severity, with optional semantic ranking.

        Only returns playbooks whose ``event_type`` matches exactly and whose
        ``min_severity`` ordinal is <= the query severity ordinal.  When
        *query_text* is provided, results are ranked by vector similarity;
        otherwise they are returned in severity-descending order.
        """
        query_ordinal = _SEVERITY_ORDINAL.get(severity)
        if query_ordinal is None:
            raise ValueError(
                f"Unknown severity '{severity}'; must be one of {sorted(_SEVERITY_ORDINAL.keys())}"
            )

        if query_text:
            query_vec = await self._store._embed.embed_query(query_text)
            sql = text(
                """
                SELECT chunk_id, kb_name, content, metadata,
                       1.0 - (embedding <=> :q) AS score
                FROM knowledge_chunk
                WHERE kb_name = :kb_name
                  AND metadata ->> 'event_type' = :event_type
                  AND (
                    CASE metadata ->> 'min_severity'
                      WHEN 'low' THEN 0
                      WHEN 'medium' THEN 1
                      WHEN 'high' THEN 2
                      WHEN 'critical' THEN 3
                      ELSE 99
                    END
                  ) <= :query_ordinal
                ORDER BY embedding <=> :q
                LIMIT :top_k
                """
            ).bindparams(bindparam("q", type_=Vector))
            async with self._session_factory() as session:
                result = await session.execute(
                    sql,
                    {
                        "kb_name": KB_NAME,
                        "q": query_vec,
                        "event_type": event_type,
                        "query_ordinal": query_ordinal,
                        "top_k": top_k,
                    },
                )
                rows = result.fetchall()
        else:
            sql = text(
                """
                SELECT chunk_id, kb_name, content, metadata
                FROM knowledge_chunk
                WHERE kb_name = :kb_name
                  AND metadata ->> 'event_type' = :event_type
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
                result = await session.execute(
                    sql,
                    {
                        "kb_name": KB_NAME,
                        "event_type": event_type,
                        "query_ordinal": query_ordinal,
                        "top_k": top_k,
                    },
                )
                rows = result.fetchall()

        playbooks: list[Playbook] = []
        for row in rows:
            meta = row.metadata or {}
            steps_raw = meta.get("steps", [])
            steps = [PlaybookStep.model_validate(s) for s in steps_raw]
            playbooks.append(
                Playbook(
                    playbook_id=meta["playbook_id"],
                    playbook_name=meta["playbook_name"],
                    event_type=meta["event_type"],
                    min_severity=meta["min_severity"],
                    description=meta.get("description", ""),
                    steps=steps,
                )
            )
        return playbooks

    async def get_playbook(self, playbook_id: str) -> Playbook | None:
        """Look up a single playbook by its playbook_id."""
        sql = text(
            """
            SELECT metadata
            FROM knowledge_chunk
            WHERE kb_name = :kb_name
              AND metadata ->> 'playbook_id' = :playbook_id
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
            meta = row.metadata or {}
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
