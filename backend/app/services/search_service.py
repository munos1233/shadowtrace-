"""Full-text search service with OpenSearch / ILIKE dual-path (ISSUE-084).

When ``OPENSEARCH_ENABLED=true`` and the OpenSearch cluster is reachable,
queries are routed to OpenSearch with highlighting.  Otherwise the service
falls back to PostgreSQL ``ILIKE`` across the three searchable tables and
sets ``degraded=True`` in the response.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.opensearch_client import (
    ALL_SUFFIXES,
    AUDIT_LOGS_SUFFIX,
    EVIDENCE_SUFFIX,
    TOOL_CALLS_SUFFIX,
    OpenSearchClient,
)
from app.db import models as orm
from app.models.search import (
    INDEX_AUDIT_LOGS,
    INDEX_EVIDENCE,
    INDEX_TOOL_CALLS,
    VALID_SEARCH_SCOPES,
    SearchResponse,
    SearchResultItem,
)

logger = logging.getLogger(__name__)

# Map scope → OpenSearch index suffix and ORM table info for the fallback.
_SCOPE_CONFIG: dict[str, dict[str, Any]] = {
    "tool-calls": {
        "os_suffix": TOOL_CALLS_SUFFIX,
        "os_index": INDEX_TOOL_CALLS,
        "fallback_table_name": "tool_call_log",
        "orm_model": orm.ToolCallLog,
        "text_cols": ["tool_name", "tool_category", "error_detail"],
        "jsonb_cols": ["parameters", "result"],
        "doc_id_col": "call_id",
        "event_id_col": "event_id",
        "timestamp_col": "completed_at",
    },
    "audit-logs": {
        "os_suffix": AUDIT_LOGS_SUFFIX,
        "os_index": INDEX_AUDIT_LOGS,
        "fallback_table_name": "event_audit_log",
        "orm_model": orm.EventAuditLog,
        "text_cols": ["from_status", "to_status", "operator", "reason"],
        "jsonb_cols": [],
        "doc_id_col": "id",
        "event_id_col": "event_id",
        "timestamp_col": "created_at",
    },
    "evidence": {
        "os_suffix": EVIDENCE_SUFFIX,
        "os_index": INDEX_EVIDENCE,
        "fallback_table_name": "evidence",
        "orm_model": orm.Evidence,
        "text_cols": ["source", "evidence_type", "description", "mitre_technique"],
        "jsonb_cols": ["raw_data", "related_entities"],
        "doc_id_col": "evidence_id",
        "event_id_col": "event_id",
        "timestamp_col": "created_at",
    },
}


class SearchService:
    """Dual-path search: OpenSearch when enabled, PostgreSQL ILIKE otherwise."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        opensearch: OpenSearchClient | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._os = opensearch

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def search(
        self,
        q: str,
        scope: str = "all",
        page: int = 1,
        page_size: int = 20,
    ) -> SearchResponse:
        """Full-text search across audit logs, tool calls, and/or evidence.

        Args:
            q: The search query string (1-500 chars).
            scope: ``tool-calls`` | ``audit-logs`` | ``evidence`` | ``all``.
            page: 1-indexed page number.
            page_size: Results per page (1-100).

        Returns:
            ``SearchResponse`` with results and pagination metadata.
        """
        if scope not in VALID_SEARCH_SCOPES:
            raise ValueError(
                f"Invalid search scope {scope!r}. Must be one of: "
                + ", ".join(sorted(VALID_SEARCH_SCOPES))
            )
        if not q or not q.strip():
            return SearchResponse(degraded=not self._os_enabled)

        query = q.strip()

        # Try OpenSearch path first.
        if self._os_enabled and self._os is not None:
            try:
                return await self._search_opensearch(query, scope, page, page_size)
            except Exception:
                logger.warning("OpenSearch search failed; falling back to ILIKE", exc_info=True)

        return await self._search_ilike(query, scope, page, page_size)

    # ------------------------------------------------------------------ #
    # OpenSearch path
    # ------------------------------------------------------------------ #

    @property
    def _os_enabled(self) -> bool:
        settings = get_settings()
        return settings.opensearch_enabled

    async def _search_opensearch(
        self, query: str, scope: str, page: int, page_size: int
    ) -> SearchResponse:
        assert self._os is not None
        suffixes = self._resolve_os_suffixes(scope)
        raw = await self._os.search(query, suffixes, page=page, page_size=page_size)
        hits = raw.get("hits", {})
        total: int = (
            hits.get("total", {}).get("value", 0)
            if isinstance(hits.get("total"), dict)
            else int(hits.get("total", 0))
        )

        items: list[SearchResultItem] = []
        for hit in hits.get("hits", []):
            source = hit.get("_source", {})
            highlight_dict: dict[str, list[str]] = hit.get("highlight", {})
            # Pick the first highlight fragment across all fields.
            highlight_str = ""
            for frags in highlight_dict.values():
                if frags:
                    highlight_str = frags[0]
                    break

            os_index: str = hit.get("_index", "")
            doc_id: str = str(hit.get("_id", ""))
            event_id = source.get("event_id")
            summary = self._build_source_summary(os_index, source)

            items.append(
                SearchResultItem(
                    index=os_index,
                    doc_id=doc_id,
                    highlight=highlight_str,
                    source_summary=summary,
                    event_id=event_id,
                    occurred_at=self._coerce_datetime(
                        source.get("completed_at")
                        or source.get("created_at")
                        or source.get("started_at")
                    ),
                    extra=source,
                )
            )

        return SearchResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            degraded=False,
        )

    # ------------------------------------------------------------------ #
    # ILIKE fallback path
    # ------------------------------------------------------------------ #

    async def _search_ilike(
        self, query: str, scope: str, page: int, page_size: int
    ) -> SearchResponse:
        """PostgreSQL ILIKE search across relevant tables.

        Each table is queried independently with ``ILIKE`` on text columns
        and ``::text`` casts for JSONB columns.  Results are combined, sorted
        by timestamp descending, and paginated.
        """
        pattern = f"%{query}%"
        scopes = self._resolve_fallback_scopes(scope)
        all_rows: list[tuple[str, str, str | None, datetime | None, dict[str, Any]]] = []

        async with self._session_factory() as session:
            for scope_key in scopes:
                cfg = _SCOPE_CONFIG[scope_key]
                model = cfg["orm_model"]
                doc_id_col = cfg["doc_id_col"]
                event_id_col = cfg["event_id_col"]
                ts_col = cfg["timestamp_col"]
                table_name = cfg["fallback_table_name"]

                # Build ILIKE conditions.
                conditions: list[Any] = []
                for col_name in cfg["text_cols"]:
                    col = getattr(model, col_name, None)
                    if col is not None:
                        conditions.append(col.ilike(pattern))
                for col_name in cfg["jsonb_cols"]:
                    col = getattr(model, col_name, None)
                    if col is not None:
                        conditions.append(cast(col, Text).ilike(pattern))

                if not conditions:
                    continue

                # Derive doc_id expression (int ids need casting).
                doc_id_attr = getattr(model, doc_id_col)
                doc_id_expr = cast(doc_id_attr, Text) if doc_id_col == "id" else doc_id_attr
                event_id_col_attr = getattr(model, event_id_col) if event_id_col else None
                ts_col_attr = getattr(model, ts_col) if ts_col else None

                # Build columns tuple dynamically to satisfy mypy.
                select_cols: list[Any] = [doc_id_expr]
                if event_id_col_attr is not None:
                    select_cols.append(event_id_col_attr)
                if ts_col_attr is not None:
                    select_cols.append(ts_col_attr)
                select_cols.append(func.count().over().label("_total"))

                stmt = (
                    select(*select_cols)
                    .where(or_(*conditions))
                    .order_by(
                        ts_col_attr.desc().nullslast()
                        if ts_col_attr is not None
                        else doc_id_expr.asc()
                    )
                )

                result = await session.execute(stmt)
                rows = result.all()
                for row in rows:
                    all_rows.append(
                        (
                            table_name,
                            str(row[0]),
                            str(row[1]) if row[1] is not None else None,
                            row[2] if len(row) > 2 and row[2] is not None else None,
                            {},  # extra (no raw source in fallback)
                        )
                    )

        # Sort combined results by timestamp descending, then paginate.
        all_rows.sort(
            key=lambda r: (
                r[3] is not None,
                r[3] or datetime.min.replace(tzinfo=None),
            ),
            reverse=True,
        )
        total = len(all_rows)
        offset = (page - 1) * page_size
        page_rows = all_rows[offset : offset + page_size]

        items: list[SearchResultItem] = []
        for table_name, doc_id, event_id, ts, extra in page_rows:
            items.append(
                SearchResultItem(
                    index=table_name,
                    doc_id=doc_id,
                    highlight="",  # No highlighting in ILIKE fallback.
                    source_summary=self._build_fallback_summary(table_name, doc_id),
                    event_id=event_id,
                    occurred_at=ts,
                    extra=extra,
                )
            )

        return SearchResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            degraded=True,
        )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _resolve_os_suffixes(self, scope: str) -> list[str]:
        if scope == "all":
            return list(ALL_SUFFIXES)
        cfg = _SCOPE_CONFIG.get(scope)
        return [cfg["os_suffix"]] if cfg else []

    def _resolve_fallback_scopes(self, scope: str) -> list[str]:
        if scope == "all":
            return ["tool-calls", "audit-logs", "evidence"]
        return [scope] if scope in _SCOPE_CONFIG else []

    def _build_source_summary(self, index: str, source: dict[str, Any]) -> str:
        """Build a one-line summary from an OpenSearch hit source."""
        if TOOL_CALLS_SUFFIX in index:
            tool = source.get("tool_name", "?")
            status = source.get("status", "?")
            return f"[工具调用] {tool} ({status})"
        if AUDIT_LOGS_SUFFIX in index:
            to_status = source.get("to_status") or "?"
            reason = source.get("reason") or ""
            snippet = reason[:80] + "…" if len(reason) > 80 else reason
            return f"[审计] →{to_status} {snippet}".strip()
        if EVIDENCE_SUFFIX in index:
            desc = source.get("description") or source.get("evidence_type", "?")
            snippet = desc[:80] + "…" if len(desc) > 80 else desc
            return f"[证据] {snippet}"
        return ""

    def _build_fallback_summary(self, table_name: str, doc_id: str) -> str:
        """One-line summary for ILIKE fallback results."""
        labels = {
            "tool_call_log": "工具调用",
            "event_audit_log": "审计日志",
            "evidence": "证据",
        }
        label = labels.get(table_name, table_name)
        return f"[{label}] {doc_id}"

    @staticmethod
    def _coerce_datetime(value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                return None
        return None
