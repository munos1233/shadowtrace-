"""Search models for OpenSearch full-text search API (ISSUE-084)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------------- #
# Index name constants
# --------------------------------------------------------------------------- #

INDEX_TOOL_CALLS = "shadowtrace-tool-calls"
INDEX_AUDIT_LOGS = "shadowtrace-audit-logs"
INDEX_EVIDENCE = "shadowtrace-evidence"

# Fallback table names used in degraded mode
TABLE_TOOL_CALL_LOG = "tool_call_log"
TABLE_EVENT_AUDIT_LOG = "event_audit_log"
TABLE_EVIDENCE = "evidence"

VALID_SEARCH_SCOPES = frozenset({"tool-calls", "audit-logs", "evidence", "all"})

# --------------------------------------------------------------------------- #
# Response models
# --------------------------------------------------------------------------- #


class SearchResultItem(BaseModel):
    """A single search hit — either from OpenSearch or the ILIKE fallback."""

    model_config = ConfigDict(extra="forbid")

    index: str
    """Index or table name this hit came from (e.g. ``shadowtrace-tool-calls``)."""

    doc_id: str
    """Document primary key (call_id, audit-log id, or evidence_id)."""

    highlight: str = ""
    """Highlighted snippet (HTML-wrapped with ``<em>`` from OpenSearch; empty for ILIKE)."""

    source_summary: str = ""
    """One-line human-readable summary of the document."""

    event_id: str | None = None
    """Associated event for navigation."""

    occurred_at: datetime | None = None
    """Timestamp for sorting / display."""

    extra: dict[str, Any] = Field(default_factory=dict)
    """Additional metadata depending on index type."""


class SearchResponse(BaseModel):
    """Paginated search response from ``GET /api/v1/search``."""

    model_config = ConfigDict(extra="forbid")

    items: list[SearchResultItem] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20
    degraded: bool = False
    """``True`` when the PostgreSQL ILIKE fallback was used instead of OpenSearch."""
