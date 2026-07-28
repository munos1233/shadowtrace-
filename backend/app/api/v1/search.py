"""Full-text search API (ISSUE-084).

``GET /api/v1/search`` provides full-text search across tool call logs,
event audit logs, and evidence.  When ``OPENSEARCH_ENABLED=false`` the
endpoint degrades gracefully to PostgreSQL ``ILIKE`` and annotates the
response with ``degraded=true``.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from app.api.v1.deps import get_search_service
from app.core.auth import CurrentPrincipal
from app.models.search import SearchResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["search"])


@router.get("/search", response_model=SearchResponse)
async def search(
    q: Annotated[
        str,
        Query(
            min_length=1,
            max_length=500,
            description="Search query string.",
        ),
    ],
    principal: CurrentPrincipal,
    search_service: Annotated[Any, Depends(get_search_service)],
    scope: Annotated[
        str,
        Query(
            pattern=r"^(tool-calls|audit-logs|evidence|all)$",
            description="Search scope: tool-calls, audit-logs, evidence, or all.",
        ),
    ] = "all",
    page: Annotated[
        int,
        Query(ge=1, le=100, description="Page number (1-indexed)."),
    ] = 1,
    page_size: Annotated[
        int,
        Query(ge=1, le=100, description="Results per page."),
    ] = 20,
) -> SearchResponse:
    """Full-text search across tool calls, audit logs, and evidence.

    When OpenSearch is enabled and reachable the results include highlighted
    snippets.  Otherwise the endpoint falls back to PostgreSQL ILIKE queries
    and sets ``degraded=true``.
    """
    from app.services.search_service import SearchService

    assert isinstance(search_service, SearchService)
    return await search_service.search(
        q=q.strip(),
        scope=scope,
        page=page,
        page_size=page_size,
    )
