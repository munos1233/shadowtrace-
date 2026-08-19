"""Attack-storyline timeline endpoint (ISSUE-070)."""

from __future__ import annotations

import logging
from typing import Annotated, Any, Protocol

from fastapi import APIRouter, Depends

from app.api.v1.deps import _get_context_store, get_event_service
from app.api.v1.errors import EventNotFoundError, ResourceNotFoundError
from app.core.auth import ReadPrincipal
from app.models.agent_io import AttackStoryline
from app.models.context import EventContext
from app.services.event_context_snapshot_projection import parse_attack_storyline

logger = logging.getLogger(__name__)

router = APIRouter()


class _EventReader(Protocol):
    async def get_event(self, event_id: str) -> object | None: ...


class _ContextReader(Protocol):
    async def get_full_context(self, event_id: str) -> EventContext: ...

    async def get_versioned_field(self, event_id: str, key: str) -> tuple[Any, int]: ...


def _storyline_not_ready(event_id: str) -> ResourceNotFoundError:
    return ResourceNotFoundError(
        f"storyline for event {event_id} is not ready",
        error_code="storyline_not_ready",
        details={"event_id": event_id},
    )


async def _load_journal_storyline(context_store: _ContextReader, event_id: str) -> Any:
    get_versioned = getattr(context_store, "get_versioned_field", None)
    if not callable(get_versioned):
        return None
    raw, _version = await get_versioned(event_id, "storyline")
    return raw


@router.get("/events/{event_id}/timeline", response_model=AttackStoryline)
async def get_timeline(
    event_id: str,
    principal: ReadPrincipal,
    event_service: Annotated[_EventReader, Depends(get_event_service)],
    context_store: Annotated[_ContextReader, Depends(_get_context_store)],
) -> AttackStoryline:
    """Return the generated attack storyline stored in WM / journal.

    EventContext after CLOSED rebuild may only hold the ISSUE-254 snapshot
    summary (``phase_count`` / ``claim_ref_count``). That blob is not an
    ``AttackStoryline``; validating it caused HTTP 500. This endpoint loads the
    full storyline from the context cache when it is complete, otherwise from
    the journal. A summary-only or missing payload is ``storyline_not_ready``.
    """

    event = await event_service.get_event(event_id)
    if event is None:
        raise EventNotFoundError(
            f"event {event_id} not found",
            details={"event_id": event_id},
        )

    try:
        context = await context_store.get_full_context(event_id)
    except KeyError as exc:
        # The event may have been deleted between the existence check and the
        # context read, or its context may not have been initialized yet.
        raise _storyline_not_ready(event_id) from exc

    parsed = parse_attack_storyline(context.storyline)
    if parsed is not None:
        return parsed

    journal_raw = await _load_journal_storyline(context_store, event_id)
    parsed = parse_attack_storyline(journal_raw)
    if parsed is None:
        logger.info(
            "timeline storyline not ready event_id=%s context_summary=%s journal_present=%s",
            event_id,
            context.storyline is not None,
            journal_raw is not None,
        )
        raise _storyline_not_ready(event_id)
    return parsed
