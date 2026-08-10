"""Track active LangGraph investigation invocations (ISSUE-296).

Nested ``resume_investigation`` / checkpoint continuation must not re-enter the
same event graph while a node is still on the call stack — otherwise approval
and resume hooks fork duplicate execution and amplify failed→failed loops.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar

_active_graph_event_id: ContextVar[str | None] = ContextVar(
    "investigation_graph_event_id",
    default=None,
)


def active_graph_event_id() -> str | None:
    return _active_graph_event_id.get()


def is_in_investigation_graph(*, event_id: str | None = None) -> bool:
    active = _active_graph_event_id.get()
    if active is None:
        return False
    if event_id is None:
        return True
    return active == event_id


@asynccontextmanager
async def bind_investigation_graph(event_id: str) -> AsyncIterator[None]:
    token = _active_graph_event_id.set(event_id)
    try:
        yield
    finally:
        _active_graph_event_id.reset(token)


__all__ = [
    "active_graph_event_id",
    "bind_investigation_graph",
    "is_in_investigation_graph",
]
