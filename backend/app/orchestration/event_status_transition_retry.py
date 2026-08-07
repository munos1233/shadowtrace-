"""Bounded retry helper for EventStatus transitions (ISSUE-234).

Shared by SuperAgent (legacy embedded graph + FAILED cleanup) and the
production LangGraph workflow so transient persistence errors get the same
retry / fail-closed semantics.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from app.core.errors import InvalidStateTransitionError, ShadowTraceError, is_retryable
from app.models.enums import EventStatus

logger = logging.getLogger(__name__)


async def transition_with_bounded_retry(
    transition_call: Callable[[], Awaitable[None]],
    *,
    event_id: str,
    target: EventStatus,
    max_retries: int,
    backoff_seconds: float,
    log_prefix: str,
) -> None:
    """Execute *transition_call* with bounded exponential backoff.

    ``InvalidStateTransitionError`` is never retried. Non-retryable errors
    fail closed immediately; retryable errors retry up to *max_retries* then
    raise ``ShadowTraceError``.
    """
    max_attempts = max_retries + 1

    for attempt in range(max_attempts):
        try:
            await transition_call()
            return
        except InvalidStateTransitionError:
            logger.error(
                "%s: illegal state transition for event=%s → %s",
                log_prefix,
                event_id,
                target.value,
                exc_info=True,
            )
            raise
        except Exception as exc:
            if not is_retryable(exc):
                logger.error(
                    "%s: non-retryable transition error for event=%s → %s",
                    log_prefix,
                    event_id,
                    target.value,
                    exc_info=True,
                )
                raise ShadowTraceError(
                    message=(
                        f"{log_prefix} state transition to {target.value} "
                        f"failed for event={event_id}"
                    ),
                    error_code="internal_error",
                    details={
                        "failures": [
                            {
                                "event_id": event_id,
                                "target": target.value,
                                "error": str(exc),
                                "attempts": attempt + 1,
                                "retryable": False,
                            }
                        ]
                    },
                ) from exc

            if attempt < max_retries:
                delay = backoff_seconds * (2**attempt)
                if delay > 0:
                    await asyncio.sleep(delay)
                logger.warning(
                    "%s: transition to %s failed for event=%s (attempt %d/%d, retrying)",
                    log_prefix,
                    target.value,
                    event_id,
                    attempt + 1,
                    max_attempts,
                    exc_info=True,
                )
                continue

            logger.error(
                "%s: transition to %s failed for event=%s after %d attempts",
                log_prefix,
                target.value,
                event_id,
                max_attempts,
                exc_info=True,
            )
            raise ShadowTraceError(
                message=(
                    f"{log_prefix} state transition to {target.value} failed for event={event_id}"
                ),
                error_code="internal_error",
                details={
                    "failures": [
                        {
                            "event_id": event_id,
                            "target": target.value,
                            "error": str(exc),
                            "attempts": max_attempts,
                        }
                    ]
                },
            ) from exc
