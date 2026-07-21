"""Socket.IO manager — ASGI mount, background Redis subscriber, and sequence (ISSUE-040).

Wraps ``socketio.AsyncServer`` and mounts it on a FastAPI app via
``socketio.ASGIApp``.  A long-lived background task subscribes to
``shadowtrace:events:*`` via Redis ``PSUBSCRIBE`` and broadcasts
every message as a unified envelope into the ``/events`` namespace.

Naming (from spec)
------------------
* Namespace: ``/events``
* Rooms: ``global`` (all connected clients), ``event:{event_id}`` (per-event)
* Envelope: ``type``, ``event_id``, ``sequence``, ``timestamp``, ``payload``
* Sequence key: ``shadowtrace:socketio:seq:{event_id}`` (Redis INCR)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import socketio
from fastapi import FastAPI
from redis.asyncio import Redis

from app.core.event_bus import SOCKET_MESSAGE_TYPES
from app.core.redis_client import RedisClient
from app.core.socketio_events import (
    GLOBAL_ROOM,
    SOCKETIO_NAMESPACE,
    _event_room,
    register_handlers,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EVENTS_CHANNEL_PATTERN = "shadowtrace:events:*"
_EVENTS_CHANNEL_PREFIX = "shadowtrace:events:"
_SEQUENCE_KEY_PREFIX = "shadowtrace:socketio:seq:"
_RECONNECT_DELAY_S = 2.0
_SEQUENCE_TTL_S = 60 * 60 * 24 * 30  # 30 days — Issue 1
_MAX_CONSECUTIVE_FAILURES = 5  # Issue 5


def _sequence_key(event_id: str) -> str:
    return f"{_SEQUENCE_KEY_PREFIX}{event_id}"


# ---------------------------------------------------------------------------
# SocketIOManager
# ---------------------------------------------------------------------------


class SocketIOManager:
    """Manage the ``socketio.AsyncServer`` lifecycle and Redis→Socket.IO bridge.

    Parameters
    ----------
    redis:
        The shared ``RedisClient`` used for PSUBSCRIBE and sequence INCR.
    """

    def __init__(self, redis: RedisClient) -> None:
        self._redis = redis
        self._sio = socketio.AsyncServer(
            async_mode="asgi",
            cors_allowed_origins="*",
            logger=False,
        )
        self._listener_task: asyncio.Task[None] | None = None
        self._stopping = False
        self._consecutive_failures = 0  # Issue 5

        register_handlers(self._sio)

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def sio(self) -> socketio.AsyncServer:
        """The managed ``AsyncServer`` instance."""
        return self._sio

    # ------------------------------------------------------------------ #
    # FastAPI integration
    # ------------------------------------------------------------------ #

    def mount(self, app: FastAPI) -> socketio.ASGIApp:
        """Wrap *app* so Socket.IO and the FastAPI app share the same ASGI server.

        Returns a new ASGI application.  Callers must use the returned object
        as the uvicorn target.
        """
        wrapped = socketio.ASGIApp(self._sio, other_asgi_app=app, socketio_path="socket.io")
        return wrapped

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Start the background Redis→Socket.IO bridge.

        Safe to call multiple times — subsequent calls are no-ops.
        """
        if self._listener_task is not None and not self._listener_task.done():
            return
        self._stopping = False
        self._consecutive_failures = 0
        self._listener_task = asyncio.create_task(self._listen())
        logger.info("SocketIOManager background listener started")

    async def stop(self) -> None:
        """Stop the background listener gracefully and disconnect all clients."""
        self._stopping = True
        if self._listener_task is not None and not self._listener_task.done():
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
        # Disconnect all sessions managed by this server.
        try:
            await self._sio.disconnect()
        except Exception:
            logger.warning("SocketIOManager disconnect raised", exc_info=True)
        logger.info("SocketIOManager stopped")

    # ------------------------------------------------------------------ #
    # Background listener
    # ------------------------------------------------------------------ #

    async def _listen(self) -> None:
        """PSUBSCRIBE ``shadowtrace:events:*`` and bridge to Socket.IO rooms.

        On connection loss, retry with a fixed back-off.  After
        ``_MAX_CONSECUTIVE_FAILURES`` consecutive failures the listener
        stops permanently and logs a CRITICAL — this guards against
        infinite-retry loops on programming errors (Issue 5).
        """
        while not self._stopping:
            try:
                await self._run_subscriber()
                self._consecutive_failures = 0  # reset on clean exit
            except asyncio.CancelledError:
                break
            except Exception:
                self._consecutive_failures += 1
                if self._consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                    logger.critical(
                        "SocketIOManager subscriber failed %d consecutive times — "
                        "giving up.  Socket.IO push is now inactive until the "
                        "process restarts.",
                        self._consecutive_failures,
                        exc_info=True,
                    )
                    break
                logger.warning(
                    "SocketIOManager subscriber error — retrying in %.1fs (attempt %d/%d)",
                    _RECONNECT_DELAY_S,
                    self._consecutive_failures,
                    _MAX_CONSECUTIVE_FAILURES,
                    exc_info=True,
                )
                await asyncio.sleep(_RECONNECT_DELAY_S)

    async def _run_subscriber(self) -> None:
        """Single PSUBSCRIBE session: decode envelopes and broadcast."""
        client: Redis | None = None
        pubsub = None
        try:
            client = self._redis.get_client()
            pubsub = client.pubsub()
            await pubsub.psubscribe(_EVENTS_CHANNEL_PATTERN)

            async for message in pubsub.listen():
                if self._stopping:
                    break
                if message is None:
                    continue
                if message.get("type") != "pmessage":
                    continue

                channel_raw = message.get("channel")
                data_raw = message.get("data")
                if not isinstance(channel_raw, (str, bytes)) or data_raw is None:
                    continue

                # Normalise channel to bytes (Issue 7: skip redundant copy).
                channel_bytes = (
                    channel_raw.encode("utf-8")
                    if isinstance(channel_raw, str)
                    else channel_raw  # already bytes
                )
                # Issue 2: type-guard data_raw before passing to loads().
                if not isinstance(data_raw, (bytes, str, memoryview)):
                    logger.warning(
                        "SocketIOManager unexpected data_raw type=%s — dropped",
                        type(data_raw).__name__,
                    )
                    continue

                await self._dispatch(channel_bytes, data_raw)

        except asyncio.CancelledError:
            raise
        except Exception:
            if not self._stopping:
                raise
        finally:
            if pubsub is not None:
                try:
                    await pubsub.punsubscribe()
                except Exception:
                    pass
                try:
                    await pubsub.aclose()  # type: ignore[no-untyped-call]
                except Exception:
                    pass

    async def _dispatch(self, channel_raw: bytes, data_raw: bytes | str | memoryview) -> None:
        """Decode one Redis message and emit to the appropriate rooms."""
        if self._stopping:
            return

        # Issue 4: decode channel with strict error handling — corrupted
        # bytes should be skipped, not propagated with U+FFFD replacements.
        try:
            channel = channel_raw.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning("SocketIOManager channel name contains invalid UTF-8 — dropped")
            return

        if not channel.startswith(_EVENTS_CHANNEL_PREFIX):
            return
        event_id = channel[len(_EVENTS_CHANNEL_PREFIX) :]
        if not event_id:
            return

        # Decode the EventBus envelope — RedisClient.loads handles
        # bytes / str / memoryview natively.
        try:
            envelope = RedisClient.loads(data_raw)
        except Exception:
            logger.warning(
                "SocketIOManager received undecodable payload on %s",
                channel,
                exc_info=True,
            )
            return

        if not isinstance(envelope, dict):
            return

        # The EventBus always includes message_type; a missing / non-string
        # key signals a corrupt or non-EventBus payload.
        message_type = envelope.get("message_type")
        if not message_type or not isinstance(message_type, str):
            logger.warning(
                "SocketIOManager envelope missing message_type on %s — dropped",
                channel,
            )
            return

        # Issue 3: defence-in-depth — validate message_type against the
        # canonical set even though EventBus already validates on publish.
        if message_type not in SOCKET_MESSAGE_TYPES:
            logger.warning(
                "SocketIOManager unknown message_type=%s on %s — dropped",
                message_type,
                channel,
            )
            return

        # Increment per-event sequence.
        seq: int = 1
        seq_key = _sequence_key(event_id)
        try:
            redis_client = self._redis.get_client()
            seq = int(await redis_client.incr(seq_key))
            # Issue 1: set TTL on the sequence key so it eventually expires.
            await redis_client.expire(seq_key, _SEQUENCE_TTL_S)
        except Exception:
            logger.warning(
                "SocketIOManager sequence INCR failed for event_id=%s",
                event_id,
                exc_info=True,
            )

        # Build unified Socket.IO envelope.
        socket_envelope: dict[str, Any] = {
            "type": message_type,
            "event_id": event_id,
            "sequence": seq,
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": envelope.get("payload", {}),
        }

        # Broadcast to both rooms concurrently.  Each emit is independent —
        # one failing must not suppress the other.
        event_room = _event_room(event_id)
        results = await asyncio.gather(
            self._sio.emit(
                "event",
                socket_envelope,
                room=event_room,
                namespace=SOCKETIO_NAMESPACE,
            ),
            self._sio.emit(
                "event",
                socket_envelope,
                room=GLOBAL_ROOM,
                namespace=SOCKETIO_NAMESPACE,
            ),
            return_exceptions=True,
        )
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                target = "event_room" if i == 0 else "global"
                logger.warning(
                    "SocketIOManager emit failed event_id=%s target=%s type=%s",
                    event_id,
                    target,
                    message_type,
                    exc_info=result,
                )


__all__ = ["SocketIOManager"]
