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
import json
import logging
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, cast

import jsonschema
import socketio
from fastapi import FastAPI

from app.core.config import get_settings
from app.core.event_bus import SOCKET_MESSAGE_TYPES, sanitize_payload
from app.core.redis_client import RedisClient
from app.core.socketio_events import (
    GLOBAL_ROOM,
    SOCKETIO_NAMESPACE,
    SocketIOSessionRegistry,
    _event_room,
    disconnect_invalid_sessions,
    register_handlers,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EVENTS_CHANNEL_PATTERN = "shadowtrace:events:*"
_EVENTS_CHANNEL_PREFIX = "shadowtrace:events:"
_SEQUENCE_KEY_PREFIX = "shadowtrace:socketio:seq:"
_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2].parent / "contracts" / "socketio" / "events.schema.json"
)
_RECONNECT_DELAY_S = 2.0
_RECOVERY_DELAY_S = 30.0
_SESSION_VALIDATION_INTERVAL_S = 30.0
_SEQUENCE_TTL_S = 60 * 60 * 24 * 30  # 30 days
_MAX_CONSECUTIVE_FAILURES = 5
SocketIOHealthStatus = Literal["ok", "degraded", "stopped"]


def _sequence_key(event_id: str) -> str:
    return f"{_SEQUENCE_KEY_PREFIX}{event_id}"


@lru_cache(maxsize=1)
def _events_schema() -> dict[str, Any]:
    """Load the Socket.IO envelope JSON Schema once per process."""
    return cast(dict[str, Any], json.loads(_SCHEMA_PATH.read_text(encoding="utf-8")))


def _is_envelope_schema_error(exc: BaseException) -> bool:
    """True when envelope validation failed; drop the message, keep the subscriber."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, jsonschema.ValidationError):
            return True
        schema_error = getattr(jsonschema, "SchemaError", None)
        if schema_error is not None and isinstance(current, schema_error):
            return True
        if type(current).__name__ in {
            "Unresolvable",
            "_WrappedReferencingError",
            "RefResolutionError",
        }:
            return True
        current = current.__cause__ or current.__context__
    return False


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
        self._sessions = SocketIOSessionRegistry()
        settings = get_settings()
        self._sio = socketio.AsyncServer(
            async_mode="asgi",
            cors_allowed_origins=settings.resolved_socketio_cors_origins(),
            cors_credentials=True,
            logger=False,
        )
        self._listener_task: asyncio.Task[None] | None = None
        self._session_validator_task: asyncio.Task[None] | None = None
        self._session_validation_lock = asyncio.Lock()
        self._stopping = False
        self._consecutive_failures = 0
        self._bridge_degraded = False
        self._last_success_at: str | None = None
        self._last_error_class: str | None = None

        global _active_manager
        _active_manager = self

        register_handlers(self._sio, sessions=self._sessions)

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def sio(self) -> socketio.AsyncServer:
        """The managed ``AsyncServer`` instance."""
        return self._sio

    @property
    def bridge_active(self) -> bool:
        """True while the Redis→Socket.IO listener task is running."""
        return self._listener_task is not None and not self._listener_task.done()

    @property
    def bridge_degraded(self) -> bool:
        """True when the listener is in a prolonged recovery backoff."""
        return self._bridge_degraded

    def health_snapshot(self) -> dict[str, object]:
        """Sanitized process-local subscriber readiness (ISSUE-298)."""
        from app.core.metrics import socketio_subscriber_health_snapshot

        metrics = socketio_subscriber_health_snapshot()
        listener_running = self.bridge_active
        if self._bridge_degraded or self._consecutive_failures > 0:
            status: SocketIOHealthStatus = "degraded"
        elif self._listener_task is None or (self._listener_task.done() and not listener_running):
            status = "stopped"
        else:
            status = "ok"
        return {
            "status": status,
            "listener_running": listener_running,
            "consecutive_failures": self._consecutive_failures,
            "last_success_at": self._last_success_at,
            "last_error_class": self._last_error_class,
            "subscriber_failures": metrics["subscriber_failures"],
            "subscriber_recoveries": metrics["subscriber_recoveries"],
        }

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
        listener_running = self._listener_task is not None and not self._listener_task.done()
        validator_running = (
            self._session_validator_task is not None and not self._session_validator_task.done()
        )
        if listener_running and validator_running:
            return
        self._stopping = False
        self._consecutive_failures = 0
        self._bridge_degraded = False
        self._last_error_class = None
        if not listener_running:
            self._listener_task = asyncio.create_task(self._listen())
        if not validator_running:
            self._session_validator_task = asyncio.create_task(self._validate_sessions())
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
        if self._session_validator_task is not None and not self._session_validator_task.done():
            self._session_validator_task.cancel()
            try:
                await self._session_validator_task
            except asyncio.CancelledError:
                pass
            self._session_validator_task = None
        try:
            await self._sio.disconnect()
        except Exception:
            logger.warning("SocketIOManager disconnect raised", exc_info=True)
        # Handlers close over this registry, so clear it without replacing it.
        self._sessions.clear()
        self._bridge_degraded = False
        self._consecutive_failures = 0
        self._last_error_class = None
        logger.info("SocketIOManager stopped")

    # ------------------------------------------------------------------ #
    # Background listener
    # ------------------------------------------------------------------ #

    async def _validate_sessions(self) -> None:
        """Periodically revoke bearer sessions even when no messages are published."""
        while not self._stopping:
            try:
                await asyncio.sleep(_SESSION_VALIDATION_INTERVAL_S)
                if not await self._disconnect_invalid_sessions():
                    logger.error("SocketIOManager periodic revoked-session cleanup incomplete")
            except asyncio.CancelledError:
                break
            except Exception:
                logger.warning(
                    "SocketIOManager periodic session validation failed",
                    exc_info=True,
                )

    async def _disconnect_invalid_sessions(self) -> bool:
        """Serialize periodic and pre-broadcast session cleanup."""
        async with self._session_validation_lock:
            return await disconnect_invalid_sessions(self._sio, self._sessions)

    async def _listen(self) -> None:
        """PSUBSCRIBE ``shadowtrace:events:*`` and bridge to Socket.IO rooms.

        On connection loss, retry with a fixed back-off.  After
        ``_MAX_CONSECUTIVE_FAILURES`` consecutive failures the listener
        enters a longer recovery delay, then retries (frontend may poll REST).
        """
        while not self._stopping:
            recovering = self._consecutive_failures > 0 or self._bridge_degraded
            try:
                await self._run_subscriber()
                if recovering:
                    from app.core.metrics import record_socketio_subscriber_recovery

                    record_socketio_subscriber_recovery(outcome="reconnected")
                self._consecutive_failures = 0
                self._bridge_degraded = False
                self._last_error_class = None
            except asyncio.CancelledError:
                break
            except Exception as exc:
                from app.core.metrics import record_socketio_subscriber_failure

                self._last_error_class = type(exc).__name__
                self._consecutive_failures += 1
                if self._consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                    record_socketio_subscriber_failure(reason="recovery_backoff")
                    self._bridge_degraded = True
                    logger.critical(
                        "SocketIOManager subscriber failed %d consecutive times — "
                        "entering %.0fs recovery backoff before retry",
                        self._consecutive_failures,
                        _RECOVERY_DELAY_S,
                        exc_info=True,
                    )
                    await asyncio.sleep(_RECOVERY_DELAY_S)
                    continue
                record_socketio_subscriber_failure(reason="subscriber_error")
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
        pubsub = None
        try:
            client = self._redis.get_client()
            pubsub = client.pubsub()
            await pubsub.psubscribe(_EVENTS_CHANNEL_PATTERN)
            self._last_success_at = datetime.now(UTC).isoformat()

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

                channel_bytes = (
                    channel_raw.encode("utf-8") if isinstance(channel_raw, str) else channel_raw
                )
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

    async def _increment_sequence(self, event_id: str) -> int | None:
        """Return the next per-event sequence or None when Redis INCR fails."""
        seq_key = _sequence_key(event_id)
        try:
            redis_client = self._redis.get_client()
            seq = int(await redis_client.incr(seq_key))
            await redis_client.expire(seq_key, _SEQUENCE_TTL_S)
            return seq
        except Exception:
            logger.warning(
                "SocketIOManager sequence INCR failed for event_id=%s — skipping emit",
                event_id,
                exc_info=True,
            )
            return None

    async def _dispatch(self, channel_raw: bytes, data_raw: bytes | str | memoryview) -> None:
        """Decode one Redis message and emit to the appropriate rooms."""
        if self._stopping:
            return

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

        message_type = envelope.get("message_type")
        if not message_type or not isinstance(message_type, str):
            logger.warning(
                "SocketIOManager envelope missing message_type on %s — dropped",
                channel,
            )
            return

        if message_type not in SOCKET_MESSAGE_TYPES:
            logger.warning(
                "SocketIOManager unknown message_type=%s on %s — dropped",
                message_type,
                channel,
            )
            return

        seq = await self._increment_sequence(event_id)
        if seq is None:
            return

        raw_payload = envelope.get("payload", {})
        safe_payload = sanitize_payload(raw_payload if isinstance(raw_payload, dict) else {})
        if not isinstance(safe_payload, dict):
            safe_payload = {}

        bus_timestamp = envelope.get("timestamp")
        if isinstance(bus_timestamp, str):
            timestamp = bus_timestamp
        else:
            timestamp = datetime.now(UTC).isoformat()

        socket_envelope: dict[str, Any] = {
            "type": message_type,
            "event_id": event_id,
            "sequence": seq,
            "timestamp": timestamp,
            "payload": safe_payload,
        }

        try:
            jsonschema.validate(instance=socket_envelope, schema=_events_schema())
        except Exception as exc:
            if not _is_envelope_schema_error(exc):
                raise
            logger.warning(
                "SocketIOManager envelope failed schema validation event_id=%s type=%s — dropped",
                event_id,
                message_type,
            )
            return

        if not await self._disconnect_invalid_sessions():
            logger.error(
                "SocketIOManager revoked-session cleanup failed event_id=%s — broadcast dropped",
                event_id,
            )
            return

        # Authorized delivery: clients only receive messages for rooms they joined
        # after handshake auth and subscribe / join_global checks (ISSUE-258).
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


_active_manager: SocketIOManager | None = None


def get_socketio_health() -> dict[str, object]:
    """Process-wide Socket.IO subscriber readiness for health probes (ISSUE-298)."""
    if _active_manager is None:
        from app.core.metrics import socketio_subscriber_health_snapshot

        metrics = socketio_subscriber_health_snapshot()
        return {
            "status": "stopped",
            "listener_running": False,
            "consecutive_failures": 0,
            "last_success_at": None,
            "last_error_class": None,
            "subscriber_failures": metrics["subscriber_failures"],
            "subscriber_recoveries": metrics["subscriber_recoveries"],
        }
    return _active_manager.health_snapshot()


def reset_socketio_health_state_for_tests() -> None:
    """Reset process-local Socket.IO health counters for deterministic tests."""
    from app.core.metrics import reset_socketio_subscriber_metrics_for_tests

    reset_socketio_subscriber_metrics_for_tests()
    if _active_manager is not None:
        _active_manager._consecutive_failures = 0
        _active_manager._bridge_degraded = False
        _active_manager._last_success_at = None
        _active_manager._last_error_class = None


__all__ = [
    "SocketIOManager",
    "_events_schema",
    "_is_envelope_schema_error",
    "_sequence_key",
    "get_socketio_health",
    "reset_socketio_health_state_for_tests",
]
