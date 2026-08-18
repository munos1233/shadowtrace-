"""Socket.IO real-time event push tests (ISSUE-040).

Acceptance criteria
-------------------
1. A subscribed client receives a ``state_change`` message **within 1 second**
   of a state transition.
2. All 18 event types are declared in the committed Socket.IO schema
   (``contracts/socketio/events.schema.json``, exported from canonical
   ``backend/app/contracts/socketio/events.schema.json``)
   and every per-type payload validates against its definition in the schema.
3. Multiple clients subscribed to the same event room all receive the broadcast.

Fallback / degrade
------------------
When Redis is unreachable the tests are skipped — the Socket.IO bridge depends
on the Redis Pub/Sub bus.  Schema-only tests run without Redis.

Run from ``backend/``:

.. code:: bash

    pytest tests/test_api/test_socketio.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import jsonschema
import pytest
import pytest_asyncio
import socketio
import uvicorn
from fastapi import FastAPI

from app.core.auth import (
    AuthenticationError,
    client_host_from_socketio_environ,
    resolve_principal_from_socketio_handshake,
)
from app.core.config import get_settings
from app.core.event_bus import SOCKET_MESSAGE_TYPES, EventBus
from app.core.redis_client import RedisClient
from app.core.socketio_events import (
    GLOBAL_ROOM,
    SOCKETIO_NAMESPACE,
    SocketIOSessionRegistry,
    _event_room,
    disconnect_invalid_sessions,
    register_handlers,
)
from app.core.socketio_manager import SocketIOManager, reset_socketio_health_state_for_tests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture(autouse=True)
def _reset_socketio_health_state() -> None:
    reset_socketio_health_state_for_tests()
    yield
    reset_socketio_health_state_for_tests()


SCHEMA_PATH = Path(__file__).resolve().parents[3] / "contracts" / "socketio" / "events.schema.json"

EXPECTED_EVENT_TYPES = sorted(SOCKET_MESSAGE_TYPES)

_DEV_AUTH_TOKENS = json.dumps(
    {
        "analyst-token": {"subject": "analyst-1", "roles": ["analyst"]},
        "norole-token": {"subject": "norole-1", "roles": []},
    }
)
_ALLOWED_TEST_ORIGIN = "http://127.0.0.1:5173"


@pytest.fixture(autouse=True)
def _socketio_dev_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dev bearer tokens + permissive CORS for Socket.IO integration tests."""
    monkeypatch.setenv("DEV_AUTH_TOKENS", _DEV_AUTH_TOKENS)
    monkeypatch.setenv("SOCKETIO_CORS_ALLOWED_ORIGINS", "*")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _auth_environ(*, origin: str = _ALLOWED_TEST_ORIGIN) -> dict[str, str]:
    return {
        "HTTP_AUTHORIZATION": "Bearer analyst-token",
        "HTTP_ORIGIN": origin,
        "REMOTE_ADDR": "127.0.0.1",
    }


def _socket_auth() -> dict[str, str]:
    return {"token": "analyst-token"}


def _socket_headers(*, origin: str = _ALLOWED_TEST_ORIGIN) -> dict[str, str]:
    return {
        "Authorization": "Bearer analyst-token",
        "Origin": origin,
    }


# ---------------------------------------------------------------------------
# Redis fixture (skipped when unreachable)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def bus() -> AsyncIterator[tuple[EventBus, RedisClient]]:
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    yield EventBus(client), client
    await client.aclose()


# ---------------------------------------------------------------------------
# Schema tests (no Redis required)
# ---------------------------------------------------------------------------


def test_schema_file_exists_and_is_valid_json() -> None:
    """The schema file must be present and parseable."""
    assert SCHEMA_PATH.is_file(), f"Schema file missing: {SCHEMA_PATH}"
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert "$schema" in doc
    assert "definitions" in doc


def test_schema_defines_all_event_types() -> None:
    """Every event type in SOCKET_MESSAGE_TYPES must have a oneOf entry."""
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    one_of = doc.get("oneOf")
    assert isinstance(one_of, list), "Schema root must have oneOf."
    assert len(one_of) == 18, f"Expected 18 entries in oneOf, got {len(one_of)}"

    types_in_schema: set[str] = set()
    for entry in one_of:
        props = entry.get("allOf", [{}])
        for part in props:
            p = part.get("properties", {})
            t = p.get("type", {})
            if "const" in t:
                types_in_schema.add(t["const"])
    assert types_in_schema == set(EXPECTED_EVENT_TYPES), (
        f"Schema types do not match SOCKET_MESSAGE_TYPES.\n"
        f"Missing: {set(EXPECTED_EVENT_TYPES) - types_in_schema}\n"
        f"Extra:   {types_in_schema - set(EXPECTED_EVENT_TYPES)}"
    )


def test_envelope_definition_has_required_fields() -> None:
    """The envelope schema mandates type, event_id, sequence, timestamp, payload."""
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    envelope = doc["definitions"]["SocketEventEnvelope"]
    assert envelope["type"] == "object"
    assert set(envelope["required"]) == {"type", "event_id", "sequence", "timestamp", "payload"}


@pytest.mark.parametrize(
    "event_type",
    EXPECTED_EVENT_TYPES,
)
def test_valid_payload_passes_validation(event_type: str) -> None:
    """Each event type validates with a minimal correct payload."""
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    payload = _example_payload(event_type)
    envelope = {
        "type": event_type,
        "event_id": "evt-20260712-a1b2c3d4",
        "sequence": 1,
        "timestamp": "2026-07-12T10:00:00Z",
        "payload": payload,
    }
    # jsonschema.validate raises on failure.
    jsonschema.validate(instance=envelope, schema=doc)


def test_approval_required_validates_non_null_impact_assessment() -> None:
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    envelope = {
        "type": "approval_required",
        "event_id": "evt-20260712-a1b2c3d4",
        "sequence": 1,
        "timestamp": "2026-07-12T10:00:00Z",
        "payload": _example_payload("approval_required"),
    }
    assert envelope["payload"]["impact_assessment"] is not None
    jsonschema.validate(instance=envelope, schema=doc)


def test_envelope_schema_error_helper_catches_referencing_failures() -> None:
    from app.core.socketio_manager import _is_envelope_schema_error

    class _WrappedReferencingError(Exception):
        pass

    assert _is_envelope_schema_error(jsonschema.ValidationError("bad envelope"))
    assert _is_envelope_schema_error(_WrappedReferencingError("unresolvable $ref"))
    assert _is_envelope_schema_error(RuntimeError("other")) is False


def test_writeback_updated_rejects_raw_result() -> None:
    """writeback_updated payload MUST NOT contain raw_result (intro §4.2.4)."""
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    envelope = {
        "type": "writeback_updated",
        "event_id": "evt-20260712-a1b2c3d4",
        "sequence": 1,
        "timestamp": "2026-07-12T10:00:00Z",
        "payload": {
            "disposition_id": "disp-0a1b2c3d",
            "writeback_id": "wbk-0a1b2c3d",
            "status": "CONFIRMED",
            "raw_result": {"vendor_secret": "must-not-leak"},
        },
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=envelope, schema=doc)


def test_writeback_updated_valid_payload() -> None:
    """writeback_updated with only allowed fields validates cleanly."""
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    envelope = {
        "type": "writeback_updated",
        "event_id": "evt-20260712-a1b2c3d4",
        "sequence": 1,
        "timestamp": "2026-07-12T10:00:00Z",
        "payload": {
            "disposition_id": "disp-0a1b2c3d",
            "writeback_id": "wbk-0a1b2c3d",
            "status": "CONFIRMED",
            "provider_code": "mock",
            "created_at": "2026-07-12T09:00:00Z",
            "updated_at": "2026-07-12T10:00:00Z",
        },
    }
    jsonschema.validate(instance=envelope, schema=doc)  # must not raise


def test_envelope_rejects_unknown_type() -> None:
    """An unknown event type must fail schema validation."""
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    envelope = {
        "type": "not_a_real_event",
        "event_id": "evt-20260712-a1b2c3d4",
        "sequence": 1,
        "timestamp": "2026-07-12T10:00:00Z",
        "payload": {},
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=envelope, schema=doc)


# ---------------------------------------------------------------------------
# Event handler unit tests (no Redis)
# ---------------------------------------------------------------------------


def _connect_session(sio: socketio.AsyncServer, sid: str) -> None:
    """Register a namespace session so ``enter_room`` / ``emit`` can succeed.

    .. warning::

       This helper reaches into ``sio.manager.rooms`` which is a private
       implementation detail of python-socketio.  If the library changes its
       internal session/room representation the tests will need updating.
       This is an acceptable trade-off for unit-level handler tests that
       avoid a full Engine.IO handshake.

    Mirrors what ``AsyncManager.connect()`` does internally:
    1. Creates the namespace key in ``self.rooms``.
    2. Adds a ``None → bidict({sid: eio_sid})`` entry for sid-to-eio resolution.
    3. Creates the self-room named after *sid* with a proper bidict.
    """
    from bidict import bidict as _bidict

    ns = SOCKETIO_NAMESPACE
    eio_sid = f"eio-{sid}"
    sio.manager.rooms.setdefault(ns, {})
    # The None key is the sid→eio_sid reverse-lookup used by basic_enter_room.
    if None not in sio.manager.rooms[ns]:
        sio.manager.rooms[ns][None] = _bidict()
    sio.manager.rooms[ns][None][sid] = eio_sid
    # Every connected sid has a self-room (the sid key itself); must be bidict
    # because python-socketio internals call ._fwdm on it.
    if sid not in sio.manager.rooms[ns]:
        sio.manager.rooms[ns][sid] = _bidict()
    sio.manager.rooms[ns][sid][sid] = eio_sid


def test_socketio_trusted_proxy_ignores_spoofed_forwarded_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The proxy allowlist is matched against the direct peer, never XFF."""
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "true")
    monkeypatch.setenv("TRUSTED_PROXY_ALLOWLIST", "10.0.0.8")
    get_settings.cache_clear()
    environ = {
        "HTTP_X_AUTH_SUBJECT": "spoofed-user",
        "HTTP_X_AUTH_ROLES": "admin",
        "HTTP_X_FORWARDED_FOR": "10.0.0.8",
        "REMOTE_ADDR": "203.0.113.20",
    }

    assert client_host_from_socketio_environ(environ) == "203.0.113.20"
    with pytest.raises(AuthenticationError):
        resolve_principal_from_socketio_handshake(environ)


def test_socketio_trusted_proxy_accepts_allowlisted_direct_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real trusted proxy may forward any end-user address without breaking auth."""
    monkeypatch.setenv("TRUSTED_AUTH_PROXY_ENABLED", "true")
    monkeypatch.setenv("TRUSTED_PROXY_ALLOWLIST", "10.0.0.8")
    get_settings.cache_clear()
    environ = {
        "HTTP_X_AUTH_SUBJECT": "proxied-user",
        "HTTP_X_AUTH_ROLES": "analyst",
        "HTTP_X_FORWARDED_FOR": "198.51.100.42",
        "REMOTE_ADDR": "10.0.0.8",
    }

    principal = resolve_principal_from_socketio_handshake(environ)

    assert principal.subject == "proxied-user"
    assert principal.roles == ["analyst"]


class TestEventHandlers:
    """Unit tests for connect / disconnect / subscribe handlers."""

    @pytest.fixture(autouse=True)
    def _stub_event_service(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _StubEvent:
            pass

        class _StubEventService:
            async def get_event(self, event_id: str) -> _StubEvent:
                return _StubEvent()

        async def _service() -> _StubEventService:
            return _StubEventService()

        monkeypatch.setattr("app.api.v1.deps.get_event_service", _service)

    @pytest.fixture
    def sessions(self) -> SocketIOSessionRegistry:
        return SocketIOSessionRegistry()

    @pytest.fixture
    def sio(self, sessions: SocketIOSessionRegistry) -> socketio.AsyncServer:
        srv = socketio.AsyncServer(async_mode="asgi", logger=False)
        register_handlers(srv, sessions=sessions)
        return srv

    @pytest.mark.asyncio
    async def test_connect_auto_joins_global_room(
        self,
        sio: socketio.AsyncServer,
        sessions: SocketIOSessionRegistry,
    ) -> None:
        """On connect, an analyst client is placed in the 'global' room."""
        sid = _fake_sid()
        _connect_session(sio, sid)

        handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert handler is not None, "connect handler not registered"
        accepted = await handler(sid, _auth_environ(), None)
        assert accepted is True

        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        assert GLOBAL_ROOM in ns_rooms, f"Global room not in {list(ns_rooms)}"
        assert sid in ns_rooms[GLOBAL_ROOM]
        assert sessions.get(sid) is not None

    @pytest.mark.asyncio
    async def test_connect_rejects_unauthenticated(
        self,
        sio: socketio.AsyncServer,
        sessions: SocketIOSessionRegistry,
    ) -> None:
        sid = _fake_sid()
        _connect_session(sio, sid)
        handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert handler is not None
        accepted = await handler(sid, {"REMOTE_ADDR": "127.0.0.1"}, None)
        assert accepted is False
        assert sessions.get(sid) is None

    @pytest.mark.asyncio
    async def test_connect_without_role_skips_global_room(
        self,
        sio: socketio.AsyncServer,
        sessions: SocketIOSessionRegistry,
    ) -> None:
        sid = _fake_sid()
        _connect_session(sio, sid)
        handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert handler is not None
        environ = {
            "HTTP_AUTHORIZATION": "Bearer norole-token",
            "REMOTE_ADDR": "127.0.0.1",
        }
        accepted = await handler(sid, environ, None)
        assert accepted is True
        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        assert sid not in ns_rooms.get(GLOBAL_ROOM, {})

    @pytest.mark.asyncio
    async def test_disconnect_clears_session_registry(
        self,
        sio: socketio.AsyncServer,
        sessions: SocketIOSessionRegistry,
    ) -> None:
        sid = _fake_sid()
        _connect_session(sio, sid)
        connect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert connect_handler is not None
        await connect_handler(sid, _auth_environ(), None)
        assert sessions.get(sid) is not None

        disconnect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("disconnect")
        assert disconnect_handler is not None
        await disconnect_handler(sid)
        assert sessions.get(sid) is None

    @pytest.mark.asyncio
    async def test_disconnect_handler_is_registered(self, sio: socketio.AsyncServer) -> None:
        """disconnect handler is registered on the /events namespace."""
        sid = _fake_sid()
        _connect_session(sio, sid)

        handler = sio.handlers[SOCKETIO_NAMESPACE].get("disconnect")
        assert handler is not None, "disconnect handler not registered"

        # disconnect handler should not raise — it only logs.
        await handler(sid)

    @pytest.mark.asyncio
    async def test_revoked_bearer_leaves_rooms_before_broadcast(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sio: socketio.AsyncServer,
        sessions: SocketIOSessionRegistry,
    ) -> None:
        sid = _fake_sid()
        _connect_session(sio, sid)
        connect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert connect_handler is not None
        await connect_handler(sid, _auth_environ(), None)
        assert sid in sio.manager.rooms[SOCKETIO_NAMESPACE][GLOBAL_ROOM]

        monkeypatch.setenv(
            "DEV_AUTH_TOKENS",
            json.dumps(
                {
                    "analyst-token": {"subject": "analyst-1", "roles": []},
                    "norole-token": {"subject": "norole-1", "roles": []},
                }
            ),
        )
        disconnect = AsyncMock()
        sio.disconnect = disconnect  # type: ignore[method-assign]

        cleanup_ok = await disconnect_invalid_sessions(sio, sessions)

        assert cleanup_ok is True
        assert sessions.get(sid) is None
        assert sid not in sio.manager.rooms[SOCKETIO_NAMESPACE].get(GLOBAL_ROOM, {})
        disconnect.assert_awaited_once_with(sid, namespace=SOCKETIO_NAMESPACE)

    @pytest.mark.asyncio
    async def test_subscribe_joins_event_room(self, sio: socketio.AsyncServer) -> None:
        """subscribe event adds client to event:{event_id} room."""
        sid = _fake_sid()
        event_id = "evt-20260712-deadbeef"

        _connect_session(sio, sid)
        connect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert connect_handler is not None
        await connect_handler(sid, _auth_environ(), None)

        handler = sio.handlers[SOCKETIO_NAMESPACE].get("subscribe")
        assert handler is not None, "subscribe handler not registered"
        await handler(sid, {"event_id": event_id})

        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        room = _event_room(event_id)
        assert room in ns_rooms
        assert sid in ns_rooms[room]
        assert sid not in ns_rooms.get(GLOBAL_ROOM, {}), "subscribe must leave global room"

    @pytest.mark.asyncio
    async def test_join_global_rejoins_after_subscribe(self, sio: socketio.AsyncServer) -> None:
        """join_global re-enters global and leaves the prior event room."""
        sid = _fake_sid()
        event_id = "evt-20260712-rejoinglobal"

        _connect_session(sio, sid)
        connect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert connect_handler is not None
        await connect_handler(sid, _auth_environ(), None)

        sub_h = sio.handlers[SOCKETIO_NAMESPACE].get("subscribe")
        assert sub_h is not None
        await sub_h(sid, {"event_id": event_id})

        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        assert sid not in ns_rooms.get(GLOBAL_ROOM, {})

        join_h = sio.handlers[SOCKETIO_NAMESPACE].get("join_global")
        assert join_h is not None, "join_global handler not registered"
        await join_h(sid, {})

        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        assert sid in ns_rooms.get(GLOBAL_ROOM, {})
        assert sid not in ns_rooms.get(_event_room(event_id), {})

    @pytest.mark.asyncio
    async def test_subscribe_rejects_missing_event_id(self, sio: socketio.AsyncServer) -> None:
        """subscribe without event_id emits an error, does not join any room."""
        sid = _fake_sid()

        _connect_session(sio, sid)
        connect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert connect_handler is not None
        await connect_handler(sid, _auth_environ(), None)

        handler = sio.handlers[SOCKETIO_NAMESPACE].get("subscribe")
        assert handler is not None

        await handler(sid, {})

        # The sid should only be in its own room (self) and global.
        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        event_rooms = {
            r for r in ns_rooms if r is not None and isinstance(r, str) and r.startswith("event:")
        }
        for room in event_rooms:
            assert sid not in ns_rooms[room], f"sid should NOT be in {room}"

    @pytest.mark.asyncio
    async def test_multiple_clients_subscribe_same_event(self, sio: socketio.AsyncServer) -> None:
        """Two clients can subscribe to the same event room independently."""
        sid_a = _fake_sid()
        sid_b = _fake_sid()
        event_id = "evt-20260712-aabbccdd"

        for sid in (sid_a, sid_b):
            _connect_session(sio, sid)
            connect_h = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
            assert connect_h is not None
            await connect_h(sid, _auth_environ(), None)

            sub_h = sio.handlers[SOCKETIO_NAMESPACE].get("subscribe")
            assert sub_h is not None
            await sub_h(sid, {"event_id": event_id})

        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        room = _event_room(event_id)
        assert room in ns_rooms
        for sid in (sid_a, sid_b):
            assert sid in ns_rooms[room], f"{sid} missing from {room}"


@pytest.mark.asyncio
async def test_manager_periodically_revalidates_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SocketIOManager(AsyncMock())  # type: ignore[arg-type]
    cleanup = AsyncMock(return_value=True)

    async def _finish_interval(_delay: float) -> None:
        manager._stopping = True

    monkeypatch.setattr("app.core.socketio_manager.asyncio.sleep", _finish_interval)
    monkeypatch.setattr(
        "app.core.socketio_manager.disconnect_invalid_sessions",
        cleanup,
    )

    await manager._validate_sessions()

    cleanup.assert_awaited_once_with(manager.sio, manager._sessions)


@pytest.mark.asyncio
async def test_manager_stop_clears_registry_without_detaching_handlers() -> None:
    manager = SocketIOManager(AsyncMock())  # type: ignore[arg-type]
    registry = manager._sessions
    sid = _fake_sid()
    _connect_session(manager.sio, sid)
    connect_handler = manager.sio.handlers[SOCKETIO_NAMESPACE].get("connect")
    assert connect_handler is not None
    await connect_handler(sid, _auth_environ(), None)
    assert registry.get(sid) is not None
    manager.sio.disconnect = AsyncMock()  # type: ignore[method-assign]

    await manager.stop()

    assert manager._sessions is registry
    assert registry.get(sid) is None


@pytest.mark.asyncio
async def test_health_snapshot_stopped_before_start() -> None:
    manager = SocketIOManager(AsyncMock())  # type: ignore[arg-type]
    snapshot = manager.health_snapshot()
    assert snapshot["status"] == "stopped"
    assert snapshot["listener_running"] is False
    assert snapshot["consecutive_failures"] == 0
    assert snapshot["last_success_at"] is None
    assert snapshot["last_error_class"] is None


@pytest.mark.asyncio
async def test_health_snapshot_ok_while_listener_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SocketIOManager(AsyncMock())  # type: ignore[arg-type]

    async def _healthy_subscriber() -> None:
        from datetime import UTC, datetime

        manager._last_success_at = datetime.now(UTC).isoformat()
        while not manager._stopping:
            await asyncio.sleep(0.01)

    monkeypatch.setattr(manager, "_run_subscriber", _healthy_subscriber)

    await manager.start()
    await asyncio.sleep(0.05)

    snapshot = manager.health_snapshot()
    assert snapshot["status"] == "ok"
    assert snapshot["listener_running"] is True
    assert snapshot["last_success_at"] is not None

    await manager.stop()


@pytest.mark.asyncio
async def test_health_snapshot_degraded_after_subscriber_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SocketIOManager(AsyncMock())  # type: ignore[arg-type]

    async def _fail_subscriber() -> None:
        raise FileNotFoundError("missing schema")

    monkeypatch.setattr(manager, "_run_subscriber", _fail_subscriber)

    async def _stop_after_retry(_delay: float) -> None:
        manager._stopping = True

    monkeypatch.setattr("app.core.socketio_manager.asyncio.sleep", _stop_after_retry)

    await manager._listen()

    snapshot = manager.health_snapshot()
    assert snapshot["status"] == "degraded"
    assert snapshot["last_error_class"] == "FileNotFoundError"
    assert snapshot["consecutive_failures"] == 1
    assert snapshot["subscriber_failures"] == 1
    assert "missing schema" not in str(snapshot)


@pytest.mark.asyncio
async def test_health_snapshot_recovers_after_subscriber_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SocketIOManager(AsyncMock())  # type: ignore[arg-type]
    attempts = {"count": 0}
    recovered = asyncio.Event()

    async def _flaky_subscriber() -> None:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise ConnectionError("redis unavailable")
        if attempts["count"] == 2:
            from datetime import UTC, datetime

            manager._last_success_at = datetime.now(UTC).isoformat()
            recovered.set()
            return
        while not manager._stopping:
            await asyncio.sleep(0)

    monkeypatch.setattr(manager, "_run_subscriber", _flaky_subscriber)

    real_sleep = asyncio.sleep

    async def _noop_sleep(_delay: float) -> None:
        await real_sleep(0)

    monkeypatch.setattr("app.core.socketio_manager.asyncio.sleep", _noop_sleep)

    await manager.start()
    await asyncio.wait_for(recovered.wait(), timeout=1.0)
    await real_sleep(0)

    snapshot = manager.health_snapshot()
    assert snapshot["status"] == "ok"
    assert snapshot["listener_running"] is True
    assert snapshot["last_error_class"] is None
    assert snapshot["consecutive_failures"] == 0
    assert snapshot["subscriber_failures"] == 1
    assert snapshot["subscriber_recoveries"] == 1

    await manager.stop()


@pytest.mark.asyncio
async def test_health_snapshot_marks_degraded_during_recovery_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SocketIOManager(AsyncMock())  # type: ignore[arg-type]

    async def _always_fail() -> None:
        raise RuntimeError("subscriber down")

    sleeps: list[float] = []

    async def _record_sleep(delay: float) -> None:
        sleeps.append(delay)
        if delay >= 30.0:
            snapshot = manager.health_snapshot()
            assert snapshot["status"] == "degraded"
            assert manager._bridge_degraded is True
            manager._stopping = True
            raise asyncio.CancelledError

    monkeypatch.setattr(manager, "_run_subscriber", _always_fail)
    monkeypatch.setattr("app.core.socketio_manager.asyncio.sleep", _record_sleep)

    with pytest.raises(asyncio.CancelledError):
        await manager._listen()

    assert sleeps.count(2.0) == 4
    assert 30.0 in sleeps
    assert manager.health_snapshot()["subscriber_failures"] == 5


# ---------------------------------------------------------------------------
# Redis-dependent integration tests
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def redis_required() -> RedisClient:
    """Yields a RedisClient if Redis is alive; skip the test otherwise."""
    client = RedisClient(url=REDIS_URL)
    if not await client.ping():
        await client.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")
    return client


@pytest_asyncio.fixture
async def socketio_server() -> AsyncIterator[tuple[SocketIOManager, EventBus, str]]:
    """Live ASGI server with Redis→Socket.IO bridge for client e2e tests."""
    redis = RedisClient(url=REDIS_URL)
    if not await redis.ping():
        await redis.aclose()
        pytest.skip("Redis not reachable; start Compose redis first")

    manager = SocketIOManager(redis)
    event_bus = EventBus(redis)
    asgi_app = manager.mount(FastAPI())
    await manager.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    config = uvicorn.Config(asgi_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    serve_task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)

    base_url = f"http://127.0.0.1:{port}"
    try:
        yield manager, event_bus, base_url
    finally:
        server.should_exit = True
        await serve_task
        await manager.stop()
        await redis.aclose()


@pytest.mark.asyncio
async def test_eventbus_publish_reaches_redis_subscriber(
    bus: tuple[EventBus, RedisClient],
    redis_required: RedisClient,  # noqa: ARG001 — ensures Redis is alive
) -> None:
    """EventBus publish/subscribe smoke test (ISSUE-013), not Socket.IO delivery."""
    event_bus, _redis = bus
    event_id = _event_id("bus00001")
    received: asyncio.Queue[dict] = asyncio.Queue()

    async def _reader() -> None:
        async for envelope in event_bus.subscribe(event_id):
            await received.put(envelope)
            break

    task = asyncio.create_task(_reader())
    await asyncio.sleep(0.05)

    published = await event_bus.publish_event(
        event_id,
        "state_change",
        _example_payload("state_change"),
    )
    assert published is True

    envelope = await asyncio.wait_for(received.get(), timeout=1.0)
    await asyncio.wait_for(task, timeout=1.0)

    assert envelope["event_id"] == event_id
    assert envelope["message_type"] == "state_change"
    assert envelope["payload"]["to_status"] == "triaging"


@pytest.mark.asyncio
async def test_socket_client_receives_state_change_within_one_second(
    socketio_server: tuple[SocketIOManager, EventBus, str],
) -> None:
    """Acceptance #1: subscribed Socket.IO client receives state_change within 1s."""
    _manager, event_bus, base_url = socketio_server
    event_id = _event_id("sock0001")
    received: asyncio.Queue[dict] = asyncio.Queue()

    async def _on_event(data: dict) -> None:
        await received.put(data)

    client = socketio.AsyncClient()
    client.on("event", _on_event, namespace=SOCKETIO_NAMESPACE)
    await client.connect(
        base_url,
        namespaces=[SOCKETIO_NAMESPACE],
        auth=_socket_auth(),
        headers=_socket_headers(),
        wait_timeout=5,
    )
    try:
        await client.emit("subscribe", {"event_id": event_id}, namespace=SOCKETIO_NAMESPACE)
        await asyncio.sleep(0.05)
        ok = await event_bus.publish_event(
            event_id,
            "state_change",
            _example_payload("state_change"),
        )
        assert ok is True
        msg = await asyncio.wait_for(received.get(), timeout=1.0)
    finally:
        await client.disconnect()

    assert msg["type"] == "state_change"
    assert msg["event_id"] == event_id
    assert msg["sequence"] >= 1
    assert "timestamp" in msg
    assert msg["payload"]["to_status"] == "triaging"
    assert msg["payload"]["operator"] == "StateMachineService"


@pytest.mark.asyncio
async def test_subscribed_client_receives_event_once_not_twice(
    socketio_server: tuple[SocketIOManager, EventBus, str],
) -> None:
    """Subscribed clients leave global so they do not receive duplicate emits."""
    _manager, event_bus, base_url = socketio_server
    event_id = _event_id("once0001")
    received: list[dict] = []

    async def _on_event(data: dict) -> None:
        received.append(data)

    client = socketio.AsyncClient()
    client.on("event", _on_event, namespace=SOCKETIO_NAMESPACE)
    await client.connect(
        base_url,
        namespaces=[SOCKETIO_NAMESPACE],
        auth=_socket_auth(),
        headers=_socket_headers(),
        wait_timeout=5,
    )
    try:
        await client.emit("subscribe", {"event_id": event_id}, namespace=SOCKETIO_NAMESPACE)
        await asyncio.sleep(0.05)
        ok = await event_bus.publish_event(
            event_id,
            "state_change",
            _example_payload("state_change"),
        )
        assert ok is True
        await asyncio.sleep(0.3)
    finally:
        await client.disconnect()

    assert len(received) == 1
    assert received[0]["event_id"] == event_id


@pytest.mark.asyncio
async def test_global_only_client_receives_broadcast(
    socketio_server: tuple[SocketIOManager, EventBus, str],
) -> None:
    """Dashboard clients that never subscribe still receive events via global room."""
    _manager, event_bus, base_url = socketio_server
    event_id = _event_id("glob0001")
    received: asyncio.Queue[dict] = asyncio.Queue()

    async def _on_event(data: dict) -> None:
        await received.put(data)

    client = socketio.AsyncClient()
    client.on("event", _on_event, namespace=SOCKETIO_NAMESPACE)
    await client.connect(
        base_url,
        namespaces=[SOCKETIO_NAMESPACE],
        auth=_socket_auth(),
        headers=_socket_headers(),
        wait_timeout=5,
    )
    try:
        await asyncio.sleep(0.05)
        ok = await event_bus.publish_event(
            event_id,
            "state_change",
            _example_payload("state_change"),
        )
        assert ok is True
        msg = await asyncio.wait_for(received.get(), timeout=1.0)
    finally:
        await client.disconnect()

    assert msg["event_id"] == event_id
    assert msg["type"] == "state_change"


@pytest.mark.asyncio
async def test_sequence_increments_per_event_id(
    redis_required: RedisClient,  # noqa: ARG001
) -> None:
    """Sequence numbers are maintained per event_id via Redis INCR."""
    client = RedisClient(url=REDIS_URL)
    try:
        from app.core.socketio_manager import _sequence_key

        event_a = f"evt-{_today_str()}-{uuid.uuid4().hex[:8]}"
        event_b = f"evt-{_today_str()}-{uuid.uuid4().hex[:8]}"
        r = client.get_client()

        # Cleanup old keys.
        await r.delete(_sequence_key(event_a), _sequence_key(event_b))

        # Each event_id should start at 1 and increment independently.
        assert int(await r.incr(_sequence_key(event_a))) == 1
        assert int(await r.incr(_sequence_key(event_a))) == 2
        assert int(await r.incr(_sequence_key(event_b))) == 1
        assert int(await r.incr(_sequence_key(event_a))) == 3
        assert int(await r.incr(_sequence_key(event_b))) == 2
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_bridge_dispatch_emits_valid_envelope(redis_required: RedisClient) -> None:
    """``_dispatch`` builds a schema-valid Socket.IO envelope and increments sequence."""
    client = RedisClient(url=REDIS_URL)
    try:
        from app.core.socketio_manager import _sequence_key

        sio = socketio.AsyncServer(async_mode="asgi", logger=False)
        sessions = SocketIOSessionRegistry()
        register_handlers(sio, sessions=sessions)
        manager = SocketIOManager(client)
        manager._sio = sio  # type: ignore[assignment]

        event_id = _event_id("bridge01")
        emitted: list[dict] = []

        async def _capture(
            event: str,
            data: dict,
            room: str | None = None,
            **kwargs: object,
        ) -> None:
            if event == "event":
                emitted.append(data)

        sio.emit = _capture  # type: ignore[method-assign, assignment]

        channel = f"shadowtrace:events:{event_id}".encode()
        payload = {
            "message_type": "state_change",
            "timestamp": "2026-07-12T10:00:00Z",
            "payload": _example_payload("state_change"),
        }
        payload_bytes = RedisClient.dumps(payload)

        await client.get_client().delete(_sequence_key(event_id))
        await manager._dispatch(channel, payload_bytes)

        seq = int(await client.get_client().get(_sequence_key(event_id)) or 0)
        assert seq == 1
        assert len(emitted) == 2  # event room + global room emits
        assert all(item["event_id"] == event_id for item in emitted)
        assert all(item["type"] == "state_change" for item in emitted)
        jsonschema.validate(
            instance=emitted[0],
            schema=json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
        )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_dispatch_skips_emit_when_sequence_incr_fails(
    redis_required: RedisClient,  # noqa: ARG001
) -> None:
    """INCR failure must not emit with a stale sequence."""
    client = RedisClient(url=REDIS_URL)
    try:
        manager = SocketIOManager(client)
        emitted: list[dict] = []

        async def _capture(event: str, data: dict, **kwargs: object) -> None:
            if event == "event":
                emitted.append(data)

        manager._sio.emit = _capture  # type: ignore[method-assign, assignment]

        event_id = _event_id("noincr1")
        channel = f"shadowtrace:events:{event_id}".encode()
        payload_bytes = RedisClient.dumps(
            {
                "message_type": "state_change",
                "payload": _example_payload("state_change"),
            }
        )

        with patch.object(
            manager,
            "_increment_sequence",
            AsyncMock(return_value=None),
        ):
            await manager._dispatch(channel, payload_bytes)

        assert emitted == []
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_dispatch_redacts_secrets_before_emit(redis_required: RedisClient) -> None:
    """Bridge re-sanitizes payload before Socket.IO emit."""
    client = RedisClient(url=REDIS_URL)
    try:
        manager = SocketIOManager(client)
        captured: list[dict] = []

        async def _capture(event: str, data: dict, **kwargs: object) -> None:
            if event == "event":
                captured.append(data)

        manager._sio.emit = _capture  # type: ignore[method-assign, assignment]

        event_id = _event_id("redact01")
        channel = f"shadowtrace:events:{event_id}".encode()
        payload = _example_payload("state_change")
        payload["reason"] = "Authorization: Bearer must-not-leak"
        payload_bytes = RedisClient.dumps({"message_type": "state_change", "payload": payload})

        await manager._dispatch(channel, payload_bytes)
        assert captured
        assert "must-not-leak" not in captured[0]["payload"]["reason"]
        assert "[REDACTED]" in captured[0]["payload"]["reason"]
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_all_event_types_publishable(bus: tuple[EventBus, RedisClient]) -> None:
    """Each of the 18 event types can be published with schema-valid payloads."""
    event_bus, _redis = bus
    event_id = _event_id("alltype1")

    for msg_type in sorted(SOCKET_MESSAGE_TYPES):
        ok = await event_bus.publish_event(
            event_id,
            msg_type,
            _example_payload(msg_type),
        )
        assert ok is True, f"publish failed for type={msg_type}"


@pytest.mark.asyncio
async def test_two_socket_clients_in_event_room_both_receive_broadcast(
    socketio_server: tuple[SocketIOManager, EventBus, str],
) -> None:
    """Acceptance #3: two Socket.IO clients in the same event room both receive the event."""
    _manager, event_bus, base_url = socketio_server
    event_id = _event_id("multi001")
    queue_a: asyncio.Queue[dict] = asyncio.Queue()
    queue_b: asyncio.Queue[dict] = asyncio.Queue()

    async def _make_client(queue: asyncio.Queue[dict]) -> socketio.AsyncClient:
        async def _on_event(data: dict) -> None:
            await queue.put(data)

        c = socketio.AsyncClient()
        c.on("event", _on_event, namespace=SOCKETIO_NAMESPACE)
        await c.connect(
            base_url,
            namespaces=[SOCKETIO_NAMESPACE],
            auth=_socket_auth(),
            headers=_socket_headers(),
            wait_timeout=5,
        )
        await c.emit("subscribe", {"event_id": event_id}, namespace=SOCKETIO_NAMESPACE)
        return c

    client_a = await _make_client(queue_a)
    client_b = await _make_client(queue_b)
    try:
        await asyncio.sleep(0.05)
        ok = await event_bus.publish_event(
            event_id,
            "state_change",
            _example_payload("state_change"),
        )
        assert ok is True
        msg_a = await asyncio.wait_for(queue_a.get(), timeout=2.0)
        msg_b = await asyncio.wait_for(queue_b.get(), timeout=2.0)
    finally:
        await client_a.disconnect()
        await client_b.disconnect()

    assert msg_a["type"] == msg_b["type"] == "state_change"
    assert msg_a["event_id"] == msg_b["event_id"] == event_id
    assert msg_a["sequence"] == msg_b["sequence"]


@pytest.mark.asyncio
async def test_eventbus_multicast_to_two_redis_subscribers(redis_required: RedisClient) -> None:
    """Two Redis subscribers on the same channel both receive the EventBus message."""
    client = RedisClient(url=REDIS_URL)
    try:
        event_bus = EventBus(client)
        event_id = _event_id("redismc")

        queue_a: asyncio.Queue[dict] = asyncio.Queue()
        queue_b: asyncio.Queue[dict] = asyncio.Queue()

        async def _reader(q: asyncio.Queue[dict]) -> None:
            async for envelope in event_bus.subscribe(event_id):
                await q.put(envelope)
                break

        task_a = asyncio.create_task(_reader(queue_a))
        task_b = asyncio.create_task(_reader(queue_b))
        await asyncio.sleep(0.05)

        ok = await event_bus.publish_event(
            event_id,
            "state_change",
            _example_payload("state_change"),
        )
        assert ok is True

        env_a = await asyncio.wait_for(queue_a.get(), timeout=2.0)
        env_b = await asyncio.wait_for(queue_b.get(), timeout=2.0)
        await asyncio.wait_for(asyncio.gather(task_a, task_b), timeout=1.0)

        assert env_a["message_type"] == "state_change"
        assert env_b["message_type"] == "state_change"
        assert env_a["event_id"] == env_b["event_id"] == event_id
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_publish_failure_graceful_without_redis(
    redis_required: RedisClient,  # noqa: ARG001
) -> None:
    """When Redis is down, publish_event returns False but does not raise."""
    dead = RedisClient(url="redis://127.0.0.1:1/0", max_connections=1)
    event_bus = EventBus(dead)
    try:
        ok = await event_bus.publish_event("evt-x", "state_change", {})
        assert ok is False
    finally:
        await dead.aclose()


@pytest.mark.asyncio
async def test_unauthenticated_socket_client_is_rejected(
    socketio_server: tuple[SocketIOManager, EventBus, str],
) -> None:
    """ISSUE-258: connections without credentials fail before joining rooms."""
    _manager, _event_bus, base_url = socketio_server
    client = socketio.AsyncClient()
    with pytest.raises(socketio.exceptions.ConnectionError):
        await client.connect(
            base_url,
            namespaces=[SOCKETIO_NAMESPACE],
            headers={"Origin": _ALLOWED_TEST_ORIGIN},
            wait_timeout=5,
        )


@pytest.mark.asyncio
async def test_non_allowlisted_origin_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    redis_required: RedisClient,  # noqa: ARG001
) -> None:
    """ISSUE-258: Engine.IO rejects handshakes from origins outside the allowlist."""
    monkeypatch.setenv("SOCKETIO_CORS_ALLOWED_ORIGINS", "http://allowed-only.example")
    get_settings.cache_clear()

    redis = RedisClient(url=REDIS_URL)
    try:
        manager = SocketIOManager(redis)
        asgi_app = manager.mount(FastAPI())
        await manager.start()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]

        config = uvicorn.Config(asgi_app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)
        serve_task = asyncio.create_task(server.serve())
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)

        base_url = f"http://127.0.0.1:{port}"
        client = socketio.AsyncClient()
        try:
            with pytest.raises(socketio.exceptions.ConnectionError):
                await client.connect(
                    base_url,
                    namespaces=[SOCKETIO_NAMESPACE],
                    auth=_socket_auth(),
                    headers=_socket_headers(origin="http://evil.example"),
                    wait_timeout=5,
                )
        finally:
            await client.disconnect()
            server.should_exit = True
            await serve_task
            await manager.stop()
    finally:
        await redis.aclose()
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_subscribe_rejects_missing_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-258: subscribe to a non-existent event is rejected."""
    sessions = SocketIOSessionRegistry()
    sio = socketio.AsyncServer(async_mode="asgi", logger=False)
    register_handlers(sio, sessions=sessions)
    sid = _fake_sid()
    _connect_session(sio, sid)

    class _MissingEventService:
        async def get_event(self, event_id: str) -> None:
            return None

    from app.api.v1.deps import get_event_service as _real_get_event_service  # noqa: F401

    async def _missing_event_service() -> _MissingEventService:
        return _MissingEventService()

    monkeypatch.setattr(
        "app.api.v1.deps.get_event_service",
        _missing_event_service,
    )

    connect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
    assert connect_handler is not None
    await connect_handler(sid, _auth_environ(), None)

    handler = sio.handlers[SOCKETIO_NAMESPACE].get("subscribe")
    assert handler is not None
    await handler(sid, {"event_id": "evt-20260712-deadbeef"})

    ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
    room = _event_room("evt-20260712-deadbeef")
    assert room not in ns_rooms or sid not in ns_rooms.get(room, {})


@pytest.mark.asyncio
async def test_roleless_client_does_not_receive_global_broadcast(
    socketio_server: tuple[SocketIOManager, EventBus, str],
) -> None:
    """ISSUE-258: authenticated principals without platform roles skip global room."""
    _manager, event_bus, base_url = socketio_server
    event_id = _event_id("norole01")
    received: list[dict] = []

    async def _on_event(data: dict) -> None:
        received.append(data)

    client = socketio.AsyncClient()
    client.on("event", _on_event, namespace=SOCKETIO_NAMESPACE)
    await client.connect(
        base_url,
        namespaces=[SOCKETIO_NAMESPACE],
        auth={"token": "norole-token"},
        headers={
            "Authorization": "Bearer norole-token",
            "Origin": _ALLOWED_TEST_ORIGIN,
        },
        wait_timeout=5,
    )
    try:
        await asyncio.sleep(0.05)
        ok = await event_bus.publish_event(
            event_id,
            "state_change",
            _example_payload("state_change"),
        )
        assert ok is True
        await asyncio.sleep(0.3)
    finally:
        await client.disconnect()

    assert received == []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _today_str() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y%m%d")


def _event_id(label: str) -> str:
    """Return a schema-valid event_id (evt-YYYYMMDD-<8 hex>)."""
    suffix = uuid.uuid4().hex[:8]
    return f"evt-{_today_str()}-{suffix}"


_counter = 0


def _fake_sid() -> str:
    global _counter
    _counter += 1
    return f"test-sid-{_counter:04d}"


def _example_payload(event_type: str) -> dict:
    """Return a minimal valid payload dict for the given event type."""
    examples: dict[str, dict] = {
        "event_created": {
            "event_id": "evt-20260712-a1b2c3d4",
            "severity": "high",
            "event_type": "malware",
            "source_product": "mock_xdr",
            "created_at": "2026-07-12T10:00:00Z",
        },
        "state_change": {
            "from_status": "new",
            "to_status": "triaging",
            "operator": "StateMachineService",
        },
        "agent_progress": {
            "agent_name": "TriageAgent",
            "phase": "analyzing",
            "message": "Extracting IOCs...",
            "progress_pct": 50,
            "step_index": 1,
            "total_steps": 3,
        },
        "agent_completed": {
            "agent_name": "TriageAgent",
            "output_summary": "Triage complete: 3 IOCs found",
            "duration_ms": 1200.5,
            "degraded": False,
        },
        "agent_failed": {
            "agent_name": "EvidenceAgent",
            "error": "LLM timeout after 3 retries",
            "error_code": "llm_timeout",
            "retryable": True,
        },
        "tool_call_started": {
            "call_id": "call-0a1b2c3d",
            "tool_name": "query_siem",
            "agent_name": "EvidenceAgent",
            "provider_code": "mock",
        },
        "tool_call_completed": {
            "call_id": "call-0a1b2c3d",
            "tool_name": "query_siem",
            "status": "success",
            "duration_ms": 350.0,
        },
        "approval_required": {
            "action_id": "act-0a1b2c3d",
            "action_name": "isolate_host",
            "summary": "Isolate host workstation-01",
            "target_count": 1,
            "deadline": "2026-07-12T10:30:00Z",
            "impact_assessment": {
                "action_id": "act-0a1b2c3d",
                "impact_score": 72,
                "affected_scope": "host workstation-01",
                "reversible": True,
                "business_disruption": "medium",
                "assessment_detail": "isolate_host blast radius",
                "affected_entity_count": 1,
                "affected_targets": ["workstation-01"],
                "assessed_by": "ImpactAssessmentService",
            },
        },
        "approval_updated": {
            "action_id": "act-0a1b2c3d",
            "decision": "approved",
            "approver": "principal:analyst-1",
            "comment": "Approved after review",
        },
        "action_executed": {
            "action_id": "act-0a1b2c3d",
            "action_name": "isolate_host",
            "execution_owner": "DIRECT_TOOL",
            "job_id": "job-0a1b2c3d",
            "target_count": 1,
        },
        "action_verified": {
            "action_id": "act-0a1b2c3d",
            "verification_result": "verified",
            "verdict": "Host confirmed isolated",
            "conflict_count": 0,
        },
        "risk_updated": {
            "risk_score": 85,
            "previous_score": 60,
            "factors": ["lateral_movement_detected", "sensitive_data_access"],
        },
        "report_generated": {
            "report_id": "rpt-0a1b2c3d",
            "sections": 5,
            "generated_at": "2026-07-12T11:00:00Z",
        },
        "final_verdict_updated": {
            "verdict": "true_positive",
            "previous_verdict": "uncertain",
            "matched_case_id": "case-0a1b2c3d",
        },
        "event_type_rewritten": {
            "event_type": "malicious_process",
            "previous_event_type": "other",
            "operator": "TriageAgent",
        },
        "disposition_submitted": {
            "disposition_id": "disp-0a1b2c3d",
            "intent_kind": "ENTITY_ACTION_SUBMIT",
            "action_id": "act-0a1b2c3d",
            "target_count": 3,
            "provider_code": "mock",
        },
        "writeback_updated": {
            "disposition_id": "disp-0a1b2c3d",
            "writeback_id": "wbk-0a1b2c3d",
            "status": "CONFIRMED",
            "provider_code": "mock",
            "created_at": "2026-07-12T09:00:00Z",
            "updated_at": "2026-07-12T10:00:00Z",
        },
        "writeback_readback_failed": {
            "disposition_id": "disp-0a1b2c3d",
            "writeback_id": "wbk-0a1b2c3d",
            "receipt_status": "ACCEPTED",
            "error_summary": "readback confirmation timed out",
            "severity": "warning",
        },
    }
    return examples.get(event_type, {})
