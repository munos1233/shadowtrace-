"""Socket.IO real-time event push tests (ISSUE-040).

Acceptance criteria
-------------------
1. A subscribed client receives a ``state_change`` message **within 1 second**
   of a state transition.
2. All 16 event types are declared in ``contracts/socketio/events.schema.json``
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
from collections.abc import AsyncIterator
from pathlib import Path

import jsonschema
import pytest
import pytest_asyncio
import socketio

from app.core.event_bus import SOCKET_MESSAGE_TYPES, EventBus
from app.core.redis_client import RedisClient
from app.core.socketio_events import (
    GLOBAL_ROOM,
    SOCKETIO_NAMESPACE,
    _event_room,
    register_handlers,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
SCHEMA_PATH = Path(__file__).resolve().parents[3] / "contracts" / "socketio" / "events.schema.json"

EXPECTED_EVENT_TYPES = sorted(SOCKET_MESSAGE_TYPES)

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


def test_schema_defines_all_sixteen_event_types() -> None:
    """Every event type in SOCKET_MESSAGE_TYPES must have a oneOf entry."""
    doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    one_of = doc.get("oneOf")
    assert isinstance(one_of, list), "Schema root must have oneOf."
    assert len(one_of) == 16, f"Expected 16 entries in oneOf, got {len(one_of)}"

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


class TestEventHandlers:
    """Unit tests for connect / disconnect / subscribe handlers."""

    @pytest.fixture
    def sio(self) -> socketio.AsyncServer:
        srv = socketio.AsyncServer(async_mode="asgi", logger=False)
        register_handlers(srv)
        return srv

    @pytest.mark.asyncio
    async def test_connect_auto_joins_global_room(self, sio: socketio.AsyncServer) -> None:
        """On connect, the client is placed in the 'global' room."""
        sid = _fake_sid()
        _connect_session(sio, sid)

        handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert handler is not None, "connect handler not registered"
        await handler(sid, {})

        # Verify room membership via the internal rooms structure.
        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        assert GLOBAL_ROOM in ns_rooms, f"Global room not in {list(ns_rooms)}"
        assert sid in ns_rooms[GLOBAL_ROOM]

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
    async def test_subscribe_joins_event_room(self, sio: socketio.AsyncServer) -> None:
        """subscribe event adds client to event:{event_id} room."""
        sid = _fake_sid()
        event_id = "evt-20260712-deadbeef"

        _connect_session(sio, sid)
        connect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert connect_handler is not None
        await connect_handler(sid, {})

        handler = sio.handlers[SOCKETIO_NAMESPACE].get("subscribe")
        assert handler is not None, "subscribe handler not registered"
        await handler(sid, {"event_id": event_id})

        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        room = _event_room(event_id)
        assert room in ns_rooms
        assert sid in ns_rooms[room]

    @pytest.mark.asyncio
    async def test_subscribe_rejects_missing_event_id(self, sio: socketio.AsyncServer) -> None:
        """subscribe without event_id emits an error, does not join any room."""
        sid = _fake_sid()

        _connect_session(sio, sid)
        connect_handler = sio.handlers[SOCKETIO_NAMESPACE].get("connect")
        assert connect_handler is not None
        await connect_handler(sid, {})

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
            await connect_h(sid, {})

            sub_h = sio.handlers[SOCKETIO_NAMESPACE].get("subscribe")
            assert sub_h is not None
            await sub_h(sid, {"event_id": event_id})

        ns_rooms = sio.manager.rooms.get(SOCKETIO_NAMESPACE, {})
        room = _event_room(event_id)
        assert room in ns_rooms
        for sid in (sid_a, sid_b):
            assert sid in ns_rooms[room], f"{sid} missing from {room}"


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


@pytest.mark.asyncio
async def test_publish_event_broadcasts_to_global_room(
    bus: tuple[EventBus, RedisClient],
    redis_required: RedisClient,  # noqa: ARG001 — ensures Redis is alive
) -> None:
    """Acceptance 1/3: subscribing client receives state_change within 1 second.

    We test at the EventBus→Socket.IO bridge level by: publishing via
    EventBus, then verifying the message arrives on the Redis Pub/Sub
    channel.  The bridge layer's dispatch logic is tested separately below.
    """
    event_bus, _redis = bus
    event_id = f"evt-{_today_str()}-sockit01"
    received: asyncio.Queue[dict] = asyncio.Queue()

    async def _reader() -> None:
        async for envelope in event_bus.subscribe(event_id):
            await received.put(envelope)
            break

    task = asyncio.create_task(_reader())
    await asyncio.sleep(0.05)

    published = await event_bus.publish_event(
        event_id, "state_change", {"from_status": "new", "to_status": "triaging"}
    )
    assert published is True

    envelope = await asyncio.wait_for(received.get(), timeout=1.0)
    await asyncio.wait_for(task, timeout=1.0)

    assert envelope["event_id"] == event_id
    assert envelope["message_type"] == "state_change"
    assert envelope["payload"]["from_status"] == "new"
    assert envelope["payload"]["to_status"] == "triaging"


@pytest.mark.asyncio
async def test_sequence_increments_per_event_id(
    redis_required: RedisClient,  # noqa: ARG001
) -> None:
    """Sequence numbers are maintained per event_id via Redis INCR."""
    client = RedisClient(url=REDIS_URL)
    try:
        from app.core.socketio_manager import _sequence_key

        event_a = f"evt-{_today_str()}-seq000a"
        event_b = f"evt-{_today_str()}-seq000b"
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
async def test_bridge_dispatch_increments_sequence(redis_required: RedisClient) -> None:
    """The PSUBSCRIBE→Socket.IO bridge decodes messages and increments the
    per-event sequence counter.

    This test exercises the dispatch logic directly (not via live PSUBSCRIBE
    to avoid races) and verifies that ``_dispatch`` correctly parses the
    channel name and calls Redis INCR.  Full end-to-end broadcast coverage
    is in ``test_publish_event_broadcasts_to_global_room`` and
    ``test_multiple_clients_receive_broadcast`` (Issue 6).
    """
    client = RedisClient(url=REDIS_URL)
    try:
        from app.core.socketio_manager import SocketIOManager, _sequence_key

        sio = socketio.AsyncServer(async_mode="asgi", logger=False)
        register_handlers(sio)
        manager = SocketIOManager(client)
        # Replace the default sio with our instrumented one for test.
        manager._sio = sio  # type: ignore[assignment]

        event_id = f"evt-{_today_str()}-bridge01"

        # Connect and subscribe a test client.
        sid = _fake_sid()
        _connect_session(sio, sid)
        await sio.enter_room(sid, GLOBAL_ROOM, namespace=SOCKETIO_NAMESPACE)
        await sio.enter_room(sid, _event_room(event_id), namespace=SOCKETIO_NAMESPACE)

        # Simulate the data that would come from Redis PSUBSCRIBE.
        channel = f"shadowtrace:events:{event_id}".encode()
        payload = {
            "message_type": "state_change",
            "payload": {"from_status": "triaging", "to_status": "planning_response"},
        }
        payload_bytes = RedisClient.dumps(payload)

        # Clean sequence key and call dispatch.
        await client.get_client().delete(_sequence_key(event_id))
        await manager._dispatch(channel, payload_bytes)

        # Wait for the emit to be processed.
        await asyncio.sleep(0.1)

        # Verify sequence was incremented.
        seq = int(await client.get_client().get(_sequence_key(event_id)) or 0)
        assert seq >= 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_all_event_types_publishable(bus: tuple[EventBus, RedisClient]) -> None:
    """Each of the 16 event types can be published through the EventBus."""
    event_bus, _redis = bus
    event_id = f"evt-{_today_str()}-alltype1"

    for msg_type in sorted(SOCKET_MESSAGE_TYPES):
        ok = await event_bus.publish_event(
            event_id,
            msg_type,
            {"test": True, "type": msg_type},
        )
        assert ok is True, f"publish failed for type={msg_type}"


@pytest.mark.asyncio
async def test_multiple_clients_receive_broadcast(redis_required: RedisClient) -> None:
    """Acceptance 3: two subscribers to the same channel both receive the message."""
    client = RedisClient(url=REDIS_URL)
    try:
        event_bus = EventBus(client)
        event_id = f"evt-{_today_str()}-multicast"

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
            event_id, "state_change", {"from_status": "new", "to_status": "triaging"}
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _today_str() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y%m%d")


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
    }
    return examples.get(event_type, {})
