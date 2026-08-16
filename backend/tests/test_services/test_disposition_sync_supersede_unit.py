"""ISSUE-219 unit tests: enqueue_command supersede lineage (no DB required).

The supersede logic lives inside ``DispositionSyncService.enqueue_command``:
before inserting a new active EVENT_STATUS_UPDATE head it must mark the
previous active head for the same ``(event_id, closure_cycle, logical_slot)``
as superseded, in the same transaction, and propagate the lineage onto the
wire payload (``supersedes_disposition_id``).  These tests drive the method
with a fake session so the behavior is verifiable without PostgreSQL.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.db import models as orm
from app.models.disposition import (
    DispositionCommand,
    SetEventDispositionParams,
    SourceDisposition,
    SourceObjectLocator,
    SubmitEntityActionParams,
)
from app.models.enums import (
    DispositionIntentKind,
    ExecutionOwner,
    OutboxDeliveryStatus,
    SourceObjectKind,
)
from app.services.disposition_sync_service import DispositionSyncService


def _command(
    *,
    intent_kind: DispositionIntentKind,
    disposition_id: str = "disp-new",
    closure_cycle: int = 1,
) -> DispositionCommand:
    if intent_kind is DispositionIntentKind.EVENT_STATUS_UPDATE:
        params: Any = SetEventDispositionParams(target_disposition=SourceDisposition.CONTAINED)
        operation_code = "set_event_disposition"
    else:
        params = SubmitEntityActionParams(
            entity_action_code="block",
            canonical_target="obj-1",
        )
        operation_code = "submit_entity_action"
    return DispositionCommand(
        disposition_id=disposition_id,
        action_id="act-1",
        closure_cycle=closure_cycle,
        intent_kind=intent_kind,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-1",
            connector_id="conn-1",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_type="incident",
            source_object_id="obj-1",
        ),
        operation_code=operation_code,
        operation_params=params,
        target_results=[],
        operator_id="op-1",
        idempotency_key="idem-1",
        source_concurrency_token=None,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        parent_disposition_id=None,
        supersedes_disposition_id=None,
    )


def _prior_head(disposition_id: str = "disp-prior") -> orm.DispositionOutbox:
    return orm.DispositionOutbox(
        outbox_id="ob-prior",
        writeback_id="wbk-prior",
        disposition_id=disposition_id,
        action_id="act-0",
        event_id="evt-1",
        closure_cycle=1,
        source_record_id="src-1",
        source_locator_hash="hash",
        source_sequence=1,
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE.value,
        logical_slot="terminal",
        supersedes_disposition_id=None,
        superseded_by_disposition_id=None,
        idempotency_key="idem-prior",
        command_payload={"op": "set_event_disposition"},
        command_payload_sha256="sha",
        delivery_status=OutboxDeliveryStatus.READY.value,
    )


class _FakeResult:
    def one(self) -> tuple[int]:
        return (1,)


class _FakeScalarsResult:
    def __init__(self, rows: list[str]) -> None:
        self._rows = rows

    def all(self) -> list[str]:
        return self._rows


class _FakeSession:
    """Records enqueue_command interactions; only prior-head query returns a row."""

    def __init__(
        self,
        source_row: Any,
        prior_head: orm.DispositionOutbox | None,
        *,
        approved_action_ids: list[str] | None = None,
    ) -> None:
        self.source_row = source_row
        self.prior_head = prior_head
        self.approved_action_ids = (
            approved_action_ids if approved_action_ids is not None else ["act-1"]
        )
        self.added: list[Any] = []
        self.flush_count = 0
        self.scalar_calls = 0

    async def get(
        self,
        model: Any,
        pk: Any,
        *,
        with_for_update: bool = False,
    ) -> Any:
        return self.source_row

    async def scalar(self, stmt: Any) -> Any:
        # First scalar is the prior active-head lookup; journal lookups (later)
        # return nothing.
        self.scalar_calls += 1
        if self.scalar_calls == 1:
            return self.prior_head
        return None

    async def scalars(self, stmt: Any) -> _FakeScalarsResult:
        return _FakeScalarsResult(self.approved_action_ids)

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        return _FakeResult()

    async def flush(self) -> None:
        self.flush_count += 1

    def add(self, obj: Any) -> None:
        self.added.append(obj)


def _service() -> DispositionSyncService:
    return DispositionSyncService(
        session_factory=AsyncMock(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=AsyncMock(),  # type: ignore[arg-type]
        outbound_guard=AsyncMock(),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_enqueue_supersedes_prior_event_status_update_head() -> None:
    """ISSUE-219: a new EVENT_STATUS_UPDATE head marks the prior active head
    of the same (event_id, closure_cycle, logical_slot) as superseded."""
    source_row = SimpleNamespace(next_outbox_sequence=7)
    prior = _prior_head()
    session = _FakeSession(source_row, prior)
    service = _service()

    record = await service.enqueue_command(
        session,
        command=_command(intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE),
        event_id="evt-1",
        source_record_id="src-1",
        logical_slot="terminal",
    )

    # Old head lineage: superseded by the new head's disposition_id.
    assert prior.superseded_by_disposition_id == record.disposition_id
    assert prior.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
    assert prior.last_error_code == "superseded_by_new_head"
    # New head lineage + wire payload carry the supersede contract.
    assert record.supersedes_disposition_id == "disp-prior"
    added_outbox = session.added[0]
    assert added_outbox.supersedes_disposition_id == "disp-prior"
    assert added_outbox.command_payload["supersedes_disposition_id"] == "disp-prior"
    # Prior-head lookup ran exactly once (the later context-journal lookup is
    # the only other scalar call in enqueue_command).
    assert session.scalar_calls == 2


@pytest.mark.asyncio
async def test_enqueue_without_prior_head_keeps_command_unchanged() -> None:
    """ISSUE-219: with no prior active head nothing is superseded."""
    source_row = SimpleNamespace(next_outbox_sequence=1)
    session = _FakeSession(source_row, prior_head=None)
    service = _service()

    record = await service.enqueue_command(
        session,
        command=_command(intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE),
        event_id="evt-1",
        source_record_id="src-1",
        logical_slot="terminal",
    )

    assert record.supersedes_disposition_id is None
    added_outbox = session.added[0]
    assert added_outbox.supersedes_disposition_id is None
    assert added_outbox.command_payload.get("supersedes_disposition_id") is None


@pytest.mark.asyncio
async def test_enqueue_entity_action_submit_never_supersedes() -> None:
    """ISSUE-219: supersede is EVENT_STATUS_UPDATE-only; other intents are
    untouched and never query/supersede an active head."""
    source_row = SimpleNamespace(next_outbox_sequence=1)
    # A prior EVENT_STATUS_UPDATE head exists, but an ENTITY_ACTION_SUBMIT
    # command must not supersede it.
    session = _FakeSession(source_row, prior_head=_prior_head())
    service = _service()

    record = await service.enqueue_command(
        session,
        command=_command(intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT),
        event_id="evt-1",
        source_record_id="src-1",
        logical_slot="terminal",
    )

    assert record.supersedes_disposition_id is None
    added_outbox = session.added[0]
    assert added_outbox.supersedes_disposition_id is None
    # The prior head must not be marked superseded by a non-terminal intent.
    assert session.prior_head.superseded_by_disposition_id is None


@pytest.mark.asyncio
async def test_enqueue_idempotent_replay_returns_existing_head() -> None:
    """ISSUE-273: same idempotency_key + payload returns existing head without superseding."""
    source_row = SimpleNamespace(next_outbox_sequence=7)
    command = _command(
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        disposition_id="disp-prior",
    )
    command = command.model_copy(update={"idempotency_key": "idem-replay"})
    payload = command.model_dump(mode="json")
    import hashlib
    import json

    payload_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8",
        ),
    ).hexdigest()
    prior = _prior_head()
    prior.idempotency_key = "idem-replay"
    prior.command_payload = payload
    prior.command_payload_sha256 = payload_hash
    session = _FakeSession(source_row, prior)
    service = _service()

    record = await service.enqueue_command(
        session,
        command=command,
        event_id="evt-1",
        source_record_id="src-1",
        logical_slot="terminal",
    )

    assert record.outbox_id == prior.outbox_id
    assert prior.superseded_by_disposition_id is None
    assert len(session.added) == 0


@pytest.mark.asyncio
async def test_finalize_superseded_head_records_dead_letter_metric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-273: finalize must emit writeback dead-letter metric for undelivered heads."""
    from datetime import UTC, datetime

    from app.services import disposition_sync_service as mod

    recorded: list[str] = []
    monkeypatch.setattr(
        mod,
        "record_writeback_dead_letter",
        lambda *, adapter, error_code=None: recorded.append(adapter),
    )
    prior = _prior_head()
    prior.delivery_status = OutboxDeliveryStatus.WAITING_RETRY.value
    prior.locked_by = "worker-x"
    service = _service()
    service._resolve_adapter = lambda _outbox: SimpleNamespace(name="mock_xdr")  # type: ignore[method-assign]

    service._finalize_superseded_head(
        prior,
        superseded_by_disposition_id="disp-new",
        now=datetime.now(UTC),
    )

    assert prior.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
    assert prior.last_error_code == "superseded_by_new_head"
    assert prior.locked_by is None
    assert recorded == ["mock_xdr"]


@pytest.mark.asyncio
async def test_block_superseded_outbox_terminates_ready_and_leased(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSUE-273: pre-egress block must DEAD_LETTER READY and LEASED superseded rows."""
    from datetime import UTC, datetime

    from app.services import disposition_sync_service as mod

    recorded: list[str] = []
    monkeypatch.setattr(
        mod,
        "record_writeback_dead_letter",
        lambda *, adapter, error_code=None: recorded.append(adapter),
    )
    service = _service()
    service._resolve_adapter = lambda _outbox: SimpleNamespace(name="mock_xdr")  # type: ignore[method-assign]
    now = datetime.now(UTC)

    ready = _prior_head("disp-ready")
    ready.outbox_id = "ob-ready"
    ready.superseded_by_disposition_id = "disp-new"
    ready.delivery_status = OutboxDeliveryStatus.READY.value
    assert service._block_superseded_outbox(ready, now=now) is OutboxDeliveryStatus.DEAD_LETTER
    assert ready.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value

    leased = _prior_head("disp-leased")
    leased.outbox_id = "ob-leased"
    leased.superseded_by_disposition_id = "disp-new"
    leased.delivery_status = OutboxDeliveryStatus.LEASED.value
    leased.locked_by = "worker-1"
    assert service._block_superseded_outbox(leased, now=now) is OutboxDeliveryStatus.DEAD_LETTER
    assert leased.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
    assert leased.locked_by is None
    assert recorded == ["mock_xdr", "mock_xdr"]


@pytest.mark.asyncio
async def test_assert_active_head_for_delivery_rejects_stale_head() -> None:
    """ISSUE-273: active-head CAS fails when another disposition is the live head."""
    outbox = _prior_head("disp-stale")
    command = _command(
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE,
        disposition_id="disp-stale",
    )
    session = SimpleNamespace(scalar=AsyncMock(return_value="disp-new"))
    service = _service()

    assert await service._assert_active_head_for_delivery(session, outbox, command) is False
    session.scalar.assert_awaited_once()
    stmt = session.scalar.await_args.args[0]
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
    assert "ORDER BY" in compiled.upper()


@pytest.mark.asyncio
async def test_claim_batch_skips_superseded_rows_even_if_returned() -> None:
    """ISSUE-273: claim loop must skip superseded rows (defense in depth vs SQL filter)."""
    from datetime import UTC, datetime

    from app.services.disposition_sync_service import OutboxWorker

    superseded = _prior_head("disp-old")
    superseded.outbox_id = "ob-superseded"
    superseded.superseded_by_disposition_id = "disp-new"
    superseded.delivery_status = OutboxDeliveryStatus.WAITING_RETRY.value
    superseded.next_retry_at = datetime.now(UTC)

    active = _prior_head("disp-active")
    active.outbox_id = "ob-active"
    active.superseded_by_disposition_id = None
    active.delivery_status = OutboxDeliveryStatus.READY.value
    active.next_retry_at = None
    active.created_at = datetime.now(UTC)

    class _Scalars:
        def all(self) -> list[orm.DispositionOutbox]:
            return [superseded, active]

    class _ClaimSession:
        def begin(self) -> _ClaimSession:
            return self

        async def __aenter__(self) -> _ClaimSession:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def scalars(self, stmt: Any) -> _Scalars:
            return _Scalars()

        async def get(self, *args: Any, **kwargs: Any) -> None:
            return None

    class _Factory:
        def __call__(self) -> _ClaimSession:
            return _ClaimSession()

    service = _service()
    service._session_factory = _Factory()  # type: ignore[assignment]
    worker = OutboxWorker(service)

    claimed = await worker._claim_batch(limit=10)
    assert claimed == ["ob-active"]
    assert active.delivery_status == OutboxDeliveryStatus.LEASED.value
    assert superseded.delivery_status == OutboxDeliveryStatus.WAITING_RETRY.value


@pytest.mark.asyncio
async def test_deliver_after_supersede_never_calls_adapter_submit() -> None:
    """ISSUE-273: claim→supersede→deliver race must yield zero provider submits."""

    outbox = _prior_head("disp-old")
    outbox.outbox_id = "ob-raced"
    outbox.delivery_status = OutboxDeliveryStatus.LEASED.value
    outbox.locked_by = "worker-test"
    outbox.superseded_by_disposition_id = None
    # Simulate concurrent supersede after claim: lineage written, status still LEASED.
    outbox.superseded_by_disposition_id = "disp-new"

    submit_calls = 0

    class _Adapter:
        name = "mock_xdr"

        async def submit(self, *args: Any, **kwargs: Any) -> Any:
            nonlocal submit_calls
            submit_calls += 1
            raise AssertionError("adapter.submit must not run for superseded outbox")

    class _DeliverSession:
        def begin(self) -> _DeliverSession:
            return self

        async def __aenter__(self) -> _DeliverSession:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def scalar(self, stmt: Any) -> Any:
            # First scalar resolves event_id for SecurityEvent lock; second loads outbox.
            if not hasattr(self, "_scalar_calls"):
                self._scalar_calls = 0
            self._scalar_calls += 1
            if self._scalar_calls == 1:
                return outbox.event_id
            return outbox

        async def get(self, model: Any, pk: Any, **kwargs: Any) -> Any:
            # Production locks SecurityEvent before the superseded early return (ISSUE-284).
            if model is orm.SecurityEvent:
                return SimpleNamespace(event_id=pk)
            raise AssertionError("action lock must not run after superseded early return")

    class _Factory:
        def __call__(self) -> _DeliverSession:
            return _DeliverSession()

    service = DispositionSyncService(
        session_factory=_Factory(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=SimpleNamespace(get=lambda _name: _Adapter()),  # type: ignore[arg-type]
        outbound_guard=AsyncMock(),  # type: ignore[arg-type]
    )
    service._worker_id = "worker-test"
    service._resolve_adapter = lambda _o: _Adapter()  # type: ignore[method-assign]

    await service._deliver_outbox("ob-raced")

    assert submit_calls == 0
    assert outbox.delivery_status == OutboxDeliveryStatus.DEAD_LETTER.value
    assert outbox.last_error_code == "superseded_by_new_head"
    assert outbox.locked_by is None


@pytest.mark.asyncio
async def test_enqueue_command_resolves_approved_action_ids_for_guard() -> None:
    """ISSUE-224: enqueue_command must pass a real approved set to the guard."""
    from app.core.guardrails import OutboundDispositionGuard

    captured: dict[str, object] = {}
    guard = OutboundDispositionGuard()
    original_validate = guard.validate

    async def _capture_validate(command: Any, context: dict[str, object]) -> Any:
        captured.update(context)
        return await original_validate(command, context)

    guard.validate = _capture_validate  # type: ignore[method-assign]

    source_row = SimpleNamespace(next_outbox_sequence=1)
    session = _FakeSession(
        source_row,
        prior_head=None,
        approved_action_ids=["act-approved-1", "act-1"],
    )
    service = DispositionSyncService(
        session_factory=AsyncMock(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=AsyncMock(),  # type: ignore[arg-type]
        outbound_guard=guard,
    )

    await service.enqueue_command(
        session,
        command=_command(intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT),
        event_id="evt-1",
        source_record_id="src-1",
    )

    assert captured["approved_action_ids"] == ["act-1", "act-approved-1"]


@pytest.mark.asyncio
async def test_enqueue_command_rejects_unapproved_action_id() -> None:
    """ISSUE-224: guard blocks when command.action_id is not in resolved set."""
    from app.core.errors import GuardrailViolationError
    from app.core.guardrails import OutboundDispositionGuard

    source_row = SimpleNamespace(next_outbox_sequence=1)
    session = _FakeSession(
        source_row,
        prior_head=None,
        approved_action_ids=["act-other"],
    )
    service = DispositionSyncService(
        session_factory=AsyncMock(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=AsyncMock(),  # type: ignore[arg-type]
        outbound_guard=OutboundDispositionGuard(),
    )

    with pytest.raises(GuardrailViolationError) as exc_info:
        await service.enqueue_command(
            session,
            command=_command(intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT),
            event_id="evt-1",
            source_record_id="src-1",
        )

    violations = exc_info.value.details["violations"]
    assert any(item["rule_name"] == "disposition_approved_action" for item in violations)
