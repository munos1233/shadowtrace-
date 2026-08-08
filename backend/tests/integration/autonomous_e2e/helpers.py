"""Shared helpers for ISSUE-110 autonomous mock full-loop E2E."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.auth import ROLE_APPROVER, Principal
from app.core.config import Settings
from app.db import models as orm
from app.db.orm.approval import ApprovalRecordORM
from app.models.enums import (
    ActionLevel,
    EventType,
    InvestigationIntentStatus,
    Severity,
    SourceObjectKind,
)
from app.models.investigation_intent import PRIMARY_LINK_ROLE
from app.models.source import SourceReference
from app.services.auto_investigate_policy import AutoInvestigatePolicyService
from app.services.auto_response_policy import AutoResponsePolicyService
from app.services.context_service import EventContextStore
from app.services.degraded_flag_service import DegradedFlagService
from app.services.event_service import EventService, IngestableSource
from app.services.investigation_intent_service import InvestigationIntentService

T = TypeVar("T")

# Queue name that production workers do not consume — for broker-up / worker-down tests.
ISOLATED_E2E_QUEUE = "iss110-isolated-e2e"

# Shared integration DB may retain intents from prior runs. Tests that call
# ``claim_and_publish_batch`` backdate ``created_at`` on dedicated rows so claim
# ordering is deterministic without truncating shared state.

_HUMAN_GATED_LEVELS = frozenset(
    {
        ActionLevel.L2.value,
        ActionLevel.L3.value,
        ActionLevel.L4.value,
        ActionLevel.L5.value,
    }
)

DEV_AUTH_TOKENS_JSON = json.dumps(
    {
        "analyst-token": {"subject": "iss110-analyst", "roles": ["analyst"]},
        "approver-token": {"subject": "iss110-approver", "roles": ["approver"]},
        "system-token": {"subject": "system", "roles": []},
        "agent-token": {"subject": "agent:response-agent", "roles": ["analyst"]},
    }
)


def mock_autonomous_settings(**overrides: Any) -> Settings:
    """Mock-only autonomous pipeline defaults for ISSUE-110."""
    base: dict[str, Any] = {
        "AUTO_INVESTIGATE_ENABLED": True,
        "AUTO_RESPONSE_ENABLED": False,
        "SOURCE_MODE": "mock_xdr",
        "TOOL_MODE": "mock",
        "DISPOSITION_MODE": "mock_xdr",
        "LLM_MODE": "mock",
        "TASK_MODE": "celery",
        "SIMULATION_ENABLED": True,
    }
    base.update(overrides)
    return Settings(**base)


def build_autonomous_stack(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
    settings: Settings | None = None,
) -> tuple[EventService, InvestigationIntentService, EventContextStore]:
    cfg = settings or mock_autonomous_settings()
    store = EventContextStore(redis_client, session_factory)
    degraded = DegradedFlagService(store, session_factory)
    intent_service = InvestigationIntentService(
        session_factory,
        policy=AutoInvestigatePolicyService(cfg),
        auto_response_policy=AutoResponsePolicyService(cfg),
        degraded_flags=degraded,
        settings=cfg,
    )
    events = EventService(
        session_factory,
        store,
        degraded_flags=degraded,
        investigation_intent=intent_service,
    )
    return events, intent_service, store


async def poll_until(
    probe: Callable[[], Awaitable[T | None]],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 0.25,
    description: str = "condition",
) -> T:
    """Poll until *probe* returns non-None (no fixed sleep assertions)."""
    deadline = time.monotonic() + timeout_s
    last: T | None = None
    while time.monotonic() < deadline:
        last = await probe()
        if last is not None:
            return last
        await asyncio.sleep(interval_s)
    raise TimeoutError(f"timed out waiting for {description} after {timeout_s}s")


def incident_source(*, object_id: str) -> IngestableSource:
    """Mock XDR incident ingest payload shared by ISSUE-110 scenarios."""
    ref = SourceReference(
        source_kind=SourceObjectKind.INCIDENT,
        source_product="mock_xdr",
        source_tenant_id="tenant-demo",
        connector_id="conn-mock",
        source_object_id=object_id,
        source_updated_at=datetime.now(UTC),
    )
    return IngestableSource(
        reference=ref,
        title="Suspicious process incident",
        event_type=EventType.MALICIOUS_PROCESS,
        severity=Severity.HIGH,
        normalized={"risk_score": 76, "event_type": "malicious_process"},
    )


async def seed_primary_source_link(
    session: AsyncSession,
    *,
    event_id: str,
    connector_id: str = "conn-mock",
) -> str:
    """Primary source link required for disposition/writeback paths."""
    source_record_id = f"src-primary-{uuid4().hex[:8]}"
    if await session.get(orm.SourceConnector, connector_id) is None:
        session.add(
            orm.SourceConnector(
                connector_id=connector_id,
                source_product="mock_xdr",
                display_name="Mock XDR",
            )
        )
    session.add(
        orm.SourceObject(
            source_record_id=source_record_id,
            source_product="mock_xdr",
            source_tenant_id="tenant-demo",
            connector_id=connector_id,
            source_kind=SourceObjectKind.INCIDENT.value,
            source_object_id=f"INC-{uuid4().hex[:8]}",
            next_outbox_sequence=0,
        )
    )
    await session.flush()
    session.add(
        orm.SourceEventLink(
            source_record_id=source_record_id,
            event_id=event_id,
            role=PRIMARY_LINK_ROLE,
        )
    )
    return source_record_id


def auth_headers(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {role}-token"}


async def backdate_intent_for_claim(
    session_factory: async_sessionmaker[AsyncSession],
    intent_id: str,
    *,
    created_at: datetime | None = None,
) -> None:
    """Make *intent_id* oldest eligible row for ``claim_and_publish_batch`` on shared DB."""
    stale = created_at or datetime(2020, 1, 1, tzinfo=UTC)
    async with session_factory() as session:
        async with session.begin():
            row = await session.get(orm.InvestigationIntent, intent_id)
            if row is None:
                raise AssertionError(f"intent not found: {intent_id}")
            row.created_at = stale
            row.updated_at = stale


def select_human_gated_action(
    rows: list[Any],
    *,
    prefer_level: ActionLevel = ActionLevel.L2,
) -> Any:
    """Pick a deterministic L2+ response action (prefer *prefer_level*, lowest revision)."""
    human_gated = [
        row
        for row in rows
        if row.tool_name != "generate_report" and row.action_level in _HUMAN_GATED_LEVELS
    ]
    if not human_gated:
        raise AssertionError("expected L2+ waiting_approval response action")
    preferred = [row for row in human_gated if row.action_level == prefer_level.value]
    pool = preferred or human_gated
    return min(pool, key=lambda row: (int(row.plan_revision or 0), row.action_id))


def celery_worker_responding() -> bool:
    """True when at least one Celery worker answers inspect ping."""
    from app.core.celery_health import probe_celery_workers

    payload = probe_celery_workers(timeout=2.0)
    return payload.get("status") == "ok" and int(payload.get("workers") or 0) > 0


def require_celery_worker(*, fail_hard: bool = False) -> None:
    import pytest

    if celery_worker_responding():
        return
    message = (
        "ISSUE-283 worker fault-injection requires live Celery worker "
        "(make autonomous-mock-e2e-worker-pytest / make up WORKER=1)"
    )
    if fail_hard:
        pytest.fail(message)
    pytest.skip(message)


@dataclass(frozen=True)
class ObservabilitySnapshot:
    """Ledger snapshot for ISSUE-110 mandatory observability."""

    event_id: str
    event_status: str | None
    intent_statuses: list[str] = field(default_factory=list)
    intent_broker_task_ids: list[str | None] = field(default_factory=list)
    intent_claim_expires_at: list[str | None] = field(default_factory=list)
    agent_trace_count: int = 0
    agent_trace_ids: list[str] = field(default_factory=list)
    action_count: int = 0
    pending_action_count: int = 0
    approval_record_count: int = 0
    approval_operators: list[str] = field(default_factory=list)
    approval_plan_revisions: list[int] = field(default_factory=list)
    approval_cycles: list[int] = field(default_factory=list)
    execution_job_count: int = 0
    disposition_outbox_count: int = 0
    audit_log_count: int = 0


async def collect_observability(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> ObservabilitySnapshot:
    async with session_factory() as session:
        event_status = await session.scalar(
            select(orm.SecurityEvent.status).where(orm.SecurityEvent.event_id == event_id)
        )
        intents = (
            await session.scalars(
                select(orm.InvestigationIntent)
                .where(orm.InvestigationIntent.event_id == event_id)
                .order_by(orm.InvestigationIntent.created_at.asc())
            )
        ).all()
        agent_trace_rows = (
            await session.scalars(
                select(orm.AgentTrace.trace_id)
                .where(orm.AgentTrace.event_id == event_id)
                .order_by(orm.AgentTrace.started_at.asc())
            )
        ).all()
        agent_trace_count = len(agent_trace_rows)
        actions = (
            await session.scalars(select(orm.Action).where(orm.Action.event_id == event_id))
        ).all()
        pending_actions = [a for a in actions if a.status == "waiting_approval"]
        approval_rows = (
            await session.scalars(
                select(ApprovalRecordORM).where(ApprovalRecordORM.event_id == event_id)
            )
        ).all()
        outbox_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.DispositionOutbox)
                .where(orm.DispositionOutbox.event_id == event_id)
            )
            or 0
        )
        audit_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.EventAuditLog)
                .where(orm.EventAuditLog.event_id == event_id)
            )
            or 0
        )
        execution_job_count = int(
            await session.scalar(
                select(func.count())
                .select_from(orm.ActionExecutionJob)
                .where(orm.ActionExecutionJob.event_id == event_id)
            )
            or 0
        )
    return ObservabilitySnapshot(
        event_id=event_id,
        event_status=str(event_status) if event_status is not None else None,
        intent_statuses=[row.status for row in intents],
        intent_broker_task_ids=[row.broker_task_id for row in intents],
        intent_claim_expires_at=[
            row.claim_expires_at.isoformat() if row.claim_expires_at is not None else None
            for row in intents
        ],
        agent_trace_count=agent_trace_count,
        agent_trace_ids=[str(trace_id) for trace_id in agent_trace_rows],
        action_count=len(actions),
        pending_action_count=len(pending_actions),
        approval_record_count=len(approval_rows),
        approval_operators=[str(r.operator or "") for r in approval_rows if r.decided_at],
        approval_plan_revisions=[int(r.plan_revision) for r in approval_rows if r.decided_at],
        approval_cycles=[int(r.approval_cycle) for r in approval_rows if r.decided_at],
        execution_job_count=execution_job_count,
        disposition_outbox_count=outbox_count,
        audit_log_count=audit_count,
    )


def patch_production_session_factory(
    monkeypatch: Any,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Route Celery task session lookups to the integration test factory."""
    monkeypatch.setattr("app.api.v1.deps._get_session_factory", lambda: session_factory)
    monkeypatch.setattr("app.db.session.get_session_factory", lambda: session_factory)


def run_investigation_with_request(
    *,
    task_id: str,
    event_id: str,
    intent_id: str | None = None,
    include_response_execution: bool = False,
    redelivered: bool = False,
) -> dict[str, str]:
    """Invoke production ``run_investigation`` inline via request stack (no eager broker)."""
    from celery.app.task import Context

    from app.tasks import investigation_tasks as task_module

    kwargs: dict[str, Any] = {"include_response_execution": include_response_execution}
    if intent_id is not None:
        kwargs["intent_id"] = intent_id
    ctx = Context(
        id=task_id,
        delivery_info={"redelivered": redelivered},
        retries=0,
    )
    task_module.run_investigation.request_stack.push(ctx)
    try:
        return task_module.run_investigation.run(event_id, **kwargs)
    finally:
        task_module.run_investigation.request_stack.pop()


def unique_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}"


def utc_now() -> datetime:
    return datetime.now(UTC)


TERMINAL_INTENT_STATUSES = frozenset(
    {
        InvestigationIntentStatus.TERMINAL.value,
        InvestigationIntentStatus.SKIPPED.value,
        InvestigationIntentStatus.DEAD.value,
    }
)


@dataclass
class MockExecutionStack:
    """Minimal mock-mode ActionExecutionService wiring for ISSUE-110 scenario B/C."""

    service: Any
    recorder: Any
    store: EventContextStore
    _http_client: Any = field(repr=False, default=None)

    async def aclose(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None


async def build_mock_execution_stack(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> MockExecutionStack:
    """Build mock execution stack for approved-action execution tests."""
    import httpx
    from httpx import ASGITransport

    from app.adapters.mock_xdr import MockXDRDispositionAdapter
    from app.adapters.registry import DispositionAdapterRegistry
    from app.core.event_bus import EventBus
    from app.core.guardrails import OutboundDispositionGuard
    from app.data_generators.scenarios import build_scenario
    from app.mock_xdr.api import create_app
    from app.mock_xdr.state import MockXDRState
    from app.services.action_execution_service import ActionExecutionService
    from app.services.disposition_sync_service import DispositionSyncService
    from app.services.event_audit_log_service import EventAuditLogService
    from app.services.state_machine_service import StateMachineService
    from app.tools.executor import ToolExecutor
    from app.tools.registry import ToolRegistry
    from tests.integration.integration_fixtures import RecordingToolExecutor

    store = EventContextStore(redis_client, session_factory)
    state = MockXDRState()
    state.load_scenario(build_scenario("insider_data_exfiltration", seed=42))
    mock_app = create_app(state=state)
    client = httpx.AsyncClient(
        transport=ASGITransport(app=mock_app),
        base_url="http://mock-xdr",
        timeout=30.0,
    )
    registry = DispositionAdapterRegistry()
    registry.register(
        "mock_xdr",
        MockXDRDispositionAdapter(
            client=client,
            read_token="mock-read-token",
            write_token="mock-write-token",
        ),
    )
    disposition_sync = DispositionSyncService(
        session_factory,
        context_store=store,
        adapter_registry=registry,
        outbound_guard=OutboundDispositionGuard(),
    )
    tool_registry = ToolRegistry()
    await tool_registry.auto_discover_for_mode(tool_mode="mock")
    inner = ToolExecutor(registry=tool_registry)
    recorder = RecordingToolExecutor(inner)
    state_machine = StateMachineService(
        session_factory,
        store,
        event_bus=EventBus(redis_client),
        audit_log=EventAuditLogService(session_factory),
        degraded_flags=DegradedFlagService(store, session_factory),
    )
    service = ActionExecutionService(
        session_factory,
        disposition_sync=disposition_sync,
        tool_executor=recorder,
        state_machine=state_machine,
        context_store=store,
    )
    return MockExecutionStack(service=service, recorder=recorder, store=store, _http_client=client)


async def count_execution_jobs(
    session_factory: async_sessionmaker[AsyncSession],
    event_id: str,
) -> int:
    async with session_factory() as session:
        return int(
            await session.scalar(
                select(func.count())
                .select_from(orm.ActionExecutionJob)
                .where(orm.ActionExecutionJob.event_id == event_id)
            )
            or 0
        )


def principal_lacks_approver_role(principal: Principal) -> bool:
    """True when *principal* cannot call production approve/reject APIs."""
    return not principal.has_any_role([ROLE_APPROVER])


async def build_approval_engine(
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: Any,
) -> Any:
    """Minimal ApprovalEngine wiring for ISSUE-110 scenario B.

    Intentionally omits ``resume_investigation`` — those tests manually drive
    ``ActionExecutionService.execute_action`` after approve. Production resume
    hook coverage lives in ``tests/integration/test_production_graph_resume.py``
    (ISSUE-194). Adversarial full loop uses ``get_approval_engine()`` instead
    (ISSUE-203).
    """
    from unittest.mock import AsyncMock

    from app.agents.response_agent import build_mock_capability_manifest
    from app.services.approval_engine import ApprovalEngine
    from app.services.state_machine_service import StateMachineService

    store = EventContextStore(redis_client, session_factory)
    state_machine = StateMachineService(session_factory, store)
    return ApprovalEngine(
        session_factory,
        event_bus=AsyncMock(),
        state_machine=state_machine,
        context_store=store,
        capability_manifest=build_mock_capability_manifest(),
    )
