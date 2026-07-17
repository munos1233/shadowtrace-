"""ISSUE-025: end-to-end tool-system integration chains.

Runs in-memory against Registry + Executor + Mock tools (no Docker required).
Marked ``tool_system``; intentionally not marked ``integration`` so
``make test-tools`` stays fast and deterministic.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, cast

import pytest

from app.core.errors import ToolExecutionError
from app.models.enums import ExecutionJobStatus, ExecutionOwner, ToolCategory
from app.models.execution import ActionExecutionJob
from app.models.tool_meta import (
    RoutingKind,
    ToolMeta,
    ToolResult,
    ToolResultStatus,
)
from app.providers.tools.mock_provider import MockToolProvider, MockToolProviderConfig
from app.services.evidence_projection import (
    EvidenceProjection,
    bind_evidence_projection,
)
from app.tools.circuit_breaker import CircuitBreakerRegistry
from app.tools.executor import InMemoryExecutionJobStore, ToolExecutor
from app.tools.registry import ToolRegistry
from app.tools.retry import RetryPolicy
from app.tools.verify._common import MockVerificationRuntime, bind_mock_verification_runtime
from tests.test_models.test_tool_schemas import REQUIRED_BASELINE_NAMES
from tests.test_tools.tool_system_fixtures import (
    CONCURRENT_QUERY_CALLS,
    WINDOW,
    RecordingAuditService,
    new_sfx,
)

pytestmark = pytest.mark.tool_system

QUERY_CHAIN: tuple[tuple[str, dict[str, Any], str], ...] = (
    (
        "query_account_login",
        {"account": "zhangsan", "time_range": WINDOW},
        "id-conflict-42-0002",
    ),
    (
        "query_edr_process",
        {"host_id": "PC-FIN-023", "time_range": WINDOW},
        "ep-conflict-42-0003",
    ),
    (
        "query_network_flow",
        {"src_ip": "10.20.30.23", "time_range": WINDOW},
        "net-key-42-0009",
    ),
    (
        "query_threat_intel",
        {"indicator": "203.0.113.88"},
        "ti-key-42-0011",
    ),
)


class _EventScopeService:
    def __init__(self, scope: Any) -> None:
        self.scope = scope

    async def get_evidence_query_scope(self, event_id: str) -> Any:
        return self.scope


def _query_meta(name: str, *, timeout_s: float = 5.0) -> ToolMeta:
    return ToolMeta(
        tool_name=name,
        tool_category=ToolCategory.QUERY,
        routing_kind=RoutingKind.TOOL_PROVIDER_ONLY,
        default_timeout_s=timeout_s,
        input_schema={
            "type": "object",
            "properties": {
                "delay_s": {"type": "number"},
                "fail_times": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "call_id": {"type": "string"},
                "tool_name": {"type": "string"},
                "provider_name": {"type": "string"},
                "status": {"type": "string"},
                "data": {"type": "object"},
            },
            "required": ["call_id", "tool_name", "provider_name", "status", "data"],
            "additionalProperties": True,
        },
    )


async def _seed_side_effect_job(
    job_store: InMemoryExecutionJobStore,
    *,
    event_id: str,
    action_id: str,
    idempotency_key: str,
) -> str:
    job_id = f"job-{new_sfx()}"
    await job_store.seed_job(
        ActionExecutionJob(
            job_id=job_id,
            event_id=event_id,
            action_id=action_id,
            provider_name="mock_tool_provider",
            idempotency_key=idempotency_key,
            status=ExecutionJobStatus.QUEUED,
        )
    )
    return job_id


@pytest.mark.asyncio
async def test_chain_query_tools_sequential_data_and_audit(
    tool_registry: ToolRegistry,
    tool_executor: ToolExecutor,
    evidence_projection: EvidenceProjection,
    event_scope_service: Any,
    audit: RecordingAuditService,
) -> None:
    """链路一：四路查询顺序调用，断言数据与审计。"""
    event_id = f"evt-query-chain-{new_sfx()}"

    for tool_name, params, expected_record in QUERY_CHAIN:
        with bind_evidence_projection(evidence_projection):
            raw = await tool_registry.execute_event_query(
                event_id,
                tool_name,
                params,
                event_service=cast(Any, event_scope_service),
            )
        result = ToolResult.model_validate(raw)
        assert result.status is ToolResultStatus.SUCCESS
        assert any(
            row.get("record_id") == expected_record for row in result.data.get("records", [])
        )

        # Also exercise Executor path + audit for the same tool.
        with bind_evidence_projection(evidence_projection):
            from app.services.evidence_projection import bind_evidence_query_scope

            with bind_evidence_query_scope(event_scope_service.scope):
                exec_result = await tool_executor.call(tool_name, params, event_id)
        assert exec_result.status is ToolResultStatus.SUCCESS

    rows = audit.rows_for_event(event_id)
    audited_names = {row["tool_name"] for row in rows}
    assert {name for name, _, _ in QUERY_CHAIN}.issubset(audited_names)
    assert all(row.get("status") == "success" for row in rows)
    assert audit.starts == audit.finishes == len(QUERY_CHAIN)


@pytest.mark.asyncio
async def test_chain_block_verify_unblock_verify(
    tool_executor: ToolExecutor,
    mock_provider: MockToolProvider,
    job_store: InMemoryExecutionJobStore,
    verification_runtime: MockVerificationRuntime,
    audit: RecordingAuditService,
) -> None:
    """链路二：block → verify(true) → unblock → verify(false)。"""
    event_id = f"evt-ip-chain-{new_sfx()}"
    target = "203.0.113.250"
    params = {"target_type": "ip", "target": target, "parameters": {}}

    block_action = f"act-block-{new_sfx()}"
    block_idem = f"idem-block-{new_sfx()}"
    block_job_id = await _seed_side_effect_job(
        job_store,
        event_id=event_id,
        action_id=block_action,
        idempotency_key=block_idem,
    )

    with bind_mock_verification_runtime(verification_runtime):
        blocked = await tool_executor.call(
            "block_ip",
            params,
            event_id,
            action_id=block_action,
            execution_job_id=block_job_id,
            idempotency_key=block_idem,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
            retry_policy=RetryPolicy(max_retries=0),
        )
        assert blocked.job_id == block_job_id
        completed = await mock_provider.run_job(blocked.job_id)
        assert completed.status.value == "success"

        verified = await tool_executor.call(
            "check_ip_block_status",
            {
                "target_type": "ip",
                "target": target,
                "parameters": {"job_id": blocked.job_id},
            },
            event_id,
        )
        assert verified.status is ToolResultStatus.SUCCESS
        assert verified.data["is_verified"] is True

        unblock_action = f"act-unblock-{new_sfx()}"
        unblock_idem = f"idem-unblock-{new_sfx()}"
        unblock_job_id = await _seed_side_effect_job(
            job_store,
            event_id=event_id,
            action_id=unblock_action,
            idempotency_key=unblock_idem,
        )
        unblocked = await tool_executor.call(
            "unblock_ip",
            params,
            event_id,
            action_id=unblock_action,
            execution_job_id=unblock_job_id,
            idempotency_key=unblock_idem,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
            retry_policy=RetryPolicy(max_retries=0),
        )
        completed_unblock = await mock_provider.run_job(unblocked.job_id)
        assert completed_unblock.status.value == "success"

        after = await tool_executor.call(
            "check_ip_block_status",
            {"target_type": "ip", "target": target, "parameters": {}},
            event_id,
        )
        assert after.status is ToolResultStatus.SUCCESS
        assert after.data["is_verified"] is False

    audited = {row["tool_name"] for row in audit.rows_for_event(event_id)}
    assert {
        "block_ip",
        "check_ip_block_status",
        "unblock_ip",
    }.issubset(audited)


@pytest.mark.asyncio
async def test_chain_seven_queries_concurrent_faster_than_serial(
    tool_registry: ToolRegistry,
    evidence_projection: EvidenceProjection,
    event_scope_service: Any,
) -> None:
    """链路三：7 路查询 asyncio.gather，全部成功且快于串行。

    Concurrency is proven with an ``asyncio.Barrier`` (all workers must arrive
    before any proceeds). Wall-clock comparison uses a large artificial delay so
    the assert is stable under CI load.
    """
    event_id = f"evt-gather-{new_sfx()}"
    artificial_delay_s = 0.08
    n = len(CONCURRENT_QUERY_CALLS)

    async def run_one(
        tool_name: str,
        params: dict[str, Any],
        *,
        barrier: asyncio.Barrier | None,
    ) -> ToolResult:
        if barrier is not None:
            await barrier.wait()
        await asyncio.sleep(artificial_delay_s)
        with bind_evidence_projection(evidence_projection):
            raw = await tool_registry.execute_event_query(
                event_id,
                tool_name,
                params,
                event_service=cast(Any, event_scope_service),
            )
        return ToolResult.model_validate(raw)

    serial_start = time.perf_counter()
    serial_results = [
        await run_one(tool_name, params, barrier=None)
        for tool_name, params in CONCURRENT_QUERY_CALLS
    ]
    serial_elapsed = time.perf_counter() - serial_start

    barrier = asyncio.Barrier(n)
    concurrent_start = time.perf_counter()
    concurrent_results = await asyncio.wait_for(
        asyncio.gather(
            *(
                run_one(tool_name, params, barrier=barrier)
                for tool_name, params in CONCURRENT_QUERY_CALLS
            )
        ),
        timeout=10.0,
    )
    concurrent_elapsed = time.perf_counter() - concurrent_start

    assert all(r.status is ToolResultStatus.SUCCESS for r in serial_results)
    assert all(r.status is ToolResultStatus.SUCCESS for r in concurrent_results)
    assert len(concurrent_results) == 7
    # ISSUE-025: concurrent wall time must beat serial. Barrier proves overlap;
    # avoid a hard absolute ceiling — CI runners add query overhead that makes
    # ``delay * n * 0.5`` flake (observed ~0.74s vs 0.28s).
    assert concurrent_elapsed < serial_elapsed
    assert concurrent_elapsed < artificial_delay_s * n


@pytest.mark.asyncio
async def test_chain_timeout_retry_circuit_open_and_recover() -> None:
    """链路四：超时/失败注入 → 重试 → 熔断打开 → 恢复。"""
    attempts: dict[str, int] = {}

    async def flaky_execute(params: dict[str, Any]) -> dict[str, Any]:
        tool = "fake_timeout_flaky"
        attempts[tool] = attempts.get(tool, 0) + 1
        fail_times = int(params.get("fail_times", 1))
        if attempts[tool] <= fail_times:
            raise ToolExecutionError("injected transient timeout/fault")
        return ToolResult(
            call_id=f"call-{uuid.uuid4().hex[:8]}",
            tool_name=tool,
            provider_name="fake",
            status=ToolResultStatus.SUCCESS,
            data={"attempt": attempts[tool]},
        ).model_dump(mode="json")

    async def slow_execute(params: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(float(params.get("delay_s", 0.2)))
        return ToolResult(
            call_id=f"call-{uuid.uuid4().hex[:8]}",
            tool_name="fake_slow",
            provider_name="fake",
            status=ToolResultStatus.SUCCESS,
            data={"done": True},
        ).model_dump(mode="json")

    registry = ToolRegistry()
    registry.register(_query_meta("fake_timeout_flaky"), flaky_execute)
    registry.register(_query_meta("fake_slow", timeout_s=0.05), slow_execute)

    sleeps: list[float] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    clock = {"now": 0.0}
    breaker_registry = CircuitBreakerRegistry(
        failure_threshold=5,
        recovery_timeout_s=60.0,
        clock=lambda: clock["now"],
    )
    audit = RecordingAuditService()
    executor = ToolExecutor(
        registry=registry,
        audit_service=audit,
        breaker_registry=breaker_registry,
        sleep=record_sleep,
    )
    event_id = f"evt-fault-{new_sfx()}"

    # Timeout path
    timed_out = await executor.call(
        "fake_slow",
        {"delay_s": 0.2},
        event_id,
        timeout=0.05,
        retry_policy=RetryPolicy(max_retries=0),
    )
    assert timed_out.status is ToolResultStatus.TIMEOUT

    # Retry path recovers after transient failures
    attempts.clear()
    recovered_via_retry = await executor.call(
        "fake_timeout_flaky",
        {"fail_times": 2},
        event_id,
        retry_policy=RetryPolicy(max_retries=3),
    )
    assert recovered_via_retry.status is ToolResultStatus.SUCCESS
    assert sleeps == [2.0, 4.0]

    # Open the circuit with consecutive failures
    attempts.clear()
    for _ in range(5):
        failed = await executor.call(
            "fake_timeout_flaky",
            {"fail_times": 999},
            event_id,
            retry_policy=RetryPolicy(max_retries=0),
        )
        assert failed.status is ToolResultStatus.FAILED

    blocked = await executor.call(
        "fake_timeout_flaky",
        {"fail_times": 0},
        event_id,
        retry_policy=RetryPolicy(max_retries=0),
    )
    assert blocked.status is ToolResultStatus.CIRCUIT_OPEN

    # Recover after timeout window
    clock["now"] = 60.0
    attempts.clear()
    recovered = await executor.call(
        "fake_timeout_flaky",
        {"fail_times": 0},
        event_id,
        retry_policy=RetryPolicy(max_retries=0),
    )
    assert recovered.status is ToolResultStatus.SUCCESS


@pytest.mark.asyncio
async def test_required_tools_subset_unique_and_disabled_absent_from_available(
    tool_registry: ToolRegistry,
    mock_provider: MockToolProvider,
    mock_state: Any,
) -> None:
    """必需工具 ⊆ 注册集、名称唯一；不可用能力不出现在可执行清单。"""
    mock_provider.register_bindings(tool_registry)

    registered_names = {
        entry.tool_meta.tool_name for entry in tool_registry.list_registered_tools()
    }
    assert REQUIRED_BASELINE_NAMES.issubset(registered_names)
    assert len(registered_names) == len(set(registered_names))

    # Healthy DIRECT_TOOL list includes block_ip
    available_before = {
        meta.tool_name
        for meta in tool_registry.list_available_tools(
            ToolCategory.RESPONSE,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
    }
    assert "block_ip" in available_before

    # Re-bind with block_ip disabled → disappears from executable list
    disabled_provider = MockToolProvider(
        mock_state,
        config=MockToolProviderConfig(
            observation_delay_ms=0,
            disabled_tools={"block_ip"},
        ),
    )
    fresh = ToolRegistry()
    fresh.auto_discover()
    disabled_provider.register_bindings(fresh)
    available_after = {
        meta.tool_name
        for meta in fresh.list_available_tools(
            ToolCategory.RESPONSE,
            execution_owner=ExecutionOwner.DIRECT_TOOL,
        )
    }
    assert "block_ip" not in available_after
    # Still do not freeze total tool count.
    assert len(registered_names) >= len(REQUIRED_BASELINE_NAMES)
