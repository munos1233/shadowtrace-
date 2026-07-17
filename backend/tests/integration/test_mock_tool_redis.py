"""Real Redis contract gate for Mock response, verification, and rollback Lua."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.redis_client import RedisClient
from app.models.enums import SourceObjectKind
from app.models.execution import ActionExecutionJob
from app.models.source import SourceReference
from app.models.tool_meta import ToolResult
from app.providers.tools.mock_provider import (
    MockToolProvider,
    MockToolProviderConfig,
    ToolExecutionContext,
)
from app.tools.mock_state import MockEnvironmentState, MockObservationRecord
from app.tools.verify._common import MockVerificationRuntime

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("clean_state"),
]

TARGET = "203.0.113.242"
DELAYED_TARGET = "203.0.113.244"


def _context(suffix: str) -> ToolExecutionContext:
    return ToolExecutionContext(
        event_id=f"evt-real-redis-{suffix}",
        action_id=f"act-real-redis-{suffix}",
        idempotency_key=f"real-redis-{suffix}",
    )


def _target(target: str = TARGET, **parameters: Any) -> dict[str, Any]:
    return {
        "target_type": "ip",
        "target": target,
        "parameters": parameters,
    }


@pytest.mark.asyncio
async def test_real_redis_response_verify_rollback_chain(
    redis_client: RedisClient,
) -> None:
    state = MockEnvironmentState(redis_client)
    provider = MockToolProvider(
        state,
        config=MockToolProviderConfig(observation_delay_ms=0),
    )
    verifier = MockVerificationRuntime(state, wait_timeout_ms=100, poll_interval_ms=5)

    queued = ActionExecutionJob.model_validate(
        await provider.execute("block_ip", _target(), context=_context("block"))
    )
    blocked = await provider.run_job(queued.job_id)
    assert blocked.status.value == "success"

    verified = ToolResult.model_validate(
        await verifier.execute(
            "check_ip_block_status",
            _target(job_id=blocked.job_id),
        )
    )
    assert verified.data["is_verified"] is True
    blocked_observation = await state.get_observation(
        "ip_blocks",
        TARGET,
        job_id=blocked.job_id,
    )
    assert blocked_observation is not None
    assert blocked_observation.source_refs == []

    rollback_queued = ActionExecutionJob.model_validate(
        await provider.execute("unblock_ip", _target(), context=_context("rollback"))
    )
    rollback = await provider.run_job(rollback_queued.job_id)
    assert rollback.status.value == "success"
    assert rollback.raw_result["rolled_back"] is True
    assert await state.get_state("blocked_ips", TARGET) is None

    unblocked = ToolResult.model_validate(
        await verifier.execute("check_ip_block_status", _target())
    )
    assert unblocked.data["is_verified"] is False
    assert unblocked.data["detail"] == "observed_status:allowed"
    history = await state.list_namespace("rollback_history")
    assert len(history) == 1
    assert next(iter(history.values()))["original_record"]["job_id"] == blocked.job_id

    now = datetime.now(UTC)
    source_ref = SourceReference(
        source_kind=SourceObjectKind.ASSET,
        source_product="mock_xdr",
        source_tenant_id="tenant-real-redis",
        connector_id="mock-xdr",
        source_object_id="asset-real-redis",
    )
    await state.set_observation(
        MockObservationRecord(
            surface="ip_blocks",
            target="203.0.113.243",
            status="blocked",
            observed_at=now,
            available_at=now,
            observed_version=1,
            source_refs=[source_ref],
            action_id="act-real-redis-source-ref",
            job_id="job-real-redis-source-ref",
            provider="mock_tool_provider",
            connector="mock-tool-connector",
        )
    )
    sourced_observation = await state.get_observation("ip_blocks", "203.0.113.243")
    assert sourced_observation is not None
    assert sourced_observation.source_refs == [source_ref]


@pytest.mark.asyncio
async def test_real_redis_delayed_projection_transitions_from_pending_to_visible(
    redis_client: RedisClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    monkeypatch.setattr("app.tools.mock_state._utc_now", lambda: current_now)
    monkeypatch.setattr("app.providers.tools.mock_provider._utc_now", lambda: current_now)
    state = MockEnvironmentState(redis_client)
    provider = MockToolProvider(
        state,
        config=MockToolProviderConfig(observation_delay_ms=60_000),
    )
    verifier = MockVerificationRuntime(state, wait_timeout_ms=0, poll_interval_ms=1)

    queued = ActionExecutionJob.model_validate(
        await provider.execute(
            "block_ip",
            _target(DELAYED_TARGET),
            context=_context("delayed"),
        )
    )
    completed = await provider.run_job(queued.job_id)
    pending = await state.get_observation(
        "ip_blocks",
        DELAYED_TARGET,
        include_pending=True,
        job_id=completed.job_id,
    )
    assert completed.status.value == "success"
    assert pending is not None
    assert (
        await state.get_observation(
            "ip_blocks",
            DELAYED_TARGET,
            job_id=completed.job_id,
        )
        is None
    )

    timed_out = ToolResult.model_validate(
        await verifier.execute(
            "check_ip_block_status",
            _target(DELAYED_TARGET, job_id=completed.job_id),
        )
    )
    assert timed_out.status.value == "timeout"
    assert timed_out.data["is_verified"] is False
    assert timed_out.data["detail"] == "observation_not_visible"

    current_now = pending.available_at + timedelta(microseconds=1)
    visible = ToolResult.model_validate(
        await verifier.execute(
            "check_ip_block_status",
            _target(DELAYED_TARGET, job_id=completed.job_id),
        )
    )
    assert visible.status.value == "success"
    assert visible.data["is_verified"] is True
