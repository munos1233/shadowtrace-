"""BudgetService token/cost metering tests (ISSUE-029)."""

from __future__ import annotations

from typing import Any

import pytest

from app.core.config import Settings
from app.core.errors import BudgetExceededError
from app.models.enums import Severity
from app.models.workflow import (
    EVENT_COST_BUDGET_USD,
    EVENT_TOKEN_BUDGET,
    GLOBAL_TOKEN_BUDGET,
    MODEL_PRICE_TABLE,
    PER_AGENT_TOKEN_CAP,
)
from app.services.budget_service import (
    BudgetService,
    BudgetUsage,
    compute_llm_cost_usd,
)


class _RecordingUsageWriter:
    def __init__(self) -> None:
        self.by_event: dict[str, BudgetUsage] = {}

    async def write_budget_usage(self, event_id: str, usage: BudgetUsage) -> None:
        self.by_event[event_id] = usage.model_copy(deep=True)


def _settings(**overrides: Any) -> Settings:
    base = {
        "budget_enabled": True,
        "global_token_budget": GLOBAL_TOKEN_BUDGET,
        "event_token_budget": EVENT_TOKEN_BUDGET,
        "event_cost_budget_usd": EVENT_COST_BUDGET_USD,
        "per_agent_token_cap": PER_AGENT_TOKEN_CAP,
        "llm_mode": "openai_compatible",
        "app_env": "development",
    }
    base.update(overrides)
    return Settings.model_validate(base)


@pytest.fixture
def writer() -> _RecordingUsageWriter:
    return _RecordingUsageWriter()


@pytest.fixture
def service(writer: _RecordingUsageWriter) -> BudgetService:
    return BudgetService(redis=None, usage_writer=writer, settings=_settings())


def test_model_price_table_uses_prompt_completion_tuple() -> None:
    assert MODEL_PRICE_TABLE["mock-model"] == (0.0, 0.0)
    assert compute_llm_cost_usd("mock-model", 1000, 500) == 0.0


def test_compute_llm_cost_usd_from_price_table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(MODEL_PRICE_TABLE, "priced-model", (1.0, 2.0))
    assert compute_llm_cost_usd("priced-model", 1500, 500) == 2.5
    assert compute_llm_cost_usd("priced-model", 1500, 500, force_zero=True) == 0.0


def test_allocate_event_budget_scales_by_severity(service: BudgetService) -> None:
    low = service.allocate_event_budget(Severity.LOW)
    medium = service.allocate_event_budget("medium")
    high = service.allocate_event_budget(Severity.HIGH)
    critical = service.allocate_event_budget(Severity.CRITICAL)
    assert low == EVENT_TOKEN_BUDGET // 2
    assert medium == EVENT_TOKEN_BUDGET
    assert high == int(EVENT_TOKEN_BUDGET * 1.5)
    assert critical == EVENT_TOKEN_BUDGET * 2
    assert critical > low


@pytest.mark.asyncio
async def test_charge_llm_and_tool_update_usage_and_event_context(
    service: BudgetService,
    writer: _RecordingUsageWriter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(MODEL_PRICE_TABLE, "priced-model", (1.0, 1.0))
    event_id = "evt-2026-budget-charge"

    snap = await service.charge_llm(
        event_id,
        "EvidenceAgent",
        "priced-model",
        prompt_tokens=1000,
        completion_tokens=500,
    )
    assert snap.event_tokens == 1500
    assert snap.event_cost_usd == 1.5
    assert snap.system_tokens == 1500
    assert snap.per_agent["EvidenceAgent"]["tokens"] == 1500

    tool_snap = await service.charge_tool(event_id, "EvidenceAgent", "query_dns")
    assert tool_snap.tool_calls == 1
    assert tool_snap.per_agent["EvidenceAgent"]["tool_calls"] == 1

    usage = await service.get_usage(event_id)
    assert usage.event_tokens == 1500
    assert usage.event_cost_usd == 1.5
    assert usage.tool_calls == 1
    assert usage.system_tokens == 1500
    assert writer.by_event[event_id].event_tokens == 1500
    assert writer.by_event[event_id].tool_calls == 1


@pytest.mark.asyncio
async def test_mock_llm_mode_forces_zero_cost(writer: _RecordingUsageWriter) -> None:
    service = BudgetService(
        redis=None,
        usage_writer=writer,
        settings=_settings(llm_mode="mock"),
    )
    await service.charge_llm(
        "evt-2026-mock-cost",
        "TriageAgent",
        "any-model",
        prompt_tokens=2000,
        completion_tokens=2000,
    )
    usage = await service.get_usage("evt-2026-mock-cost")
    assert usage.event_tokens == 4000
    assert usage.event_cost_usd == 0.0


@pytest.mark.asyncio
async def test_event_token_overage_raises_on_next_check(
    service: BudgetService,
) -> None:
    event_id = "evt-2026-event-cap"
    await service.charge_llm(
        event_id,
        "RiskAgent",
        "mock-model",
        prompt_tokens=EVENT_TOKEN_BUDGET,
        completion_tokens=1,
    )
    with pytest.raises(BudgetExceededError) as exc_info:
        await service.check(event_id, "RiskAgent")
    assert exc_info.value.error_code == "budget_exceeded"
    assert exc_info.value.details["scope"] == "event"
    assert exc_info.value.details["metric"] == "tokens"


@pytest.mark.asyncio
async def test_agent_and_system_overage_scopes(
    writer: _RecordingUsageWriter,
) -> None:
    agent_service = BudgetService(
        redis=None,
        usage_writer=writer,
        settings=_settings(per_agent_token_cap=100, event_token_budget=10_000),
    )
    await agent_service.charge_llm(
        "evt-2026-agent-cap",
        "ReportAgent",
        "mock-model",
        prompt_tokens=80,
        completion_tokens=30,
    )
    with pytest.raises(BudgetExceededError) as agent_exc:
        await agent_service.check("evt-2026-agent-cap", "ReportAgent")
    assert agent_exc.value.details["scope"] == "agent"

    system_service = BudgetService(
        redis=None,
        usage_writer=writer,
        settings=_settings(
            global_token_budget=50,
            event_token_budget=10_000,
            per_agent_token_cap=10_000,
        ),
    )
    await system_service.charge_llm(
        "evt-2026-system-cap",
        "SuperAgent",
        "mock-model",
        prompt_tokens=40,
        completion_tokens=20,
    )
    with pytest.raises(BudgetExceededError) as system_exc:
        await system_service.check("evt-2026-system-cap", "SuperAgent")
    assert system_exc.value.details["scope"] == "system"


@pytest.mark.asyncio
async def test_event_cost_overage_raises(
    writer: _RecordingUsageWriter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(MODEL_PRICE_TABLE, "pricey", (10.0, 10.0))
    service = BudgetService(
        redis=None,
        usage_writer=writer,
        settings=_settings(event_cost_budget_usd=1.0, event_token_budget=1_000_000),
    )
    await service.charge_llm(
        "evt-2026-cost-cap",
        "RiskAgent",
        "pricey",
        prompt_tokens=1000,
        completion_tokens=0,
    )
    with pytest.raises(BudgetExceededError) as exc_info:
        await service.check("evt-2026-cost-cap", "RiskAgent")
    assert exc_info.value.details["scope"] == "event"
    assert exc_info.value.details["metric"] == "cost_usd"


@pytest.mark.asyncio
async def test_budget_disabled_never_raises(writer: _RecordingUsageWriter) -> None:
    service = BudgetService(
        redis=None,
        usage_writer=writer,
        settings=_settings(budget_enabled=False, event_token_budget=10),
        enabled=False,
    )
    await service.charge_llm(
        "evt-2026-disabled",
        "TriageAgent",
        "mock-model",
        prompt_tokens=100,
        completion_tokens=100,
    )
    await service.check("evt-2026-disabled", "TriageAgent")
    usage = await service.get_usage("evt-2026-disabled")
    assert usage.event_tokens == 200
    assert "evt-2026-disabled" in writer.by_event


@pytest.mark.asyncio
async def test_reset_event_clears_event_counters_only(service: BudgetService) -> None:
    await service.charge_llm(
        "evt-2026-reset-a",
        "TriageAgent",
        "mock-model",
        prompt_tokens=10,
        completion_tokens=5,
    )
    await service.charge_llm(
        "evt-2026-reset-b",
        "TriageAgent",
        "mock-model",
        prompt_tokens=7,
        completion_tokens=3,
    )
    await service.reset_event("evt-2026-reset-a")
    usage_a = await service.get_usage("evt-2026-reset-a")
    usage_b = await service.get_usage("evt-2026-reset-b")
    assert usage_a.event_tokens == 0
    assert usage_b.event_tokens == 10
    assert usage_b.system_tokens == 25


@pytest.mark.asyncio
async def test_llm_client_check_blocks_when_over_budget() -> None:
    from app.core.llm.base import InMemoryLLMCallAuditRecorder, LLMMessage
    from app.core.llm.mock_client import MockLLMClient

    writer = _RecordingUsageWriter()
    budget = BudgetService(
        redis=None,
        usage_writer=writer,
        settings=_settings(event_token_budget=50),
    )
    client = MockLLMClient(
        audit_recorder=InMemoryLLMCallAuditRecorder(),
        budget_service=budget,
        primary_model="mock-model",
    )
    await budget.charge_llm(
        "evt-2026-llm-hook",
        "TriageAgent",
        "mock-model",
        prompt_tokens=51,
        completion_tokens=0,
    )
    with pytest.raises(BudgetExceededError) as exc_info:
        await client.chat(
            [LLMMessage(role="user", content="hello")],
            event_id="evt-2026-llm-hook",
            agent_name="TriageAgent",
            prompt_key="missing_prompt_for_budget_test",
        )
    assert exc_info.value.details["scope"] == "event"


@pytest.mark.asyncio
async def test_tool_executor_check_before_call() -> None:
    from app.tools.executor import ToolExecutor
    from app.tools.registry import ToolRegistry

    writer = _RecordingUsageWriter()
    budget = BudgetService(
        redis=None,
        usage_writer=writer,
        settings=_settings(event_token_budget=10),
    )
    await budget.charge_llm(
        "evt-2026-tool-hook",
        "EvidenceAgent",
        "mock-model",
        prompt_tokens=11,
        completion_tokens=0,
    )

    registry = ToolRegistry()
    discovered = registry.auto_discover()
    assert discovered
    tool_name = next(
        name
        for name in discovered
        if registry.get_tool(name).tool_meta.tool_category.value == "query"
    )

    executor = ToolExecutor(registry=registry, budget_service=budget)
    with pytest.raises(BudgetExceededError) as exc_info:
        await executor.call(
            tool_name,
            {"event_id": "evt-2026-tool-hook"},
            "evt-2026-tool-hook",
            agent_name="EvidenceAgent",
        )
    assert exc_info.value.details["scope"] == "event"
