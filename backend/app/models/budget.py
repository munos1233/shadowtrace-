"""Budget domain models (ISSUE-029 / intro §4.10)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import BudgetScope

__all__ = ["BudgetScope", "BudgetSnapshot"]


class BudgetSnapshot(BaseModel):
    """Point-in-time view after a charge or usage read."""

    model_config = ConfigDict(extra="forbid")

    scope: BudgetScope | None = None
    event_id: str
    agent_name: str | None = None
    event_tokens: int = Field(default=0, ge=0)
    event_cost_usd: float = Field(default=0.0, ge=0.0)
    tool_calls: int = Field(default=0, ge=0)
    system_tokens: int = Field(default=0, ge=0)
    per_agent: dict[str, Any] = Field(default_factory=dict)
    event_token_budget: int = Field(default=0, ge=0)
    event_cost_budget_usd: float = Field(default=0.0, ge=0.0)
    per_agent_token_cap: int = Field(default=0, ge=0)
    global_token_budget: int = Field(default=0, ge=0)
