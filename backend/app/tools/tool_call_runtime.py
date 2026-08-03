"""Production wiring for ToolCallGrant, compatibility path, and ReAct executors (ISSUE-134)."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.core.config import Settings
from app.core.errors import ToolCallGrantUnavailableError
from app.models.agent_io import PlanStep
from app.models.enums import ToolCategory
from app.models.tool_call_grant import ToolCallGrantScope, ToolCallMode
from app.models.tool_meta import RoutingKind
from app.orchestration.react_engine import (
    DEFAULT_TOOL_CALL_BUDGET,
    ReadOnlyAgentCallable,
    ReadOnlyReActExecutor,
)
from app.services.safe_tool_projection import SafeToolProjectionService
from app.services.tenant_resolution import resolve_tenant_id
from app.services.tool_call_grant_resolver import resolve_effective_query_tools
from app.services.tool_call_grant_service import (
    ToolCallGrantService,
    build_react_grant_request,
)
from app.tools.bound_tool_executor import BoundToolExecutor
from app.tools.compatibility_query_path import CompatibilityQueryToolPath
from app.tools.executor import ToolExecutor
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


def build_evidence_query_executor(
    inner: ToolExecutor,
    *,
    settings: Settings,
) -> CompatibilityQueryToolPath:
    """Wrap the shared ToolExecutor with the named Evidence compatibility path."""

    return CompatibilityQueryToolPath(
        inner=inner,
        registry=inner.registry,
        settings=settings,
    )


def list_dynamic_query_tools(registry: ToolRegistry) -> list[str]:
    """Query tools eligible for dynamic ReAct grants (registry ∩ non-disposition)."""

    return sorted(
        meta.tool_name
        for meta in registry.list_tools(category=ToolCategory.QUERY)
        if meta.routing_kind is not RoutingKind.DISPOSITION_ONLY
    )


def resolve_react_grant_tools(
    registry: ToolRegistry,
    required_tools: list[str] | None,
) -> list[str]:
    """Intersect plan-step required_tools with registry; fall back when plan is empty."""

    if required_tools:
        narrowed = sorted(
            resolve_effective_query_tools(
                ToolCallGrantScope(allowed_tools=required_tools),
                registry,
            )
        )
        if narrowed:
            return narrowed
        logger.warning(
            "react plan required_tools produced empty grant scope; "
            "falling back to registry query tools"
        )
    return sorted(
        resolve_effective_query_tools(
            ToolCallGrantScope(allowed_tools=list_dynamic_query_tools(registry)),
            registry,
        )
    )


def plan_step_binding_id(step: PlanStep | None) -> str | None:
    if step is None:
        return None
    return f"react-step-{step.step_order}"


@dataclass
class ReactToolExecutorFactory:
    """Mint grant-bound executors per investigation event for ReAct dynamic calls."""

    inner_executor: ToolExecutor
    grant_service: ToolCallGrantService
    settings: Settings
    projection_service: SafeToolProjectionService

    @property
    def registry(self) -> ToolRegistry:
        return self.inner_executor.registry

    async def for_event(
        self,
        event_id: str,
        *,
        tenant_id: str | None = None,
        source_snapshot: dict[str, Any] | None = None,
        plan_step: PlanStep | None = None,
    ) -> ReadOnlyReActExecutor:
        resolved_tenant = (tenant_id or resolve_tenant_id(source_snapshot) or "").strip()
        if not resolved_tenant:
            resolved_tenant = self.settings.retrieval_default_tenant_id.strip()

        if not self.settings.tool_call_grant_required:
            return ReadOnlyReActExecutor(self.inner_executor, event_id=event_id)

        if not self.grant_service.available:
            raise ToolCallGrantUnavailableError(
                "tool call grant service unavailable for dynamic ReAct",
                details={"event_id": event_id},
            )

        scope_tools = resolve_react_grant_tools(
            self.registry,
            list(plan_step.required_tools) if plan_step is not None else None,
        )
        step_id = plan_step_binding_id(plan_step)
        issued = await self.grant_service.issue_grant(
            build_react_grant_request(
                event_id=event_id,
                tenant_id=resolved_tenant,
                allowed_tools=scope_tools,
                max_calls=max(1, DEFAULT_TOOL_CALL_BUDGET),
                policy_version=self.settings.tool_call_grant_policy_version,
                plan_step_id=step_id,
            )
        )
        if issued.grant_token:
            grant = issued.grant
            grant_token = issued.grant_token
        else:
            grant = await self.grant_service.load_grant_trusted(issued.grant.grant_id)
            grant_token = ""
            logger.info(
                "react grant idempotent replay grant_id=%s event_id=%s",
                grant.grant_id,
                event_id,
            )

        bound = BoundToolExecutor(
            inner=self.inner_executor,
            grant=grant,
            grant_service=self.grant_service,
            registry=self.registry,
            projection_service=self.projection_service,
            grant_token=grant_token,
        )
        return ReadOnlyReActExecutor(bound, event_id=event_id)

    async def for_shadow_run(
        self,
        event_id: str,
        *,
        shadow_run_id: str,
        tenant_id: str,
        allowed_agents: Mapping[str, ReadOnlyAgentCallable] | None = None,
        allowed_tools: list[str] | None = None,
        max_calls: int | None = None,
    ) -> ReadOnlyReActExecutor:
        """Mint a shadow-namespace grant for isolated query pivot (#641)."""
        if not shadow_run_id.strip():
            raise ValueError("shadow_run_id is required for shadow ReAct executor")
        if not tenant_id.strip():
            raise ValueError("tenant_id is required for shadow ReAct executor")

        if not self.settings.tool_call_grant_required:
            return ReadOnlyReActExecutor(
                self.inner_executor,
                event_id=event_id,
                allowed_agents=allowed_agents,
                agent_name="shadow_query_pivot",
            )

        if not self.grant_service.available:
            raise ToolCallGrantUnavailableError(
                "tool call grant service unavailable for shadow ReAct",
                details={"event_id": event_id, "shadow_run_id": shadow_run_id},
            )

        scope_tools = resolve_react_grant_tools(
            self.registry,
            allowed_tools or list_dynamic_query_tools(self.registry),
        )
        issued = await self.grant_service.issue_grant(
            build_react_grant_request(
                event_id=event_id,
                tenant_id=tenant_id,
                allowed_tools=scope_tools,
                max_calls=max(1, max_calls or DEFAULT_TOOL_CALL_BUDGET),
                policy_version=self.settings.tool_call_grant_policy_version,
                plan_step_id=f"shadow-{shadow_run_id}",
                shadow_run_id=shadow_run_id,
                mode=ToolCallMode.SHADOW,
            )
        )
        if issued.grant_token:
            grant = issued.grant
            grant_token = issued.grant_token
        else:
            grant = await self.grant_service.load_grant_trusted(issued.grant.grant_id)
            grant_token = ""

        bound = BoundToolExecutor(
            inner=self.inner_executor,
            grant=grant,
            grant_service=self.grant_service,
            registry=self.registry,
            projection_service=self.projection_service,
            grant_token=grant_token,
        )
        return ReadOnlyReActExecutor(
            bound,
            event_id=event_id,
            allowed_agents=allowed_agents,
            agent_name="shadow_query_pivot",
        )


__all__ = [
    "ReactToolExecutorFactory",
    "build_evidence_query_executor",
    "list_dynamic_query_tools",
    "plan_step_binding_id",
    "resolve_react_grant_tools",
]
