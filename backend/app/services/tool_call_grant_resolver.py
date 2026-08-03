"""Grant scope resolution — registry ∩ grant intersection (ISSUE-134).

Phase B note: canonicalized scope-policy adapters (connector/domain/entity)
will extend ``validate_scope_params``; Phase A inlines checks here intentionally.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import orjson

from app.models.enums import ToolCategory
from app.models.tool_call_grant import (
    BoundExecutionPrincipal,
    ToolCallGrant,
    ToolCallGrantScope,
    ToolCallMode,
)
from app.models.tool_meta import RoutingKind
from app.tools.registry import ToolRegistry


def build_react_idempotency_key(
    event_id: str,
    *,
    plan_step_id: str | None = None,
    allowed_tools: list[str] | None = None,
    max_calls: int | None = None,
    shadow_run_id: str | None = None,
) -> str:
    """Stable idempotency key for ReAct step grant mint/retry."""

    step = (plan_step_id or "default").strip() or "default"
    key = f"react-{event_id}-{step}"
    if shadow_run_id:
        key = f"{key}-shadow-{(shadow_run_id or '').strip()}"
    if allowed_tools is not None:
        scope_payload = f"{','.join(sorted(allowed_tools))}:{max_calls or 0}"
        scope_digest = hashlib.sha256(scope_payload.encode("utf-8")).hexdigest()[:8]
        key = f"{key}-{scope_digest}"
    return key[:256]


def build_namespace_key(
    mode: ToolCallMode,
    *,
    event_id: str,
    shadow_run_id: str | None = None,
) -> str:
    if mode is ToolCallMode.SHADOW:
        run_id = (shadow_run_id or "").strip()
        if not run_id:
            raise ValueError("shadow_run_id is required for shadow namespace")
        return f"shadow:{run_id}"
    if mode is ToolCallMode.COMPATIBILITY:
        return f"compat:{event_id}"
    return f"production:{event_id}"


def build_grant_id() -> str:
    return f"tcg-{secrets.token_hex(8)}"


def build_attempt_id() -> str:
    return f"tca-{secrets.token_hex(8)}"


def build_principal_id() -> str:
    return f"tcp-{secrets.token_hex(8)}"


def hash_grant_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_grant_token() -> str:
    return secrets.token_urlsafe(32)


def params_fingerprint(params: dict[str, object]) -> str:
    canonical = orjson.dumps(params, option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(canonical).hexdigest()


def resolve_effective_query_tools(
    scope: ToolCallGrantScope,
    registry: ToolRegistry,
) -> frozenset[str]:
    """Intersect grant allow-list with registered query tools."""

    allowed = set(scope.allowed_tools)
    registered = {
        meta.tool_name
        for meta in registry.list_tools(category=ToolCategory.QUERY)
        if meta.routing_kind is not RoutingKind.DISPOSITION_ONLY
    }
    return frozenset(allowed & registered)


def is_tool_allowed_by_grant(
    tool_name: str,
    *,
    scope: ToolCallGrantScope,
    registry: ToolRegistry,
) -> bool:
    return tool_name in resolve_effective_query_tools(scope, registry)


def is_non_query_dynamic_tool(registry: ToolRegistry, tool_name: str) -> bool:
    """Return True when the tool is response/rollback/disposition (must be zero for dynamic)."""

    try:
        registered = registry.get_tool(tool_name)
    except Exception:
        return True
    meta = registered.tool_meta
    if meta.tool_category is not ToolCategory.QUERY:
        return True
    return meta.routing_kind is RoutingKind.DISPOSITION_ONLY


def validate_scope_params(
    params: dict[str, object],
    *,
    scope: ToolCallGrantScope,
) -> str | None:
    """Return denial reason when params expand beyond grant scope; else None."""

    if scope.connector_ids:
        connector = params.get("connector_id")
        source_connector = params.get("source_connector_id")
        resolved: str | None = None
        if isinstance(connector, str) and connector.strip():
            resolved = connector.strip()
        elif isinstance(source_connector, str) and source_connector.strip():
            resolved = source_connector.strip()
        if resolved is None:
            return "connector scope requires explicit connector_id or source_connector_id"
        if resolved not in scope.connector_ids:
            return "connector_id not in grant scope"

    if scope.allowed_domains:
        domain = params.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            return "domain scope requires explicit domain parameter"
        if domain.strip() not in scope.allowed_domains:
            return "domain not in grant scope"

    if scope.allowed_entities:
        matched = False
        for key in ("entity_id", "account", "host", "ip", "process_name"):
            value = params.get(key)
            if isinstance(value, str) and value.strip():
                if value.strip() not in scope.allowed_entities:
                    return f"{key} not in grant scope"
                matched = True
        if not matched:
            return "entity scope requires explicit scoped entity parameter"
    return None


def grant_from_row(row: object) -> ToolCallGrant:
    from app.db import models as orm

    assert isinstance(row, orm.ToolCallGrantORM)
    return ToolCallGrant(
        grant_id=row.grant_id,
        mode=ToolCallMode(row.mode),
        namespace_key=row.namespace_key,
        shadow_run_id=row.shadow_run_id,
        event_id=row.event_id,
        plan_step_id=row.plan_step_id,
        task_id=row.task_id,
        tenant_id=row.tenant_id,
        scope=ToolCallGrantScope.model_validate(row.scope),
        execution_principal=BoundExecutionPrincipal.model_validate(row.execution_principal),
        max_calls=int(row.max_calls),
        attempt_count=int(row.attempt_count),
        valid_from=row.valid_from,
        expires_at=row.expires_at,
        policy_version=row.policy_version,
        schema_version=row.schema_version,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
    )


def default_grant_window(*, valid_for_seconds: int) -> tuple[datetime, datetime]:
    now = datetime.now(tz=UTC)
    return now, now + timedelta(seconds=valid_for_seconds)


__all__ = [
    "build_attempt_id",
    "build_grant_id",
    "build_namespace_key",
    "build_principal_id",
    "build_react_idempotency_key",
    "default_grant_window",
    "grant_from_row",
    "hash_grant_token",
    "is_non_query_dynamic_tool",
    "is_tool_allowed_by_grant",
    "issue_grant_token",
    "params_fingerprint",
    "resolve_effective_query_tools",
    "validate_scope_params",
]
