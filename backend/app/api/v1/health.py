"""Health check API: GET /api/v1/health."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response
from redis.asyncio import Redis

from app.core.celery_health import build_celery_health
from app.core.config import Settings, get_settings
from app.db.session_provider import peek_session_provider, ping_postgres_url
from app.models.knowledge_release import KNOWLEDGE_QUERY_PLAN_SCHEMA_VERSION
from app.services.action_approval_policy import APPROVAL_POLICY_VERSION
from app.services.detection_governance_policy import DETECTION_GOVERNANCE_POLICY_VERSION

router = APIRouter(tags=["health"])

# Process-wide Redis cache so health probes reuse one client per URL.
_REDIS_CLIENTS: dict[str, Redis] = {}


def _get_redis(redis_url: str) -> Redis:
    client = _REDIS_CLIENTS.get(redis_url)
    if client is None:
        client = Redis.from_url(redis_url, decode_responses=True)
        _REDIS_CLIENTS[redis_url] = client
    return client


async def shutdown_health_clients() -> None:
    """Close cached Redis clients on application shutdown (DB via SessionProvider)."""
    for client in _REDIS_CLIENTS.values():
        await client.aclose()
    _REDIS_CLIENTS.clear()


async def check_embedding_provider() -> dict[str, object]:
    """Return sanitized embedding provider readiness (ISSUE-140)."""
    try:
        from app.core.embedding.factory import get_embedding_client

        health = await get_embedding_client().health_probe()
        return health.model_dump(mode="json")
    except Exception:  # noqa: BLE001 — health must never raise
        return {
            "status": "error",
            "mode": "unknown",
            "release_id": "",
            "model_id": "",
            "dimension": 0,
            "store_vector_dimension": 0,
            "index_schema_ok": False,
            "distance_metric": "cosine",
            "normalization": "unit_l2",
            "config_hash": "",
            "error_code": "embedding_provider_error",
            "latency_ms": None,
        }


async def check_llm_provider(settings: Settings | None = None) -> dict[str, object]:
    """Return sanitized LLM provider readiness (ISSUE-106)."""
    from app.core.llm.diagnostics import check_llm_provider as _check_llm

    return await _check_llm(settings)


async def _check_playbook_resources(settings: Settings | None = None) -> dict[str, object]:
    """Return sanitized PlaybookKB resource readiness (ISSUE-139 / #645)."""
    from app.playbook.resources import check_playbook_resources

    return await check_playbook_resources(settings)


async def _check_loaded_resources(settings: Settings | None = None) -> dict[str, object]:
    """Return sanitized retrieval resource readiness (ISSUE-138)."""
    from app.rag.resources import check_loaded_resources

    return await check_loaded_resources(settings)


async def check_postgres(database_url: str) -> str:
    """Return 'ok' if SELECT 1 succeeds, else 'error'."""
    try:
        provider = peek_session_provider()
        if provider is not None and provider.database_url == database_url:
            ok = await provider.ping_postgres()
        else:
            # Ephemeral NullPool probe when settings URL differs from the process provider.
            ok = await ping_postgres_url(database_url, pool="nullpool")
        return "ok" if ok else "error"
    except Exception:  # noqa: BLE001 — health must never raise
        return "error"


async def check_redis(redis_url: str) -> str:
    """Return 'ok' if PING succeeds, else 'error'."""
    try:
        client = _get_redis(redis_url)
        pong = await client.ping()
        return "ok" if pong else "error"
    except Exception:  # noqa: BLE001 — health must never raise
        return "error"


def _component_summary(*, status: str, mode: str, capability: dict[str, str]) -> dict[str, Any]:
    """Adapter/provider summary: status, mode, capability — never credentials."""
    return {
        "status": status,
        "mode": mode,
        "capability": capability,
    }


@router.get("/health")
async def health(
    settings: Annotated[Settings, Depends(get_settings)],
    response: Response,
) -> dict[str, Any]:
    """Report dependency and adapter placeholder health.

    Returns 200 when every hard dependency is reachable, otherwise 503 so that
    HTTP-only probes (compose `curl -f`, load balancers) detect degradation.
    """
    postgres = await check_postgres(settings.database_url)
    redis_status = await check_redis(settings.redis_url)
    embedding_provider = await check_embedding_provider()
    llm_provider = await check_llm_provider(settings)
    loaded_resources = await _check_loaded_resources(settings)
    playbook_resources = await _check_playbook_resources(settings)

    # NOTE: capability values below are UNVERIFIED placeholders for the Mock
    # phase. Once real adapters land they must be replaced with actual
    # capability probing (live capabilities default to UNKNOWN).
    source_adapter = _component_summary(
        status="ok" if settings.source_mode == "mock_xdr" else "degraded",
        mode=settings.source_mode,
        capability={
            "LOG_INGESTION": "SUPPORTED" if settings.source_mode == "mock_xdr" else "UNKNOWN",
            "QUERY": "SUPPORTED" if settings.source_mode == "mock_xdr" else "UNKNOWN",
            "EVENT_DISPOSITION": "UNSUPPORTED",
            "ENTITY_RESPONSE": "UNSUPPORTED",
        },
    )
    disposition_adapter = _component_summary(
        status="ok" if settings.disposition_mode == "mock_xdr" else "degraded",
        mode=settings.disposition_mode,
        capability={
            "LOG_INGESTION": "UNSUPPORTED",
            "QUERY": "UNKNOWN",
            "EVENT_DISPOSITION": (
                "SUPPORTED" if settings.disposition_mode == "mock_xdr" else "UNKNOWN"
            ),
            "ENTITY_RESPONSE": (
                "SUPPORTED" if settings.disposition_mode == "mock_xdr" else "UNKNOWN"
            ),
        },
    )
    tool_provider = _component_summary(
        status="ok" if settings.tool_mode == "mock" else "degraded",
        mode=settings.tool_mode,
        capability={
            "query": "SUPPORTED" if settings.tool_mode == "mock" else "UNKNOWN",
            "response": "SUPPORTED" if settings.tool_mode == "mock" else "UNKNOWN",
            "verification": "SUPPORTED" if settings.tool_mode == "mock" else "UNKNOWN",
            "rollback": "SUPPORTED" if settings.tool_mode == "mock" else "UNKNOWN",
        },
    )

    broker_url = (settings.celery_broker_url or settings.redis_url).strip()
    celery_health = await build_celery_health(
        task_mode=settings.task_mode,
        broker_url=broker_url,
    )
    from app.orchestration.checkpointer import get_checkpoint_health

    checkpoint_health = get_checkpoint_health()
    from app.core.metrics import get_budget_redis_health

    budget_redis_health = get_budget_redis_health()

    hard_deps_ok = postgres == "ok" and redis_status == "ok"
    embedding_ok = embedding_provider.get("status") == "ok"
    llm_ok = llm_provider.get("status") == "ok"
    loaded_ok = loaded_resources.get("status") == "ready"
    playbook_ok = playbook_resources.get("status") == "ready"
    # Production / PLAYBOOK_RELEASE_REQUIRE_ACTIVE / demo PLAYBOOK_REQUIRED gate
    # health only — investigation stack remains fail-soft (ISSUE-245 / #820).
    playbook_required = settings.app_env.strip().lower() == "production" or (
        settings.playbook_release_require_active or settings.playbook_required
    )
    llm_required = bool(settings.llm_required)
    celery_task_mode = str(celery_health.get("task_mode", "background"))
    celery_broker_status = str(celery_health.get("broker", "error"))
    celery_worker_status = str(celery_health.get("worker", {}).get("status", "not_applicable"))

    overall = "ok"
    if not hard_deps_ok or not embedding_ok:
        overall = "degraded"
    elif not loaded_ok:
        overall = "degraded"
    elif playbook_required and not playbook_ok:
        overall = "degraded"
    elif llm_required and not llm_ok:
        overall = "degraded"
    elif celery_worker_status in {"degraded", "error"}:
        overall = "degraded"
    elif celery_task_mode == "celery" and celery_broker_status == "error":
        overall = "degraded"
    elif checkpoint_health.get("status") == "degraded":
        overall = "degraded"
    elif budget_redis_health.get("status") == "degraded":
        overall = "degraded"

    # 503 only for hard dependency / embedding failures — not missing workers alone (#622).
    # LLM affects HTTP status only when explicitly required (#609).
    # Playbook readiness affects HTTP status when production or require_active (#645).
    if (
        not hard_deps_ok
        or not embedding_ok
        or (llm_required and not llm_ok)
        or (playbook_required and not playbook_ok)
    ):
        response.status_code = 503

    return {
        "status": overall,
        "postgres": postgres,
        "redis": redis_status,
        "checkpoint": checkpoint_health,
        "budget_redis": budget_redis_health,
        "embedding_provider": embedding_provider,
        "loaded_resources": loaded_resources,
        "playbook_resources": playbook_resources,
        "llm": llm_provider,
        "celery": celery_health,
        "source_adapter": source_adapter,
        "disposition_adapter": disposition_adapter,
        "tool_provider": tool_provider,
        "simulation_enabled": settings.simulation_enabled,
        "version": settings.app_version,
        "investigation": {
            "orchestration_mode": settings.orchestration_mode,
            "full_loop_available": settings.orchestration_mode.strip().lower() != "analysis_only",
            "task_mode": (settings.task_mode or "background").strip().lower(),
            "auto_investigate_enabled": settings.auto_investigate_enabled,
            "auto_response_enabled": settings.auto_response_enabled,
            "approval_policy_version": APPROVAL_POLICY_VERSION,
            "detection_governance_policy_version": DETECTION_GOVERNANCE_POLICY_VERSION,
            "knowledge_query_plan_schema_version": KNOWLEDGE_QUERY_PLAN_SCHEMA_VERSION,
        },
    }
