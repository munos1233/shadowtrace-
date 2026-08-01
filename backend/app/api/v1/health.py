"""Health check API: GET /api/v1/health."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response
from redis.asyncio import Redis

from app.core.celery_health import build_celery_health
from app.core.config import Settings, get_settings
from app.db.session_provider import peek_session_provider, ping_postgres_url

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

    hard_deps_ok = postgres == "ok" and redis_status == "ok"
    embedding_ok = embedding_provider.get("status") == "ok"
    celery_task_mode = str(celery_health.get("task_mode", "background"))
    celery_broker_status = str(celery_health.get("broker", "error"))
    celery_worker_status = str(celery_health.get("worker", {}).get("status", "not_applicable"))

    overall = "ok"
    if not hard_deps_ok or not embedding_ok:
        overall = "degraded"
    elif celery_worker_status in {"degraded", "error"}:
        overall = "degraded"
    elif celery_task_mode == "celery" and celery_broker_status == "error":
        overall = "degraded"

    # 503 only for hard dependency / embedding failures — not missing workers alone (#622).
    if not hard_deps_ok or not embedding_ok:
        response.status_code = 503

    return {
        "status": overall,
        "postgres": postgres,
        "redis": redis_status,
        "embedding_provider": embedding_provider,
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
        },
    }
