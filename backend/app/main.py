"""ShadowTrace FastAPI application entrypoint."""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import api_router
from app.api.v1.errors import register_exception_handlers
from app.api.v1.health import shutdown_health_clients
from app.core.config import get_settings
from app.core.redis_client import RedisClient
from app.core.sanitization import configure_app_logging
from app.core.socketio_manager import SocketIOManager
from app.core.telemetry import setup_telemetry
from app.db.session import dispose_session_provider, get_session_provider
from app.orchestration.orchestration_config import assert_orchestration_mode

# ISSUE-223: install RedactingFormatter on the "app" logger before any
# application code emits log records.  Idempotent — safe across hot-
# reload and multi-worker restarts.
configure_app_logging()

logger = logging.getLogger(__name__)

APPROVAL_SCAN_INTERVAL_SECONDS = 60

# ---------------------------------------------------------------------------
# Lazy infrastructure singletons (connections established on first use)
# ---------------------------------------------------------------------------

_redis = RedisClient()
_socketio_manager = SocketIOManager(_redis)


# ---------------------------------------------------------------------------
# Application factory + lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
    # Fail-closed (ISSUE-093 §5): validate runtime settings BEFORE serving any
    # traffic. Settings construction raises ConfigurationError if app_env is
    # production and any mock/simulation mode is active.
    settings = get_settings()
    assert_orchestration_mode(settings)

    # Start the Redis→Socket.IO bridge background task.
    await _socketio_manager.start()

    async def _approval_timeout_scan_loop() -> None:
        while True:
            await asyncio.sleep(APPROVAL_SCAN_INTERVAL_SECONDS)
            try:
                from app.api.v1.deps import get_approval_engine

                engine = await get_approval_engine()
                await engine.scan_timeouts()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("approval timeout scan failed")

    scan_task = asyncio.create_task(_approval_timeout_scan_loop())

    if settings.opensearch_enabled:
        try:
            from app.api.v1.deps import _get_opensearch_client

            opensearch = _get_opensearch_client()
            await opensearch.initialize_indices()
        except Exception:
            logger.warning("OpenSearch index initialization failed", exc_info=True)

    try:
        from app.rag.resources import warmup_retrieval_resources

        warmup_retrieval_resources()
    except Exception:
        logger.warning("Retrieval resource warmup failed", exc_info=True)

    try:
        yield
    finally:
        scan_task.cancel()
        with suppress(asyncio.CancelledError):
            await scan_task
        await _socketio_manager.stop()
        await shutdown_health_clients()
        await dispose_session_provider()
        try:
            from app.core.embedding.factory import close_embedding_client
            from app.playbook.resources import reset_playbook_resources_cache
            from app.rag.resources import reset_loaded_retrieval_resources

            await close_embedding_client()
            reset_loaded_retrieval_resources()
            reset_playbook_resources_cache()
        except Exception:
            logger.warning("Retrieval resource shutdown failed", exc_info=True)
        try:
            from app.api.v1.deps import shutdown_neo4j_client

            await shutdown_neo4j_client()
        except Exception:
            logger.warning("Neo4j client shutdown failed", exc_info=True)


app = FastAPI(title="ShadowTrace", version="0.1.0", lifespan=_lifespan)
register_exception_handlers(app)

# Compose / local dev serves the Vite frontend on a different origin than the API.
# Use Settings.is_production() (ISSUE-217) so padded APP_ENV cannot widen CORS.
if not get_settings().is_production():
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router, prefix="/api/v1")

setup_telemetry(app=app, engine=get_session_provider().engine())

# ---------------------------------------------------------------------------
# Socket.IO wrapper — uvicorn / Docker must target ``socket_app``, not ``app``.
# ``app`` is kept as the inner FastAPI instance so that ``app.openapi()``,
# TestClient, and scripts that import ``from app.main import app`` continue to
# work unchanged.
# ---------------------------------------------------------------------------

socket_app = _socketio_manager.mount(app)
