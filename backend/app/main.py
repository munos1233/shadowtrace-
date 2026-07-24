"""ShadowTrace FastAPI application entrypoint."""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI

from app.api.v1 import api_router
from app.api.v1.errors import register_exception_handlers
from app.api.v1.health import shutdown_health_clients
from app.core.config import get_settings
from app.core.redis_client import RedisClient
from app.core.socketio_manager import SocketIOManager
from app.orchestration.orchestration_config import assert_orchestration_mode

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

    try:
        yield
    finally:
        scan_task.cancel()
        with suppress(asyncio.CancelledError):
            await scan_task
        await _socketio_manager.stop()
        await shutdown_health_clients()


app = FastAPI(title="ShadowTrace", version="0.1.0", lifespan=_lifespan)
register_exception_handlers(app)
app.include_router(api_router, prefix="/api/v1")

# ---------------------------------------------------------------------------
# Socket.IO wrapper — uvicorn / Docker must target ``socket_app``, not ``app``.
# ``app`` is kept as the inner FastAPI instance so that ``app.openapi()``,
# TestClient, and scripts that import ``from app.main import app`` continue to
# work unchanged.
# ---------------------------------------------------------------------------

socket_app = _socketio_manager.mount(app)
