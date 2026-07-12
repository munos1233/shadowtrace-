"""ShadowTrace FastAPI application entrypoint."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.v1 import api_router
from app.api.v1.errors import register_exception_handlers
from app.api.v1.health import shutdown_health_clients


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    await shutdown_health_clients()


app = FastAPI(title="ShadowTrace", version="0.1.0", lifespan=lifespan)
register_exception_handlers(app)
app.include_router(api_router, prefix="/api/v1")
