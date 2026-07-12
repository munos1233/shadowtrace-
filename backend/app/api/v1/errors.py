"""Domain API exceptions and the unified error handler (ISSUE-004 / ISSUE-008).

Every handled error serializes via ``ShadowTraceError.to_response()`` to
``error_code`` / ``error_message`` / ``details``. ``details`` never contains
secrets or raw configuration; for writeback-unsupported it enumerates the
blocking reason.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.auth import AuthenticationError, AuthorizationError
from app.core.errors import (
    APIError,
    ApprovalRequiredError,
    DispositionPermissionDenied,
    EventNotFoundError,
    InvalidStateTransitionError,
    InvalidVerdictStatusCombinationError,
    ResourceNotFoundError,
    ShadowTraceError,
    WritebackConflictError,
    WritebackFailedError,
    WritebackPendingError,
    WritebackUnsupportedError,
)

# Re-export domain errors so API modules keep a stable import path.
__all__ = [
    "APIError",
    "ShadowTraceError",
    "EventNotFoundError",
    "InvalidStateTransitionError",
    "InvalidVerdictStatusCombinationError",
    "ApprovalRequiredError",
    "WritebackPendingError",
    "WritebackFailedError",
    "WritebackConflictError",
    "WritebackUnsupportedError",
    "DispositionPermissionDenied",
    "ResourceNotFoundError",
    "register_exception_handlers",
]


def _error_body(error_code: str, error_message: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"error_code": error_code, "error_message": error_message, "details": details}


def register_exception_handlers(app: FastAPI) -> None:
    """Register the unified error handlers on the FastAPI app."""

    @app.exception_handler(ShadowTraceError)
    async def _handle_shadowtrace(_: Request, exc: ShadowTraceError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_response())

    @app.exception_handler(AuthenticationError)
    async def _handle_authn(_: Request, exc: AuthenticationError) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content=_error_body("unauthorized", str(exc) or "authentication required", {}),
        )

    @app.exception_handler(AuthorizationError)
    async def _handle_authz(_: Request, exc: AuthorizationError) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content=_error_body("forbidden", str(exc), {"required_roles": exc.required}),
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=_error_body(
                "validation_error",
                "request validation failed",
                {"errors": exc.errors()},
            ),
        )

    @app.exception_handler(Exception)
    async def _handle_unknown(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=_error_body("internal_error", "internal server error", {}),
        )
