"""Domain API exceptions and the unified error handler (ISSUE-004).

Every handled error serializes to ``ErrorResponse`` (``error_code`` /
``error_message`` / ``details``). ``details`` never contains secrets or raw
configuration; for writeback-unsupported it enumerates the blocking reason.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.auth import AuthenticationError, AuthorizationError
from app.models.workflow import (
    InvalidStateTransitionError,
    InvalidVerdictStatusCombinationError,
)

# Re-export domain state-machine errors so API modules keep a stable import path.
__all__ = [
    "APIError",
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


class APIError(Exception):
    """Base class for handled API errors."""

    status_code: int = 400
    error_code: str = "error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        self.error_message = message
        self.details = details or {}
        super().__init__(message)


class EventNotFoundError(APIError):
    status_code = 404
    error_code = "event_not_found"


class ApprovalRequiredError(APIError):
    status_code = 409
    error_code = "approval_required"


class WritebackPendingError(APIError):
    status_code = 409
    error_code = "writeback_pending"


class WritebackFailedError(APIError):
    status_code = 409
    error_code = "writeback_failed"


class WritebackConflictError(APIError):
    status_code = 409
    error_code = "writeback_conflict"


class WritebackUnsupportedError(APIError):
    status_code = 422
    error_code = "writeback_unsupported"


class DispositionPermissionDenied(APIError):
    status_code = 403
    error_code = "disposition_permission_denied"


class ResourceNotFoundError(APIError):
    """Generic 404 for non-event resources (jobs, dispositions, etc.)."""

    status_code = 404
    error_code = "not_found"


def _error_body(error_code: str, error_message: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"error_code": error_code, "error_message": error_message, "details": details}


def register_exception_handlers(app: FastAPI) -> None:
    """Register the unified error handlers on the FastAPI app."""

    @app.exception_handler(APIError)
    async def _handle_api_error(_: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.error_code, exc.error_message, exc.details),
        )

    @app.exception_handler(InvalidStateTransitionError)
    async def _handle_invalid_transition(
        _: Request, exc: InvalidStateTransitionError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.error_code, exc.error_message, exc.details),
        )

    @app.exception_handler(InvalidVerdictStatusCombinationError)
    async def _handle_invalid_verdict(
        _: Request, exc: InvalidVerdictStatusCombinationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.error_code, exc.error_message, exc.details),
        )

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
            content=_error_body("validation_error", "request validation failed",
                                {"errors": exc.errors()}),
        )

    @app.exception_handler(Exception)
    async def _handle_unknown(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=_error_body("internal_error", "internal server error", {}),
        )
