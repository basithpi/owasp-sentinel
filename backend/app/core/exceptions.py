from typing import Any, Optional

from fastapi import Request
from fastapi.responses import JSONResponse


class SentinelException(Exception):
    """Base exception for all OWASP Sentinel errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        detail: Optional[Any] = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.detail = detail
        super().__init__(message)


class NotFoundError(SentinelException):
    """404 – Resource not found."""

    def __init__(self, message: str = "Resource not found", detail: Optional[Any] = None) -> None:
        super().__init__(message, status_code=404, detail=detail)


class UnauthorizedError(SentinelException):
    """401 – Authentication required or token invalid."""

    def __init__(
        self, message: str = "Authentication required", detail: Optional[Any] = None
    ) -> None:
        super().__init__(message, status_code=401, detail=detail)


class ForbiddenError(SentinelException):
    """403 – Authenticated but insufficient permissions."""

    def __init__(
        self, message: str = "Insufficient permissions", detail: Optional[Any] = None
    ) -> None:
        super().__init__(message, status_code=403, detail=detail)


class ValidationError(SentinelException):
    """422 – Input validation failed."""

    def __init__(
        self, message: str = "Validation error", detail: Optional[Any] = None
    ) -> None:
        super().__init__(message, status_code=422, detail=detail)


class ConflictError(SentinelException):
    """409 – Conflict with existing resource."""

    def __init__(
        self, message: str = "Resource conflict", detail: Optional[Any] = None
    ) -> None:
        super().__init__(message, status_code=409, detail=detail)


class ServiceUnavailableError(SentinelException):
    """503 – Downstream service unavailable."""

    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        detail: Optional[Any] = None,
    ) -> None:
        super().__init__(message, status_code=503, detail=detail)


# ---------------------------------------------------------------------------
# FastAPI exception handlers
# ---------------------------------------------------------------------------

async def sentinel_exception_handler(
    request: Request, exc: SentinelException
) -> JSONResponse:
    """Convert SentinelException subclasses into structured JSON responses."""
    body: dict[str, Any] = {"error": exc.message, "status_code": exc.status_code}
    if exc.detail is not None:
        body["detail"] = exc.detail
    return JSONResponse(status_code=exc.status_code, content=body)


def register_exception_handlers(app: Any) -> None:
    """Register all custom exception handlers on a FastAPI application."""
    app.add_exception_handler(SentinelException, sentinel_exception_handler)
    # Register every concrete subclass as well so isinstance checks work
    for subclass in SentinelException.__subclasses__():
        app.add_exception_handler(subclass, sentinel_exception_handler)
