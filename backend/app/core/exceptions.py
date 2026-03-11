from __future__ import annotations

from typing import Any, Optional


class SentinelBaseError(Exception):
    def __init__(self, message: str, detail: Optional[Any] = None):
        self.message = message
        self.detail = detail
        super().__init__(message)


class NotFoundError(SentinelBaseError):
    pass


class UnauthorizedError(SentinelBaseError):
    pass


class ForbiddenError(SentinelBaseError):
    pass


class ValidationError(SentinelBaseError):
    pass


class ConflictError(SentinelBaseError):
    pass


class ServiceUnavailableError(SentinelBaseError):
    pass


class RateLimitError(SentinelBaseError):
    pass
