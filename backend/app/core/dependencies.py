from typing import Annotated, Optional

from fastapi import Depends, Header, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.user import User
from ..schemas.auth import TokenData
from .exceptions import ForbiddenError, UnauthorizedError
from .security import verify_token

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[
        Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Extract and validate the JWT bearer token, returning the matching User."""
    if credentials is None:
        raise UnauthorizedError("Missing authentication token")

    payload = verify_token(credentials.credentials, token_type="access")
    if payload is None:
        raise UnauthorizedError("Invalid or expired token")

    user_id: Optional[str] = payload.get("sub")
    if user_id is None:
        raise UnauthorizedError("Token missing subject claim")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise UnauthorizedError("User not found")

    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Ensure the authenticated user is active."""
    if not current_user.is_active:
        raise ForbiddenError("User account is disabled")
    return current_user


async def require_admin(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """Ensure the authenticated user has the admin role."""
    if current_user.role != "admin" and not current_user.is_superuser:
        raise ForbiddenError("Administrator privileges required")
    return current_user


class PaginationParams:
    """Common pagination query parameters."""

    def __init__(
        self,
        skip: int = Query(default=0, ge=0, description="Number of records to skip"),
        limit: int = Query(
            default=20, ge=1, le=100, description="Maximum records to return"
        ),
    ) -> None:
        self.skip = skip
        self.limit = limit


# Type aliases for cleaner endpoint signatures
CurrentUser = Annotated[User, Depends(get_current_active_user)]
AdminUser = Annotated[User, Depends(require_admin)]
Pagination = Annotated[PaginationParams, Depends(PaginationParams)]
DB = Annotated[AsyncSession, Depends(get_db)]
