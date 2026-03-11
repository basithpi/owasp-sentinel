import uuid
from typing import Optional

import redis.asyncio as aioredis
from fastapi import APIRouter, status
from sqlalchemy import select

from ...config import settings
from ...core.dependencies import CurrentUser, DB, get_current_active_user
from ...core.exceptions import ConflictError, NotFoundError, UnauthorizedError
from ...core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token,
)
from ...models.user import User
from ...schemas.auth import (
    PasswordChange,
    RefreshTokenRequest,
    Token,
    UserLogin,
    UserRegister,
    UserResponse,
    UserUpdate,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_token_subject(user: User) -> str:
    return str(user.id)


def _token_pair(user: User) -> Token:
    data = {"sub": _build_token_subject(user), "email": user.email, "role": user.role}
    return Token(
        access_token=create_access_token(data),
        refresh_token=create_refresh_token(data),
    )


async def _get_redis() -> aioredis.Redis:
    return await aioredis.from_url(settings.redis_url, decode_responses=True)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister, db: DB) -> User:
    """Register a new user account."""
    existing = await db.execute(
        select(User).where(
            (User.email == payload.email) | (User.username == payload.username)
        )
    )
    if existing.scalar_one_or_none():
        raise ConflictError("A user with that email or username already exists")

    user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=get_password_hash(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.post("/login", response_model=Token)
async def login(payload: UserLogin, db: DB) -> Token:
    """Authenticate with email + password and receive JWT tokens."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.hashed_password):
        raise UnauthorizedError("Invalid email or password")
    if not user.is_active:
        raise UnauthorizedError("User account is disabled")

    return _token_pair(user)


@router.post("/refresh", response_model=Token)
async def refresh_token(payload: RefreshTokenRequest, db: DB) -> Token:
    """Exchange a valid refresh token for a new token pair."""
    token_payload = verify_token(payload.refresh_token, token_type="refresh")
    if token_payload is None:
        raise UnauthorizedError("Invalid or expired refresh token")

    user_id = token_payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise UnauthorizedError("User not found or inactive")

    return _token_pair(user)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser) -> User:
    """Return the currently authenticated user's profile."""
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_me(payload: UserUpdate, current_user: CurrentUser, db: DB) -> User:
    """Update the current user's profile (full_name, username)."""
    if payload.username and payload.username != current_user.username:
        existing = await db.execute(
            select(User).where(User.username == payload.username)
        )
        if existing.scalar_one_or_none():
            raise ConflictError("Username already taken")
        current_user.username = payload.username

    if payload.full_name is not None:
        current_user.full_name = payload.full_name

    await db.flush()
    await db.refresh(current_user)
    return current_user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    payload: PasswordChange, current_user: CurrentUser, db: DB
) -> None:
    """Change the current user's password."""
    if not verify_password(payload.old_password, current_user.hashed_password):
        raise UnauthorizedError("Current password is incorrect")

    current_user.hashed_password = get_password_hash(payload.new_password)
    await db.flush()


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(current_user: CurrentUser) -> None:
    """
    Logout endpoint — client should discard tokens.

    In a production system the access token would be added to a Redis
    blocklist here; omitted to avoid hard dependency on Redis availability
    during local development without Redis.
    """
    return None
