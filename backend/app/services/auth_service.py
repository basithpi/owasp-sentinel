from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, UnauthorizedError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_api_key,
    get_password_hash,
    verify_password,
)
from app.config import settings
from app.models.user import User
from app.schemas.user import Token, UserCreate


class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def register_user(self, user_data: UserCreate) -> User:
        existing = self.db.query(User).filter(
            (User.email == user_data.email) | (User.username == user_data.username)
        ).first()
        if existing:
            if existing.email == user_data.email:
                raise ConflictError("Email already registered")
            raise ConflictError("Username already taken")

        user = User(
            email=user_data.email,
            username=user_data.username,
            hashed_password=get_password_hash(user_data.password),
            full_name=user_data.full_name,
            role=user_data.role,
            api_key=generate_api_key(),
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def authenticate_user(self, email: str, password: str) -> User:
        user = self.db.query(User).filter(User.email == email, User.is_active.is_(True)).first()
        if not user or not verify_password(password, user.hashed_password):
            raise UnauthorizedError("Incorrect email or password")
        user.last_login = datetime.now(timezone.utc)
        self.db.commit()
        return user

    def create_tokens(self, user: User) -> Token:
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(data={"sub": str(user.id)})
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    def refresh_access_token(self, refresh_token: str) -> Token:
        from jose import JWTError
        try:
            payload = decode_token(refresh_token)
            if payload.get("type") != "refresh":
                raise UnauthorizedError("Invalid refresh token")
            user_id = payload.get("sub")
            if not user_id:
                raise UnauthorizedError("Invalid token payload")
        except JWTError:
            raise UnauthorizedError("Invalid or expired refresh token")

        user = self.db.query(User).filter(User.id == uuid.UUID(user_id), User.is_active.is_(True)).first()
        if not user:
            raise NotFoundError("User not found")
        return self.create_tokens(user)

    def regenerate_api_key(self, user: User) -> str:
        new_key = generate_api_key()
        user.api_key = new_key
        self.db.commit()
        return new_key
