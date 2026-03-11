from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy.orm import Session

from app.core.security import get_password_hash, verify_password
from app.database import get_db
from app.dependencies import get_current_active_user
from app.models.user import User

router = APIRouter()


# ---------------------------------------------------------------------------
# Inline schemas
# ---------------------------------------------------------------------------


class ProfileResponse(BaseModel):
    """User profile returned by GET /settings/profile."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    avatar_url: Optional[str] = None
    preferences: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None


class ProfileUpdate(BaseModel):
    """Payload for updating a user's profile fields."""

    username: Optional[str] = Field(default=None, min_length=3, max_length=100)
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(default=None, max_length=255)
    avatar_url: Optional[str] = Field(default=None, max_length=500)


class PasswordChange(BaseModel):
    """Payload for changing the current user's password."""

    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class APIKeyEntry(BaseModel):
    """A stored API key for a third-party service."""

    service: str
    masked_key: str
    created_at: Optional[str] = None


class APIKeyCreate(BaseModel):
    """Payload for creating or updating an API key for a named service."""

    service: str = Field(min_length=1, max_length=100)
    api_key: str = Field(min_length=1)


class NotificationPreferences(BaseModel):
    """User-configurable notification preference flags."""

    email_on_scan_complete: bool = True
    email_on_critical_finding: bool = True
    email_on_high_finding: bool = False
    in_app_on_scan_complete: bool = True
    in_app_on_finding: bool = True
    slack_webhook_url: Optional[str] = None
    slack_on_critical: bool = False


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _mask_key(key: str) -> str:
    """Return a version of *key* with all but the last 4 characters masked."""
    if len(key) <= 4:
        return "****"
    return "*" * (len(key) - 4) + key[-4:]


# ---------------------------------------------------------------------------
# Profile endpoints
# ---------------------------------------------------------------------------


@router.get("/profile", response_model=ProfileResponse)
def get_profile(
    current_user: User = Depends(get_current_active_user),
):
    """Return the profile of the currently authenticated user."""
    return current_user


@router.put("/profile", response_model=ProfileResponse)
def update_profile(
    update_data: ProfileUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update the current user's profile (username, email, full_name, avatar_url)."""
    update_dict = update_data.model_dump(exclude_unset=True)

    if "email" in update_dict and update_dict["email"] != current_user.email:
        from app.models.user import User as UserModel

        existing = db.query(UserModel).filter(UserModel.email == update_dict["email"]).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email address is already in use",
            )

    if "username" in update_dict and update_dict["username"] != current_user.username:
        from app.models.user import User as UserModel

        existing = db.query(UserModel).filter(UserModel.username == update_dict["username"]).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username is already taken",
            )

    for key, value in update_dict.items():
        setattr(current_user, key, value)

    db.commit()
    db.refresh(current_user)
    return current_user


# ---------------------------------------------------------------------------
# Password endpoint
# ---------------------------------------------------------------------------


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Change the current user's password after verifying the existing one."""
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    if password_data.new_password == password_data.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password",
        )
    current_user.hashed_password = get_password_hash(password_data.new_password)
    db.commit()


# ---------------------------------------------------------------------------
# API key endpoints  (stored in user.preferences["api_keys"])
# ---------------------------------------------------------------------------


@router.get("/api-keys", response_model=List[APIKeyEntry])
def list_api_keys(
    current_user: User = Depends(get_current_active_user),
) -> List[APIKeyEntry]:
    """List the third-party API keys stored for the current user (masked)."""
    stored: Dict[str, Any] = (current_user.preferences or {}).get("api_keys", {})
    return [
        APIKeyEntry(
            service=service,
            masked_key=_mask_key(entry.get("key", "")),
            created_at=entry.get("created_at"),
        )
        for service, entry in stored.items()
    ]


@router.post("/api-keys", response_model=APIKeyEntry, status_code=status.HTTP_201_CREATED)
def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Store or replace an API key for a named third-party service."""
    prefs: Dict[str, Any] = dict(current_user.preferences or {})
    api_keys: Dict[str, Any] = dict(prefs.get("api_keys", {}))
    api_keys[key_data.service] = {
        "key": key_data.api_key,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    prefs["api_keys"] = api_keys
    current_user.preferences = prefs
    db.commit()
    db.refresh(current_user)
    return APIKeyEntry(
        service=key_data.service,
        masked_key=_mask_key(key_data.api_key),
        created_at=api_keys[key_data.service]["created_at"],
    )


@router.delete("/api-keys/{service}", status_code=status.HTTP_204_NO_CONTENT)
def delete_api_key(
    service: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Remove a stored API key for the given service name."""
    prefs: Dict[str, Any] = dict(current_user.preferences or {})
    api_keys: Dict[str, Any] = dict(prefs.get("api_keys", {}))
    if service not in api_keys:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No API key found for service '{service}'",
        )
    del api_keys[service]
    prefs["api_keys"] = api_keys
    current_user.preferences = prefs
    db.commit()


# ---------------------------------------------------------------------------
# Notification preference endpoints  (stored in user.preferences["notifications"])
# ---------------------------------------------------------------------------


@router.get("/notifications", response_model=NotificationPreferences)
def get_notification_preferences(
    current_user: User = Depends(get_current_active_user),
) -> NotificationPreferences:
    """Return the current user's notification preferences."""
    stored: Dict[str, Any] = (current_user.preferences or {}).get("notifications", {})
    return NotificationPreferences(**stored)


@router.put("/notifications", response_model=NotificationPreferences)
def update_notification_preferences(
    prefs_data: NotificationPreferences,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> NotificationPreferences:
    """Update the current user's notification preferences."""
    full_prefs: Dict[str, Any] = dict(current_user.preferences or {})
    full_prefs["notifications"] = prefs_data.model_dump()
    current_user.preferences = full_prefs
    db.commit()
    db.refresh(current_user)
    return prefs_data
