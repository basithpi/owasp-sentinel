from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.database import get_db
from app.dependencies import get_current_active_user, get_pagination_params
from app.models.notification import Notification
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.services.notification_service import NotificationService

router = APIRouter()


# ---------------------------------------------------------------------------
# Inline schema (no separate schema file for Notification yet)
# ---------------------------------------------------------------------------


class NotificationResponse(BaseModel):
    """Serialized notification returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    message: str
    type: str
    is_read: bool
    reference_type: Optional[str] = None
    reference_id: Optional[str] = None
    extra_data: Dict[str, Any] = {}
    created_at: datetime


def _handle_service_errors(e: Exception) -> None:
    """Translate service layer exceptions into HTTP responses."""
    if isinstance(e, NotFoundError):
        raise HTTPException(status_code=404, detail=e.message)
    if isinstance(e, ConflictError):
        raise HTTPException(status_code=409, detail=e.message)
    if isinstance(e, ForbiddenError):
        raise HTTPException(status_code=403, detail=e.message)
    raise HTTPException(status_code=500, detail=str(e))


@router.get("/unread-count")
def get_unread_count(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Dict[str, int]:
    """Return the total number of unread notifications for the current user."""
    count = (
        db.query(Notification)
        .filter(Notification.user_id == current_user.id, Notification.is_read.is_(False))
        .count()
    )
    return {"unread_count": count}


@router.get("", response_model=PaginatedResponse[NotificationResponse])
def list_notifications(
    is_read: Optional[bool] = Query(default=None, description="Filter by read state"),
    notification_type: Optional[str] = Query(default=None, alias="type", description="Filter by type"),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List notifications for the current user with optional filters."""
    query = db.query(Notification).filter(Notification.user_id == current_user.id)
    if is_read is not None:
        query = query.filter(Notification.is_read == is_read)
    if notification_type is not None:
        query = query.filter(Notification.type == notification_type)
    total = query.count()
    notifications = (
        query.order_by(Notification.created_at.desc())
        .offset(pagination.offset)
        .limit(pagination.limit)
        .all()
    )
    return PaginatedResponse.create(items=notifications, total=total, params=pagination)


@router.put("/{notification_id}/read", response_model=NotificationResponse)
def mark_notification_read(
    notification_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Mark a single notification as read."""
    service = NotificationService(db)
    try:
        return service.mark_read(notification_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.post("/mark-all-read")
def mark_all_read(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Mark every unread notification as read for the current user."""
    service = NotificationService(db)
    updated_count = service.mark_all_read(current_user)
    return {"message": f"Marked {updated_count} notification(s) as read", "count": updated_count}


@router.delete("/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_notification(
    notification_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete a notification permanently."""
    service = NotificationService(db)
    try:
        service.delete_notification(notification_id, current_user)
    except Exception as e:
        _handle_service_errors(e)
