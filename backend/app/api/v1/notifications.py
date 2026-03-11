import uuid
from typing import Optional

from fastapi import APIRouter, Query, status
from sqlalchemy import func, select

from ...core.dependencies import CurrentUser, DB, Pagination
from ...core.exceptions import NotFoundError
from ...models.notification import Notification
from ...schemas import PaginatedResponse
from ...schemas.notification import NotificationResponse

router = APIRouter(prefix="/notifications", tags=["Notifications"])


async def _get_notification_or_404(
    notification_id: uuid.UUID, db: DB, user_id: uuid.UUID
) -> Notification:
    result = await db.execute(
        select(Notification).where(
            Notification.id == notification_id,
            Notification.user_id == user_id,
        )
    )
    notification = result.scalar_one_or_none()
    if notification is None:
        raise NotFoundError(f"Notification {notification_id} not found")
    return notification


# ---------------------------------------------------------------------------
# /read-all must be declared before /{id}/read to avoid routing conflict
# ---------------------------------------------------------------------------


@router.put("/read-all", status_code=status.HTTP_204_NO_CONTENT)
async def mark_all_notifications_read(
    db: DB,
    current_user: CurrentUser,
) -> None:
    """Mark all unread notifications as read for the current user."""
    result = await db.execute(
        select(Notification).where(
            Notification.user_id == current_user.id,
            Notification.is_read.is_(False),
        )
    )
    notifications = result.scalars().all()
    for notification in notifications:
        notification.is_read = True
    await db.flush()


@router.get("", response_model=PaginatedResponse[NotificationResponse])
async def list_notifications(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
    unread_only: Optional[bool] = Query(default=None),
) -> PaginatedResponse[NotificationResponse]:
    """List notifications for the current user, optionally filtered to unread."""
    query = select(Notification).where(Notification.user_id == current_user.id)

    if unread_only:
        query = query.where(Notification.is_read.is_(False))

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Notification.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    return PaginatedResponse(
        items=list(result.scalars().all()),
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.put("/{notification_id}/read", response_model=NotificationResponse)
async def mark_notification_read(
    notification_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> Notification:
    """Mark a specific notification as read."""
    notification = await _get_notification_or_404(
        notification_id, db, current_user.id
    )
    notification.is_read = True
    await db.flush()
    await db.refresh(notification)
    return notification
