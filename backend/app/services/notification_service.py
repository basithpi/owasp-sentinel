from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.notification import Notification
from app.models.user import User

# In-memory WebSocket connections: user_id -> set of websockets
_ws_connections: Dict[str, Set] = {}


class NotificationService:
    def __init__(self, db: Session):
        self.db = db

    def create_notification(
        self,
        user: User,
        title: str,
        message: str,
        type: str = "info",
        reference_type: Optional[str] = None,
        reference_id: Optional[str] = None,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> Notification:
        notification = Notification(
            user_id=user.id,
            title=title,
            message=message,
            type=type,
            reference_type=reference_type,
            reference_id=reference_id,
            extra_data=extra_data or {},
        )
        self.db.add(notification)
        self.db.commit()
        self.db.refresh(notification)
        return notification

    def list_notifications(
        self,
        user: User,
        offset: int = 0,
        limit: int = 20,
        unread_only: bool = False,
    ) -> tuple[List[Notification], int]:
        query = self.db.query(Notification).filter(Notification.user_id == user.id)
        if unread_only:
            query = query.filter(Notification.is_read.is_(False))
        total = query.count()
        notifications = query.order_by(Notification.created_at.desc()).offset(offset).limit(limit).all()
        return notifications, total

    def mark_read(self, notification_id: uuid.UUID, user: User) -> Notification:
        notif = self.db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.user_id == user.id,
        ).first()
        if not notif:
            raise NotFoundError(f"Notification {notification_id} not found")
        notif.is_read = True
        self.db.commit()
        self.db.refresh(notif)
        return notif

    def mark_all_read(self, user: User) -> int:
        count = (
            self.db.query(Notification)
            .filter(Notification.user_id == user.id, Notification.is_read.is_(False))
            .update({"is_read": True})
        )
        self.db.commit()
        return count

    def delete_notification(self, notification_id: uuid.UUID, user: User) -> None:
        notif = self.db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.user_id == user.id,
        ).first()
        if not notif:
            raise NotFoundError(f"Notification {notification_id} not found")
        self.db.delete(notif)
        self.db.commit()

    @staticmethod
    def register_ws(user_id: str, ws) -> None:
        if user_id not in _ws_connections:
            _ws_connections[user_id] = set()
        _ws_connections[user_id].add(ws)

    @staticmethod
    def unregister_ws(user_id: str, ws) -> None:
        if user_id in _ws_connections:
            _ws_connections[user_id].discard(ws)

    @staticmethod
    async def broadcast_to_user(user_id: str, data: Dict[str, Any]) -> None:
        if user_id not in _ws_connections:
            return
        message = json.dumps(data)
        dead = set()
        for ws in _ws_connections[user_id]:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        for ws in dead:
            _ws_connections[user_id].discard(ws)
