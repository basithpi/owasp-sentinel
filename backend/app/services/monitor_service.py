from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenError, NotFoundError
from app.models.monitor import Monitor
from app.models.target import Target
from app.models.user import User


class MonitorService:
    def __init__(self, db: Session):
        self.db = db

    def create_monitor(
        self,
        user: User,
        target_id: uuid.UUID,
        name: str,
        check_interval: int = 3600,
        alert_config: Optional[dict] = None,
        description: Optional[str] = None,
    ) -> Monitor:
        target = self.db.query(Target).filter(
            Target.id == target_id, Target.user_id == user.id
        ).first()
        if not target:
            raise NotFoundError(f"Target {target_id} not found")

        monitor = Monitor(
            user_id=user.id,
            target_id=target_id,
            name=name,
            description=description,
            check_interval=check_interval,
            alert_config=alert_config or {},
        )
        self.db.add(monitor)
        self.db.commit()
        self.db.refresh(monitor)
        return monitor

    def list_monitors(self, user: User, offset: int = 0, limit: int = 20) -> tuple[List[Monitor], int]:
        query = self.db.query(Monitor)
        if user.role != "admin":
            query = query.filter(Monitor.user_id == user.id)
        total = query.count()
        monitors = query.order_by(Monitor.created_at.desc()).offset(offset).limit(limit).all()
        return monitors, total

    def get_monitor(self, monitor_id: uuid.UUID, user: User) -> Monitor:
        monitor = self.db.query(Monitor).filter(Monitor.id == monitor_id).first()
        if not monitor:
            raise NotFoundError(f"Monitor {monitor_id} not found")
        if monitor.user_id != user.id and user.role != "admin":
            raise ForbiddenError("Access denied")
        return monitor

    def update_monitor_result(self, monitor_id: uuid.UUID, result: dict, status: str = "active") -> None:
        monitor = self.db.query(Monitor).filter(Monitor.id == monitor_id).first()
        if monitor:
            monitor.last_check_at = datetime.now(timezone.utc)
            monitor.last_result = result
            monitor.status = status
            self.db.commit()

    def delete_monitor(self, monitor_id: uuid.UUID, user: User) -> None:
        monitor = self.get_monitor(monitor_id, user)
        self.db.delete(monitor)
        self.db.commit()
