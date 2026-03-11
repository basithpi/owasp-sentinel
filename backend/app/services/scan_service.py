from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanUpdate


class ScanService:
    def __init__(self, db: Session):
        self.db = db

    def create_scan(self, scan_data: ScanCreate, user: User) -> Scan:
        target = self.db.query(Target).filter(
            Target.id == scan_data.target_id,
            Target.user_id == user.id,
        ).first()
        if not target:
            raise NotFoundError(f"Target {scan_data.target_id} not found")

        scan = Scan(
            user_id=user.id,
            target_id=scan_data.target_id,
            name=scan_data.name,
            description=scan_data.description,
            scan_type=scan_data.scan_type,
            config=scan_data.config.model_dump(),
            status="pending",
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def get_scan(self, scan_id: uuid.UUID, user: User) -> Scan:
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise NotFoundError(f"Scan {scan_id} not found")
        if scan.user_id != user.id and user.role not in ("admin", "analyst"):
            raise ForbiddenError("Access denied")
        return scan

    def list_scans(
        self,
        user: User,
        offset: int = 0,
        limit: int = 20,
        status: Optional[str] = None,
        target_id: Optional[uuid.UUID] = None,
    ) -> tuple[List[Scan], int]:
        query = self.db.query(Scan)
        if user.role != "admin":
            query = query.filter(Scan.user_id == user.id)
        if status:
            query = query.filter(Scan.status == status)
        if target_id:
            query = query.filter(Scan.target_id == target_id)
        total = query.count()
        scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
        return scans, total

    def update_scan(self, scan_id: uuid.UUID, scan_data: ScanUpdate, user: User) -> Scan:
        scan = self.get_scan(scan_id, user)
        if scan.status in ("running",):
            raise ConflictError("Cannot update a running scan")
        update_data = scan_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if key == "config" and value:
                setattr(scan, key, value.model_dump() if hasattr(value, "model_dump") else value)
            else:
                setattr(scan, key, value)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def delete_scan(self, scan_id: uuid.UUID, user: User) -> None:
        scan = self.get_scan(scan_id, user)
        if scan.status == "running":
            raise ConflictError("Cannot delete a running scan")
        self.db.delete(scan)
        self.db.commit()

    def start_scan(self, scan_id: uuid.UUID, user: User) -> Scan:
        scan = self.get_scan(scan_id, user)
        if scan.status not in ("pending", "paused", "failed"):
            raise ConflictError(f"Cannot start scan in status: {scan.status}")
        from app.tasks.scan_tasks import run_scan
        task = run_scan.delay(str(scan_id))
        scan.celery_task_id = task.id
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def pause_scan(self, scan_id: uuid.UUID, user: User) -> Scan:
        scan = self.get_scan(scan_id, user)
        if scan.status != "running":
            raise ConflictError("Only running scans can be paused")
        scan.status = "paused"
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def resume_scan(self, scan_id: uuid.UUID, user: User) -> Scan:
        scan = self.get_scan(scan_id, user)
        if scan.status != "paused":
            raise ConflictError("Only paused scans can be resumed")
        return self.start_scan(scan_id, user)

    def cancel_scan(self, scan_id: uuid.UUID, user: User) -> Scan:
        scan = self.get_scan(scan_id, user)
        if scan.status in ("completed", "cancelled"):
            raise ConflictError(f"Scan is already {scan.status}")
        if scan.celery_task_id:
            from app.tasks.celery_app import celery_app
            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        scan.status = "cancelled"
        scan.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def update_progress(self, scan_id: uuid.UUID, progress: int, status: Optional[str] = None) -> None:
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.progress = min(100, max(0, progress))
            if status:
                scan.status = status
            if progress >= 100:
                scan.completed_at = datetime.now(timezone.utc)
            self.db.commit()
