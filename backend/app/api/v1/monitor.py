from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.database import get_db
from app.dependencies import get_current_active_user, get_pagination_params
from app.models.monitor import Monitor
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.services.monitor_service import MonitorService

router = APIRouter()


# ---------------------------------------------------------------------------
# Inline schemas (no separate schema file for Monitor yet)
# ---------------------------------------------------------------------------


class MonitorCreate(BaseModel):
    """Payload for creating a new monitor."""

    target_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    monitor_type: Optional[str] = Field(default="http", max_length=50)
    check_interval: int = Field(default=3600, ge=60, description="Interval in seconds (min 60)")
    alert_config: Dict[str, Any] = Field(default_factory=dict)


class MonitorUpdate(BaseModel):
    """Payload for updating a monitor."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    check_interval: Optional[int] = Field(default=None, ge=60)
    alert_config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class MonitorResponse(BaseModel):
    """Serialized monitor returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    target_id: uuid.UUID
    name: str
    description: Optional[str] = None
    check_interval: int
    is_active: bool
    status: str
    last_check_at: Optional[datetime] = None
    last_result: Dict[str, Any] = {}
    alert_config: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime


def _handle_service_errors(e: Exception) -> None:
    """Translate service layer exceptions into HTTP responses."""
    if isinstance(e, NotFoundError):
        raise HTTPException(status_code=404, detail=e.message)
    if isinstance(e, ConflictError):
        raise HTTPException(status_code=409, detail=e.message)
    if isinstance(e, ForbiddenError):
        raise HTTPException(status_code=403, detail=e.message)
    raise HTTPException(status_code=500, detail=str(e))


def _get_monitor_or_404(monitor_id: uuid.UUID, current_user: User, db: Session) -> Monitor:
    """Fetch a monitor and enforce ownership, raising HTTP 404/403 as appropriate."""
    service = MonitorService(db)
    try:
        return service.get_monitor(monitor_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.get("", response_model=PaginatedResponse[MonitorResponse])
def list_monitors(
    target_id: Optional[uuid.UUID] = Query(default=None, description="Filter by target ID"),
    is_active: Optional[bool] = Query(default=None, description="Filter by active state"),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List monitors for the current user with optional filters."""
    query = db.query(Monitor)
    if current_user.role != "admin":
        query = query.filter(Monitor.user_id == current_user.id)
    if target_id is not None:
        query = query.filter(Monitor.target_id == target_id)
    if is_active is not None:
        query = query.filter(Monitor.is_active == is_active)
    total = query.count()
    monitors = query.order_by(Monitor.created_at.desc()).offset(pagination.offset).limit(pagination.limit).all()
    return PaginatedResponse.create(items=monitors, total=total, params=pagination)


@router.post("", response_model=MonitorResponse, status_code=status.HTTP_201_CREATED)
def create_monitor(
    monitor_data: MonitorCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create a new monitor for a target."""
    service = MonitorService(db)
    try:
        return service.create_monitor(
            user=current_user,
            target_id=monitor_data.target_id,
            name=monitor_data.name,
            check_interval=monitor_data.check_interval,
            alert_config=monitor_data.alert_config,
            description=monitor_data.description,
        )
    except Exception as e:
        _handle_service_errors(e)


@router.get("/{monitor_id}", response_model=MonitorResponse)
def get_monitor(
    monitor_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Retrieve a single monitor by ID."""
    return _get_monitor_or_404(monitor_id, current_user, db)


@router.put("/{monitor_id}", response_model=MonitorResponse)
def update_monitor(
    monitor_id: uuid.UUID,
    update_data: MonitorUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update a monitor's configuration."""
    monitor = _get_monitor_or_404(monitor_id, current_user, db)
    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(monitor, key, value)
    db.commit()
    db.refresh(monitor)
    return monitor


@router.delete("/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_monitor(
    monitor_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete a monitor permanently."""
    service = MonitorService(db)
    try:
        service.delete_monitor(monitor_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.get("/{monitor_id}/alerts")
def get_monitor_alerts(
    monitor_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return any alerts or detected changes stored in the monitor's last result."""
    monitor = _get_monitor_or_404(monitor_id, current_user, db)
    last_result: Dict[str, Any] = monitor.last_result or {}
    alerts: List[Dict[str, Any]] = last_result.get("alerts", [])
    changes: List[Dict[str, Any]] = last_result.get("changes", [])
    return [
        {
            "monitor_id": str(monitor_id),
            "type": item.get("type", "change"),
            "message": item.get("message", ""),
            "severity": item.get("severity", "info"),
            "detected_at": item.get("detected_at") or (
                monitor.last_check_at.isoformat() if monitor.last_check_at else None
            ),
            "data": item.get("data", {}),
        }
        for item in (alerts + changes)
    ]


@router.post("/{monitor_id}/toggle", response_model=MonitorResponse)
def toggle_monitor(
    monitor_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Enable or disable a monitor by flipping its is_active flag."""
    monitor = _get_monitor_or_404(monitor_id, current_user, db)
    monitor.is_active = not monitor.is_active
    monitor.status = "active" if monitor.is_active else "paused"
    db.commit()
    db.refresh(monitor)
    return monitor
