from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.database import get_db
from app.dependencies import get_current_active_user, get_pagination_params
from app.models.tool import Tool
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.schemas.tool import ToolResponse, ToolUpdate
from app.services.tool_service import ToolService

router = APIRouter()


class ToolRunRequest(BaseModel):
    """Request body for running a tool against a target."""

    target_id: uuid.UUID
    config_overrides: Dict[str, Any] = {}


class ToolRunResponse(BaseModel):
    """Response after triggering a tool run."""

    tool_id: uuid.UUID
    tool_name: str
    target_id: uuid.UUID
    status: str
    message: str
    health: Dict[str, Any] = {}


def _handle_service_errors(e: Exception) -> None:
    """Translate service layer exceptions into HTTP responses."""
    if isinstance(e, NotFoundError):
        raise HTTPException(status_code=404, detail=e.message)
    if isinstance(e, ConflictError):
        raise HTTPException(status_code=409, detail=e.message)
    if isinstance(e, ForbiddenError):
        raise HTTPException(status_code=403, detail=e.message)
    raise HTTPException(status_code=500, detail=str(e))


@router.get("", response_model=PaginatedResponse[ToolResponse])
def list_tools(
    category: Optional[str] = Query(default=None, description="Filter by tool category"),
    is_enabled: Optional[bool] = Query(default=None, description="Filter by enabled state"),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List all security tools with optional category and enabled-state filters."""
    query = db.query(Tool)
    if category is not None:
        query = query.filter(Tool.category == category)
    if is_enabled is not None:
        query = query.filter(Tool.is_enabled == is_enabled)
    total = query.count()
    tools = query.order_by(Tool.name).offset(pagination.offset).limit(pagination.limit).all()
    return PaginatedResponse.create(items=tools, total=total, params=pagination)


@router.get("/{tool_id}", response_model=ToolResponse)
def get_tool(
    tool_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Retrieve a single tool by ID."""
    service = ToolService(db)
    try:
        return service.get_tool(tool_id)
    except Exception as e:
        _handle_service_errors(e)


@router.post("/{tool_id}/run", response_model=ToolRunResponse)
def run_tool(
    tool_id: uuid.UUID,
    run_request: ToolRunRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Run a specific security tool against a target.

    Validates the tool is enabled and available, performs a health check,
    then queues the tool execution. Use GET /scans to track execution progress.
    """
    service = ToolService(db)
    try:
        tool = service.get_tool(tool_id)
    except Exception as e:
        _handle_service_errors(e)

    if not tool.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Tool '{tool.name}' is disabled and cannot be run",
        )

    from app.models.target import Target

    target = db.query(Target).filter(Target.id == run_request.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if target.user_id != current_user.id and current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Access denied to target")

    health = service.check_tool_health(tool.name)
    service.update_health_status(tool_id, health)

    run_status = "queued" if health.get("is_healthy") else "unavailable"
    message = (
        f"Tool '{tool.name}' queued against target '{target.name}'"
        if health.get("is_healthy")
        else f"Tool '{tool.name}' is not available on this host: {health.get('message')}"
    )

    return ToolRunResponse(
        tool_id=tool_id,
        tool_name=tool.name,
        target_id=run_request.target_id,
        status=run_status,
        message=message,
        health=health,
    )


@router.get("/{tool_id}/results")
def get_tool_results(
    tool_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get the latest health-check results and availability status for a tool."""
    service = ToolService(db)
    try:
        tool = service.get_tool(tool_id)
    except Exception as e:
        _handle_service_errors(e)

    return {
        "tool_id": str(tool.id),
        "tool_name": tool.name,
        "is_available": tool.is_available,
        "is_enabled": tool.is_enabled,
        "health_status": tool.health_status,
        "last_health_check": tool.last_health_check.isoformat() if tool.last_health_check else None,
        "category": tool.category,
        "version": tool.version,
    }


@router.put("/{tool_id}/toggle", response_model=ToolResponse)
def toggle_tool(
    tool_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Toggle the enabled/disabled state of a tool. Requires admin or analyst role."""
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or analyst role required to toggle tools",
        )
    service = ToolService(db)
    try:
        tool = service.get_tool(tool_id)
        return service.update_tool(tool_id, ToolUpdate(is_enabled=not tool.is_enabled))
    except Exception as e:
        _handle_service_errors(e)
