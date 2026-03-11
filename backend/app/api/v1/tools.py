import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, status
from sqlalchemy import func, select

from ...core.dependencies import AdminUser, CurrentUser, DB, Pagination
from ...core.exceptions import NotFoundError
from ...models.tool import Tool
from ...schemas import PaginatedResponse
from ...schemas.tool import ToolResponse, ToolUpdate

router = APIRouter(prefix="/tools", tags=["Tools"])


async def _get_tool_or_404(tool_id: uuid.UUID, db: DB) -> Tool:
    result = await db.execute(select(Tool).where(Tool.id == tool_id))
    tool = result.scalar_one_or_none()
    if tool is None:
        raise NotFoundError(f"Tool {tool_id} not found")
    return tool


# ---------------------------------------------------------------------------
# /health must be declared before /{id} to avoid routing conflict
# ---------------------------------------------------------------------------


@router.get("/health")
async def tools_health(
    db: DB,
    current_user: CurrentUser,
) -> Dict[str, Any]:
    """Return an aggregate health summary for all registered tools."""
    result = await db.execute(select(Tool))
    tools = result.scalars().all()

    summary: Dict[str, int] = {
        "healthy": 0,
        "degraded": 0,
        "unhealthy": 0,
        "unknown": 0,
    }
    tool_statuses: List[Dict[str, Any]] = []

    for tool in tools:
        status_key = tool.health_status if tool.health_status in summary else "unknown"
        summary[status_key] += 1
        tool_statuses.append(
            {
                "id": str(tool.id),
                "name": tool.name,
                "health_status": tool.health_status,
                "is_enabled": tool.is_enabled,
                "is_installed": tool.is_installed,
                "last_health_check": (
                    tool.last_health_check.isoformat()
                    if tool.last_health_check
                    else None
                ),
            }
        )

    total = len(tools)
    overall = (
        "healthy"
        if summary["unhealthy"] == 0 and summary["degraded"] == 0
        else ("degraded" if summary["unhealthy"] == 0 else "unhealthy")
    )

    return {
        "overall_status": overall,
        "total_tools": total,
        "summary": summary,
        "tools": tool_statuses,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# CRUD endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=PaginatedResponse[ToolResponse])
async def list_tools(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
) -> PaginatedResponse[ToolResponse]:
    """List all registered security tools."""
    query = select(Tool)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Tool.name.asc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    return PaginatedResponse(
        items=list(result.scalars().all()),
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.get("/{tool_id}", response_model=ToolResponse)
async def get_tool(
    tool_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> Tool:
    """Retrieve details for a single tool."""
    return await _get_tool_or_404(tool_id, db)


@router.post("/{tool_id}/toggle", response_model=ToolResponse)
async def toggle_tool(
    tool_id: uuid.UUID,
    db: DB,
    current_user: AdminUser,
) -> Tool:
    """Enable or disable a tool (admin only)."""
    tool = await _get_tool_or_404(tool_id, db)
    tool.is_enabled = not tool.is_enabled
    await db.flush()
    await db.refresh(tool)
    return tool


@router.put("/{tool_id}/config", response_model=ToolResponse)
async def update_tool_config(
    tool_id: uuid.UUID,
    payload: ToolUpdate,
    db: DB,
    current_user: AdminUser,
) -> Tool:
    """Update tool configuration and metadata (admin only)."""
    tool = await _get_tool_or_404(tool_id, db)

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(tool, field, value)

    await db.flush()
    await db.refresh(tool)
    return tool
