import uuid

from fastapi import APIRouter, status
from sqlalchemy import func, select

from ...core.dependencies import CurrentUser, DB, Pagination
from ...core.exceptions import NotFoundError
from ...models.monitor import Monitor
from ...schemas import PaginatedResponse
from ...schemas.monitor import MonitorCreate, MonitorResponse, MonitorUpdate

router = APIRouter(prefix="/monitors", tags=["Monitors"])


async def _get_monitor_or_404(monitor_id: uuid.UUID, db: DB) -> Monitor:
    result = await db.execute(select(Monitor).where(Monitor.id == monitor_id))
    monitor = result.scalar_one_or_none()
    if monitor is None:
        raise NotFoundError(f"Monitor {monitor_id} not found")
    return monitor


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=PaginatedResponse[MonitorResponse])
async def list_monitors(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
) -> PaginatedResponse[MonitorResponse]:
    """List all monitors with pagination."""
    query = select(Monitor)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Monitor.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    return PaginatedResponse(
        items=list(result.scalars().all()),
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post("", response_model=MonitorResponse, status_code=status.HTTP_201_CREATED)
async def create_monitor(
    payload: MonitorCreate,
    db: DB,
    current_user: CurrentUser,
) -> Monitor:
    """Create a new monitor."""
    monitor = Monitor(**payload.model_dump(), created_by=current_user.id)
    db.add(monitor)
    await db.flush()
    await db.refresh(monitor)
    return monitor


@router.get("/{monitor_id}", response_model=MonitorResponse)
async def get_monitor(
    monitor_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> Monitor:
    """Retrieve details for a single monitor."""
    return await _get_monitor_or_404(monitor_id, db)


@router.put("/{monitor_id}", response_model=MonitorResponse)
async def update_monitor(
    monitor_id: uuid.UUID,
    payload: MonitorUpdate,
    db: DB,
    current_user: CurrentUser,
) -> Monitor:
    """Update a monitor's configuration."""
    monitor = await _get_monitor_or_404(monitor_id, db)

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(monitor, field, value)

    await db.flush()
    await db.refresh(monitor)
    return monitor


@router.delete("/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitor(
    monitor_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> None:
    """Delete a monitor."""
    monitor = await _get_monitor_or_404(monitor_id, db)
    await db.delete(monitor)
    await db.flush()


@router.post("/{monitor_id}/toggle", response_model=MonitorResponse)
async def toggle_monitor(
    monitor_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> Monitor:
    """Enable or disable a monitor."""
    monitor = await _get_monitor_or_404(monitor_id, db)
    monitor.is_active = not monitor.is_active
    await db.flush()
    await db.refresh(monitor)
    return monitor
