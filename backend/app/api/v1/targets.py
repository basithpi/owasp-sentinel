import uuid
from typing import List, Optional

from fastapi import APIRouter, Query, status
from sqlalchemy import func, select

from ...core.dependencies import CurrentUser, DB, Pagination
from ...core.exceptions import ForbiddenError, NotFoundError
from ...models.scan import Scan
from ...models.target import Target
from ...schemas import PaginatedResponse
from ...schemas.scan import ScanResponse
from ...schemas.target import TargetCreate, TargetResponse, TargetUpdate

router = APIRouter(prefix="/targets", tags=["Targets"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_target_or_404(target_id: uuid.UUID, db: DB) -> Target:
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise NotFoundError(f"Target {target_id} not found")
    return target


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=PaginatedResponse[TargetResponse])
async def list_targets(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
    status: Optional[str] = Query(default=None),
    target_type: Optional[str] = Query(default=None),
    tags: Optional[List[str]] = Query(default=None),
    search: Optional[str] = Query(default=None),
) -> PaginatedResponse[TargetResponse]:
    """List targets with optional filtering and pagination."""
    query = select(Target)

    if status:
        query = query.where(Target.status == status)
    if target_type:
        query = query.where(Target.target_type == target_type)
    if search:
        query = query.where(Target.name.ilike(f"%{search}%"))
    if tags:
        for tag in tags:
            query = query.where(Target.tags.contains([tag]))

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Target.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    items = list(result.scalars().all())

    return PaginatedResponse(
        items=items, total=total, skip=pagination.skip, limit=pagination.limit
    )


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate, db: DB, current_user: CurrentUser
) -> Target:
    """Create a new scan target."""
    target = Target(**payload.model_dump(), created_by=current_user.id)
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: uuid.UUID, db: DB, current_user: CurrentUser) -> Target:
    """Retrieve a single target by ID."""
    return await _get_target_or_404(target_id, db)


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: uuid.UUID,
    payload: TargetUpdate,
    db: DB,
    current_user: CurrentUser,
) -> Target:
    """Update a target's fields."""
    target = await _get_target_or_404(target_id, db)

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(target, field, value)

    await db.flush()
    await db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> None:
    """Delete a target and all its associated data."""
    target = await _get_target_or_404(target_id, db)
    await db.delete(target)
    await db.flush()


@router.get("/{target_id}/scans", response_model=PaginatedResponse[ScanResponse])
async def get_target_scans(
    target_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
    pagination: Pagination,
) -> PaginatedResponse[ScanResponse]:
    """List all scans associated with a target."""
    await _get_target_or_404(target_id, db)

    query = select(Scan).where(Scan.target_id == target_id)
    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Scan.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    items = list(result.scalars().all())

    return PaginatedResponse(
        items=items, total=total, skip=pagination.skip, limit=pagination.limit
    )
