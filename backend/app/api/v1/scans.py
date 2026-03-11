import uuid
from typing import Optional

from fastapi import APIRouter, Query, status
from sqlalchemy import func, select

from ...core.dependencies import CurrentUser, DB, Pagination
from ...core.exceptions import ConflictError, ForbiddenError, NotFoundError
from ...models.finding import Finding
from ...models.scan import Scan, ScanSchedule
from ...schemas import PaginatedResponse
from ...schemas.finding import FindingResponse
from ...schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanScheduleCreate,
    ScanScheduleResponse,
    ScanScheduleUpdate,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_scan_or_404(scan_id: uuid.UUID, db: DB) -> Scan:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise NotFoundError(f"Scan {scan_id} not found")
    return scan


async def _get_schedule_or_404(schedule_id: uuid.UUID, db: DB) -> ScanSchedule:
    result = await db.execute(
        select(ScanSchedule).where(ScanSchedule.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()
    if schedule is None:
        raise NotFoundError(f"Schedule {schedule_id} not found")
    return schedule


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=PaginatedResponse[ScanResponse])
async def list_scans(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
    target_id: Optional[uuid.UUID] = Query(default=None),
    scan_status: Optional[str] = Query(default=None, alias="status"),
    scan_type: Optional[str] = Query(default=None),
) -> PaginatedResponse[ScanResponse]:
    """List scans with optional filters."""
    query = select(Scan)

    if target_id:
        query = query.where(Scan.target_id == target_id)
    if scan_status:
        query = query.where(Scan.status == scan_status)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Scan.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    return PaginatedResponse(
        items=list(result.scalars().all()),
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreate, db: DB, current_user: CurrentUser) -> Scan:
    """Create and enqueue a new scan."""
    scan = Scan(**payload.model_dump(), created_by=current_user.id, status="pending")
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    # In production, dispatch to Celery here: scan_task.delay(str(scan.id))
    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: uuid.UUID, db: DB, current_user: CurrentUser) -> Scan:
    return await _get_scan_or_404(scan_id, db)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: uuid.UUID, db: DB, current_user: CurrentUser) -> None:
    scan = await _get_scan_or_404(scan_id, db)
    await db.delete(scan)
    await db.flush()


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(scan_id: uuid.UUID, db: DB, current_user: CurrentUser) -> Scan:
    """Cancel a scan that is pending or running."""
    scan = await _get_scan_or_404(scan_id, db)
    if scan.status not in {"pending", "running"}:
        raise ConflictError(
            f"Cannot cancel a scan with status '{scan.status}'"
        )
    scan.status = "cancelled"
    await db.flush()
    await db.refresh(scan)
    return scan


@router.get("/{scan_id}/findings", response_model=PaginatedResponse[FindingResponse])
async def get_scan_findings(
    scan_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
    pagination: Pagination,
    severity: Optional[str] = Query(default=None),
) -> PaginatedResponse[FindingResponse]:
    """List all findings for a specific scan."""
    await _get_scan_or_404(scan_id, db)

    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Finding.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    return PaginatedResponse(
        items=list(result.scalars().all()),
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


# ---------------------------------------------------------------------------
# Schedule endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/schedules",
    response_model=ScanScheduleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_schedule(
    payload: ScanScheduleCreate, db: DB, current_user: CurrentUser
) -> ScanSchedule:
    """Create a recurring scan schedule."""
    schedule = ScanSchedule(**payload.model_dump())
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return schedule


@router.get("/schedules", response_model=PaginatedResponse[ScanScheduleResponse])
async def list_schedules(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
    target_id: Optional[uuid.UUID] = Query(default=None),
) -> PaginatedResponse[ScanScheduleResponse]:
    """List all scan schedules."""
    query = select(ScanSchedule)
    if target_id:
        query = query.where(ScanSchedule.target_id == target_id)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(ScanSchedule.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    return PaginatedResponse(
        items=list(result.scalars().all()),
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> None:
    schedule = await _get_schedule_or_404(schedule_id, db)
    await db.delete(schedule)
    await db.flush()
