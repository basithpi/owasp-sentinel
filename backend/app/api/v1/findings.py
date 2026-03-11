import uuid
from typing import Optional

from fastapi import APIRouter, Query, status
from sqlalchemy import func, select

from ...core.dependencies import CurrentUser, DB, Pagination
from ...core.exceptions import NotFoundError
from ...models.finding import Finding
from ...schemas import PaginatedResponse
from ...schemas.finding import FindingResponse, FindingUpdate

router = APIRouter(prefix="/findings", tags=["Findings"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_finding_or_404(finding_id: uuid.UUID, db: DB) -> Finding:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise NotFoundError(f"Finding {finding_id} not found")
    return finding


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=PaginatedResponse[FindingResponse])
async def list_findings(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
    scan_id: Optional[uuid.UUID] = Query(default=None),
    target_id: Optional[uuid.UUID] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    finding_status: Optional[str] = Query(default=None, alias="status"),
    owasp_category: Optional[str] = Query(default=None),
    tool_name: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
) -> PaginatedResponse[FindingResponse]:
    """List findings with rich filtering options."""
    query = select(Finding)

    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if target_id:
        query = query.where(Finding.target_id == target_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if finding_status:
        query = query.where(Finding.status == finding_status)
    if owasp_category:
        query = query.where(Finding.owasp_category == owasp_category)
    if tool_name:
        query = query.where(Finding.tool_name == tool_name)
    if search:
        query = query.where(Finding.title.ilike(f"%{search}%"))

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


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> Finding:
    return await _get_finding_or_404(finding_id, db)


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    db: DB,
    current_user: CurrentUser,
) -> Finding:
    """Update finding fields (status, remediation, evidence, etc.)."""
    finding = await _get_finding_or_404(finding_id, db)

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)

    await db.flush()
    await db.refresh(finding)
    return finding


@router.delete("/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_finding(
    finding_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> None:
    finding = await _get_finding_or_404(finding_id, db)
    await db.delete(finding)
    await db.flush()


@router.post("/{finding_id}/confirm", response_model=FindingResponse)
async def confirm_finding(
    finding_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> Finding:
    """Mark a finding as confirmed."""
    finding = await _get_finding_or_404(finding_id, db)
    finding.status = "confirmed"
    await db.flush()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/false-positive", response_model=FindingResponse)
async def mark_false_positive(
    finding_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> Finding:
    """Mark a finding as a false positive."""
    finding = await _get_finding_or_404(finding_id, db)
    finding.status = "false_positive"
    await db.flush()
    await db.refresh(finding)
    return finding
