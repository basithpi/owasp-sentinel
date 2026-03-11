from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.database import get_db
from app.dependencies import get_current_active_user, get_pagination_params
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.target import TargetCreate, TargetResponse, TargetUpdate
from app.services.scan_service import ScanService

router = APIRouter()


def _get_target_or_404(target_id: uuid.UUID, user: User, db: Session):
    from app.models.target import Target
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if target.user_id != user.id and user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Access denied")
    return target


@router.get("", response_model=PaginatedResponse[TargetResponse])
def list_targets(
    is_active: Optional[bool] = Query(default=None),
    tag: Optional[str] = Query(default=None),
    target_type: Optional[str] = Query(default=None),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    from app.models.target import Target
    query = db.query(Target)
    if current_user.role != "admin":
        query = query.filter(Target.user_id == current_user.id)
    if is_active is not None:
        query = query.filter(Target.is_active == is_active)
    if target_type:
        query = query.filter(Target.target_type == target_type)
    total = query.count()
    targets = query.order_by(Target.created_at.desc()).offset(pagination.offset).limit(pagination.limit).all()
    return PaginatedResponse.create(items=targets, total=total, params=pagination)


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    target_data: TargetCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    from app.models.target import Target
    target = Target(
        user_id=current_user.id,
        name=target_data.name,
        description=target_data.description,
        target_type=target_data.target_type,
        value=target_data.value,
        scope_rules=target_data.scope_rules,
        tags=target_data.tags,
        metadata_=target_data.metadata_,
        is_active=target_data.is_active,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    return _get_target_or_404(target_id, current_user, db)


@router.put("/{target_id}", response_model=TargetResponse)
def update_target(
    target_id: uuid.UUID,
    update_data: TargetUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    target = _get_target_or_404(target_id, current_user, db)
    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        real_key = "metadata_" if key == "metadata" else key
        setattr(target, real_key, value)
    db.commit()
    db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    target = _get_target_or_404(target_id, current_user, db)
    db.delete(target)
    db.commit()


@router.post("/{target_id}/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def trigger_scan(
    target_id: uuid.UUID,
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    _get_target_or_404(target_id, current_user, db)
    scan_data.target_id = target_id
    service = ScanService(db)
    try:
        scan = service.create_scan(scan_data, current_user)
        return service.start_scan(scan.id, current_user)
    except (NotFoundError, ConflictError) as e:
        raise HTTPException(status_code=400, detail=e.message)


@router.get("/{target_id}/findings", response_model=PaginatedResponse[FindingResponse])
def get_target_findings(
    target_id: uuid.UUID,
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    _get_target_or_404(target_id, current_user, db)
    from app.services.finding_service import FindingService
    service = FindingService(db)
    findings, total = service.list_findings(current_user, offset=pagination.offset, limit=pagination.limit, target_id=target_id)
    return PaginatedResponse.create(items=findings, total=total, params=pagination)


@router.get("/{target_id}/scans", response_model=PaginatedResponse[ScanResponse])
def get_target_scans(
    target_id: uuid.UUID,
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    _get_target_or_404(target_id, current_user, db)
    service = ScanService(db)
    scans, total = service.list_scans(current_user, offset=pagination.offset, limit=pagination.limit, target_id=target_id)
    return PaginatedResponse.create(items=scans, total=total, params=pagination)
