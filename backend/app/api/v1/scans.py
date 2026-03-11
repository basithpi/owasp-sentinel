from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.database import get_db
from app.dependencies import get_current_active_user, get_pagination_params
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanCreate, ScanResponse, ScanUpdate
from app.services.finding_service import FindingService
from app.services.scan_service import ScanService

router = APIRouter()


def _handle_service_errors(e: Exception):
    if isinstance(e, NotFoundError):
        raise HTTPException(status_code=404, detail=e.message)
    if isinstance(e, ConflictError):
        raise HTTPException(status_code=409, detail=e.message)
    if isinstance(e, ForbiddenError):
        raise HTTPException(status_code=403, detail=e.message)
    raise HTTPException(status_code=500, detail=str(e))


@router.get("", response_model=PaginatedResponse[ScanResponse])
def list_scans(
    scan_status: Optional[str] = Query(default=None, alias="status"),
    target_id: Optional[uuid.UUID] = Query(default=None),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    scans, total = service.list_scans(
        current_user,
        offset=pagination.offset,
        limit=pagination.limit,
        status=scan_status,
        target_id=target_id,
    )
    return PaginatedResponse.create(items=scans, total=total, params=pagination)


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        return service.create_scan(scan_data, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        return service.get_scan(scan_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.put("/{scan_id}", response_model=ScanResponse)
def update_scan(
    scan_id: uuid.UUID,
    scan_data: ScanUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        return service.update_scan(scan_id, scan_data, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        service.delete_scan(scan_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.post("/{scan_id}/start", response_model=ScanResponse)
def start_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        return service.start_scan(scan_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.post("/{scan_id}/pause", response_model=ScanResponse)
def pause_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        return service.pause_scan(scan_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.post("/{scan_id}/resume", response_model=ScanResponse)
def resume_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        return service.resume_scan(scan_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        return service.cancel_scan(scan_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.get("/{scan_id}/findings", response_model=PaginatedResponse[FindingResponse])
def get_scan_findings(
    scan_id: uuid.UUID,
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    scan_service = ScanService(db)
    try:
        scan_service.get_scan(scan_id, current_user)
    except Exception as e:
        _handle_service_errors(e)

    finding_service = FindingService(db)
    findings, total = finding_service.list_findings(
        current_user,
        offset=pagination.offset,
        limit=pagination.limit,
        scan_id=scan_id,
    )
    return PaginatedResponse.create(items=findings, total=total, params=pagination)


@router.get("/{scan_id}/logs")
def get_scan_logs(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = ScanService(db)
    try:
        scan = service.get_scan(scan_id, current_user)
        return {"scan_id": str(scan_id), "logs": scan.error_log or "", "status": scan.status}
    except Exception as e:
        _handle_service_errors(e)


@router.websocket("/{scan_id}/ws")
async def scan_websocket(
    scan_id: uuid.UUID,
    websocket: WebSocket,
    db: Session = Depends(get_db),
):
    await websocket.accept()
    try:
        while True:
            scan = db.query(__import__("app.models.scan", fromlist=["Scan"]).Scan).filter(
                __import__("app.models.scan", fromlist=["Scan"]).Scan.id == scan_id
            ).first()
            if scan:
                await websocket.send_json({
                    "scan_id": str(scan_id),
                    "status": scan.status,
                    "progress": scan.progress,
                    "findings_count": scan.findings_count,
                })
                if scan.status in ("completed", "failed", "cancelled"):
                    break
            import asyncio
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
