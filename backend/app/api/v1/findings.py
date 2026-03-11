from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenError, NotFoundError
from app.database import get_db
from app.dependencies import get_current_active_user, get_pagination_params
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.schemas.finding import FindingResponse, FindingStats, FindingStatusUpdate, FindingUpdate
from app.services.finding_service import FindingService

router = APIRouter()


def _handle_errors(e: Exception):
    if isinstance(e, NotFoundError):
        raise HTTPException(status_code=404, detail=e.message)
    if isinstance(e, ForbiddenError):
        raise HTTPException(status_code=403, detail=e.message)
    raise HTTPException(status_code=500, detail=str(e))


@router.get("", response_model=PaginatedResponse[FindingResponse])
def list_findings(
    severity: Optional[str] = Query(default=None),
    owasp_category: Optional[str] = Query(default=None),
    tool_name: Optional[str] = Query(default=None),
    finding_status: Optional[str] = Query(default=None, alias="status"),
    scan_id: Optional[uuid.UUID] = Query(default=None),
    target_id: Optional[uuid.UUID] = Query(default=None),
    include_fp: bool = Query(default=False, description="Include false positives"),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = FindingService(db)
    findings, total = service.list_findings(
        current_user,
        offset=pagination.offset,
        limit=pagination.limit,
        severity=severity,
        owasp_category=owasp_category,
        tool_name=tool_name,
        status=finding_status,
        scan_id=scan_id,
        target_id=target_id,
        include_false_positives=include_fp,
    )
    return PaginatedResponse.create(items=findings, total=total, params=pagination)


@router.get("/stats", response_model=FindingStats)
def get_finding_stats(
    scan_id: Optional[uuid.UUID] = Query(default=None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = FindingService(db)
    return service.get_stats(current_user, scan_id=scan_id)


@router.get("/export")
def export_findings(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    scan_id: Optional[uuid.UUID] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = FindingService(db)
    findings, _ = service.list_findings(
        current_user,
        offset=0,
        limit=10000,
        scan_id=scan_id,
        severity=severity,
        include_false_positives=True,
    )

    if format == "json":
        data = [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "owasp_category": f.owasp_category,
                "status": f.status,
                "url": f.url,
                "tool_name": f.tool_name,
                "cvss_score": f.cvss_score,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ]
        return StreamingResponse(
            io.BytesIO(json.dumps(data, indent=2).encode()),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=findings.json"},
        )
    else:
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["id", "title", "severity", "owasp_category", "status", "url", "tool_name", "cvss_score"],
        )
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "owasp_category": f.owasp_category or "",
                "status": f.status,
                "url": f.url or "",
                "tool_name": f.tool_name,
                "cvss_score": f.cvss_score or "",
            })
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = FindingService(db)
    try:
        return service.get_finding(finding_id, current_user)
    except Exception as e:
        _handle_errors(e)


@router.put("/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: uuid.UUID,
    update_data: FindingUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = FindingService(db)
    try:
        return service.update_finding(finding_id, update_data, current_user)
    except Exception as e:
        _handle_errors(e)


@router.put("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: uuid.UUID,
    status_data: FindingStatusUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = FindingService(db)
    try:
        return service.update_status(finding_id, status_data.status, current_user)
    except Exception as e:
        _handle_errors(e)


@router.post("/{finding_id}/false-positive", response_model=FindingResponse)
def toggle_false_positive(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = FindingService(db)
    try:
        return service.mark_false_positive(finding_id, current_user)
    except Exception as e:
        _handle_errors(e)
