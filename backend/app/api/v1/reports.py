from __future__ import annotations

import io
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.database import get_db
from app.dependencies import get_current_active_user, get_pagination_params
from app.models.report import Report
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.schemas.report import ReportCreate, ReportResponse
from app.services.report_service import ReportService

router = APIRouter()


class ReportExportRequest(BaseModel):
    """Request body for exporting a report in a different format."""

    format: str = "json"


def _handle_service_errors(e: Exception) -> None:
    """Translate service layer exceptions into HTTP responses."""
    if isinstance(e, NotFoundError):
        raise HTTPException(status_code=404, detail=e.message)
    if isinstance(e, ConflictError):
        raise HTTPException(status_code=409, detail=e.message)
    if isinstance(e, ForbiddenError):
        raise HTTPException(status_code=403, detail=e.message)
    raise HTTPException(status_code=500, detail=str(e))


@router.get("", response_model=PaginatedResponse[ReportResponse])
def list_reports(
    scan_id: Optional[uuid.UUID] = Query(default=None, description="Filter by scan ID"),
    report_format: Optional[str] = Query(default=None, alias="format", description="Filter by format"),
    report_status: Optional[str] = Query(default=None, alias="status", description="Filter by status"),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List all reports for the current user with optional filters."""
    query = db.query(Report)
    if current_user.role != "admin":
        query = query.filter(Report.user_id == current_user.id)
    if report_format is not None:
        query = query.filter(Report.format == report_format)
    if report_status is not None:
        query = query.filter(Report.status == report_status)
    # scan_id filter is applied after fetch since scan_ids is a JSON list field
    all_reports = query.order_by(Report.created_at.desc()).all()
    if scan_id is not None:
        all_reports = [r for r in all_reports if str(scan_id) in (r.scan_ids or [])]
    total = len(all_reports)
    paginated = all_reports[pagination.offset : pagination.offset + pagination.limit]
    return PaginatedResponse.create(items=paginated, total=total, params=pagination)


@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def create_report(
    report_data: ReportCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create a new report and queue it for generation."""
    service = ReportService(db)
    try:
        return service.create_report(report_data, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.get("/{report_id}", response_model=ReportResponse)
def get_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Retrieve a single report by ID."""
    service = ReportService(db)
    try:
        return service.get_report(report_id, current_user)
    except Exception as e:
        _handle_service_errors(e)


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete a report and its associated file."""
    service = ReportService(db)
    try:
        report = service.get_report(report_id, current_user)
    except Exception as e:
        _handle_service_errors(e)
    if report.content_path and os.path.exists(report.content_path):
        try:
            os.remove(report.content_path)
        except OSError:
            pass
    db.delete(report)
    db.commit()


@router.get("/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Download the generated report file."""
    service = ReportService(db)
    try:
        report = service.get_report(report_id, current_user)
    except Exception as e:
        _handle_service_errors(e)

    if report.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Report is not ready for download (status: {report.status})",
        )

    if report.content_path and os.path.exists(report.content_path):
        media_type_map = {
            "pdf": "application/pdf",
            "html": "text/html",
            "json": "application/json",
            "markdown": "text/markdown",
        }
        media_type = media_type_map.get(report.format, "application/octet-stream")
        filename = f"report_{report_id}.{report.format}"
        return FileResponse(
            path=report.content_path,
            media_type=media_type,
            filename=filename,
        )

    # Generate content on-the-fly when file is not on disk
    from app.models.finding import Finding

    finding_ids = [uuid.UUID(fid) for fid in (report.finding_ids or [])]
    findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all() if finding_ids else []

    if report.format == "json":
        content = service.generate_json_report(report, findings).encode()
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.json"},
        )
    if report.format == "markdown":
        content = service.generate_markdown_report(report, findings).encode()
        return StreamingResponse(
            io.BytesIO(content),
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.md"},
        )
    if report.format == "pdf":
        content = service.generate_pdf_report(report, findings)
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.pdf"},
        )

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=f"Unsupported report format: {report.format}",
    )


@router.post("/{report_id}/export")
def export_report(
    report_id: uuid.UUID,
    export_request: ReportExportRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Export an existing report in a different format."""
    allowed_formats = {"pdf", "html", "json", "markdown"}
    if export_request.format not in allowed_formats:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format. Allowed: {', '.join(sorted(allowed_formats))}",
        )

    service = ReportService(db)
    try:
        report = service.get_report(report_id, current_user)
    except Exception as e:
        _handle_service_errors(e)

    from app.models.finding import Finding

    finding_ids = [uuid.UUID(fid) for fid in (report.finding_ids or [])]
    findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all() if finding_ids else []

    fmt = export_request.format
    if fmt == "json":
        content = service.generate_json_report(report, findings).encode()
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.json"},
        )
    if fmt == "markdown":
        content = service.generate_markdown_report(report, findings).encode()
        return StreamingResponse(
            io.BytesIO(content),
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.md"},
        )
    if fmt == "pdf":
        content = service.generate_pdf_report(report, findings)
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.pdf"},
        )

    # html: render a basic HTML wrapper around the markdown content
    md_content = service.generate_markdown_report(report, findings)
    html_content = (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{report.name}</title></head><body><pre>{md_content}</pre></body></html>"
    ).encode()
    return StreamingResponse(
        io.BytesIO(html_content),
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=report_{report_id}.html"},
    )
