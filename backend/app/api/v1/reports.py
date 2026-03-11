import asyncio
import uuid
from collections.abc import AsyncGenerator
from typing import Optional

from fastapi import APIRouter, Query, status
from fastapi.responses import StreamingResponse
from minio import Minio
from minio.error import S3Error
from sqlalchemy import func, select

from ...config import settings
from ...core.dependencies import AdminUser, CurrentUser, DB, Pagination
from ...core.exceptions import NotFoundError, ServiceUnavailableError
from ...models.report import Report
from ...schemas import PaginatedResponse
from ...schemas.report import ReportCreate, ReportResponse, ReportUpdate

router = APIRouter(prefix="/reports", tags=["Reports"])

_MEDIA_TYPES = {
    "pdf": "application/pdf",
    "html": "text/html",
    "json": "application/json",
    "markdown": "text/markdown",
}

_FILE_EXTENSIONS = {
    "pdf": "pdf",
    "html": "html",
    "json": "json",
    "markdown": "md",
}


def _get_minio_client() -> Minio:
    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )


async def _get_report_or_404(report_id: uuid.UUID, db: DB) -> Report:
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if report is None:
        raise NotFoundError(f"Report {report_id} not found")
    return report


async def _stream_from_minio(file_path: str) -> AsyncGenerator[bytes, None]:
    """Async generator that streams an object from MinIO in 64 KiB chunks."""
    loop = asyncio.get_event_loop()
    client = _get_minio_client()

    def _get_object():
        return client.get_object(settings.minio_bucket_reports, file_path)

    try:
        response = await loop.run_in_executor(None, _get_object)
    except S3Error as exc:
        raise ServiceUnavailableError(f"Could not retrieve report file: {exc}") from exc

    try:
        while True:
            chunk = await loop.run_in_executor(None, response.read, 65536)
            if not chunk:
                break
            yield chunk
    finally:
        response.close()
        response.release_conn()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=PaginatedResponse[ReportResponse])
async def list_reports(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
    report_format: Optional[str] = Query(default=None, alias="format"),
    report_status: Optional[str] = Query(default=None, alias="status"),
    scan_id: Optional[uuid.UUID] = Query(default=None),
) -> PaginatedResponse[ReportResponse]:
    """List all reports with optional filtering by format, status, or scan."""
    query = select(Report)

    if report_format:
        query = query.where(Report.format == report_format)
    if report_status:
        query = query.where(Report.status == report_status)
    if scan_id:
        query = query.where(Report.scan_id == scan_id)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Report.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    return PaginatedResponse(
        items=list(result.scalars().all()),
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post(
    "/generate",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def generate_report(
    payload: ReportCreate,
    db: DB,
    current_user: CurrentUser,
) -> Report:
    """Create a report record and enqueue the generation task."""
    report = Report(
        **payload.model_dump(),
        status="generating",
        created_by=current_user.id,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    # In production, dispatch to Celery: generate_report_task.delay(str(report.id))
    return report


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> Report:
    """Retrieve details for a single report."""
    return await _get_report_or_404(report_id, db)


@router.get("/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> StreamingResponse:
    """Stream the generated report file from MinIO."""
    report = await _get_report_or_404(report_id, db)

    if report.status != "completed" or not report.file_path:
        raise NotFoundError("Report file is not yet available")

    extension = _FILE_EXTENSIONS.get(report.format, report.format)
    filename = f"{report.name}.{extension}"
    media_type = _MEDIA_TYPES.get(report.format, "application/octet-stream")

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
    }
    if report.file_size:
        headers["Content-Length"] = str(report.file_size)

    return StreamingResponse(
        _stream_from_minio(report.file_path),
        media_type=media_type,
        headers=headers,
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> None:
    """Delete a report record (and its file from MinIO if present)."""
    report = await _get_report_or_404(report_id, db)

    if report.file_path:
        loop = asyncio.get_event_loop()
        client = _get_minio_client()
        try:
            await loop.run_in_executor(
                None,
                lambda: client.remove_object(
                    settings.minio_bucket_reports, report.file_path
                ),
            )
        except S3Error:
            pass  # File already gone or bucket missing — proceed with DB deletion

    await db.delete(report)
    await db.flush()
