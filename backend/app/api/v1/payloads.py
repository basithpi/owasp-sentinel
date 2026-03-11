from __future__ import annotations

import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenError, NotFoundError
from app.database import get_db
from app.dependencies import get_current_active_user, get_pagination_params
from app.models.user import User
from app.schemas.common import PaginatedResponse, PaginationParams
from app.schemas.payload import (
    PayloadCreate,
    PayloadEncodeRequest,
    PayloadMutateRequest,
    PayloadResponse,
    PayloadUpdate,
)
from app.services.payload_service import PayloadService

router = APIRouter()


@router.get("", response_model=PaginatedResponse[PayloadResponse])
def list_payloads(
    category: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    payloads, total = service.list_payloads(
        offset=pagination.offset,
        limit=pagination.limit,
        category=category,
        search=search,
        user=current_user,
    )
    return PaginatedResponse.create(items=payloads, total=total, params=pagination)


@router.get("/tree", response_model=Dict[str, List[str]])
def get_category_tree(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    return service.get_category_tree()


@router.get("/search", response_model=PaginatedResponse[PayloadResponse])
def search_payloads(
    q: str = Query(..., min_length=1),
    pagination: PaginationParams = Depends(get_pagination_params),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    payloads, total = service.list_payloads(
        offset=pagination.offset,
        limit=pagination.limit,
        search=q,
        user=current_user,
    )
    return PaginatedResponse.create(items=payloads, total=total, params=pagination)


@router.post("/mutate", response_model=Dict[str, List[str]])
def mutate_payloads(
    request: PayloadMutateRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    return service.mutate_payloads(request.payloads, request.mutations)


@router.post("/encode", response_model=Dict[str, str])
def encode_payload(
    request: PayloadEncodeRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    try:
        encoded = service.encode_payload(request.payload, request.encoding)
        return {"original": request.payload, "encoded": encoded, "encoding": request.encoding}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/upload", response_model=PayloadResponse, status_code=status.HTTP_201_CREATED)
async def upload_payload(
    file: UploadFile = File(...),
    category: str = Query(...),
    name: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    import hashlib
    content = await file.read()
    content_str = content.decode("utf-8", errors="replace")
    payload_count = len([line for line in content_str.splitlines() if line.strip()])
    content_hash = hashlib.sha256(content).hexdigest()

    file_path = f"uploads/payloads/{current_user.id}/{file.filename}"

    service = PayloadService(db)
    payload_data = PayloadCreate(
        name=name or file.filename or "uploaded_payload",
        category=category,
        file_path=file_path,
        content_hash=content_hash,
        payload_count=payload_count,
        is_builtin=False,
        source="upload",
    )
    return service.create_payload(payload_data, current_user)


@router.get("/{payload_id}", response_model=PayloadResponse)
def get_payload(
    payload_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    try:
        return service.get_payload(payload_id)
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)


@router.post("", response_model=PayloadResponse, status_code=status.HTTP_201_CREATED)
def create_payload(
    payload_data: PayloadCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    return service.create_payload(payload_data, current_user)


@router.put("/{payload_id}", response_model=PayloadResponse)
def update_payload(
    payload_id: uuid.UUID,
    update_data: PayloadUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    try:
        return service.update_payload(payload_id, update_data, current_user)
    except (NotFoundError, ForbiddenError) as e:
        raise HTTPException(status_code=404 if isinstance(e, NotFoundError) else 403, detail=e.message)


@router.delete("/{payload_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_payload(
    payload_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PayloadService(db)
    try:
        service.delete_payload(payload_id, current_user)
    except (NotFoundError, ForbiddenError) as e:
        raise HTTPException(status_code=404 if isinstance(e, NotFoundError) else 403, detail=e.message)
