import uuid
from typing import List, Optional

from fastapi import APIRouter, Query, status
from sqlalchemy import distinct, func, select

from ...core.dependencies import CurrentUser, DB, Pagination
from ...core.exceptions import NotFoundError
from ...models.payload import Payload
from ...schemas import PaginatedResponse
from ...schemas.payload import PayloadCreate, PayloadResponse, PayloadUpdate

router = APIRouter(prefix="/payloads", tags=["Payloads"])

VALID_CATEGORIES = [
    "sqli", "xss", "cmd", "ssti", "ssrf", "xxe",
    "lfi", "rfi", "idor", "auth", "csrf", "other",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_payload_or_404(payload_id: uuid.UUID, db: DB) -> Payload:
    result = await db.execute(select(Payload).where(Payload.id == payload_id))
    obj = result.scalar_one_or_none()
    if obj is None:
        raise NotFoundError(f"Payload {payload_id} not found")
    return obj


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/categories", response_model=List[str])
async def list_categories(current_user: CurrentUser) -> List[str]:
    """Return the list of supported payload categories."""
    return VALID_CATEGORIES


@router.get("", response_model=PaginatedResponse[PayloadResponse])
async def list_payloads(
    db: DB,
    pagination: Pagination,
    current_user: CurrentUser,
    category: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    is_active: Optional[bool] = Query(default=None),
) -> PaginatedResponse[PayloadResponse]:
    """List payloads with optional filtering."""
    query = select(Payload)

    if category:
        query = query.where(Payload.category == category)
    if is_active is not None:
        query = query.where(Payload.is_active == is_active)
    if search:
        query = query.where(
            Payload.name.ilike(f"%{search}%") | Payload.description.ilike(f"%{search}%")
        )

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    result = await db.execute(
        query.order_by(Payload.created_at.desc())
        .offset(pagination.skip)
        .limit(pagination.limit)
    )
    return PaginatedResponse(
        items=list(result.scalars().all()),
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post("", response_model=PayloadResponse, status_code=status.HTTP_201_CREATED)
async def create_payload(
    payload_in: PayloadCreate, db: DB, current_user: CurrentUser
) -> Payload:
    """Create a new payload entry."""
    obj = Payload(**payload_in.model_dump())
    db.add(obj)
    await db.flush()
    await db.refresh(obj)
    return obj


@router.get("/{payload_id}", response_model=PayloadResponse)
async def get_payload(
    payload_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> Payload:
    return await _get_payload_or_404(payload_id, db)


@router.put("/{payload_id}", response_model=PayloadResponse)
async def update_payload(
    payload_id: uuid.UUID,
    payload_in: PayloadUpdate,
    db: DB,
    current_user: CurrentUser,
) -> Payload:
    """Update a payload's fields."""
    obj = await _get_payload_or_404(payload_id, db)

    for field, value in payload_in.model_dump(exclude_unset=True).items():
        setattr(obj, field, value)

    await db.flush()
    await db.refresh(obj)
    return obj


@router.delete("/{payload_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_payload(
    payload_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> None:
    obj = await _get_payload_or_404(payload_id, db)
    await db.delete(obj)
    await db.flush()
