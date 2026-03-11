import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ScanBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scan_type: str = Field(min_length=1, max_length=100)
    config: Optional[dict] = Field(default_factory=dict)


class ScanCreate(ScanBase):
    target_id: uuid.UUID


class ScanUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    status: Optional[str] = None
    progress: Optional[int] = Field(default=None, ge=0, le=100)
    error_message: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"pending", "running", "completed", "failed", "cancelled"}
            if v not in allowed:
                raise ValueError(f"status must be one of {allowed}")
        return v


class ScanResponse(ScanBase):
    id: uuid.UUID
    target_id: uuid.UUID
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: Optional[uuid.UUID]
    progress: int
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanScheduleBase(BaseModel):
    cron_expression: str = Field(min_length=1, max_length=100)
    scan_type: str = Field(min_length=1, max_length=100)
    config: Optional[dict] = Field(default_factory=dict)
    is_active: bool = True


class ScanScheduleCreate(ScanScheduleBase):
    target_id: uuid.UUID


class ScanScheduleUpdate(BaseModel):
    cron_expression: Optional[str] = Field(default=None, max_length=100)
    scan_type: Optional[str] = Field(default=None, max_length=100)
    config: Optional[dict] = None
    is_active: Optional[bool] = None


class ScanScheduleResponse(ScanScheduleBase):
    id: uuid.UUID
    target_id: uuid.UUID
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
