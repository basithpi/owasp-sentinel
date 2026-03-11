import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ReportBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    format: str = Field(default="pdf")
    config: Optional[dict] = Field(default_factory=dict)

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        allowed = {"pdf", "html", "json", "markdown"}
        if v not in allowed:
            raise ValueError(f"format must be one of {allowed}")
        return v


class ReportCreate(ReportBase):
    scan_id: Optional[uuid.UUID] = None
    target_id: Optional[uuid.UUID] = None


class ReportUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    status: Optional[str] = None
    file_path: Optional[str] = Field(default=None, max_length=1024)
    file_size: Optional[int] = Field(default=None, ge=0)

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"generating", "completed", "failed"}
            if v not in allowed:
                raise ValueError(f"status must be one of {allowed}")
        return v


class ReportResponse(ReportBase):
    id: uuid.UUID
    scan_id: Optional[uuid.UUID]
    target_id: Optional[uuid.UUID]
    status: str
    file_path: Optional[str]
    file_size: Optional[int]
    created_by: Optional[uuid.UUID]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
