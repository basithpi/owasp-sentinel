import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class NotificationBase(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    message: str = Field(min_length=1)
    type: str = Field(default="info")
    category: str = Field(default="system")
    reference_id: Optional[str] = Field(default=None, max_length=255)

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"info", "warning", "error", "success"}
        if v not in allowed:
            raise ValueError(f"type must be one of {allowed}")
        return v

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        allowed = {"scan", "finding", "system", "report"}
        if v not in allowed:
            raise ValueError(f"category must be one of {allowed}")
        return v


class NotificationCreate(NotificationBase):
    user_id: uuid.UUID


class NotificationUpdate(BaseModel):
    is_read: Optional[bool] = None


class NotificationResponse(NotificationBase):
    id: uuid.UUID
    user_id: uuid.UUID
    is_read: bool
    created_at: datetime

    model_config = {"from_attributes": True}
