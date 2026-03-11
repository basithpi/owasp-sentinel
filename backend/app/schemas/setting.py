import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class SettingBase(BaseModel):
    key: str = Field(min_length=1, max_length=255)
    value: Optional[Any] = None
    category: Optional[str] = Field(default=None, max_length=100)
    description: Optional[str] = None


class SettingCreate(SettingBase):
    pass


class SettingUpdate(BaseModel):
    value: Optional[Any] = None
    category: Optional[str] = Field(default=None, max_length=100)
    description: Optional[str] = None


class SettingResponse(SettingBase):
    id: uuid.UUID
    updated_by: Optional[uuid.UUID]
    updated_at: datetime

    model_config = {"from_attributes": True}
