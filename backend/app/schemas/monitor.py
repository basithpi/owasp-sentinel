import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class MonitorBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    monitor_type: str
    is_active: bool = True
    config: Optional[dict] = Field(default_factory=dict)
    alert_on_change: bool = True

    @field_validator("monitor_type")
    @classmethod
    def validate_monitor_type(cls, v: str) -> str:
        allowed = {"subdomain", "cert", "technology", "uptime"}
        if v not in allowed:
            raise ValueError(f"monitor_type must be one of {allowed}")
        return v


class MonitorCreate(MonitorBase):
    target_id: uuid.UUID


class MonitorUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    is_active: Optional[bool] = None
    config: Optional[dict] = None
    alert_on_change: Optional[bool] = None


class MonitorResponse(MonitorBase):
    id: uuid.UUID
    target_id: uuid.UUID
    last_check: Optional[datetime]
    last_result: Optional[dict]
    created_by: Optional[uuid.UUID]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
