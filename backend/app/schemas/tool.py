import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ToolBase(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    version: Optional[str] = Field(default=None, max_length=50)
    description: Optional[str] = None
    category: Optional[str] = Field(default=None, max_length=100)
    is_enabled: bool = True
    config: Optional[dict] = Field(default_factory=dict)


class ToolCreate(ToolBase):
    pass


class ToolUpdate(BaseModel):
    version: Optional[str] = Field(default=None, max_length=50)
    description: Optional[str] = None
    category: Optional[str] = Field(default=None, max_length=100)
    is_enabled: Optional[bool] = None
    is_installed: Optional[bool] = None
    health_status: Optional[str] = None
    config: Optional[dict] = None

    @field_validator("health_status")
    @classmethod
    def validate_health_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"healthy", "degraded", "unhealthy", "unknown"}
            if v not in allowed:
                raise ValueError(f"health_status must be one of {allowed}")
        return v


class ToolResponse(ToolBase):
    id: uuid.UUID
    is_installed: bool
    last_health_check: Optional[datetime]
    health_status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
