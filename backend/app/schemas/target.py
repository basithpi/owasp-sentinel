import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class TargetBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=2048)
    description: Optional[str] = None
    target_type: str = Field(default="url")
    tags: Optional[List[str]] = Field(default_factory=list)

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, v: str) -> str:
        allowed = {"url", "ip", "domain", "cidr"}
        if v not in allowed:
            raise ValueError(f"target_type must be one of {allowed}")
        return v


class TargetCreate(TargetBase):
    pass


class TargetUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    url: Optional[str] = Field(default=None, min_length=1, max_length=2048)
    description: Optional[str] = None
    target_type: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"active", "archived", "testing"}
            if v not in allowed:
                raise ValueError(f"status must be one of {allowed}")
        return v


class TargetResponse(TargetBase):
    id: uuid.UUID
    status: str
    created_by: Optional[uuid.UUID]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
