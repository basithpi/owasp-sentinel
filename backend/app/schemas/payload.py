import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class PayloadBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1)
    category: str
    subcategory: Optional[str] = Field(default=None, max_length=100)
    tags: Optional[List[str]] = Field(default_factory=list)
    description: Optional[str] = None
    is_active: bool = True

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        allowed = {
            "sqli", "xss", "cmd", "ssti", "ssrf", "xxe",
            "lfi", "rfi", "idor", "auth", "csrf", "other",
        }
        if v not in allowed:
            raise ValueError(f"category must be one of {allowed}")
        return v


class PayloadCreate(PayloadBase):
    pass


class PayloadUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    content: Optional[str] = Field(default=None, min_length=1)
    category: Optional[str] = None
    subcategory: Optional[str] = Field(default=None, max_length=100)
    tags: Optional[List[str]] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class PayloadResponse(PayloadBase):
    id: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}
