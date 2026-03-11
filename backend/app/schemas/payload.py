from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class PayloadBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=100)
    subcategory: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    source: str = "custom"


class PayloadCreate(PayloadBase):
    file_path: str
    content_hash: str
    payload_count: int = 0
    is_builtin: bool = False


class PayloadUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    category: Optional[str] = None
    subcategory: Optional[str] = None
    tags: Optional[List[str]] = None
    description: Optional[str] = None


class PayloadResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    name: str
    category: str
    subcategory: Optional[str] = None
    file_path: str
    content_hash: str
    payload_count: int
    tags: List[str] = []
    description: Optional[str] = None
    source: str
    is_builtin: bool
    stats: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime


class PayloadMutateRequest(BaseModel):
    payloads: List[str]
    mutations: List[str] = Field(
        default=["case", "url_encode", "html_encode", "double_encode"],
        description="Types of mutations to apply",
    )


class PayloadEncodeRequest(BaseModel):
    payload: str
    encoding: str = Field(pattern="^(url|html|base64|hex|unicode|double_url)$")


class PayloadTestRequest(BaseModel):
    payload_ids: List[uuid.UUID]
    target_url: str
    parameter: str
    method: str = Field(default="GET", pattern="^(GET|POST|PUT|PATCH|DELETE)$")
