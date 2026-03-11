from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TargetBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    target_type: str = Field(pattern="^(domain|ip|url|cidr|wildcard)$")
    value: str = Field(min_length=1, max_length=500)
    scope_rules: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    metadata_: Dict[str, Any] = Field(default_factory=dict, alias="metadata")
    is_active: bool = True


class TargetCreate(TargetBase):
    pass


class TargetUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    target_type: Optional[str] = Field(default=None, pattern="^(domain|ip|url|cidr|wildcard)$")
    value: Optional[str] = Field(default=None, min_length=1, max_length=500)
    scope_rules: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    metadata_: Optional[Dict[str, Any]] = Field(default=None, alias="metadata")
    is_active: Optional[bool] = None


class TargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    description: Optional[str] = None
    target_type: str
    value: str
    scope_rules: Dict[str, Any] = {}
    tags: List[str] = []
    metadata_: Dict[str, Any] = Field(default_factory=dict, alias="metadata")
    is_active: bool
    created_at: datetime
    updated_at: datetime
