from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class ToolBase(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    version: str
    description: Optional[str] = None
    category: str
    docker_image: str
    is_enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)
    priority: str = Field(default="P1", pattern="^(P0|P1|P2)$")


class ToolCreate(ToolBase):
    pass


class ToolUpdate(BaseModel):
    version: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    priority: Optional[str] = Field(default=None, pattern="^(P0|P1|P2)$")


class ToolResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: str
    description: Optional[str] = None
    category: str
    docker_image: str
    is_available: bool
    is_enabled: bool
    health_status: str
    last_health_check: Optional[datetime] = None
    config: Dict[str, Any] = {}
    priority: str
    created_at: datetime


class HealthStatus(BaseModel):
    is_healthy: bool
    version: Optional[str] = None
    message: str
    checked_at: datetime
