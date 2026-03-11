from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanConfig(BaseModel):
    tools: List[str] = Field(default_factory=list)
    modules: List[str] = Field(default_factory=list)
    intensity: str = Field(default="normal", pattern="^(light|normal|aggressive)$")
    timeout: int = Field(default=3600, ge=60, le=86400)
    max_threads: int = Field(default=10, ge=1, le=50)
    rate_limit: int = Field(default=100, ge=1)
    custom_options: Dict[str, Any] = Field(default_factory=dict)


class ScanBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    scan_type: str = Field(default="full", pattern="^(full|recon|vuln_scan|specific_tool)$")
    config: ScanConfig = Field(default_factory=ScanConfig)


class ScanCreate(ScanBase):
    target_id: uuid.UUID


class ScanUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    config: Optional[ScanConfig] = None


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    target_id: uuid.UUID
    scan_type: str
    name: str
    description: Optional[str] = None
    status: str
    config: Dict[str, Any] = {}
    progress: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int
    error_log: Optional[str] = None
    celery_task_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
