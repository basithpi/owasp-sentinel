from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ReportCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    format: str = Field(default="pdf", pattern="^(pdf|html|json|markdown)$")
    template: str = "default"
    scan_ids: List[uuid.UUID] = Field(default_factory=list)
    finding_ids: List[uuid.UUID] = Field(default_factory=list)


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    format: str
    template: str
    scan_ids: List[str] = []
    finding_ids: List[str] = []
    content_path: Optional[str] = None
    status: str
    generated_at: Optional[datetime] = None
    created_at: datetime
