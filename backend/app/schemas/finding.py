from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class FindingBase(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    description: str
    severity: str = Field(pattern="^(critical|high|medium|low|info)$")
    confidence: str = Field(default="firm", pattern="^(certain|firm|tentative)$")
    owasp_category: Optional[str] = None
    cwe_id: Optional[int] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    tool_name: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    reproduction_steps: Optional[str] = None
    remediation: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload_used: Optional[str] = None


class FindingCreate(FindingBase):
    scan_id: uuid.UUID
    target_id: uuid.UUID


class FindingUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    confidence: Optional[str] = Field(default=None, pattern="^(certain|firm|tentative)$")
    owasp_category: Optional[str] = None
    cwe_id: Optional[int] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    reproduction_steps: Optional[str] = None
    remediation: Optional[str] = None
    is_false_positive: Optional[bool] = None
    status: Optional[str] = Field(default=None, pattern="^(open|confirmed|fixed|accepted|wontfix)$")


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|confirmed|fixed|accepted|wontfix)$")
    note: Optional[str] = None


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    target_id: uuid.UUID
    user_id: uuid.UUID
    title: str
    description: str
    severity: str
    confidence: str
    owasp_category: Optional[str] = None
    cwe_id: Optional[int] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    tool_name: str
    evidence: Dict[str, Any] = {}
    reproduction_steps: Optional[str] = None
    remediation: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload_used: Optional[str] = None
    is_false_positive: bool
    is_duplicate: bool
    duplicate_of_id: Optional[uuid.UUID] = None
    status: str
    ai_analysis: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime


class FindingStats(BaseModel):
    total: int
    by_severity: Dict[str, int] = {}
    by_owasp: Dict[str, int] = {}
    by_tool: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    false_positives: int = 0
    duplicates: int = 0
