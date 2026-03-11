import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class FindingBase(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    description: Optional[str] = None
    severity: str
    owasp_category: Optional[str] = Field(default=None, max_length=10)
    cwe_id: Optional[int] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    url: Optional[str] = Field(default=None, max_length=2048)
    parameter: Optional[str] = Field(default=None, max_length=512)
    payload_used: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    tool_name: Optional[str] = Field(default=None, max_length=100)
    raw_output: Optional[dict] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v

    @field_validator("owasp_category")
    @classmethod
    def validate_owasp(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            import re
            if not re.match(r"^A0[1-9]$|^A10$", v):
                raise ValueError("owasp_category must be A01-A10")
        return v


class FindingCreate(FindingBase):
    scan_id: uuid.UUID
    target_id: uuid.UUID


class FindingUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=512)
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"critical", "high", "medium", "low", "info"}
            if v not in allowed:
                raise ValueError(f"severity must be one of {allowed}")
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"open", "confirmed", "false_positive", "fixed"}
            if v not in allowed:
                raise ValueError(f"status must be one of {allowed}")
        return v


class FindingResponse(FindingBase):
    id: uuid.UUID
    scan_id: uuid.UUID
    target_id: uuid.UUID
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
