from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class OWASPBreakdown(BaseModel):
    category: str
    label: str
    count: int
    percentage: float


class SeverityTimeline(BaseModel):
    date: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ToolEffectiveness(BaseModel):
    tool_name: str
    findings_count: int
    unique_findings: int
    critical_count: int
    high_count: int
    effectiveness_score: float


class DashboardStats(BaseModel):
    total_targets: int = 0
    active_targets: int = 0
    total_scans: int = 0
    running_scans: int = 0
    completed_scans: int = 0
    total_findings: int = 0
    open_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    false_positives: int = 0
    severity_breakdown: SeverityBreakdown = SeverityBreakdown()
    owasp_breakdown: List[OWASPBreakdown] = []
    severity_timeline: List[SeverityTimeline] = []
    tool_effectiveness: List[ToolEffectiveness] = []
    recent_findings: List[Dict[str, Any]] = []
    recent_scans: List[Dict[str, Any]] = []
