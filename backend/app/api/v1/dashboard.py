from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_active_user
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.dashboard import DashboardStats, OWASPBreakdown, SeverityBreakdown

router = APIRouter()

# Canonical OWASP Top 10 2021 labels keyed by category code
_OWASP_LABELS: Dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


def _user_filter(query, model, current_user: User):
    """Restrict a query to the current user's records unless they are an admin."""
    if current_user.role != "admin":
        return query.filter(model.user_id == current_user.id)
    return query


@router.get("/stats", response_model=DashboardStats)
def get_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Return aggregated counts and breakdowns for the dashboard overview panel."""
    target_q = _user_filter(db.query(Target), Target, current_user)
    total_targets: int = target_q.count()
    active_targets: int = target_q.filter(Target.is_active.is_(True)).count()

    scan_q = _user_filter(db.query(Scan), Scan, current_user)
    total_scans: int = scan_q.count()
    running_scans: int = scan_q.filter(Scan.status == "running").count()
    completed_scans: int = scan_q.filter(Scan.status == "completed").count()

    finding_q = _user_filter(db.query(Finding), Finding, current_user)
    total_findings: int = finding_q.count()
    open_findings: int = finding_q.filter(Finding.status == "open").count()
    false_positives: int = finding_q.filter(Finding.is_false_positive.is_(True)).count()

    severity_counts: Dict[str, int] = {}
    for severity_value, count in (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.user_id == current_user.id if current_user.role != "admin" else True)
        .group_by(Finding.severity)
        .all()
    ):
        severity_counts[severity_value] = count

    breakdown = SeverityBreakdown(
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
        info=severity_counts.get("info", 0),
    )

    return DashboardStats(
        total_targets=total_targets,
        active_targets=active_targets,
        total_scans=total_scans,
        running_scans=running_scans,
        completed_scans=completed_scans,
        total_findings=total_findings,
        open_findings=open_findings,
        critical_findings=severity_counts.get("critical", 0),
        high_findings=severity_counts.get("high", 0),
        false_positives=false_positives,
        severity_breakdown=breakdown,
    )


@router.get("/recent-scans")
def get_recent_scans(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return the 10 most recently created scans for the current user."""
    query = _user_filter(db.query(Scan), Scan, current_user)
    scans = query.order_by(Scan.created_at.desc()).limit(10).all()
    return [
        {
            "id": str(s.id),
            "name": s.name,
            "status": s.status,
            "scan_type": s.scan_type,
            "progress": s.progress,
            "findings_count": s.findings_count,
            "target_id": str(s.target_id),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "created_at": s.created_at.isoformat(),
        }
        for s in scans
    ]


@router.get("/recent-findings")
def get_recent_findings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return the 10 most recently discovered findings for the current user."""
    query = _user_filter(db.query(Finding), Finding, current_user)
    findings = query.order_by(Finding.created_at.desc()).limit(10).all()
    return [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "owasp_category": f.owasp_category,
            "tool_name": f.tool_name,
            "url": f.url,
            "cvss_score": f.cvss_score,
            "scan_id": str(f.scan_id),
            "target_id": str(f.target_id),
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]


@router.get("/activity")
def get_activity(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return an activity feed of scans and findings created in the last 7 days."""
    since = datetime.now(timezone.utc) - timedelta(days=7)

    scan_q = _user_filter(db.query(Scan), Scan, current_user)
    recent_scans = (
        scan_q.filter(Scan.created_at >= since).order_by(Scan.created_at.desc()).all()
    )

    finding_q = _user_filter(db.query(Finding), Finding, current_user)
    recent_findings = (
        finding_q.filter(Finding.created_at >= since).order_by(Finding.created_at.desc()).all()
    )

    events: List[Dict[str, Any]] = []
    for s in recent_scans:
        events.append(
            {
                "type": "scan",
                "event": f"Scan '{s.name}' {s.status}",
                "id": str(s.id),
                "status": s.status,
                "timestamp": s.created_at.isoformat(),
            }
        )
    for f in recent_findings:
        events.append(
            {
                "type": "finding",
                "event": f"Finding '{f.title}' ({f.severity}) discovered",
                "id": str(f.id),
                "severity": f.severity,
                "timestamp": f.created_at.isoformat(),
            }
        )

    events.sort(key=lambda x: x["timestamp"], reverse=True)
    return events


@router.get("/owasp-breakdown")
def get_owasp_breakdown(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> List[OWASPBreakdown]:
    """Return finding counts broken down by OWASP Top 10 2021 category."""
    finding_q = _user_filter(db.query(Finding), Finding, current_user)
    total_findings: int = finding_q.count()

    rows = (
        finding_q.filter(Finding.owasp_category.isnot(None))
        .with_entities(Finding.owasp_category, func.count(Finding.id))
        .group_by(Finding.owasp_category)
        .all()
    )

    counts: Dict[str, int] = {row[0]: row[1] for row in rows}
    result: List[OWASPBreakdown] = []
    for code, label in _OWASP_LABELS.items():
        count = counts.get(code, 0)
        percentage = round((count / total_findings * 100), 2) if total_findings > 0 else 0.0
        result.append(OWASPBreakdown(category=code, label=label, count=count, percentage=percentage))

    result.sort(key=lambda x: x.count, reverse=True)
    return result
