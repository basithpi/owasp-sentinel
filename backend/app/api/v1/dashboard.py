from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter
from sqlalchemy import case, func, select

from ...core.dependencies import CurrentUser, DB
from ...models.finding import Finding
from ...models.report import Report
from ...models.scan import Scan
from ...models.target import Target

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_dashboard_stats(
    db: DB,
    current_user: CurrentUser,
) -> Dict[str, Any]:
    """Overall platform statistics."""
    total_scans_result = await db.execute(select(func.count(Scan.id)))
    total_scans = total_scans_result.scalar_one()

    active_scans_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.status.in_(["pending", "running"]))
    )
    active_scans = active_scans_result.scalar_one()

    total_findings_result = await db.execute(select(func.count(Finding.id)))
    total_findings = total_findings_result.scalar_one()

    critical_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.severity == "critical")
    )
    critical_findings = critical_result.scalar_one()

    high_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.severity == "high")
    )
    high_findings = high_result.scalar_one()

    total_targets_result = await db.execute(select(func.count(Target.id)))
    total_targets = total_targets_result.scalar_one()

    total_reports_result = await db.execute(select(func.count(Report.id)))
    total_reports = total_reports_result.scalar_one()

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "total_targets": total_targets,
        "total_reports": total_reports,
    }


@router.get("/owasp-breakdown")
async def get_owasp_breakdown(
    db: DB,
    current_user: CurrentUser,
) -> List[Dict[str, Any]]:
    """Count findings grouped by OWASP category."""
    result = await db.execute(
        select(Finding.owasp_category, func.count(Finding.id).label("count"))
        .where(Finding.owasp_category.isnot(None))
        .group_by(Finding.owasp_category)
        .order_by(func.count(Finding.id).desc())
    )
    rows = result.all()
    return [{"owasp_category": row.owasp_category, "count": row.count} for row in rows]


@router.get("/severity-timeline")
async def get_severity_timeline(
    db: DB,
    current_user: CurrentUser,
) -> List[Dict[str, Any]]:
    """Number of findings per severity per day for the last 30 days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    day_col = func.date_trunc("day", Finding.created_at).label("day")
    result = await db.execute(
        select(
            day_col,
            Finding.severity,
            func.count(Finding.id).label("count"),
        )
        .where(Finding.created_at >= cutoff)
        .group_by(day_col, Finding.severity)
        .order_by(day_col, Finding.severity)
    )
    rows = result.all()
    return [
        {
            "day": row.day.date().isoformat() if row.day else None,
            "severity": row.severity,
            "count": row.count,
        }
        for row in rows
    ]


@router.get("/tool-effectiveness")
async def get_tool_effectiveness(
    db: DB,
    current_user: CurrentUser,
) -> List[Dict[str, Any]]:
    """Count findings produced by each tool."""
    result = await db.execute(
        select(
            Finding.tool_name,
            func.count(Finding.id).label("total_findings"),
            func.count(
                case((Finding.severity == "critical", Finding.id))
            ).label("critical"),
            func.count(
                case((Finding.severity == "high", Finding.id))
            ).label("high"),
        )
        .where(Finding.tool_name.isnot(None))
        .group_by(Finding.tool_name)
        .order_by(func.count(Finding.id).desc())
    )
    rows = result.all()
    return [
        {
            "tool_name": row.tool_name,
            "total_findings": row.total_findings,
            "critical": row.critical,
            "high": row.high,
        }
        for row in rows
    ]


@router.get("/recent-activity")
async def get_recent_activity(
    db: DB,
    current_user: CurrentUser,
) -> Dict[str, Any]:
    """Last 10 scans and last 10 findings."""
    scans_result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(10)
    )
    recent_scans = scans_result.scalars().all()

    findings_result = await db.execute(
        select(Finding).order_by(Finding.created_at.desc()).limit(10)
    )
    recent_findings = findings_result.scalars().all()

    return {
        "recent_scans": [
            {
                "id": str(scan.id),
                "name": scan.name,
                "status": scan.status,
                "scan_type": scan.scan_type,
                "target_id": str(scan.target_id),
                "created_at": scan.created_at.isoformat(),
            }
            for scan in recent_scans
        ],
        "recent_findings": [
            {
                "id": str(finding.id),
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "scan_id": str(finding.scan_id),
                "target_id": str(finding.target_id),
                "owasp_category": finding.owasp_category,
                "created_at": finding.created_at.isoformat(),
            }
            for finding in recent_findings
        ],
    }
