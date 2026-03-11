from __future__ import annotations

import io
import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.schemas.report import ReportCreate


class ReportService:
    def __init__(self, db: Session):
        self.db = db

    def create_report(self, data: ReportCreate, user: User) -> Report:
        report = Report(
            user_id=user.id,
            name=data.name,
            format=data.format,
            template=data.template,
            scan_ids=[str(sid) for sid in data.scan_ids],
            finding_ids=[str(fid) for fid in data.finding_ids],
            status="pending",
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def get_report(self, report_id: uuid.UUID, user: User) -> Report:
        report = self.db.query(Report).filter(Report.id == report_id).first()
        if not report:
            raise NotFoundError(f"Report {report_id} not found")
        if report.user_id != user.id and user.role != "admin":
            from app.core.exceptions import ForbiddenError
            raise ForbiddenError("Access denied")
        return report

    def list_reports(self, user: User, offset: int = 0, limit: int = 20) -> tuple[List[Report], int]:
        query = self.db.query(Report)
        if user.role != "admin":
            query = query.filter(Report.user_id == user.id)
        total = query.count()
        reports = query.order_by(Report.created_at.desc()).offset(offset).limit(limit).all()
        return reports, total

    def generate_json_report(self, report: Report, findings: List[Finding]) -> str:
        data = {
            "report_id": str(report.id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(findings),
                "by_severity": {},
            },
            "findings": [],
        }
        for f in findings:
            data["summary"]["by_severity"][f.severity] = (
                data["summary"]["by_severity"].get(f.severity, 0) + 1
            )
            data["findings"].append({
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "owasp_category": f.owasp_category,
                "cvss_score": f.cvss_score,
                "status": f.status,
                "url": f.url,
                "description": f.description,
                "remediation": f.remediation,
            })
        return json.dumps(data, indent=2)

    def generate_markdown_report(self, report: Report, findings: List[Finding]) -> str:
        lines = [
            f"# {report.name}",
            f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"\n## Summary\n",
            f"Total Findings: **{len(findings)}**\n",
        ]
        by_severity: dict = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        for sev, count in sorted(by_severity.items()):
            lines.append(f"- {sev.capitalize()}: {count}")

        lines.append("\n## Findings\n")
        for i, f in enumerate(findings, 1):
            lines.extend([
                f"### {i}. {f.title}",
                f"**Severity:** {f.severity.upper()} | **Status:** {f.status}",
                f"\n**Description:**\n{f.description}",
            ])
            if f.remediation:
                lines.append(f"\n**Remediation:**\n{f.remediation}")
            lines.append("---")
        return "\n".join(lines)

    def generate_pdf_report(self, report: Report, findings: List[Finding]) -> bytes:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            story.append(Paragraph(report.name, styles["Title"]))
            story.append(Spacer(1, 12))
            story.append(Paragraph(
                f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                styles["Normal"],
            ))
            story.append(Spacer(1, 24))

            severity_data = [["Severity", "Count"]]
            by_severity: dict = {}
            for f in findings:
                by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            for sev, count in sorted(by_severity.items()):
                severity_data.append([sev.capitalize(), str(count)])

            if len(severity_data) > 1:
                table = Table(severity_data)
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]))
                story.append(table)
                story.append(Spacer(1, 24))

            for f in findings:
                story.append(Paragraph(f.title, styles["Heading2"]))
                story.append(Paragraph(f"Severity: {f.severity.upper()}", styles["Normal"]))
                story.append(Paragraph(f.description, styles["Normal"]))
                story.append(Spacer(1, 12))

            doc.build(story)
            return buffer.getvalue()
        except ImportError:
            return b"PDF generation requires reportlab"

    def update_report_status(self, report_id: uuid.UUID, status: str, content_path: Optional[str] = None) -> None:
        report = self.db.query(Report).filter(Report.id == report_id).first()
        if report:
            report.status = status
            if content_path:
                report.content_path = content_path
            if status == "completed":
                report.generated_at = datetime.now(timezone.utc)
            self.db.commit()
