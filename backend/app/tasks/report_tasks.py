"""Report generation Celery tasks for OWASP Sentinel v3.

Each task:
1. Queries findings from the DB (synchronous SQLAlchemy).
2. Renders content (HTML via Jinja2, PDF via WeasyPrint, JSON, Markdown).
3. Uploads the file to MinIO object storage.
4. Updates the ``reports`` table with the file path, size, and status.
"""
import io
import json
import logging
import os
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader

from ..config import settings
from ..models.finding import Finding
from ..models.report import Report
from ..models.scan import Scan
from ..models.target import Target
from ._sync_db import get_sync_session
from .celery_app import celery_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Template environment
# ---------------------------------------------------------------------------

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=True,
)

# ---------------------------------------------------------------------------
# MinIO helper
# ---------------------------------------------------------------------------


def _get_minio_client():
    """Return a configured MinIO client, creating the reports bucket if needed."""
    from minio import Minio
    from minio.error import S3Error

    client = Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )
    try:
        if not client.bucket_exists(settings.minio_bucket_reports):
            client.make_bucket(settings.minio_bucket_reports)
    except S3Error as exc:
        logger.warning("MinIO bucket check/create failed: %s", exc)
    return client


def _upload_to_minio(
    content: bytes,
    object_name: str,
    content_type: str,
) -> str:
    """Upload *content* to MinIO and return the object path."""
    client = _get_minio_client()
    client.put_object(
        settings.minio_bucket_reports,
        object_name,
        io.BytesIO(content),
        length=len(content),
        content_type=content_type,
    )
    return f"{settings.minio_bucket_reports}/{object_name}"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _load_report_data(
    report_id: str,
    scan_id: Optional[str],
    target_id: Optional[str],
) -> Dict[str, Any]:
    """Load report, scan, target, and findings from the DB."""
    with get_sync_session() as db:
        report = db.query(Report).filter(Report.id == report_id).first()
        if report is None:
            raise ValueError(f"Report {report_id} not found")

        scan = None
        if scan_id:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()

        target = None
        if target_id:
            target = db.query(Target).filter(Target.id == target_id).first()

        # Build finding query
        query = db.query(Finding)
        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)
        elif target_id:
            query = query.filter(Finding.target_id == target_id)
        findings = query.order_by(Finding.severity).all()

        # Detach from session by converting to plain dicts
        findings_data = [_finding_to_dict(f) for f in findings]
        report_data = _report_to_dict(report)
        scan_data = _scan_to_dict(scan) if scan else None
        target_data = _target_to_dict(target) if target else None

    return {
        "report": report_data,
        "scan": scan_data,
        "target": target_data,
        "findings": findings_data,
    }


def _update_report_status(
    report_id: str,
    status: str,
    file_path: Optional[str] = None,
    file_size: Optional[int] = None,
    error: Optional[str] = None,
) -> None:
    with get_sync_session() as db:
        report = db.query(Report).filter(Report.id == report_id).first()
        if report is None:
            return
        report.status = status
        if file_path:
            report.file_path = file_path
        if file_size is not None:
            report.file_size = file_size


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    return {
        "id": str(f.id),
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "owasp_category": f.owasp_category,
        "cwe_id": f.cwe_id,
        "cvss_score": f.cvss_score,
        "url": f.url,
        "parameter": f.parameter,
        "payload_used": f.payload_used,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "status": f.status,
        "tool_name": f.tool_name,
        "raw_output": f.raw_output,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def _report_to_dict(r: Report) -> Dict[str, Any]:
    return {
        "id": str(r.id),
        "name": r.name,
        "format": r.format,
        "status": r.status,
        "config": r.config or {},
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _scan_to_dict(s: Scan) -> Dict[str, Any]:
    return {
        "id": str(s.id),
        "name": s.name,
        "status": s.status,
        "scan_type": s.scan_type,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
    }


def _target_to_dict(t: Target) -> Dict[str, Any]:
    return {"id": str(t.id), "name": t.name, "url": t.url}


# ---------------------------------------------------------------------------
# Shared rendering context builder
# ---------------------------------------------------------------------------


def _build_template_context(data: Dict[str, Any]) -> Dict[str, Any]:
    findings = data["findings"]
    severity_counts = Counter(f["severity"] for f in findings)
    return {
        "report": data["report"],
        "scan": data["scan"],
        "target": data["target"],
        "findings": findings,
        "severity_counts": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


# ---------------------------------------------------------------------------
# PDF Report
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="report_tasks.generate_pdf_report")
def generate_pdf_report(
    self,
    report_id: str,
    scan_id: Optional[str],
    target_id: Optional[str],
) -> Dict[str, Any]:
    """Generate a PDF report from the HTML template using WeasyPrint.

    Steps:
    1. Load findings / scan / target from DB.
    2. Render the Jinja2 HTML template.
    3. Convert HTML → PDF with WeasyPrint.
    4. Upload PDF to MinIO.
    5. Update ``reports`` record with path, size, and ``completed`` status.
    """
    logger.info("generate_pdf_report: report_id=%s", report_id)
    try:
        data = _load_report_data(report_id, scan_id, target_id)
        ctx = _build_template_context(data)

        # Render HTML
        template = _jinja_env.get_template("report.html")
        html_content = template.render(**ctx)

        # Convert to PDF
        from weasyprint import HTML as WeasyprintHTML

        pdf_bytes = WeasyprintHTML(string=html_content).write_pdf()

        # Upload to MinIO
        object_name = f"reports/{report_id}/report.pdf"
        file_path = _upload_to_minio(pdf_bytes, object_name, "application/pdf")

        _update_report_status(
            report_id,
            status="completed",
            file_path=file_path,
            file_size=len(pdf_bytes),
        )

        logger.info("generate_pdf_report: completed, size=%d bytes", len(pdf_bytes))
        return {
            "report_id": report_id,
            "format": "pdf",
            "status": "completed",
            "file_path": file_path,
            "file_size": len(pdf_bytes),
        }

    except Exception as exc:
        logger.exception("generate_pdf_report failed: %s", exc)
        _update_report_status(report_id, status="failed")
        raise self.retry(exc=exc, countdown=30)


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="report_tasks.generate_html_report")
def generate_html_report(
    self,
    report_id: str,
    scan_id: Optional[str],
    target_id: Optional[str],
) -> Dict[str, Any]:
    """Generate an HTML report from the Jinja2 template."""
    logger.info("generate_html_report: report_id=%s", report_id)
    try:
        data = _load_report_data(report_id, scan_id, target_id)
        ctx = _build_template_context(data)

        template = _jinja_env.get_template("report.html")
        html_content = template.render(**ctx)
        html_bytes = html_content.encode("utf-8")

        object_name = f"reports/{report_id}/report.html"
        file_path = _upload_to_minio(html_bytes, object_name, "text/html; charset=utf-8")

        _update_report_status(
            report_id,
            status="completed",
            file_path=file_path,
            file_size=len(html_bytes),
        )

        logger.info("generate_html_report: completed, size=%d bytes", len(html_bytes))
        return {
            "report_id": report_id,
            "format": "html",
            "status": "completed",
            "file_path": file_path,
            "file_size": len(html_bytes),
        }

    except Exception as exc:
        logger.exception("generate_html_report failed: %s", exc)
        _update_report_status(report_id, status="failed")
        raise self.retry(exc=exc, countdown=30)


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="report_tasks.generate_json_report")
def generate_json_report(
    self,
    report_id: str,
    scan_id: Optional[str],
    target_id: Optional[str],
) -> Dict[str, Any]:
    """Generate a JSON report containing all findings data."""
    logger.info("generate_json_report: report_id=%s", report_id)
    try:
        data = _load_report_data(report_id, scan_id, target_id)
        ctx = _build_template_context(data)

        report_payload = {
            "report": ctx["report"],
            "scan": ctx["scan"],
            "target": ctx["target"],
            "generated_at": ctx["generated_at"],
            "severity_summary": ctx["severity_counts"],
            "total_findings": len(ctx["findings"]),
            "findings": ctx["findings"],
        }

        json_bytes = json.dumps(report_payload, indent=2, default=str).encode("utf-8")
        object_name = f"reports/{report_id}/report.json"
        file_path = _upload_to_minio(json_bytes, object_name, "application/json")

        _update_report_status(
            report_id,
            status="completed",
            file_path=file_path,
            file_size=len(json_bytes),
        )

        logger.info("generate_json_report: completed, size=%d bytes", len(json_bytes))
        return {
            "report_id": report_id,
            "format": "json",
            "status": "completed",
            "file_path": file_path,
            "file_size": len(json_bytes),
        }

    except Exception as exc:
        logger.exception("generate_json_report failed: %s", exc)
        _update_report_status(report_id, status="failed")
        raise self.retry(exc=exc, countdown=30)


# ---------------------------------------------------------------------------
# Markdown Report
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="report_tasks.generate_markdown_report")
def generate_markdown_report(
    self,
    report_id: str,
    scan_id: Optional[str],
    target_id: Optional[str],
) -> Dict[str, Any]:
    """Generate a Markdown report."""
    logger.info("generate_markdown_report: report_id=%s", report_id)
    try:
        data = _load_report_data(report_id, scan_id, target_id)
        ctx = _build_template_context(data)

        lines: List[str] = []

        lines.append(f"# {ctx['report']['name']}")
        lines.append("")
        lines.append(f"> Generated: {ctx['generated_at']}")
        lines.append("")

        if ctx["target"]:
            t = ctx["target"]
            lines.append(f"**Target:** {t['name']} — `{t['url']}`")
            lines.append("")

        if ctx["scan"]:
            s = ctx["scan"]
            lines.append(f"**Scan:** {s['name']} | Status: `{s['status']}`")
            lines.append("")

        # Severity summary table
        sc = ctx["severity_counts"]
        lines.append("## Severity Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {sev.capitalize()} | {sc[sev]} |")
        lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")

        for sev in ("critical", "high", "medium", "low", "info"):
            sev_findings = [f for f in ctx["findings"] if f["severity"] == sev]
            if not sev_findings:
                continue
            lines.append(f"### {sev.upper()} ({len(sev_findings)})")
            lines.append("")
            for f in sev_findings:
                lines.append(f"#### {f['title']}")
                lines.append("")
                if f.get("url"):
                    lines.append(f"- **URL:** `{f['url']}`")
                if f.get("description"):
                    lines.append(f"- **Description:** {f['description']}")
                if f.get("owasp_category"):
                    lines.append(f"- **OWASP:** {f['owasp_category']}")
                if f.get("cwe_id"):
                    lines.append(f"- **CWE:** CWE-{f['cwe_id']}")
                if f.get("cvss_score"):
                    lines.append(f"- **CVSS:** {f['cvss_score']}")
                if f.get("parameter"):
                    lines.append(f"- **Parameter:** `{f['parameter']}`")
                if f.get("payload_used"):
                    lines.append(f"- **Payload:** `{f['payload_used']}`")
                if f.get("tool_name"):
                    lines.append(f"- **Tool:** {f['tool_name']}")
                if f.get("remediation"):
                    lines.append(f"- **Remediation:** {f['remediation']}")
                if f.get("evidence"):
                    lines.append("")
                    lines.append("**Evidence:**")
                    lines.append("```")
                    lines.append(str(f["evidence"]))
                    lines.append("```")
                lines.append("")

        lines.append("---")
        lines.append(
            "_This report was generated automatically by OWASP Sentinel v3. "
            "Results should be validated by a qualified security professional._"
        )

        md_content = "\n".join(lines)
        md_bytes = md_content.encode("utf-8")

        object_name = f"reports/{report_id}/report.md"
        file_path = _upload_to_minio(md_bytes, object_name, "text/markdown; charset=utf-8")

        _update_report_status(
            report_id,
            status="completed",
            file_path=file_path,
            file_size=len(md_bytes),
        )

        logger.info("generate_markdown_report: completed, size=%d bytes", len(md_bytes))
        return {
            "report_id": report_id,
            "format": "markdown",
            "status": "completed",
            "file_path": file_path,
            "file_size": len(md_bytes),
        }

    except Exception as exc:
        logger.exception("generate_markdown_report failed: %s", exc)
        _update_report_status(report_id, status="failed")
        raise self.retry(exc=exc, countdown=30)
