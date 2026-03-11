from __future__ import annotations

import hashlib
import uuid
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenError, NotFoundError
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingCreate, FindingStats, FindingUpdate


class FindingService:
    def __init__(self, db: Session):
        self.db = db

    def _compute_hash(self, finding: FindingCreate) -> str:
        content = f"{finding.title}:{finding.url}:{finding.parameter}:{finding.severity}"
        return hashlib.sha256(content.encode()).hexdigest()

    def create_finding(self, finding_data: FindingCreate, user: User) -> Finding:
        # Check for duplicate
        existing_hash = self._compute_hash(finding_data)
        existing = self.db.query(Finding).filter(
            Finding.scan_id == finding_data.scan_id,
            Finding.title == finding_data.title,
            Finding.url == finding_data.url,
        ).first()

        finding = Finding(
            scan_id=finding_data.scan_id,
            target_id=finding_data.target_id,
            user_id=user.id,
            title=finding_data.title,
            description=finding_data.description,
            severity=finding_data.severity,
            confidence=finding_data.confidence,
            owasp_category=finding_data.owasp_category,
            cwe_id=finding_data.cwe_id,
            cvss_score=finding_data.cvss_score,
            cvss_vector=finding_data.cvss_vector,
            tool_name=finding_data.tool_name,
            evidence=finding_data.evidence,
            reproduction_steps=finding_data.reproduction_steps,
            remediation=finding_data.remediation,
            url=finding_data.url,
            parameter=finding_data.parameter,
            payload_used=finding_data.payload_used,
            is_duplicate=existing is not None,
            duplicate_of_id=existing.id if existing else None,
        )
        self.db.add(finding)

        # Update scan findings count
        scan = self.db.query(Scan).filter(Scan.id == finding_data.scan_id).first()
        if scan:
            scan.findings_count = (scan.findings_count or 0) + 1

        self.db.commit()
        self.db.refresh(finding)
        return finding

    def get_finding(self, finding_id: uuid.UUID, user: User) -> Finding:
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise NotFoundError(f"Finding {finding_id} not found")
        if finding.user_id != user.id and user.role not in ("admin", "analyst"):
            raise ForbiddenError("Access denied")
        return finding

    def list_findings(
        self,
        user: User,
        offset: int = 0,
        limit: int = 20,
        severity: Optional[str] = None,
        owasp_category: Optional[str] = None,
        tool_name: Optional[str] = None,
        status: Optional[str] = None,
        scan_id: Optional[uuid.UUID] = None,
        target_id: Optional[uuid.UUID] = None,
        include_false_positives: bool = False,
    ) -> tuple[List[Finding], int]:
        query = self.db.query(Finding)
        if user.role != "admin":
            query = query.filter(Finding.user_id == user.id)
        if severity:
            query = query.filter(Finding.severity == severity)
        if owasp_category:
            query = query.filter(Finding.owasp_category == owasp_category)
        if tool_name:
            query = query.filter(Finding.tool_name == tool_name)
        if status:
            query = query.filter(Finding.status == status)
        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)
        if target_id:
            query = query.filter(Finding.target_id == target_id)
        if not include_false_positives:
            query = query.filter(Finding.is_false_positive.is_(False))
        total = query.count()
        findings = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()
        return findings, total

    def update_finding(self, finding_id: uuid.UUID, data: FindingUpdate, user: User) -> Finding:
        finding = self.get_finding(finding_id, user)
        update_data = data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(finding, key, value)
        self.db.commit()
        self.db.refresh(finding)
        return finding

    def mark_false_positive(self, finding_id: uuid.UUID, user: User) -> Finding:
        finding = self.get_finding(finding_id, user)
        finding.is_false_positive = not finding.is_false_positive
        self.db.commit()
        self.db.refresh(finding)
        return finding

    def update_status(self, finding_id: uuid.UUID, status: str, user: User) -> Finding:
        finding = self.get_finding(finding_id, user)
        finding.status = status
        self.db.commit()
        self.db.refresh(finding)
        return finding

    def get_stats(self, user: User, scan_id: Optional[uuid.UUID] = None) -> FindingStats:
        query = self.db.query(Finding)
        if user.role != "admin":
            query = query.filter(Finding.user_id == user.id)
        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)

        findings = query.all()
        total = len(findings)

        by_severity: Dict[str, int] = {}
        by_owasp: Dict[str, int] = {}
        by_tool: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            if f.owasp_category:
                by_owasp[f.owasp_category] = by_owasp.get(f.owasp_category, 0) + 1
            by_tool[f.tool_name] = by_tool.get(f.tool_name, 0) + 1
            by_status[f.status] = by_status.get(f.status, 0) + 1

        return FindingStats(
            total=total,
            by_severity=by_severity,
            by_owasp=by_owasp,
            by_tool=by_tool,
            by_status=by_status,
            false_positives=sum(1 for f in findings if f.is_false_positive),
            duplicates=sum(1 for f in findings if f.is_duplicate),
        )
