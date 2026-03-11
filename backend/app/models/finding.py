from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", "info", name="finding_severity"),
        nullable=False,
    )
    confidence: Mapped[str] = mapped_column(
        Enum("certain", "firm", "tentative", name="finding_confidence"),
        nullable=False,
        default="firm",
    )
    owasp_category: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    cwe_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    reproduction_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    payload_used: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    duplicate_of_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        Enum("open", "confirmed", "fixed", "accepted", "wontfix", name="finding_status"),
        nullable=False,
        default="open",
    )
    ai_analysis: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    target: Mapped["Target"] = relationship("Target", back_populates="findings")
    user: Mapped["User"] = relationship("User", back_populates="findings")
    duplicate_of: Mapped[Optional["Finding"]] = relationship("Finding", remote_side="Finding.id", foreign_keys=[duplicate_of_id])

    def __repr__(self) -> str:
        return f"<Finding id={self.id} title={self.title} severity={self.severity}>"
