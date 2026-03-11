from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    scan_type: Mapped[str] = mapped_column(
        Enum("full", "recon", "vuln_scan", "specific_tool", name="scan_type"),
        nullable=False,
        default="full",
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        Enum("pending", "running", "paused", "completed", "failed", "cancelled", name="scan_status"),
        nullable=False,
        default="pending",
    )
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="scans")
    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="scan", lazy="select")

    def __repr__(self) -> str:
        return f"<Scan id={self.id} name={self.name} status={self.status}>"
