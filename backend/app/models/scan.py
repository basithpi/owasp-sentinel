import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import BaseModelMixin, TimestampMixin, UUIDPrimaryKeyMixin


class Scan(BaseModelMixin, Base):
    __tablename__ = "scans"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "pending", "running", "completed", "failed", "cancelled",
            name="scan_status",
        ),
        nullable=False,
        default="pending",
        index=True,
    )
    scan_type: Mapped[str] = mapped_column(String(100), nullable=False)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    target: Mapped["Target"] = relationship(  # noqa: F821
        "Target", back_populates="scans", foreign_keys=[target_id]
    )
    creator: Mapped[Optional["User"]] = relationship(  # noqa: F821
        "User", back_populates="scans", foreign_keys=[created_by]
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="scan", foreign_keys="Finding.scan_id"
    )
    reports: Mapped[list["Report"]] = relationship(  # noqa: F821
        "Report", back_populates="scan", foreign_keys="Report.scan_id"
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} name={self.name} status={self.status}>"


class ScanSchedule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scan_schedules"

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    scan_type: Mapped[str] = mapped_column(String(100), nullable=False)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)
    last_run: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_run: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    target: Mapped["Target"] = relationship("Target")  # noqa: F821

    def __repr__(self) -> str:
        return f"<ScanSchedule id={self.id} target_id={self.target_id}>"
