from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    format: Mapped[str] = mapped_column(
        Enum("pdf", "html", "json", "markdown", name="report_format"),
        nullable=False,
        default="pdf",
    )
    template: Mapped[str] = mapped_column(String(100), default="default", nullable=False)
    scan_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    finding_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    content_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(
        Enum("pending", "generating", "completed", "failed", name="report_status"),
        nullable=False,
        default="pending",
    )
    generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="reports")

    def __repr__(self) -> str:
        return f"<Report id={self.id} name={self.name} format={self.format}>"
