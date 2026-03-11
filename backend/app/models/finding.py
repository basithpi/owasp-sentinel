import uuid
from typing import Optional

from sqlalchemy import Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import BaseModelMixin


class Finding(BaseModelMixin, Base):
    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", "info", name="finding_severity"),
        nullable=False,
        index=True,
    )
    owasp_category: Mapped[Optional[str]] = mapped_column(
        String(10), nullable=True, index=True
    )
    cwe_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    payload_used: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        Enum(
            "open", "confirmed", "false_positive", "fixed",
            name="finding_status",
        ),
        nullable=False,
        default="open",
        index=True,
    )
    tool_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    raw_output: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    scan: Mapped["Scan"] = relationship(  # noqa: F821
        "Scan", back_populates="findings", foreign_keys=[scan_id]
    )
    target: Mapped["Target"] = relationship(  # noqa: F821
        "Target", back_populates="findings", foreign_keys=[target_id]
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} title={self.title} severity={self.severity}>"
