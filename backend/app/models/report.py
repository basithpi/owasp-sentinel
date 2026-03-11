import uuid
from typing import Optional

from sqlalchemy import BigInteger, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import BaseModelMixin


class Report(BaseModelMixin, Base):
    __tablename__ = "reports"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    format: Mapped[str] = mapped_column(
        Enum("pdf", "html", "json", "markdown", name="report_format"),
        nullable=False,
        default="pdf",
    )
    status: Mapped[str] = mapped_column(
        Enum("generating", "completed", "failed", name="report_status"),
        nullable=False,
        default="generating",
        index=True,
    )
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship(  # noqa: F821
        "Scan", back_populates="reports", foreign_keys=[scan_id]
    )
    target: Mapped[Optional["Target"]] = relationship(  # noqa: F821
        "Target", foreign_keys=[target_id]
    )
    creator: Mapped[Optional["User"]] = relationship(  # noqa: F821
        "User", back_populates="reports", foreign_keys=[created_by]
    )

    def __repr__(self) -> str:
        return f"<Report id={self.id} name={self.name} format={self.format}>"
