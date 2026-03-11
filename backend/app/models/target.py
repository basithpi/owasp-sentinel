import uuid
from typing import Optional

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import BaseModelMixin


class Target(BaseModelMixin, Base):
    __tablename__ = "targets"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_type: Mapped[str] = mapped_column(
        Enum("url", "ip", "domain", "cidr", name="target_type"),
        nullable=False,
        default="url",
    )
    status: Mapped[str] = mapped_column(
        Enum("active", "archived", "testing", name="target_status"),
        nullable=False,
        default="active",
        index=True,
    )
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    creator: Mapped[Optional["User"]] = relationship(  # noqa: F821
        "User", back_populates="targets", foreign_keys=[created_by]
    )
    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        "Scan", back_populates="target", foreign_keys="Scan.target_id"
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="target", foreign_keys="Finding.target_id"
    )
    monitors: Mapped[list["Monitor"]] = relationship(  # noqa: F821
        "Monitor", back_populates="target", foreign_keys="Monitor.target_id"
    )

    def __repr__(self) -> str:
        return f"<Target id={self.id} name={self.name}>"
