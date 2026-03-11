import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import BaseModelMixin


class Monitor(BaseModelMixin, Base):
    __tablename__ = "monitors"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    monitor_type: Mapped[str] = mapped_column(
        Enum(
            "subdomain", "cert", "technology", "uptime",
            name="monitor_type",
        ),
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)
    last_check: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    alert_on_change: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    target: Mapped["Target"] = relationship(  # noqa: F821
        "Target", back_populates="monitors", foreign_keys=[target_id]
    )
    creator: Mapped[Optional["User"]] = relationship(  # noqa: F821
        "User", foreign_keys=[created_by]
    )

    def __repr__(self) -> str:
        return f"<Monitor id={self.id} name={self.name} type={self.monitor_type}>"
