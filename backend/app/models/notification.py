import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Enum, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import UUIDPrimaryKeyMixin


class Notification(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "notifications"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(
        Enum("info", "warning", "error", "success", name="notification_type"),
        nullable=False,
        default="info",
    )
    category: Mapped[str] = mapped_column(
        Enum("scan", "finding", "system", "report", name="notification_category"),
        nullable=False,
        default="system",
        index=True,
    )
    reference_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    user: Mapped["User"] = relationship(  # noqa: F821
        "User", back_populates="notifications", foreign_keys=[user_id]
    )

    def __repr__(self) -> str:
        return f"<Notification id={self.id} user_id={self.user_id} is_read={self.is_read}>"
