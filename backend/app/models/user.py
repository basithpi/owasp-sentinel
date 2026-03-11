import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .base import BaseModelMixin


class User(BaseModelMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    username: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    role: Mapped[str] = mapped_column(
        Enum("admin", "analyst", "viewer", name="user_role"),
        default="analyst",
        nullable=False,
    )

    # Relationships
    targets: Mapped[list["Target"]] = relationship(  # noqa: F821
        "Target", back_populates="creator", foreign_keys="Target.created_by"
    )
    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        "Scan", back_populates="creator", foreign_keys="Scan.created_by"
    )
    reports: Mapped[list["Report"]] = relationship(  # noqa: F821
        "Report", back_populates="creator", foreign_keys="Report.created_by"
    )
    notifications: Mapped[list["Notification"]] = relationship(  # noqa: F821
        "Notification", back_populates="user", foreign_keys="Notification.user_id"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"
