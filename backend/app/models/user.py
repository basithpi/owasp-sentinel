from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Enum, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(
        Enum("admin", "analyst", "viewer", name="user_role"),
        nullable=False,
        default="analyst",
    )
    api_key: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    preferences: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    targets: Mapped[List["Target"]] = relationship("Target", back_populates="user", lazy="select")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="user", lazy="select")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="user", lazy="select")
    payloads: Mapped[List["Payload"]] = relationship("Payload", back_populates="user", lazy="select")
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="user", lazy="select")
    notifications: Mapped[List["Notification"]] = relationship("Notification", back_populates="user", lazy="select")

    __table_args__ = (
        Index("ix_users_email", "email"),
        Index("ix_users_username", "username"),
        Index("ix_users_api_key", "api_key"),
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"
