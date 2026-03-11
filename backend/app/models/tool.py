from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, String, Text, func
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base
from .base import BaseModelMixin


class Tool(BaseModelMixin, Base):
    __tablename__ = "tools"

    name: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True, index=True
    )
    version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_installed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_health_check: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_status: Mapped[str] = mapped_column(
        Enum(
            "healthy", "degraded", "unhealthy", "unknown",
            name="tool_health_status",
        ),
        nullable=False,
        default="unknown",
    )
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)

    def __repr__(self) -> str:
        return f"<Tool id={self.id} name={self.name} health={self.health_status}>"
