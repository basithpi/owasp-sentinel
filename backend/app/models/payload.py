from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, String, Text, func
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base
from .base import UUIDPrimaryKeyMixin


class Payload(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "payloads"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(
        Enum(
            "sqli", "xss", "cmd", "ssti", "ssrf", "xxe",
            "lfi", "rfi", "idor", "auth", "csrf", "other",
            name="payload_category",
        ),
        nullable=False,
        index=True,
    )
    subcategory: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        return f"<Payload id={self.id} name={self.name} category={self.category}>"
