from __future__ import annotations

import asyncio
import subprocess
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.tool import Tool
from app.schemas.tool import ToolCreate, ToolUpdate


class ToolService:
    def __init__(self, db: Session):
        self.db = db

    def list_tools(self, offset: int = 0, limit: int = 50) -> tuple[List[Tool], int]:
        query = self.db.query(Tool)
        total = query.count()
        tools = query.order_by(Tool.name).offset(offset).limit(limit).all()
        return tools, total

    def get_tool(self, tool_id: uuid.UUID) -> Tool:
        tool = self.db.query(Tool).filter(Tool.id == tool_id).first()
        if not tool:
            raise NotFoundError(f"Tool {tool_id} not found")
        return tool

    def get_tool_by_name(self, name: str) -> Optional[Tool]:
        return self.db.query(Tool).filter(Tool.name == name).first()

    def create_tool(self, data: ToolCreate) -> Tool:
        tool = Tool(
            name=data.name,
            version=data.version,
            description=data.description,
            category=data.category,
            docker_image=data.docker_image,
            is_enabled=data.is_enabled,
            config=data.config,
            priority=data.priority,
        )
        self.db.add(tool)
        self.db.commit()
        self.db.refresh(tool)
        return tool

    def update_tool(self, tool_id: uuid.UUID, data: ToolUpdate) -> Tool:
        tool = self.get_tool(tool_id)
        update_data = data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(tool, key, value)
        self.db.commit()
        self.db.refresh(tool)
        return tool

    def check_tool_health(self, tool_name: str) -> dict:
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            is_available = result.returncode == 0
            return {
                "is_healthy": is_available,
                "version": None,
                "message": "Tool available" if is_available else "Tool not found",
            }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return {"is_healthy": False, "version": None, "message": "Health check failed"}

    def update_health_status(self, tool_id: uuid.UUID, health: dict) -> Tool:
        tool = self.get_tool(tool_id)
        tool.health_status = "healthy" if health.get("is_healthy") else "unhealthy"
        tool.is_available = health.get("is_healthy", False)
        tool.last_health_check = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(tool)
        return tool
