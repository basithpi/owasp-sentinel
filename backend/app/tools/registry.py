from typing import Dict, Type, Optional
from .base import BaseTool


class ToolRegistry:
    _registry: Dict[str, Type[BaseTool]] = {}

    @classmethod
    def register(cls, tool_class: Type[BaseTool]) -> Type[BaseTool]:
        cls._registry[tool_class.name] = tool_class
        return tool_class

    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseTool]]:
        return cls._registry.get(name)

    @classmethod
    def create(cls, name: str) -> Optional[BaseTool]:
        tool_class = cls.get(name)
        return tool_class() if tool_class else None

    @classmethod
    def list_all(cls) -> list:
        return list(cls._registry.keys())


registry = ToolRegistry()
