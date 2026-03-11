from abc import ABC, abstractmethod
from typing import List, Dict, Any

from ..tools.base import Finding


class BaseOWASPModule(ABC):
    category: str = ""
    name: str = ""
    description: str = ""
    tools: List[str] = []

    @abstractmethod
    async def scan(self, target: str, config: Dict[str, Any]) -> List[Finding]:
        """Run the OWASP module scan against target."""
        pass

    def get_default_config(self) -> Dict[str, Any]:
        return {
            "timeout": 300,
            "severity": ["critical", "high", "medium"],
            "tools": self.tools,
        }

    async def run_tool(self, tool_name: str, target: str, config: Dict[str, Any]) -> List[Finding]:
        from ..tools.registry import registry
        tool = registry.create(tool_name)
        if not tool:
            return []
        try:
            result = await tool.execute(target, config)
            return result.findings
        except Exception:
            return []
