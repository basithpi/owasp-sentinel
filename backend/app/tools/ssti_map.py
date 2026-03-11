import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class SstiMapTool(BaseTool):
    name = "ssti_map"
    category = "template-injection"
    priority = "P1"
    TPLMAP_PATH = "/opt/tplmap/tplmap.py"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        cmd = ["python3", self.TPLMAP_PATH, "-u", target]
        rc, stdout, stderr = await self._run_command(cmd, timeout=120)
        findings = await self.parse_output(stdout + stderr)
        return ToolResult(success=True, findings=findings, raw_output=stdout)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        lower = raw_output.lower()
        if "template injection" in lower or "ssti" in lower or ("tplmap" in lower and "found" in lower):
            engine = "Unknown"
            for eng in ["Jinja2", "Twig", "Smarty", "Freemarker", "Velocity", "Mako", "ERB"]:
                if eng.lower() in lower:
                    engine = eng
                    break
            findings.append(Finding(
                title=f"Server-Side Template Injection ({engine})",
                description=f"tplmap detected SSTI vulnerability using {engine} engine",
                severity=FindingSeverity.CRITICAL,
                owasp_category="A05",
                tool_name="ssti_map",
                raw_output={"output": raw_output[:2000], "engine": engine},
            ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        if os.path.exists(self.TPLMAP_PATH):
            return HealthCheckResult(status=HealthStatus.HEALTHY, version="installed")
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message=f"{self.TPLMAP_PATH} not found")
