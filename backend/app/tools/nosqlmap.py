import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class NoSqlMapTool(BaseTool):
    name = "nosqlmap"
    category = "nosql-injection"
    priority = "P1"
    NOSQLMAP_PATH = "/opt/NoSQLMap/nosqlmap.py"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        cmd = ["python3", self.NOSQLMAP_PATH, "--attack", "2", "--victim", target, "--httpMethod", "GET"]
        rc, stdout, stderr = await self._run_command(cmd, timeout=120)
        findings = await self.parse_output(stdout + stderr)
        return ToolResult(success=True, findings=findings, raw_output=stdout)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        if "injection" in raw_output.lower() or "vulnerable" in raw_output.lower():
            findings.append(Finding(
                title="NoSQL Injection Vulnerability",
                description="NoSQLMap detected a NoSQL injection vulnerability",
                severity=FindingSeverity.HIGH,
                owasp_category="A05",
                tool_name="nosqlmap",
                raw_output={"output": raw_output[:2000]},
            ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        if os.path.exists(self.NOSQLMAP_PATH):
            return HealthCheckResult(status=HealthStatus.HEALTHY, version="installed")
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message=f"{self.NOSQLMAP_PATH} not found")
