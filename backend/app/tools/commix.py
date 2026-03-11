import json
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class CommixTool(BaseTool):
    name = "commix"
    category = "command-injection"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        cmd = ["commix", f"--url={target}", "--batch", "--all"]
        rc, stdout, stderr = await self._run_command(cmd, timeout=120)
        findings = await self.parse_output(stdout + stderr)
        return ToolResult(success=True, findings=findings, raw_output=stdout)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        if "is vulnerable" in raw_output.lower() or "command injection" in raw_output.lower():
            findings.append(Finding(
                title="Command Injection Vulnerability",
                description="Commix detected command injection vulnerability",
                severity=FindingSeverity.CRITICAL,
                owasp_category="A05",
                tool_name="commix",
                raw_output={"output": raw_output[:2000]},
            ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["commix", "--version"])
        if rc == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="commix not found")
