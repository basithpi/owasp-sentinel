import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class SsrfmapTool(BaseTool):
    name = "ssrfmap"
    category = "ssrf"
    priority = "P1"
    SSRFMAP_PATH = "/opt/SSRFmap/ssrfmap.py"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        param = config.get("param", "url")
        request_file = config.get("request_file", "")
        if request_file and os.path.exists(request_file):
            cmd = ["python3", self.SSRFMAP_PATH, "-r", request_file, "-p", param]
        else:
            cmd = ["python3", self.SSRFMAP_PATH, "--target", target]
        rc, stdout, stderr = await self._run_command(cmd, timeout=120)
        findings = await self.parse_output(stdout + stderr)
        return ToolResult(success=True, findings=findings, raw_output=stdout)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        if "ssrf" in raw_output.lower() or "vulnerable" in raw_output.lower():
            findings.append(Finding(
                title="SSRF Vulnerability Detected",
                description="SSRFMap detected a Server-Side Request Forgery vulnerability",
                severity=FindingSeverity.HIGH,
                owasp_category="A01",
                tool_name="ssrfmap",
                raw_output={"output": raw_output[:2000]},
            ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        if os.path.exists(self.SSRFMAP_PATH):
            return HealthCheckResult(status=HealthStatus.HEALTHY, version="installed")
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message=f"{self.SSRFMAP_PATH} not found")
