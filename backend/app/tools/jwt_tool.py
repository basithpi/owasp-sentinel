import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class JwtToolTool(BaseTool):
    name = "jwt_tool"
    category = "authentication"
    priority = "P1"
    JWT_TOOL_PATH = "/opt/jwt_tool/jwt_tool.py"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        token = config.get("token", "")
        if not token:
            return ToolResult(success=False, findings=[], raw_output="", error="No JWT token provided")
        cmd = ["python3", self.JWT_TOOL_PATH, token, "-t", target, "-M", "at"]
        rc, stdout, stderr = await self._run_command(cmd, timeout=60)
        findings = await self.parse_output(stdout + stderr)
        return ToolResult(success=True, findings=findings, raw_output=stdout)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        vuln_keywords = {
            "alg:none": (FindingSeverity.CRITICAL, "JWT Algorithm None Attack"),
            "rsa/hmac": (FindingSeverity.CRITICAL, "JWT Algorithm Confusion Attack"),
            "expired": (FindingSeverity.MEDIUM, "JWT Token Expired but Accepted"),
            "weak secret": (FindingSeverity.HIGH, "JWT Weak Secret"),
        }
        lower = raw_output.lower()
        for keyword, (severity, title) in vuln_keywords.items():
            if keyword in lower:
                findings.append(Finding(
                    title=title,
                    description=f"JWT vulnerability detected: {title}",
                    severity=severity,
                    owasp_category="A07",
                    tool_name="jwt_tool",
                    raw_output={"output": raw_output[:2000]},
                ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        if os.path.exists(self.JWT_TOOL_PATH):
            return HealthCheckResult(status=HealthStatus.HEALTHY, version="installed")
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message=f"{self.JWT_TOOL_PATH} not found")
