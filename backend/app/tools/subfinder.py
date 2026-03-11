import json
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class SubfinderTool(BaseTool):
    name = "subfinder"
    category = "subdomain-enumeration"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        cmd = ["subfinder", "-d", target, "-json", "-silent"]
        returncode, stdout, stderr = await self._run_command(cmd)
        findings = await self.parse_output(stdout)
        return ToolResult(
            success=returncode == 0,
            findings=findings,
            raw_output=stdout,
            error=stderr if returncode != 0 else None,
        )

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                subdomain = data.get("host", data.get("subdomain", line.strip()))
                findings.append(Finding(
                    title=f"Subdomain discovered: {subdomain}",
                    description=f"Subdomain {subdomain} was discovered via passive enumeration.",
                    severity=FindingSeverity.INFO,
                    url=subdomain,
                    tool_name="subfinder",
                    raw_output=data,
                ))
            except json.JSONDecodeError:
                sub = line.strip()
                if sub:
                    findings.append(Finding(
                        title=f"Subdomain discovered: {sub}",
                        description=f"Subdomain {sub} was discovered.",
                        severity=FindingSeverity.INFO,
                        url=sub,
                        tool_name="subfinder",
                        raw_output={},
                    ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["subfinder", "-version"])
        if returncode == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="subfinder not found")
