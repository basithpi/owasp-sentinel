import json
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class HttpxTool(BaseTool):
    name = "httpx"
    category = "http-probe"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        cmd = ["httpx", "-u", target, "-json", "-title", "-status-code", "-tech-detect", "-silent"]
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
                url = data.get("url", target if hasattr(self, "_current_target") else "")
                status_code = data.get("status-code", data.get("status_code", 0))
                title = data.get("title", "")
                technologies = data.get("technologies", data.get("tech", []))

                severity = FindingSeverity.INFO
                description_parts = [f"Status: {status_code}", f"Title: {title}"]
                if technologies:
                    description_parts.append(f"Technologies: {', '.join(technologies)}")

                findings.append(Finding(
                    title=f"HTTP probe: {url} [{status_code}]",
                    description="\n".join(description_parts),
                    severity=severity,
                    url=url,
                    tool_name="httpx",
                    raw_output=data,
                ))
            except json.JSONDecodeError:
                continue
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["httpx", "-version"])
        if returncode == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="httpx not found")
