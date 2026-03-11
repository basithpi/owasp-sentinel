import json
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class KatanaTool(BaseTool):
    name = "katana"
    category = "web-crawler"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        depth = config.get("depth", 3)
        cmd = ["katana", "-u", target, "-json", "-d", str(depth), "-silent"]
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
                url = data.get("request", {}).get("endpoint", data.get("endpoint", line.strip()))
                findings.append(Finding(
                    title=f"URL discovered: {url}",
                    description=f"Web crawler discovered URL: {url}",
                    severity=FindingSeverity.INFO,
                    url=url,
                    tool_name="katana",
                    raw_output=data,
                ))
            except json.JSONDecodeError:
                url = line.strip()
                if url:
                    findings.append(Finding(
                        title=f"URL discovered: {url}",
                        description=f"Web crawler discovered URL: {url}",
                        severity=FindingSeverity.INFO,
                        url=url,
                        tool_name="katana",
                        raw_output={},
                    ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["katana", "-version"])
        if returncode == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="katana not found")
