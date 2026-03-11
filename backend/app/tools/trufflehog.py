import json
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class TrufflehogTool(BaseTool):
    name = "trufflehog"
    category = "secret-scanner"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        if target.startswith("http") or target.startswith("git"):
            cmd = ["trufflehog", "git", target, "--json", "--no-update"]
        else:
            cmd = ["trufflehog", "filesystem", target, "--json", "--no-update"]
        rc, stdout, stderr = await self._run_command(cmd)
        findings = await self.parse_output(stdout)
        return ToolResult(success=rc == 0, findings=findings, raw_output=stdout, error=stderr if rc not in (0, 183) else None)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(Finding(
                    title=f"Secret Found: {data.get('DetectorName', 'Unknown')}",
                    description=f"Secret detected by {data.get('DetectorName')} detector. Verified: {data.get('Verified', False)}",
                    severity=FindingSeverity.CRITICAL if data.get("Verified") else FindingSeverity.HIGH,
                    url=data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
                    evidence=str(data.get("Raw", ""))[:200],
                    owasp_category="A03",
                    tool_name="trufflehog",
                    raw_output=data,
                ))
            except Exception:
                continue
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["trufflehog", "version"])
        if rc == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="trufflehog not found")
