import json
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class NucleiTool(BaseTool):
    name = "nuclei"
    category = "vulnerability-scanner"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        severity = config.get("severity", "critical,high,medium")
        templates = config.get("templates", "")
        cmd = ["nuclei", "-u", target, "-json", "-silent", f"-severity={severity}"]
        if templates:
            cmd.extend(["-t", templates])
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
        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                owasp_ids = info.get("classification", {}).get("owasp-id", [""])
                owasp_id = owasp_ids[0] if owasp_ids else ""
                finding = Finding(
                    title=info.get("name", "Nuclei Finding"),
                    description=info.get("description", ""),
                    severity=severity_map.get(info.get("severity", "info").lower(), FindingSeverity.INFO),
                    url=data.get("matched-at", ""),
                    owasp_category=owasp_id,
                    tool_name="nuclei",
                    raw_output=data,
                )
                findings.append(finding)
            except json.JSONDecodeError:
                continue
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["nuclei", "-version"])
        if returncode == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="nuclei not found")
