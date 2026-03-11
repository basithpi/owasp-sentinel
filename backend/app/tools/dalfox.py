import json
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class DalfoxTool(BaseTool):
    name = "dalfox"
    category = "xss-scanner"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        cmd = ["dalfox", "url", target, "--format", "json"]
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
                payload = data.get("payload", "")
                url = data.get("inject_type", "")
                findings.append(Finding(
                    title="XSS vulnerability detected (Dalfox)",
                    description=data.get("message", f"XSS payload: {payload}"),
                    severity=FindingSeverity.HIGH,
                    url=data.get("param", ""),
                    payload_used=payload,
                    owasp_category="A03:2021",
                    cwe_id="CWE-79",
                    tool_name="dalfox",
                    raw_output=data,
                ))
            except json.JSONDecodeError:
                lower = line.lower()
                if "xss" in lower or "vuln" in lower:
                    findings.append(Finding(
                        title="XSS vulnerability detected (Dalfox)",
                        description=line.strip(),
                        severity=FindingSeverity.HIGH,
                        owasp_category="A03:2021",
                        cwe_id="CWE-79",
                        tool_name="dalfox",
                        raw_output={"line": line},
                    ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["dalfox", "version"])
        if returncode == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="dalfox not found")
