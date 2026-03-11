import json
import os
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry

_XSSTRIKE_PATH = "/opt/XSStrike/xsstrike.py"


@registry.register
class XssTrikeTool(BaseTool):
    name = "xsstrike"
    category = "xss-scanner"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        cmd = ["python3", _XSSTRIKE_PATH, "-u", target, "--json"]
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
                url = data.get("url", "")
                findings.append(Finding(
                    title="XSS vulnerability detected (XSStrike)",
                    description=data.get("description", f"XSS found with payload: {payload}"),
                    severity=FindingSeverity.HIGH,
                    url=url,
                    payload_used=payload,
                    owasp_category="A03:2021",
                    cwe_id="CWE-79",
                    tool_name="xsstrike",
                    raw_output=data,
                ))
            except json.JSONDecodeError:
                lower = line.lower()
                if "xss" in lower or "vulnerable" in lower or "payload" in lower:
                    findings.append(Finding(
                        title="XSS vulnerability detected (XSStrike)",
                        description=line.strip(),
                        severity=FindingSeverity.HIGH,
                        owasp_category="A03:2021",
                        cwe_id="CWE-79",
                        tool_name="xsstrike",
                        raw_output={"line": line},
                    ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        if os.path.isfile(_XSSTRIKE_PATH):
            return HealthCheckResult(status=HealthStatus.HEALTHY, message=f"Found at {_XSSTRIKE_PATH}")
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message=f"{_XSSTRIKE_PATH} not found")
