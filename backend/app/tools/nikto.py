import json
import os
import uuid
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class NiktoTool(BaseTool):
    name = "nikto"
    category = "misconfiguration-scanner"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        run_id = uuid.uuid4().hex[:8]
        output_file = f"/tmp/nikto_{run_id}.json"
        cmd = ["nikto", "-h", target, "-Format", "json", "-output", output_file]
        returncode, stdout, stderr = await self._run_command(cmd)
        raw = stdout
        if os.path.isfile(output_file):
            with open(output_file) as f:
                raw = f.read()
            os.remove(output_file)
        findings = await self.parse_output(raw)
        return ToolResult(
            success=returncode == 0,
            findings=findings,
            raw_output=raw,
            error=stderr if returncode != 0 else None,
        )

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                osvdb = vuln.get("OSVDBID", "")
                msg = vuln.get("message", vuln.get("msg", "Nikto finding"))
                url = vuln.get("url", "")
                findings.append(Finding(
                    title=f"Nikto: {msg[:80]}",
                    description=msg,
                    severity=FindingSeverity.MEDIUM,
                    url=url,
                    cwe_id=f"OSVDB-{osvdb}" if osvdb else "",
                    tool_name="nikto",
                    raw_output=vuln,
                ))
        except json.JSONDecodeError:
            for line in raw_output.splitlines():
                line = line.strip()
                if line.startswith("+"):
                    findings.append(Finding(
                        title=f"Nikto: {line[1:].strip()[:80]}",
                        description=line[1:].strip(),
                        severity=FindingSeverity.MEDIUM,
                        tool_name="nikto",
                        raw_output={"line": line},
                    ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["nikto", "-Version"])
        if returncode == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="nikto not found")
