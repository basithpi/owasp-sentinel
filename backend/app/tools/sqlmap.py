import os
import uuid
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class SqlmapTool(BaseTool):
    name = "sqlmap"
    category = "sql-injection"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        run_id = uuid.uuid4().hex[:8]
        output_dir = f"/tmp/sqlmap_{run_id}"
        level = config.get("level", 3)
        cmd = [
            "sqlmap", "-u", target, "--batch",
            f"--output-dir={output_dir}", "--forms",
            f"--level={level}", "--results-file=/tmp/sqlmap_results_{run_id}.csv",
        ]
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
        lines = raw_output.splitlines()
        for line in lines:
            lower = line.lower()
            if "injectable" in lower or "sql injection" in lower or "parameter" in lower and "vulnerable" in lower:
                findings.append(Finding(
                    title="SQL Injection vulnerability detected",
                    description=line.strip(),
                    severity=FindingSeverity.CRITICAL,
                    owasp_category="A03:2021",
                    cwe_id="CWE-89",
                    tool_name="sqlmap",
                    raw_output={"line": line},
                ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["sqlmap", "--version"])
        if returncode == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="sqlmap not found")
