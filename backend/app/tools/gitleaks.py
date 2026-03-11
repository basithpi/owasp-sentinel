import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class GitleaksTool(BaseTool):
    name = "gitleaks"
    category = "secret-scanner"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            cmd = ["gitleaks", "detect", "--source", target, "--report-format", "json", "--report-path", report_path, "--exit-code", "0"]
            rc, stdout, stderr = await self._run_command(cmd)
            with open(report_path) as f:
                raw = f.read()
            findings = await self.parse_output(raw)
            return ToolResult(success=True, findings=findings, raw_output=raw)
        except Exception as e:
            return ToolResult(success=False, findings=[], raw_output="", error=str(e))
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        try:
            leaks = json.loads(raw_output) if raw_output.strip() else []
            for leak in leaks:
                findings.append(Finding(
                    title=f"Secret Leak: {leak.get('RuleID', 'unknown')}",
                    description=f"Secret found in {leak.get('File', 'unknown')} at line {leak.get('StartLine', 0)}",
                    severity=FindingSeverity.CRITICAL,
                    url=leak.get("File", ""),
                    evidence=leak.get("Match", "")[:200],
                    owasp_category="A03",
                    tool_name="gitleaks",
                    raw_output=leak,
                ))
        except Exception:
            pass
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["gitleaks", "version"])
        if rc == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="gitleaks not found")
