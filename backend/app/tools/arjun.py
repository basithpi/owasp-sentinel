import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class ArjunTool(BaseTool):
    name = "arjun"
    category = "parameter-discovery"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        try:
            cmd = ["arjun", "-u", target, "--json", "-o", out_file]
            rc, stdout, stderr = await self._run_command(cmd, timeout=120)
            try:
                with open(out_file) as f:
                    raw = f.read()
            except FileNotFoundError:
                raw = stdout
            findings = await self.parse_output(raw)
            return ToolResult(success=True, findings=findings, raw_output=raw)
        except Exception as e:
            return ToolResult(success=False, findings=[], raw_output="", error=str(e))
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
            for endpoint, params in data.items():
                if params:
                    findings.append(Finding(
                        title=f"Parameters Discovered: {endpoint}",
                        description=f"Arjun found parameters: {', '.join(params)}",
                        severity=FindingSeverity.INFO,
                        url=endpoint,
                        tool_name="arjun",
                        raw_output={"endpoint": endpoint, "params": params},
                    ))
        except Exception:
            pass
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["arjun", "--help"])
        if rc == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version="latest")
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="arjun not found")
