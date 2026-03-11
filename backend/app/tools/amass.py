import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class AmassTool(BaseTool):
    name = "amass"
    category = "recon"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        try:
            cmd = ["amass", "enum", "-d", target, "-json", out_file, "-passive"]
            rc, stdout, stderr = await self._run_command(cmd, timeout=180)
            with open(out_file) as f:
                raw = f.read()
            findings = await self.parse_output(raw)
            return ToolResult(success=True, findings=findings, raw_output=raw)
        except Exception as e:
            return ToolResult(success=False, findings=[], raw_output="", error=str(e))
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        subdomains = set()
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "")
                if name and name not in subdomains:
                    subdomains.add(name)
                    findings.append(Finding(
                        title=f"Subdomain: {name}",
                        description=f"Discovered subdomain via Amass: {name}",
                        severity=FindingSeverity.INFO,
                        url=name,
                        tool_name="amass",
                        raw_output=data,
                    ))
            except Exception:
                continue
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["amass", "version"])
        if rc == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="amass not found")
