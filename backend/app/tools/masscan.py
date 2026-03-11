import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class MasscanTool(BaseTool):
    name = "masscan"
    category = "port-scanner"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        try:
            ports = config.get("ports", "1-1000")
            rate = config.get("rate", "1000")
            cmd = ["masscan", target, f"-p{ports}", f"--rate={rate}", "-oJ", out_file]
            rc, stdout, stderr = await self._run_command(cmd, timeout=120)
            with open(out_file) as f:
                raw = f.read()
            findings = await self.parse_output(raw)
            return ToolResult(success=rc == 0, findings=findings, raw_output=raw, error=stderr if rc != 0 else None)
        except Exception as e:
            return ToolResult(success=False, findings=[], raw_output="", error=str(e))
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        try:
            stripped = raw_output.strip()
            data = json.loads(stripped.rstrip(",") + "]" if stripped.endswith(",") else stripped)
            if isinstance(data, list):
                for entry in data:
                    ip = entry.get("ip", "")
                    for port_info in entry.get("ports", []):
                        port = port_info.get("port", 0)
                        proto = port_info.get("proto", "tcp")
                        findings.append(Finding(
                            title=f"Open Port: {port}/{proto} on {ip}",
                            description=f"Masscan found open port {port}/{proto}",
                            severity=FindingSeverity.INFO,
                            url=f"{ip}:{port}",
                            tool_name="masscan",
                            raw_output=entry,
                        ))
        except Exception:
            pass
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["masscan", "--version"])
        if rc == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="masscan not found")
